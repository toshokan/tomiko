use tomiko_core::types::{
    AuthCode, Client, ClientId, ClientSecret, GrantType, RedirectUri, ResponseType, Scope,
};

use async_trait::async_trait;

#[derive(Debug)]
#[cfg_attr(feature = "serde-traits", derive(serde::Deserialize))]
pub struct AuthorizationRequest {
    pub response_type: ResponseType,
    pub client_id: ClientId,
    pub redirect_uri: RedirectUri,
    pub scope: Scope,
    pub state: Option<String>,
}

#[derive(Debug)]
#[cfg_attr(feature = "serde-traits", derive(serde::Deserialize))]
pub struct TokenRequest {
    pub grant_type: GrantType,
    pub redirect_uri: RedirectUri,
    pub code: AuthCode,
}

#[derive(Debug)]
#[cfg_attr(feature = "serde-traits", derive(serde::Serialize))]
pub struct AuthorizationResponse {
    code: AuthCode,
    #[cfg_attr(
        feature = "serde-traits",
        serde(skip_serializing_if = "Option::is_none")
    )]
    state: Option<String>,
}

impl AuthorizationResponse {
    pub fn new(code: AuthCode, state: Option<String>) -> Self {
        Self { code, state }
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "serde-traits", derive(serde::Serialize))]
pub struct TokenType(String);

#[cfg_attr(feature = "serde-traits", derive(serde::Serialize))]
#[derive(Debug)]
pub struct AccessTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub refresh_token: Option<String>,
    pub expires_in: Option<u32>,
    pub scope: Option<Scope>,
}

#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "serde-traits",
    derive(serde::Serialize),
    serde(rename_all = "snake_case")
)]
pub enum AuthorizationErrorKind {
    InvalidRequest,
    UnauthorizedClient,
    AccessDenied,
    UnsupportedResponseType,
    InvalidScope,
    ServerError,
    TemporarilyUnavailable,
}

#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "serde-traits",
    derive(serde::Serialize),
    serde(rename_all = "snake_case")
)]
pub struct AuthorizationError {
    #[cfg_attr(feature = "serde-traits", serde(rename = "error"))]
    pub kind: AuthorizationErrorKind,
    #[cfg_attr(feature = "serde-traits", serde(rename = "error_description"))]
    pub description: Option<String>,
    #[cfg_attr(
        feature = "serde-traits",
        serde(rename = "error_uri"),
        serde(skip_serializing_if = "Option::is_none")
    )]
    pub uri: Option<String>,
    #[cfg_attr(
        feature = "serde-traits",
        serde(skip_serializing_if = "Option::is_none")
    )]
    pub state: Option<String>,
}

macro_rules! make_helper {
    ($name: ident, $variant: path) => {
        pub fn $name(state: &Option<String>) -> Self {
            Self {
                kind: $variant,
                description: None,
                uri: None,
                state: state.as_ref().map(ToString::to_string),
            }
        }
    };
}

impl AuthorizationError {
    make_helper!(server_error, AuthorizationErrorKind::ServerError);
    make_helper!(
        unauthorized_client,
        AuthorizationErrorKind::UnauthorizedClient
    );
}

#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "serde-traits",
    derive(serde::Serialize),
    serde(rename_all = "snake_case")
)]
pub enum AccessTokenErrorKind {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    UnauthorizedClient,
    UnsupportedGrantType,
    InvalidScope,
}

#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "serde-traits",
    derive(serde::Serialize),
    serde(rename_all = "snake_case")
)]
pub struct AccessTokenError {
    #[cfg_attr(feature = "serde-traits", serde(rename = "error"))]
    pub kind: AccessTokenErrorKind,
    #[cfg_attr(feature = "serde-traits", serde(rename = "error_description"))]
    pub description: Option<String>,
    #[cfg_attr(
        feature = "serde-traits",
        serde(rename = "error_uri"),
        serde(skip_serializing_if = "Option::is_none")
    )]
    pub uri: Option<String>,
}

#[derive(Debug)]
#[cfg_attr(feature = "serde-traits", derive(serde::Deserialize))]
pub struct ClientCredentials {
    pub client_id: ClientId,
    pub client_secret: ClientSecret,
}

#[async_trait]
pub trait AuthenticationCodeFlow {
    async fn check_client_auth(&self, credentials: ClientCredentials) -> Result<Client, ()>;
    async fn authorization_request(
        &self,
        req: AuthorizationRequest,
    ) -> Result<AuthorizationResponse, AuthorizationError>;
    async fn access_token_request(
        &self,
        client: ClientId,
        req: TokenRequest,
    ) -> Result<AccessTokenResponse, AccessTokenError>;
    async fn create_client(&self, credentials: ClientCredentials) -> Result<Client, ()>;
}
