use tomiko_core::types::{
    AuthCode, ClientId, ClientSecret, GrantType, RedirectUri, ResponseType, Scope,
};

use async_trait::async_trait;

#[derive(Debug)]
#[cfg_attr(feature = "serde-traits", derive(serde::Deserialize))]
pub struct AuthorizationRequest {
    pub response_type: ResponseType,
    pub client_id: ClientId,
    pub redirect_uri: RedirectUri,
    pub scope: Scope,
    pub state: String,
}

#[derive(Debug)]
#[cfg_attr(feature = "serde-traits", derive(serde::Deserialize))]
pub struct TokenRequest {
    grant_type: GrantType,
    redirect_uri: RedirectUri,
    code: AuthCode,
}

#[derive(Debug)]
#[cfg_attr(feature = "serde-traits", derive(serde::Serialize))]
pub struct AuthorizationResponse {
    code: AuthCode,
    state: String,
}

impl AuthorizationResponse {
    pub fn new(code: AuthCode, state: String) -> Self {
        Self { code, state }
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "serde-traits", derive(serde::Serialize))]
pub struct TokenType(String);

#[cfg_attr(feature = "serde-traits", derive(serde::Serialize))]
#[derive(Debug)]
pub struct AccessTokenResponse<T> {
    access_token: T,
    token_type: String,
    refresh_token: Option<T>,
    expires_in: Option<u32>,
    scope: Option<Scope>,
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
        pub fn $name(state: &str) -> Self {
            Self {
                kind: $variant,
                description: None,
                uri: None,
                state: Some(state.to_string()),
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
    kind: AccessTokenErrorKind,
    #[cfg_attr(feature = "serde-traits", serde(rename = "error_description"))]
    description: Option<String>,
    #[cfg_attr(
        feature = "serde-traits",
        serde(rename = "error_uri"),
        serde(skip_serializing_if = "Option::is_none")
    )]
    uri: Option<String>,
}

#[derive(Debug)]
#[cfg_attr(feature = "serde-traits", derive(serde::Deserialize))]
pub struct ClientCredentials {
    pub client_id: ClientId,
    pub client_secret: ClientSecret,
}

#[async_trait]
pub trait AuthenticationCodeFlow {
    async fn authorization_request(
        &self,
        req: AuthorizationRequest,
    ) -> Result<AuthorizationResponse, AuthorizationError>;
    async fn access_token_request<T>(
        &self,
        req: TokenRequest,
        pw: HashedClientCredentials,
    ) -> Result<AccessTokenResponse<T>, AccessTokenError>;
}

#[derive(Debug)]
pub struct HashedClientSecret(String);

#[derive(Debug)]
pub struct HashedClientCredentials {
    pub client_id: ClientId,
    pub client_secret: HashedClientSecret,
}

pub struct Hasher {
    secret: String,
}

impl Hasher {
    pub fn with_secret(secret: String) -> Self {
        Self { secret }
    }

    pub fn hash(&self, credentials: ClientCredentials) -> Result<HashedClientCredentials, ()> {
        let mut hasher = argonautica::Hasher::default();
        let hash = hasher
            .with_password(credentials.client_secret.0)
            .with_secret_key(&self.secret)
            .hash()
            .expect("Failed to hash"); // TODO

        Ok(HashedClientCredentials {
            client_id: credentials.client_id,
            client_secret: HashedClientSecret(hash),
        })
    }
}
