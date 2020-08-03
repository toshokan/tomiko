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
    pub state: Option<String>,
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
    async fn check_client_auth(&self, credentials: ClientCredentials) -> Result<ClientId, ()>;
    async fn authorization_request(
        &self,
        req: AuthorizationRequest,
    ) -> Result<AuthorizationResponse, AuthorizationError>;
    async fn access_token_request<T>(
        &self,
	client: ClientId,
        req: TokenRequest,
    ) -> Result<AccessTokenResponse<T>, AccessTokenError>;
    async fn create_client(
	&self,
	credentials: ClientCredentials
    ) -> Result<ClientId, ()>;
}

#[derive(Debug)]
pub struct HashedClientSecret(pub String);

impl HashedClientSecret {
    pub fn from_raw(raw: String) -> Self {
        Self(raw)
    }
}

#[derive(Debug)]
pub struct HashedClientCredentials {
    pub client_id: ClientId,
    pub client_secret: HashedClientSecret,
}

#[derive(Debug)]
pub struct HashingService {
    secret_key: String,
}

impl HashingService {
    pub fn with_secret_key(secret_key: String) -> Self {
        Self { secret_key }
    }

    pub fn hash(&self, secret: &ClientSecret) -> Result<HashedClientSecret, ()> {
        let mut hasher = argonautica::Hasher::default();
        let hash = hasher
            .with_password(&secret.0)
            .with_secret_key(&self.secret_key)
            .hash()
            .expect("Failed to hash"); // TODO

        Ok(HashedClientSecret(hash))
    }

    pub fn verify(
        &self,
        secret: &ClientSecret,
        hashed: &HashedClientSecret,
    ) -> Result<bool, ()> {
        let mut verifier = argonautica::Verifier::default();
        let result = verifier
            .with_secret_key(&self.secret_key)
            .with_password(&secret.0)
            .with_hash(&hashed.0)
            .verify()
            .map_err(|_| ());
        result
    }
}
