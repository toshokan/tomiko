use tomiko_core::types::{
    AuthCode,
    ClientId,
    ClientSecret,
    GrantType,
    Scope,
    RedirectUri,
    ResponseType
};

use async_trait::async_trait;

#[derive(Debug)]
#[cfg_attr(feature = "serde-traits",
	   derive(serde::Deserialize)
)]
pub struct AuthorizationRequest {
    response_type: ResponseType,
    client_id: ClientId,
    redirect_uri: RedirectUri,
    scope: Scope,
    state: String
}

#[derive(Debug)]
#[cfg_attr(feature = "serde-traits",
	   derive(serde::Deserialize)
)]
pub struct TokenRequest {
    grant_type: GrantType,
    client_id: ClientId,
    client_secret: ClientSecret,
    redirect_uri: RedirectUri,
    code: AuthCode
}

#[derive(Debug)]
#[cfg_attr(feature = "serde-traits",
	   derive(serde::Serialize)
)]
pub struct AuthorizationResponse {
    code: AuthCode,
    state: String,
}

#[derive(Debug)]
#[cfg_attr(feature = "serde-traits",
	   derive(serde::Serialize)
)]
pub struct TokenType(String);

#[cfg_attr(feature = "serde-traits",
	   derive(serde::Serialize)
)]

#[derive(Debug)]
pub struct AccessTokenResponse<T> {
    access_token: T,
    token_type: String,
    refresh_token: Option<T>,
    expires_in: Option<u32>,
    scope: Option<Scope>
}

#[derive(Debug)]
#[cfg_attr(feature = "serde-traits",
	   derive(serde::Serialize),
	   serde(rename_all="snake_case")
)]
pub enum AuthorizationErrorKind {
    InvalidRequest,
    UnauthorizedClient,
    AccessDenied,
    UnsupportedResponseType,
    InvalidScope,
    ServerError,
    TemporarilyUnavailable
}

#[cfg_attr(feature = "serde-traits",
	   derive(serde::Serialize),
	   serde(rename_all="snake_case")
)]
pub struct AuthorizationError {
    #[cfg_attr(feature = "serde-traits",
	   serde(rename="error"))]
    kind: AuthorizationErrorKind,
    #[cfg_attr(feature = "serde-traits",
	   serde(rename="error_description"))]
    description: Option<String>,
    #[cfg_attr(feature = "serde-traits",
	   serde(rename="error_uri"))]
    uri: Option<String>,
    state: Option<String>
}

#[derive(Debug)]
#[cfg_attr(feature = "serde-traits",
	   derive(serde::Serialize),
	   serde(rename_all="snake_case")
)]
pub enum AccessTokenErrorKind {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    UnauthorizedClient,
    UnsupportedGrantType,
    InvalidScope
}

#[derive(Debug)]
#[cfg_attr(feature = "serde-traits",
	   derive(serde::Serialize),
	   serde(rename_all="snake_case")
)]
pub struct AccessTokenError {
    #[cfg_attr(feature = "serde-traits",
	       serde(rename="error"))]
    kind: AccessTokenErrorKind,
    #[cfg_attr(feature = "serde-traits",
	       serde(rename="error_description"))]
    description: Option<String>,
    #[cfg_attr(feature = "serde-traits",
	       serde(rename="error_uri"))]
    uri: Option<String>
}

#[async_trait]
pub trait AuthenticationCodeFlow {
    async fn authorization_request(req: AuthorizationRequest) -> Result<AuthorizationResponse, AuthorizationError>;
    async fn access_token_request<T>(req: TokenRequest) -> Result<AccessTokenResponse<T>, AccessTokenError>;
}
