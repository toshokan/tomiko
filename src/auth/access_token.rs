use crate::auth::{oidc, pkce};
use crate::core::types::{AuthCode, RedirectUri, Scope};

use super::error::ErrorResponse;

pub type AccessTokenError = ErrorResponse<AccessTokenErrorKind>;

#[derive(Debug, serde::Serialize)]
pub enum TokenType {
    Bearer,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenTypeHint {
    AccessToken,
    RefreshToken,
}

#[derive(Debug, serde::Deserialize)]
#[serde(tag = "grant_type")]
pub enum TokenRequest {
    #[serde(rename = "authorization_code")]
    AuthenticationCode(AuthenticationCodeTokenRequest),
    #[serde(rename = "client_credentials")]
    ClientCredentials(ClientCredentialsTokenRequest),
    #[serde(rename = "refresh_token")]
    RefreshToken(RefreshTokenRequest),
}

#[derive(Debug, serde::Deserialize)]
pub struct AuthenticationCodeTokenRequest {
    pub redirect_uri: RedirectUri,
    pub code: AuthCode,
    #[serde(flatten)]
    pub pkce_verifier: Option<pkce::Verifier>,
}

#[derive(Debug, serde::Deserialize)]
pub struct ClientCredentialsTokenRequest {
    pub scope: Scope,
}

#[derive(Debug, serde::Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
    pub scope: Option<Scope>,
}

#[derive(serde::Serialize, Debug)]
pub struct AccessTokenResponse {
    pub access_token: String,
    pub token_type: TokenType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<u32>,
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oidc: Option<oidc::AccessTokenResponse>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessTokenErrorKind {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    UnauthorizedClient,
    UnsupportedGrantType,
    InvalidScope,
}

impl From<AccessTokenErrorKind> for AccessTokenError {
    fn from(kind: AccessTokenErrorKind) -> Self {
        Self {
            kind,
            description: None,
            uri: None,
        }
    }
}
