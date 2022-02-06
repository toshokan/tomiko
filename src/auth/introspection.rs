use crate::core::types::{ClientId, Scope, TokenId};

use super::TokenType;
use super::TokenTypeHint;

#[derive(Debug, serde::Deserialize)]
pub struct IntrospectionRequest {
    pub token: String,
    pub token_type_hint: Option<TokenTypeHint>,
}

#[derive(Debug, serde::Serialize)]
pub struct IntrospectionResponse {
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<TokenType>,
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims: Option<IntrospectionClaims>,
}

#[derive(Debug, serde::Serialize)]
pub struct IntrospectionClaims {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<Scope>,
    pub client_id: ClientId,
    pub username: String,
    pub exp: u64,
    pub iat: u64,
    pub nbf: u64,
    pub sub: String,
    pub aud: String,
    pub iss: String,
    pub jti: TokenId,
}
