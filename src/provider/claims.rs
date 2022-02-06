use crate::{
    core::{
        models::{PersistentSeedId, RefreshTokenId},
        types::{Scope, TokenId},
    },
    oidc::types::Nonce,
};

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct AccessClaims {
    pub iss: String,
    pub exp: u64,
    pub aud: String,
    pub sub: String,
    pub client_id: String,
    pub iat: u64,
    pub nbf: u64,
    pub jti: TokenId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<Scope>,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct IdClaims {
    pub sub: String,
    pub iss: String,
    pub aud: String,
    pub exp: u64,
    pub iat: u64,
    pub nbf: u64,
    pub auth_time: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<Nonce>,
    pub azp: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct RefreshClaims {
    #[serde(rename = "t/ps")]
    pub tps: PersistentSeedId,
    pub jti: RefreshTokenId,
    pub iat: u64,
    pub iss: String,
}
