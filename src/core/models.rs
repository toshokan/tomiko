use crate::auth::{AuthorizationCodeRequestExt, AuthorizationRequestData};

use super::types::*;

#[derive(Debug)]
pub struct Client {
    pub id: ClientId,
    pub secret: HashedClientSecret,
}

#[derive(Debug)]
pub struct AuthCodeData {
    pub code: HashedAuthCode,
    pub client_id: ClientId,
    pub req: AuthorizationRequestData<AuthorizationCodeRequestExt>,
    pub subject: String
}

#[derive(Debug)]
pub struct RedirectRecord {
    pub client_id: ClientId,
    pub uri: RedirectUri,
}

#[derive(Debug, Clone)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct PersistentSeedId(pub String);

pub struct PersistentSeed {
    pub id: PersistentSeedId,
    pub client_id: ClientId,
    pub auth_data: AuthorizationData
}

#[derive(Debug)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct RefreshTokenId(pub String);

pub struct RefreshTokenRecord {
    pub id: RefreshTokenId,
    pub seed: PersistentSeedId,
    pub invalid_after: i64,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct AuthorizationData {
    pub subject: String,
    pub scope: Scope
}

#[derive(Debug)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct RefreshClaims {
    #[serde(rename = "t/ps")]
    pub tps: PersistentSeedId,
    pub jti: RefreshTokenId,
    pub iat: u64
}

impl Scope {
    pub fn has_refresh(&self) -> bool {
	self.contains("offline_access")
    }
}

#[derive(Debug)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Consent {
    pub client_id: ClientId,
    pub subject: String,
    pub scope: Scope
}

#[derive(Debug)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ConsentId  {
    pub client_id: ClientId,
    pub subject: String
}
