use crate::auth::{AuthorizationCodeRequestExt, AuthorizationRequestData};

use super::types::*;

#[derive(Debug)]
pub struct Client {
    pub id: ClientId,
    pub name: String,
    pub secret: HashedClientSecret,
}

#[derive(Debug, Clone)]
pub struct AuthCodeData {
    pub code: HashedAuthCode,
    pub client_id: ClientId,
    pub req: AuthorizationRequestData<AuthorizationCodeRequestExt>,
    pub subject: String
}

impl Expire for AuthCodeData {
    const EXPIRES_IN_SECS: u64 = 10 * 60;
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

#[derive(Debug)]
pub struct PersistentSeed {
    pub id: PersistentSeedId,
    pub client_id: ClientId,
    pub subject: String,
    pub auth_data: AuthorizationData
}

#[derive(Debug, Clone)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct RefreshTokenId(pub String);

#[derive(Debug)]
pub struct RefreshTokenData {
    pub id: RefreshTokenId,
    pub seed: PersistentSeedId,
}

impl Expire for RefreshTokenData {
    const EXPIRES_IN_SECS: u64 = (24 * 60 * 60);
}

#[derive(Debug)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct AuthorizationData {
    pub scope: Scope,
    #[serde(flatten)]
    pub ext: AuthorizationDataExt
}

#[derive(Debug)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct AuthorizationDataExt {
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "crate::oidc::AuthorizationCodeGrantAuthorizationRequest::deserialize_skip_default")]
    pub oidc: Option<crate::oidc::AuthorizationCodeGrantAuthorizationRequest>
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

#[derive(Debug)]
#[derive(serde::Serialize)]
pub struct ClientInfo {
    pub client_id: ClientId,
    pub name: String
}
