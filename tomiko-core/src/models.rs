use crate::types::*;

#[derive(Debug)]
pub struct Client {
    pub id: ClientId,
    pub secret: HashedClientSecret,
}

#[derive(Debug)]
pub struct AuthCodeData {
    pub code: AuthCode,
    pub client_id: ClientId,
    pub state: Option<String>,
    pub redirect_uri: RedirectUri,
    pub scope: Option<Scope>,
}

#[derive(Debug)]
pub struct RedirectRecord {
    pub client_id: ClientId,
    pub uri: RedirectUri,
}
