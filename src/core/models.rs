use crate::auth::AuthorizationCodeGrantAuthorizationRequest;

use super::types::*;

#[derive(Debug)]
pub struct Client {
    pub id: ClientId,
    pub secret: HashedClientSecret,
}

#[derive(Debug)]
pub struct AuthCodeData {
    pub code: AuthCode,
    pub client_id: ClientId,
    pub req: AuthorizationCodeGrantAuthorizationRequest
}

#[derive(Debug)]
pub struct RedirectRecord {
    pub client_id: ClientId,
    pub uri: RedirectUri,
}
