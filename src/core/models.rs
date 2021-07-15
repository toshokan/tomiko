use crate::auth::{AuthorizationCodeRequestExt, AuthorizationRequestData};

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
    pub req: AuthorizationRequestData<AuthorizationCodeRequestExt>,
    pub subject: String
}

#[derive(Debug)]
pub struct RedirectRecord {
    pub client_id: ClientId,
    pub uri: RedirectUri,
}
