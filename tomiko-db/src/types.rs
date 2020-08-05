use tomiko_util::hash::HashedClientSecret;
use tomiko_core::types::{ClientId, RedirectUri};

#[derive(Debug)]
pub struct Client {
    pub id: ClientId,
    pub secret: HashedClientSecret,
}

#[derive(Debug)]
pub struct RedirectRecord {
    pub client_id: ClientId,
    pub uri: RedirectUri,
}
