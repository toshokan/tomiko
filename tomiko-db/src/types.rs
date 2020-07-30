use tomiko_core::types::{ClientId, ClientSecret, RedirectUri};

#[derive(Debug)]
pub struct Client {
    pub id: ClientId,
    pub secret: ClientSecret
}

#[derive(Debug)]
pub struct RedirectRecord {
    pub client_id: ClientId,
    pub uri: RedirectUri
}
