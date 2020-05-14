use tomiko_core::types::{ClientId, ClientSecret, RedirectUri};

#[derive(Debug)]
#[derive(sqlx::FromRow)]
pub struct Client {
    id: ClientId,
    secret: ClientSecret
}

#[derive(Debug)]
#[derive(sqlx::FromRow)]
pub struct RedirectRecord {
    #[sqlx(rename="client_id")]
    id: ClientId,
    uri: RedirectUri
}
