pub mod error;
pub mod reply;

use http_basic_auth::Credential as BasicCredentials;
use tomiko_auth::ClientCredentials;
use tomiko_core::types::{ClientId, ClientSecret};

#[derive(serde::Deserialize)]
pub struct WithCredentials<T> {
    #[serde(flatten)]
    credentials: ClientCredentials,
    #[serde(flatten)]
    body: T,
}

impl<T> From<(BasicCredentials, T)> for WithCredentials<T> {
    fn from((credentials, value): (BasicCredentials, T)) -> Self {
        let credentials = ClientCredentials {
            client_id: ClientId(credentials.user_id),
            client_secret: ClientSecret(credentials.password),
        };

        Self::join(credentials, value)
    }
}

impl<T> WithCredentials<T> {
    pub fn join(credentials: ClientCredentials, body: T) -> Self {
        Self { credentials, body }
    }
    pub fn split(self) -> (ClientCredentials, T) {
        (self.credentials, self.body)
    }
}
