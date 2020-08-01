use tomiko_core::types::{ClientId, ClientSecret, RedirectUri};

pub mod raw {
    #[derive(Debug)]
    pub struct Client {
	pub id: String,
	pub secret: String
    }

    #[derive(Debug)]
    pub struct RedirectRecord {
	pub client_id: String,
	pub uri: String
    }
}

#[derive(Debug)]
pub struct Client {
    pub id: ClientId,
    pub secret: ClientSecret
}

impl From<raw::Client> for Client {
    fn from(x: raw::Client) -> Self {
	Self {
	    id: ClientId(x.id),
	    secret: ClientSecret(x.secret)
	}
    }
}

#[derive(Debug)]
pub struct RedirectRecord {
    pub client_id: ClientId,
    pub uri: RedirectUri
}

impl From<raw::RedirectRecord> for RedirectRecord {
    fn from(x: raw::RedirectRecord) -> Self {
	Self {
	    client_id: ClientId(x.client_id),
	    uri: RedirectUri(x.uri)
	}
    }
}
