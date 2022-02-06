use std::sync::Arc;
use warp::Filter;

use crate::provider::OAuth2Provider;

mod endpoints;

use endpoints::{
    oauth::oauth_endpoint,
    challenge::challenge_endpoint,
    consent::consent_endpoint,
    client::client_endpoint
};

use super::encoding::error::handle_reject;

#[derive(Debug)]
pub struct Server {
    provider: Arc<OAuth2Provider>,
}

impl Server {
    pub fn new(provider: Arc<OAuth2Provider>) -> Self {
        Self {
            provider: Arc::clone(&provider),
        }
    }

    pub async fn serve(self) -> Option<()> {
        let provider = self.provider;

        let oauth = warp::path("oauth")
	    .and(oauth_endpoint(provider.clone()));
	
	let challenge = warp::path("challenge")
	    .and(challenge_endpoint(provider.clone()));
	
	let consent = warp::path("consent")
	    .and(consent_endpoint(provider.clone()));

	let client = warp::path("client")
	    .and(client_endpoint(provider.clone()));


	let cors = warp::cors()
	    .allow_any_origin();

	let routes = oauth
	    .or(challenge)
	    .or(consent)
	    .or(client)
	    .recover(handle_reject)
	    .with(warp::log("http-api"))
	    .with(cors);

        warp::serve(routes).run(([0, 0, 0, 0], 8001)).await;

        Some(())
    }
}
