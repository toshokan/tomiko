use crate::auth::{ClientCredentials, UpdateChallengeDataRequest};
use crate::core::types::ChallengeId;

use std::sync::Arc;
use warp::{Filter, Rejection};

use super::encoding::{error::handle_reject, reply::form_encode, reply::reply, WithCredentials};
use http_basic_auth::Credential as BasicCredentials;

use crate::provider::OAuth2Provider;

#[derive(Debug)]
pub struct Server {
    provider: Arc<OAuth2Provider>,
}

fn body_with_credentials<T: serde::de::DeserializeOwned + Send>(
) -> impl Filter<Extract = ((ClientCredentials, T),), Error = Rejection> + Clone {
    let basic = warp::header::<BasicCredentials>("Authorization")
        .and(warp::body::form::<T>())
        .map(|c, b| (c, b).into());
    let body = warp::body::form::<WithCredentials<T>>();
    basic
        .or(body)
        .unify()
        .map(|w: WithCredentials<T>| w.split())
}

impl Server {
    pub fn new(provider: Arc<OAuth2Provider>) -> Self {
        Self {
            provider: Arc::clone(&provider),
        }
    }

    pub async fn serve(self) -> Option<()> {
        let provider = self.provider;

        let oauth = warp::path("oauth");
        let with_provider = warp::any().map(move || provider.clone());

	// Either a redirect success, a redirect error, or a direct error
        let authenticate = warp::path("authenticate")
            .and(with_provider.clone())
            .and(warp::filters::query::query())
            .and_then(|provider: Arc<OAuth2Provider>, req| async move {
                let result = provider.authorization_request(req).await;
                reply(result)
            });

	// Either a direct success or a direct error
        let token_request = warp::path("token")
            .and(warp::post())
            .and(with_provider.clone())
            .and(body_with_credentials())
            .and_then(|provider: Arc<OAuth2Provider>, (credentials, req)| async move {

                let result = provider.access_token_request(credentials, req).await;
		form_encode(result)
            });

        let challenge_data = warp::path!("challenge-info" / ChallengeId)
            .and(warp::get())
            .and(with_provider.clone())
            .and_then(|id, provider: Arc<OAuth2Provider>| async move {
                provider
                    .get_challenge_info(id)
                    .await
                    .map(|i| warp::reply::json(&i))
                    .ok_or_else(|| warp::reject()) // TODO
            });

        let update_challenge_data = warp::path!("challenge-data" / ChallengeId)
            .and(warp::post())
            .and(warp::body::json())
            .and(with_provider.clone())
            .and_then(
                |id, req: UpdateChallengeDataRequest, provider: Arc<OAuth2Provider>| async move {
                    provider
                        .update_challenge_data_request(id, req)
                        .await
                        .map(|i| warp::reply::json(&i))
                        .map_err(|_| warp::reject()) // TODO
                },
            );

	let challenge = warp::path!("challenge" / ChallengeId)
	    .and(warp::get())
	    .and(with_provider.clone())
	    .and_then(|id, provider: Arc<OAuth2Provider>| async move {
		let result = provider.get_challenge_result(id).await;
		reply(result)
	    });

        let routes = oauth
            .and(warp::path("v1"))
            .and(
                authenticate
                    .or(token_request)
                    .or(challenge_data)
                    .or(update_challenge_data)
                    .or(challenge)
            )
            .recover(handle_reject)
            .with(warp::log("http-api"));

        warp::serve(routes).run(([127, 0, 0, 1], 8001)).await;

        Some(())
    }
}
