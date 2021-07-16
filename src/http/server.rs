use crate::auth::{ClientCredentials, UpdateChallengeDataRequest};
use crate::core::types::{BearerToken, ChallengeId};

use std::sync::Arc;
use warp::{Filter, Rejection};

use super::encoding::{error::handle_reject, reply::accept, reply::json_encode, reply::reply, WithCredentials};
use http_basic_auth::Credential as BasicCredentials;

use crate::provider::OAuth2Provider;

pub trait PeekOwned<T> {
    fn peek(&self) -> T;
}

pub fn validate_client<'p, T, F>(filter: F) -> impl Filter<Extract = ((Arc<OAuth2Provider>, T),), Error = Rejection> + Clone
where
    T: PeekOwned<(crate::core::types::ClientId, crate::core::types::RedirectUri)> + Send,
    F: Filter<Extract = (Arc<OAuth2Provider>, T), Error = Rejection> + Clone + Send
{
    filter.and_then(|p: Arc<OAuth2Provider>, t: T| async move {
	let (c, r) = t.peek();
	if p.validate_client(&c, &r, &None).await.is_err() {
	    Err(warp::reject::custom(
		super::encoding::error::AuthRejection::BadRequest(crate::auth::BadRequest::BadRedirect)
	    ))
	} else {
	    Ok((p, t))
	}
	
    })
}

impl PeekOwned<(crate::core::types::ClientId, crate::core::types::RedirectUri)> for crate::auth::AuthorizationRequest {
    fn peek(&self) -> (crate::core::types::ClientId, crate::core::types::RedirectUri) {
	let parts = &self.as_parts();
	(parts.client_id.clone(), parts.redirect_uri.clone())
    }
}

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

fn bearer() -> impl Filter<Extract = (BearerToken,), Error = Rejection> + Clone {
    warp::header("Authorization")
        .and_then(|s: String| async move {
	    let token = match s.split_once("Bearer ") {
		Some(("", token)) => Ok(token.to_string()),
		_ => Err(crate::auth::BadRequest::BadToken)
	    };
	    accept(token)
		.map(|t| BearerToken(t))
	})
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
	let challenge = warp::path("challenge");
        let with_provider = warp::any().map(move || provider.clone());

	// Either a redirect success, a redirect error, or a direct error
        let authenticate = warp::path("authenticate")
            .and(with_provider.clone())
            .and(warp::filters::query::query())
            .with(warp::wrap_fn(validate_client))
            .untuple_one()
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
		json_encode(result)
            });

        let challenge_data = warp::path!("info" / ChallengeId)
            .and(warp::get())
            .and(with_provider.clone())
            .and(bearer())
            .and_then(|id, provider: Arc<OAuth2Provider>, token| async move {
                provider
                    .get_challenge_info(token, id)
                    .await
                    .map(|i| warp::reply::json(&i))
                    .ok_or_else(|| warp::reject()) // TODO
            });

        let challenge_update = warp::path!("data" / ChallengeId)
            .and(warp::post())
            .and(warp::body::json())
            .and(with_provider.clone())
            .and(bearer())
            .and_then(
                |id, req: UpdateChallengeDataRequest, provider: Arc<OAuth2Provider>, token| async move {
                    provider
                        .update_challenge_data_request(token, id, req)
                        .await
                        .map(|i| warp::reply::json(&i))
                        .map_err(|_| warp::reject()) // TODO
                },
            );

	let challenge_continue = warp::path!("continue" / ChallengeId)
	    .and(warp::get())
	    .and(with_provider.clone())
	    .and_then(|id, provider: Arc<OAuth2Provider>| async move {
		let result = provider.get_challenge_result(id).await;
		reply(result)
	    });

	let cors = warp::cors()
	    .allow_any_origin();

        let routes =
	    (
		oauth
		    .and(warp::path("v1"))
		    .and(
			authenticate
			    .or(token_request)
		    ))
	    .or(
		challenge
		    .and(warp::path("v1"))
		    .and(
			challenge_data
			    .or(challenge_update)
			    .or(challenge_continue)
		    )
	    )
            .recover(handle_reject)
            .with(warp::log("http-api"))
            .with(cors);

        warp::serve(routes).run(([127, 0, 0, 1], 8001)).await;

        Some(())
    }
}
