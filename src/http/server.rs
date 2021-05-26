use crate::auth::{ClientCredentials, Provider, UpdateChallengeInfoRequest};
use crate::core::types::ChallengeId;

use std::sync::Arc;
use warp::{Filter, Rejection};

use super::encoding::{error::handle_reject, reply::form_encode, WithCredentials};
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
                use crate::auth::MaybeChallenge::*;
		use warp::reply::Reply;

                let result = provider.authorization_request(req).await;
                match result {
                    Ok(Challenge(c)) => {
                        let url = format!("http://localhost:8002/login?challenge-id={}", c.id.0);
                        Ok(warp::http::Response::builder()
                            .header("Location", url)
                            .status(307)
                            .body(warp::hyper::Body::empty())
                            .unwrap())
                    }
                    Ok(Accept(result)) => {
			Ok(result.into_response())
		    },
		    Err(_e) => {
			Err(warp::reject())
		    }
                }
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

        let challenge_info = warp::path!("challenge-info" / ChallengeId)
            .and(warp::get())
            .and(with_provider.clone())
            .and_then(|id, provider: Arc<OAuth2Provider>| async move {
                provider
                    .get_challenge_info(id)
                    .await
                    .map(|i| warp::reply::json(&i))
                    .ok_or_else(|| warp::reject()) // TODO
            });

        let update_challenge_info = warp::path!("challenge-info" / ChallengeId)
            .and(warp::post())
            .and(warp::body::json())
            .and(with_provider.clone())
            .and_then(
                |id, req: UpdateChallengeInfoRequest, provider: Arc<OAuth2Provider>| async move {
                    provider
                        .update_challenge_info_request(id, req)
                        .await
                        .map(|i| warp::reply::json(&i))
                        .map_err(|_| warp::reject()) // TODO
                },
            );

	let challenge = warp::path!("challenge" / ChallengeId)
	    .and(warp::get())
	    .and(with_provider.clone())
	    .and_then(|id, provider: Arc<OAuth2Provider>| async move {
		use warp::reply::Reply;
		
		let result = provider.get_challenge_result(id).await
		    .map(|e| e.into_response())
		    .map_err(|_| warp::reject());
		result
	    });

        let routes = oauth
            .and(warp::path("v1"))
            .and(
                authenticate
                    .or(token_request)
                    .or(challenge_info)
                    .or(update_challenge_info)
                    .or(challenge)
            )
            .recover(handle_reject)
            .with(warp::log("http-api"));

        warp::serve(routes).run(([127, 0, 0, 1], 8001)).await;

        Some(())
    }
}

#[cfg(feature = "none")]
mod none {
    enum ErrorT<A, I> {
	App(A),
	Irrecoverable(I)
    }

    type Redirect<T> = Option<T>;
    
    type TResult<S, E> = Result<S, ErrorT<E, ()>>;
    type TResult2<S, E> = TResult<Redirect<S>, Redirect<E>>;

    enum RedirectError {}
    enum DirectError {}
}
