use crate::auth::{ClientCredentials, Provider, UpdateChallengeInfoRequest};
use crate::core::types::ChallengeId;

use std::sync::Arc;
use warp::{Filter, Rejection};

use super::encoding::{error::handle_reject, reply::form_encode, WithCredentials};
use http_basic_auth::Credential as BasicCredentials;

#[derive(Debug)]
pub struct Server<P> {
    provider: Arc<P>,
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

impl<P: Provider + Send + Sync + 'static> Server<P> {
    pub fn new(provider: Arc<P>) -> Self {
        Self {
            provider: Arc::clone(&provider),
        }
    }

    pub async fn serve(self) -> Option<()> {
        let provider = self.provider;

        let oauth = warp::path("oauth");
        let with_provider = warp::any().map(move || provider.clone());

        let authenticate = warp::path("authenticate")
            .and(with_provider.clone())
            .and(warp::filters::query::query())
            .and_then(|provider: Arc<P>, req| async move {
                use crate::auth::{ChallengeExt, MaybeChallenge::*};
                use warp::reply::Reply;

                let result = provider.authorization_request(req).await;
                match result.transpose() {
                    Challenge(c) => {
                        let url = format!("http://localhost:8002/login?challenge-id={}", c.id.0);
                        Ok(warp::http::Response::builder()
                            .header("Location", url)
                            .status(307)
                            .body(warp::hyper::Body::empty())
                            .unwrap())
                    }
                    Accept(result) => form_encode(result).map(|r| r.into_response()),
                }
            });

        let token_request = warp::path("token")
            .and(warp::post())
            .and(with_provider.clone())
            .and(body_with_credentials())
            .and_then(|provider: Arc<P>, (credentials, req)| async move {
                let result = provider.access_token_request(credentials, req).await;
                form_encode(result)
            });

        let challenge_info = warp::path!("challenge" / ChallengeId)
            .and(warp::get())
            .and(with_provider.clone())
            .and_then(|id, provider: Arc<P>| async move {
                provider
                    .get_challenge_info(id)
                    .await
                    .map(|i| warp::reply::json(&i))
                    .ok_or_else(|| warp::reject()) // TODO
            });

        let update_challenge_info = warp::path!("challenge" / ChallengeId)
            .and(warp::post())
            .and(warp::body::json())
            .and(with_provider.clone())
            .and_then(
                |id, req: UpdateChallengeInfoRequest, provider: Arc<P>| async move {
                    provider
                        .update_challenge_info_request(id, req)
                        .await
                        .map(|i| warp::reply::json(&i))
                        .map_err(|_| warp::reject()) // TODO
                },
            );

        let routes = oauth
            .and(warp::path("v1"))
            .and(
                authenticate
                    .or(token_request)
                    .or(challenge_info)
                    .or(update_challenge_info),
            )
            .recover(handle_reject)
            .with(warp::log("http-api"));

        warp::serve(routes).run(([127, 0, 0, 1], 8001)).await;

        Some(())
    }
}
