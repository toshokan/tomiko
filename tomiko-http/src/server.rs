use tomiko_auth::{ClientCredentials, Provider};

use std::sync::Arc;
use warp::{Filter, Rejection};

use crate::encoding::{error::handle_reject, reply::form_encode, WithCredentials};
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
		use tomiko_auth::{MaybeChallenge::*, ChallengeExt};
		use warp::reply::Reply;
		
		let result = provider.authorization_request(req).await;
		match result.transpose() {
		    Challenge(c) => {
			let url = format!("http://localhost:8001/login?challenge={}", c.id);
			Ok(warp::http::Response::builder()
			    .header("Location", url)
			    .status(307)
			    .body(warp::hyper::Body::empty())
			    .unwrap())
		    },
		    Accept(result) => form_encode(result)
			.map(|r| r.into_response())
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

	let challenge_info = warp::path!("challenge" / String)
	    .and(with_provider.clone())
	    .and_then(|id, provider: Arc<P>| async move {
		provider.get_challenge_info(id).await
		    .map(|i| warp::reply::json(&i))
		    .ok_or_else(|| warp::reject()) // TODO
	    });

        let routes = oauth
            .and(warp::path("v1"))
            .and(authenticate.or(token_request).or(challenge_info))
            .recover(handle_reject)
            .with(warp::log("http-api"));

        warp::serve(routes).run(([127, 0, 0, 1], 8001)).await;

        Some(())
    }
}
