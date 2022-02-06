use std::sync::Arc;

use warp::Filter;

use crate::http::encoding::{self, reply};
use crate::provider::OAuth2Provider;

pub fn oauth_endpoint(
    provider: Arc<OAuth2Provider>,
) -> impl warp::Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    let with_provider = warp::any().map(move || provider.clone());

    let authenticate = warp::path("authenticate")
        .and(with_provider.clone())
        .and(warp::filters::query::query())
        .and_then(|provider: Arc<OAuth2Provider>, req| async move {
            let result = provider.authorization_request(req).await;
            reply::reply(result)
        });

    // Either a direct success or a direct error
    let token = warp::path("token")
        .and(warp::post())
        .and(with_provider.clone())
        .and(encoding::body_with_credentials())
        .and_then(
            |provider: Arc<OAuth2Provider>, (credentials, req)| async move {
                let result = provider.access_token_request(credentials, req).await;
                reply::json_encode(result)
            },
        );

    let introspect = warp::path("introspect")
        .and(warp::post())
        .and(with_provider.clone())
        .and(encoding::body_with_credentials())
        .and_then(
            |provider: Arc<OAuth2Provider>, (credentials, req)| async move {
                let result = provider.introspection_request(credentials, req).await;
                reply::json_encode(result)
            },
        );

    let revoke = warp::path("revoke")
        .and(warp::post())
        .and(with_provider.clone())
        .and(encoding::body_with_credentials())
        .and_then(
            |provider: Arc<OAuth2Provider>, (credentials, req)| async move {
                reply::json_encode(provider.revocation_request(credentials, req).await)
            },
        );

    warp::path("v1").and(authenticate.or(token).or(introspect).or(revoke))
}
