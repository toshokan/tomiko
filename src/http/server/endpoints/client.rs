use std::sync::Arc;

use warp::Filter;

use crate::core::types::ClientId;
use crate::http::encoding::{self, reply};
use crate::provider::OAuth2Provider;

pub fn client_endpoint(
    provider: Arc<OAuth2Provider>,
) -> impl warp::Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    let with_provider = warp::any().map(move || provider.clone());

    let get = warp::path!("info" / ClientId)
        .and(warp::get())
        .and(with_provider.clone())
        .and(encoding::bearer())
        .and_then(|id, provider: Arc<OAuth2Provider>, token| async move {
            reply::json_encode(provider.get_client_info(token, id).await)
        });

    warp::path("v1").and(get)
}
