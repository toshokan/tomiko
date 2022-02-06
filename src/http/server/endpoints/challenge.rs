use std::sync::Arc;

use warp::Filter;

use crate::{provider::OAuth2Provider, core::types::ChallengeId};
use crate::http::encoding::{self, reply};

pub fn challenge_endpoint(provider: Arc<OAuth2Provider>) -> impl warp::Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    let with_provider = warp::any().map(move || provider.clone());
    
    let info = warp::path!("info" / ChallengeId)
        .and(warp::get())
        .and(with_provider.clone())
        .and(encoding::bearer())
        .and_then(|id, provider: Arc<OAuth2Provider>, token| async move {
            provider
                .get_challenge_info(token, id)
                .await
                .map(|i| warp::reply::json(&i))
                .map_err(|_| warp::reject()) // TODO
        });

    let update = warp::path!("data" / ChallengeId)
        .and(warp::post())
	.and(with_provider.clone())
        .and(warp::body::json())
        .and(encoding::bearer())
        .and_then(
            |id, provider: Arc<OAuth2Provider>, req, token| async move {
                provider
                    .update_challenge_data_request(token, id, req)
                    .await
                    .map(|i| warp::reply::json(&i))
                    .map_err(|_| warp::reject()) // TODO
            },
        );

    let cont = warp::path!("continue" / ChallengeId)
	.and(warp::get())
	.and(with_provider.clone())
	.and_then(|id, provider: Arc<OAuth2Provider>| async move {
	    let result = provider.get_challenge_result(id).await;
	    reply::reply(result)
	});

    warp::path("v1")
	.and(info.or(update).or(cont))
}
