use std::sync::Arc;

use warp::Filter;

use crate::provider::OAuth2Provider;
use crate::http::encoding::{self, reply};

pub fn consent_endpoint(provider: Arc<OAuth2Provider>) -> impl warp::Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    let with_provider = warp::any().map(move || provider.clone());
    
    let get = warp::path!("consent")
        .and(warp::get())
	.and(warp::query())
        .and(with_provider.clone())
        .and(encoding::bearer())
        .and_then(|id, provider: Arc<OAuth2Provider>, token| async move {
	    reply::json_encode(
		provider
                    .get_consent(token, id)
                    .await
	    )
        });

    let all = warp::path!("consent" / String)
        .and(warp::get())
        .and(with_provider.clone())
        .and(encoding::bearer())
        .and_then(|subject: String, provider: Arc<OAuth2Provider>, token| async move {
	    reply::json_encode(
		provider
                    .get_all_consents(token, subject)
                    .await
	    )
        });

    let set = warp::path!("consent")
        .and(warp::post())
	.and(warp::body::json())
        .and(with_provider.clone())
        .and(encoding::bearer())
        .and_then(|consent, provider: Arc<OAuth2Provider>, token| async move {
	    reply::json_encode(
		provider
                    .put_consent(token, consent)
                    .await
	    )
        });

    let revoke = warp::path!("revoke")
        .and(warp::get())
	.and(warp::query())
        .and(with_provider.clone())
        .and(encoding::bearer())
        .and_then(|id, provider: Arc<OAuth2Provider>, token| async move {
	    reply::json_encode(
		provider
                .revoke_consent(token, id)
                .await
	    )
        });

    warp::path("v1")
	.and(get.or(all).or(set).or(revoke))
}
