use crate::{auth::{
    AccessTokenError, AuthorizationError, BadRequest, MaybeRedirect, Redirect, WithState,
}, provider::error::Error};
use warp::{Rejection, Reply};

#[derive(Debug, Clone)]
pub enum AuthRejection {
    Authorization(Redirect<WithState<AuthorizationError>>),
    AccessToken(AccessTokenError),
    BadRequest(BadRequest),
    ServerError
}

impl warp::reject::Reject for AuthRejection {}

impl From<Error> for AuthRejection {
    fn from(e: Error) -> Self {
	match e {
	    // TODO
	    Error::BadRequest => AuthRejection::BadRequest(BadRequest::ServerError),
	    _ => AuthRejection::ServerError
	}
    }
}

impl From<BadRequest> for AuthRejection {
    fn from(error: BadRequest) -> Self {
	Self::BadRequest(error)
    }
}

impl From<Redirect<WithState<AuthorizationError>>> for AuthRejection {
    fn from(error: Redirect<WithState<AuthorizationError>>) -> Self {
        Self::Authorization(error)
    }
}

impl From<MaybeRedirect<WithState<AuthorizationError>, BadRequest>> for AuthRejection {
    fn from(error: MaybeRedirect<WithState<AuthorizationError>, BadRequest>) -> Self {
        match error {
            MaybeRedirect::Redirected(r) => Self::from(r),
            MaybeRedirect::Direct(d) => Self::BadRequest(d),
        }
    }
}

impl From<AccessTokenError> for AuthRejection {
    fn from(error: AccessTokenError) -> Self {
        Self::AccessToken(error)
    }
}

pub async fn handle_reject(err: Rejection) -> Result<impl Reply, Rejection> {
    match err.find::<AuthRejection>() {
        Some(e) => {
            let e = e.clone();
            match e {
                AuthRejection::Authorization(e) => Ok(e.into_response()),
                AuthRejection::AccessToken(e) => {
                    let resp = warp::reply::json(&e);
                    Ok(
                        warp::reply::with_status(resp, warp::http::StatusCode::BAD_REQUEST)
                            .into_response(),
                    )
                }
                AuthRejection::BadRequest(b) => Ok(warp::reply::with_status(
                    warp::reply::json(&b),
                    warp::http::StatusCode::BAD_REQUEST,
                ).into_response()),
		AuthRejection::ServerError => Ok(
		    warp::reply::with_status("Server Error", warp::http::StatusCode::INTERNAL_SERVER_ERROR)
			.into_response())
            }
        }
        _ => Err(err),
    }
}
