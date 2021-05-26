use crate::auth::{AccessTokenError, AuthorizationError, BadRedirect, MaybeRedirect, Redirect};
use warp::{Rejection, Reply};

#[derive(Debug, Clone)]
pub enum AuthRejection {
    Authorization(Redirect<AuthorizationError>),
    AccessToken(AccessTokenError),
    BadRedirect(BadRedirect)
}

impl warp::reject::Reject for AuthRejection {}

impl From<Redirect<AuthorizationError>> for AuthRejection {
    fn from(error: Redirect<AuthorizationError>) -> Self {
	Self::Authorization(error)
    }
}

impl From<MaybeRedirect<AuthorizationError, BadRedirect>> for AuthRejection {
    fn from(error: MaybeRedirect<AuthorizationError, BadRedirect>) -> Self {
	match error {
	    MaybeRedirect::Redirected(r) => Self::from(r),
	    MaybeRedirect::Direct(d) => Self::BadRedirect(d)
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
		    Ok(warp::reply::with_status(resp, warp::http::StatusCode::BAD_REQUEST).into_response())
		},
		AuthRejection::BadRedirect(_) => {
		    Ok(warp::reply::with_status(warp::reply(), warp::http::StatusCode::BAD_REQUEST).into_response())
		}
	    }
        }
        _ => Err(err),
    }
}
