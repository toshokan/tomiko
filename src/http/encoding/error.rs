use crate::auth::{AccessTokenError, AuthorizationError, Redirect};
use warp::{Rejection, Reply};

#[derive(Debug, Clone)]
pub enum AuthRejection {
    Authorization(Redirect<AuthorizationError>),
    AccessToken(AccessTokenError),
}

impl warp::reject::Reject for AuthRejection {}

impl From<Redirect<AuthorizationError>> for AuthRejection {
    fn from(error: Redirect<AuthorizationError>) -> Self {
	Self::Authorization(error)
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
		}
	    }
        }
        _ => Err(err),
    }
}
