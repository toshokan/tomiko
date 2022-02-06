use crate::{
    auth::{
        AccessTokenError, AuthorizationError, AuthorizationErrorResponse, MaybeRedirect, Redirect,
    },
    provider::error::Error,
};
use warp::{Rejection, Reply};

#[derive(Debug, Clone)]
pub enum AuthRejection {
    BadChallenge,
    BadRedirect,
    Authorization(Redirect<AuthorizationErrorResponse>),
    AccessToken(AccessTokenError),
    // BadRequest(BadRequest),
    BadRequest,
    Unauthorized,
    ServerError,
}

impl warp::reject::Reject for AuthRejection {}

impl From<Error> for AuthRejection {
    fn from(e: Error) -> Self {
        match e {
            // TODO
            Error::Unauthorized => AuthRejection::Unauthorized,
            Error::BadRequest => AuthRejection::BadRequest,
            // Error::BadRequest => AuthRejection::BadRequest(BadRequest::ServerError),
            _ => AuthRejection::ServerError,
        }
    }
}

// impl From<BadRequest> for AuthRejection {
//     fn from(error: BadRequest) -> Self {
// 	Self::BadRequest(error)
//     }
// }

impl From<Redirect<AuthorizationErrorResponse>> for AuthRejection {
    fn from(error: Redirect<AuthorizationErrorResponse>) -> Self {
        Self::Authorization(error)
    }
}

impl From<AuthorizationError> for AuthRejection {
    fn from(error: AuthorizationError) -> Self {
        use crate::auth::authorization::AuthorizationRedirectErrorKind;

        match error {
            MaybeRedirect::Redirected(r) => Self::from(r),
            MaybeRedirect::Direct(AuthorizationRedirectErrorKind::BadRedirect) => Self::BadRedirect,
            MaybeRedirect::Direct(AuthorizationRedirectErrorKind::BadChallenge) => {
                Self::BadChallenge
            }
        }
    }
}

impl From<AccessTokenError> for AuthRejection {
    fn from(error: AccessTokenError) -> Self {
        Self::AccessToken(error)
    }
}

pub async fn handle_reject(err: Rejection) -> Result<impl Reply, Rejection> {
    use warp::{http::StatusCode, reply::with_status};

    match err.find::<AuthRejection>() {
        Some(e) => {
            let e = e.clone();
            match e {
		AuthRejection::BadRedirect => {
		    Ok(with_status(
			"bad_redirect",
			StatusCode::BAD_REQUEST
		    ).into_response())
		},
		AuthRejection::BadChallenge => {
		    Ok(with_status(
			"bad_challenge",
			StatusCode::BAD_REQUEST
		    ).into_response())
		}
		AuthRejection::ServerError => {
		    Ok(with_status(
			"server_error",
			StatusCode::INTERNAL_SERVER_ERROR
		    ).into_response())
		}
		AuthRejection::Unauthorized => {
		    Ok(with_status(
			"unauthorized",
			StatusCode::UNAUTHORIZED
		    ).into_response())
		},
		AuthRejection::BadRequest => {
		    Ok(with_status(
			"bad_request",
			StatusCode::BAD_REQUEST
		    ).into_response())
		},
		AuthRejection::Authorization(e) => {
		    Ok(e.into_response())
		}
                AuthRejection::AccessToken(e) => {
                    Ok(with_status(
			warp::reply::json(&e),
			StatusCode::BAD_REQUEST
		    ).into_response())
                }
                // AuthRejection::BadRequest(b) => Ok(warp::reply::with_status(
                //     warp::reply::json(&b),
                //     warp::http::StatusCode::BAD_REQUEST,
                // ).into_response()),
            }
        }
        _ => Err(err),
    }
}
