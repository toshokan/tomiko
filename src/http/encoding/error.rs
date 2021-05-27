use crate::auth::{
    AccessTokenError, AuthorizationError, BadRedirect, MaybeRedirect, Redirect, WithState,
};
use warp::{Rejection, Reply};

#[derive(Debug, Clone)]
pub enum AuthRejection {
    Authorization(Redirect<WithState<AuthorizationError>>),
    AccessToken(AccessTokenError),
    BadRedirect(BadRedirect),
}

impl warp::reject::Reject for AuthRejection {}

impl From<Redirect<WithState<AuthorizationError>>> for AuthRejection {
    fn from(error: Redirect<WithState<AuthorizationError>>) -> Self {
        Self::Authorization(error)
    }
}

impl From<MaybeRedirect<WithState<AuthorizationError>, BadRedirect>> for AuthRejection {
    fn from(error: MaybeRedirect<WithState<AuthorizationError>, BadRedirect>) -> Self {
        match error {
            MaybeRedirect::Redirected(r) => Self::from(r),
            MaybeRedirect::Direct(d) => Self::BadRedirect(d),
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
                AuthRejection::BadRedirect(_) => Ok(warp::reply::with_status(
                    warp::reply(),
                    warp::http::StatusCode::BAD_REQUEST,
                )
                .into_response()),
            }
        }
        _ => Err(err),
    }
}
