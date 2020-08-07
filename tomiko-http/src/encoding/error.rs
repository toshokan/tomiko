use tomiko_auth::{AuthorizationError, AccessTokenError};
use crate::encoding::reply::FormEncoded;
use warp::{Rejection, Reply};

#[derive(Debug, Clone, serde::Serialize)]
#[serde(untagged)]
pub enum AuthRejection {
    Authorization(AuthorizationError),
    AccessToken(AccessTokenError),
}

impl warp::reject::Reject for AuthRejection {}

impl From<AuthorizationError> for AuthRejection {
    fn from(error: AuthorizationError) -> Self {
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
            let encoded = FormEncoded::encode(e);
            let reply = warp::reply::with_status(encoded, warp::http::StatusCode::BAD_REQUEST);
            Ok(reply)
        }
        _ => Err(err),
    }
}
