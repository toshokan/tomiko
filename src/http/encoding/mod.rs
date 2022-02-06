pub mod error;
pub mod reply;

use crate::auth::ClientCredentials;
use crate::core::types::{BearerToken, ClientId, ClientSecret};
use crate::provider::error::Error;
use http_basic_auth::Credential as BasicCredentials;
use warp::{Filter, Rejection};

use self::error::AuthRejection;

#[derive(serde::Deserialize)]
pub struct WithCredentials<T> {
    #[serde(flatten)]
    credentials: ClientCredentials,
    #[serde(flatten)]
    body: T,
}

impl<T> From<(BasicCredentials, T)> for WithCredentials<T> {
    fn from((credentials, value): (BasicCredentials, T)) -> Self {
        let credentials = ClientCredentials {
            client_id: ClientId(credentials.user_id),
            client_secret: ClientSecret(credentials.password),
        };

        Self::join(credentials, value)
    }
}

impl<T> WithCredentials<T> {
    pub fn join(credentials: ClientCredentials, body: T) -> Self {
        Self { credentials, body }
    }
    pub fn split(self) -> (ClientCredentials, T) {
        (self.credentials, self.body)
    }
}

pub fn body_with_credentials<T: serde::de::DeserializeOwned + Send>(
) -> impl Filter<Extract = ((ClientCredentials, T),), Error = Rejection> + Clone {
    let basic = warp::header::<BasicCredentials>("Authorization")
        .and(warp::body::form::<T>())
        .map(|c, b| (c, b).into());
    let body = warp::body::form::<WithCredentials<T>>();
    basic
        .or(body)
        .unify()
        .or_else(|_| async move { Err(warp::reject::custom(AuthRejection::Unauthorized)) })
        .map(|w: WithCredentials<T>| w.split())
}

pub fn bearer() -> impl Filter<Extract = (BearerToken,), Error = Rejection> + Clone {
    warp::header("Authorization").and_then(|s: String| async move {
        let token = match s.split_once("Bearer ") {
            Some(("", token)) => Ok(token.to_string()),
            _ => Err(Error::Unauthorized),
        };
        reply::accept(token).map(|t| BearerToken(t))
    })
}
