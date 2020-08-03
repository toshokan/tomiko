use super::FormEncoded;
use futures::future;
use tomiko_auth::{
    AccessTokenError, AuthenticationCodeFlow, AuthorizationError, AuthorizationRequest,
};
use tomiko_auth::{ClientCredentials, HashedClientCredentials, HashingService, TokenRequest};
use tomiko_core::types::{ClientId, ClientSecret};

use std::sync::Arc;
use warp::{Filter, Rejection, Reply};

use http_basic_auth::Credential as BasicCredentials;

#[derive(Debug, Clone, serde::Serialize)]
#[serde(untagged)]
enum AuthRejection {
    Authorization(AuthorizationError),
    AccessToken(AccessTokenError),
}

impl warp::reject::Reject for AuthRejection {}

#[derive(serde::Deserialize)]
pub struct BodyClientCredentials<T> {
    #[serde(flatten)]
    credentials: ClientCredentials,
    #[serde(flatten)]
    body: T,
}

impl<T> BodyClientCredentials<T> {
    pub fn join(credentials: ClientCredentials, body: T) -> Self {
        Self { credentials, body }
    }
    pub fn split(self) -> (ClientCredentials, T) {
        (self.credentials, self.body)
    }
}

macro_rules! request_auth {
    ($with_driver: ident, $ty: ident) => {{
	let basic =
	    warp::header::<BasicCredentials>("Authorization")
	    .and(warp::body::form::<$ty>())
	    .map(|contents: BasicCredentials, f: $ty| {
		let credentials = ClientCredentials {
		    client_id: ClientId(contents.user_id),
		    client_secret: ClientSecret(contents.password),
		};
		BodyClientCredentials::join(credentials, f)
	    });
	let from_body = warp::body::form::<BodyClientCredentials<$ty>>();

	basic
	    .or(from_body)
	    .unify()
	    .and($with_driver.clone())
	    .and_then(|bcc: BodyClientCredentials<$ty>, driver: Arc<T>| async move {
		let (credentials, body) = bcc.split();
		
		let result = driver
		    .check_client_auth(credentials)
		    .await
		    .map(|id| (id, body))
		    .map_err(|_| warp::reject());
		result
	    })
    }}
}

#[derive(Debug, Clone)]
pub struct Server<T> {
    driver: Arc<T>,
}

impl<T> Server<T> {
    pub fn new(driver: T) -> Self {
        Self {
            driver: Arc::new(driver),
        }
    }

    async fn handle_reject(err: Rejection) -> Result<impl Reply, Rejection> {
        match err.find::<AuthRejection>() {
            Some(e) => {
                let encoded = FormEncoded::encode(e.clone()).unwrap();
                let reply = warp::reply::with_status(encoded, warp::http::StatusCode::BAD_REQUEST);
                Ok(reply)
            }
            _ => Err(err),
        }
    }
}

impl<T: AuthenticationCodeFlow + Send + Sync + 'static> Server<T> {
    async fn authenticate(driver: &T, req: AuthorizationRequest) -> Result<impl Reply, Rejection> {
        let result = driver.authorization_request(req).await;
        match result {
            Ok(result) => {
                let encoded = FormEncoded::encode(result).unwrap(); // TODO
                Ok(encoded)
            }
            Err(e) => Err(warp::reject::custom(AuthRejection::Authorization(e))),
        }
    }

    async fn token_request(
        driver: &T,
        client: ClientId,
        req: TokenRequest,
    ) -> Result<impl Reply, Rejection> {
        let result = driver.access_token_request::<String>(client, req).await;
        match result {
            Ok(result) => {
                let encoded = FormEncoded::encode(result).unwrap(); // TODO
                Ok(encoded)
            }
            Err(e) => Err(warp::reject::custom(AuthRejection::AccessToken(e))),
        }
    }

    pub async fn serve(self) -> Option<()> {
	let driver = self.driver.clone();
	
        let with_driver = warp::any().map(move || driver.clone());

        let oauth = warp::path("oauth");

        let authenticate = warp::path("authenticate")
            .and(with_driver.clone())
            .and(warp::filters::query::query())
            .and_then(|driver: Arc<T>, req: AuthorizationRequest| async move {
                Self::authenticate(&driver, req).await
            });

        let token_request = warp::path("token")
            .and(warp::post())
            .and(with_driver.clone())
	    .and(request_auth!(with_driver, TokenRequest))
            .and_then(|driver: Arc<T>, (client_id, req)| async move {
                Self::token_request(&driver, client_id, req).await
            });

        let make_client = warp::path("client")
            .and(with_driver.clone())
            .and(warp::query::<ClientCredentials>())
            .and_then(|driver: Arc<T>, credentials| async move {
                driver
                    .create_client(credentials)
                    .await
                    .map_err(|_| warp::reject())
                    .map(|c| warp::reply::html(format!("{:?}", c)))
            });

        let routes = oauth
            .and(warp::path("v1"))
            .and(authenticate.or(token_request).or(make_client))
            .recover(Self::handle_reject);

        warp::serve(routes).run(([127, 0, 0, 1], 8001)).await;

        Some(())
    }
}
