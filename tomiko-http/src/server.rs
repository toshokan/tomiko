use super::FormEncoded;
use tomiko_auth::{
    AccessTokenError, AuthenticationCodeFlow, AuthorizationError, AuthorizationRequest,
    ClientCredentials, TokenRequest,
};
use tomiko_core::types::{ClientId, ClientSecret};
use tomiko_core::models::Client;

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
        let result = driver.access_token_request(client, req).await;
        match result {
            Ok(result) => {
                let encoded = FormEncoded::encode(result).unwrap(); // TODO
                Ok(encoded)
            }
            Err(e) => Err(warp::reject::custom(AuthRejection::AccessToken(e))),
        }
    }

    fn with_driver(
        &self,
    ) -> impl Filter<Extract = (Arc<T>,), Error = std::convert::Infallible> + Clone {
        let driver = self.driver.clone();
        warp::any().map(move || driver.clone())
    }

    fn request_auth<B: serde::de::DeserializeOwned + Send>(
        &self,
    ) -> impl Filter<Extract = ((Client, B),), Error = Rejection> + Clone {
        let basic = warp::header::<BasicCredentials>("Authorization")
            .and(warp::body::form::<B>())
            .map(|contents: BasicCredentials, f: B| {
                let credentials = ClientCredentials {
                    client_id: ClientId(contents.user_id),
                    client_secret: ClientSecret(contents.password),
                };
                BodyClientCredentials::join(credentials, f)
            });
        let from_body = warp::body::form::<BodyClientCredentials<B>>();

        basic
            .or(from_body)
            .unify()
            .and(self.with_driver())
            .and_then(|bcc: BodyClientCredentials<B>, driver: Arc<T>| async move {
                let (credentials, body) = bcc.split();

                driver
                    .check_client_auth(credentials)
                    .await
                    .map(|id| (id, body))
                    .map_err(|_| warp::reject())
            })
    }

    pub async fn serve(self) -> Option<()> {
	use std::collections::HashMap;
	use std::sync::Mutex;
	
        let oauth = warp::path("oauth");
	let state: Arc<Mutex<HashMap<String, (AuthorizationRequest, bool)>>> = Arc::new(std::sync::Mutex::new(HashMap::new()));

	let with_state = warp::any().map(move || state.clone());

        let authenticate = warp::path("authenticate")
            .and(self.with_driver())
            .and(warp::filters::query::query())
	    .and(with_state.clone())
            .map(|driver: Arc<T>, req: AuthorizationRequest, state: Arc<Mutex<HashMap<String, _>>>| {
		let mut map = state.lock().unwrap();
		map.insert("test123".to_string(), (req, false));
		
		warp::http::Response::builder()
		    .header("tomiko-sid", "test123")
		    .header("Location", "http://localhost:8002/login.html")
		    .status(307)
		    .body(warp::hyper::Body::empty())
                // Self::authenticate(&driver, req).await
            });

        let token_request = warp::path("token")
            .and(warp::post())
            .and(self.with_driver())
            .and(self.request_auth())
            .and_then(
                |driver: Arc<T>, (client, req): (Client, TokenRequest)| async move {
                    Self::token_request(&driver, client.id, req).await
                },
            );

        let make_client = warp::path("client")
            .and(self.with_driver())
            .and(warp::query::<ClientCredentials>())
            .and_then(|driver: Arc<T>, credentials| async move {
                driver
                    .create_client(credentials)
                    .await
                    .map_err(|_| warp::reject())
                    .map(|c| warp::reply::html(format!("{:?}", c)))
            });

	let next = warp::path("continue")
	    .and(warp::path::param())
	    .and(warp::path::end())
	    .and(with_state.clone())
	    .and(self.with_driver())
	    .and_then(|sid: String, state: Arc<Mutex<HashMap<String, (AuthorizationRequest, bool)>>>, driver: Arc<T>| async move {
		let (req, auth) = {
		    let mut state = state.lock().unwrap();
		    state.remove(&sid).unwrap()
		};
		
		if auth {
		    Self::authenticate(&driver, req)
			.await
		} else {
		    Err(warp::reject())
		}
	    });

	let check = warp::post()
	    .and(warp::path("check_auth"))
	    .and(warp::body::form())
	    .and(with_state.clone())
	    .and_then(|req: CheckAuthRequest, state: Arc<Mutex<HashMap<String, (AuthorizationRequest, bool)>>>| async move {
		let svc = CheckAuthService;
		let result = svc.check_credentials(&req)
		    .await;
		let mut state = state.lock().unwrap();
		state.entry(req.sid.clone()).and_modify(|e| e.1 = result);

		if result {
                   let resp = warp::http::Response::builder()
                       .header("Location", format!("/continue/{}", &req.sid))
                       .status(307)
                       .body(warp::hyper::Body::empty());
                   Ok(resp)
               } else {
                   Err(warp::reject())
               }
	    });

        let routes = oauth
            .and(warp::path("v1"))
            .and(authenticate.or(token_request).or(make_client))
            .recover(Self::handle_reject);

        warp::serve(check.or(next).or(routes)).run(([127, 0, 0, 1], 8001)).await;

        Some(())
    }
}

struct CheckAuthService;

#[derive(serde::Deserialize)]
struct CheckAuthRequest {
    username: String,
    password: String,
    sid: String
}

impl CheckAuthService {
    async fn check_credentials(&self, req: &CheckAuthRequest) -> bool {
	req.password == "test"
    }
}
