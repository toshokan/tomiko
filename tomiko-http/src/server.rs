use super::FormEncoded;
use tomiko_auth::{AccessTokenError, AuthorizationError, ClientCredentials, Provider};
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

fn form_encode(
    value: Result<impl serde::Serialize, impl Into<AuthRejection>>,
) -> Result<impl Reply, Rejection> {
    value
        .map(|v| FormEncoded::encode(v))
        .map_err(|e| warp::reject::custom::<AuthRejection>(e.into()))
}

impl warp::reject::Reject for AuthRejection {}

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

#[derive(Debug)]
pub struct Server<P> {
    provider: Arc<P>,
}

fn body_with_credentials<T: serde::de::DeserializeOwned + Send>(
) -> impl Filter<Extract = ((ClientCredentials, T),), Error = Rejection> + Clone {
    let basic = warp::header::<BasicCredentials>("Authorization")
        .and(warp::body::form::<T>())
        .map(|c, b| (c, b).into());
    let body = warp::body::form::<WithCredentials<T>>();
    basic
        .or(body)
        .unify()
        .map(|w: WithCredentials<T>| w.split())
}

impl<P: Provider + Send + Sync + 'static> Server<P> {
    pub fn new(provider: P) -> Self {
        Self {
            provider: Arc::new(provider),
        }
    }

    pub async fn serve(self) -> Option<()> {
        let provider = self.provider;

        let oauth = warp::path("oauth");
        let with_provider = warp::any().map(move || provider.clone());

        let authenticate = warp::path("authenticate")
            .and(with_provider.clone())
            .and(warp::filters::query::query())
            .and_then(|provider: Arc<P>, req| async move {
                // warp::http::Response::builder()
                //     .header("Location", "http://localhost:8002/login.html?sid=test123")
                //     .status(307)
                //     .body(warp::hyper::Body::empty())
                let result = provider.authorization_request(req).await;
                form_encode(result)
            });

        let token_request = warp::path("token")
            .and(warp::post())
            .and(with_provider.clone())
            .and(body_with_credentials())
            .and_then(|provider: Arc<P>, (credentials, req)| async move {
                let result = provider.access_token_request(credentials, req).await;
                form_encode(result)
            });

        // let next = warp::path("continue")
        //     .and(warp::path::param())
        //     .and(warp::path::end())
        //     .and(with_state.clone())
        //     .and(self.with_driver())
        //     .and_then(
        //         |sid: String,
        //          state: Arc<Mutex<HashMap<String, (AuthorizationRequest, bool)>>>,
        //          driver: Arc<T>| async move {
        //             let (req, auth) = {
        //                 let mut state = state.lock().unwrap();
        //                 state.remove(&sid).unwrap()
        //             };

        //             if auth {
        //                 Self::authenticate(&driver, req).await
        //             } else {
        //                 Err(warp::reject())
        //             }
        //         },
        //     );

        // let check = warp::post()
        //     .and(warp::path("check_auth"))
        //     .and(warp::body::form())
        //     .and(with_state.clone())
        //     .and_then(
        //         |req: CheckAuthRequest,
        //          state: Arc<Mutex<HashMap<String, (AuthorizationRequest, bool)>>>| async move {
        //             let svc = CheckAuthService;
        //             let result = svc.check_credentials(&req).await;
        //             let mut state = state.lock().unwrap();
        //             state.entry(req.sid.clone()).and_modify(|e| e.1 = result);

        //             if result {
        //                 let resp = warp::http::Response::builder()
        //                     .header("Location", format!("/continue/{}", &req.sid))
        //                     .status(307)
        //                     .body(warp::hyper::Body::empty());
        //                 Ok(resp)
        //             } else {
        //                 Err(warp::reject())
        //             }
        //         },
        //     );

        let routes = oauth
            .and(warp::path("v1"))
            .and(authenticate.or(token_request));
        // .and(authenticate.or(token_request).or(make_client));
        // .recover(Self::handle_reject);

        // warp::serve(check.or(next).or(routes))
        warp::serve(routes).run(([127, 0, 0, 1], 8001)).await;

        Some(())
    }
}

// struct CheckAuthService;

// #[derive(serde::Deserialize)]
// struct CheckAuthRequest {
//     username: String,
//     password: String,
//     sid: String,
// }

// impl CheckAuthService {
//     async fn check_credentials(&self, req: &CheckAuthRequest) -> bool {
//         req.password == "test"
//     }
// }
