use tomiko_auth::{AuthorizationRequest, AuthorizationError, AccessTokenError, AuthenticationCodeFlow};
use tomiko_auth::TokenRequest;
use super::FormEncoded;

use warp::{Filter, Reply, Rejection};
use std::sync::Arc;

#[derive(Debug, Clone)]
#[derive(serde::Serialize)]
#[serde(untagged)]
enum AuthRejection {
    Authorization(AuthorizationError),
    AccessToken(AccessTokenError)
}

impl warp::reject::Reject for AuthRejection {}


#[derive(Debug, Clone)]
pub struct Server<T> {
    driver: T
}

impl<T> Server<T> {
    pub fn new(driver: T) -> Self {
	Self {
	    driver
	}
    }

    async fn handle_reject(err: Rejection) -> Result<impl Reply, Rejection> {
	if let Some(e) = err.find::<AuthRejection>() {
	    let encoded = FormEncoded::encode(e.clone()).unwrap();
	    let reply = warp::reply::with_status(encoded, warp::http::StatusCode::BAD_REQUEST);
	    Ok(reply)
	} else if let Some(e) = err.find::<warp::reject::InvalidQuery>() {
	    unimplemented!("Error handling for deserialize") // TODO
	} else {
	    Err(err)
	}
    }
}

struct ClientPassword {
    client_id: String,
    client_secret: String
}

fn basic_auth() -> impl Filter<Extract = (Option<ClientPassword>,), Error = std::convert::Infallible> + Clone {
    let with_header =
	warp::header("Authorization")
    	.map(|tok: String| -> Option<ClientPassword> {
	    eprintln!("{:?}", tok);
	    None
	});
    let header_missing = warp::any().map(|| None);
    
    warp::any().and(with_header.or(header_missing)).unify()
}

impl<T: AuthenticationCodeFlow + Send + Sync + 'static> Server<T> {
    async fn authenticate(driver: &T, req: AuthorizationRequest) -> Result<impl Reply, Rejection> {
	let result = driver.authorization_request(req).await;
	match result {
	    Ok(result) => {
		let encoded = FormEncoded::encode(result).unwrap(); // TODO
		Ok(encoded)
	    },
	    Err(e) => Err(warp::reject::custom(AuthRejection::Authorization(e)))
	}
    }

    async fn token_request(driver: &T, pw: ClientPassword, req: TokenRequest) -> Result<impl Reply, Rejection> {
	let result = driver.access_token_request::<String>(req).await;
	match result {
	    Ok(result) => {
		let encoded = FormEncoded::encode(result).unwrap(); // TODO
		Ok(encoded)
	    },
	    Err(e) => Err(warp::reject::custom(AuthRejection::AccessToken(e)))
	}
    }
    
    pub async fn serve(self) -> Option<()> {
	let driver = Arc::new(self.driver);

	let with_driver = warp::any().map(move || driver.clone());
	
	let oauth = warp::path("oauth");
	let auth = warp::path("authenticate")
	    .and(with_driver.clone())
	    .and(warp::filters::query::query())
	    .and_then(|driver: Arc<T>, req: AuthorizationRequest| async move {
	    	Self::authenticate(&driver, req).await
	    });

	let token = warp::path("token")
	    .and(with_driver.clone())
	    .and(client_auth())
	    .and(warp::filters::query::query())
	    .and_then(|driver: Arc<T>, pass: ClientPassword, req: TokenRequest| async move {
		Self::token_request(&driver, pass, req).await
	    });

	let routes = oauth
	    .and(warp::path("v1"))
	    .and(auth.or(token))
	    .recover(Self::handle_reject);
	
	warp::serve(routes)
	    .run(([127, 0, 0, 1], 8001))
	    .await;
	
	Some(())
    }
}
