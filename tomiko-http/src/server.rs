use tomiko_auth::{AuthorizationRequest, AuthenticationCodeFlow};

use warp::Filter;
use std::sync::Arc;

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
}

fn with<T: Clone + Send>(t: T) -> impl Filter<Extract = (T,), Error = std::convert::Infallible> + Clone{
    warp::any().map(move || t.clone())
}

impl<T: AuthenticationCodeFlow + Send + Sync + 'static> Server<T> {
    async fn authenticate(driver: &T, req: AuthorizationRequest) -> Result<String, warp::Rejection> {
	Ok(format!("{:#?}", req))
    }
    
    pub async fn serve(self) -> Option<()> {
	let driver = Arc::new(self.driver);
	
	let oauth = warp::path("oauth");
	let auth = warp::path("authenticate")
	    .and(with(driver.clone()))
	    .and(warp::filters::query::query())
	    .and_then(|driver: Arc<T>, req: AuthorizationRequest| async move {
		Self::authenticate(&driver, req).await
	    });

	let routes = oauth
	    .and(warp::path("v1"))
	    .and(auth);
	
	warp::serve(routes)
	    .run(([127, 0, 0, 1], 8001))
	    .await;
	Some(())
    }
}
