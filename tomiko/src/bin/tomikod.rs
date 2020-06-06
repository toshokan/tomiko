use tomiko_core::types::{AuthCode, ClientId, RedirectUri};
use tomiko_auth::{AuthenticationCodeFlow,
		  AuthorizationRequest, AuthorizationResponse, AuthorizationError, AuthorizationErrorKind,
		  TokenRequest, AccessTokenResponse, AccessTokenError};
use tomiko_util::random::FromRandom;

use tomiko_http::server::Server;
use tomiko_db::{Store, DbStore};
use async_trait::async_trait;

#[derive(Debug)]
struct OAuthDriver {
    store: DbStore
}

impl OAuthDriver {
    async fn validate_client(&self, client_id: &ClientId, redirect_uri: &RedirectUri, state: &str) -> Result<(), AuthorizationError> {
	if let Err(_) = self.store.check_client_uri(client_id, redirect_uri).await {
	    let error = AuthorizationError {
	    	kind: AuthorizationErrorKind::UnauthorizedClient,
		description: None,
		uri: None,
		state: Some(state.to_owned())
	    };
	    return Err(error);
	}

	Ok(())
    }
}

#[async_trait]
impl AuthenticationCodeFlow for OAuthDriver {
    async fn authorization_request(&self, req: AuthorizationRequest) -> Result<AuthorizationResponse, AuthorizationError> {
	self.validate_client(&req.client_id, &req.redirect_uri, &req.state).await?;
	
	let code = AuthCode::from_random();
	let code = self.store.store_code(&req.client_id, code, &req.state).await.map_err(|_| {
	    AuthorizationError::server_error(req.state.clone())
	})?;
	let response = AuthorizationResponse::new(code, req.state);
	Ok(response)
    }

    async fn access_token_request<T>(&self, _req: TokenRequest) -> Result<AccessTokenResponse<T>, AccessTokenError> {
	panic!("access_token_req")
    }
}

async fn tomikod() -> Option<()> {
    let uri = std::env::var("DATABASE_URL")
	.expect("Supply a DATABASE_URL");
    
    let store = DbStore::acquire(&uri).await.ok()?;
    let driver = OAuthDriver {
	store
    };
    let server = Server::new(driver);
    server.serve().await;
    Some(())
}

#[tokio::main]
async fn main() -> Result<(), ()> {
    dotenv::dotenv().ok();
    
    tomikod()
	.await
	.ok_or(())
}
