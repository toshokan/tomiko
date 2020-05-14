use tomiko_core::types::{AuthCode, ClientId, RedirectUri};
use tomiko_auth::{AuthenticationCodeFlow,
		  AuthorizationRequest, AuthorizationResponse, AuthorizationError, AuthorizationErrorKind,
		  TokenRequest, AccessTokenResponse, AccessTokenError};
use tomiko_util::random::FromRandom;

use tomiko_http::server::Server;
use async_trait::async_trait;

#[derive(Default)]
struct OAuthDriver;

impl OAuthDriver {
    async fn validate_client(_client_id: &ClientId, _redirect_uri: &RedirectUri, state: &str) -> Result<(), AuthorizationError> {
	if false {
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
	Self::validate_client(&req.client_id, &req.redirect_uri, &req.state).await?;
	
	let code = AuthCode::from_random();
	let response = AuthorizationResponse::new(code, req.state);
	Ok(response)
    }

    async fn access_token_request<T>(&self, _req: TokenRequest) -> Result<AccessTokenResponse<T>, AccessTokenError> {
	panic!("access_token_req")
    }
}

async fn tomikod() -> Option<()> {
    let server = Server::new(OAuthDriver::default());
    server.serve().await;
    Some(())
}

#[tokio::main]
async fn main() -> Result<(), ()> {
    tomikod()
	.await
	.ok_or(())
}
