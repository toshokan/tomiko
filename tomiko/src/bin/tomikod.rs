use tomiko_core::types::AuthCode;
use tomiko_auth::{AuthenticationCodeFlow,
		  AuthorizationRequest, AuthorizationResponse, AuthorizationError,
		  TokenRequest, AccessTokenResponse, AccessTokenError};
use tomiko_util::random::FromRandom;

use tomiko_http::server::Server;
use async_trait::async_trait;

#[derive(Default)]
struct OAuthDriver;

#[async_trait]
impl AuthenticationCodeFlow for OAuthDriver {
    async fn authorization_request(&self, req: AuthorizationRequest) -> Result<AuthorizationResponse, AuthorizationError> {
	let code = AuthCode::from_random();
	let response = AuthorizationResponse::new(code, req.state);
	Ok(response)
    }

    async fn access_token_request<T>(&self, req: TokenRequest) -> Result<AccessTokenResponse<T>, AccessTokenError> {
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
