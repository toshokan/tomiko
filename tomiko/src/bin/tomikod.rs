use tomiko_auth::{AuthenticationCodeFlow,
		  AuthorizationRequest, AuthorizationResponse, AuthorizationError,
		  TokenRequest, AccessTokenResponse, AccessTokenError};

use tomiko_http::server::Server;

use async_trait::async_trait;

#[derive(Default)]
struct OAuthDriver;

#[async_trait]
impl AuthenticationCodeFlow for OAuthDriver {
    async fn authorization_request(req: AuthorizationRequest) -> Result<AuthorizationResponse, AuthorizationError> {
	panic!("auth_req")
    }

    async fn access_token_request<T>(req: TokenRequest) -> Result<AccessTokenResponse<T>, AccessTokenError> {
	panic!("access_token_req")
    }
}

async fn tomikod() -> Option<()> {
    let dummy = OAuthDriver;
    let server = Server::new(dummy);
    server.serve().await;
    Some(())
}

#[tokio::main]
async fn main() -> Result<(), ()> {
    tomikod()
	.await
	.ok_or(())
}
