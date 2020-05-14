use tomiko_http::server::Server;

use async_trait::async_trait;

struct Dummy;

#[async_trait]
impl tomiko_auth::AuthenticationCodeFlow for Dummy {
    async fn authorization_request(req: tomiko_auth::AuthorizationRequest) -> Result<tomiko_auth::AuthorizationResponse, tomiko_auth::AuthorizationError> {
	panic!("Yo")
    }

    async fn access_token_request<T>(req: tomiko_auth::TokenRequest) -> Result<tomiko_auth::AccessTokenResponse<T>, tomiko_auth::AccessTokenError> {
	panic!("Yo2")
    }
}

async fn tomikod() -> Option<()> {
    let dummy = Dummy;
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
