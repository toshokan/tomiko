use tomiko_auth::{
    AccessTokenError, AccessTokenResponse, AuthenticationCodeFlow, AuthorizationError,
    AuthorizationRequest, AuthorizationResponse, ClientCredentials, HashingService, TokenRequest,
};
use tomiko_core::types::{AuthCode, ClientId, RedirectUri};
use tomiko_util::random::FromRandom;

use async_trait::async_trait;
use tomiko_db::{DbStore, Store};
use tomiko_http::server::Server;

#[derive(Debug)]
struct OAuthDriver {
    store: DbStore,
    hasher: HashingService,
}

impl OAuthDriver {
    async fn validate_client(
        &self,
        client_id: &ClientId,
        redirect_uri: &RedirectUri,
        state: &Option<String>,
    ) -> Result<(), AuthorizationError> {
        self.store
            .check_client_uri(client_id, redirect_uri)
            .await
            .map_err(|_| AuthorizationError::unauthorized_client(state))?;

        Ok(())
    }
}

#[async_trait]
impl AuthenticationCodeFlow for OAuthDriver {
    async fn check_client_auth(&self, credentials: ClientCredentials) -> Result<ClientId, ()> {
        let client = self.store.get_client(&credentials.client_id).await?;

        let result = self
            .hasher
            .verify(&credentials.client_secret, &client.secret)
            .map_err(|_| ())?;

        if result {
            Ok(client.id)
        } else {
            Err(())
        }
    }

    async fn authorization_request(
        &self,
        req: AuthorizationRequest,
    ) -> Result<AuthorizationResponse, AuthorizationError> {
        self.validate_client(&req.client_id, &req.redirect_uri, &req.state)
            .await?;

        let code = AuthCode::from_random();
        let code = self
            .store
            .store_code(&req.client_id, code, &req.state, &req.redirect_uri)
            .await
            .map_err(|_| AuthorizationError::server_error(&req.state))?;
        let response = AuthorizationResponse::new(code, req.state);
        Ok(response)
    }

    async fn access_token_request<T>(
        &self,
        _client: ClientId,
        _req: TokenRequest,
    ) -> Result<AccessTokenResponse<T>, AccessTokenError> {
        dbg!(_req, _client);
        panic!("access_token_req")
    }

    async fn create_client(&self, credentials: ClientCredentials) -> Result<ClientId, ()> {
        let hashed = self.hasher.hash(&credentials.client_secret)?;
        let client = self.store.put_client(credentials.client_id, hashed).await?;
        Ok(client.id)
    }
}

async fn tomikod(config: Config) -> Option<()> {
    let store = DbStore::acquire(&config.database_url).await.ok()?;
    let hasher = HashingService::with_secret_key(config.hash_secret);

    let driver = OAuthDriver { store, hasher };

    let server = Server::new(driver);
    server.serve().await;
    Some(())
}

#[derive(Debug)]
pub struct Config {
    database_url: String,
    hash_secret: String,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            database_url: std::env::var("DATABASE_URL").expect("Supply DATABASE_URL"),
            hash_secret: std::env::var("HASH_SECRET").expect("Supply HASH_SECRET"),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), ()> {
    dotenv::dotenv().ok();
    let config = Config::from_env();
    tomikod(config).await.ok_or(())
}
