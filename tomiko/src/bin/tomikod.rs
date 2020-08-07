use tomiko_auth::{
    AccessTokenError, AccessTokenErrorKind, AccessTokenResponse, AuthorizationError,
    AuthorizationRequest, AuthorizationResponse, ClientCredentials, Store, TokenRequest,
};
use tomiko_core::models::{AuthCodeData, Client};
use tomiko_core::types::{AuthCode, ClientId, RedirectUri};
use tomiko_util::{hash::HashingService, random::FromRandom};

use async_trait::async_trait;
use std::sync::Arc;
use tomiko_db::DbStore;
use tomiko_http::server::Server;

#[derive(Debug)]
struct OAuth2Provider {
    store: DbStore,
    hasher: HashingService,
}

impl OAuth2Provider {
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

    async fn check_client_authentication(
        &self,
        cred: &ClientCredentials,
    ) -> Result<Client, AccessTokenError> {
        let client = self.store.get_client(&cred.client_id).await;

        if let Ok(Some(c)) = client {
            let result = self
                .hasher
                .verify(&cred.client_secret, &c.secret)
                .expect("Failed to hash");
            if result {
                return Ok(c);
            }
        }

        Err(AccessTokenError {
            kind: AccessTokenErrorKind::InvalidClient,
            description: Some("Bad authentication".to_string()),
            uri: None,
        })
    }

    async fn start_clean_up_worker(&self) -> Result<(), ()> {
        use std::time::Duration;
        use tokio::{stream::StreamExt, time::interval};

        let mut interval = interval(Duration::from_secs(15));

        while let Some(_x) = interval.next().await {
            self.store.clean_up().await?
        }

        Ok(())
    }
}

use tomiko_auth::Provider;

#[async_trait]
impl Provider for OAuth2Provider {
    async fn authorization_request(
        &self,
        req: AuthorizationRequest,
    ) -> Result<AuthorizationResponse, AuthorizationError> {
        self.validate_client(&req.client_id, &req.redirect_uri, &req.state)
            .await?;
        let state = req.state.clone();

        let code = AuthCode::from_random();

        let data = AuthCodeData {
            client_id: req.client_id,
            code,
            state: req.state,
            redirect_uri: req.redirect_uri,
            scope: Some(req.scope), // TODO
        };

        let expiry = std::time::SystemTime::now()
            .checked_add(std::time::Duration::from_secs(10 * 60))
            .unwrap();

        let data = self
            .store
            .store_code(data, expiry)
            .await
            .map_err(|_| AuthorizationError::server_error(&state))?;

        let response = AuthorizationResponse::new(data.code, data.state);
        Ok(response)
    }

    async fn access_token_request(
        &self,
        credentials: ClientCredentials,
        req: TokenRequest,
    ) -> Result<AccessTokenResponse, AccessTokenError> {
        let client = self.check_client_authentication(&credentials).await?;

        let data = self
            .store
            .get_authcode_data(&client.id, &req.code)
            .await
            .map_err(|_| AccessTokenErrorKind::InvalidGrant)?;

        if &data.redirect_uri == &req.redirect_uri {
            Ok(AccessTokenResponse {
                access_token: "TOKEN_SAMPLE".to_string(),
                token_type: "SAMPLE".to_string(),
                refresh_token: None,
                expires_in: None,
                scope: data.scope,
            })
        } else {
            Err(AccessTokenErrorKind::InvalidGrant.into())
        }
    }
}

async fn tomikod(config: Config) -> Option<()> {
    let store = DbStore::acquire(&config.database_url).await.ok()?;
    let hasher = HashingService::with_secret_key(config.hash_secret);

    let provider = Arc::new(OAuth2Provider { store, hasher });

    let _clean_up = {
        let provider = Arc::clone(&provider);
        tokio::spawn(async move { provider.start_clean_up_worker().await });
    };

    let server = Server::new(provider);
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
    tracing_subscriber::fmt::init();
    dotenv::dotenv().ok();
    let config = Config::from_env();
    tomikod(config).await.ok_or(())
}
