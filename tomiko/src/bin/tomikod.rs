use tomiko_auth::{
    AccessTokenError, AccessTokenErrorKind, AccessTokenResponse, AuthorizationError,
    AuthorizationRequest, AuthorizationResponse, ClientCredentials, Store, TokenRequest,
};
use tomiko_core::models::{AuthCodeData, Client};
use tomiko_core::types::{AuthCode, ClientId, RedirectUri};
use tomiko_util::{hash::HashingService, random::FromRandom};

use async_trait::async_trait;
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
}

use tomiko_auth::Provider;

#[async_trait]
impl Provider for OAuth2Provider {
    async fn authorization_request(&self, req: AuthorizationRequest) -> Result<AuthorizationResponse, AuthorizationError> {
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

    async fn access_token_request(&self, _credentials: ClientCredentials, _req: TokenRequest) -> Result<AccessTokenResponse, AccessTokenError> {
	unimplemented!();
	
	// let data = self
        //     .store
        //     .get_authcode_data(&client_id, &req.code)
        //     .await
        //     .map_err(|_| AccessTokenError {
        //         kind: AccessTokenErrorKind::InvalidGrant,
        //         description: None,
        //         uri: None,
        //     })?;

        // if &data.redirect_uri == &req.redirect_uri {
        //     Ok(AccessTokenResponse {
        //         access_token: "TOKEN_SAMPLE".to_string(),
        //         token_type: "SAMPLE".to_string(),
        //         refresh_token: None,
        //         expires_in: None,
        //         scope: data.scope,
        //     })
        // } else {
        //     Err(AccessTokenError {
        //         kind: AccessTokenErrorKind::InvalidGrant,
        //         description: None,
        //         uri: None,
        //     })
        // }
    }
}

// #[async_trait]
// impl AuthenticationCodeFlow for OAuthDriver {
//     async fn check_client_auth(&self, credentials: ClientCredentials) -> Result<Client, ()> {
//         let client = self.store.get_client(&credentials.client_id).await?;

//         let result = self
//             .hasher
//             .verify(&credentials.client_secret, &client.secret)
//             .map_err(|_| ())?;

//         if result {
//             Ok(client)
//         } else {
//             Err(())
//         }
//     }

//     async fn authorization_request(
//         &self,
//         req: AuthorizationRequest,
//     ) -> Result<AuthorizationResponse, AuthorizationError> {
//         self.validate_client(&req.client_id, &req.redirect_uri, &req.state)
//             .await?;
//         let state = req.state.clone();

//         let code = AuthCode::from_random();

//         let data = AuthCodeData {
//             client_id: req.client_id,
//             code,
//             state: req.state,
//             redirect_uri: req.redirect_uri,
//             scope: Some(req.scope), // TODO
//         };

//         let expiry = std::time::SystemTime::now()
//             .checked_add(std::time::Duration::from_secs(10 * 60))
//             .unwrap();

//         let data = self
//             .store
//             .store_code(data, expiry)
//             .await
//             .map_err(|_| AuthorizationError::server_error(&state))?;

//         let response = AuthorizationResponse::new(data.code, data.state);
//         Ok(response)
//     }

//     async fn access_token_request(
//         &self,
//         client_id: ClientId,
//         req: TokenRequest,
//     ) -> Result<AccessTokenResponse, AccessTokenError> {
//         let data = self
//             .store
//             .get_authcode_data(&client_id, &req.code)
//             .await
//             .map_err(|_| AccessTokenError {
//                 kind: AccessTokenErrorKind::InvalidGrant,
//                 description: None,
//                 uri: None,
//             })?;

//         if &data.redirect_uri == &req.redirect_uri {
//             Ok(AccessTokenResponse {
//                 access_token: "TOKEN_SAMPLE".to_string(),
//                 token_type: "SAMPLE".to_string(),
//                 refresh_token: None,
//                 expires_in: None,
//                 scope: data.scope,
//             })
//         } else {
//             Err(AccessTokenError {
//                 kind: AccessTokenErrorKind::InvalidGrant,
//                 description: None,
//                 uri: None,
//             })
//         }
//     }

//     async fn create_client(&self, credentials: ClientCredentials) -> Result<Client, ()> {
//         let hashed = self.hasher.hash(&credentials.client_secret)?;
//         let client = self.store.put_client(credentials.client_id, hashed).await?;
//         Ok(client)
//     }
// }

async fn tomikod(config: Config) -> Option<()> {
    let store = DbStore::acquire(&config.database_url).await.ok()?;
    let hasher = HashingService::with_secret_key(config.hash_secret);

    let driver = OAuth2Provider { store, hasher };

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
