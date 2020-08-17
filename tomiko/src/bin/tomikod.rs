use tomiko_auth::{
    AccessTokenError, AccessTokenErrorKind, AccessTokenResponse, AuthorizationError,
    AuthorizationRequest, AuthorizationResponse, ClientCredentials, Store, TokenRequest,
};
use tomiko_core::models::{AuthCodeData, Client};
use tomiko_core::types::{AuthCode, ClientId, RedirectUri, Scope};
use tomiko_util::{hash::HashingService, random::FromRandom};

use async_trait::async_trait;
use std::sync::Arc;
use tomiko_db::DbStore;
use tomiko_http::server::Server;
use jsonwebtoken::EncodingKey;

#[derive(Debug)]
struct OAuth2Provider {
    store: DbStore,
    hasher: HashingService,
    token: TokenService,
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

use tomiko_auth::{MaybeChallenge::{self, *}, Provider};

#[async_trait]
impl Provider for OAuth2Provider {
    async fn authorization_request(
        &self,
        req: AuthorizationRequest,
    ) -> Result<MaybeChallenge<AuthorizationResponse>, AuthorizationError> {
	use AuthorizationRequest::*;
	
	match req {
	    AuthorizationCode(req) => {
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
		Ok(Accept(response))
	    },
	    _ => unimplemented!()
	}
        
    }

    async fn access_token_request(
        &self,
        credentials: ClientCredentials,
        req: TokenRequest,
    ) -> Result<AccessTokenResponse, AccessTokenError> {
        let client = self.check_client_authentication(&credentials).await?;
	use TokenRequest::*;
	match req {
	    AuthenticationCode(req) => {
		let data = self
		    .store
		    .get_authcode_data(&client.id, &req.code)
		    .await
		    .map_err(|_| AccessTokenErrorKind::InvalidGrant)?;

		if &data.redirect_uri == &req.redirect_uri {
		    let access_token = self.token.new_token(&client, data.scope.as_ref());
		    let token_type = TokenService::token_type().to_string();

		    Ok(AccessTokenResponse {
			access_token,
			token_type,
			refresh_token: None,
			expires_in: None,
			scope: data.scope,
		    })
		} else {
		    Err(AccessTokenErrorKind::InvalidGrant.into())
		}
	    },
	    ClientCredentials(req) => {
		let scope = self.store.trim_client_scopes(&client.id, &req.scope)
		    .await.expect("Trim scopes issue");
		
		let access_token = self.token.new_token(&client, Some(&scope));
		let token_type = TokenService::token_type().to_string();

		Ok(AccessTokenResponse {
		    access_token,
		    token_type,
		    refresh_token: None,
		    expires_in: None,
		    scope: Some(scope),
		})
	    },
	    _ => unimplemented!()
	}
    }
}

struct TokenService {
    secret: EncodingKey
}

impl std::fmt::Debug for TokenService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TokenService {{ ... }}")
    }
}

impl TokenService {
    pub fn new(secret_path: &str) -> Self {
	use std::io::Read;
	
	let mut contents = Vec::new();
	std::fs::File::open(&secret_path)
	    .expect("Failed to open secret")
	    .read_to_end(&mut contents)
	    .expect("Failed to read secret");
	let secret = EncodingKey::from_ec_pem(&contents)
	    .expect("Failed to parse secret");
	
        Self { secret }
    }

    pub fn token_type() -> &'static str {
        "application/jwt"
    }

    fn current_timestamp() -> std::time::Duration {
	use std::time::SystemTime;
	let now = SystemTime::now();
	
	now.duration_since(SystemTime::UNIX_EPOCH)
	    .expect("Unix Epoch is in the past.")
    }

    pub fn new_token(&self, client: &Client, scope: Option<&Scope>) -> String {
	use jsonwebtoken::{encode, Header, Algorithm};

	let time_now = Self::current_timestamp().as_secs();
	let expiry = time_now + 3600;

	let claims = TomikoClaims {
	    sub: client.id.0.to_string(),
	    scope: scope.cloned().unwrap_or(Scope::from_delimited_parts("")),
	    iat: time_now,
	    exp: expiry,
	    iss: "tomiko".to_string()
	};

	let header = Header {
	    alg: Algorithm::ES256,
	    ..Default::default()
	};
	
	encode(&header, &claims, &self.secret)
	    .expect("Failed to encode token claims")
    }
}

async fn tomikod(config: Config) -> Option<()> {
    let store = DbStore::acquire(&config.database_url).await.ok()?;
    let hasher = HashingService::with_secret_key(config.hash_secret);
    let token = TokenService::new(&config.jwt_private_key_file);

    let provider = Arc::new(OAuth2Provider { store, hasher, token });

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
    jwt_private_key_file: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct TomikoClaims {
    sub: String,
    iss: String,
    iat: u64,
    exp: u64,
    scope: Scope
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            database_url: std::env::var("DATABASE_URL").expect("Supply DATABASE_URL"),
            hash_secret: std::env::var("HASH_SECRET").expect("Supply HASH_SECRET"),
            jwt_private_key_file: std::env::var("JWT_PRIVATE_KEY_FILE")
                .expect("Supply JWT_PRIVATE_KEY_FILE"),
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
