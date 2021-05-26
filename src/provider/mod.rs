use crate::{auth::{AccessTokenError, AccessTokenErrorKind, AccessTokenResponse, AuthorizationError, AuthorizationRequest, AuthorizationResponse, BadRedirect, ChallengeInfo, ClientCredentials, MaybeRedirect, Redirect, Store, TokenRequest, UpdateChallengeInfoRequest, UpdateChallengeInfoResponse}, core::{models::AuthCodeData, types::AuthCode}};
use crate::core::models::Client;
use crate::core::types::{ChallengeId, ClientId, RedirectUri, Scope};
use crate::util::{hash::HashingService, random::FromRandom};
use crate::auth::MaybeChallenge::{self, *};

use jsonwebtoken::EncodingKey;
use std::sync::Arc;
use crate::db::DbStore;
use crate::http::server::Server;

#[derive(Debug)]
pub struct OAuth2Provider {
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
    ) -> Result<(), MaybeRedirect<AuthorizationError, BadRedirect>> {
        self.store
            .check_client_uri(client_id, redirect_uri)
            .await
            .map_err(|_| MaybeRedirect::Redirected(Redirect::new(redirect_uri.clone(), AuthorizationError::unauthorized_client(state))))?;

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
        use tokio::time::interval;

        let mut interval = interval(Duration::from_secs(15));

	loop {
	    interval.tick().await;
	    self.store.clean_up().await?
	}
    }
}



// #[async_trait]
// impl Provider for OAuth2Provider {
impl OAuth2Provider {
    pub async fn authorization_request(
        &self,
        req: AuthorizationRequest,
    ) -> Result<MaybeChallenge<Redirect<AuthorizationResponse>>, MaybeRedirect<AuthorizationError, BadRedirect>> {
        use AuthorizationRequest::*;

        match req {
            AuthorizationCode(req) => {
                self.validate_client(&req.client_id, &req.redirect_uri, &req.state)
                    .await?;
                let state = req.state.clone();

		let uri = req.redirect_uri.clone();
                let info = ChallengeInfo {
                    id: ChallengeId::from_random(),
                    client_id: req.client_id,
                    uri: req.redirect_uri,
                    scope: req.scope,
                    state: req.state,
		    ok: false
                };

                let id = self.store.store_challenge_info(info)
		    .await
		    .map_err(|_| MaybeRedirect::Redirected(Redirect::new(uri, AuthorizationError::server_error(&state))))?;
		
                let challenge = crate::auth::Challenge { id };

                Ok(Challenge(challenge))
            }
            _ => unimplemented!(),
        }
    }

    pub async fn access_token_request(
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
            }
            ClientCredentials(req) => {
                let scope = self
                    .store
                    .trim_client_scopes(&client.id, &req.scope)
                    .await
                    .expect("Trim scopes issue");

                let access_token = self.token.new_token(&client, Some(&scope));
                let token_type = TokenService::token_type().to_string();

                Ok(AccessTokenResponse {
                    access_token,
                    token_type,
                    refresh_token: None,
                    expires_in: None,
                    scope: Some(scope),
                })
            }
            _ => unimplemented!(),
        }
    }

    pub async fn get_challenge_info(&self, id: ChallengeId) -> Option<crate::auth::ChallengeInfo> {
        let challenge = self.store.get_challenge_info(&id).await.ok()?;
        challenge
    }

    pub async fn with_redirect<F, T, E>(uri: RedirectUri, f: impl FnOnce() -> F) -> Result<Redirect<T>, Redirect<E>>
	where F: std::future::Future<Output = Result<T, E>>
    {
	f().await
	    .map(|o| Redirect::new(uri.clone(), o))
	    .map_err(|e| Redirect::new(uri.clone(), e))
    }

    pub async fn get_challenge_result(&self, id: ChallengeId) -> Result<Redirect<AuthorizationResponse>, Redirect<AuthorizationError>> {
	let info = self.store.get_challenge_info(&id).await.expect("Error getting challenge info");
	if let Some(info) = info {
	    Self::with_redirect(info.uri.clone(), move || async move {
		let state = info.state.clone();
		if !info.ok {
		    Err(AuthorizationError::access_denied(&state))?;
		}
		
		let code = AuthCode::from_random();
		let data = AuthCodeData {
		    client_id: info.client_id,
		    code: code.clone(),
		    state: info.state,
		    redirect_uri: info.uri,
		    scope: Some(info.scope),
		};
		
		let expiry = std::time::SystemTime::now()
		    .checked_add(std::time::Duration::from_secs(10 * 60))
		    .unwrap();
		
		// Store code
		self
		    .store
		    .store_code(data, expiry)
		    .await
		    .map_err(|_| AuthorizationError::server_error(&state))?;
		
		Ok(AuthorizationResponse::new(code, state))
	    }).await
	} else {
	    unimplemented!()
	}
    }

    pub async fn update_challenge_info_request(
        &self,
        id: ChallengeId,
        req: UpdateChallengeInfoRequest,
    ) -> Result<crate::auth::UpdateChallengeInfoResponse, ()> {
	let mut info = self.store.get_challenge_info(&id).await?.expect("No matching challenge");
	info.ok = match req {
	    UpdateChallengeInfoRequest::Accept => true,
	    UpdateChallengeInfoRequest::Reject => false
	};
	self.store.update_challenge_info(info).await?;
	Ok(UpdateChallengeInfoResponse {
	    redirect_to: format!("http://localhost:8001/oauth/v1/challenge/{}", id.0)
	})
	
        // use UpdateChallengeInfoRequest::*;

        // let info = self.store.get_challenge_info(id).await?;
	
        // let resp = if let Some(info) = info {
	//     let state = info.state.clone();
        //     match req {
        //         Accept => {
	// 	    let code = AuthCode::from_random();

        //             let data = AuthCodeData {
        //                 client_id: info.client_id,
        //                 code,
        //                 state: info.state,
        //                 redirect_uri: info.uri,
        //                 scope: Some(info.scope),
        //             };

        //             let expiry = std::time::SystemTime::now()
        //                 .checked_add(std::time::Duration::from_secs(10 * 60))
        //                 .unwrap();

        //             let data = self
        //                 .store
        //                 .store_code(data, expiry)
        //                 .await
        //                 .map_err(|_| AuthorizationError::server_error(&state))
        //                 .expect("Bad data");

        //             let response = AuthorizationResponse::new(data.code, data.state);
	// 	    AuthResponse(response)
	// 	},
        //         Reject => RedirectTo(RedirectUri("http://localhost:8002/failure".to_string())),
        //     }
        // } else {
        //     RedirectTo(RedirectUri("http://localhost:8002/not_found".to_string()))
        // };
	// Ok(resp)
    }
}

struct TokenService {
    secret: EncodingKey,
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
        let secret = EncodingKey::from_ec_pem(&contents).expect("Failed to parse secret");

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
        use jsonwebtoken::{encode, Algorithm, Header};

        let time_now = Self::current_timestamp().as_secs();
        let expiry = time_now + 3600;

        let claims = TomikoClaims {
            sub: client.id.0.to_string(),
            scope: scope.cloned().unwrap_or(Scope::from_delimited_parts("")),
            iat: time_now,
            exp: expiry,
            iss: "tomiko".to_string(),
        };

        let header = Header {
            alg: Algorithm::ES256,
            ..Default::default()
        };

        encode(&header, &claims, &self.secret).expect("Failed to encode token claims")
    }
}

async fn tomikod(config: Config) -> Option<()> {
    let store = DbStore::acquire(&config.database_url).await.ok()?;
    let hasher = HashingService::with_secret_key(config.hash_secret);
    let token = TokenService::new(&config.jwt_private_key_file);
    let provider = Arc::new(OAuth2Provider {
        store,
        hasher,
        token,
    });

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
    scope: Scope,
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

pub async fn main() -> Result<(), ()> {
    tracing_subscriber::fmt::init();
    dotenv::dotenv().ok();
    let config = Config::from_env();
    tomikod(config).await.ok_or(())
}
