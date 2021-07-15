use crate::auth::{ChallengeInfo, MaybeChallenge::{self, *}, pkce};
use crate::core::models::Client;
use crate::core::types::{ChallengeId, ClientId, RedirectUri, Scope};
use crate::oidc::types::Nonce;
use crate::util::{hash::HashingService, random::FromRandom};
use crate::{
    auth::{
        AccessTokenError, AccessTokenErrorKind, AccessTokenResponse, AuthenticationCodeResponse,
        AuthorizationError, AuthorizationRequest, AuthorizationResponse, BadRequest,
        ChallengeData, ClientCredentials, MaybeRedirect, Redirect, Store, TokenRequest,
        TokenType, UpdateChallengeDataRequest, UpdateChallengeDataResponse, WithState,
    },
    core::{models::AuthCodeData, types::AuthCode},
};

use crate::db::DbStore;
use crate::http::server::Server;
use jsonwebtoken::EncodingKey;
use std::sync::Arc;

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
        _state: &Option<String>,
    ) -> Result<(), MaybeRedirect<WithState<AuthorizationError>, BadRequest>> {
        self.store
            .check_client_uri(client_id, redirect_uri)
            .await
            .map_err(|_| {
                MaybeRedirect::Direct(BadRequest::BadRedirect)
            })?;

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
    ) -> Result<
        MaybeChallenge<Redirect<AuthorizationResponse>>,
        MaybeRedirect<WithState<AuthorizationError>, BadRequest>,
	> {
	let parts = req.as_parts();
	self.validate_client(&parts.client_id, &parts.redirect_uri, &parts.state)
            .await?;
        let state = parts.state.clone();

	if parts.scope.has_openid() {
	    // TODO
	}

        let uri = parts.redirect_uri.clone();
        let info = ChallengeData {
            id: ChallengeId::from_random(),
            req: req.clone(),
            ok: false,
	    subject: None
        };

        let id = self.store.store_challenge_data(info).await.map_err(|_| {
            MaybeRedirect::Redirected(Redirect::new(
                uri,
                (AuthorizationError::server_error(), state.clone()).into(),
            ))
        })?;

        let challenge = crate::auth::Challenge { id };

        Ok(Challenge(challenge))
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

		if let Some(challenge) = data.req.ext.pkce_challenge {
		    pkce::verify(&challenge, req.pkce_verifier.as_ref())?;
		}

                if &data.req.redirect_uri == &req.redirect_uri {
                    let access_token = self.token.new_token(&client.id, &data.subject, &data.req.scope);
                    let token_type = TokenService::token_type();

		    let oidc = if data.req.scope.has_openid() || data.req.ext.oidc.is_some() {
			Some(crate::oidc::AccessTokenResponse {
			    id_token: self.token.new_id_token(&client.id, &data.subject, None) // TODO: grab nonce
			})
		    } else {
			None
		    };

                    Ok(AccessTokenResponse {
                        access_token,
                        token_type,
                        refresh_token: None,
                        expires_in: None,
			oidc
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

		if scope != req.scope {
		    return Err(AccessTokenErrorKind::InvalidGrant.into());
		}

                let access_token = self.token.new_token(&client.id, &client.id.0.to_string(), &scope);
                let token_type = TokenService::token_type();

                Ok(AccessTokenResponse {
                    access_token,
                    token_type,
                    refresh_token: None,
                    expires_in: None,
		    oidc: None
                })
            }
            _ => unimplemented!(),
        }
    }

    pub async fn get_challenge_info(&self, id: ChallengeId) -> Option<ChallengeInfo> {
	self.store
	    .get_challenge_data(&id)
	    .await
	    .ok()?
	    .map(Into::into)
    }

    pub async fn with_redirect<F, T, E>(
        uri: RedirectUri,
        f: impl FnOnce() -> F,
    ) -> Result<Redirect<T>, Redirect<E>>
    where
        F: std::future::Future<Output = Result<T, E>>,
    {
        f().await
            .map(|o| Redirect::new(uri.clone(), o))
            .map_err(|e| Redirect::new(uri.clone(), e))
    }

    pub async fn get_challenge_result(
        &self,
        id: ChallengeId,
    ) -> Result<Redirect<AuthorizationResponse>, Redirect<WithState<AuthorizationError>>> {
        let info = self
            .store
            .get_challenge_data(&id)
            .await
            .expect("Error getting challenge info");
        if let Some(info) = info {
	    let parts = info.req.as_parts();
            Self::with_redirect(parts.redirect_uri.clone(), move || async move {
                match info.req {
                    AuthorizationRequest::AuthorizationCode(ref req) => {
                        let state = req.state.clone();
                        if !info.ok {
                            Err((AuthorizationError::access_denied(), state.clone()))?;
                        }

			let subject = info.subject.expect("Accepted challenge without subject");

                        let code = AuthCode::from_random();
                        let data = AuthCodeData {
                            code: code.clone(),
                            client_id: req.client_id.clone(),
                            req: req.clone(),
			    subject: subject
                        };

                        let expiry = std::time::SystemTime::now()
                            .checked_add(std::time::Duration::from_secs(10 * 60))
                            .unwrap();

                        // Store code
                        self.store
                            .store_code(data, expiry)
                            .await
                            .map_err(|_| (AuthorizationError::server_error(), state.clone()))?;

                        Ok(AuthorizationResponse::AuthenticationCode(
                            AuthenticationCodeResponse::new(code, state),
                        ))
                    }
                    AuthorizationRequest::Implicit(req) => { // TODO: unify logic with ImplicitId below
			let state = req.state.clone();
                        if !info.ok {
                            Err((AuthorizationError::access_denied(), state.clone()))?;
                        }

			let subject = info.subject.expect("Accepted challenge without subject");

			let access_token = self.token.new_token(&req.client_id, &subject, &req.scope);
						
                        let token_type = TokenService::token_type();

                        Ok(AuthorizationResponse::Implicit(AccessTokenResponse {
                            access_token,
                            token_type,
                            refresh_token: None,
                            expires_in: None,
			    oidc: None
                        }))
		    },
		    AuthorizationRequest::ImplicitId(req) => {
			let state = req.state.clone();
                        if !info.ok {
                            Err((AuthorizationError::access_denied(), state.clone()))?;
                        }

			let subject = info.subject.expect("Accepted challenge without subject");

			let access_token = self.token.new_token(&req.client_id, &subject, &req.scope);
			let id_token = self.token.new_id_token(&req.client_id, &subject, Some(&req.ext.oidc.nonce));
			let oidc = Some(crate::oidc::AccessTokenResponse {
			    id_token
			});
			
                        let token_type = TokenService::token_type();

                        Ok(AuthorizationResponse::Implicit(AccessTokenResponse {
                            access_token,
                            token_type,
                            refresh_token: None,
                            expires_in: None,
			    oidc
                        }))
                    }
                }
            })
            .await
        } else {
            unimplemented!()
        }
    }

    pub async fn update_challenge_data_request(
        &self,
        id: ChallengeId,
        req: UpdateChallengeDataRequest,
    ) -> Result<crate::auth::UpdateChallengeDataResponse, ()> {
        let mut info = self
            .store
            .get_challenge_data(&id)
            .await?
            .expect("No matching challenge");
        info.ok = match req {
            UpdateChallengeDataRequest::Accept{subject} => {
		info.subject = Some(subject);
		true
	    }
            UpdateChallengeDataRequest::Reject => false
        };
        self.store.update_challenge_data(info).await?;
        Ok(UpdateChallengeDataResponse {
            redirect_to: format!("http://localhost:8001/oauth/v1/challenge/{}", id.0),
        })
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

    pub fn token_type() -> TokenType {
	TokenType::Bearer
    }

    fn current_timestamp() -> std::time::Duration {
        use std::time::SystemTime;
        let now = SystemTime::now();

        now.duration_since(SystemTime::UNIX_EPOCH)
            .expect("Unix Epoch is in the past.")
    }

    pub fn new_token(&self, client_id: &ClientId, subject: &str, scope: &Scope) -> String {
        use jsonwebtoken::{encode, Algorithm, Header};

        let time_now = Self::current_timestamp().as_secs();
        let expiry = time_now + 3600;

	let claims = AccessClaims {
	    iss: "tomiko".to_string(),
	    exp: expiry,
	    aud: client_id.0.to_string(),
	    sub: subject.to_string(),
	    client_id: client_id.0.to_string(),
	    iat: time_now,
	    jti: "<not_implemented>".to_string(),
	    scope: Some(scope.clone())
	};

        let header = Header {
            alg: Algorithm::ES256,
            ..Default::default()
        };

        encode(&header, &claims, &self.secret).expect("Failed to encode token claims")
    }

    pub fn new_id_token(&self, client_id: &ClientId, subject: &str, nonce: Option<&Nonce>) -> String {
	use jsonwebtoken::{encode, Algorithm, Header};

        let time_now = Self::current_timestamp().as_secs();
        let expiry = time_now + 3600;

	let claims = IdClaims {
            sub: subject.to_string(),
	    iss: "tomiko".to_string(),
	    aud: client_id.0.to_string(),
	    exp: expiry,
            iat: time_now,
	    auth_time: time_now, // TODO: get from challenge data
	    nonce: nonce.cloned(),
	    azp: client_id.0.to_string(),
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
struct AccessClaims {
    iss: String,
    exp: u64,
    aud: String,
    sub: String,
    client_id: String,
    iat: u64,
    jti: String,
    #[serde(skip_serializing_if="Option::is_none")]
    scope: Option<Scope>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct IdClaims {
    sub: String,
    iss: String,
    aud: String,
    exp: u64,
    iat: u64,
    auth_time: u64,
    #[serde(skip_serializing_if="Option::is_none")]
    nonce: Option<Nonce>,
    azp: String
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
