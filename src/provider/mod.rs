use crate::{auth::{ChallengeInfo, MaybeChallenge::{self, *}, pkce}, core::models::{AuthorizationData, Consent, ConsentId, PersistentSeed, PersistentSeedId, RefreshClaims, RefreshTokenId}};
use crate::core::models::Client;
use crate::core::types::{BearerToken, ChallengeId, ClientId, RedirectUri, Scope};
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

pub mod error;

use crate::db::DbStore;
use crate::http::server::Server;
use jsonwebtoken::{DecodingKey, EncodingKey};
use std::sync::Arc;
use self::error::ResultExt;

#[derive(Debug)]
pub struct OAuth2Provider {
    store: DbStore,
    hasher: HashingService,
    token: TokenService,
}

impl OAuth2Provider {
    pub async fn validate_client(
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
        let uri = parts.redirect_uri.clone();
	
	let info = ChallengeData::new(&req);
	let challenge = info.challenge();

	self.store.store_challenge_data(info)
	    .await
	    .map_err(|_| AuthorizationError::server_error())
	    .add_state_context(&parts.state)
	    .add_redirect_context(uri)?;

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
		let hashed_code = self.hasher.hash_without_salt(&req.code);
		
                let data = self
                    .store
                    .take_authcode_data(&client.id, &hashed_code)
                    .await
                    .map_err(|_| AccessTokenErrorKind::InvalidGrant)?;

		if let Some(challenge) = data.req.ext.pkce_challenge {
		    pkce::verify(&challenge, req.pkce_verifier.as_ref())?;
		}

                if &data.req.redirect_uri == &req.redirect_uri && &data.req.client_id == &credentials.client_id {
                    let access_token = self.token.new_token(&client.id, &data.subject, &data.req.scope);
                    let token_type = TokenService::token_type();

		    let oidc = if data.req.scope.has_openid() || data.req.ext.oidc.is_some() {
			Some(crate::oidc::AccessTokenResponse {
			    id_token: self.token.new_id_token(&client.id, &data.subject, None) // TODO: grab nonce
			})
		    } else {
			None
		    };

		    let refresh_token = if data.req.scope.has_refresh() {
			let seed = PersistentSeed {
			    id: PersistentSeedId::from_random(),
			    client_id: client.id.clone(),
			    auth_data: AuthorizationData {
				subject: data.subject.clone(),
				scope: data.req.scope.clone()
			    }
			};
			self.store.store_persistent_seed(&seed).await
			    .map_err(|_| AccessTokenErrorKind::InvalidRequest)?;

			let token = self.token.new_refresh_token(&seed);
			Some(token)
		    } else {
			None
		    };

                    Ok(AccessTokenResponse {
                        access_token,
                        token_type,
                        refresh_token,
                        expires_in: Some(15 * 60),
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
                    .await;

		let scope = match scope {
		    Ok(scope) if scope == req.scope => scope,
		    _ => return Err(AccessTokenErrorKind::InvalidGrant.into())
		};

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

    pub fn validate_token_for_challenge(&self, token: BearerToken) -> Option<()> {
	let claims = self.token.validate_token(&token.0).ok()?;
	match claims.scope {
	    Some(scope) if scope.contains("tomiko::challenge:rw") => Some(()),
	    _ => None
	}
    }

    pub fn validate_token_for_consent(&self, token: BearerToken) -> Option<()> {
	let claims = self.token.validate_token(&token.0).ok()?;
	match claims.scope {
	    Some(scope) if scope.contains("tomiko::consent:rw") => Some(()),
	    _ => None
	}
    }

    pub async fn get_challenge_info(&self, token: BearerToken, id: ChallengeId) -> Option<ChallengeInfo> {
	self.validate_token_for_challenge(token)?;
	self.store
	    .get_challenge_data(&id)
	    .await
	    .ok()?
	    .map(Into::into)
    }

    pub async fn get_challenge_result(
        &self,
        id: ChallengeId,
    ) -> Result<Redirect<AuthorizationResponse>, MaybeRedirect<WithState<AuthorizationError>, BadRequest>> {
        let info = self
            .store
            .get_challenge_data(&id)
            .await
            .expect("Error getting challenge info");
	//  Can only be called once.
	self.store.delete_challenge_data(&id).await.expect("Error deleting challenge");
        if let Some(info) = info {
	    let parts = info.req.as_parts();
	    let uri = parts.redirect_uri.clone();
	    let state = parts.state.clone();

	    if !info.ok {
                Err(AuthorizationError::access_denied())
		    .add_state_context(&state)
		    .add_redirect_context(uri.clone())?;
            }
	    
	    match info.req {
                AuthorizationRequest::AuthorizationCode(ref req) => {
		    let subject = info.subject.expect("Accepted challenge without subject");
		    
		    let mut req = req.clone();
		    req.scope = info.scope;

                    let code = AuthCode::from_random();
		    let hashed_code = self.hasher.hash_without_salt(&code);
                    let data = AuthCodeData {
                        code: hashed_code,
                        client_id: req.client_id.clone(),
                        req: req.clone(),
			subject
                    };

                    // Store code
                    self.store
                        .store_code(data)
                        .await
                        .map_err(|_| AuthorizationError::server_error())
			.add_state_context(&state)
			.add_redirect_context(uri.clone())?;

                    Ok(AuthorizationResponse::AuthenticationCode(
                        AuthenticationCodeResponse::new(code, state),
                    )).redirect_ok(uri.clone())
                }
                AuthorizationRequest::Implicit(req) => { // TODO: unify logic with ImplicitId below
		    let subject = info.subject.expect("Accepted challenge without subject");

		    let access_token = self.token.new_token(&req.client_id, &subject, &info.scope);
		    
                    let token_type = TokenService::token_type();

                    Ok(AuthorizationResponse::Implicit(AccessTokenResponse {
                        access_token,
                        token_type,
                        refresh_token: None,
                        expires_in: None,
			oidc: None
                    })).redirect_ok(uri.clone())
		},
		AuthorizationRequest::ImplicitId(req) => {
		    let subject = info.subject.expect("Accepted challenge without subject");

		    let access_token = self.token.new_token(&req.client_id, &subject, &info.scope);
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
                    })).redirect_ok(uri.clone())
                }
            }
        } else {
	    Err(BadRequest::BadChallenge)
		.without_redirect()
        }
    }

    pub async fn get_consent(
	&self,
	token: BearerToken,
	id: ConsentId
    ) -> Result<Consent, ()> {
	self.validate_token_for_consent(token).ok_or_else(|| ())?;
	self.store.get_consent(&id.client_id, &id.subject).await
    }

    pub async fn get_all_consents(
	&self,
	token: BearerToken,
	subject: String
    ) -> Result<Vec<Consent>, ()> {
	self.validate_token_for_consent(token).ok_or_else(|| ())?;
	self.store.get_all_consents(&subject).await
    }

    pub async fn put_consent(
	&self,
	token: BearerToken,
	consent:  Consent
    ) -> Result<(), ()> {
	self.validate_token_for_consent(token).ok_or_else(|| ())?;
	self.store.put_consent(consent).await
    }

    pub async fn revoke_consent(
	&self,
	token: BearerToken,
	id:  ConsentId,
    ) -> Result<(), ()> {
	self.validate_token_for_consent(token).ok_or_else(|| ())?;
	self.store.delete_consent(&id.client_id, &id.subject).await
    }

    pub async fn update_challenge_data_request(
        &self,
	token: BearerToken,
        id: ChallengeId,
        req: UpdateChallengeDataRequest,
    ) -> Result<crate::auth::UpdateChallengeDataResponse, ()> {
	self.validate_token_for_challenge(token).ok_or_else(|| ())?;
	
        let mut info = self
            .store
            .get_challenge_data(&id)
            .await?
            .expect("No matching challenge");
        info.ok = match req {
            UpdateChallengeDataRequest::Accept{subject, scope} => {
		info.subject = Some(subject);
		info.scope = scope;
		true
	    }
            UpdateChallengeDataRequest::Reject => false
        };
        self.store.update_challenge_data(info).await?;
        Ok(UpdateChallengeDataResponse {
            redirect_to: format!("http://localhost:8001/challenge/v1/continue/{}", id.0),
        })
    }
}

struct TokenService {
    secret: EncodingKey,
    public: DecodingKey<'static>
}

impl std::fmt::Debug for TokenService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TokenService {{ ... }}")
    }
}

impl TokenService {
    pub fn new(secret_path: &str, public_path: &str) -> Self {
        use std::io::Read;

        let secret = {
	    let mut contents = Vec::new();
            std::fs::File::open(&secret_path)
		.expect("Failed to open secret")
		.read_to_end(&mut contents)
		.expect("Failed to read secret");
            EncodingKey::from_ec_pem(&contents).expect("Failed to parse secret")
	};

	let public = {
	    let mut contents = Vec::new();
            std::fs::File::open(&public_path)
		.expect("Failed to open public key")
		.read_to_end(&mut contents)
		.expect("Failed to read public key");
            DecodingKey::from_ec_pem(&contents).expect("Failed to parse public key").into_static()
	};

        Self { secret, public }
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

    pub fn validate_token(&self, token: &str) -> Result<AccessClaims, ()> {
	let mut validation = jsonwebtoken::Validation::default();
	validation.iss = Some("tomiko".to_string());
	validation.algorithms = vec![jsonwebtoken::Algorithm::ES256];
	jsonwebtoken::decode::<AccessClaims>(token, &self.public, &validation)
	    .map(|td| td.claims)
	    .map_err(|e| {
		dbg!(e);
		()
	    })
    }

    pub fn new_token(&self, client_id: &ClientId, subject: &str, scope: &Scope) -> String {
        let time_now = Self::current_timestamp().as_secs();
        let expiry = time_now + (15 * 60);

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

	self.make_token(claims)
    }

    pub fn make_token(&self, claims: impl serde::Serialize) -> String {
	use jsonwebtoken::{encode, Algorithm, Header};
	let header = Header {
            alg: Algorithm::ES256,
            ..Default::default()
        };

        encode(&header, &claims, &self.secret).expect("Failed to encode token claims")
    }

    pub fn new_id_token(&self, client_id: &ClientId, subject: &str, nonce: Option<&Nonce>) -> String {
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

	self.make_token(claims)
    }

    pub fn new_refresh_token(&self, seed: &PersistentSeed) -> String {
	let time_now = Self::current_timestamp().as_secs();
        let expiry = time_now + (24 * 60 * 60);

	let claims = RefreshClaims {
	    tps: seed.id.clone(),
	    jti: RefreshTokenId::from_random(),
	    iat: expiry
	};

	self.make_token(claims)
    }
}

async fn tomikod(config: Config) -> Option<()> {
    let store = DbStore::acquire(&config.database_url).await.ok()?;
    let hasher = HashingService::with_secret_key(config.hash_secret);
    let token = TokenService::new(&config.jwt_private_key_file, &config.jwt_public_key_file);
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
    jwt_public_key_file: String,
}

#[derive(Debug)]
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
	    jwt_public_key_file: std::env::var("JWT_PUBLIC_KEY_FILE")
                .expect("Supply JWT_PUBLIC_KEY_FILE"),
        }
    }
}

pub async fn main() -> Result<(), ()> {
    tracing_subscriber::fmt::init();
    dotenv::dotenv().ok();
    let config = Config::from_env();
    tomikod(config).await.ok_or(())
}
