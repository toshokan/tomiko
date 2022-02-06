use crate::{auth::{AuthorizationRequestData, Challenge, ChallengeInfo, MaybeChallenge::{self, *}, pkce}, core::{models::{AuthorizationData, Consent, ConsentId, PersistentSeed, PersistentSeedId, ClientInfo, AuthorizationDataExt}}};
use crate::core::models::Client;
use crate::core::types::{BearerToken, ChallengeId, ClientId, RedirectUri};
use crate::util::{hash::HashingService, random::FromRandom};
use crate::{
    auth::{
        AccessTokenError, AccessTokenErrorKind, AccessTokenResponse, AuthenticationCodeResponse,
        AuthorizationError, AuthorizationRequest, AuthorizationResponse, BadRequest,
        ChallengeData, ClientCredentials, MaybeRedirect, Redirect, Store, TokenRequest,
        UpdateChallengeDataRequest, UpdateChallengeDataResponse, WithState,
    },
    core::{models::AuthCodeData, types::AuthCode},
};

pub mod error;
mod token;
mod claims;
pub mod introspection;

use token::TokenService;

use error::Error;

use crate::db::DbStore;
use crate::http::server::Server;
use std::sync::Arc;
use self::error::ResultExt;

use tracing::{event, Level};

#[derive(Debug)]
pub struct OAuth2Provider {
    store: DbStore,
    hasher: HashingService,
    token: TokenService,
    challenge_base: String,
    self_base: String,
}

impl OAuth2Provider {
    #[tracing::instrument(skip(self))]
    pub async fn validate_client(
        &self,
        client_id: &ClientId,
        redirect_uri: &RedirectUri
    ) -> Result<(), BadRequest> {
	event!(Level::TRACE, "Validating client URI");
        self.store
            .check_client_uri(client_id, redirect_uri)
            .map_err(|_| {
                BadRequest::BadRedirect
            })?;

        Ok(())
    }

    #[tracing::instrument(skip(self, cred), fields(client_id = ?cred.client_id))]
    async fn check_client_authentication(
        &self,
        cred: &ClientCredentials,
    ) -> Result<Client, AccessTokenError> {
	event!(Level::TRACE, "Checking client authentication");
        let client = self.store.get_client(&cred.client_id);

        if let Ok(Some(c)) = client {
            let result = self
                .hasher
                .verify(&cred.client_secret, &c.secret);
	    
            if let Ok(true) = result {
                return Ok(c);
            }
        }

	event!(Level::WARN, "Invalid authentication");
        Err(AccessTokenError {
            kind: AccessTokenErrorKind::InvalidClient,
            description: Some("Bad authentication".to_string()),
            uri: None,
        })
    }

    async fn start_clean_up_worker(&self) -> Result<(), Error> {
        use std::time::Duration;
        use tokio::time::interval;

        let mut interval = interval(Duration::from_secs(15));
	event!(Level::DEBUG, "Starting clean-up worker");
        loop {
            interval.tick().await;
	    event!(Level::TRACE, "Cleaning invalid entries codes, tokens, and challenges");
            self.store.clean_up()?;
        }
    }
}

impl OAuth2Provider {
    #[tracing::instrument(skip_all)]
    pub async fn authorization_request(
        &self,
        req: AuthorizationRequest,
    ) -> Result<
        MaybeChallenge<Redirect<AuthorizationResponse>>,
        MaybeRedirect<WithState<AuthorizationError>, BadRequest>,
	> {
	let parts = req.as_parts();
        let uri = parts.redirect_uri.clone();

	self.validate_client(parts.client_id, &uri)
	    .await
	    .map_err(|_| BadRequest::BadRedirect)
	    .without_redirect()?;
	
	let info = ChallengeData::new(&req);
	let challenge = self.make_challenge(&info.id);

	self.store.store_challenge_data(info)
	    .map_err(|_| AuthorizationError::server_error())
	    .add_state_context(&parts.state)
	    .add_redirect_context(uri)?;

	event!(
	    Level::DEBUG,
	    client_id = ?parts.client_id,
	    challenge_id = ?challenge.id,
	    "Issuing authorization challenge"
	);
        Ok(Challenge(challenge))
    }

    #[tracing::instrument(skip_all, fields(client_id = ?credentials.client_id))]
    pub async fn access_token_request(
        &self,
        credentials: ClientCredentials,
        req: TokenRequest,
    ) -> Result<AccessTokenResponse, AccessTokenError> {
	event!(Level::TRACE, "Handling access token request");
        let client = self.check_client_authentication(&credentials).await?;
	
        use TokenRequest::*;
	
        match req {
            AuthenticationCode(req) => {
		event!(Level::TRACE, "Handling authorization_code grant");
		let hashed_code = self.hasher.hash_without_salt(&req.code);
		
                let data = self
                    .store
                    .take_authcode_data(&client.id, &hashed_code)
                    .map_err(|_| AccessTokenErrorKind::InvalidGrant)?;

		if let Some(challenge) = data.req.ext.pkce_challenge {
		    event!(Level::DEBUG, "Verifying PKCE challenge");
		    pkce::verify(&challenge, req.pkce_verifier.as_ref())?;
		}

                if &data.req.redirect_uri == &req.redirect_uri && &data.req.client_id == &credentials.client_id {
                    let access_token = self.token.new_token(&client.id, &data.subject, &data.req.scope);
                    let token_type = TokenService::token_type();

		    let oidc = if data.req.scope.has_openid() || data.req.ext.oidc.is_some() {
			event!(Level::DEBUG, "Processing OpenID Connect extension data");
			let nonce = data.req.ext.oidc.as_ref().map(|o| o.nonce.clone()).flatten();
			Some(crate::oidc::AccessTokenResponse {
			    id_token: self.token.new_id_token(&client.id, &data.subject, nonce.as_ref())
			})
		    } else {
			None
		    };

		    let refresh_token = if data.req.scope.has_refresh() {
			let seed = PersistentSeed {
			    id: PersistentSeedId::from_random(),
			    client_id: client.id.clone(),
			    subject: data.subject.clone(),
			    auth_data: AuthorizationData {
				scope: data.req.scope.clone(),
				ext: AuthorizationDataExt {
				    oidc: data.req.ext.oidc
				}
			    }
			};
			event!(
			    Level::DEBUG,
			    "t/ps" = ?seed.id,
			    "sub" = ?seed.subject,
			    "Generating persistent seed"
			);
			self.store.store_persistent_seed(&seed)
			    .map_err(|_| AccessTokenErrorKind::InvalidRequest)?;

			let (token, data) = self.token.new_refresh_token(&seed);
			self.store.put_refresh_token(data)
			    .map_err(|_| AccessTokenErrorKind::InvalidGrant)?;
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
		event!(Level::TRACE, "Handling client_credentials grant");
                let scope = self
                    .store
                    .trim_client_scopes(&client.id, &req.scope);

		let scope = match scope {
		    Ok(scope) if scope == req.scope => scope,
		    _ => {
			event!(
			    Level::ERROR,
			    scope = %req.scope.as_joined(),
			    "Invalid scopes for client"
			);
			return Err(AccessTokenErrorKind::InvalidGrant.into())
		    }
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
            },
	    RefreshToken(req) => {
		event!(Level::TRACE, "Handling refresh_tokens grant");
		let claims = self.token.validate_refresh_token(&req.refresh_token)
		    .map_err(|_| AccessTokenErrorKind::InvalidGrant)?;
		
		let seed = self.store.find_refresh_token_seed(&claims.jti)
		    .map_err(|_| AccessTokenErrorKind::InvalidGrant)?
		    .ok_or(AccessTokenErrorKind::InvalidGrant)?;

		self.store.invalidate_refresh_token(&claims.jti)
		    .map_err(|_| AccessTokenErrorKind::InvalidGrant)?;

		if client.id != seed.client_id {
		    event!(
			Level::WARN,
			original_client_id = ?seed.client_id,
			refresh_client_id = ?client.id,
			"client_ids do not match"
		    );
		    Err(AccessTokenErrorKind::InvalidGrant)?
		}

		let scope = match req.scope {
		    Some(scope) => {
			if seed.auth_data.scope.contains_all(&scope) {
			    scope
			} else {
			    // This scope was not in the original request
			    Err(AccessTokenErrorKind::InvalidGrant)?
			}
		    },
		    None => seed.auth_data.scope.clone()
		};

		let access_token = self.token.new_token(&client.id, &seed.subject, &scope);
                let token_type = TokenService::token_type();

		let oidc = if scope.has_openid() || seed.auth_data.ext.oidc.is_some() {
		    event!(Level::DEBUG, "Processing OpenID Connect extension data");
		    let nonce = seed.auth_data.ext.oidc.as_ref().map(|o| o.nonce.clone()).flatten();
		    Some(crate::oidc::AccessTokenResponse {
			id_token: self.token.new_id_token(&client.id, &seed.subject, nonce.as_ref())
		    })
		} else {
		    None
		};

		let refresh_token = if scope.has_refresh() {
		    let (token, data) = self.token.new_refresh_token(&seed);
		    self.store.put_refresh_token(data)
			.map_err(|_| AccessTokenErrorKind::InvalidGrant)?;
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
	    }
        }
    }

    fn validate_token_for_challenge(&self, token: BearerToken) -> Result<(), Error> {
	self.token.validate_token_contains(token, "tomiko::challenge:rw")
    }

    fn validate_token_for_consent(&self, token: BearerToken) -> Result<(), Error> {
	self.token.validate_token_contains(token, "tomiko::consent:rw")
    }

    fn validate_token_for_client_info(&self, token: BearerToken) -> Result<(), Error> {
	self.token.validate_token_contains(token, "tomiko::client:ro")
    }

    #[tracing::instrument(skip(self, token))]
    pub async fn get_challenge_info(&self, token: BearerToken, id: ChallengeId) -> Result<ChallengeInfo, Error> {
	event!(
	    Level::DEBUG,
	    "Retrieving challenge info"
	);
	self.validate_token_for_challenge(token)?;
	self.store
	    .get_challenge_data(&id)?
	    .map(Into::into)
	    .ok_or(Error:: BadRequest)
    }

    #[tracing::instrument(skip(self))]
    pub async fn get_challenge_result(
        &self,
        id: ChallengeId,
    ) -> Result<Redirect<AuthorizationResponse>, MaybeRedirect<WithState<AuthorizationError>, BadRequest>> {
	event!(
	    Level::DEBUG,
	    "Getting final challenge outcome"
	);
        let info = self
            .store
            .get_challenge_data(&id)
	    .map_err(|_| BadRequest::BadChallenge)
	    .without_redirect()?;

	//  Can only be called once.
	self.store.delete_challenge_data(&id)
	    .map_err(|_| BadRequest::ServerError)
	    .without_redirect()?;
	
        if let Some(info) = info {
	    let parts = info.req.as_parts();
	    let uri = parts.redirect_uri.clone();
	    let state = parts.state.clone();

	    if !info.ok {
		event!(
		    Level::WARN,
		    "Challenge was not passed"
		);
                Err(AuthorizationError::access_denied())
		    .add_state_context(&state)
		    .add_redirect_context(uri.clone())?;
            }
	    
	    match info.req {
                AuthorizationRequest::AuthorizationCode(ref req) => {
		    event!(
			Level::DEBUG,
			client_id = ?req.client_id,
			"Handling code response"
		    );
		    let subject = info.subject.expect("Accepted challenge without subject");
		    
		    let mut req = req.clone();
		    req.scope = info.scope;

                    let code = AuthCode::from_random();
		    let hashed_code = self.hasher.hash_without_salt(&code);

		    event!(
			Level::DEBUG,
			client_id = ?req.client_id,
			hashed_code = ?hashed_code,
			"Generated authorization code"
		    );
                    let data = AuthCodeData {
                        code: hashed_code,
                        client_id: req.client_id.clone(),
                        req: req.clone(),
			subject
                    };

                    // Store code
                    self.store
                        .store_code(data)
                        .map_err(|_| AuthorizationError::server_error())
			.add_state_context(&state)
			.add_redirect_context(uri.clone())?;

                    Ok(AuthorizationResponse::AuthenticationCode(
                        AuthenticationCodeResponse::new(code, state),
                    )).redirect_ok(uri.clone())
                }
		AuthorizationRequest::Implicit(AuthorizationRequestData{ ref client_id, .. }) |
		AuthorizationRequest::ImplicitId(AuthorizationRequestData{ ref client_id, .. }) => {
		    event!(
			Level::DEBUG,
			client_id = ?client_id,
			"Handling implicit response"
		    );
		    let subject = info.subject.expect("Accepted challenge without subject");
		    let oidc = if let AuthorizationRequest::ImplicitId(req) = &info.req {
			event!(
			    Level::DEBUG,
			    client_id = ?client_id,
			    "Processing OpenID Connect implicit_id Extension"
			);
			let id_token = self.token.new_id_token(&req.client_id, &subject, Some(&req.ext.oidc.nonce));
			Some(crate::oidc::AccessTokenResponse {
			    id_token
			})
		    } else {
			None
		    };

		    let access_token = self.token.new_token(client_id, &subject, &info.scope);
		    
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

    #[tracing::instrument(skip(self, token))]
    pub async fn get_consent(
	&self,
	token: BearerToken,
	id: ConsentId
    ) -> Result<Consent, Error> {
	event!(Level::DEBUG, "Getting consent data");
	self.validate_token_for_consent(token)?;
	Ok(self.store.get_consent(&id.client_id, &id.subject)?)
    }

    #[tracing::instrument(skip(self, token))]
    pub async fn get_all_consents(
	&self,
	token: BearerToken,
	subject: String
    ) -> Result<Vec<Consent>, Error> {
	event!(Level::DEBUG, "Getting all consent data");
	self.validate_token_for_consent(token)?;
	Ok(self.store.get_all_consents(&subject)?)
    }

    #[tracing::instrument(skip(self, token))]
    pub async fn put_consent(
	&self,
	token: BearerToken,
	consent:  Consent
    ) -> Result<(), Error> {
	event!(Level::DEBUG, "Storing consent decision");
	self.validate_token_for_consent(token)?;
	Ok(self.store.put_consent(consent)?)
    }

    #[tracing::instrument(skip(self, token))]
    pub async fn revoke_consent(
	&self,
	token: BearerToken,
	id:  ConsentId,
    ) -> Result<(), Error> {
	event!(Level::DEBUG, "Revoking consent decision");
	self.validate_token_for_consent(token)?;
	Ok(self.store.delete_consent(&id.client_id, &id.subject)?)
    }

    #[tracing::instrument(skip(self, token))]
    pub async fn update_challenge_data_request(
        &self,
	token: BearerToken,
        id: ChallengeId,
        req: UpdateChallengeDataRequest,
    ) -> Result<crate::auth::UpdateChallengeDataResponse, Error> {
	event!(Level::DEBUG, "Updating challenge data");
	self.validate_token_for_challenge(token)?;
	
        let mut info = self
            .store
            .get_challenge_data(&id)?
	    .ok_or(Error::BadRequest)?;
	    
        info.ok = match req {
            UpdateChallengeDataRequest::Accept{subject, scope} => {
		event!(
		    Level::TRACE,
		    subject = %subject,
		    scope = %scope.as_joined(),
		    "Challenge accepted"
		);
		info.subject = Some(subject);
		info.scope = scope;
		true
	    }
            UpdateChallengeDataRequest::Reject => {
		event!(Level::TRACE, "Challenge rejected");
		false
	    }
        };
        self.store.update_challenge_data(info)?;
        Ok(UpdateChallengeDataResponse {
            redirect_to: format!("{}/challenge/v1/continue/{}", &self.self_base, id.0),
        })
    }

    fn make_challenge(&self, id: &ChallengeId) -> Challenge {
	let id = id.clone();
	Challenge {
	    base_url: self.challenge_base.clone(),
	    id
	}
    }

    pub async fn get_client_info(
	&self,
	token: BearerToken,
	id: ClientId
    ) -> Result<Option<ClientInfo>, Error> {
	self.validate_token_for_client_info(token)?;
	let client = self.store.get_client(&id)?;
	Ok(client.map(|c| ClientInfo {
	    client_id: c.id,
	    name: c.name
	}))
    }
}






async fn tomikod(config: Config) -> Option<()> {
    event!(Level::DEBUG, "Acquiring database connection");
    let store = DbStore::acquire(&config.database_url).ok()?;
    event!(Level::DEBUG, "Running pending database migrations");
    store.migrate();
    let hasher = HashingService::with_secret_key(config.hash_secret);
    let token = TokenService::new(&config.jwt_private_key_file, &config.jwt_public_key_file, config.issuer_prefix.clone());
    let provider = Arc::new(OAuth2Provider {
        store,
        hasher,
        token,
	challenge_base: config.challenge_base,
	self_base: config.self_base,
    });

    let _clean_up = {
        let provider = Arc::clone(&provider);
        tokio::spawn(async move { provider.start_clean_up_worker().await });
    };

    event!(Level::INFO, issuer = %config.issuer_prefix);
    event!(Level::DEBUG, "Starting HTTP server");
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
    challenge_base: String,
    self_base: String,
    issuer_prefix: String
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
	    challenge_base: std::env::var("CHALLENGE_HTTP_BASE")
                .expect("Supply CHALLENGE_HTTP_BASE"),
	    self_base: std::env::var("SELF_HTTP_BASE")
                .expect("Supply SELF_HTTP_BASE"),
	    issuer_prefix: std::env::var("ISSUER_PREFIX")
		.expect("Supply ISSUER_PREFIX")
        }
    }
}

pub async fn main() -> Result<(), ()> {
    tracing_subscriber::fmt::init();
    event!(Level::INFO, "Starting tomiko");

    event!(Level::DEBUG, "Loading configuration from environment");
    dotenv::dotenv().ok();
    let config = Config::from_env();
    
    tomikod(config).await.ok_or(())
}
