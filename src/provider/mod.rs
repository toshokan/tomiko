use crate::{auth::{AuthorizationRequestData, Challenge, ChallengeInfo, self}, core::{models::{Consent, ConsentId, ClientInfo}}};
use crate::core::models::Client;
use crate::core::types::{BearerToken, ChallengeId, ClientId, RedirectUri};
use crate::util::{hash::HashingService, random::FromRandom};
use crate::{
    auth::{
        AccessTokenError, AccessTokenErrorKind, AccessTokenResponse, AuthenticationCodeResponse,
        AuthorizationError, AuthorizationRequest, AuthorizationResponse, BadRequest,
        ClientCredentials, Redirect, Store,
        UpdateChallengeDataRequest, UpdateChallengeDataResponse,
    },
    core::{models::AuthCodeData, types::AuthCode},
};

pub mod error;
mod token;
mod claims;

pub mod authorization;
pub mod access_token;
pub mod introspection;
pub mod revocation;


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
    ) -> Result<Redirect<AuthorizationResponse>, AuthorizationError> {
	use auth::authorization::{AuthorizationErrorKind, AuthorizationRedirectErrorKind};
	
	event!(
	    Level::DEBUG,
	    "Getting final challenge outcome"
	);
        let info = self
            .store
            .get_challenge_data(&id)
	    .and_then(|info| {
		// Can only be called once
		self.store.delete_challenge_data(&id)?;
		info.ok_or(Error::BadRequest) // TODO
	    })
	    .map_err(|_| AuthorizationRedirectErrorKind::BadChallenge)
	    .without_redirect()?;
	
	let parts = info.req.as_parts();
	let uri = parts.redirect_uri.clone();
	let state = parts.state.clone();

	if !info.ok {
	    event!(
		Level::WARN,
		"Challenge was not passed"
	    );
            Err(AuthorizationErrorKind::AccessDenied.into())
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
                    .map_err(|_| AuthorizationErrorKind::ServerError.into())
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
