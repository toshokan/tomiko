use crate::auth::TokenType;
use crate::core::models::{RefreshTokenId, PersistentSeed, RefreshTokenData};
use crate::core::types::{ClientId, TokenId, Scope, BearerToken};
use crate::oidc::types::Nonce;
use crate::provider::{
    Error,
    claims::{AccessClaims, IdClaims, RefreshClaims}
};
use crate::util::random::FromRandom;

use jsonwebtoken::{DecodingKey, EncodingKey};
use tracing::{event, Level};


pub struct TokenService {
    secret: EncodingKey,
    public: DecodingKey<'static>,
    issuer_prefix: String,
}

impl std::fmt::Debug for TokenService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TokenService {{ ... }}")
    }
}

impl TokenService {
    pub fn new(secret_path: &str, public_path: &str, issuer_prefix: String) -> Self {
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

        Self { secret, public, issuer_prefix }
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

    fn issuer(&self) -> String {
	format!("{}::tomiko", &self.issuer_prefix)
    }

    pub fn validate_token(&self, token: &str) -> Result<AccessClaims, Error> {
	let mut validation = jsonwebtoken::Validation::default();
	validation.iss = Some(self.issuer());
	validation.algorithms = vec![jsonwebtoken::Algorithm::ES256];
	jsonwebtoken::decode::<AccessClaims>(token, &self.public, &validation)
	    .map(|td| td.claims)
	    .map_err(|_| Error::Unauthorized)
    }

    pub fn validate_refresh_token(&self, token: &str) -> Result<RefreshClaims, Error> {
	let mut validation = jsonwebtoken::Validation::default();
	validation.iss = Some(self.issuer());
	validation.validate_exp = false;
	validation.algorithms = vec![jsonwebtoken::Algorithm::ES256];
	jsonwebtoken::decode::<RefreshClaims>(token, &self.public, &validation)
	    .map(|td| td.claims)
	    .map_err(|_| Error::Unauthorized)
    }

    #[tracing::instrument(skip(self, scope), fields(scope = %scope.as_joined()))]
    pub fn new_token(&self, client_id: &ClientId, subject: &str, scope: &Scope) -> String {
        let time_now = Self::current_timestamp().as_secs();
        let expiry = time_now + (15 * 60);

	let claims = AccessClaims {
	    iss: self.issuer(),
	    exp: expiry,
	    aud: client_id.0.to_string(),
	    sub: subject.to_string(),
	    client_id: client_id.0.to_string(),
	    iat: time_now,
	    nbf: time_now,
	    jti: TokenId::from_random(),
	    scope: Some(scope.clone())
	};

	event!(Level::DEBUG, "Issuing access_token");
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

    #[tracing::instrument(skip(self, nonce))]
    pub fn new_id_token(&self, client_id: &ClientId, subject: &str, nonce: Option<&Nonce>) -> String {
        let time_now = Self::current_timestamp().as_secs();
        let expiry = time_now + 3600;

	let claims = IdClaims {
            sub: subject.to_string(),
	    iss: self.issuer(),
	    aud: client_id.0.to_string(),
	    exp: expiry,
            iat: time_now,
	    nbf: time_now,
	    auth_time: time_now, // TODO: get from challenge data
	    nonce: nonce.cloned(),
	    azp: client_id.0.to_string(),
        };

	event!(Level::DEBUG, "Issuing id_token");
	self.make_token(claims)
    }

    #[tracing::instrument(skip_all)]
    pub fn new_refresh_token(&self, seed: &PersistentSeed) -> (String, RefreshTokenData) {
	let time_now = Self::current_timestamp().as_secs();

	let jti = RefreshTokenId::from_random();

	let claims = RefreshClaims {
	    iss: self.issuer(),
	    tps: seed.id.clone(),
	    jti: jti.clone(),
	    iat: time_now
	};

	let record = RefreshTokenData {
	    id: jti,
	    seed: seed.id.clone(),
	};

	event!(
	    Level::DEBUG,
	    "t/ps" = ?seed.id,
	    "Issuing refresh token"
	);
	(self.make_token(claims), record)
    }

    pub fn validate_token_contains(&self, token: BearerToken, scope_entry: &str) -> Result<(), Error> {
	let claims = self.validate_token(&token.0)?;
	match claims.scope {
	    Some(scope) if scope.contains(scope_entry) => Ok(()),
	    _ => Err(Error::Unauthorized)
	}
    }
}
