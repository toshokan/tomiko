use crate::core::models::{AuthCodeData, Client};
use crate::core::types::{
    ChallengeId, ClientId, ClientSecret, Expire, HashedAuthCode, HashedClientSecret, RedirectUri, Scope,
};

pub mod authorization;
pub mod access_token;
pub mod error;
pub mod pkce;
pub mod introspection;
pub mod revocation;

use error::ErrorResponse;
pub use authorization::*;
pub use access_token::*;

use crate::oidc;
use crate::provider::error::Error;
use crate::util::random::FromRandom;


#[derive(Debug, Clone)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ImplicitRequestExt<O> {
    #[serde(flatten)]
    pub oidc: O
}



#[derive(Debug, Clone)]
#[derive(serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BadRequest {
    BadRedirect,
    BadChallenge,
    BadToken,
    ServerError,
}

#[derive(Debug)]
pub enum MaybeRedirect<R, D> {
    Redirected(Redirect<R>),
    Direct(D)
}

#[derive(Debug, Clone)]
#[derive(serde::Serialize)]
pub struct WithState<T> {
    #[serde(flatten)]
    pub inner: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>
}

impl<T> From<(T, Option<String>)> for WithState<T> {
    fn from((t, state): (T, Option<String>)) -> Self {
	Self {
	    inner: t,
	    state
	}
    }
}



#[derive(Debug)]
#[derive(serde::Deserialize)]
pub struct ClientCredentials {
    pub client_id: ClientId,
    pub client_secret: ClientSecret,
}

#[derive(Debug)]
#[derive(serde::Serialize)]
pub struct Challenge {
    pub base_url: String,
    pub id: ChallengeId,
}

#[derive(Debug)]
#[derive(serde::Serialize)]
pub struct ChallengeData {
    pub id: ChallengeId,
    pub req: AuthorizationRequest,
    pub ok: bool,
    pub subject: Option<String>,
    pub scope: Scope
}

impl Expire for ChallengeData {
    const EXPIRES_IN_SECS: u64 = 5 * 60;
}

impl ChallengeData {
    pub fn new(req: &AuthorizationRequest) -> Self {
	let scope = {
	    let parts = req.as_parts();
	    let mut scope = parts.scope.clone();
	    scope.trim_privileged();
	    scope
	};
	Self {
	    id: ChallengeId::from_random(),
	    req: req.clone(),
	    ok: false,
	    subject: None,
	    scope
	}
    }
}

#[derive(Debug, Clone)]
#[derive(serde::Serialize)]
pub struct ChallengeInfo {
    pub id: ChallengeId,
    pub client_id: ClientId,
    pub scope: Scope,
    pub ok: bool
}

impl From<ChallengeData> for ChallengeInfo {
    fn from(data: ChallengeData) -> Self {
	let parts = data.req.as_parts();
	Self {
	    id: data.id,
	    client_id: parts.client_id.clone(),
	    scope: data.scope.clone(),
	    ok: data.ok
	}
    }
}

#[derive(Debug)]
#[derive(serde::Deserialize)]
#[serde(tag = "action")]
#[serde(rename_all = "snake_case")]
pub enum UpdateChallengeDataRequest {
    Accept {
	subject: String,
	scope: Scope
    },
    Reject,
}

#[derive(Debug)]
#[derive(serde::Serialize)]
pub struct UpdateChallengeDataResponse {
    pub redirect_to: String
}

pub enum MaybeChallenge<T> {
    Challenge(Challenge),
    Accept(T),
}

pub trait ChallengeExt<T, E> {
    fn transpose(self) -> MaybeChallenge<Result<T, E>>;
}

impl<T, E> ChallengeExt<T, E> for Result<MaybeChallenge<T>, E> {
    fn transpose(self) -> MaybeChallenge<Result<T, E>> {
        use MaybeChallenge::*;

        match self {
            Ok(Challenge(c)) => Challenge(c),
            Ok(Accept(t)) => Accept(Ok(t)),
            Err(e) => Accept(Err(e)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Redirect<T> {
    pub uri: RedirectUri,
    pub params: T
}

impl<T> Redirect<T> {
    pub fn new(uri: RedirectUri, params: T) -> Self {
	Redirect {
	    uri,
	    params
	}
    }
}

pub trait Store {
    fn check_client_uri(&self, client_id: &ClientId, uri: &RedirectUri) -> Result<(), Error>;
    fn store_code(&self, data: AuthCodeData) -> Result<AuthCodeData, Error>;
    fn get_client(&self, client_id: &ClientId) -> Result<Option<Client>, Error>;
    fn put_client(
        &self,
        client_id: ClientId,
	name: String,
        secret: HashedClientSecret,
    ) -> Result<Client, Error>;
    fn take_authcode_data(
        &self,
        client_id: &ClientId,
        code: &HashedAuthCode,
    ) -> Result<AuthCodeData, Error>;
    fn clean_up(&self) -> Result<(), Error>;
    fn trim_client_scopes(&self, client_id: &ClientId, scope: &Scope) -> Result<Scope, Error>;
    fn store_challenge_data(&self, info: ChallengeData) -> Result<ChallengeId, Error>;
    fn get_challenge_data(&self, id: &ChallengeId) -> Result<Option<ChallengeData>, Error>;
    fn delete_challenge_data(&self, id: &ChallengeId) -> Result<(), Error>;
    fn update_challenge_data(&self, info: ChallengeData) -> Result<ChallengeData, Error>;
}
