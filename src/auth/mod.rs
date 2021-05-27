use async_trait::async_trait;
use std::time::SystemTime;
use crate::core::models::{AuthCodeData, Client};
use crate::core::types::{
    AuthCode, ChallengeId, ClientId, ClientSecret, HashedClientSecret, RedirectUri, Scope,
};

#[derive(Debug, Clone)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct AuthorizationCodeGrantAuthorizationRequest {
    pub client_id: ClientId,
    pub redirect_uri: RedirectUri,
    pub scope: Scope,
    pub state: Option<String>,
}

#[derive(Debug, Clone)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ImplicitGrantAuthorizationRequest {
    pub client_id: ClientId,
    pub redirect_uri: RedirectUri,
    pub scope: Scope,
    pub state: Option<String>,
}

#[derive(Debug, Clone)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(tag = "response_type")]
pub enum AuthorizationRequest {
    #[serde(rename = "code")]
    AuthorizationCode(AuthorizationCodeGrantAuthorizationRequest),
    #[serde(rename = "token")]
    Implicit(ImplicitGrantAuthorizationRequest),
}

impl AuthorizationRequest {
    pub fn as_parts(&self) -> AuthorizationRequestParts<'_> {
	use AuthorizationRequest::*;
	
	match &self {
	    AuthorizationCode(AuthorizationCodeGrantAuthorizationRequest {
		client_id, redirect_uri, state, ..
	    }) |
	    Implicit(ImplicitGrantAuthorizationRequest {
		client_id, redirect_uri, state, ..
	    }) => {
		AuthorizationRequestParts {
		    client_id,
		    redirect_uri,
		    state
		}
	    }
	}
    }
}

#[derive(Debug, Clone)]
pub struct AuthorizationRequestParts<'r> {
    pub client_id: &'r ClientId,
    pub redirect_uri: &'r RedirectUri,
    pub state: &'r Option<String>
}

#[derive(Debug)]
#[derive(serde::Deserialize)]
pub struct AuthenticationCodeTokenRequest {
    pub redirect_uri: RedirectUri,
    pub code: AuthCode,
}

#[derive(Debug)]
#[derive(serde::Deserialize)]
pub struct ResourceOwnerPasswordCredentialsTokenRequest {
    username: String,
    password: String,
    scope: Scope,
}

#[derive(Debug)]
#[derive(serde::Deserialize)]
pub struct ClientCredentialsTokenRequest {
    pub scope: Scope,
}

#[derive(Debug)]
#[derive(serde::Deserialize)]
#[serde(tag = "grant_type")]
pub enum TokenRequest {
    #[serde(rename = "authorization_code")]
    AuthenticationCode(AuthenticationCodeTokenRequest),
    #[serde(rename = "password")]
    ResourceOwnerPasswordCredentials(ResourceOwnerPasswordCredentialsTokenRequest),
    #[serde(rename = "client_credentials")]
    ClientCredentials(ClientCredentialsTokenRequest),
}

#[derive(Debug)]
#[derive(serde::Serialize)]
#[serde(untagged)]
pub enum AuthorizationResponse {
    AuthenticationCode(AuthenticationCodeResponse),
    Implicit(AccessTokenResponse)
}

#[derive(Debug)]
#[derive(serde::Serialize)]
pub struct AuthenticationCodeResponse {
    code: AuthCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<String>,
}


impl AuthenticationCodeResponse {
    pub fn new(code: AuthCode, state: Option<String>) -> Self {
        Self { code, state }
    }
}

#[derive(Debug)]
#[derive(serde::Serialize)]
pub struct TokenType(String);

#[derive(serde::Serialize)]
#[derive(Debug)]
pub struct AccessTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub refresh_token: Option<String>,
    pub expires_in: Option<u32>,
    pub scope: Option<Scope>,
}

#[derive(Debug, Clone)]
pub struct BadRedirect;

#[derive(Debug)]
pub enum MaybeRedirect<R, D> {
    Redirected(Redirect<R>),
    Direct(D)
}

#[derive(Debug, Clone)]
#[derive(serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationErrorKind {
    InvalidRequest,
    UnauthorizedClient,
    AccessDenied,
    UnsupportedResponseType,
    InvalidScope,
    ServerError,
    TemporarilyUnavailable,
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

#[derive(Debug, Clone)]
#[derive(serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub struct AuthorizationError {
    #[serde(rename = "error")]
    pub kind: AuthorizationErrorKind,
    #[serde(rename = "error_description")]
    pub description: Option<String>,
    #[serde(rename = "error_uri")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
}

macro_rules! make_helper {
    ($name: ident, $variant: path) => {
        pub fn $name() -> Self {
            Self {
                kind: $variant,
                description: None,
                uri: None,
            }
        }
    };
}

impl AuthorizationError {
    make_helper!(server_error, AuthorizationErrorKind::ServerError);
    make_helper!(access_denied, AuthorizationErrorKind::AccessDenied);
    make_helper!(
        unauthorized_client,
        AuthorizationErrorKind::UnauthorizedClient
    );
}

#[derive(Debug, Clone)]
#[derive(serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessTokenErrorKind {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    UnauthorizedClient,
    UnsupportedGrantType,
    InvalidScope,
}

#[derive(Debug, Clone)]
#[derive(serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub struct AccessTokenError {
    #[serde(rename = "error")]
    pub kind: AccessTokenErrorKind,
    #[serde(rename = "error_description")]
    pub description: Option<String>,
    #[serde(rename = "error_uri")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
}

impl From<AccessTokenErrorKind> for AccessTokenError {
    fn from(kind: AccessTokenErrorKind) -> Self {
        Self {
            kind,
            description: None,
            uri: None,
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
    pub id: ChallengeId,
}

#[derive(Debug)]
#[derive(serde::Serialize)]
pub struct ChallengeData {
    pub id: ChallengeId,
    pub req: AuthorizationRequest,
    pub ok: bool
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
	match data.req {
	    AuthorizationRequest::AuthorizationCode(req) => {
		Self {
		    id: data.id,
		    client_id: req.client_id,
		    scope: req.scope,
		    ok: data.ok
		}
	    }
	    AuthorizationRequest::Implicit(req) => {
		Self {
		    id: data.id,
		    client_id: req.client_id,
		    scope: req.scope,
		    ok: data.ok
		}
	    }
	}
    }
}

#[derive(Debug)]
#[derive(serde::Deserialize)]
pub enum UpdateChallengeDataRequest {
    Accept,
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

#[async_trait]
pub trait Store {
    async fn check_client_uri(&self, client_id: &ClientId, uri: &RedirectUri) -> Result<(), ()>;
    async fn store_code(&self, data: AuthCodeData, expiry: SystemTime) -> Result<AuthCodeData, ()>;
    async fn get_client(&self, client_id: &ClientId) -> Result<Option<Client>, ()>;
    async fn put_client(
        &self,
        client_id: ClientId,
        secret: HashedClientSecret,
    ) -> Result<Client, ()>;
    async fn get_authcode_data(
        &self,
        client_id: &ClientId,
        code: &AuthCode,
    ) -> Result<AuthCodeData, ()>;
    async fn clean_up(&self) -> Result<(), ()>;
    async fn trim_client_scopes(&self, client_id: &ClientId, scope: &Scope) -> Result<Scope, ()>;
    async fn store_challenge_data(&self, info: ChallengeData) -> Result<ChallengeId, ()>;
    async fn get_challenge_data(&self, id: &ChallengeId) -> Result<Option<ChallengeData>, ()>;
    async fn update_challenge_data(&self, info: ChallengeData) -> Result<ChallengeData, ()>;
}

#[async_trait]
pub trait Provider {
    async fn authorization_request(
        &self,
        req: AuthorizationRequest,
    ) -> Result<MaybeChallenge<Redirect<AuthorizationResponse>>, AuthorizationError>;
    async fn access_token_request(
        &self,
        credentials: ClientCredentials,
        req: TokenRequest,
    ) -> Result<AccessTokenResponse, AccessTokenError>;
    async fn get_challenge_info(&self, id: ChallengeId) -> Option<ChallengeData>;
    async fn update_challenge_info_request(
        &self,
        id: ChallengeId,
        req: UpdateChallengeDataRequest,
    ) -> Result<UpdateChallengeDataResponse, ()>;
}
