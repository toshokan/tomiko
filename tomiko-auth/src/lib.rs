use async_trait::async_trait;
use std::time::SystemTime;
use tomiko_core::models::{AuthCodeData, Client};
use tomiko_core::types::{
    AuthCode, ClientId, ClientSecret, HashedClientSecret, RedirectUri, Scope,
};

#[derive(Debug)]
#[cfg_attr(feature = "serde-traits", derive(serde::Deserialize))]
pub struct AuthorizationCodeGrantAuthorizationRequest {
    pub client_id: ClientId,
    pub redirect_uri: RedirectUri,
    pub scope: Scope,
    pub state: Option<String>,
}

#[derive(Debug)]
#[cfg_attr(feature = "serde-traits", derive(serde::Deserialize))]
pub struct ImplicitGrantAuthorizationRequest {
    client_id: ClientId,
    redirect_uri: RedirectUri,
    scope: Scope,
    state: Option<String>,
}

#[derive(Debug)]
#[cfg_attr(
    feature = "serde-traits",
    derive(serde::Deserialize),
    serde(tag = "response_type")
)]
pub enum AuthorizationRequest {
    #[cfg_attr(feature = "serde-traits", serde(rename = "code"))]
    AuthorizationCode(AuthorizationCodeGrantAuthorizationRequest),
    #[cfg_attr(feature = "serde-traits", serde(rename = "token"))]
    Implicit(ImplicitGrantAuthorizationRequest),
}

#[derive(Debug)]
#[cfg_attr(feature = "serde-traits", derive(serde::Deserialize))]
pub struct AuthenticationCodeTokenRequest {
    pub redirect_uri: RedirectUri,
    pub code: AuthCode,
}

#[derive(Debug)]
#[cfg_attr(feature = "serde-traits", derive(serde::Deserialize))]
pub struct ResourceOwnerPasswordCredentialsTokenRequest {
    username: String,
    password: String,
    scope: Scope,
}

#[derive(Debug)]
#[cfg_attr(feature = "serde-traits", derive(serde::Deserialize))]
pub struct ClientCredentialsTokenRequest {
    pub scope: Scope,
}

#[derive(Debug)]
#[cfg_attr(
    feature = "serde-traits",
    derive(serde::Deserialize),
    serde(tag = "grant_type")
)]
pub enum TokenRequest {
    #[cfg_attr(feature = "serde-traits", serde(rename = "authorization_code"))]
    AuthenticationCode(AuthenticationCodeTokenRequest),
    #[cfg_attr(feature = "serde-traits", serde(rename = "password"))]
    ResourceOwnerPasswordCredentials(ResourceOwnerPasswordCredentialsTokenRequest),
    #[cfg_attr(feature = "serde-traits", serde(rename = "client_credentials"))]
    ClientCredentials(ClientCredentialsTokenRequest),
}

#[derive(Debug)]
#[cfg_attr(feature = "serde-traits", derive(serde::Serialize))]
pub struct AuthorizationResponse {
    code: AuthCode,
    #[cfg_attr(
        feature = "serde-traits",
        serde(skip_serializing_if = "Option::is_none")
    )]
    state: Option<String>,
}

impl AuthorizationResponse {
    pub fn new(code: AuthCode, state: Option<String>) -> Self {
        Self { code, state }
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "serde-traits", derive(serde::Serialize))]
pub struct TokenType(String);

#[cfg_attr(feature = "serde-traits", derive(serde::Serialize))]
#[derive(Debug)]
pub struct AccessTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub refresh_token: Option<String>,
    pub expires_in: Option<u32>,
    pub scope: Option<Scope>,
}

#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "serde-traits",
    derive(serde::Serialize),
    serde(rename_all = "snake_case")
)]
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
#[cfg_attr(
    feature = "serde-traits",
    derive(serde::Serialize),
    serde(rename_all = "snake_case")
)]
pub struct AuthorizationError {
    #[cfg_attr(feature = "serde-traits", serde(rename = "error"))]
    pub kind: AuthorizationErrorKind,
    #[cfg_attr(feature = "serde-traits", serde(rename = "error_description"))]
    pub description: Option<String>,
    #[cfg_attr(
        feature = "serde-traits",
        serde(rename = "error_uri"),
        serde(skip_serializing_if = "Option::is_none")
    )]
    pub uri: Option<String>,
    #[cfg_attr(
        feature = "serde-traits",
        serde(skip_serializing_if = "Option::is_none")
    )]
    pub state: Option<String>,
}

macro_rules! make_helper {
    ($name: ident, $variant: path) => {
        pub fn $name(state: &Option<String>) -> Self {
            Self {
                kind: $variant,
                description: None,
                uri: None,
                state: state.as_ref().map(ToString::to_string),
            }
        }
    };
}

impl AuthorizationError {
    make_helper!(server_error, AuthorizationErrorKind::ServerError);
    make_helper!(
        unauthorized_client,
        AuthorizationErrorKind::UnauthorizedClient
    );
}

#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "serde-traits",
    derive(serde::Serialize),
    serde(rename_all = "snake_case")
)]
pub enum AccessTokenErrorKind {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    UnauthorizedClient,
    UnsupportedGrantType,
    InvalidScope,
}

#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "serde-traits",
    derive(serde::Serialize),
    serde(rename_all = "snake_case")
)]
pub struct AccessTokenError {
    #[cfg_attr(feature = "serde-traits", serde(rename = "error"))]
    pub kind: AccessTokenErrorKind,
    #[cfg_attr(feature = "serde-traits", serde(rename = "error_description"))]
    pub description: Option<String>,
    #[cfg_attr(
        feature = "serde-traits",
        serde(rename = "error_uri"),
        serde(skip_serializing_if = "Option::is_none")
    )]
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
#[cfg_attr(feature = "serde-traits", derive(serde::Deserialize))]
pub struct ClientCredentials {
    pub client_id: ClientId,
    pub client_secret: ClientSecret,
}

#[derive(Debug)]
#[cfg_attr(feature = "serde-traits", derive(serde::Serialize))]
pub struct Challenge {
    pub id: String
}

#[derive(Debug)]
#[cfg_attr(feature = "serde-traits", derive(serde::Serialize))]
pub struct ChallengeInfo {
    pub id: String,
    pub client_id: ClientId,
    pub uri: RedirectUri,
    pub scope: Scope,
}

#[derive(Debug)]
#[cfg_attr(feature = "serde-traits", derive(serde::Deserialize))]
pub enum UpdateChallengeInfoRequest {
    Accept,
    Reject
}

#[derive(Debug)]
#[cfg_attr(feature = "serde-traits", derive(serde::Serialize))]
pub enum UpdateChallengeInfoResponse {
    RedirectTo(RedirectUri)
}

pub enum MaybeChallenge<T> {
    Challenge(Challenge),
    Accept(T)
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
	    Err(e) => Accept(Err(e))
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
    async fn get_challenge_info(&self, id: String) -> Result<Option<ChallengeInfo>, ()>;
}

#[async_trait]
pub trait Provider {
    async fn authorization_request(
        &self,
        req: AuthorizationRequest,
    ) -> Result<MaybeChallenge<AuthorizationResponse>, AuthorizationError>;
    async fn access_token_request(
        &self,
        credentials: ClientCredentials,
        req: TokenRequest,
    ) -> Result<AccessTokenResponse, AccessTokenError>;
    async fn get_challenge_info(
	&self,
	id: String
    ) -> Option<ChallengeInfo>;
    async fn update_challenge_info_request(
	&self,
	id: String,
	req: UpdateChallengeInfoRequest
    ) -> Result<UpdateChallengeInfoResponse, ()>;
}


