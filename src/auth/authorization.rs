use crate::auth::{pkce, oidc, AccessTokenResponse};

use crate::core::types::AuthCode;
use crate::{auth::error::{ErrorResponse, ErrorKind}, core::types::{ClientId, RedirectUri, Scope}};

use super::{MaybeRedirect, WithState, ImplicitRequestExt};

pub type AuthorizationErrorResponse = WithState<ErrorResponse<AuthorizationErrorKind>>;
pub type AuthorizationError = MaybeRedirect<AuthorizationErrorResponse, AuthorizationRedirectErrorKind>;

#[derive(Debug, Clone)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(tag = "response_type")]
pub enum AuthorizationRequest {
    #[serde(rename = "code")]
    AuthorizationCode(AuthorizationRequestData<AuthorizationCodeRequestExt>),
    #[serde(rename = "token")]
    Implicit(AuthorizationRequestData<ImplicitRequestExt<Option<oidc::ImplicitGrantAuthorizationRequest>>>),
    #[serde(rename = "id_token token")]
    ImplicitId(AuthorizationRequestData<ImplicitRequestExt<oidc::ImplicitGrantAuthorizationRequest>>)
}

impl AuthorizationRequest {
    pub fn as_parts(&self) -> AuthorizationRequestParts<'_> {
	use AuthorizationRequest::*;
	
	match &self {
	    AuthorizationCode(AuthorizationRequestData {
		client_id, redirect_uri, state, scope, ..
	    }) |
	    Implicit(AuthorizationRequestData {
		client_id, redirect_uri, state, scope, ..
	    }) |
	    ImplicitId(AuthorizationRequestData {
		client_id, redirect_uri, state, scope, ..
	    })=> {
		AuthorizationRequestParts {
		    client_id,
		    redirect_uri,
		    state,
		    scope
		}
	    }
	}
    }
}

#[derive(Debug, Clone)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct AuthorizationRequestData<E> {
    pub client_id: ClientId,
    pub redirect_uri: RedirectUri,
    pub scope: Scope,
    pub state: Option<String>,
    #[serde(flatten)]
    pub ext: E
}

#[derive(Debug, Clone)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct AuthorizationCodeRequestExt {
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pkce_challenge: Option<pkce::Challenge>,
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "oidc::AuthorizationCodeGrantAuthorizationRequest::deserialize_skip_default")]
    pub oidc: Option<oidc::AuthorizationCodeGrantAuthorizationRequest>
}

#[derive(Debug, Clone)]
pub struct AuthorizationRequestParts<'r> {
    pub client_id: &'r ClientId,
    pub redirect_uri: &'r RedirectUri,
    pub state: &'r Option<String>,
    pub scope: &'r Scope
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

#[derive(Debug, Clone)]
#[derive(serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationErrorKind {
    Base(ErrorKind),
    AccessDenied,
    UnsupportedResponseType,
    ServerError,
    TemporarilyUnavailable
}

impl Into<ErrorResponse<AuthorizationErrorKind>> for AuthorizationErrorKind {
    fn into(self) -> ErrorResponse<AuthorizationErrorKind> {
	ErrorResponse {
	    kind: self,
	    description: None,
	    uri: None
	}
    }
}

#[derive(Debug, Clone)]
#[derive(serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationRedirectErrorKind {
    BadRedirect,
    BadChallenge,
}
