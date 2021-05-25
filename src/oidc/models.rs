use crate::auth::AuthorizationRequest as OAuthAuthorizationRequest;
use super::types::{Display, Prompt};

#[derive(Debug)]
#[derive(serde::Deserialize)]
struct AuthorizationRequest {
    #[serde(flatten)]
    oauth: OAuthAuthorizationRequest,
    nonce: Option<String>,
    display: Option<Display>,
    prompt: Option<Prompt>,
    max_age: Option<u64>,
    ui_locales: Option<String>,
    id_token_hint: Option<String>,
    login_hint: Option<String>,
    acr_values: Option<String>
}
