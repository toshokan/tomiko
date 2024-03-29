pub mod models;
pub mod types;

use crate::core::types::Scope;
use models::AuthorizationRequest;
use types::Nonce;

pub type AuthorizationCodeGrantAuthorizationRequest = AuthorizationRequest<Option<Nonce>>;
pub type ImplicitGrantAuthorizationRequest = AuthorizationRequest<Nonce>;
pub use models::AccessTokenResponse;

impl Scope {
    pub fn has_openid(&self) -> bool {
        self.contains("openid")
    }
}

impl crate::auth::AuthorizationRequest {
    pub fn is_openid_grant(&self) -> bool {
        match self {
            Self::ImplicitId { .. } => true,
            _ => false,
        }
    }
}
