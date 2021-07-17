pub mod types;
pub mod models;

use crate::core::types::Scope;
use types::Nonce;
use models::AuthorizationRequest;

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
	    Self::ImplicitId{..} => true,
	    _ => false
	}
    }
}
