pub mod types;
pub mod models;

use crate::core::types::Scope;
use types::Nonce;
use models::AuthorizationRequest;

pub type AuthorizationCodeGrantAuthorizationRequest = AuthorizationRequest<Option<Nonce>>;
pub type ImplicitGrantAuthorizationRequest = AuthorizationRequest<Nonce>;

impl Scope {
    pub fn has_openid(&self) -> bool {
	self.borrow_parts().iter().find(|p| p == &"openid").is_some()
    }
}
