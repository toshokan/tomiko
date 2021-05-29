pub mod types;
pub mod models;

pub type AuthorizationCodeGrantAuthorizationRequest = models::AuthorizationRequest<Option<types::Nonce>>;
pub type ImplicitGrantAuthorizationRequest = models::AuthorizationRequest<types::Nonce>;
