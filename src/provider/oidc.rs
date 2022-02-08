use crate::{
    core::types::{ClientId, Scope},
    oidc::{self, models::AuthorizationRequest, types::Nonce, AccessTokenResponse},
};

use super::OAuth2Provider;

use tracing::{event, Level};

type AuthCodeExt = oidc::AuthorizationCodeGrantAuthorizationRequest;
type ImplicitExt = oidc::ImplicitGrantAuthorizationRequest;

impl OAuth2Provider {
    pub fn handle_auth_code_oidc(
        &self,
        client_id: &ClientId,
        subject: &str,
        scope: &Scope,
        extension_data: &Option<AuthCodeExt>,
    ) -> Option<AccessTokenResponse> {
        if scope.has_openid() {
            let data = extension_data.clone().unwrap_or_default();
            self.handle_oidc(client_id, subject, data)
        } else {
	    None
	}
    }

    pub fn handle_implicit_oidc(
        &self,
        client_id: &ClientId,
        subject: &str,
        scope: &Scope,
        extension_data: &Option<ImplicitExt>,
    ) -> Option<AccessTokenResponse> {
        match extension_data {
            Some(data) if scope.has_openid() => {
                self.handle_oidc(client_id, subject, data.as_optional_nonce())
            }
            _ => None,
        }
    }

    fn handle_oidc(
        &self,
        client_id: &ClientId,
        subject: &str,
        extension_data: AuthorizationRequest<Option<Nonce>>,
    ) -> Option<AccessTokenResponse> {
        event!(Level::DEBUG, "Processing OpenID Connect extension data");
        let nonce = extension_data.nonce;

        Some(AccessTokenResponse {
            id_token: self.token.new_id_token(client_id, subject, nonce.as_ref()),
        })
    }
}
