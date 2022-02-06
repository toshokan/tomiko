use crate::auth::{
    pkce, AccessTokenError, AccessTokenErrorKind, AccessTokenResponse, ClientCredentials, Store,
    TokenRequest,
};
use crate::core::models::{
    AuthorizationData, AuthorizationDataExt, PersistentSeed, PersistentSeedId,
};
use crate::provider::token::TokenService;
use crate::util::random::FromRandom;

use super::OAuth2Provider;

use tracing::{event, Level};

impl OAuth2Provider {
    #[tracing::instrument(skip_all, fields(client_id = ?credentials.client_id))]
    pub async fn access_token_request(
        &self,
        credentials: ClientCredentials,
        req: TokenRequest,
    ) -> Result<AccessTokenResponse, AccessTokenError> {
        event!(Level::TRACE, "Handling access token request");
        let client = self.check_client_authentication(&credentials).await?;

        use TokenRequest::*;

        match req {
            AuthenticationCode(req) => {
                event!(Level::TRACE, "Handling authorization_code grant");
                let hashed_code = self.hasher.hash_without_salt(&req.code);

                let data = self
                    .store
                    .take_authcode_data(&client.id, &hashed_code)
                    .map_err(|_| AccessTokenErrorKind::InvalidGrant)?;

                if let Some(challenge) = data.req.ext.pkce_challenge {
                    event!(Level::DEBUG, "Verifying PKCE challenge");
                    pkce::verify(&challenge, req.pkce_verifier.as_ref())?;
                }

                if &data.req.redirect_uri == &req.redirect_uri
                    && &data.req.client_id == &credentials.client_id
                {
                    let access_token =
                        self.token
                            .new_token(&client.id, &data.subject, &data.req.scope);
                    let token_type = TokenService::token_type();

                    let oidc = if data.req.scope.has_openid() || data.req.ext.oidc.is_some() {
                        event!(Level::DEBUG, "Processing OpenID Connect extension data");
                        let nonce = data
                            .req
                            .ext
                            .oidc
                            .as_ref()
                            .map(|o| o.nonce.clone())
                            .flatten();
                        Some(crate::oidc::AccessTokenResponse {
                            id_token: self.token.new_id_token(
                                &client.id,
                                &data.subject,
                                nonce.as_ref(),
                            ),
                        })
                    } else {
                        None
                    };

                    let refresh_token = if data.req.scope.has_refresh() {
                        let seed = PersistentSeed {
                            id: PersistentSeedId::from_random(),
                            client_id: client.id.clone(),
                            subject: data.subject.clone(),
                            auth_data: AuthorizationData {
                                scope: data.req.scope.clone(),
                                ext: AuthorizationDataExt {
                                    oidc: data.req.ext.oidc,
                                },
                            },
                        };
                        event!(
                            Level::DEBUG,
                            "t/ps" = ?seed.id,
                            "sub" = ?seed.subject,
                            "Generating persistent seed"
                        );
                        self.store
                            .store_persistent_seed(&seed)
                            .map_err(|_| AccessTokenErrorKind::InvalidRequest)?;

                        let (token, data) = self.token.new_refresh_token(&seed);
                        self.store
                            .put_refresh_token(data)
                            .map_err(|_| AccessTokenErrorKind::InvalidGrant)?;
                        Some(token)
                    } else {
                        None
                    };

                    Ok(AccessTokenResponse {
                        access_token,
                        token_type,
                        refresh_token,
                        expires_in: Some(15 * 60),
                        oidc,
                    })
                } else {
                    Err(AccessTokenErrorKind::InvalidGrant.into())
                }
            }
            ClientCredentials(req) => {
                event!(Level::TRACE, "Handling client_credentials grant");
                let scope = self.store.trim_client_scopes(&client.id, &req.scope);

                let scope = match scope {
                    Ok(scope) if scope == req.scope => scope,
                    _ => {
                        event!(
                            Level::ERROR,
                            scope = %req.scope.as_joined(),
                            "Invalid scopes for client"
                        );
                        return Err(AccessTokenErrorKind::InvalidGrant.into());
                    }
                };

                let access_token =
                    self.token
                        .new_token(&client.id, &client.id.0.to_string(), &scope);
                let token_type = TokenService::token_type();

                Ok(AccessTokenResponse {
                    access_token,
                    token_type,
                    refresh_token: None,
                    expires_in: None,
                    oidc: None,
                })
            }
            RefreshToken(req) => {
                event!(Level::TRACE, "Handling refresh_tokens grant");
                let claims = self
                    .token
                    .validate_refresh_token(&req.refresh_token)
                    .map_err(|_| AccessTokenErrorKind::InvalidGrant)?;

                let seed = self
                    .store
                    .find_refresh_token_seed(&claims.jti)
                    .map_err(|_| AccessTokenErrorKind::InvalidGrant)?
                    .ok_or(AccessTokenErrorKind::InvalidGrant)?;

                self.store
                    .invalidate_refresh_token(&claims.jti)
                    .map_err(|_| AccessTokenErrorKind::InvalidGrant)?;

                if client.id != seed.client_id {
                    event!(
                    Level::WARN,
                    original_client_id = ?seed.client_id,
                    refresh_client_id = ?client.id,
                    "client_ids do not match"
                    );
                    Err(AccessTokenErrorKind::InvalidGrant)?
                }

                let scope = match req.scope {
                    Some(scope) => {
                        if seed.auth_data.scope.contains_all(&scope) {
                            scope
                        } else {
                            // This scope was not in the original request
                            Err(AccessTokenErrorKind::InvalidGrant)?
                        }
                    }
                    None => seed.auth_data.scope.clone(),
                };

                let access_token = self.token.new_token(&client.id, &seed.subject, &scope);
                let token_type = TokenService::token_type();

                let oidc = if scope.has_openid() || seed.auth_data.ext.oidc.is_some() {
                    event!(Level::DEBUG, "Processing OpenID Connect extension data");
                    let nonce = seed
                        .auth_data
                        .ext
                        .oidc
                        .as_ref()
                        .map(|o| o.nonce.clone())
                        .flatten();
                    Some(crate::oidc::AccessTokenResponse {
                        id_token: self.token.new_id_token(
                            &client.id,
                            &seed.subject,
                            nonce.as_ref(),
                        ),
                    })
                } else {
                    None
                };

                let refresh_token = if scope.has_refresh() {
                    let (token, data) = self.token.new_refresh_token(&seed);
                    self.store
                        .put_refresh_token(data)
                        .map_err(|_| AccessTokenErrorKind::InvalidGrant)?;
                    Some(token)
                } else {
                    None
                };

                Ok(AccessTokenResponse {
                    access_token,
                    token_type,
                    refresh_token,
                    expires_in: Some(15 * 60),
                    oidc,
                })
            }
        }
    }
}
