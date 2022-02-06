use crate::auth::{revocation::RevocationRequest, ClientCredentials, TokenTypeHint};

use super::{error::Error, OAuth2Provider};

use tracing::{event, Level};

impl OAuth2Provider {
    #[tracing::instrument(
	skip(self, credentials),
	fields(client_id = ?credentials.client_id)
    )]
    pub async fn revocation_request(
        &self,
        credentials: ClientCredentials,
        request: RevocationRequest,
    ) -> Result<(), Error> {
        self.check_client_authentication(&credentials)
            .await
            .map_err(|_| Error::Unauthorized)?;

        match request.token_type_hint {
            None | Some(TokenTypeHint::AccessToken) => {
                event!(Level::WARN, "Unsupported revocation type");
                Err(Error::BadRequest)?
            }
            Some(TokenTypeHint::RefreshToken) => {
                let seed = self
                    .token
                    .validate_refresh_token(&request.token)
                    .and_then(|t| self.store.find_refresh_token_seed(&t.jti));

                if let Ok(Some(seed)) = seed {
                    if seed.client_id != credentials.client_id {
                        event!(
                            Level::WARN,
                            original_client_id = ?seed.client_id,
                            revoke_client_id = ?credentials.client_id,
                            "client_ids do not match"
                        );
                        Err(Error::BadRequest)?
                    }

                    event!(
                    Level::DEBUG,
                    seed = ?seed.id,
                    "Invalidating persistent seed"
                    );
                    self.store.invalidate_seed(seed.id)?;
                }

                Ok(())
            }
        }
    }
}
