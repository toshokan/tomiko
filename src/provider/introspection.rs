use crate::{auth::{ClientCredentials, introspection::{IntrospectionRequest, IntrospectionResponse, IntrospectionClaims, TokenTypeHint}}, core::types::ClientId};

use super::{OAuth2Provider, token::TokenService};
use super::Error;

use tracing::{event, Level};

impl OAuth2Provider {
    #[tracing::instrument(skip(self, credentials), fields(client_id = ?credentials.client_id))]
    pub async fn introspection_request(
	&self,
	credentials: ClientCredentials,
	request: IntrospectionRequest
    ) -> Result<IntrospectionResponse, Error> {
	self.check_client_authentication(&credentials)
	    .await
	    .map_err(|_| Error::Unauthorized)?;

	match request.token_type_hint {
	    None | Some(TokenTypeHint::AccessToken) => {
		let claims = self.token.validate_token(&request.token);

		if let Ok(claims) = claims {
		    event!(Level::DEBUG, sub = ?claims.sub, "Valid access token");
		    return Ok(IntrospectionResponse {
			active: true,
			token_type: Some(TokenService::token_type()),
			claims: Some(IntrospectionClaims {
			    scope: claims.scope,
			    client_id: ClientId(claims.client_id),
			    username: claims.sub.clone(),
			    exp: claims.exp,
			    iat: claims.iat,
			    nbf: claims.nbf,
			    sub: claims.sub,
			    aud: claims.aud,
			    iss: claims.iss,
			    jti: claims.jti
			})
		    });
		}
	    },
	    Some(TokenTypeHint::RefreshToken) => {
		let seed = self.token.validate_refresh_token(&request.token)
		    .and_then(|t| self.store.find_refresh_token_seed(&t.jti));

		if let Ok(Some(seed)) = seed {
		    event!(Level::DEBUG, sub = ?seed.subject, "Valid refresh token");
		    return Ok(IntrospectionResponse {
			active: true,
			token_type: None,
			claims: None
		    });
		}
	    }
	}

	event!(Level::WARN, "Invalid token");
	Ok(IntrospectionResponse {
	    active: false,
	    token_type: None,
	    claims: None,
	})
    }
}
