use crate::{auth::{ClientCredentials, introspection::{IntrospectionRequest, IntrospectionResponse, IntrospectionClaims}}, core::types::ClientId};

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
	
	let claims = self.token.validate_token(&request.token);
	
	match claims {
	    Ok(claims) => {
		event!(Level::DEBUG, sub = ?claims.sub, "Valid token");
		Ok(IntrospectionResponse {
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
		})
	    },
	    _ => {
		event!(Level::WARN, "Invalid token");
		Ok(IntrospectionResponse {
		    active: false,
		    token_type: None,
		    claims: None,
		})
	    }
	}
    }
}
