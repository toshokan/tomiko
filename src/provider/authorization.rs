use crate::{
    auth::{
        AuthorizationError, AuthorizationErrorKind, AuthorizationRedirectErrorKind,
        AuthorizationRequest, AuthorizationResponse, ChallengeData, MaybeChallenge, Redirect,
        Store,
    },
    provider::error::ResultExt,
};

use tracing::{event, Level};

use super::OAuth2Provider;

impl OAuth2Provider {
    #[tracing::instrument(skip_all)]
    pub async fn authorization_request(
        &self,
        req: AuthorizationRequest,
    ) -> Result<MaybeChallenge<Redirect<AuthorizationResponse>>, AuthorizationError> {
        let parts = req.as_parts();
        let uri = parts.redirect_uri.clone();

        self.validate_client(parts.client_id, &uri)
            .await
            .map_err(|_| AuthorizationRedirectErrorKind::BadRedirect)
            .without_redirect()?;

        let info = ChallengeData::new(&req);
        let challenge = self.make_challenge(&info.id);

        self.store
            .store_challenge_data(info)
            .map_err(|_| AuthorizationErrorKind::ServerError.into())
            .add_state_context(&parts.state)
            .add_redirect_context(uri)?;

        event!(
            Level::DEBUG,
            client_id = ?parts.client_id,
            challenge_id = ?challenge.id,
            "Issuing authorization challenge"
        );
        Ok(MaybeChallenge::Challenge(challenge))
    }
}
