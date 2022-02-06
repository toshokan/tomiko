use super::{ErrorResponse, TokenTypeHint};

#[derive(Debug, serde::Deserialize)]
pub struct RevocationRequest {
    pub token: String,
    pub token_type_hint: Option<TokenTypeHint>,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationErrorKind {
    UnsupportedTokenType,
}

pub type RevocationError = ErrorResponse<RevocationErrorKind>;
