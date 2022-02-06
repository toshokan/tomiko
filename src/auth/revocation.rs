use super::{TokenTypeHint, ErrorResponse};


#[derive(Debug)]
#[derive(serde::Deserialize)]
pub struct RevocationRequest {
    pub token: String,
    pub token_type_hint: Option<TokenTypeHint>
}

#[derive(Debug)]
#[derive(serde::Serialize)]
#[serde(rename_all="snake_case")]
pub enum RevocationErrorKind {
    UnsupportedTokenType
}

pub type RevocationError = ErrorResponse<RevocationErrorKind>;
