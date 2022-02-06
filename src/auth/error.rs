#[derive(Debug, Clone)]
#[derive(serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ErrorResponse<K> {
    #[serde(rename = "error")]
    pub kind: K,
    #[serde(rename = "error_description")]
    pub description: Option<String>,
    #[serde(rename = "error_uri")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
}

#[derive(Debug, Clone)]
#[derive(serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    InvalidRequest,
    UnauthorizedClient,
    InvalidScope,
}

#[derive(Debug, Clone)]
#[derive(serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKindExt {
    ServerError,
    TemporarilyUnavailable
}


#[derive(Debug, Clone)]
#[derive(serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessTokenErrorKind {
    Base(ErrorKind),
    Ext(ErrorKindExt),
    InvalidClient,
    InvalidGrant,
    UnsuportedGrantType
}
