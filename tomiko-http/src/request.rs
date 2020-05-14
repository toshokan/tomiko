use tomiko_core::types::{
    AuthCode,
    ClientId,
    ClientSecret,
    GrantType,
    Scope,
    RedirectUri,
    ResponseType
};

#[derive(Debug)]
#[derive(serde::Deserialize)]
struct AuthRequest {
    response_type: ResponseType,
    client_id: ClientId,
    redirect_uri: RedirectUri,
    scope: Scope,
    state: String
}

#[derive(Debug)]
#[derive(serde::Deserialize)]
struct TokenRequest {
    grant_type: GrantType,
    client_id: ClientId,
    client_secret: ClientSecret,
    redirect_uri: RedirectUri,
    code: AuthCode
}
