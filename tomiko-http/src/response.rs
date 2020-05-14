use tomiko_core::types::AuthCode;

#[derive(Debug, serde::Serialize)]
struct AuthResponse {
    code: AuthCode,
    state: String,
}
