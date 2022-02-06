use super::{AccessTokenError, AccessTokenErrorKind};

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub enum Transformation {
    #[serde(rename = "plain")]
    Plain,
    S256,
}

impl Default for Transformation {
    fn default() -> Self {
        Self::Plain
    }
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct Challenge {
    #[serde(rename = "code_challenge")]
    pub code: String,
    #[serde(rename = "code_challenge_method")]
    #[serde(default)]
    pub method: Transformation,
}

#[derive(Debug, serde::Deserialize)]
pub struct Verifier {
    #[serde(rename = "code_verifier")]
    pub value: String,
}

pub fn verify(challenge: &Challenge, verifier: Option<&Verifier>) -> Result<(), AccessTokenError> {
    use sha2::{Digest, Sha256};

    if let Some(verifier) = verifier {
        use Transformation::*;
        let matches = match challenge.method {
            Plain => challenge.code == verifier.value,
            S256 => {
                let digest = Sha256::digest(verifier.value.as_bytes());
                let digest = base64::encode_config(digest, base64::URL_SAFE_NO_PAD);
                digest == challenge.code
            }
        };
        if matches {
            Ok(())
        } else {
            Err(AccessTokenError::from(AccessTokenErrorKind::InvalidRequest))
        }
    } else {
        Err(AccessTokenError::from(AccessTokenErrorKind::InvalidRequest))
    }
}
