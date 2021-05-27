#[derive(Debug, Clone)]
#[derive(serde::Deserialize, serde::Serialize)]
pub enum Transformation {
    #[serde(rename = "plain")]
    Plain,
    S256
}

impl Default for Transformation {
    fn default() -> Self {
	Self::Plain
    }
}

#[derive(Debug, Clone)]
#[derive(serde::Deserialize, serde::Serialize)]
pub struct Challenge {
    #[serde(rename = "code_challenge")]
    pub code: String,
    #[serde(rename = "code_challenge_method")]
    #[serde(default)]
    pub method: Transformation
}

#[derive(Debug)]
#[derive(serde::Deserialize)]
pub struct Verifier {
    #[serde(rename = "code_verifier")]
    pub value: String
}
