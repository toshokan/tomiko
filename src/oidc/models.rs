use super::types::{Display, Prompt};

#[derive(Debug, Clone, Default, PartialEq)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct AuthorizationRequest<N> {
    pub nonce: N,
    display: Option<Display>,
    prompt: Option<Prompt>,
    max_age: Option<u64>,
    ui_locales: Option<String>,
    id_token_hint: Option<String>,
    login_hint: Option<String>,
    acr_values: Option<String>
}

impl<N> AuthorizationRequest<N>
where
    N: Default,
    N: PartialEq<N>,
{
    pub(crate) fn deserialize_skip_default<'de, D>(d: D) -> Result<Option<Self>, D::Error>
    where
	D: serde::Deserializer<'de>,
	N: serde::Deserialize<'de>
    {
	use serde::Deserialize;
	
	let result = Self::deserialize(d)?;
	if Self::is_default(&result) {
	    Ok(None)
	} else {
	    Ok(Some(result))
	}
    }
    
    fn is_default(&self) -> bool {
	let default = Self::default();
	&default == self
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct AccessTokenResponse {
    pub id_token: String
}
