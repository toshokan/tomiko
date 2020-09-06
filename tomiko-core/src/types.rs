#[cfg(feature = "serde-traits")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug)]
#[cfg_attr(
    feature = "serde-traits",
    derive(serde::Deserialize),
    serde(rename_all = "snake_case")
)]
pub enum GrantType {
    AuthorizationCode,
}

#[derive(Debug, Clone)]
pub struct Scope(Vec<String>);

impl Scope {
    pub fn from_parts(parts: Vec<String>) -> Self {
	Self(parts)
    }
    
    pub fn from_delimited_parts(parts: &str) -> Self {
        let parts = parts.split(' ').map(ToString::to_string).collect();
        Self(parts)
    }

    pub fn as_joined(&self) -> String {
        self.0.join(" ")
    }

    pub fn as_parts(&self) -> Vec<String> {
	self.0.iter().cloned().collect()
    }
}

#[cfg(feature = "serde-traits")]
impl<'de> Deserialize<'de> for Scope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let parts = String::deserialize(deserializer)?;
        Ok(Self::from_delimited_parts(&parts))
    }
}

#[cfg(feature = "serde-traits")]
impl Serialize for Scope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let joined = self.0.join(" ");
        serializer.serialize_str(&joined)
    }
}

#[derive(Debug)]
#[cfg_attr(
    feature = "serde-traits",
    derive(serde::Deserialize),
    serde(rename_all = "snake_case")
)]
pub enum ResponseType {
    Code,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(
    feature = "serde-traits",
    derive(serde::Serialize),
    derive(serde::Deserialize),
    serde(transparent)
)]
pub struct ClientId(pub String); // TODO

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde-traits",
    derive(serde::Serialize),
    derive(serde::Deserialize),
    serde(transparent)
)]
pub struct RedirectUri(pub String); // TODO

#[derive(Debug)]
#[cfg_attr(
    feature = "serde-traits",
    derive(serde::Deserialize),
    serde(transparent)
)]
pub struct ClientSecret(pub String); // TODO

#[derive(Debug, Eq, PartialEq)]
pub struct HashedClientSecret(pub String);

impl HashedClientSecret {
    pub fn from_raw(raw: String) -> Self {
        Self(raw)
    }
}

#[derive(Debug)]
#[cfg_attr(
    feature = "serde-traits",
    derive(serde::Serialize),
    derive(serde::Deserialize),
    serde(transparent)
)]
pub struct AuthCode(pub String); // TODO

#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "serde-traits",
    derive(serde::Serialize),
    derive(serde::Deserialize),
    serde(transparent)
)]
pub struct ChallengeId(pub String);

impl std::str::FromStr for ChallengeId {
    type Err = std::convert::Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
	Ok(Self(s.to_string()))
    }
}
