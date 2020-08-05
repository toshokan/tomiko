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

#[derive(Debug)]
pub struct Scope(Vec<String>);

#[cfg(feature = "serde-traits")]
impl<'de> Deserialize<'de> for Scope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let parts = String::deserialize(deserializer)?
            .split(' ')
            .map(ToString::to_string)
            .collect();
        Ok(Self(parts))
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
    derive(serde::Deserialize),
    serde(transparent)
)]
pub struct ClientId(pub String); // TODO

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde-traits",
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

#[derive(Debug)]
#[cfg_attr(
    feature = "serde-traits",
    derive(serde::Serialize),
    derive(serde::Deserialize),
    serde(transparent)
)]
pub struct AuthCode(pub String); // TODO
