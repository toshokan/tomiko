use std::{
    collections::HashSet,
    str::FromStr,
    time::{Duration, SystemTime},
};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantType {
    AuthorizationCode,
}

#[derive(Debug, Clone, Eq)]
pub struct Scope(HashSet<String>);

impl Scope {
    pub fn from_parts(mut parts: Vec<String>) -> Self {
        let set = parts.drain(..).collect();
        Self(set)
    }

    pub fn from_delimited_parts(parts: &str) -> Self {
        let parts = parts.split(' ').map(ToString::to_string).collect();
        Self(parts)
    }

    pub fn as_joined(&self) -> String {
        self.0
            .iter()
            .map(AsRef::as_ref)
            .collect::<Vec<&str>>()
            .join(" ")
    }

    pub fn contains(&self, scope: &str) -> bool {
        self.0.contains(scope)
    }

    pub fn as_parts(&self) -> Vec<String> {
        self.0.iter().cloned().collect()
    }

    pub fn contains_all(&self, other: &Scope) -> bool {
        self.0.is_superset(&other.0)
    }

    pub fn trim_privileged(&mut self) {
        self.0 = self
            .0
            .drain()
            .filter(|s| !s.starts_with("tomiko::"))
            .collect()
    }
}

impl PartialEq for Scope {
    fn eq(&self, other: &Self) -> bool {
        let mut lhs = self.as_parts();
        let mut rhs = other.as_parts();
        lhs.sort();
        rhs.sort();
        lhs == rhs
    }
}

impl<'de> Deserialize<'de> for Scope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let parts = String::deserialize(deserializer)?;
        Ok(Self::from_delimited_parts(&parts))
    }
}

impl Serialize for Scope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let joined = self.as_joined();
        serializer.serialize_str(&joined)
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseType {
    Code,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(transparent)]
pub struct ClientId(pub String); // TODO

impl FromStr for ClientId {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_string()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
#[serde(transparent)]
pub struct RedirectUri(pub String); // TODO

#[derive(Debug, serde::Deserialize)]
#[serde(transparent)]
pub struct ClientSecret(pub String); // TODO

impl AsRef<str> for ClientSecret {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct HashedClientSecret(pub String);

impl HashedClientSecret {
    pub fn from_raw(raw: String) -> Self {
        Self(raw)
    }
}

impl From<String> for HashedClientSecret {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl AsRef<str> for HashedClientSecret {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(transparent)]
pub struct AuthCode(pub String); // TODO
impl AsRef<str> for AuthCode {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub struct HashedAuthCode(pub String);
impl From<String> for HashedAuthCode {
    fn from(from: String) -> Self {
        Self(from)
    }
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(transparent)]
pub struct ChallengeId(pub String);

impl std::str::FromStr for ChallengeId {
    type Err = std::convert::Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_string()))
    }
}

#[derive(Debug)]
pub struct BearerToken(pub String);

pub struct Expiry(SystemTime);

impl Into<i64> for Expiry {
    fn into(self) -> i64 {
        use std::convert::TryInto;

        self.0
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs()
            .try_into()
            .unwrap_or(0)
    }
}

pub trait Expire {
    const EXPIRES_IN_SECS: u64;

    fn expiry() -> Expiry {
        let time = SystemTime::now()
            .checked_add(Duration::from_secs(Self::EXPIRES_IN_SECS))
            .unwrap_or(SystemTime::now());
        Expiry(time)
    }
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(transparent)]
pub struct TokenId(pub String);
