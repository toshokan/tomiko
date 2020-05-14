#[cfg(feature = "serde-traits")]
use serde::{Deserialize, Deserializer};

#[derive(Debug)]
#[cfg_attr(feature = "serde-traits",
	   derive(serde::Deserialize),
	   serde(rename_all="snake_case")
)]
pub enum GrantType {
    AuthorizationCode
}

#[derive(Debug)]
pub struct Scope(Vec<String>);

#[cfg(feature = "serde-traits")]
impl<'de> Deserialize<'de> for Scope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
	let parts = String::deserialize(deserializer)?
	    .split(' ')
	    .map(ToString::to_string)
	    .collect();
	Ok(Self(parts))
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "serde-traits",
	   derive(serde::Deserialize),
	   serde(rename_all="snake_case")
)]
pub enum ResponseType {
    Code
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde-traits",
	   derive(serde::Deserialize),
	   serde(transparent)
)]
#[cfg_attr(feature = "sqlx-traits",
	   derive(sqlx::Type),
	   sqlx(transparent)
)]
pub struct ClientId(String);

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde-traits",
	   derive(serde::Deserialize),
	   serde(transparent)
)]
#[cfg_attr(feature = "sqlx-traits",
	   derive(sqlx::Type),
	   sqlx(transparent)
)]
pub struct RedirectUri(String);

#[derive(Debug)]
#[cfg_attr(feature = "serde-traits",
	   derive(serde::Deserialize),
	   serde(transparent)
)]
#[cfg_attr(feature = "sqlx-traits",
	   derive(sqlx::Type),
	   sqlx(transparent)
)]
pub struct ClientSecret(String);

#[derive(Debug)]
#[cfg_attr(feature = "serde-traits",
	   derive(serde::Serialize),
	   derive(serde::Deserialize),
	   serde(transparent)
)]
#[cfg_attr(feature = "sqlx-traits",
	   derive(sqlx::Type),
	   sqlx(transparent)
)]
pub struct AuthCode(pub String); // TODO

// impl AuthCode {
//     pub fn random() -> Self {
// 	Self(random_string(32))
//     }
// }
