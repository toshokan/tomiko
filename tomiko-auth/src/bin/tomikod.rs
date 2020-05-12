use warp::Filter;
use serde::{Deserialize, Deserializer};

#[derive(Debug, Deserialize)]
struct AuthRequest {
    response_type: ResponseType,
    client_id: ClientId,
    redirect_uri: String, // TODO
    scope: Scope,
    state: String
}

#[derive(Debug)]
struct Scope(Vec<String>);

#[derive(Debug, Deserialize)]
#[serde(rename_all="lowercase")]
enum ResponseType {
    Code
}

#[derive(Debug, Deserialize)]
#[serde(transparent)]
struct ClientId(String);

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

#[tokio::main]
async fn main() {
    let oauth = warp::path("oauth");
    
    let v1 = oauth
        .and(warp::path("v1"))
        .and(warp::filters::query::query())
        .map(|r: AuthRequest| {
	    format!("Request {:?}", r)
	});
    
    warp::serve(v1).run(([127, 0, 0, 1], 8001)).await;
}
