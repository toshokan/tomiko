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

#[derive(Debug, Deserialize)]
struct TokenRequest {
    grant_type: GrantType,
    client_id: ClientId,
    client_secret: ClientSecret,
    redirect_uri: String, // TODO,
    code: AuthCode
}

#[derive(Debug, Deserialize)]
#[serde(rename_all="snake_case")]
enum GrantType {
    AuthorizationCode
}

#[derive(Debug)]
struct Scope(Vec<String>);

#[derive(Debug, Deserialize)]
#[serde(rename_all="snake_case")]
enum ResponseType {
    Code
}

#[derive(Debug, Deserialize)]
#[serde(transparent)]
struct ClientId(String);

#[derive(Debug, Deserialize)]
#[serde(transparent)]
struct ClientSecret(String);

#[derive(Debug, Deserialize)]
#[serde(transparent)]
struct AuthCode(String);

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

fn debug_req<R: std::fmt::Debug>(r: R) -> String {
    format!("Request {:?}", r)
}

#[tokio::main]
async fn main() {
    let oauth = warp::path("oauth");

    let auth = warp::path("auth")
	.and(warp::filters::query::query())
        .map(debug_req::<AuthRequest>);

    let token = warp::path("token")
        .and(warp::filters::method::post())
        .and(warp::filters::body::form())
        .map(debug_req::<TokenRequest>);

    let routes = auth
	.or(token);
    
    let v1 = oauth
        .and(warp::path("v1"))
	.and(routes);
    
    warp::serve(v1).run(([127, 0, 0, 1], 8001)).await;
}
