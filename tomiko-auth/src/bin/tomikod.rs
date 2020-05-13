use warp::Filter;
use serde::{Deserialize, Deserializer};

use std::convert::Infallible;

use sqlx::sqlite::SqlitePool;

#[derive(Debug, Deserialize)]
struct AuthRequest {
    response_type: ResponseType,
    client_id: ClientId,
    redirect_uri: RedirectUri,
    scope: Scope,
    state: String
}

#[derive(Debug, Deserialize)]
struct TokenRequest {
    grant_type: GrantType,
    client_id: ClientId,
    client_secret: ClientSecret,
    redirect_uri: RedirectUri,
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

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[derive(sqlx::Type)]
#[sqlx(transparent)]
#[derive(serde::Deserialize)]
#[serde(transparent)]
struct ClientId(String);

#[derive(Clone, Debug)]
#[derive(sqlx::Type)]
#[sqlx(transparent)]
#[derive(serde::Deserialize)]
#[serde(transparent)]
struct RedirectUri(String);

#[derive(Debug)]
#[derive(sqlx::Type)]
#[sqlx(transparent)]
#[derive(serde::Deserialize)]
#[serde(transparent)]
struct ClientSecret(String);

#[derive(Debug, Deserialize)]
#[serde(transparent)]
struct AuthCode(String);

#[derive(Debug)]
#[derive(sqlx::FromRow)]
struct Client {
    id: ClientId,
    secret: ClientSecret
}

#[derive(Debug)]
#[derive(sqlx::FromRow)]
struct RedirectRecord {
    #[sqlx(rename="client_id")]
    id: ClientId,
    uri: RedirectUri
}

#[derive(Debug)]
enum Error {
    UnregisteredUri(RedirectUri)
}

impl warp::reject::Reject for Error {}

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

async fn ensure_uri(db: &SqlitePool, req: &AuthRequest) -> Result<(), warp::Rejection> {
    use sqlx::sqlite::SqliteQueryAs;
    
    let mut conn = db.acquire().await.unwrap();
    let result = sqlx::query_as::<_, RedirectRecord>("SELECT * FROM uris WHERE client_id = ? AND uri = ?")
        .bind(&req.client_id)
        .bind(&req.redirect_uri)
	.fetch_optional(&mut conn).await;

    if let Ok(r) = result {
	if r.is_some() {
	    return Ok(())
	}
    }
    
    Err(warp::reject::custom(Error::UnregisteredUri(req.redirect_uri.clone())))
}

async fn authorize(db: SqlitePool, req: AuthRequest) -> Result<String, warp::Rejection> {
    ensure_uri(&db, &req).await?;
    
    Ok(debug_req(req))
}

fn debug_req<R: std::fmt::Debug>(r: R) -> String {
    format!("Request {:?}", r)
}

fn random_string(size: usize) -> String {
    use rand::Rng;
    
    rand::thread_rng()
        .sample_iter(rand::distributions::Alphanumeric)
        .take(size)
        .collect()
}

fn with_db(pool: SqlitePool) -> impl Filter<Extract = (SqlitePool,), Error = Infallible> + Clone {
    warp::any().map(move || pool.clone())
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();

    let db_url = std::env::var("DATABASE_URL").expect("set DATABASE_URL");
    
    let pool = SqlitePool::builder()
        .max_size(1)
        .build(&db_url).await.unwrap();
    
    let oauth = warp::path("oauth");

    let auth = warp::path("auth")
        .and(with_db(pool.clone()))
	.and(warp::filters::query::query())
        .and_then(authorize);

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
