use warp::Filter;
use warp::reply::Response;
use serde::{Deserialize, Deserializer};

use std::convert::Infallible;
use std::marker::PhantomData;

use sqlx::sqlite::SqlitePool;

#[derive(Debug, Deserialize)]
struct AuthRequest {
    response_type: ResponseType,
    client_id: ClientId,
    redirect_uri: RedirectUri,
    scope: Scope,
    state: String
}

#[derive(Debug)]
#[derive(serde::Serialize)]
struct AuthResponse {
    code: AuthCode,
    state: String
}

struct FormEncoded<T> {
    body: String,
    p: PhantomData<T>
}

impl<T: serde::Serialize> FormEncoded<T> {
    fn encode(t: T) -> Result<Self, serde_urlencoded::ser::Error> {
	let body = serde_urlencoded::to_string(t)?;
	Ok(Self {
	    body,
	    p: PhantomData
	})
    }
}

impl<T: Send> warp::reply::Reply for FormEncoded<T> {
    fn into_response(self) -> Response {
	let body = warp::hyper::Body::from(self.body);
	let mut request = warp::http::Response::new(body);
	request.headers_mut().insert(
	    "content-type",
	    warp::hyper::header::HeaderValue::from_static("application/x-www-form-urlencoded")
	);
	request
    }
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

#[derive(Debug)]
#[derive(sqlx::Type)]
#[sqlx(transparent)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
struct AuthCode(String);

impl AuthCode {
    pub fn random() -> Self {
	Self(random_string(32))
    }
}

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

#[allow(dead_code)] // TODO
#[derive(Clone, Debug)]
#[derive(serde::Serialize)]
#[serde(rename_all="snake_case")]
enum Error {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    UnauthorizedClient,
    UnsupportedGrantType,
    InvalidScope
}

impl Default for Error {
    fn default() -> Self { Self::InvalidRequest }
}

#[derive(Clone, Debug, Default)]
#[derive(serde::Serialize)]
struct ErrorResponse {
    error: Error,
    #[serde(rename="error_description")]
    #[serde(skip_serializing_if="Option::is_none")]
    description: Option<String>
}

impl From<Error> for ErrorResponse {
    fn from(error: Error) -> Self {
	Self {
	    error,
	    ..Default::default()
	}
    }
}

impl warp::Reply for ErrorResponse {
    fn into_response(self) -> warp::reply::Response {
	warp::reply::with_status(
	    warp::reply::json(&self),
	    warp::http::StatusCode::BAD_REQUEST
	).into_response()
    }
}

impl warp::reject::Reject for ErrorResponse {}

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

    Err(warp::reject::custom(ErrorResponse::default())) // TODO: Return the correct error
}

async fn generate_code(db: &SqlitePool, req: &AuthRequest) -> Result<AuthCode, sqlx::Error> {
    let mut conn = db.acquire().await.unwrap();
    
    let code = AuthCode::random();
    sqlx::query("INSERT INTO codes(client_id, code) VALUES(?, ?)")
        .bind(&req.client_id)
        .bind(&code)
        .execute(&mut conn).await?;

    Ok(code)
}

async fn authorize(db: SqlitePool, req: AuthRequest) -> Result<FormEncoded<AuthResponse>, warp::Rejection> {
    ensure_uri(&db, &req).await?;
    // ensure scopes
    let code = generate_code(&db, &req).await.unwrap();

    let resp = AuthResponse {
	code,
	state: req.state
    };
    
    Ok(FormEncoded::encode(resp).unwrap())
}

async fn give_token(db: SqlitePool, req: TokenRequest) -> Result<String, warp::Rejection> {
    use sqlx::sqlite::SqliteQueryAs;
    
    let mut tx = db.begin().await.unwrap();
    let code: Option<(AuthCode,)> = sqlx::query_as("SELECT code FROM codes WHERE client_id = ? AND code = ?")
        .bind(&req.client_id)
        .bind(&req.code)
        .fetch_optional(&mut tx).await.unwrap();
    
    if let Some(c) = code {
	let r = sqlx::query("DELETE FROM codes WHERE client_id = ? AND code = ?")
	    .bind(&req.client_id)
	    .bind(&c.0)
	    .execute(&mut tx).await;
	if r.is_ok() {
	    tx.commit().await.unwrap();
	    return Ok("done!".to_string())
	}
    }

    Err(warp::reject::custom(ErrorResponse::default()))
}

fn debug_req<R: std::fmt::Debug>(r: R) -> String {
    format!("Request {:?}", r)
}

async fn handle_reject(err: warp::Rejection) -> Result<impl warp::Reply, warp::Rejection> {
    if let Some(e @ ErrorResponse { .. }) = err.find() {
	Ok(e.clone())
    } else {
	Err(err)
    }
}

fn random_string(size: usize) -> String {
    use rand::Rng;
    
    let s: String = rand::thread_rng()
        .sample_iter(rand::distributions::Alphanumeric)
        .take(size)
        .collect();
    base64::encode_config(s, base64::URL_SAFE_NO_PAD)
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
        .and(with_db(pool.clone()))
        .and(warp::filters::method::post())
        .and(warp::filters::body::form())
        .and_then(give_token);

    let routes = auth
	.or(token);
    
    let v1 = oauth
        .and(warp::path("v1"))
	.and(routes)
        .recover(handle_reject);
    
    warp::serve(v1).run(([127, 0, 0, 1], 8001)).await;
}
