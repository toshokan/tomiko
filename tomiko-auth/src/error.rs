// #[allow(dead_code)] // TODO
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
