use super::error::AuthRejection;
use warp::reply::{Reply, Response};
use warp::Rejection;

pub struct FormEncoded {
    inner: Result<String, ()>,
}

impl FormEncoded {
    pub fn encode(body: impl serde::Serialize) -> Self {
        let inner = serde_urlencoded::to_string(body).map_err(|_| ());
        Self { inner }
    }
}

impl warp::reply::Reply for FormEncoded {
    fn into_response(self) -> Response {
        use warp::http::Response;

        match self.inner {
            Ok(body) => {
                let mut response = Response::new(body.into());
                response.headers_mut().insert(
                    "content-type",
                    warp::hyper::header::HeaderValue::from_static(
                        "application/x-www-form-urlencoded",
                    ),
                );
                response
            }
            Err(_) => warp::http::StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
}

pub fn form_encode(
    value: Result<impl serde::Serialize, impl Into<AuthRejection>>,
) -> Result<impl Reply, Rejection> {
    value
        .map(|v| FormEncoded::encode(v))
        .map_err(|e| warp::reject::custom::<AuthRejection>(e.into()))
}