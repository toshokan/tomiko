use warp::reply::Response;

mod request;
mod response;

use std::marker::PhantomData;

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
