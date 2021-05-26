use crate::auth::{MaybeChallenge, Redirect};
use crate::core::types::{ChallengeId, RedirectUri};
use warp::reply::{Reply, Response};
use url::Url;

fn append_params(r: RedirectUri, p: impl serde::Serialize) -> Url {
    let mut url = Url::parse(&r.0).unwrap();
    let new_qs = serde_urlencoded::to_string(p).unwrap();
    let pairs = form_urlencoded::parse(&new_qs.as_bytes());
    url.query_pairs_mut().extend_pairs(pairs);
    url
}

impl<T: serde::Serialize + Send> Reply for Redirect<T> {
    fn into_response(self) -> Response {
	let url = append_params(self.uri, self.params);
	warp::http::Response::builder()
	    .header("Location", url.to_string())
	    .status(307)
	    .body(warp::hyper::Body::empty())
	    .unwrap()
    }
}

impl<T: Reply> Reply for MaybeChallenge<T> {
    fn into_response(self) -> Response {
	match self {
	    Self::Challenge(c) => {
		#[derive(serde::Serialize)]
		struct ChallengeRef {
		    #[serde(rename = "challenge-id")]
		    id: ChallengeId
		}
		let login_uri = RedirectUri("http://localhost:8002/login".to_string());
		Redirect::new(
		    login_uri,
		    ChallengeRef {
			id: c.id
		    }
		).into_response()
	    },
	    Self::Accept(r) => r.into_response()
	}
    }
}
