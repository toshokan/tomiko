use crate::{auth::{MaybeRedirect, Redirect, WithState}, core::types::RedirectUri};

pub enum Error {
    Unauthorized,
    BadRequest,
    Db(diesel::result::Error),
    Serde(serde_json::Error)
}

impl From<diesel::result::Error> for Error {
    fn from(e: diesel::result::Error) -> Self {
	Self::Db(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
	Self::Serde(e)
    }
}

pub trait ResultExt<T, E> {
    fn redirect_ok(self, uri: RedirectUri) -> Result<Redirect<T>, E>;
    fn without_redirect<R>(self) -> Result<T, MaybeRedirect<R, E>>;
    fn add_redirect_context<D>(self, uri: RedirectUri) -> Result<T, MaybeRedirect<E, D>>;
    fn add_state_context(self, state: &Option<String>) -> Result<T, WithState<E>>;
}

impl<T, E> ResultExt<T, E> for Result<T, E> {
    fn redirect_ok(self, uri: RedirectUri) -> Result<Redirect<T>, E> {
	self.map(|o| Redirect::new(uri, o))
    }
    fn without_redirect<R>(self) -> Result<T, MaybeRedirect<R, E>> {
	self.map_err(|e| MaybeRedirect::Direct(e))
    }
    fn add_redirect_context<D>(self, uri: RedirectUri) -> Result<T, MaybeRedirect<E, D>> {
	self.map_err(|e| MaybeRedirect::Redirected(Redirect::new(
	    uri,
	    e
	)))
    }
    fn add_state_context(self, state: &Option<String>) -> Result<T, WithState<E>> {
	self.map_err(|e| WithState {
	    state: state.clone(),
	    inner: e
	})
    }
}
