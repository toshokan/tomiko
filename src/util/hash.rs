use crate::core::types::{ClientId, ClientSecret, HashedClientSecret};

#[derive(Debug)]
pub struct HashedClientCredentials {
    pub client_id: ClientId,
    pub client_secret: HashedClientSecret,
}

#[derive(Debug)]
pub struct HashingService {
    secret_key: String,
}

pub trait HashTo: AsRef<str> {
    type HashedType;
}

impl HashTo for ClientSecret {
    type HashedType = HashedClientSecret;
}

impl HashingService {
    pub fn with_secret_key(secret_key: String) -> Self {
        Self { secret_key }
    }

    pub fn hash<T, H>(&self, to_hash: &T) -> Result<H, ()>
    where
	T: HashTo<HashedType = H>,
	H: From<String>
    {
	let s = to_hash.as_ref();
	let mut hasher = argonautica::Hasher::default();
        let hash = hasher
            .with_password(s)
            .with_secret_key(&self.secret_key)
            .hash()
            .expect("Failed to hash"); // TODO
	Ok(hash.into())
    }

    pub fn verify<T, H>(&self, secret: &T, hashed: &H) -> Result<bool, ()>
    where
	T: HashTo<HashedType = H>,
	H: AsRef<str>
    {
	let mut verifier = argonautica::Verifier::default();
        verifier
            .with_secret_key(&self.secret_key)
            .with_password(secret.as_ref())
            .with_hash(hashed.as_ref())
            .verify()
            .map_err(|_| ())
    }
}
