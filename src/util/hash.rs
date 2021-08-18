use crate::core::types::{AuthCode, ClientId, ClientSecret, HashedAuthCode, HashedClientSecret};

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

impl HashTo for AuthCode {
    type HashedType = HashedAuthCode;
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
	    .map_err(|_| ())?;
	
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

    pub fn hash_without_salt<T, H>(&self, to_hash: &T) -> H
    where
	T: HashTo<HashedType = H>,
	H: From<String>
    {
	use sha2::Digest;
	
	let to_hash = to_hash.as_ref();
	let digest = sha2::Sha512::digest(to_hash.as_bytes());
	let hash = base64::encode_config(digest, base64::URL_SAFE);
	hash.into()
    }
}
