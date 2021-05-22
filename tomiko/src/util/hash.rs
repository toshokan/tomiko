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

impl HashingService {
    pub fn with_secret_key(secret_key: String) -> Self {
        Self { secret_key }
    }

    pub fn hash(&self, secret: &ClientSecret) -> Result<HashedClientSecret, ()> {
        let mut hasher = argonautica::Hasher::default();
        let hash = hasher
            .with_password(&secret.0)
            .with_secret_key(&self.secret_key)
            .hash()
            .expect("Failed to hash"); // TODO

        Ok(HashedClientSecret(hash))
    }

    pub fn verify(&self, secret: &ClientSecret, hashed: &HashedClientSecret) -> Result<bool, ()> {
        let mut verifier = argonautica::Verifier::default();
        verifier
            .with_secret_key(&self.secret_key)
            .with_password(&secret.0)
            .with_hash(&hashed.0)
            .verify()
            .map_err(|_| ())
    }
}
