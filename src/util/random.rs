use crate::core::{models::{PersistentSeedId, RefreshTokenId}, types::{AuthCode, ChallengeId}};

pub trait FromRandom {
    fn from_random() -> Self;
}

impl FromRandom for AuthCode {
    fn from_random() -> Self {
        AuthCode(random_string(64))
    }
}

impl FromRandom for ChallengeId {
    fn from_random() -> Self {
        ChallengeId(random_string(64))
    }
}

impl FromRandom for PersistentSeedId {
    fn from_random() -> Self {
	PersistentSeedId(random_string(96))
    }
}

impl FromRandom for RefreshTokenId {
    fn from_random() -> Self {
	RefreshTokenId(random_string(128))
    }
}

fn random_string(size: usize) -> String {
    use rand::Rng;

    let s: String = rand::thread_rng()
        .sample_iter(rand::distributions::Alphanumeric)
        .take(size)
        .map(|b| b as char)
        .collect();
    base64::encode_config(s, base64::URL_SAFE_NO_PAD)
}
