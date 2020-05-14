use tomiko_core::types::AuthCode;

pub trait FromRandom {
    fn from_random() -> Self;
}

impl FromRandom for AuthCode {
    fn from_random() -> Self {
	AuthCode(
	    random_string(32)
	)
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