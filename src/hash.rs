use crate::Body;
use argon2::{self, hash_encoded, Config};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use std::error::Error;

// Carries salt
pub struct Salt {
    salt: String,
}

// Salt generation
impl Salt {
    pub fn generate_salt() -> Self {
        let val: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(16)
            .map(char::from)
            .collect::<String>();
        Salt { salt: val }
    }
}

pub trait PasswordHash {
    fn generate_hash(&self, config: Config) -> Result<String, Box<dyn Error>>;
}

impl PasswordHash for Body {
    fn generate_hash(&self, config: Config) -> Result<String, Box<dyn Error>> {
        let salt = Salt::generate_salt();
        match self {
            Body::AuthenticationContinue {
                flags: _,
                user,
                data: _,
                ..
            } => {
                let hash = hash_encoded(user, salt.salt.as_bytes(), &config)?;
                Ok(hash)
            }
            _ => bail!("not implemented yet"),
        }
    }
}
