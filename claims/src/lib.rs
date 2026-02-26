use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub iat: i64,
    pub exp: i64,
    pub nbf: i64,
    pub jti: String,
    pub iss: String,
    pub aud: String,
    pub scope: String,
}
