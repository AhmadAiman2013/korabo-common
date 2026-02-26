use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::Json;
use axum::response::{IntoResponse, Response};
use serde_json::{from_str, json, Value};
use thiserror::Error;
use claims::Claims;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use jsonwebtoken::errors::ErrorKind;

const JWKS_JSON: &str = include_str!("./jwks.json");

#[derive(Debug, Error)]
pub enum JwtError {
    #[error("Missing authorization header")]
    MissingHeader,

    #[error("Invalid token format")]
    InvalidFormat,

    #[error("Token has expired")]
    Expired,

    #[error("Invalid token signature")]
    InvalidSignature,

    #[error("Invalid issuer or audience")]
    InvalidClaims,

    #[error("Unknown key ID")]
    UnknownKid,

    #[error("Failed to decode claims")]
    DecodeFailed,

    #[error("Failed to load JWKS")]
    JwksLoadFailed
}

impl IntoResponse for JwtError {
    fn into_response(self) -> Response {
        let status = match &self {
            JwtError::MissingHeader => StatusCode::UNAUTHORIZED,
            JwtError::InvalidFormat => StatusCode::BAD_REQUEST,
            JwtError::Expired => StatusCode::UNAUTHORIZED,
            JwtError::InvalidSignature => StatusCode::UNAUTHORIZED,
            JwtError::InvalidClaims => StatusCode::UNAUTHORIZED,
            JwtError::UnknownKid => StatusCode::UNAUTHORIZED,
            JwtError::DecodeFailed => StatusCode::UNAUTHORIZED,
            JwtError::JwksLoadFailed => StatusCode::INTERNAL_SERVER_ERROR,
        };

        let msg = Json(json!({
            "error": "unauthorized",
            "message": self.to_string()
        }));

        (status, msg).into_response()
    }
}

#[derive(Clone)]
pub struct JwtPublicKey {
    pub decoding_key: DecodingKey,
    pub kid: String,
    pub issuer: String,
    pub audience: String,
}

impl JwtPublicKey {
    pub fn from_jwks_file(issuer: String, audience: String) -> Result<Self, JwtError> {
        let jwks: Value = from_str(JWKS_JSON).map_err(|_| JwtError::JwksLoadFailed)?;

        let key = &jwks["keys"][0];

        let n = key["n"].as_str().ok_or(JwtError::JwksLoadFailed)?;
        let e = key["e"].as_str().ok_or(JwtError::JwksLoadFailed)?;
        let kid = key["kid"].as_str().ok_or(JwtError::JwksLoadFailed)?.to_string();

        let decoding_key = DecodingKey::from_rsa_components(&n, &e).map_err(|_| JwtError::JwksLoadFailed)?;

        Ok(Self {
            decoding_key,
            kid,
            issuer,
            audience
        })
    }
}

pub struct AuthClaims(pub Claims);

impl<S> FromRequestParts<S> for AuthClaims
where
    S: Send + Sync + AsRef<JwtPublicKey>,
{
    type Rejection = JwtError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth_headers = parts
            .headers
            .get("Authorization")
            .and_then(|value| value.to_str().ok())
            .ok_or(JwtError::MissingHeader)?;

        let claims = extract_claims(auth_headers, state.as_ref())?;

        Ok(AuthClaims(claims))
    }
}

pub fn extract_claims(auth_header: &str, key: &JwtPublicKey) -> Result<Claims, JwtError> {
    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or(JwtError::InvalidFormat)?;

    let header = decode_header(token).map_err(|_| JwtError::InvalidFormat)?;
    if header.kid.as_ref() != Some(&key.kid) {
        return Err(JwtError::UnknownKid);
    }

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[&key.issuer]);
    validation.set_audience(&[&key.audience]);

    let token_data = decode::<Claims>(token, &key.decoding_key, &validation).map_err(|e| {
        match e.kind() {
            ErrorKind::ExpiredSignature => JwtError::Expired,
            ErrorKind::InvalidIssuer | ErrorKind::InvalidAudience => JwtError::InvalidClaims,
            ErrorKind::InvalidSignature => JwtError::InvalidSignature,
            _ => JwtError::DecodeFailed,
        }
    })?;

    Ok(token_data.claims)
}

