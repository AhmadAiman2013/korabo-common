use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::Json;
use axum::response::{IntoResponse, Response};
use serde_json::{from_slice, json};
use thiserror::Error;
use claims::Claims;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

#[derive(Debug, Error)]
pub enum JwtError {
    #[error("Missing authorization header")]
    MissingHeader,

    #[error("Invalid token format")]
    InvalidFormat,

    #[error("Failed to decode claims")]
    DecodeFailed
}

impl IntoResponse for JwtError {
    fn into_response(self) -> Response {
        let status = StatusCode::UNAUTHORIZED;
        let msg = Json(json!({
            "msg": self.to_string()
        }));
        (status, msg).into_response()
    }
}

pub struct AuthClaims(pub Claims);

impl<S> FromRequestParts<S> for AuthClaims
where
    S: Send + Sync,
{
    type Rejection = JwtError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let auth_headers = parts
            .headers
            .get("Authorization")
            .and_then(|value| value.to_str().ok())
            .ok_or(JwtError::MissingHeader)?;

        let claims = extract_claims(auth_headers)?;

        Ok(AuthClaims(claims))
    }
}

pub fn extract_claims(auth_header: &str) -> Result<Claims, JwtError> {
    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or(JwtError::InvalidFormat)?;

    let payload_b64 = token.split('.').nth(1)
        .ok_or(JwtError::InvalidFormat)?;

    let decoded = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| JwtError::DecodeFailed)?;

    from_slice::<Claims>(&decoded).map_err(|_| JwtError::DecodeFailed)
}

