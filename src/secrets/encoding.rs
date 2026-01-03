use base64::Engine as _;
use secrecy::{SecretBox, SecretString};
use snafu::prelude::*;

use crate::MaybeSendSync;

/// Error when decoding a secret.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum EncodingError {
    /// The bytes are not valid UTF-8.
    #[snafu(display("Invalid UTF-8"))]
    InvalidUtf8 {
        /// The underlying UTF-8 error.
        source: std::str::Utf8Error,
    },
    /// The string is not valid hexadecimal.
    #[snafu(display("Invalid hex"))]
    InvalidHex {
        /// The hex decoding error.
        source: hex::FromHexError,
    },
    /// The string is not valid base64.
    #[snafu(display("Invalid base64"))]
    InvalidBase64 {
        /// The base64 decoding error.
        source: base64::DecodeError,
    },
}

/// Trait for decoding raw bytes into a typed secret.
pub trait SecretEncoding: MaybeSendSync + Clone {
    /// The type of secret this encoding produces.
    type Output: MaybeSendSync + Clone;

    /// Decodes raw bytes into the secret type.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes cannot be decoded (e.g., invalid UTF-8,
    /// invalid hex characters).
    fn decode(&self, bytes: &[u8]) -> Result<Self::Output, EncodingError>;
}

/// Interprets bytes as UTF-8 text, returning a `SecretString`.
///
/// Trims leading/trailing whitespace from the decoded string.
#[derive(Debug, Clone, Copy, Default)]
pub struct StringEncoding;

impl SecretEncoding for StringEncoding {
    type Output = SecretString;

    fn decode(&self, bytes: &[u8]) -> Result<Self::Output, EncodingError> {
        let s = std::str::from_utf8(bytes).context(InvalidUtf8Snafu)?;
        Ok(SecretString::from(s.trim().to_string()))
    }
}

/// Uses raw bytes directly, returning `SecretBytes`.
///
/// No transformation is applied - bytes pass through as-is.
#[derive(Debug, Clone, Copy, Default)]
pub struct BinaryEncoding;

impl SecretEncoding for BinaryEncoding {
    type Output = SecretBox<[u8]>;

    fn decode(&self, bytes: &[u8]) -> Result<Self::Output, EncodingError> {
        Ok(SecretBox::new(bytes.to_vec().into_boxed_slice()))
    }
}

/// Decodes hex-encoded text into `SecretBytes`.
///
/// Trims whitespace before decoding. Expects the bytes to be valid UTF-8
/// containing hexadecimal characters (0-9, a-f, A-F).
#[derive(Debug, Clone, Copy, Default)]
pub struct HexEncoding;

impl SecretEncoding for HexEncoding {
    type Output = SecretBox<[u8]>;

    fn decode(&self, bytes: &[u8]) -> Result<Self::Output, EncodingError> {
        let s = std::str::from_utf8(bytes).context(InvalidUtf8Snafu)?;
        let decoded = hex::decode(s.trim()).context(InvalidHexSnafu)?;
        Ok(SecretBox::new(decoded.into_boxed_slice()))
    }
}

/// Decodes base64-encoded text into `SecretBytes`.
///
/// Trims whitespace before decoding. Expects the bytes to be valid base64
/// with padding.
#[derive(Debug, Clone, Copy, Default)]
pub struct Base64Encoding;

impl SecretEncoding for Base64Encoding {
    type Output = SecretBox<[u8]>;

    fn decode(&self, bytes: &[u8]) -> Result<Self::Output, EncodingError> {
        let s = std::str::from_utf8(bytes).context(InvalidUtf8Snafu)?;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(s.trim())
            .context(InvalidBase64Snafu)?;
        Ok(SecretBox::new(decoded.into_boxed_slice()))
    }
}
