//! Cryptographic signing traits.

mod r#async;
mod sync;

pub use r#async::JwsSigner;
use bytes::Bytes;
pub use sync::JwsSignerSync;

/// Result of signing the provided bytes. The signature is compatible with RFC 7515 (JWS) / RFC 7518 (JWA).
///
/// To avoid race conditions if the key is reloaded/updated, any required metadata is returned
/// with the signature.
pub struct SignedBytes {
    /// The signature for the bytes, compatible with JWA.
    pub signature: Bytes,

    /// The JWS algorithm identifier.
    ///
    /// This is specifically for use in the JWT `alg` header parameter.
    pub jws_algorithm: &'static str,

    /// The key ID of the signer.
    ///
    /// This is specifically for use in the JWT `kid` header parameter.
    ///
    /// Note: The "natural" key ID is not always directly suitable as a
    /// `kid` value, and may require transformation before use.
    pub key_id: Option<String>,
}
