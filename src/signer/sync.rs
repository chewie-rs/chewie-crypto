//! Synchronous cryptographic signing traits.

use crate::MaybeSendSync;

use bytes::Bytes;

/// Base trait for cryptographic signing operations (synchronous).
pub trait SignerSync: MaybeSendSync + Clone {
    /// The error type returned by this signer's operations.
    type Error: std::error::Error + MaybeSendSync + 'static;

    /// Returns a descriptive name for the algorithm used by this signer.
    fn algorithm(&self) -> &str;

    /// Synchronously signs the given input data and returns the raw signature bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the signing operation fails.
    fn sign_sync(&self, input: &[u8]) -> Result<Bytes, Self::Error>;
}

/// Trait for signers that produce RFC 7515 (JWS) / RFC 7518 (JWA) compatible signatures (synchronous).
pub trait JwsSignerSync: SignerSync {
    /// Returns the JWS algorithm identifier.
    ///
    /// This is specifically for use in the JWT `alg` header parameter.
    fn jws_algorithm(&self) -> &str;
}
