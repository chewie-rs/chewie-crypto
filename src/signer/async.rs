//! Asynchronous cryptographic signing traits.

use crate::{MaybeSend, MaybeSendSync};

use bytes::Bytes;

/// Base trait for asynchronous cryptographic signing operations.
pub trait Signer: MaybeSendSync + Clone {
    /// The error type returned by this signer's operations.
    type Error: std::error::Error + MaybeSendSync + 'static;

    /// Returns a descriptive name for the algorithm used by this signer.
    fn algorithm(&self) -> &str;

    /// Asynchronously signs the given input data and returns the raw signature bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the signing operation fails.
    fn sign(&self, input: &[u8]) -> impl Future<Output = Result<Bytes, Self::Error>> + MaybeSend;
}

/// Trait for signers that produce RFC 7515 (JWS) / RFC 7518 (JWA) compatible signatures.
pub trait JwsSigner: Signer {
    /// Returns the JWS algorithm identifier.
    ///
    /// This is specifically for use in the JWT `alg` header parameter.
    fn jws_algorithm(&self) -> &str;
}
