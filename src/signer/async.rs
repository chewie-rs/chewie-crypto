//! Asynchronous cryptographic signing traits.

use crate::{MaybeSend, MaybeSendSync, signer::SignedBytes};

/// Trait for signers that produce RFC 7515 (JWS) / RFC 7518 (JWA) compatible signatures.
pub trait JwsSigner: MaybeSendSync + Clone {
    /// The error type returned by this signer's operations.
    type Error: std::error::Error + MaybeSendSync + 'static;

    /// Returns a descriptive name for the algorithm used by this signer.
    fn algorithm(&self) -> &str;

    /// Asynchronously signs the given input data and returns the signature with metadata.
    ///
    /// The returned [`SignedBytes`] contains the JWA-compatible signature
    /// along with the algorithm and key ID used.
    ///
    /// # Errors
    ///
    /// Returns an error if the signing operation fails.
    fn sign(
        &self,
        input: &[u8],
    ) -> impl Future<Output = Result<SignedBytes, Self::Error>> + MaybeSend;
}
