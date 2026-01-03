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
