//! Synchronous cryptographic signing traits.

use std::borrow::Cow;

use bytes::Bytes;
use snafu::prelude::*;

use crate::{
    MaybeSendSync,
    signer::error::{MismatchedKeyInfoSnafu, UnderlyingSnafu},
};

/// Trait for signers that produce RFC 7515 (JWS) / RFC 7518 (JWA) compatible signatures (synchronous).
pub trait JwsSignerSync: MaybeSendSync + Clone {
    /// The underlying error type returned by this signer's operations.
    type Error: std::error::Error + MaybeSendSync + 'static;

    /// Returns a descriptive name for the algorithm used by this signer.
    fn algorithm(&self) -> Cow<'_, str>;

    /// Returns the JWS algorithm identifier.
    ///
    /// This is specifically for use in the JWT `alg` header parameter.
    fn jws_algorithm(&self) -> Cow<'_, str>;

    /// Returns the key ID of the signer.
    ///
    /// This is specifically for use in the JWT `kid` header parameter.
    ///
    /// Note: The "natural" key ID is not always directly suitable as a
    /// `kid` value, and may require transformation before use.
    fn key_id(&self) -> Option<Cow<'_, str>>;

    /// Signs the given input data and returns the signature.
    ///
    /// This should not be called directly, as it does not verify that the algorithm
    /// and key ID match the values signed (which could happen due to key updates).
    ///
    /// # Errors
    ///
    /// Returns an error if the signing operation fails.
    fn sign_unchecked(&self, input: &[u8]) -> Result<Bytes, Self::Error>;

    /// Asynchronously signs the given input data and returns the signature with metadata.
    ///
    /// # Errors
    ///
    /// Returns an error if the key metadata is mismatched, or the signing operation fails.
    fn sign_sync(
        &self,
        input: &[u8],
        jws_algorithm: &str,
        key_id: Option<&str>,
    ) -> Result<Bytes, super::Error<Self::Error>> {
        if jws_algorithm != self.jws_algorithm().as_ref() || key_id != self.key_id().as_deref() {
            MismatchedKeyInfoSnafu.fail()
        } else {
            self.sign_unchecked(input).context(UnderlyingSnafu)
        }
    }
}
