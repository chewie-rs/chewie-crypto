//! Asynchronous cryptographic signing traits.

use std::borrow::Cow;

use bytes::Bytes;
use snafu::prelude::*;

use crate::{
    MaybeSend, MaybeSendSync,
    signer::error::{MismatchedKeyInfoSnafu, UnderlyingSnafu},
};

/// Trait for signers that produce RFC 7515 (JWS) / RFC 7518 (JWA) compatible signatures.
pub trait JwsSigner: MaybeSendSync + Clone {
    /// The error type returned by this signer's operations.
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

    /// Asynchronously signs the given input data and returns the signature.
    ///
    /// This should not be called directly, as it does not verify that the algorithm
    /// and key ID match the values signed (which could happen due to key updates).
    ///
    /// # Errors
    ///
    /// Returns an error if the signing operation fails.
    fn sign_unchecked(
        &self,
        input: &[u8],
    ) -> impl Future<Output = Result<Bytes, Self::Error>> + MaybeSend;

    /// Asynchronously signs the given input data and returns the signature with metadata.
    ///
    /// # Errors
    ///
    /// Returns an error if the key metadata is mismatched, or the signing operation fails.
    fn sign(
        &self,
        input: &[u8],
        jws_algorithm: &str,
        key_id: Option<&str>,
    ) -> impl Future<Output = Result<Bytes, super::Error<Self::Error>>> + MaybeSend {
        async move {
            if jws_algorithm != self.jws_algorithm().as_ref() || key_id != self.key_id().as_deref()
            {
                MismatchedKeyInfoSnafu.fail()
            } else {
                self.sign_unchecked(input).await.context(UnderlyingSnafu)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use crate::signer::JwsSignerSync;

    #[derive(Debug, Clone)]
    struct MockSigner;

    impl JwsSignerSync for MockSigner {
        type Error = Infallible;

        fn algorithm_sync(&self) -> std::borrow::Cow<'_, str> {
            "ALG".into()
        }

        fn jws_algorithm_sync(&self) -> std::borrow::Cow<'_, str> {
            "JWS-ALG".into()
        }

        fn key_id_sync(&self) -> Option<std::borrow::Cow<'_, str>> {
            None
        }

        fn sign_unchecked(&self, _input: &[u8]) -> Result<bytes::Bytes, Self::Error> {
            Ok(bytes::Bytes::new())
        }
    }

    #[test]
    fn test_metadata_no_mismatch_succeeds() {
        MockSigner
            .sign_sync(&[], "JWS-ALG", None)
            .expect("no mismatch");
    }

    #[test]
    fn test_metadata_different_alg_fails() {
        let result = MockSigner.sign_sync(&[], "JWS-ALG2", None);

        assert!(matches!(
            result,
            Err(crate::signer::Error::MismatchedKeyInfo)
        ))
    }

    #[test]
    fn test_metadata_different_kid_fails() {
        let result = MockSigner.sign_sync(&[], "JWS-ALG", Some("key-id"));

        assert!(matches!(
            result,
            Err(crate::signer::Error::MismatchedKeyInfo)
        ))
    }
}
