//! Synchronous cryptographic signing traits.

use std::borrow::Cow;

use bytes::Bytes;
use snafu::prelude::*;

use crate::{
    MaybeSend, MaybeSendSync,
    signer::{
        JwsSigner,
        error::{MismatchedKeyInfoSnafu, UnderlyingSnafu},
    },
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

impl<Sgn: JwsSignerSync> JwsSigner for Sgn {
    type Error = Sgn::Error;

    fn algorithm(&self) -> Cow<'_, str> {
        JwsSignerSync::algorithm(self)
    }

    fn jws_algorithm(&self) -> Cow<'_, str> {
        JwsSignerSync::jws_algorithm(self)
    }

    fn key_id(&self) -> Option<Cow<'_, str>> {
        JwsSignerSync::key_id(self)
    }

    fn sign_unchecked(
        &self,
        input: &[u8],
    ) -> impl Future<Output = Result<Bytes, Self::Error>> + MaybeSend {
        std::future::ready(JwsSignerSync::sign_unchecked(self, input))
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use crate::signer::{JwsSigner, JwsSignerSync};

    #[derive(Debug, Clone)]
    struct MockSigner;

    impl JwsSignerSync for MockSigner {
        type Error = Infallible;

        fn algorithm(&self) -> std::borrow::Cow<'_, str> {
            "ALG".into()
        }

        fn jws_algorithm(&self) -> std::borrow::Cow<'_, str> {
            "JWS-ALG".into()
        }

        fn key_id(&self) -> Option<std::borrow::Cow<'_, str>> {
            None
        }

        fn sign_unchecked(&self, _input: &[u8]) -> Result<bytes::Bytes, Self::Error> {
            Ok(bytes::Bytes::new())
        }
    }

    #[test]
    fn test_algorithm_through_blanket_impl() {
        assert_eq!(JwsSigner::algorithm(&MockSigner), "ALG");
    }

    #[test]
    fn test_jws_algorithm_through_blanket_impl() {
        assert_eq!(JwsSigner::jws_algorithm(&MockSigner), "JWS-ALG");
    }

    #[test]
    fn test_key_id_algorithm_through_blanket_impl() {
        assert_eq!(JwsSigner::key_id(&MockSigner), None);
    }

    #[tokio::test]
    async fn test_sign_through_blanket_impl() {
        assert!(matches!(
            JwsSigner::sign(&MockSigner, &[], "JWS-ALG", None).await,
            Ok(_)
        ));
    }
}
