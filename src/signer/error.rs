use snafu::Snafu;

use crate::MaybeSendSync;

/// The error type returned by signing operations.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(super)))]
pub enum Error<E: std::error::Error + MaybeSendSync + 'static> {
    /// Algorithm or key ID is mismatched with metadata.
    ///
    /// Callers should usually retry once if this is received.
    MismatchedKeyInfo,
    /// The error from the underlying implementation.
    UnderlyingError {
        /// The source error.
        source: E,
    },
}
