#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![warn(clippy::pedantic)]

//! Cryptographic trait definitions for Rust applications, optimized for
//! OAuth 2.0 and `OpenID` Connect.

mod platform;
pub use platform::{MaybeSend, MaybeSendSync, MaybeSync};
pub mod prelude;
pub mod secrets;
pub mod signer;

// Re-exports
pub use bytes::Bytes;
pub use secrecy::{ExposeSecret, SecretBox, SecretString};
