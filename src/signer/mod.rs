//! Cryptographic signing traits.

mod r#async;
mod sync;

pub use r#async::Signer;
pub use sync::SignerSync;
