//! Platform-specific marker traits for cross-platform compatibility.
//!
//! These traits abstract over `Send`/`Sync` requirements that differ between
//! native platforms and browser WASM.

/// Marker trait for types that may be `Send`, depending on platform.
#[cfg(any(native, wasm_wasi))]
pub trait MaybeSend: Send {}
#[cfg(any(native, wasm_wasi))]
impl<T: Send> MaybeSend for T {}

/// Marker trait for types that may be `Send`, depending on platform.
#[cfg(wasm_browser)]
pub trait MaybeSend {}
#[cfg(wasm_browser)]
impl<T> MaybeSend for T {}

/// Marker trait for types that may be `Send + Sync`, depending on platform.
#[cfg(any(native, wasm_wasi))]
pub trait MaybeSendSync: Send + Sync {}
#[cfg(any(native, wasm_wasi))]
impl<T: Send + Sync> MaybeSendSync for T {}

/// Marker trait for types that may be `Send + Sync`, depending on platform.
#[cfg(wasm_browser)]
pub trait MaybeSendSync {}
#[cfg(wasm_browser)]
impl<T> MaybeSendSync for T {}

/// Marker trait for types that may be `Sync`, depending on platform.
#[cfg(any(native, wasm_wasi))]
pub trait MaybeSync: Sync {}
#[cfg(any(native, wasm_wasi))]
impl<T: Sync> MaybeSync for T {}

/// Marker trait for types that may be `Sync`, depending on platform.
#[cfg(wasm_browser)]
pub trait MaybeSync {}
#[cfg(wasm_browser)]
impl<T> MaybeSync for T {}
