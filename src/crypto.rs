//! Shared cryptographic provider contract and optional software primitives (CRY).
//!
//! [`CryptoProvider`] is available without optional features. Enable
//! `software-crypto` for the RustCrypto-backed `SoftwareCrypto` provider.

pub use crate::security::{CryptoProvider, Sha256State};

#[cfg(feature = "software-crypto")]
mod software;
#[cfg(feature = "software-crypto")]
pub use software::{SoftwareCrypto, SoftwareSha256};
