//! # nunc
//!
//! Trustworthy wall-clock time via multi-source network consensus.
//!
//! The system clock is ground truth for every other Rust time crate.
//! `nunc` is the thing you call before you trust the system clock —
//! or when you can't.
//!
//! See `README.md` for the full design rationale and proof sketch.

pub mod config;
pub mod consensus;
pub mod eagle;
pub mod error;
pub mod pool;
pub mod pool_data;
pub mod sources;
pub mod types;

#[cfg(feature = "https")]
pub mod ct;

// Flat re-exports for the common path
pub use config::{Config, Mode, query, query_with_config};
pub use eagle::{OPS, EAGLE_EPOCH_UNIX_SECS};
pub use error::NuncError;
pub use types::{NuncTime, Observation, OutlierReport, Protocol};
