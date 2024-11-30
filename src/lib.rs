//! Rabin-Williams signature implementation
//! 
//! This library provides an implementation of the Rabin-Williams digital signature scheme.

pub mod errors;
pub mod keys;
pub mod signing;
pub mod utils;

pub use keys::{PublicKey, PrivateKey, KeyPair};
pub use signing::{sign, verify};
pub use errors::RabinWilliamsError;

/// Re-export commonly used types from num-bigint
pub use num_bigint::{BigUint, BigInt};
