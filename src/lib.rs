//! Rabin-Williams signature implementation
//! 
//! This library provides an implementation of the Rabin-Williams digital signature scheme.

pub mod errors;
pub mod keys;
pub mod utils;

pub use keys::{PublicKey, PrivateKey, KeyPair};
pub use errors::RabinWilliamsError;

/// Re-export commonly used types from num-bigint
pub use num_bigint::{BigUint, BigInt};

#[cfg(test)]
mod tests {
    /// Initialize tracing subscriber for all tests
    #[ctor::ctor]
    fn init() {
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_test_writer()
            .init();
    }
}
