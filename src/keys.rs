use crate::errors::{RabinWilliamsError, Result};
use num_bigint::{BigUint, RandBigInt};
use num_prime::{nt_funcs::is_prime, Primality};

#[derive(Clone, Debug)]
pub struct PublicKey {
    pub n: BigUint,
}

#[derive(Clone, Debug)]
pub struct PrivateKey {
    pub p: BigUint,
    pub q: BigUint,
}

#[derive(Clone, Debug)]
pub struct KeyPair {
    pub public: PublicKey,
    pub private: PrivateKey,
}

impl KeyPair {
    /// Generates a new Rabin-Williams key pair
    pub fn generate(bits: usize) -> Result<Self> {
        if bits < 1024 {
            return Err(RabinWilliamsError::InvalidKeySize);
        }

        let half_bits = bits / 2;

        // Generate primes p and q such that p ≡ 3 (mod 8) and q ≡ 7 (mod 8)
        let p = generate_prime_congruent(half_bits, 3, 8)?;
        let q = generate_prime_congruent(half_bits, 7, 8)?;

        let n = &p * &q;

        Ok(KeyPair {
            public: PublicKey { n },
            private: PrivateKey { p, q },
        })
    }
}

/// Generates a prime number with specified bit length and congruence conditions
fn generate_prime_congruent(bits: usize, remainder: u32, modulus: u32) -> Result<BigUint> {
    let mut rng = rand::thread_rng();

    for _ in 0..1000 {
        // Increased maximum attempts to find suitable prime
        // Generate random number with exact bit length
        let num = rng.gen_biguint(bits as u64);

        // Ensure the number has exactly the specified bit length
        let mut adjusted = num.clone() | (BigUint::from(1u32) << (bits - 1));

        // Adjust to meet congruence condition while preserving bit length
        loop {
            let rem = &adjusted % modulus;
            if rem == remainder.into() {
                break;
            }
            adjusted += 1u32;
            // Check if we've exceeded our bit length
            if adjusted.bits() as usize > bits {
                adjusted = num.clone(); // Start over with original number
                continue;
            }
        }

        if is_prime(&adjusted, None) == Primality::Yes {
            return Ok(adjusted);
        }
    }

    Err(RabinWilliamsError::InvalidPrime)
}


