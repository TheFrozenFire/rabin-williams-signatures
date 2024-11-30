use num_bigint::BigUint;
use rand::Rng;
use crate::errors::{Result, RabinWilliamsError};

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
    
    for _ in 0..100 {  // Maximum attempts to find suitable prime
        let mut num = rng.gen::<BigUint>() % (BigUint::from(1u32) << bits);
        
        // Ensure the number has exactly the specified bit length
        num |= BigUint::from(1u32) << (bits - 1);
        
        // Adjust to meet congruence condition
        num = num - (num.clone() % modulus) + remainder;
        
        if is_prime(&num) {
            return Ok(num);
        }
    }
    
    Err(RabinWilliamsError::InvalidPrime)
}

/// Miller-Rabin primality test
fn is_prime(n: &BigUint) -> bool {
    if n <= &BigUint::from(1u32) {
        return false;
    }
    if n <= &BigUint::from(3u32) {
        return true;
    }
    if n.is_even() {
        return false;
    }

    let mut d = n - 1u32;
    let mut s = 0u32;
    while d.is_even() {
        d >>= 1;
        s += 1;
    }

    // Number of Miller-Rabin tests for adequate security
    let k = 50;
    let mut rng = rand::thread_rng();

    'witness: for _ in 0..k {
        let a = loop {
            let a = rng.gen::<BigUint>() % (n - 3u32) + 2u32;
            if a < n - 1u32 {
                break a;
            }
        };

        let mut x = a.modpow(&d, n);
        if x == BigUint::from(1u32) || x == n - 1u32 {
            continue 'witness;
        }

        for _ in 1..s {
            x = (&x * &x) % n;
            if x == n - 1u32 {
                continue 'witness;
            }
            if x == BigUint::from(1u32) {
                return false;
            }
        }
        return false;
    }
    true
}
