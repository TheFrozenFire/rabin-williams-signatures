use num_bigint::BigUint;
use num_integer::Integer;
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
    
    for _ in 0..1000 {  // Increased maximum attempts to find suitable prime
        // Generate random number with exact bit length
        let mut num = BigUint::from(0u32);
        let u64_bits = 64;
        let num_chunks = (bits + u64_bits - 1) / u64_bits;
        
        for i in 0..num_chunks {
            let chunk = if i == num_chunks - 1 {
                // For the last chunk, only generate necessary bits
                let remaining_bits = bits % u64_bits;
                if remaining_bits == 0 {
                    rng.gen::<u64>()
                } else {
                    rng.gen::<u64>() & ((1u64 << remaining_bits) - 1)
                }
            } else {
                rng.gen::<u64>()
            };
            
            num = (num << u64_bits) | BigUint::from(chunk);
        }
        
        // Ensure the number has exactly the specified bit length
        num |= BigUint::from(1u32) << (bits - 1);
        
        // Adjust to meet congruence condition while preserving bit length
        let mut adjusted = num.clone();
        loop {
            let rem = &adjusted % modulus;
            if rem == remainder.into() {
                break;
            }
            adjusted += 1u32;
            // Check if we've exceeded our bit length
            if adjusted.bits() as usize > bits {
                adjusted = num.clone();  // Start over with original number
                continue;
            }
        }
        
        if is_prime(&adjusted) {
            return Ok(adjusted);
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

    // Witness loop - testing multiple random bases
    let k = match n.bits() {
        bits if bits < 1536 => 4,  // < 1536 bits
        bits if bits < 2048 => 8,  // < 2048 bits
        _ => 16,                   // >= 2048 bits
    };
    
    let mut rng = rand::thread_rng();

    'witness: for _ in 0..k {
        // Generate a random base in [2, n-2]
        let a = loop {
            let mut bytes = vec![0u8; (n.bits() as usize + 7) / 8];
            rng.fill(&mut bytes[..]);
            let a = BigUint::from_bytes_be(&bytes) % n;
            if a >= BigUint::from(2u32) && &a < &(n - 2u32) {
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
