use crate::errors::{RabinWilliamsError, Result};
use num_bigint::{BigUint, RandBigInt};
use num_prime::{nt_funcs::is_prime, Primality, PrimalityTestConfig};
use sha2::{Sha256, Digest};
use crate::utils::{chinese_remainder_theorem, make_quadratic_residue};

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
    let min = BigUint::from(1u32) << (bits - 1);
    let max = (BigUint::from(1u32) << bits) - 1u32;
    
    for _ in 0..1000 {
        // Generate random number in range [min, max]
        let num = rng.gen_biguint_range(&min, &max);
        
        // Find the next number that meets the congruence condition
        let mut candidate = num;
        while candidate <= max {
            if (&candidate % modulus) == remainder.into() {
                let config = PrimalityTestConfig::default();
                let primality = is_prime(&candidate, Some(config));
                if primality == Primality::Yes || primality.probably() {
                    return Ok(candidate);
                }
            }
            candidate += 1u32;
        }
    }
    
    Err(RabinWilliamsError::InvalidPrime)
}

impl PublicKey {
    /// Returns a reference to the modulus n
    pub fn n(&self) -> &BigUint {
        &self.n
    }

    pub fn extract_signature(&self, signature: &[u8]) -> Result<(i32, u32, BigUint)> {
        if signature.is_empty() {
            return Err(RabinWilliamsError::InvalidSignature);
        }

        let first_byte = signature[0];
        
        // Validate that only bits 0 and 1 are used
        if first_byte & 0xFC != 0 {
            return Err(RabinWilliamsError::InvalidSignature);
        }

        let e = if (first_byte & 1) == 0 { 1 } else { -1 };
        let f = if (first_byte & 2) == 0 { 1 } else { 2 };

        // Ensure there's at least one byte after the flags
        if signature.len() < 2 {
            return Err(RabinWilliamsError::InvalidSignature);
        }

        // Parse the BigUint, handling potential errors
        let x = BigUint::from_bytes_be(&signature[1..]);

        Ok((e, f, x))
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        // Compute SHA-256 hash of the message
        let mut hasher = Sha256::new();
        hasher.update(message);
        let hash = hasher.finalize();
        let m = BigUint::from_bytes_be(&hash);

        let (e, f, x) = self.extract_signature(signature)?;

        // Compute x² mod n
        let x_squared = (&x * &x) % self.n();
        let n = self.n();

        let result = match (e, f) {
            (1, 1) => x_squared,
            (1, 2) => {
                // To reverse m' = 2m (mod n), we need m = m' * 2^-1 (mod n)
                // For odd n, 2^-1 (mod n) is (n+1)/2
                let two_inv = (n + 1u32) / 2u32;
                (&x_squared * two_inv) % n
            },
            (-1, 1) => (n - &x_squared) % n,
            (-1, 2) => {
                // To reverse m' = -2m (mod n), we need m = -m' * 2^-1 (mod n)
                let two_inv = (n + 1u32) / 2u32;
                ((n - &x_squared) * two_inv) % n
            },
            _ => panic!("unreachable"),
        };

        Ok(result == m)
    }
}

impl PrivateKey {
    pub fn n(&self) -> BigUint {
        self.p.clone() * self.q.clone()
    }

    /// Signs a message using the Rabin-Williams signature scheme
    /// 
    /// This implementation uses the deterministic Rabin-Williams approach
    /// which takes advantage of the special form of the primes (p ≡ 3 mod 8, q ≡ 7 mod 8)
    /// to compute a signature in a single attempt.
    /// 
    /// The signature x satisfies efx² ≡ H(m) (mod N) where:
    /// - e ∈ {-1, 1}
    /// - f ∈ {1, 2}
    /// - x is the signature
    /// - H(m) is the SHA-256 hash of the message
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        // Compute SHA-256 hash of the message
        let mut hasher = Sha256::new();
        hasher.update(message);
        let hash = hasher.finalize();
        let m = BigUint::from_bytes_be(&hash);
        
        let (m, (e, f)) = make_quadratic_residue(&m, &self.p, &self.q);
        
        // Compute square roots modulo p and q
        let mp = &m % &self.p;
        let mq = &m % &self.q;
        
        // For p ≡ 3 mod 8, the square root is deterministic
        let p_plus_1_div_4 = (&self.p + 1u32) / 4u32;
        let sp = mp.modpow(&p_plus_1_div_4, &self.p);
        
        // For q ≡ 7 mod 8, the square root is deterministic
        let q_plus_1_div_4 = (&self.q + 1u32) / 4u32;
        let sq = mq.modpow(&q_plus_1_div_4, &self.q);
        
        tracing::debug!("Computed square roots modulo p and q");
        
        // Use CRT to combine the results
        let remainders = vec![
            sp,
            sq
        ];
        let moduli = vec![
            self.p.clone(),
            self.q.clone()
        ];
        
        let signature = chinese_remainder_theorem(&remainders, &moduli)?;
        
        // Convert to bytes and encode e and f
        let mut sig_bytes = signature.to_bytes_be();
        // Encode e and f in the first byte:
        // bit 0: e (0 for 1, 1 for -1)
        // bit 1: f (0 for 1, 1 for 2)
        let first_byte = ((e == -1) as u8) | (((f == 2) as u8) << 1);
        sig_bytes.insert(0, first_byte);
        
        tracing::info!("Successfully generated Rabin-Williams signature with e={}, f={}", e, f);
        Ok(sig_bytes)
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{thread_rng, Rng};

    #[test]
    fn test_key_generation() -> Result<()> {
        // Generate a keypair with 1024-bit modulus
        let keypair = KeyPair::generate(1024)?;

        // Verify key sizes
        assert!(keypair.public.n.bits() >= 1023); // Allow for slight variation
        assert!(keypair.private.p.bits() >= 511);
        assert!(keypair.private.q.bits() >= 511);

        // Verify p ≡ 3 (mod 8)
        assert_eq!(&keypair.private.p % 8u32, 3u32.into());

        // Verify q ≡ 7 (mod 8) 
        assert_eq!(&keypair.private.q % 8u32, 7u32.into());

        // Verify n = p * q
        assert_eq!(keypair.public.n, &keypair.private.p * &keypair.private.q);

        Ok(())
    }

    // Helper function to generate random message
    fn generate_random_message() -> Vec<u8> {
        let mut rng = thread_rng();
        let len = rng.gen_range(10..100); // Random length between 10 and 100 bytes
        let random_bytes: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
        let mut hasher = Sha256::new();
        hasher.update(&random_bytes);
        hasher.finalize().to_vec()
    }

    #[test]
    fn test_sign_verify() {
        let key_pair = KeyPair::generate(1024).unwrap();
        
        for i in 0..10 {
            let message = generate_random_message();
            
            // Sign message
            let signature = key_pair.private.sign(&message).unwrap();

            tracing::info!("Signature: {:?}", BigUint::from_bytes_be(&signature));
            
            // Verify signature and assert it's valid
            let is_valid = key_pair.public.verify(&message, &signature).unwrap();
            assert!(is_valid, "Signature verification failed for message {}", i);
            tracing::info!("Is valid {i}: {:?}", is_valid);
        }
    }

    #[test]
    fn test_invalid_signature() {
        let key_pair = KeyPair::generate(1024).unwrap();
        let message = b"Hello, World!";
        let mut signature = key_pair.private.sign(message).unwrap();
        
        // Tamper with signature
        signature[0] ^= 1;
        
        let is_valid = key_pair.public.verify(message, &signature).unwrap();
        
        assert!(!is_valid);
    }
}
