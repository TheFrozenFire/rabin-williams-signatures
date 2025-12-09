use crate::errors::{RabinWilliamsError, Result};
use num_bigint::{BigUint, RandBigInt};
use num_integer::Integer;
use num_prime::{nt_funcs::is_prime, Primality, PrimalityTestConfig};
use digest::Digest;
use sha2::Sha256;
use crate::utils::{chinese_remainder_theorem, make_quadratic_residue, mod_inverse};
use crate::hash::HashWrapper;

#[derive(Clone, Debug)]
pub struct PublicKey<D: Digest + Clone = Sha256> {
    pub n: BigUint,
    hash_fn: HashWrapper<D>,
}

#[derive(Clone, Debug)]
pub struct PrivateKey<D: Digest + Clone = Sha256> {
    pub p: BigUint,
    pub q: BigUint,
    hash_fn: HashWrapper<D>,
}

#[derive(Clone, Debug)]
pub struct KeyPair<D: Digest + Clone = Sha256> {
    pub public: PublicKey<D>,
    pub private: PrivateKey<D>,
}

impl<D: Digest + Clone> KeyPair<D> {
    /// Generates a new Rabin-Williams key pair with the specified hash function
    pub fn generate_with_hash(bits: usize, hash_fn: HashWrapper<D>) -> Result<Self> {
        if bits < 1024 {
            return Err(RabinWilliamsError::InvalidKeySize);
        }

        let half_bits = bits / 2;

        // Generate primes p and q such that p ≡ 3 (mod 8) and q ≡ 7 (mod 8)
        let p = generate_prime_congruent(half_bits, 3, 8)?;
        let q = generate_prime_congruent(half_bits, 7, 8)?;

        let n = &p * &q;

        Ok(KeyPair {
            public: PublicKey { n: n.clone(), hash_fn: hash_fn.clone() },
            private: PrivateKey { p, q, hash_fn },
        })
    }
}

impl KeyPair<Sha256> {
    /// Generates a new Rabin-Williams key pair using SHA-256 as the default hash function
    pub fn generate(bits: usize) -> Result<Self> {
        Self::generate_with_hash(bits, HashWrapper::default())
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

impl<D: Digest + Clone> PublicKey<D> {
    /// Creates a new PublicKey from a modulus n
    pub fn from_n(n: BigUint) -> Self {
        Self {
            n,
            hash_fn: HashWrapper::default(),
        }
    }

    /// Returns a reference to the modulus n
    pub fn n(&self) -> &BigUint {
        &self.n
    }

    // Generate a random coprime to n
    pub fn coprime(&self) -> BigUint {
        let mut rng = rand::thread_rng();
        loop {
            let e = rng.gen_biguint_range(&BigUint::from(1u32), &self.n);
            if e.gcd(&self.n) == BigUint::from(1u32) {
                return e;
            }
        }
    }

    pub fn blinding(&self) -> (BigUint, BigUint) {
        let r = self.coprime();
        let r_squared = &r * &r % self.n.clone();
        (r, r_squared)
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
        let m = self.hash_fn.hash(message);
        let (e, f, x) = self.extract_signature(signature)?;

        // Compute x² mod n
        let x_squared = (&x * &x) % self.n();
        let n = self.n();

        let result = match (e, f) {
            (1, 1) => x_squared,
            (1, 2) => {
                let two_inv = (n + 1u32) / 2u32;
                (&x_squared * two_inv) % n
            },
            (-1, 1) => (n - &x_squared) % n,
            (-1, 2) => {
                let two_inv = (n + 1u32) / 2u32;
                ((n - &x_squared) * two_inv) % n
            },
            _ => panic!("unreachable"),
        };

        Ok(result == m)
    }

    /// Blinds a message using a random coprime r
    /// Returns the blinded message hash and the blinding factor r
    pub fn blind_message(&self, message: &[u8]) -> (BigUint, BigUint) {
        let m = self.hash_fn.hash(message);
        let (r, r_squared) = self.blinding();
        let blinded_message = &r_squared * &m % self.n();
        (blinded_message, r)
    }

    /// Unblinds a signature using the blinding factor r
    pub fn unblind_signature(&self, signature: &[u8], r: &BigUint) -> Result<Vec<u8>> {
        let (e, f, x) = self.extract_signature(signature)?;
        let r_inv = mod_inverse(r, self.n()).ok_or(RabinWilliamsError::InvalidSignature)?;
        let unblinded_x = &r_inv * &x % self.n();
        Ok(PrivateKey::<D>::pack_signature(e, f, &unblinded_x))
    }
}

impl<D: Digest + Clone> PrivateKey<D> {
    /// Creates a new PrivateKey from primes p and q
    pub fn from_primes(p: BigUint, q: BigUint) -> Self {
        Self {
            p,
            q,
            hash_fn: HashWrapper::default(),
        }
    }

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
    /// - H(m) is the hash of the message using the configured hash function
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let hash = self.hash_fn.hash(message).to_bytes_be();
        self.raw_sign(&hash)
    }

    pub fn raw_sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let m = BigUint::from_bytes_be(&message);
        
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
        
        tracing::info!("Successfully generated Rabin-Williams signature with e={}, f={}", e, f);
        Ok(Self::pack_signature(e, f, &signature))
    }

    pub fn pack_signature(e: i32, f: u32, x: &BigUint) -> Vec<u8> {
        let mut sig_bytes = x.to_bytes_be();
        // Encode e and f in the first byte:
        // bit 0: e (0 for 1, 1 for -1)
        // bit 1: f (0 for 1, 1 for 2)
        let first_byte = ((e == -1) as u8) | (((f == 2) as u8) << 1);
        sig_bytes.insert(0, first_byte);
        sig_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{thread_rng, Rng};
    use sha2::Sha512;

    // Helper function to generate random message
    fn generate_random_message() -> Vec<u8> {
        let mut rng = thread_rng();
        let len = rng.gen_range(10..100); // Random length between 10 and 100 bytes
        let random_bytes: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
        random_bytes
    }

    #[test]
    fn test_key_generation() -> Result<()> {
        // Generate a keypair with 1024-bit modulus using default SHA-256
        let keypair: KeyPair<Sha256> = KeyPair::generate(1024)?;

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

    #[test]
    fn test_sign_verify() -> Result<()> {
        let key_pair: KeyPair<Sha256> = KeyPair::generate(1024)?;
        
        for i in 0..10 {
            let message = generate_random_message();
            
            // Sign message
            let signature = key_pair.private.sign(&message)?;

            tracing::info!("Signature: {:?}", BigUint::from_bytes_be(&signature));
            
            // Verify signature and assert it's valid
            let is_valid = key_pair.public.verify(&message, &signature)?;
            assert!(is_valid, "Signature verification failed for message {}", i);
            tracing::info!("Is valid {i}: {:?}", is_valid);
        }

        Ok(())
    }

    #[test]
    fn test_blind_sign_verify() -> Result<()> {
        let key_pair: KeyPair<Sha256> = KeyPair::generate(1024)?;
        let message = generate_random_message();

        // Blind the message
        let (blinded_message, r) = key_pair.public.blind_message(&message);
        
        // Sign the blinded message
        let blinded_signature = key_pair.private.raw_sign(&blinded_message.to_bytes_be())?;
        
        // Unblind the signature
        let unblinded_signature = key_pair.public.unblind_signature(&blinded_signature, &r)?;

        // Verify the unblinded signature
        let is_valid = key_pair.public.verify(&message, &unblinded_signature)?;
        assert!(is_valid);

        Ok(())
    }

    #[test]
    fn test_invalid_signature() -> Result<()> {
        let key_pair: KeyPair<Sha256> = KeyPair::generate(1024)?;
        let message = b"Hello, World!";
        let mut signature = key_pair.private.sign(message)?;
        
        // Tamper with signature
        signature[0] ^= 1;
        
        let is_valid = key_pair.public.verify(message, &signature)?;
        assert!(!is_valid);

        Ok(())
    }

    #[test]
    fn test_custom_hash() -> Result<()> {
        // Generate a keypair with SHA-512
        let hash_fn = HashWrapper::<Sha512>::default();
        let keypair: KeyPair<Sha512> = KeyPair::generate_with_hash(1024, hash_fn)?;

        let message = b"Hello, World!";
        let signature = keypair.private.sign(message)?;
        let is_valid = keypair.public.verify(message, &signature)?;
        assert!(is_valid);

        Ok(())
    }
}
