use num_bigint::{BigUint, BigInt, ToBigInt};
use num_traits::{Zero, One};
use crate::errors::{Result, RabinWilliamsError};
use crate::keys::{PrivateKey, PublicKey};
use crate::utils::{mod_sqrt, chinese_remainder_theorem};

/// Signs a message using the Rabin-Williams signature scheme
pub fn sign(message: &[u8], private_key: &PrivateKey) -> Result<Vec<u8>> {
    let m = BigUint::from_bytes_be(message);
    
    // Ensure message is smaller than modulus
    if &m >= &(&private_key.p * &private_key.q) {
        return Err(RabinWilliamsError::MessageTooLarge);
    }
    
    // Compute square roots modulo p and q
    let mp = &m % &private_key.p;
    let mq = &m % &private_key.q;
    
    let sp = mod_sqrt(&mp, &private_key.p)?;
    let sq = mod_sqrt(&mq, &private_key.q)?;
    
    // Use CRT to combine the results
    let remainders = vec![
        sp.to_bigint().unwrap(),
        sq.to_bigint().unwrap()
    ];
    let moduli = vec![
        private_key.p.to_bigint().unwrap(),
        private_key.q.to_bigint().unwrap()
    ];
    
    let signature = chinese_remainder_theorem(&remainders, &moduli)?;
    
    // Convert signature to bytes
    let sig_bytes = if signature >= BigInt::zero() {
        signature.to_biguint().unwrap().to_bytes_be()
    } else {
        (-signature).to_biguint().unwrap().to_bytes_be()
    };
    
    Ok(sig_bytes)
}

/// Verifies a Rabin-Williams signature
pub fn verify(message: &[u8], signature: &[u8], public_key: &PublicKey) -> Result<bool> {
    let m = BigUint::from_bytes_be(message);
    let s = BigUint::from_bytes_be(signature);
    
    // Compute s² mod n
    let s_squared = (&s * &s) % &public_key.n;
    
    // Compare with original message
    Ok(s_squared == m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyPair;

    #[test]
    fn test_sign_verify() {
        // Generate key pair
        let key_pair = KeyPair::generate(1024).unwrap();
        
        // Test message
        let message = b"Hello, World!";
        
        // Sign message
        let signature = sign(message, &key_pair.private).unwrap();
        
        // Verify signature
        let is_valid = verify(message, &signature, &key_pair.public).unwrap();
        
        assert!(is_valid);
    }

    #[test]
    fn test_invalid_signature() {
        let key_pair = KeyPair::generate(1024).unwrap();
        let message = b"Hello, World!";
        let mut signature = sign(message, &key_pair.private).unwrap();
        
        // Tamper with signature
        signature[0] ^= 1;
        
        let is_valid = verify(message, &signature, &key_pair.public).unwrap();
        
        assert!(!is_valid);
    }
}
