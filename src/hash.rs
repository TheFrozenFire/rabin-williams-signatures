use digest::Digest;
use num_bigint::BigUint;
use sha2::Sha256;

/// A wrapper around a Digest implementation that provides BigUint conversion
#[derive(Clone, Debug)]
pub struct HashWrapper<D: Digest + Clone>(D);

impl<D: Digest + Clone> HashWrapper<D> {
    pub fn new() -> Self {
        Self(D::new())
    }

    pub fn hash(&self, message: &[u8]) -> BigUint {
        let mut hasher = self.0.clone();
        hasher.update(message);
        BigUint::from_bytes_be(&hasher.finalize())
    }
}

impl<D: Digest + Clone> Default for HashWrapper<D> {
    fn default() -> Self {
        Self::new()
    }
}

/// Type alias for SHA-256 hash function
pub type Sha256Hash = HashWrapper<Sha256>;

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Sha512;

    use num_traits::Zero;

    #[test]
    fn test_hash_wrapper() {
        let wrapper = HashWrapper::<Sha256>::default();
        let message = b"Hello, World!";
        let hash = wrapper.hash(message);
        assert!(!hash.is_zero());
    }

    #[test]
    fn test_different_hash_functions() {
        let sha256 = HashWrapper::<Sha256>::default();
        let sha512 = HashWrapper::<Sha512>::default();
        let message = b"Hello, World!";

        let hash256 = sha256.hash(message);
        let hash512 = sha512.hash(message);

        // Different hash functions should produce different outputs
        assert_ne!(hash256, hash512);
    }
} 