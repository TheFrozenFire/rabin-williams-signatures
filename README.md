# Rabin-Williams Signatures

A Rust implementation of the [Rabin-Williams signature scheme](https://en.wikipedia.org/wiki/Rabin_signature_algorithm#Rabin-Williams),
featuring both regular and blind signatures.

## Overview

This library implements the Rabin-Williams signature scheme, which is a variant of the Rabin signature scheme. The implementation includes:

- Key pair generation with configurable key sizes (minimum 1024 bits)
- Regular message signing and verification
- Blind signature support
- Flexible hash function abstraction using the `digest` crate with SHA-256 as the default

## Features

- **Secure Key Generation**: Generates primes p and q with specific congruence conditions (p ≡ 3 mod 8, q ≡ 7 mod 8)
- **Deterministic Signatures**: Uses a deterministic approach for signature generation
- **Blind Signatures**: Supports blind signatures for privacy-preserving applications
- **Custom Hash Functions**: Supports any hash function that implements the `digest` crate's `Digest` trait

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
rabin-williams-signatures = { git = "https://github.com/thefrozenfire/rabin-williams-signatures" }
```

### Basic Usage

```rust
use rabin_williams_signatures::keys::{KeyPair, Result};

fn main() -> Result<()> {
    // Generate a key pair using the default SHA-256 hash function
    let key_pair = KeyPair::generate(1024)?;
    
    // Sign a message
    let message = b"Hello, World!";
    let signature = key_pair.private.sign(message)?;
    
    // Verify the signature
    let is_valid = key_pair.public.verify(message, &signature)?;
    assert!(is_valid);
    
    Ok(())
}
```

### Using a Custom Hash Function

You can use any hash function that implements the `digest` crate's `Digest` trait. For example, to use SHA-512:

```rust
use rabin_williams_signatures::keys::{KeyPair, HashWrapper, Result};
use sha2::Sha512;

fn main() -> Result<()> {
    // Generate a key pair using SHA-512
    let hash_fn = HashWrapper::<Sha512>::default();
    let key_pair = KeyPair::generate_with_hash(1024, hash_fn)?;
    
    // Use the key pair as normal
    let message = b"Hello, World!";
    let signature = key_pair.private.sign(message)?;
    let is_valid = key_pair.public.verify(message, &signature)?;
    assert!(is_valid);
    
    Ok(())
}
```

You can also use other hash functions from the `digest` ecosystem, such as:
- SHA-1 (from the `sha1` crate)
- SHA-3 (from the `sha3` crate)
- BLAKE2 (from the `blake2` crate)
- RIPEMD (from the `ripemd` crate)
- And many more!

### Blind Signatures

```rust
use rabin_williams_signatures::keys::{KeyPair, Result};

fn main() -> Result<()> {
    let key_pair = KeyPair::generate(1024)?;
    let message = b"Hello, World!";
    
    // Blind the message
    let (blinded_message, r) = key_pair.public.blind_message(message);
    
    // Sign the blinded message
    let blinded_signature = key_pair.private.raw_sign(&blinded_message.to_bytes_be())?;
    
    // Unblind the signature
    let unblinded_signature = key_pair.public.unblind_signature(&blinded_signature, &r)?;
    
    // Verify the unblinded signature
    let is_valid = key_pair.public.verify(message, &unblinded_signature)?;
    assert!(is_valid);
    
    Ok(())
}
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.