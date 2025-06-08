# Rabin-Williams Signatures

A Rust implementation of the [Rabin-Williams signature scheme](https://en.wikipedia.org/wiki/Rabin_signature_algorithm#Rabin-Williams),
featuring both regular and blind signatures.

## Overview

This library implements the Rabin-Williams signature scheme, which is a variant of the Rabin signature scheme. The implementation includes:

- Key pair generation with configurable key sizes (minimum 1024 bits)
- Regular message signing and verification
- Blind signature support
- SHA-256 for message hashing

## Features

- **Secure Key Generation**: Generates primes p and q with specific congruence conditions (p ≡ 3 mod 8, q ≡ 7 mod 8)
- **Deterministic Signatures**: Uses a deterministic approach for signature generation
- **Blind Signatures**: Supports blind signatures for privacy-preserving applications

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
    // Generate a key pair
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