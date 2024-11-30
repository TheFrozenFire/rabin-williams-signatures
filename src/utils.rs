use num_bigint::{BigUint, BigInt};
use num_integer::Integer;
use num_traits::{One, Zero};
use crate::errors::{Result, RabinWilliamsError};

/// Computes the modular square root using the Tonelli-Shanks algorithm
pub fn mod_sqrt(a: &BigUint, p: &BigUint) -> Result<BigUint> {
    if !is_quadratic_residue(a, p) {
        return Err(RabinWilliamsError::SquareRootModPrimeFailed);
    }

    if p.is_zero() || p.is_one() {
        return Err(RabinWilliamsError::InvalidPrime);
    }

    // Handle p mod 4 == 3 case using faster computation
    if p % 4u32 == 3u32.into() {
        let exp = (p + 1u32) / 4u32;
        return Ok(a.modpow(&exp, p));
    }

    // Tonelli-Shanks algorithm implementation
    let mut q = p - 1u32;
    let mut s = 0u32;
    while (&q % 2u32).is_zero() {
        s += 1;
        q >>= 1;
    }

    if s == 1 {
        let exp = (p + 1u32) / 4u32;
        return Ok(a.modpow(&exp, p));
    }

    // Find quadratic non-residue
    let mut z = BigUint::from(2u32);
    while is_quadratic_residue(&z, p) {
        z += 1u32;
    }

    let mut c = z.modpow(&q, p);
    let mut r = a.modpow(&((q + 1u32) / 2u32), p);
    let mut t = a.modpow(&q, p);
    let mut m = s;

    loop {
        if t.is_one() {
            return Ok(r);
        }

        let mut i = 0u32;
        let mut temp = t.clone();
        while !temp.is_one() && i < m {
            temp = (&temp * &temp) % p;
            i += 1;
        }

        if i == m {
            return Err(RabinWilliamsError::SquareRootModPrimeFailed);
        }

        let b = c.modpow(&BigUint::from(2u32).pow(m - i - 1), p);
        r = (r * &b) % p;
        c = (&b * &b) % p;
        t = (t * &c) % p;
        m = i;
    }
}

/// Checks if a number is a quadratic residue modulo p
pub fn is_quadratic_residue(a: &BigUint, p: &BigUint) -> bool {
    if p.is_zero() || p.is_one() {
        return false;
    }
    let exp = (p - 1u32) / 2u32;
    a.modpow(&exp, p) == BigUint::one()
}

/// Chinese Remainder Theorem implementation
pub fn chinese_remainder_theorem(remainders: &[BigInt], moduli: &[BigInt]) -> Result<BigInt> {
    if remainders.len() != moduli.len() {
        return Err(RabinWilliamsError::ComputationError);
    }

    let prod = moduli.iter().product::<BigInt>();
    
    let mut sum = BigInt::zero();
    for i in 0..remainders.len() {
        let p = &prod / &moduli[i];
        let mut inv = mod_inverse(&p, &moduli[i])
            .ok_or(RabinWilliamsError::ComputationError)?;
        if inv < BigInt::zero() {
            inv += &moduli[i];
        }
        sum += &remainders[i] * &p * inv;
    }

    Ok(sum % prod)
}

/// Computes modular multiplicative inverse using extended Euclidean algorithm
pub fn mod_inverse(a: &BigInt, m: &BigInt) -> Option<BigInt> {
    let mut t = BigInt::zero();
    let mut newt = BigInt::one();
    let mut r = m.clone();
    let mut newr = a.clone();

    while !newr.is_zero() {
        let quotient = &r / &newr;
        let temp_t = t.clone();
        t = newt.clone();
        newt = temp_t - &quotient * newt;
        let temp_r = r.clone();
        r = newr.clone();
        newr = temp_r - &quotient * newr;
    }

    if r > BigInt::one() {
        return None;
    }
    if t < BigInt::zero() {
        t += m;
    }
    Some(t)
}
