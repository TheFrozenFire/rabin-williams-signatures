use num_bigint::{BigUint, BigInt, ToBigInt};
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
        let exp = (p.clone() + 1u32) / 4u32;
        return Ok(a.modpow(&exp, p));
    }

    // Tonelli-Shanks algorithm implementation
    let mut q = p.clone() - 1u32;
    let mut s = 0u32;
    while (&q % 2u32).is_zero() {
        s += 1;
        q >>= 1;
    }

    if s == 1 {
        let exp = (p.clone() + 1u32) / 4u32;
        return Ok(a.modpow(&exp, p));
    }

    // Find quadratic non-residue
    let mut z = BigUint::from(2u32);
    while is_quadratic_residue(&z, p) {
        z += 1u32;
    }

    let mut c = z.modpow(&q, p);
    let mut r = a.modpow(&((q.clone() + 1u32) / 2u32), p);
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
        r = (&r * &b) % p;
        c = (&b * &b) % p;
        t = (&t * &c) % p;
        m = i;
    }
}

/// Chinese Remainder Theorem implementation
pub fn chinese_remainder_theorem(remainders: &[BigUint], moduli: &[BigUint]) -> Result<BigUint> {
    if remainders.len() != moduli.len() || remainders.is_empty() {
        return Err(RabinWilliamsError::ComputationError);
    }

    // Compute product of all moduli
    let prod = moduli.iter().fold(BigUint::one(), |acc, m| acc * m.clone());
    
    let mut sum = BigUint::zero();
    for i in 0..remainders.len() {
        let p = &prod / moduli[i].clone();
        let inv = mod_inverse(&p, &moduli[i])
            .ok_or(RabinWilliamsError::ComputationError)?;
        
        let term = (remainders[i].clone() * &p % &prod * inv % &prod) % &prod;
        sum = (sum + term) % &prod;
    }

    Ok(sum)
}

/// Computes modular multiplicative inverse using extended Euclidean algorithm
pub fn mod_inverse(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    if m.is_zero() {
        return None;
    }

    let mut t = BigInt::zero();
    let mut newt = BigInt::one();
    let mut r = m.to_bigint().unwrap();
    let mut newr = a.to_bigint().unwrap();

    while !newr.is_zero() {
        let quotient = &r / &newr;
        (t, newt) = (newt.clone(), &t - &quotient * &newt);
        (r, newr) = (newr.clone(), &r - &quotient * &newr);
    }

    if r > BigInt::one() {
        return None;
    }
    if t < BigInt::zero() {
        t = t + m.to_bigint().unwrap();
    }
    Some(t.to_biguint().unwrap())
}

pub fn is_quadratic_residue(a: &BigUint, p: &BigUint) -> bool {
    if p.is_zero() || p.is_one() {
        return false;
    }
    let exp = (p.clone() - 1u32) / 2u32;
    a.modpow(&exp, p) == BigUint::one()
}

pub fn make_quadratic_residue(a: &BigUint, p: &BigUint, q: &BigUint) -> (BigUint, (i32, u32)) {
    let n = p * q;
    let candidates = [
        (a.clone(), 1, 1),
        (n.clone() - a.clone(), -1, 1),
        ((a.clone() * 2u32) % &n, 1, 2),
        (((n.clone() - a.clone()) * 2u32) % &n, -1, 2),
    ];
    for (cand, e, f) in candidates.iter() {
        if is_quadratic_residue(&cand, p) && is_quadratic_residue(&cand, q) {
            return (cand.clone(), (*e, *f));
        }
    }
    panic!("No quadratic residue found for given a, p, q");
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;

    #[test]
    fn test_mod_sqrt() {
        // Test case where p ≡ 3 (mod 4)
        let p = BigUint::from(7u32);
        let a = BigUint::from(2u32);
        let sqrt = mod_sqrt(&a, &p).unwrap();
        assert_eq!((&sqrt * &sqrt) % &p, a);

        // Test case where p ≡ 1 (mod 4)
        let p = BigUint::from(13u32);
        let a = BigUint::from(3u32);
        let sqrt = mod_sqrt(&a, &p).unwrap();
        assert_eq!((&sqrt * &sqrt) % &p, a);

        // Test non-quadratic residue
        let p = BigUint::from(7u32);
        let a = BigUint::from(3u32);
        assert!(mod_sqrt(&a, &p).is_err());

        // Test invalid prime
        let p = BigUint::from(1u32);
        let a = BigUint::from(2u32);
        assert!(mod_sqrt(&a, &p).is_err());
    }

    #[test]
    fn test_chinese_remainder_theorem() {
        // Test simple case
        let remainders = vec![
            BigUint::from(2u32),
            BigUint::from(3u32),
            BigUint::from(2u32),
        ];
        let moduli = vec![
            BigUint::from(3u32),
            BigUint::from(5u32),
            BigUint::from(7u32),
        ];
        let result = chinese_remainder_theorem(&remainders, &moduli).unwrap();
        assert_eq!(result, BigUint::from(23u32));

        // Test empty input
        assert!(chinese_remainder_theorem(&[], &[]).is_err());

        // Test mismatched lengths
        let remainders = vec![BigUint::from(2u32)];
        let moduli = vec![BigUint::from(3u32), BigUint::from(5u32)];
        assert!(chinese_remainder_theorem(&remainders, &moduli).is_err());

        // Test larger numbers
        let remainders = vec![
            BigUint::from(123456u32),
            BigUint::from(789012u32),
        ];
        let moduli = vec![
            BigUint::from(1000003u32),
            BigUint::from(1000007u32),
        ];
        let result = chinese_remainder_theorem(&remainders, &moduli).unwrap();
        for (r, m) in remainders.iter().zip(moduli.iter()) {
            assert_eq!(&result % m, r.clone());
        }
    }

    #[test]
    fn test_mod_inverse() {
        // Test simple case
        let a = BigUint::from(3u32);
        let m = BigUint::from(11u32);
        let inv = mod_inverse(&a, &m).unwrap();
        assert_eq!((&a * &inv) % &m, BigUint::from(1u32));

        // Test case where inverse doesn't exist
        let a = BigUint::from(2u32);
        let m = BigUint::from(4u32);
        assert!(mod_inverse(&a, &m).is_none());

        // Test with zero modulus
        let a = BigUint::from(3u32);
        let m = BigUint::from(0u32);
        assert!(mod_inverse(&a, &m).is_none());

        // Test with larger numbers
        let a = BigUint::from(123456u32);
        let m = BigUint::from(1000003u32);
        let inv = mod_inverse(&a, &m).unwrap();
        assert_eq!((&a * &inv) % &m, BigUint::from(1u32));
    }

    #[test]
    fn test_is_quadratic_residue() {
        // Test quadratic residues
        let p = BigUint::from(7u32);
        assert!(is_quadratic_residue(&BigUint::from(2u32), &p));
        assert!(is_quadratic_residue(&BigUint::from(4u32), &p));

        // Test non-quadratic residues
        assert!(!is_quadratic_residue(&BigUint::from(3u32), &p));
        assert!(!is_quadratic_residue(&BigUint::from(5u32), &p));

        // Test edge cases
        assert!(!is_quadratic_residue(&BigUint::from(2u32), &BigUint::from(0u32)));
        assert!(!is_quadratic_residue(&BigUint::from(2u32), &BigUint::from(1u32)));
    }

    #[test]
    fn test_make_quadratic_residue() {
        let p = BigUint::from(7u32);
        let q = BigUint::from(11u32);
        let n = &p * &q;

        // Test case where a is already a quadratic residue
        let a = BigUint::from(4u32);
        let (result, (_e, _f)) = make_quadratic_residue(&a, &p, &q);
        println!("a = {}, result = {}, p = {}, is_qr = {}", a, result, p, is_quadratic_residue(&result, &p));
        assert!(is_quadratic_residue(&result, &p));
        assert!(is_quadratic_residue(&result, &q));

        // Test case where a needs to be negated
        let a = BigUint::from(3u32);
        let (result, (_e, _f)) = make_quadratic_residue(&a, &p, &q);
        println!("a = {}, result = {}, p = {}, is_qr = {}", a, result, p, is_quadratic_residue(&result, &p));
        assert!(is_quadratic_residue(&result, &p));
        assert!(is_quadratic_residue(&result, &q));

        // Test case where a needs to be multiplied by 2
        let a = BigUint::from(5u32);
        let (result, (_e, _f)) = make_quadratic_residue(&a, &p, &q);
        println!("a = {}, result = {}, p = {}, is_qr = {}", a, result, p, is_quadratic_residue(&result, &p));
        assert!(is_quadratic_residue(&result, &p));
        assert!(is_quadratic_residue(&result, &q));

        // Verify the result is always less than n
        assert!(result < n);
    }
}