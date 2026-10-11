use super::*;
use num_bigint::BigUint;
use num_traits::ToPrimitive;

fn next(state: &mut u64) -> u64 {
    super::super::next(state)
}
/// Proth primes with witness three: Fermat primes for short transforms
/// and the two largest 58-bit transform primes.
fn transform_primes() -> Vec<u64> {
    let first = crate::proth_prime(58, 1 << 58);
    vec![17, 257, 65_537, first, crate::proth_prime(58, first)]
}
/// The residue of a product, from 128-bit integer arithmetic alone.
fn product(left: u64, right: u64, prime: u64) -> u64 {
    (u128::from(left) * u128::from(right) % u128::from(prime)) as u64
}
fn exponentiation(base: u64, exponent: u64, prime: u64) -> u64 {
    BigUint::from(base)
        .modpow(&BigUint::from(exponent), &BigUint::from(prime))
        .to_u64()
        .unwrap()
}
fn residues(prime: u64, count: usize, state: &mut u64) -> Vec<u64> {
    let mut values = vec![0, 1, 2, prime / 2, prime - 2, prime - 1];
    values.extend((values.len()..count).map(|_| next(state) % prime));
    values.truncate(count);
    values
}

#[test]
fn high_products_match_128_bit_products() {
    let mut state = 0x9e37_79b9_7f4a_7c15;
    let mut values = vec![
        0,
        1,
        u64::MAX,
        u64::MAX - 1,
        1 << 63,
        (1 << 32) - 1,
        1 << 32,
    ];
    values.extend((0..64).map(|_| next(&mut state)));
    for left in &values {
        for right in &values {
            let expected = ((u128::from(*left) * u128::from(*right)) >> 64) as u64;
            assert_eq!(high_product(*left, *right), expected);
            assert_eq!(partial_high_product(*left, *right), expected);
        }
    }
}

// The 61-bit Mersenne prime checks the residue arithmetic near its
// bound.
#[test]
fn residue_arithmetic_matches_integer_arithmetic() {
    let mut state = 0x0005_eed0_fa11;
    for prime in transform_primes().into_iter().chain([(1 << 61) - 1]) {
        let modulus = PrimeModulus::new(prime);
        assert_eq!(*modulus, prime);
        let values = residues(prime, 48, &mut state);
        for left in &values {
            for right in &values {
                let expected = product(*left, *right, prime);
                assert_eq!(modulus.multiply(*left, *right), expected);
                let quotient = modulus.shoup(*right);
                assert_eq!(
                    BigUint::from(quotient),
                    (BigUint::from(*right) << 64usize) / prime
                );
                assert_eq!(modulus.multiply_shoup(*left, *right, quotient), expected);
                // Any word, not only a residue, multiplies lazily.
                let word = next(&mut state);
                let lazy = modulus.lazy_multiply_shoup(word, *right, quotient);
                assert!(lazy < 2 * prime);
                assert_eq!(lazy % prime, product(word % prime, *right, prime));
            }
            let exponent = next(&mut state);
            assert_eq!(
                modulus.power(*left, exponent),
                exponentiation(*left, exponent, prime)
            );
            if *left != 0 {
                assert_eq!(product(modulus.inverse(*left), *left, prime), 1);
            }
        }
        let mut wide = vec![
            0,
            u128::MAX,
            u128::MAX - 1,
            u128::from(prime) * u128::from(prime) - 1,
            u128::from(prime) << 64,
            (u128::from(prime) << 64) - 1,
        ];
        wide.extend(
            (0..256).map(|_| (u128::from(next(&mut state)) << 64) | u128::from(next(&mut state))),
        );
        for value in wide {
            assert_eq!(
                u128::from(modulus.reduce_wide(value)),
                value % u128::from(prime)
            );
        }
    }
}

#[test]
#[should_panic(expected = "Invertible residue")]
fn zero_has_no_inverse() {
    PrimeModulus::new(17).inverse(0);
}

// The forward transform evaluates at the odd powers of three to the
// (p - 1) / 2n in bit-reversed order, here evaluated directly.
#[test]
fn forward_transforms_evaluate_at_the_odd_root_powers() {
    let mut state = 0x0dd5_eed0;
    let primes = transform_primes();
    for (prime, length) in [
        (primes[0], 2),
        (primes[0], 8),
        (primes[1], 128),
        (primes[2], 1024),
        (primes[3], 4),
        (primes[3], 512),
        (primes[4], 2048),
    ] {
        let modulus = PrimeModulus::new(prime);
        let transform = Transform::new(&modulus, length);
        let root = exponentiation(3, (prime - 1) / (2 * length as u64), prime);
        let bits = length.trailing_zeros();
        let values = residues(prime, length, &mut state);
        let mut transformed = values.clone();
        transform.forward(&mut transformed);
        for (index, value) in transformed.iter().enumerate() {
            let reversed = (index.reverse_bits() >> (usize::BITS - bits)) as u64;
            let point = exponentiation(root, 2 * reversed + 1, prime);
            let evaluation = values.iter().rev().fold(0, |sum, coefficient| {
                (product(sum, point, prime) + coefficient) % prime
            });
            assert_eq!(
                *value, evaluation,
                "prime {prime} length {length} index {index}"
            );
        }
        transform.backward(&mut transformed);
        assert_eq!(transformed, values);
    }
}

// Pointwise products of transforms are the transforms of products
// modulo X^n + 1, here multiplied term by term.
#[test]
fn transform_products_match_negacyclic_schoolbook_products() {
    let mut state = 0xc0ff_ee15;
    let primes = transform_primes();
    for (prime, length, terms) in [
        (primes[0], 8, 8),
        (primes[2], 256, 256),
        (primes[3], 1024, 1024),
        (primes[4], supported_profile::DEGREE, 6),
    ] {
        let modulus = PrimeModulus::new(prime);
        let transform = Transform::new(&modulus, length);
        let left = residues(prime, length, &mut state);
        // A short right factor has its terms at scattered positions,
        // which keeps the schoolbook product short.
        let mut right = vec![0; length];
        for (term, value) in residues(prime, terms, &mut state).into_iter().enumerate() {
            let position = if terms == length {
                term
            } else {
                next(&mut state) as usize % length
            };
            right[position] = if term == 0 { prime - 1 } else { value };
        }
        let mut expected = vec![0; length];
        for (shift, factor) in right.iter().enumerate() {
            if *factor == 0 {
                continue;
            }
            for (position, value) in left.iter().enumerate() {
                let term = product(*value, *factor, prime);
                let target = (position + shift) % length;
                expected[target] = if position + shift < length {
                    (expected[target] + term) % prime
                } else {
                    (expected[target] + prime - term) % prime
                };
            }
        }
        let (mut left_transform, mut right_transform) = (left.clone(), right);
        transform.forward(&mut left_transform);
        transform.forward(&mut right_transform);
        let mut products: Vec<u64> = left_transform
            .iter()
            .zip(&right_transform)
            .map(|(left, right)| modulus.multiply(*left, *right))
            .collect();
        transform.backward(&mut products);
        assert_eq!(products, expected, "prime {prime} length {length}");
        transform.backward(&mut left_transform);
        assert_eq!(left_transform, left);
    }
}

#[test]
fn transforms_refuse_lengths_and_primes_without_a_certified_root() {
    let modulus = PrimeModulus::new(17);
    for length in [1, 3, 12, 16] {
        assert!(std::panic::catch_unwind(|| Transform::new(&modulus, length)).is_err());
    }
    // 97 = 3 2^5 + 1 is prime, but three is a square modulo 97.
    let square = PrimeModulus::new(97);
    assert!(std::panic::catch_unwind(|| Transform::new(&square, 16)).is_err());
}
