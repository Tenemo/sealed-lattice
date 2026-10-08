use super::*;
use num_bigint::BigInt;
use num_traits::{Signed, Zero};

fn next(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}
fn unpack(value: &[u64]) -> BigUint {
    value
        .iter()
        .rev()
        .fold(BigUint::zero(), |result, word| (result << 64usize) + *word)
}
fn moduli() -> Vec<BigUint> {
    [(3, 2), (5, 5), (10, 10), (20, 20)]
        .into_iter()
        .map(|(participants, options)| {
            let modulus = supported_profile::Profile::new(participants, options)
                .unwrap()
                .ciphertext_modulus();
            (BigUint::from(modulus.odd_factor()) << modulus.exponent()) + 1u32
        })
        .collect()
}

#[test]
fn widening_products_match_128_bit_products() {
    let mut state = 0x0123_4567_89ab_cdef;
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
            let product = u128::from(*left) * u128::from(*right);
            let expected = (product as u64, (product >> 64) as u64);
            assert_eq!(widening_multiply(*left, *right), expected);
            assert_eq!(partial_products(*left, *right), expected);
        }
    }
}

#[test]
fn division_matches_big_integer_quotients_at_the_extremes() {
    for modulus in moduli() {
        let wide = WideModulus::new(&modulus);
        let limit = &modulus << 64usize;
        let mut state = 0x5eed ^ modulus.bits();
        let mut values = vec![
            BigUint::zero(),
            BigUint::from(1u32),
            &modulus - 1u32,
            modulus.clone(),
            &modulus + 1u32,
            &limit - 1u32,
            &limit - &modulus,
            &limit - &modulus - 1u32,
            (&modulus << 63usize) - 1u32,
            &modulus * 2u32 - 1u32,
        ];
        for multiple in [2u64, 3, u64::MAX - 1, u64::MAX] {
            values.push(&modulus * multiple);
            values.push(&modulus * multiple - 1u32);
        }
        for _ in 0..200 {
            let words: Vec<u64> = (0..=wide.words).map(|_| next(&mut state)).collect();
            values.push(unpack(&words) % &limit);
        }
        for value in values {
            let mut remainder = vec![0; wide.words];
            let quotient = wide.divide(&words_of(&value, wide.words + 1), &mut remainder);
            assert_eq!(BigUint::from(quotient), &value / &modulus);
            assert_eq!(unpack(&remainder), &value % &modulus);
        }
    }
}

#[test]
fn modular_operations_match_big_integer_results() {
    for modulus in moduli() {
        let wide = WideModulus::new(&modulus);
        let mut state = 0xfeed ^ modulus.bits();
        let mut values = vec![
            BigUint::zero(),
            BigUint::from(1u32),
            &modulus - 1u32,
            &modulus >> 1usize,
            (&modulus >> 1usize) + 1u32,
        ];
        for _ in 0..40 {
            let words: Vec<u64> = (0..wide.words).map(|_| next(&mut state)).collect();
            values.push(unpack(&words) % &modulus);
        }
        let signed_modulus = BigInt::from(modulus.clone());
        let canonical = |value: BigInt| {
            let value = value % &signed_modulus;
            if value.is_negative() {
                (value + &signed_modulus).magnitude().clone()
            } else {
                value.magnitude().clone()
            }
        };
        let mut output = vec![0; wide.words];
        for left in &values {
            let left_words = words_of(left, wide.words);
            assert!(wide.is_canonical(&left_words));
            wide.negate(&left_words, &mut output);
            assert_eq!(unpack(&output), canonical(-BigInt::from(left.clone())));
            for factor in [
                0i64,
                1,
                -1,
                7,
                -65_537,
                i64::from(i32::MAX),
                i64::from(i32::MIN),
            ] {
                wide.multiply_signed(&left_words, factor, &mut output);
                assert_eq!(
                    unpack(&output),
                    canonical(BigInt::from(left.clone()) * factor)
                );
            }
            for right in &values {
                wide.add(&left_words, &words_of(right, wide.words), &mut output);
                assert_eq!(unpack(&output), (left + right) % &modulus);
            }
        }
        for value in [0i64, 1, -1, 32_768, -32_768, i64::MAX, -i64::MAX] {
            wide.signed(value, &mut output);
            assert_eq!(unpack(&output), canonical(BigInt::from(value)));
        }
        assert!(!wide.is_canonical(&words_of(&modulus, wide.words)));
        assert!(!wide.is_canonical(&vec![u64::MAX; wide.words]));
    }
}

// The reference lift: the centered integer from the product's residues,
// then its value modulo q or its scaled rounded quotient.
fn reference(primes: &[u64], residues: &[u64], modulus: &BigUint, tensor: bool) -> BigUint {
    let product: BigUint = primes.iter().map(|prime| BigUint::from(*prime)).product();
    let mut value = BigUint::zero();
    for (prime, residue) in primes.iter().zip(residues) {
        let cofactor = &product / *prime;
        let inverse =
            (&cofactor % *prime).modpow(&BigUint::from(prime - 2), &BigUint::from(*prime));
        value += cofactor * (inverse * residue % *prime);
    }
    value %= &product;
    let negative = value > &product >> 1usize;
    let magnitude = if negative { &product - value } else { value };
    let reduced = if tensor {
        (magnitude * 65_537u32 + (modulus >> 1usize)) / modulus % modulus
    } else {
        magnitude % modulus
    };
    if negative && !reduced.is_zero() {
        modulus - reduced
    } else {
        reduced
    }
}

// A tensor's rounded quotient floor((S + floor(q / 2)) / q), with S the
// multipliers times each prime's remainder t P / p_i mod q and then
// q - (t P mod q), computed here from the primes and the modulus:
// the fixed-point fractions decide it for multipliers at zero, at
// their largest and at random, and the exact path agrees. A fraction
// within 2^64 units below a whole number is left to the exact path.
#[test]
fn rounded_quotients_match_exact_quotients() {
    let mut primes = Vec::new();
    let mut limit = 1u64 << 58;
    while primes.len() < 36 {
        limit = super::super::super::proth_prime(58, limit);
        primes.push(limit);
    }
    let reductions: Vec<PrimeModulus> = primes
        .iter()
        .map(|prime| PrimeModulus::new(*prime))
        .collect();
    for modulus in moduli() {
        let wide = WideModulus::new(&modulus);
        let half = &modulus >> 1usize;
        let bound = 2u32 * BigUint::from(65_536u32) * &half * &half;
        let mut count = 0;
        let mut product = BigUint::from(1u32);
        while !Lift::covers(&product, count, &bound) {
            product *= primes[count];
            count += 1;
        }
        let lift = Lift::new(
            &primes[..count],
            &reductions[..count],
            &modulus,
            65_537,
            true,
        );
        let mut remainders: Vec<BigUint> = primes[..count]
            .iter()
            .map(|prime| &product / *prime * 65_537u32 % &modulus)
            .collect();
        remainders.push(&modulus - &product * 65_537u32 % &modulus);
        let mut state = 0x7a11 ^ count as u64;
        let mut cases = vec![
            vec![0; count + 1],
            primes[..count]
                .iter()
                .map(|prime| prime - 1)
                .chain([count as u64])
                .collect::<Vec<_>>(),
        ];
        for _ in 0..400 {
            let mut multipliers: Vec<u64> = primes[..count]
                .iter()
                .map(|prime| next(&mut state) % prime)
                .collect();
            multipliers.push(next(&mut state) % (count as u64 + 1));
            cases.push(multipliers);
        }
        let mut buffer = vec![0; wide.words + 1];
        let mut remainder = vec![0; wide.words];
        for multipliers in cases {
            let sum = multipliers
                .iter()
                .zip(&remainders)
                .map(|(multiplier, remainder)| remainder * *multiplier)
                .sum::<BigUint>();
            let expected = ((sum + &half) / &modulus).to_u64().unwrap();
            assert_eq!(lift.rounded_quotient(&multipliers), Some(expected));
            assert_eq!(
                lift.exact_rounded_quotient(&multipliers, &wide, &mut buffer, &mut remainder),
                expected
            );
        }
    }
    assert_eq!(decided([u64::MAX, u64::MAX - 1, 7]), Some(7));
    assert_eq!(decided([0, u64::MAX, 7]), None);
}

#[test]
fn lifts_match_big_integer_reconstruction_across_the_bound() {
    let mut primes = Vec::new();
    let mut limit = 1u64 << 58;
    while primes.len() < 36 {
        limit = super::super::super::proth_prime(58, limit);
        primes.push(limit);
    }
    let reductions: Vec<PrimeModulus> = primes
        .iter()
        .map(|prime| PrimeModulus::new(*prime))
        .collect();
    for modulus in moduli() {
        let wide = WideModulus::new(&modulus);
        for tensor in [false, true] {
            // The tensor bound is the degree times the square of half
            // the modulus, and a plaintext product's is smaller.
            let half = &modulus >> 1usize;
            let bound = if tensor {
                2u32 * BigUint::from(65_536u32) * &half * &half
            } else {
                2u32 * BigUint::from(65_536u32 * 32_768) * &half
            };
            let mut count = 0;
            let mut product = BigUint::from(1u32);
            while !Lift::covers(&product, count, &bound) {
                product *= primes[count];
                count += 1;
            }
            let lift = Lift::new(
                &primes[..count],
                &reductions[..count],
                &modulus,
                65_537,
                tensor,
            );
            let magnitude = &bound >> 1usize;
            let mut state = 0xabcd ^ count as u64;
            let mut integers: Vec<BigInt> = vec![
                BigInt::zero(),
                BigInt::from(1),
                BigInt::from(-1),
                BigInt::from(magnitude.clone()),
                -BigInt::from(magnitude.clone()),
                BigInt::from(&magnitude - 1u32),
                BigInt::from(modulus.clone()),
                -BigInt::from(&half + 1u32),
                BigInt::from(half.clone()),
            ];
            for _ in 0..300 {
                let words: Vec<u64> = (0..2 * wide.words + 1).map(|_| next(&mut state)).collect();
                let value = BigInt::from(unpack(&words) % &magnitude);
                integers.push(if next(&mut state) & 1 == 0 {
                    value
                } else {
                    -value
                });
            }
            let signed_product = BigInt::from(product.clone());
            let residues: Vec<Vec<u64>> = primes[..count]
                .iter()
                .map(|prime| {
                    integers
                        .iter()
                        .map(|integer| {
                            let prime = BigInt::from(*prime);
                            (((integer % &prime) + &prime) % &prime).to_u64().unwrap()
                        })
                        .collect()
                })
                .collect();
            let residues: Vec<&[u64]> = residues.iter().map(Vec::as_slice).collect();
            let mut output = vec![0; wide.words];
            for (position, integer) in integers.iter().enumerate() {
                let values: Vec<u64> = residues.iter().map(|values| values[position]).collect();
                lift.coefficient(
                    &residues,
                    position,
                    &reductions[..count],
                    &wide,
                    &mut output,
                );
                assert_eq!(
                    unpack(&output),
                    reference(&primes[..count], &values, &modulus, tensor),
                    "integer {integer}, tensor {tensor}, bits {}",
                    modulus.bits()
                );
                assert!(integer.magnitude() < &(&signed_product.magnitude().clone() >> 1usize));
            }
        }
    }
}
