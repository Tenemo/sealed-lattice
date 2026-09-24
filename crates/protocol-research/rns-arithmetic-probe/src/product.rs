use fhe_math::{ntt::NttOperator, rns::RnsContext, zq::Modulus};
use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{One, ToPrimitive, Zero};
use sha2::{Digest, Sha512};

fn next(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

fn inputs(degree: usize, modulus: &BigUint, seed: u64) -> Vec<BigInt> {
    let mut state = seed;
    let half = modulus >> 1usize;
    let sampling_words = modulus.bits().div_ceil(64) as usize + 1;
    (0..degree)
        .map(|_| {
            let bytes: Vec<u8> = (0..sampling_words)
                .flat_map(|_| next(&mut state).to_le_bytes())
                .collect();
            let value = BigUint::from_bytes_le(&bytes) % modulus;
            if value > half {
                BigInt::from(value) - BigInt::from(modulus.clone())
            } else {
                BigInt::from(value)
            }
        })
        .collect()
}

fn residue(value: &BigInt, prime: u64) -> u64 {
    let value_mod = (value.magnitude() % prime).to_u64().unwrap();
    if value.sign() == Sign::Minus && value_mod != 0 {
        prime - value_mod
    } else {
        value_mod
    }
}

fn round_tensor(value: BigInt, modulus: &BigUint) -> BigUint {
    let rounded = (value.magnitude() * 65537u64 + (modulus >> 1usize)) / modulus % modulus;
    if value.sign() == Sign::Minus && !rounded.is_zero() {
        modulus - rounded
    } else {
        rounded
    }
}

pub fn probe(log_degree: u32) -> String {
    assert!((3..=16).contains(&log_degree));
    let degree = 1usize << log_degree;
    let modulus = ((BigUint::from(65537u64) * 65319u64) << 832usize) + 1u64;
    let half = &modulus >> 1usize;
    let raw_bound = &half * &half * degree;
    let prime_count = (2 * modulus.bits() + log_degree as u64 + 1).div_ceil(58) as usize;
    let mut limit = 1u64 << 58;
    let primes: Vec<u64> = (0..prime_count)
        .map(|_| {
            limit = super::proth_prime(58, limit);
            limit
        })
        .collect();
    let context = RnsContext::new(&primes).unwrap();
    assert!(context.modulus() > &(2u64 * raw_bound));
    let operators: Vec<NttOperator> = primes
        .iter()
        .map(|prime| NttOperator::new(&Modulus::new(*prime).unwrap(), degree).unwrap())
        .collect();
    let left = inputs(degree, &modulus, 0x6a09_e667_f3bc_c909);
    let right = inputs(degree, &modulus, 0xbb67_ae85_84ca_a73b);
    let selected: Vec<usize> = if degree == 8 {
        (0..degree).collect()
    } else {
        vec![0, 1, degree / 2, degree - 1]
    };
    let expected: Vec<BigUint> = selected
        .iter()
        .map(|output| {
            let mut sum = BigInt::zero();
            for (index, coefficient) in left.iter().enumerate() {
                let other = (output + degree - index) % degree;
                let product = coefficient * &right[other];
                if *output < index {
                    sum -= product;
                } else {
                    sum += product;
                }
            }
            round_tensor(sum, &modulus)
        })
        .collect();
    let mut products = Vec::with_capacity(prime_count);
    for (prime, transform) in primes.iter().zip(&operators) {
        let ring = Modulus::new(*prime).unwrap();
        let mut first: Vec<u64> = left.iter().map(|value| residue(value, *prime)).collect();
        let mut second: Vec<u64> = right.iter().map(|value| residue(value, *prime)).collect();
        transform.forward(&mut first);
        transform.forward(&mut second);
        for (first, second) in first.iter_mut().zip(second) {
            *first = ring.mul(*first, second);
        }
        transform.backward(&mut first);
        products.push(first);
    }
    let mut digest = Sha512::new();
    let mut coefficient_residues = vec![0; prime_count];
    let half_product = context.modulus() >> 1usize;
    let width = modulus.bits().div_ceil(8) as usize;
    for position in 0..degree {
        for (slot, polynomial) in coefficient_residues.iter_mut().zip(&products) {
            *slot = polynomial[position];
        }
        let raw = context.lift((&coefficient_residues).into());
        let raw = if raw > half_product {
            BigInt::from(raw) - BigInt::from(context.modulus().clone())
        } else {
            BigInt::from(raw)
        };
        let scaled = round_tensor(raw, &modulus);
        if let Some(index) = selected.iter().position(|selected| *selected == position) {
            assert_eq!(scaled, expected[index]);
        }
        let mut bytes = scaled.to_bytes_le();
        bytes.resize(width, 0);
        digest.update(&bytes);
    }
    let digest = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let certificate_count = primes
        .iter()
        .filter(|prime| super::power(3, (**prime - 1) / 2, **prime) == **prime - 1)
        .count();
    assert_eq!(certificate_count, prime_count);
    assert_eq!(modulus.bits(), 864);
    assert_eq!(BigUint::one(), &modulus % 65537u64);
    format!(
        "{{\"degree\":{degree},\"fheModulus\":\"{modulus}\",\"arithmeticPrimeCount\":{prime_count},\"arithmeticModulusBits\":{},\"directConvolutionCoefficientsChecked\":{},\"digest\":\"{digest}\"}}",
        context.modulus().bits(),
        selected.len()
    )
}
