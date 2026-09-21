use fhe_math::rns::{RnsContext, RnsScaler, ScalingFactor};
use num_bigint::BigUint;
use num_traits::{One, ToPrimitive, Zero};
mod encrypted;
mod product;
pub use encrypted::probe as encrypted_probe;
pub use encrypted::ranking;
pub use product::probe as product_probe;
use std::{cell::RefCell, sync::Arc};

#[cfg(target_arch = "wasm32")]
#[link(wasm_import_module = "benchmark")]
unsafe extern "C" {
    fn record_phase(code: u32);
}

fn benchmark_phase(code: u32) {
    #[cfg(target_arch = "wasm32")]
    // SAFETY: This measurement callback receives one integer and returns no
    // value. It cannot select data or influence arithmetic decisions.
    unsafe {
        record_phase(code);
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = code;
}

fn power(mut value: u64, mut exponent: u64, modulus: u64) -> u64 {
    let mut result = 1;
    while exponent > 0 {
        if exponent & 1 != 0 {
            result = (result as u128 * value as u128 % modulus as u128) as u64;
        }
        value = (value as u128 * value as u128 % modulus as u128) as u64;
        exponent >>= 1;
    }
    result
}

fn proth_prime(bits: u32, below: u64) -> u64 {
    let mut odd = (((below - 1) >> 32) - 1) | 1;
    loop {
        let candidate = (odd << 32) + 1;
        assert_eq!(64 - candidate.leading_zeros(), bits);
        assert!(odd < 1u64 << 32);
        if candidate < below && power(3, (candidate - 1) / 2, candidate) == candidate - 1 {
            return candidate;
        }
        odd -= 2;
    }
}

pub fn profile() -> Vec<u64> {
    let mut result = Vec::new();
    for (bits, count) in [(58, 9), (57, 6)] {
        let mut limit = 1u64 << bits;
        for _ in 0..count {
            limit = proth_prime(bits, limit);
            result.push(limit);
        }
    }
    result
}

fn canonical_round(
    value: &BigUint,
    numerator: &BigUint,
    denominator: &BigUint,
    source: &BigUint,
    target: &BigUint,
) -> BigUint {
    let negative = value > &(source >> 1);
    let magnitude = if negative {
        source - value
    } else {
        value.clone()
    };
    let rounded: BigUint = (magnitude * numerator + (denominator >> 1usize)) / denominator % target;
    if negative && !rounded.is_zero() {
        target - rounded
    } else {
        rounded
    }
}

pub fn probe() -> String {
    let primes = profile();
    let from = Arc::new(RnsContext::new(&primes).expect("valid distinct certified primes"));
    let modulus = from.modulus();
    assert_eq!(modulus.bits(), 864);
    let plaintext = BigUint::from(65537u64);
    let inverse_mod_plain = power((modulus % &plaintext).to_u64().unwrap(), 65535, 65537);
    let inverse_plain = (modulus * (65537 - inverse_mod_plain) + 1u64) / &plaintext;
    assert_eq!(&inverse_plain * &plaintext % modulus, BigUint::one());
    let half: BigUint = modulus >> 1usize;
    let mut cases = vec![
        ("zero".to_string(), BigUint::zero()),
        ("one".to_string(), BigUint::one()),
        ("minus-one".to_string(), modulus - 1u64),
    ];
    for offset in -4i64..=4 {
        let near_half: BigUint = if offset < 0 {
            &half - offset.unsigned_abs()
        } else {
            &half + offset as u64
        };
        cases.push((format!("center/{offset}"), near_half.clone()));
        cases.push((
            format!("rounded-fraction/{offset}"),
            near_half * &inverse_plain % modulus,
        ));
    }
    let scaled = RnsScaler::new(&from, &from, ScalingFactor::new(&plaintext, modulus));
    let inspection_prime = proth_prime(61, 1u64 << 61);
    let inspection = Arc::new(RnsContext::new(&[inspection_prime]).unwrap());
    let extended = RnsScaler::new(&from, &inspection, ScalingFactor::one());
    let mut observations = Vec::new();
    for (name, value) in cases {
        let input = from.project(&value);
        let actual = from.lift((&scaled.scale_new((&input).into(), primes.len())).into());
        let expected = canonical_round(&value, &plaintext, modulus, modulus, modulus);
        let difference = (&actual + modulus - &expected) % modulus;
        let difference = if difference > half {
            format!("-{}", modulus - difference)
        } else {
            difference.to_string()
        };
        let actual_extension = extended.scale_new((&input).into(), 1)[0];
        let expected_extension = canonical_round(
            &value,
            &BigUint::one(),
            &BigUint::one(),
            modulus,
            inspection.modulus(),
        );
        observations.push(format!("{{\"case\":\"{name}\",\"roundingDifference\":\"{difference}\",\"canonicalExtensionMatches\":{}}}", BigUint::from(actual_extension) == expected_extension));
    }
    let primes_json = primes
        .iter()
        .map(|prime| format!("\"{prime}\""))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"modulus\":\"{modulus}\",\"modulusBits\":{},\"primePowerOfTwo\":32,\"primeWitness\":3,\"primes\":[{primes_json}],\"inspectionPrime\":\"{inspection_prime}\",\"observations\":[{}]}}",
        modulus.bits(),
        observations.join(",")
    )
}

thread_local! { static OUTPUT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) }; }

#[unsafe(no_mangle)]
pub extern "C" fn run_rounding_probe() -> u32 {
    let output = probe().into_bytes();
    let length = output.len() as u32;
    OUTPUT.with(|state| *state.borrow_mut() = output);
    length
}

#[unsafe(no_mangle)]
pub extern "C" fn rounding_probe_output() -> u32 {
    OUTPUT.with(|state| state.borrow().as_ptr() as usize as u32)
}

#[unsafe(no_mangle)]
pub extern "C" fn run_product_probe(log_degree: u32) -> u32 {
    if !(3..=16).contains(&log_degree) {
        return 0;
    }
    let output = product_probe(log_degree).into_bytes();
    let length = output.len() as u32;
    OUTPUT.with(|state| *state.borrow_mut() = output);
    length
}

#[unsafe(no_mangle)]
pub extern "C" fn run_encrypted_probe(log_degree: u32) -> u32 {
    if !(3..=16).contains(&log_degree) {
        return 0;
    }
    let output = encrypted_probe(log_degree).into_bytes();
    let length = output.len() as u32;
    OUTPUT.with(|state| *state.borrow_mut() = output);
    length
}

#[unsafe(no_mangle)]
pub extern "C" fn run_requested_output_probe(top_count: u32) -> u32 {
    let Ok(output) = ranking::requested_output_probe(top_count as usize) else {
        return 0;
    };
    let output = output.into_bytes();
    let length = output.len() as u32;
    OUTPUT.with(|state| *state.borrow_mut() = output);
    length
}
