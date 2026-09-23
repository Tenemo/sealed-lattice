mod encrypted;
pub use encrypted::ranking;

// Numerical probes decrypt synthetic test ciphertexts. Evaluation builds
// exclude them; only an explicit research build enables this feature.
#[cfg(feature = "numerical-probes")]
#[path = "numerical-probes.rs"]
mod numerical_probes;
#[cfg(feature = "numerical-probes")]
mod product;
#[cfg(feature = "numerical-probes")]
pub use encrypted::probe as encrypted_probe;
#[cfg(feature = "numerical-probes")]
use numerical_probes::benchmark_phase;
#[cfg(feature = "numerical-probes")]
pub use product::probe as product_probe;

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
