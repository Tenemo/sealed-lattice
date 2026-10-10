// The numerical probes decrypt synthetic test ciphertexts and never reach
// the participant module.
#[cfg(all(feature = "numerical-probes", target_arch = "wasm32"))]
compile_error!("The numerical-probes feature decrypts test ciphertexts and never builds for Wasm.");

mod encrypted;
pub use encrypted::{JOBS, ranking};

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

/// The largest prime `odd * 2^32 + 1` of the bit length below the limit,
/// certified by Proth's theorem with witness three.
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
