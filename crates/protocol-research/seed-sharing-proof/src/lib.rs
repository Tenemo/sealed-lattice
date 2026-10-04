//! Bounded outer seed-sharing relation experiment. The arithmetic ring has
//! degree 256; the common word engine still has its full proof domain. This
//! module supplies no setup capability or distributed recovery protocol.
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(any(test, all(feature = "scalar-fixture", target_arch = "wasm32")))]
mod browser;
#[cfg(any(test, feature = "fixture"))]
pub mod fixture;
pub mod layout;
pub mod operator;
#[cfg(feature = "native-fixture")]
pub mod proof;
#[cfg(any(test, feature = "native-fixture", feature = "scalar-prover-fixture"))]
pub mod prover;
#[cfg(any(test, all(feature = "scalar-prover-fixture", target_arch = "wasm32")))]
#[path = "prover-browser.rs"]
mod prover_browser;
pub mod statement;
#[cfg(any(test, feature = "fixture"))]
pub mod verification;
pub mod witness;

use num_bigint::{BigInt, Sign};
use supported_profile::Profile;

pub const DEGREE: usize = 256;
pub const RECIPIENTS: usize = 4;
pub const SEED_BITS: usize = 4;
pub const SUPPORT: usize = supported_profile::SHARE_EPHEMERAL_SUPPORT;
pub const SCALE: i128 = supported_profile::SHARE_SCALE as i128;
pub type Error = &'static str;

pub fn profile() -> Profile {
    Profile::new(RECIPIENTS, 2).unwrap()
}
pub fn modulus() -> BigInt {
    BigInt::from_bytes_le(Sign::Plus, supported_profile::share_modulus())
}
pub fn center(value: BigInt) -> BigInt {
    let modulus = modulus();
    let positive = ((value % &modulus) + &modulus) % &modulus;
    if positive > (&modulus >> 1usize) {
        positive - modulus
    } else {
        positive
    }
}
pub(crate) fn digit(value: &BigInt, limb: usize) -> i128 {
    let magnitude = value.magnitude();
    let bits = profile().share_limb_bits();
    let part = (magnitude >> (limb * bits)) % (num_bigint::BigUint::from(1u8) << bits);
    let result = i128::try_from(part).unwrap();
    if value.sign() == Sign::Minus {
        -result
    } else {
        result
    }
}
pub(crate) fn rotation(recipient: usize, output: usize) -> (usize, i128) {
    rotation_for_degree(DEGREE, recipient, output)
}
pub(crate) fn rotation_for_degree(degree: usize, recipient: usize, output: usize) -> (usize, i128) {
    let exponent = recipient * (degree / profile().interpolation_degree());
    let source = (output + 2 * degree - exponent) % degree;
    let signed_exponent = source + exponent;
    (
        source,
        if (signed_exponent / degree).is_multiple_of(2) {
            1
        } else {
            -1
        },
    )
}

#[cfg(test)]
#[path = "reference/dense.rs"]
mod dense;
#[cfg(test)]
mod tests;
