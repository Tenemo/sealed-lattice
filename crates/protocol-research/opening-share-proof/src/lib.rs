//! Bounded public opening-share relation. Only real seed-sharing verification
//! creates a predecessor record. The selected descriptor remains a fixture
//! premise, not a reliable-broadcast or registration capability.
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(any(test, all(feature = "scalar-fixture", target_arch = "wasm32")))]
mod browser;
#[cfg(any(test, feature = "native-fixture", feature = "scalar-fixture"))]
pub mod fixture;
pub mod layout;
pub mod operator;
pub mod predecessor;
#[cfg(feature = "native-fixture")]
pub mod proof;
#[cfg(any(test, feature = "native-fixture", feature = "scalar-prover-fixture"))]
pub mod prover;
pub mod statement;
pub mod verification;
pub mod witness;

use num_bigint::{BigInt, Sign};
use supported_profile::Profile;

pub const DEGREE: usize = seed_sharing_proof::DEGREE;
pub const RECIPIENTS: usize = seed_sharing_proof::RECIPIENTS;
pub const SELECTED: usize = 2;
pub const SUPPORT: usize = supported_profile::RECIPIENT_SECRET_SUPPORT;
pub const SCALE: i128 = supported_profile::SHARE_SCALE as i128;
pub const KEY_ERROR_BITS: usize = supported_profile::SETUP_ERROR_BITS;
pub const WORD_BITS: usize = supported_profile::WORD_BITS;
pub const LIMB_BITS: usize = supported_profile::FHE_LIMB_BITS;
pub const KEY_ERROR_RADIUS: i128 = 1 << (KEY_ERROR_BITS - 1);
pub const HONEST_ERROR: i128 =
    (SUPPORT + supported_profile::SHARE_EPHEMERAL_SUPPORT + 1) as i128 * KEY_ERROR_RADIUS;
pub const RECOVERY_ERROR_BITS: usize = (i128::BITS - HONEST_ERROR.leading_zeros()) as usize + 1;
pub const ROLE: &[u8] = b"bounded-opening-share-fixture/v1";
pub type Error = &'static str;

pub fn profile() -> Profile {
    seed_sharing_proof::profile()
}
pub fn modulus() -> BigInt {
    BigInt::from_bytes_le(Sign::Plus, supported_profile::share_modulus())
}
pub fn maximum_share() -> i128 {
    1 + profile().sharing_degree() as i128 * (1i128 << (profile().sharing_coefficient_bits() - 1))
}
pub fn share_coefficient_bytes() -> usize {
    1 + ((i128::BITS - maximum_share().leading_zeros()) as usize).div_ceil(8)
}
pub(crate) fn center(value: BigInt) -> BigInt {
    let modulus = modulus();
    let positive = ((value % &modulus) + &modulus) % &modulus;
    if positive > (&modulus >> 1usize) {
        positive - modulus
    } else {
        positive
    }
}
pub(crate) fn digit(value: &BigInt, limb: usize) -> i128 {
    let bits = LIMB_BITS;
    let part = (value.magnitude() >> (limb * bits)) % (num_bigint::BigUint::from(1u8) << bits);
    let result = i128::try_from(part).unwrap();
    if value.sign() == Sign::Minus {
        -result
    } else {
        result
    }
}

#[cfg(test)]
#[path = "reference/browser.rs"]
mod browser_tests;
#[cfg(test)]
#[path = "reference/dense.rs"]
mod dense;
#[cfg(test)]
mod tests;
