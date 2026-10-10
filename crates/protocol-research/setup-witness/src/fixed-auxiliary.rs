//! The suite's public auxiliary encryption pair. Neither coordinate depends
//! on a poll, roster or contributor, and no participant holds its secret key.

use crate::{
    common_polynomial::{public_polynomial, public_records},
    integer,
};
use num_bigint::BigInt;
use supported_profile::{AUXILIARY_DEGREE, auxiliary_modulus, fixed_common_sample_bits};

fn polynomial(label: &str) -> Vec<BigInt> {
    public_polynomial(
        label,
        AUXILIARY_DEGREE,
        &integer(auxiliary_modulus()),
        fixed_common_sample_bits(),
    )
}

fn records(label: &str) -> Vec<u8> {
    public_records(
        label,
        AUXILIARY_DEGREE,
        auxiliary_modulus(),
        fixed_common_sample_bits(),
    )
}

pub fn common_polynomial() -> Vec<BigInt> {
    polynomial("common-auxiliary")
}

pub fn public_key() -> Vec<BigInt> {
    polynomial("common-auxiliary-key")
}

pub fn common_records() -> Vec<u8> {
    records("common-auxiliary")
}

pub fn public_key_records() -> Vec<u8> {
    records("common-auxiliary-key")
}

#[cfg(test)]
#[path = "fixed-auxiliary-tests.rs"]
mod tests;
