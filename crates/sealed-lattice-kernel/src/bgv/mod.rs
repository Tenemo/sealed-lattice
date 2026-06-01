pub(crate) mod commands;
pub(crate) mod profile;

mod base_conversion;
mod encoding;
pub(crate) mod evaluator;
mod modular_arithmetic;
mod ntt;
mod rns;
mod serialization;
mod setup;
mod setup_helpers;
mod validation;

pub(crate) use setup::{
    encrypted_aggregate_bridge_batch_lift_bound_certificate_hash,
    encrypted_aggregate_bridge_batch_lift_bound_certificate_value,
    encrypted_aggregate_bridge_ciphertext_commitment_context,
    encrypted_aggregate_bridge_ciphertext_commitment_hash_from_context,
};

#[cfg(test)]
pub const MODULE_MARKER: &str = "bgv";
