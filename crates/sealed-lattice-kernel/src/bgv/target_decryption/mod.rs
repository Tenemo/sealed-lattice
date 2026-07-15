#[cfg(test)]
mod bindings;
mod ciphertext_codec;
#[cfg(test)]
mod command;
#[cfg(test)]
mod json_fields;
#[cfg(test)]
mod opening;
#[cfg(test)]
mod proof_material;
#[cfg(test)]
mod proof_relation;
#[cfg(test)]
mod proof_slice;
#[cfg(test)]
mod result_release;
#[cfg(test)]
mod share_generation;
#[cfg(test)]
mod share_records;
#[cfg(test)]
mod share_statement;

#[cfg(test)]
use bindings::*;
pub(crate) use ciphertext_codec::direct_target_ciphertext_hash;
#[cfg(test)]
use ciphertext_codec::*;
#[cfg(test)]
pub(crate) use command::{
    absorb_bgv_target_decryption_result_release_share_for_test,
    begin_bgv_target_decryption_result_release_for_test,
    derive_bgv_target_decryption_share_proof_statement_from_request,
    finish_bgv_target_decryption_result_release_for_test,
    generate_bgv_target_decryption_share_from_local_share_request,
    generate_bgv_target_decryption_share_proof_request_for_test,
    verify_bgv_target_decryption_share_proof_statement_binding_from_request,
};
#[cfg(test)]
use json_fields::*;
#[cfg(test)]
use opening::*;
#[cfg(test)]
use proof_material::*;
#[cfg(test)]
use proof_relation::*;
#[cfg(test)]
use proof_slice::*;
#[cfg(test)]
use result_release::*;
#[cfg(test)]
use share_generation::*;
#[cfg(test)]
use share_records::*;
#[cfg(test)]
use share_statement::*;

#[cfg(test)]
use serde_json::Value;
use serde_json::json;

use crate::{encoding::CanonicalResult, hashing::derive_canonical_object_hash};

#[cfg(test)]
use crate::{
    bgv::{
        coefficient_codec::coefficient_vector_from_le_hex,
        evaluator::{
            engine::{Ciphertext, decryption_accumulator_to_coefficients},
            records::MAXIMUM_OPTION_COUNT,
            top_k::CANONICAL_TARGET_CIPHERTEXT_LEVEL,
        },
        modular_arithmetic::{add_mod_fast, inverse_mod, mul_mod, mul_mod_fast, sub_mod},
        parameters::{BgvBasisKind, DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE},
        serialization::{BgvObjectKind, ciphertext_root, parse_bgv_object},
        setup::{
            TARGET_DECRYPTION_FLOODING_NOISE_COEFFICIENT_BOUND,
            TARGET_DECRYPTION_SHARE_PROOF_FAMILY, VssPublicAggregateThresholdCommitmentSetContext,
            accepted_setup_participant_roster_from_package,
            collective_bgv_setup_context_hashes_from_package, derive_collective_setup_package_hash,
            target_decryption_interpolation_denominator_clearing_factor,
            verify_vss_public_aggregate_threshold_commitment_set,
        },
        setup_helpers::{
            array_at_path, hash_at_path, read_non_empty_string as required_string_field,
            string_at_path, unsigned_at_path, usize_at_path, usize_field, value_at_path,
        },
    },
    encoding::{CanonicalError, CanonicalErrorCode},
    transcript_core::decode_hex,
};

#[cfg(test)]
use crate::bgv::evaluator::engine::DevelopmentBgvKey;
#[cfg(test)]
use crate::bgv::{
    coefficient_codec::coefficient_vector_le_hex,
    evaluator::{
        engine::{negacyclic_mul, signed_residue},
        prg::DeterministicSampler,
    },
};
#[cfg(test)]
use crate::hashing::hash512_hex;
#[cfg(all(test, not(target_arch = "wasm32")))]
use rayon::prelude::*;

#[cfg(test)]
const TARGET_DECRYPTION_FLOODING_NOISE_DOMAIN: &str =
    "sealed-lattice-bgv-rns/target-decryption-flooding-noise";
#[cfg(test)]
const TARGET_DECRYPTION_FLOODING_NOISE_COMMITMENT_MATERIAL_SEED_DOMAIN: &str =
    "sealed-lattice-bgv-rns/target-decryption-flooding-noise-commitment-material-seed";
#[cfg(test)]
const TARGET_DECRYPTION_FLOODING_NOISE_COMMITMENT_ROLE: &str = "target-decryption-flooding-noise";
#[cfg(test)]
const TARGET_DECRYPTION_SMUDGING_ROLES: [&str; 2] = ["targetId", "targetOrder"];

#[cfg(test)]
#[derive(Clone)]
struct TargetShareProfile {
    minimum_shares_for_interpolation: usize,
    decryption_share_quorum: usize,
}

#[cfg(test)]
#[derive(Clone)]
struct ParticipantBinding {
    trustee_identity: String,
    roster_position: usize,
}

#[cfg(test)]
impl ParticipantBinding {
    fn interpolation_point(&self) -> CanonicalResult<u64> {
        self.roster_position
            .checked_add(1)
            .and_then(|one_based_position| u64::try_from(one_based_position).ok())
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "target decryption interpolation point does not fit u64",
                )
            })
    }
}

#[cfg(test)]
#[derive(Clone)]
struct SetupBinding {
    setup_package_hash: String,
    setup_context_hash: String,
    public_matrix_seed_hash: String,
    participants: Vec<ParticipantBinding>,
    aggregate_threshold_commitment_set: AggregateThresholdCommitmentSetBinding,
}

#[cfg(test)]
#[derive(Clone)]
struct AggregateThresholdCommitmentSetBinding {
    rns_limb_count: usize,
    recipient_records: Vec<Vec<AggregateThresholdCommitmentRecordBinding>>,
}

#[cfg(test)]
#[derive(Clone)]
struct AggregateThresholdCommitmentRecordBinding {
    rns_prime: u64,
    aggregate_commitment_root: String,
    aggregate_opening_root: String,
    aggregate_commitment: Value,
}

#[cfg(test)]
#[derive(Clone)]
struct TargetAcceptedBinding {
    target_accepted_record_hash: String,
    target_ciphertext_hash: String,
}

#[cfg(test)]
#[derive(Clone)]
struct TargetCiphertextPair {
    target_id: Ciphertext,
    target_order: Ciphertext,
    target_id_root: String,
    target_order_root: String,
    target_ciphertext_hash: String,
    top_count: usize,
}

#[cfg(test)]
mod tests;
