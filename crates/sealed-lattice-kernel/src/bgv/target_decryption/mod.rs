mod accepted_setup_registry;
mod bindings;
mod ciphertext_codec;
mod command;
mod json_fields;
mod opening;
mod proof_material;
mod proof_relation;
mod proof_slice;
mod result_release;
mod share_generation;
mod share_records;
mod share_statement;

use bindings::*;
pub(crate) use ciphertext_codec::direct_target_ciphertext_hash;
use ciphertext_codec::*;
pub(crate) use command::{
    absorb_bgv_target_decryption_result_release_share_from_request,
    begin_bgv_target_decryption_result_release_from_request,
    finish_bgv_target_decryption_result_release_from_request,
};
#[cfg(test)]
pub(crate) use command::{
    derive_bgv_target_decryption_share_proof_statement_from_request,
    verify_bgv_target_decryption_share_proof_statement_binding_from_request,
};
pub(crate) use command::{
    generate_bgv_target_decryption_share_from_local_share_request,
    generate_bgv_target_decryption_share_proof_material_from_local_witness_request,
};
use json_fields::*;
use opening::*;
use proof_material::*;
use proof_relation::*;
use proof_slice::*;
use result_release::*;
use share_generation::*;
use share_records::*;
use share_statement::*;

use serde_json::Value;
use serde_json::json;

use crate::{encoding::CanonicalResult, hashing::derive_canonical_object_hash};

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
            TARGET_DECRYPTION_SHARE_PROOF_FAMILY, TARGET_DECRYPTION_SMUDGING_COEFFICIENT_BOUND,
            VssPublicAggregateThresholdCommitmentSetContext,
            accepted_setup_participant_roster_from_package,
            collective_bgv_setup_context_hashes_from_package, derive_collective_setup_package_hash,
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
use crate::bgv::{
    coefficient_codec::coefficient_vector_le_hex,
    evaluator::{
        engine::{negacyclic_mul, signed_residue},
        prg::DeterministicSampler,
    },
};
use crate::hashing::hash512_hex;
#[cfg(not(target_arch = "wasm32"))]
use rayon::prelude::*;

const TARGET_DECRYPTION_SMUDGING_SEED_HASH_DOMAIN: &str =
    "sealed-lattice-bgv-rns/target-decryption-smudging-seed";
const TARGET_DECRYPTION_SMUDGING_ZERO_SHARE_DOMAIN: &str =
    "sealed-lattice-bgv-rns/target-decryption-smudging-zero-share";
const TARGET_DECRYPTION_SMUDGING_COMMITMENT_MATERIAL_SEED_DOMAIN: &str =
    "sealed-lattice-bgv-rns/target-decryption-smudging-commitment-material-seed";
const TARGET_DECRYPTION_SMUDGING_COMMITMENT_ROLE: &str =
    "target-decryption-smudging-polynomial-coefficient";
const TARGET_DECRYPTION_SMUDGING_ROLES: [&str; 2] = ["targetId", "targetOrder"];

#[derive(Clone)]
struct TargetShareProfile {
    decryption_threshold: usize,
    minimum_shares_for_interpolation: usize,
    decryption_share_quorum: usize,
}

#[derive(Clone)]
struct ParticipantBinding {
    trustee_identity: String,
    roster_position: usize,
}

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

#[derive(Clone)]
struct SetupBinding {
    setup_package_hash: String,
    ceremony_id: String,
    setup_epoch: String,
    election_manifest_hash: String,
    roster_hash: String,
    setup_parameters_hash: String,
    public_matrix_seed_hash: String,
    participants: Vec<ParticipantBinding>,
    aggregate_threshold_commitment_set: AggregateThresholdCommitmentSetBinding,
}

#[derive(Clone)]
struct AggregateThresholdCommitmentSetBinding {
    rns_limb_count: usize,
    recipient_records: Vec<Vec<AggregateThresholdCommitmentRecordBinding>>,
}

#[derive(Clone)]
struct AggregateThresholdCommitmentRecordBinding {
    rns_prime: u64,
    aggregate_commitment_root: String,
    aggregate_opening_root: String,
    #[cfg(test)]
    aggregate_commitment: Value,
}

#[derive(Clone)]
struct TargetAcceptedBinding {
    target_accepted_record_hash: String,
    target_ciphertext_hash: String,
}

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
pub(crate) use accepted_setup_registry::register_verified_target_release_setup;
use accepted_setup_registry::verified_target_release_setup_binding;
