mod bindings;
mod ciphertext_codec;
mod command;
mod json_fields;
#[cfg(any(feature = "target-decryption-development-commands", test))]
mod opening;
mod proof_material;
#[cfg(any(feature = "target-decryption-development-commands", test))]
mod proof_relation;
mod proof_slice;
mod result_release;
#[cfg(any(feature = "target-decryption-development-commands", test))]
mod share_generation;
mod share_records;
mod share_statement;

use bindings::*;
pub(crate) use ciphertext_codec::direct_target_ciphertext_hash;
use ciphertext_codec::*;
pub(crate) use command::{
    absorb_bgv_target_decryption_result_release_share_from_request,
    begin_bgv_target_decryption_result_release_from_request,
    derive_bgv_target_decryption_result_release_setup_context_from_request,
    finish_bgv_target_decryption_result_release_from_request,
};
#[cfg(any(feature = "target-decryption-development-commands", test))]
pub(crate) use command::{
    derive_bgv_target_decryption_share_proof_statement_from_request,
    generate_bgv_target_decryption_share_from_local_share_request,
    generate_bgv_target_decryption_share_proof_material_from_local_witness_request,
    verify_bgv_target_decryption_share_proof_material_from_request,
    verify_bgv_target_decryption_share_proof_statement_binding_from_request,
};
use json_fields::*;
#[cfg(any(feature = "target-decryption-development-commands", test))]
use opening::*;
use proof_material::*;
#[cfg(any(feature = "target-decryption-development-commands", test))]
use proof_relation::*;
use proof_slice::*;
use result_release::*;
#[cfg(any(feature = "target-decryption-development-commands", test))]
use share_generation::*;
use share_records::*;
use share_statement::*;

use serde_json::Value;
use serde_json::json;

use crate::{
    bgv::evaluator::top_k::TIE_POLICY, encoding::CanonicalResult,
    hashing::derive_canonical_object_hash,
};

use crate::{
    bgv::{
        coefficient_codec::{coefficient_vector_from_le_hex, coefficient_vector_hash512},
        evaluator::{
            engine::{Ciphertext, decryption_accumulator_to_coefficients},
            records::MAXIMUM_OPTION_COUNT,
            top_k::{canonical_target_basis_hash, packed_score_slot},
        },
        modular_arithmetic::{add_mod_fast, inverse_mod, mul_mod, mul_mod_fast, sub_mod},
        ntt::forward_negacyclic_ntt,
        parameters::{BgvBasisKind, DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE},
        serialization::{BgvObjectKind, ciphertext_root, parse_bgv_object},
        setup::{
            TARGET_DECRYPTION_SHARE_PROOF_FAMILY, accepted_setup_participant_roster_from_package,
            canonical_target_decryption_parameter_hashes,
            collective_bgv_setup_context_hashes_from_package,
            verify_vss_public_aggregate_threshold_commitment_set_request,
        },
        setup_helpers::{
            array_at_path, hash_at_path, integer_at_path, string_at_path, unsigned_at_path,
            usize_at_path, value_at_path,
        },
    },
    encoding::{CanonicalError, CanonicalErrorCode},
    transcript_core::{decode_hex, decode_standard_base64},
};

#[cfg(any(feature = "target-decryption-development-commands", test))]
use crate::bgv::coefficient_codec::{signed_byte_vector_from_hex, signed_byte_vector_hex};
#[cfg(any(feature = "target-decryption-development-commands", test))]
use crate::bgv::setup::development_evaluator_key_from_passive_setup_package;
use crate::bgv::setup::{VSS_PUBLIC_OUTPUT_COORDINATE_COUNT, VSS_PUBLIC_RANDOMNESS_COLUMN_COUNT};
#[cfg(any(feature = "target-decryption-development-commands", test))]
use crate::bgv::setup::{
    VssPublicCommitmentOpeningInput, compute_vss_public_commitment_from_opening,
};
#[cfg(any(feature = "target-decryption-development-commands", test))]
use crate::bgv::{
    coefficient_codec::coefficient_vector_le_hex,
    evaluator::{
        engine::{DevelopmentBgvKey, negacyclic_mul, signed_residue},
        prg::DeterministicSampler,
    },
};
#[cfg(any(feature = "target-decryption-development-commands", test))]
use crate::hashing::hash512_hex;
#[cfg(any(feature = "target-decryption-development-commands", test))]
use crate::transcript_core::encode_standard_base64;

#[cfg(all(
    not(target_arch = "wasm32"),
    any(feature = "target-decryption-development-commands", test)
))]
use rayon::prelude::*;

const TARGET_SHARE_PAYLOAD_ENCODING: &str =
    "coefficient-domain-u64-little-endian-partial-decryption-limbs";
const TARGET_PARTIAL_DECRYPTION_LIMB_HASH_DOMAIN: &str =
    "sealed-lattice-bgv-rns/target-partial-decryption-limb-v1";
#[cfg(any(feature = "target-decryption-development-commands", test))]
const TARGET_DECRYPTION_SMUDGING_SEED_HASH_DOMAIN: &str =
    "sealed-lattice-bgv-rns/target-decryption-smudging-seed-v1";
#[cfg(any(feature = "target-decryption-development-commands", test))]
const TARGET_DECRYPTION_SMUDGING_ZERO_SHARE_DOMAIN: &str =
    "sealed-lattice-bgv-rns/target-decryption-smudging-zero-share-v1";
#[cfg(any(feature = "target-decryption-development-commands", test))]
const TARGET_DECRYPTION_SMUDGING_COMMITMENT_RANDOMNESS_DOMAIN: &str =
    "sealed-lattice-bgv-rns/target-decryption-smudging-commitment-randomness-v1";
pub(super) const TARGET_DECRYPTION_SMUDGING_COEFFICIENT_BOUND: i64 = 16;
const TARGET_DECRYPTION_SMUDGING_COMMITMENT_ROLE: &str =
    "target-decryption-smudging-polynomial-coefficient";
const TARGET_DECRYPTION_SMUDGING_ROLES: [&str; 2] = ["targetId", "targetOrder"];

#[derive(Clone)]
struct TargetShareProfile {
    decryption_threshold: usize,
    minimum_shares_for_interpolation: usize,
    decryption_share_quorum: usize,
    hash: String,
}

#[derive(Clone)]
struct ParticipantBinding {
    trustee_identity: String,
    roster_position: usize,
    board_position: usize,
    interpolation_point: u64,
    recovery_epoch: u64,
    device_epoch: u64,
}

#[derive(Clone)]
struct SetupBinding {
    setup_package_hash: String,
    ceremony_id: String,
    election_manifest_hash: String,
    roster_hash: String,
    setup_parameters_hash: String,
    target_decryption_profile_hash: String,
    target_decryption_profile_binding_hash: String,
    public_matrix_seed_hash: String,
    share_linkage_statement_root: Option<String>,
    participants: Vec<ParticipantBinding>,
    aggregate_threshold_commitment_set: Option<AggregateThresholdCommitmentSetBinding>,
}

#[derive(Clone)]
struct AggregateThresholdCommitmentSetBinding {
    aggregate_threshold_commitment_root: String,
    rns_limb_count: usize,
    recipient_records: Vec<Vec<AggregateThresholdCommitmentRecordBinding>>,
}

#[derive(Clone)]
struct AggregateThresholdCommitmentRecordBinding {
    rns_prime: u64,
    aggregate_commitment_root: String,
    aggregate_opening_root: String,
    aggregate_commitment: Value,
    source_share_commitment_roots: Vec<String>,
    source_share_opening_roots: Vec<String>,
}

#[derive(Clone)]
struct TargetAcceptedBinding {
    target_accepted_record_hash: String,
    target_proposal_hash: String,
    target_preimage_hash: String,
    target_finality_record_hash: String,
    target_finality_checkpoint_hash: String,
    evaluator_replay_record_hash: String,
    target_context_hash: String,
    target_ciphertext_hash: String,
    target_layout_hash: String,
    target_decryption_profile_hash: String,
    target_basis_hash: String,
}

#[derive(Clone)]
struct TargetCiphertextPair {
    target_id: Ciphertext,
    target_order: Ciphertext,
    target_id_root: String,
    target_order_root: String,
    target_ciphertext_hash: String,
    target_ciphertext_binding_hash: String,
    top_count: usize,
}

fn aggregate_message_coefficient_bound(
    rns_prime: u64,
    participant_count: usize,
) -> CanonicalResult<u64> {
    if participant_count == 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "compact aggregate opening participant count must be positive",
        ));
    }
    rns_prime
        .checked_mul(u64::try_from(participant_count).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "compact aggregate opening participant count does not fit u64",
            )
        })?)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "compact aggregate opening message coefficient bound overflowed",
            )
        })
}

#[cfg(test)]
mod tests;
