mod bindings;
mod ciphertext_codec;
mod command;
mod compact_opening;
mod development_fixture;
mod json_fields;
mod proof_material;
mod proof_relation;
mod proof_slice;
mod recombination;
mod share_generation;
mod share_records;
mod share_statement;
use bindings::*;
pub(crate) use ciphertext_codec::direct_target_ciphertext_hash;
use ciphertext_codec::*;
pub(crate) use command::{
    derive_bgv_target_decryption_share_proof_statement_from_request,
    generate_bgv_target_decryption_share_from_local_share_request,
    generate_bgv_target_decryption_share_proof_material_from_local_witness_request,
    generate_bgv_target_decryption_share_proof_slice_from_local_witness_request,
    verify_and_recombine_bgv_target_decryption_shares_from_request,
    verify_bgv_target_decryption_share_proof_material_from_request,
    verify_bgv_target_decryption_share_proof_statement_binding_from_request,
};
use compact_opening::*;
pub(crate) use development_fixture::generate_bgv_target_decryption_fixture_from_request;
use json_fields::*;
use proof_material::*;
use proof_relation::*;
use proof_slice::*;
use recombination::*;
use share_generation::*;
use share_records::*;
use share_statement::*;

use serde_json::{Value, json};

use crate::{
    bgv::{
        coefficient_codec::{
            coefficient_vector_from_le_hex, coefficient_vector_hash512, coefficient_vector_le_hex,
            signed_byte_vector_from_hex, signed_byte_vector_hex,
        },
        evaluator::{
            engine::{
                Ciphertext, DevelopmentBgvKey, decryption_accumulator_to_coefficients,
                negacyclic_mul, signed_residue,
            },
            prg::DeterministicSampler,
            records::MAXIMUM_OPTION_COUNT,
            top_k::{
                TIE_POLICY, canonical_target_basis_hash, packed_score_slot,
                validate_canonical_target_ciphertext,
            },
        },
        modular_arithmetic::{add_mod_fast, inverse_mod, mul_mod, mul_mod_fast, sub_mod},
        ntt::forward_negacyclic_ntt,
        profile::{BgvBasisKind, DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE},
        serialization::{BgvObjectKind, ciphertext_root, parse_bgv_object},
        setup::{
            COLLECTIVE_BGV_SETUP_PROFILE_ID, COMPACT_VSS_COMMITMENT_PROFILE_ID,
            COMPACT_VSS_OUTPUT_COORDINATE_COUNT, COMPACT_VSS_RANDOMNESS_COLUMN_COUNT,
            CompactVssCommitmentOpeningInput, TARGET_DECRYPTION_PROFILE_ID,
            TARGET_DECRYPTION_SHARE_PROOF_FAMILY, collective_bgv_setup_context_hashes_from_package,
            compute_compact_vss_commitment_from_opening,
            development_evaluator_key_from_passive_setup_package,
            validate_passive_setup_package_for_encrypted_evaluation,
            verify_compact_vss_aggregate_threshold_commitment_set_request,
        },
        setup_helpers::{
            array_at_path, hash_at_path, integer_at_path, string_at_path, unsigned_at_path,
            usize_at_path, value_at_path,
        },
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::{derive_protocol_hash, hash512_hex},
    transcript_core::decode_hex,
};

#[cfg(not(target_arch = "wasm32"))]
use rayon::prelude::*;

const TARGET_SHARE_PAYLOAD_ENCODING: &str =
    "coefficient-domain-u64-little-endian-partial-decryption-limbs";
const TARGET_PARTIAL_DECRYPTION_LIMB_HASH_DOMAIN: &str =
    "sealed-lattice-bgv-rns/target-partial-decryption-limb-v1";
const TARGET_DECRYPTION_SMUDGING_SEED_HASH_DOMAIN: &str =
    "sealed-lattice-bgv-rns/target-decryption-smudging-seed-v1";
const TARGET_DECRYPTION_SMUDGING_ZERO_SHARE_DOMAIN: &str =
    "sealed-lattice-bgv-rns/target-decryption-smudging-zero-share-v1";
const TARGET_DECRYPTION_SMUDGING_COMMITMENT_RANDOMNESS_DOMAIN: &str =
    "sealed-lattice-bgv-rns/target-decryption-smudging-commitment-randomness-v1";
const TARGET_DECRYPTION_SHARE_PROOF_BYTES_HASH_DOMAIN: &str =
    "sealed-lattice-bgv-rns/target-decryption-share-proof-bytes-v1";
pub(super) const TARGET_DECRYPTION_SMUDGING_PROFILE_ID: &str =
    "sealed-lattice-target-decryption-zero-share-smudging-development-v1";
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

struct ParticipantBinding {
    trustee_identity: String,
    roster_position: usize,
    board_position: usize,
    interpolation_point: u64,
    recovery_epoch: u64,
    device_epoch: u64,
    trustee_threshold_verification_key_hash: String,
}

struct ThresholdVerificationBinding {
    threshold_share_verification_key_root: String,
    threshold_share_verification_key_hash: String,
}

struct SetupBinding {
    setup_package_hash: String,
    ceremony_id: String,
    election_manifest_hash: String,
    roster_hash: String,
    setup_profile_hash: String,
    q_share_hash: String,
    carry_aware_vss_share_relation_profile_hash: String,
    commitment_profile_hash: String,
    threshold_profile_hash: String,
    target_decryption_profile_hash: String,
    target_decryption_profile_binding_hash: String,
    public_matrix_seed_hash: String,
    compact_share_linkage_statement_root: Option<String>,
    participants: Vec<ParticipantBinding>,
    threshold_verification: ThresholdVerificationBinding,
    compact_aggregate_threshold_commitment_set:
        Option<CompactAggregateThresholdCommitmentSetBinding>,
}

struct CompactAggregateThresholdCommitmentSetBinding {
    aggregate_threshold_commitment_root: String,
    rns_limb_count: usize,
    recipient_records: Vec<Vec<CompactAggregateThresholdCommitmentRecordBinding>>,
}

struct CompactAggregateThresholdCommitmentRecordBinding {
    rns_prime: u64,
    aggregate_commitment_root: String,
    aggregate_commitment: Value,
}

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

struct TargetCiphertextPair {
    target_id: Ciphertext,
    target_order: Ciphertext,
    target_id_root: String,
    target_order_root: String,
    target_ciphertext_hash: String,
    target_ciphertext_binding_hash: String,
    top_count: usize,
}

#[cfg(test)]
mod tests;
