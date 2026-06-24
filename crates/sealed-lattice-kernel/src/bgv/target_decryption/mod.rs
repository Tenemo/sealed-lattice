use std::collections::BTreeSet;
mod bindings;
mod ciphertext_codec;
mod command;
mod compact_opening;
mod development_fixture;
mod json_fields;
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
    generate_bgv_target_decryption_share_from_request,
    recombine_bgv_target_decryption_shares_from_request,
    verify_bgv_target_decryption_share_proof_statement_from_request,
};
use compact_opening::*;
pub(crate) use development_fixture::generate_bgv_target_decryption_fixture_from_request;
use json_fields::*;
use recombination::*;
use share_generation::*;
use share_records::*;
use share_statement::*;

use serde_json::{Value, json};

use crate::{
    bgv::{
        coefficient_codec::{
            coefficient_vector_from_le_hex, coefficient_vector_hash512, coefficient_vector_le_hex,
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
        modular_arithmetic::{add_mod, add_mod_fast, inverse_mod, mul_mod, mul_mod_fast},
        ntt::forward_negacyclic_ntt,
        profile::{BgvBasisKind, DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE},
        serialization::{BgvObjectKind, ciphertext_root, parse_bgv_object},
        setup::{
            COLLECTIVE_BGV_SETUP_PROFILE_ID, TARGET_DECRYPTION_PROFILE_ID,
            collective_bgv_setup_context_hashes_from_package,
            development_evaluator_key_from_passive_setup_package,
            validate_passive_setup_package_for_encrypted_evaluation,
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
const TARGET_SMUDGING_NOISE_SHARE_HASH_DOMAIN: &str =
    "sealed-lattice-bgv-rns/target-smudging-zero-share-noise-v1";
const TARGET_DECRYPTION_SMUDGING_SEED_HASH_DOMAIN: &str =
    "sealed-lattice-bgv-rns/target-decryption-smudging-seed-v1";
const TARGET_DECRYPTION_SMUDGING_ZERO_SHARE_DOMAIN: &str =
    "sealed-lattice-bgv-rns/target-decryption-smudging-zero-share-v1";
pub(super) const TARGET_DECRYPTION_SMUDGING_PROFILE_ID: &str =
    "sealed-lattice-target-decryption-zero-share-smudging-development-v1";
pub(super) const TARGET_DECRYPTION_SMUDGING_DEVELOPMENT_SCOPE: &str =
    "development-only-not-certified-for-production-use";
pub(super) const TARGET_DECRYPTION_SMUDGING_COEFFICIENT_BOUND: i64 = 16;
pub(super) const TARGET_DECRYPTION_SMUDGING_ZERO_SHARING_RULE: &str = "smudging masks are Shamir shares of zero over each active RNS prime and cancel under target-decryption Lagrange recombination";
pub(super) const TARGET_DECRYPTION_SMUDGING_CORRECTNESS_RULE: &str = "each released partial-decryption coefficient adds plaintextModulus times the local zero-share mask before recombination";
pub(super) const TARGET_DECRYPTION_SMUDGING_PROOF_BOUNDARY: &str = "development report binds mask hashes and parameters; production activation still requires a zero-knowledge proof for the released smudged share relation";
pub(super) const TARGET_DECRYPTION_SHARE_PROOF_BOUNDARY: &str = "statement binding only; production activation still requires a zero-knowledge target-decryption proof backend for restored compact openings and released smudged shares";
pub(super) const TARGET_DECRYPTION_RESTORED_WITNESS_OWNERSHIP: &str =
    "recipient-owned-restorable-local-state";
pub(super) const TARGET_DECRYPTION_ONE_SHOT_CONTEXT_RULE: &str = "one accepted target context and target ciphertext pair require one target-decryption share proof statement";
pub(super) const TARGET_DECRYPTION_RESTORED_WITNESS_RULE: &str = "the prover uses recipient-owned restored compact aggregate opening material; source credentials alone are not a target-decryption share proof witness";
pub(super) const TARGET_DECRYPTION_TARGET_BASIS_RULE: &str = "the share payload, target ciphertexts, compact aggregate openings, and accepted target record use the declared canonical target basis and active target limbs";
pub(super) const TARGET_DECRYPTION_SMUDGING_REQUIREMENT: &str = "released smudged decryption shares require zero-knowledge proof coverage before production target-decryption activation";
pub(super) const TARGET_DECRYPTION_RECOMBINATION_REQUIREMENT: &str = "target result acceptance requires denominator-cleared Lagrange recombination and decoding-margin verification before production activation";

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
    participants: Vec<ParticipantBinding>,
    threshold_verification: ThresholdVerificationBinding,
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
}

#[derive(Clone)]
struct PartialDecryptionShare {
    record: Value,
    target_id_partials: Vec<Vec<u64>>,
    target_order_partials: Vec<Vec<u64>>,
    smudging_input_report_hash: String,
    roster_position: usize,
    board_position: usize,
    interpolation_point: u64,
}

#[cfg(test)]
mod tests;
