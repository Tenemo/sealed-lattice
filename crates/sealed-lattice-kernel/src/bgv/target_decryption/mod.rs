use std::collections::BTreeSet;
mod bindings;
mod ciphertext_codec;
mod command;
mod json_fields;
mod recombination;
mod share_generation;
mod share_records;
use bindings::*;
use ciphertext_codec::*;
pub(crate) use command::{
    generate_bgv_target_decryption_share_from_request,
    recombine_bgv_target_decryption_shares_from_request,
};
use json_fields::*;
use recombination::*;
use share_generation::*;
use share_records::*;

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
            top_k::{TIE_POLICY, packed_score_slot},
        },
        modular_arithmetic::{add_mod, add_mod_fast, inverse_mod, mul_mod, mul_mod_fast},
        ntt::forward_negacyclic_ntt,
        profile::{BgvBasisKind, DATA_PRIMES, POLYNOMIAL_DEGREE},
        serialization::{BgvObjectKind, ciphertext_root, parse_bgv_object},
        setup::{
            TARGET_DECRYPTION_PROFILE_ID, development_evaluator_key_from_passive_setup_package,
            validate_passive_setup_package_for_encrypted_evaluation,
        },
        setup_helpers::{
            array_at_path, bool_at_path, hash_at_path, reject_forbidden_setup_fields,
            string_at_path, unsigned_at_path, usize_at_path, value_at_path,
        },
        validation::reject_unexpected_bgv_request_fields,
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::derive_protocol_hash,
    transcript_core::decode_hex,
};

#[cfg(not(target_arch = "wasm32"))]
use rayon::prelude::*;

const TARGET_SHARE_PAYLOAD_ENCODING: &str =
    "coefficient-domain-u64-little-endian-partial-decryption-limbs";
const TARGET_PARTIAL_DECRYPTION_LIMB_HASH_DOMAIN: &str =
    "sealed-lattice-bgv-rns/target-partial-decryption-limb-v1";
const TARGET_SHARE_EQUATION: &str =
    "PartDec_i(C_target)=c1*s_i(x_i) over each active BGV data prime";
const SELECTED_SHARE_RULE: &str = "FirstValidSharesInCanonicalBoardOrder";

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
    roster_position: usize,
    board_position: usize,
    interpolation_point: u64,
}

#[cfg(test)]
mod tests;
