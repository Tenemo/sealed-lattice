use super::*;
use crate::bgv::evaluator::{
    key_switch::{KEY_SWITCH_ERROR_DOMAIN, KEY_SWITCH_SAMPLE_DOMAIN},
    prg::DeterministicSampler,
    records::MAXIMUM_OPTION_COUNT,
    top_k::{
        DIRECT_COMPARISON_OUTPUT_LEVEL, SELECTED_EVALUATOR_WORKING_LEVEL,
        direct_score_packing_basis_galois_elements, packed_rank_forward_basis_galois_elements,
        packed_rank_return_basis_galois_elements,
    },
};
use crate::bgv::setup::sampling::{
    bounded_collective_error_share_coefficient, bounded_collective_secret_share_coefficient,
};

#[cfg(not(target_arch = "wasm32"))]
use rayon::prelude::*;
mod collective_key_material;
mod evaluation_binding;
mod evaluation_stream;
mod public_evaluation_keys;
mod relation_checks;
mod rotation_schedule;
mod threshold_verification;
pub(super) use collective_key_material::*;
pub(super) use evaluation_binding::*;
pub(super) use evaluation_stream::*;
pub(super) use public_evaluation_keys::*;
use relation_checks::*;
use rotation_schedule::*;
pub(super) use threshold_verification::*;

const DECRYPTABLE_PUBLIC_KEY_COMPONENT_MODEL: &str =
    "componentZero=sum_i(-a*s_i+p*e_i),componentOne=a-over-selected-BGV-RNS-data-basis";
const EVALUATION_KEY_STREAM_POLICY: &str =
    "sealed-lattice-deterministic-bgv-key-switch-material-stream-v1";

pub(super) struct CollectivePublicKeyCoefficients {
    pub(super) component_zero_coefficients: Vec<u64>,
    pub(super) component_one_coefficients: Vec<u64>,
}

struct EvaluationKeyMaterialBinding {
    record: Value,
    material_hash: String,
    relinearization_key_root: String,
    relinearization_key_record: Value,
    key_switch_key_root: String,
    key_switch_key_record: Value,
    rotation_key_roots: Vec<Value>,
    rotation_key_records: Vec<Value>,
}

struct RotationScheduleEntry {
    rotation: usize,
    level: usize,
    purpose: &'static str,
}

struct EvaluationKeyMaterialInput<'a> {
    setup_seed_hash: &'a str,
    sampled_relation_checks: Value,
    ceremony_id: &'a str,
    manifest_hash: &'a str,
    roster_hash: &'a str,
    collective_public_key: &'a Value,
    key_switch_decomposition_hash: &'a str,
    rot_set: &'a Value,
    rot_set_hash: &'a str,
}
