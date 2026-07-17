use serde_json::{Value, json};

mod accepted_setup;
mod canonical_stream_transport;
mod commitment;
mod evaluation_key_share_material;
// The key-switch digit-atom machinery: the limb-group relation substrate and
// the atom-family proof backend that proves and verifies key-bearing trustee
// evaluation-key statements (the schedule layer under
// `limb_group_key_switch_atom::family_backend::schedule`).
mod limb_group_key_switch_atom;
mod private_vss;
mod private_vss_share_proof;
mod same_secret_bridge;
mod sampling;
mod setup_proof;
mod sharing;
mod source_constant_commitments;
#[cfg(test)]
mod transcript_order_audit;
mod trustee_evaluation_key_proof;
mod vss;
mod vss_commitment;

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) use accepted_setup::accepted_setup_participant_roster_from_package;
#[cfg(test)]
pub(in crate::bgv) use accepted_setup::decryption_threshold_for_participant_count;
pub(in crate::bgv) use accepted_setup::{
    decryption_threshold_for_roster_length, derive_collective_setup_package_hash,
};
pub(crate) use accepted_setup::{
    describe_collective_bgv_setup_parameters,
    describe_collective_bgv_setup_parameters_for_participant_count,
    verify_collective_bgv_setup_package_in_session_from_request,
};
#[cfg(test)]
pub(crate) use canonical_stream_transport::BGV_CANONICAL_STREAM_FAMILY_TARGET_DECRYPTION_AGGREGATE_OPENING;
#[cfg(test)]
pub(crate) use canonical_stream_transport::retain_generated_canonical_proof_material;
pub(in crate::bgv::setup) use canonical_stream_transport::{
    AcceptedSetupProofBindingSession, accepted_setup_component_material,
    accepted_setup_public_key_share_material, consume_accepted_setup_proof_binding,
    finish_accepted_setup_proof_binding_session, take_accepted_setup_proof_material_bytes,
};
#[cfg(test)]
pub(in crate::bgv::setup) use canonical_stream_transport::{
    CanonicalSetupProofBindingLease, accepted_setup_proof_binding_lease,
    restore_accepted_setup_proof_binding_lease, retain_accepted_setup_proof_binding,
};
#[cfg(test)]
pub(crate) use canonical_stream_transport::{
    TARGET_DECRYPTION_AGGREGATE_OPENING_MATERIAL_FAMILY,
    evict_authenticated_canonical_proof_materials,
};
pub(crate) use canonical_stream_transport::{
    absorb_bgv_canonical_stream_chunk, active_accepted_setup_proof_binding_session,
    begin_accepted_setup_canonical_stream, begin_accepted_setup_proof_binding_session,
    begin_bgv_canonical_material_reader, begin_bgv_canonical_stream,
    cancel_accepted_setup_proof_binding_session, cancel_bgv_canonical_material_reader,
    cancel_bgv_canonical_stream, finish_bgv_canonical_material_reader, finish_bgv_canonical_stream,
    read_bgv_canonical_material_chunk, take_authenticated_canonical_proof_material_bytes,
};
#[cfg(test)]
pub(crate) use commitment::{LatticeAnchorCommitment, lattice_anchor_commitment_canonical_bytes};
pub(crate) use commitment::{
    SETUP_COMMITMENT_HIDING_ERROR_WIDTH, SETUP_COMMITMENT_HIDING_SECRET_WIDTH,
    SETUP_COMMITMENT_MODULE_RANK, SETUP_COMMITMENT_MODULUS_LIMB_INDICES,
    compute_setup_commitment_from_typed_opening, parse_lattice_anchor_commitment_canonical_bytes,
    setup_commitment_worker_response_bytes,
};
pub(crate) use private_vss::verify_private_vss_share_envelope_from_request;

pub(crate) fn derive_succinct_setup_statement_hash_from_request(
    request: &Value,
) -> crate::encoding::CanonicalResult<Value> {
    match request.get("proofFamily").and_then(Value::as_str) {
        Some("private-vss-share") => {
            private_vss::derive_private_vss_share_statement_hash_from_request(request)
        }
        _ => Err(crate::encoding::CanonicalError::new(
            crate::encoding::CanonicalErrorCode::InvalidProtocolObject,
            "proofFamily must select a supported succinct setup statement",
        )),
    }
}
#[cfg(test)]
pub(in crate::bgv::setup) use same_secret_bridge::same_secret_bridge_proof_verification_request_from_public_records;
pub(crate) use same_secret_bridge::{
    verify_vss_same_secret_bridge_proof_material_set_request,
    verify_vss_same_secret_bridge_statement_set_request,
};
pub(crate) use setup_proof::ProofByteSource;
#[cfg(test)]
pub(crate) use setup_proof::{
    BgvProofMaterialBytes, authenticate_setup_proof_material_stream_for_test,
};
#[cfg(test)]
pub(in crate::bgv) use trustee_evaluation_key_proof::TARGET_DECRYPTION_FLOODING_NOISE_COEFFICIENT_BOUND;
#[cfg(test)]
pub(crate) use trustee_evaluation_key_proof::TARGET_DECRYPTION_SHARE_PROOF_FAMILY;
#[cfg(test)]
pub(in crate::bgv) use trustee_evaluation_key_proof::target_decryption_interpolation_denominator_clearing_factor;

pub(crate) fn verify_collective_bgv_setup_package_with_session_from_request(
    request: &Value,
    session_handle: u32,
) -> crate::encoding::CanonicalResult<Value> {
    let session = active_accepted_setup_proof_binding_session(session_handle)?;
    verify_collective_bgv_setup_package_in_session_from_request(request, session)
}

#[cfg(test)]
pub(crate) use vss_commitment::{
    VssAggregateThresholdProofContext, verify_vss_public_aggregate_threshold_proofs,
};
#[cfg(test)]
pub(crate) use vss_commitment::{
    VssCommittedMaterialCommitmentInput, VssPublicAggregateThresholdCommitmentSetContext,
    compute_vss_committed_material_commitment,
    validate_standalone_vss_committed_material_commitment,
    verify_vss_public_aggregate_threshold_commitment_set,
};
#[cfg(test)]
pub(in crate::bgv::setup) const TEST_CHECKPOINT_ROOT_ENVIRONMENT_VARIABLE: &str =
    "SEALED_LATTICE_TEST_CHECKPOINT_ROOT";

#[cfg(test)]
pub(in crate::bgv::setup) fn accepted_setup_test_checkpoint_root_directory() -> std::path::PathBuf {
    std::env::var_os(TEST_CHECKPOINT_ROOT_ENVIRONMENT_VARIABLE)
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("temp").join("test-checkpoints"))
}

#[cfg(test)]
pub(in crate::bgv::setup) fn accepted_setup_final_package_material_store_checkpoint_directory()
-> std::path::PathBuf {
    accepted_setup_test_checkpoint_root_directory()
        .join("accepted-setup-final-package-material-store")
}

use crate::{
    bgv::{
        evaluator::records::MAXIMUM_OPTION_COUNT,
        modular_arithmetic::add_mod,
        parameters::{DATA_PRIMES, POLYNOMIAL_DEGREE, bgv_parameters_hash},
        setup_helpers::{
            array_at_path, hash_at_path, string_at_path, unsigned_at_path, validate_hash_string,
            value_at_path,
        },
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::derive_canonical_object_hash,
};

#[cfg(test)]
use crate::hashing::{hash_framed_parts_512 as hash512, hash512_hex};

#[cfg(test)]
use crate::bgv::{
    modular_arithmetic::mul_mod,
    ntt::{forward_negacyclic_ntt_in_place, inverse_negacyclic_ntt_in_place},
};

// The context hashes that target-decryption commitment contexts and proof
// statements bind to. The setup-context hash canonically binds setupContext,
// including rosterHash. The setup-parameters hash is recomputed from the
// accepted roster so target decryption pins the setup identity established by
// setup acceptance.
#[cfg(test)]
pub(crate) struct CollectiveBgvSetupContextHashes {
    pub(crate) setup_context_hash: String,
    pub(crate) setup_parameters_hash: String,
}

#[cfg(test)]
pub(crate) fn collective_bgv_setup_context_hashes_from_package(
    setup_package: &Value,
) -> CanonicalResult<CollectiveBgvSetupContextHashes> {
    let roster = accepted_setup::accepted_roster_from_package(setup_package)?;

    Ok(CollectiveBgvSetupContextHashes {
        setup_context_hash: accepted_setup::setup_context_hash(value_at_path(
            setup_package,
            &["setupContext"],
        )?)?,
        setup_parameters_hash: accepted_setup::setup_parameters_hash_for_roster(&roster)?,
    })
}

// Roster-derived setupParametersHash for a configurable participant count, matching
// what collective_bgv_setup_context_hashes_from_package recomputes from an
// accepted package's setupContext.participantCount. Target-decryption test
// fixtures use it to bind an accepted SetupPackage whose setupContext agrees with
// the reader without hand-copying the derivation.
#[cfg(test)]
pub(crate) fn accepted_setup_target_decryption_setup_parameters_hash(
    participant_count: u64,
) -> CanonicalResult<String> {
    accepted_setup::setup_parameters_hash_for_roster(
        &accepted_setup::roster_parameters_from_participant_count(participant_count),
    )
}
