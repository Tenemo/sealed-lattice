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
mod local_trustee_state;
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
mod vss_commitment;
pub(crate) use trustee_evaluation_key_proof::generate_trustee_evaluation_key_proof_from_request;
mod vss;

#[cfg(test)]
mod tests;

pub(in crate::bgv) use accepted_setup::derive_collective_setup_package_hash;
pub(crate) use accepted_setup::{
    accepted_setup_participant_roster_from_package, describe_collective_bgv_setup_parameters,
    describe_collective_bgv_setup_parameters_for_participant_count,
    verify_collective_bgv_setup_package_in_session_from_request,
};
#[cfg(test)]
pub(crate) use canonical_stream_transport::BGV_CANONICAL_STREAM_FAMILY_TARGET_DECRYPTION_AGGREGATE_OPENING;
pub(in crate::bgv::setup) use canonical_stream_transport::{
    AcceptedSetupProofBindingSession, accepted_setup_component_material,
    accepted_setup_public_key_share_material, consume_accepted_setup_proof_binding,
    finish_accepted_setup_proof_binding_session, take_accepted_setup_proof_material_bytes,
};
#[cfg(test)]
pub(in crate::bgv::setup) use canonical_stream_transport::{
    CanonicalSetupProofBindingLease, accepted_setup_proof_binding_lease,
    begin_accepted_setup_fixture_proof_binding_session,
    evict_verified_canonical_setup_proof_materials,
    finish_accepted_setup_fixture_proof_binding_session,
    restore_accepted_setup_proof_binding_lease, retain_accepted_setup_proof_binding,
    verified_canonical_setup_proof_material_bytes,
};
pub(crate) use canonical_stream_transport::{
    TARGET_DECRYPTION_AGGREGATE_OPENING_MATERIAL_FAMILY, absorb_bgv_canonical_stream_chunk,
    active_accepted_setup_proof_binding_session, begin_accepted_setup_canonical_stream,
    begin_accepted_setup_proof_binding_session, begin_bgv_canonical_material_reader,
    begin_bgv_canonical_stream, cancel_accepted_setup_proof_binding_session,
    cancel_bgv_canonical_material_reader, cancel_bgv_canonical_stream,
    evict_verified_canonical_proof_materials, finish_bgv_canonical_material_reader,
    finish_bgv_canonical_stream, read_bgv_canonical_material_chunk,
    retain_generated_canonical_proof_material, take_verified_canonical_proof_material_bytes,
};
pub(crate) use commitment::compute_setup_commitment_from_opening_request;
pub(crate) use local_trustee_state::verify_local_trustee_setup_state_from_request;
pub(crate) use private_vss::{
    generate_private_vss_share_proof_from_request, verify_private_vss_share_envelope_from_request,
};
#[cfg(test)]
pub(in crate::bgv::setup) use same_secret_bridge::{
    same_secret_bridge_proof_verification_request_from_public_records,
    verify_and_retain_same_secret_bridge_proof_binding,
};
pub(crate) use same_secret_bridge::{
    verify_vss_same_secret_bridge_proof_material_set_request,
    verify_vss_same_secret_bridge_statement_set_request,
};
pub(crate) use setup_proof::ProofByteSource;
pub(crate) use trustee_evaluation_key_proof::describe_trustee_evaluation_key_statement_from_request;
pub(crate) use trustee_evaluation_key_proof::generate_target_decryption_share_proof_bytes_from_request;
pub(crate) use trustee_evaluation_key_proof::verify_target_decryption_share_proof_source_from_request;
pub(crate) use trustee_evaluation_key_proof::{
    TARGET_DECRYPTION_SHARE_PROOF_FAMILY, TARGET_DECRYPTION_SMUDGING_COEFFICIENT_BOUND,
};

pub(crate) fn verify_collective_bgv_setup_package_with_session_from_request(
    request: &Value,
    session_handle: u32,
) -> crate::encoding::CanonicalResult<Value> {
    let session = active_accepted_setup_proof_binding_session(session_handle)?;
    let mut response =
        verify_collective_bgv_setup_package_in_session_from_request(request, session)?;
    if response.get("isValid").and_then(Value::as_bool) == Some(true) {
        let accepted_setup_handle =
            crate::bgv::target_decryption::register_verified_target_release_setup(
                &request["setupPackage"],
            )?;
        response["acceptedSetupHandle"] = Value::from(accepted_setup_handle);
    }
    Ok(response)
}
#[cfg(test)]
pub(crate) use trustee_evaluation_key_proof::verify_vss_share_linkage_proof_material_set_from_request;
pub(crate) use trustee_evaluation_key_proof::{
    generate_same_secret_bridge_proof_from_request, generate_vss_share_linkage_proof_from_request,
};
pub(crate) use vss_commitment::{
    VssAggregateThresholdProofContext, VssPublicAggregateThresholdCommitmentSetContext,
    compute_vss_committed_material_commitment_request,
    validate_standalone_vss_committed_material_commitment,
    verify_vss_public_aggregate_threshold_commitment_set,
    verify_vss_public_aggregate_threshold_proofs,
};
pub(crate) use vss_commitment::{
    VssCommittedMaterialCommitmentInput, compute_vss_committed_material_commitment,
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
            array_at_path, hash_at_path, read_non_empty_string, read_optional_u64, string_at_path,
            unsigned_at_path, usize_at_path, validate_hash_string, value_at_path,
        },
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::{derive_canonical_object_hash, hash_framed_parts_512 as hash512, hash512_hex},
};

#[cfg(test)]
use crate::bgv::{
    modular_arithmetic::mul_mod,
    ntt::{forward_negacyclic_ntt_in_place, inverse_negacyclic_ntt_in_place},
};

// The roster-derived context hashes that target-decryption commitment contexts
// and proof statements bind to. The roster hash is read from the accepted setup
// package's setupContext. The setup-parameters and Q_share hashes are the deterministic roster-derived
// identities recomputed from the accepted-setup parameter set, so a target
// decryption verified against a package pins the same setup identity the setup
// acceptance established.
pub(crate) struct CollectiveBgvSetupContextHashes {
    pub(crate) roster_hash: String,
    pub(crate) setup_parameters_hash: String,
}

pub(crate) fn collective_bgv_setup_context_hashes_from_package(
    setup_package: &Value,
) -> CanonicalResult<CollectiveBgvSetupContextHashes> {
    let roster_hash = hash_at_path(setup_package, &["setupContext", "rosterHash"])?.to_string();
    let roster = accepted_setup::accepted_roster_from_package(setup_package)?;

    Ok(CollectiveBgvSetupContextHashes {
        roster_hash,
        setup_parameters_hash: accepted_setup::setup_parameters_hash_for_roster(&roster)?,
    })
}

// Roster-derived setupParametersHash for a supported participant count, matching
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
