mod authority;
mod canonical_package;
mod canonical_package_builder;
mod collective_and_relinearization_verification_population;
mod evaluator_source;
mod finalization;
mod generation_authority;
mod generation_population;
mod generation_relinearization;
mod prepackage_evaluator_source_catalog;
mod setup_parameters;
mod verification_assembly;
mod verification_population;
mod verified_public_proof_catalog;
mod verified_public_randomness;
mod verified_terminals;
mod vss_qualification;

pub(in crate::bgv) use self::verified_public_randomness::{
    VerifiedPublicRandomness, verify_public_randomness_board_sources,
};
pub(in crate::bgv) use self::verified_terminals::{
    VerifiedAggregateThresholdShareTerminal, VerifiedVssQualificationTerminals,
    VerifiedVssShareLinkageTerminal, derive_recipient_input_root,
};

pub(in crate::bgv) use self::authority::{
    BrowserOwnedAggregateThresholdShareLimb, VerifiedAcceptedSetupAuthority,
    VerifiedAcceptedSetupAuthorityHandle, VerifiedAcceptedSetupParticipantTargetReleaseLease,
    VerifiedEvaluatorCommonComponentAuthority, VerifiedEvaluatorExecutionAuthority,
    lease_verified_participant_target_release_source, take_verified_evaluator_execution_authority,
    with_verified_accepted_setup_authority, with_verified_participant_target_release_source,
};
pub(in crate::bgv) use self::canonical_package::CanonicalAcceptedSetupPackage;
pub(crate) use self::canonical_package_builder::{
    CanonicalPackageStreamKind, add_generated_proof_source_to_accepted_setup_package_builder,
    contribute_generated_canonical_package_proof_and_stream_source,
};
pub(crate) use self::collective_and_relinearization_verification_population::{
    cancel_collective_public_key_verification_terminal_source_reservation,
    commit_reserved_collective_public_key_verification_terminal_source,
    reserve_collective_public_key_verification_terminal_source,
    retain_relinearization_round_one_aggregate_verification_terminal_source,
    retain_relinearization_round_one_verification_terminal_source,
    retain_relinearization_round_two_verification_terminal_source,
};
pub(in crate::bgv) use self::evaluator_source::VerifiedAcceptedSetupEvaluatorSourceCatalog;
#[cfg(all(test, not(target_arch = "wasm32")))]
pub(crate) use self::generation_authority::PreparedExactSameSecretGenerationSources;
pub(in crate::bgv) use self::generation_authority::{
    SetupGaloisGenerationPreparationError, SetupGeneratedCommittedMaterial,
    SetupGeneratedGaloisEntry, SetupGeneratedGaloisSourceAuthority,
    SetupGeneratedGaloisSourceComponent, SetupGeneratedKeySwitchComponent,
    SetupGenerationAnchorOpening, SetupGenerationAuthorityHandle, SetupGenerationGaloisApplication,
    SetupGenerationGaloisBatchSource, SetupGenerationGaloisPreparationSource,
    SetupGenerationKeyRelationApplication, SetupGenerationKeyRelationPreparationSource,
    SetupGenerationKeyRelationSource, SetupGenerationPublicKeyShareSourceHandle,
    SetupGenerationRecipientPayloadSourceHandle, SetupGenerationRelinearizationRoundOneApplication,
    SetupGenerationRelinearizationRoundOneSource, SetupGenerationRelinearizationRoundTwoActivation,
    SetupGenerationRelinearizationRoundTwoApplication,
    SetupGenerationRelinearizationRoundTwoPreparationSource,
    SetupGenerationRelinearizationRoundTwoSource, SetupGenerationVssApplication,
    SetupGenerationVssPreparationSource, SetupKeyRelationGenerationPreparationError,
    SetupKeyRelationProofFamily, SetupRelinearizationGenerationPreparationError,
    SetupVssGenerationPreparationError,
    absorb_setup_generation_relinearization_round_two_activation_pair,
    begin_setup_generation_relinearization_round_two_activation,
    cancel_setup_generation_public_key_share_body, cancel_setup_generation_recipient_vss_payload,
    finish_setup_generation_relinearization_round_two_activation,
    open_setup_generation_public_key_share_body, open_setup_generation_recipient_vss_payload,
    read_setup_generation_public_key_share_body, read_setup_generation_recipient_vss_payload_chunk,
    release_setup_generation_authority,
    resolve_setup_generated_relinearization_round_one_source_authority,
    resolve_setup_generated_relinearization_round_two_source_authority,
    resolve_setup_generation_galois_preparation_source,
    resolve_setup_generation_key_relation_preparation_source,
    resolve_setup_generation_relinearization_round_one_preparation_source,
    resolve_setup_generation_relinearization_round_two_preparation_source,
    resolve_setup_generation_vss_preparation_source,
    setup_generation_public_key_share_body_byte_length,
    setup_generation_public_key_share_source_byte_length,
    setup_generation_recipient_vss_payload_byte_length,
    setup_generation_recipient_vss_payload_source_byte_length,
    setup_generation_recipient_vss_payload_source_recipient_roster_position,
    setup_generation_retained_memory_accounting, with_setup_generation_galois_batch,
    with_setup_generation_galois_public_component_chunk, with_setup_generation_key_relation,
    with_setup_generation_relinearization_round_one,
    with_setup_generation_relinearization_round_one_component_chunk,
    with_setup_generation_relinearization_round_two,
    with_setup_generation_relinearization_round_two_component_chunk,
    with_setup_generation_relinearization_round_two_witness, with_setup_generation_vss_material,
};
pub(crate) use self::generation_authority::{
    SetupGenerationDealerPublicRecordSource, resolve_setup_generation_dealer_public_record_source,
};
pub(in crate::bgv) use self::generation_population::populate_browser_owned_setup_generation_authority;
#[cfg(all(test, not(target_arch = "wasm32")))]
pub(crate) use self::generation_population::populate_exact_same_secret_evidence_authority;
pub(in crate::bgv) use self::generation_relinearization::{
    SetupGeneratedRelinearizationAggregateSourceAuthority,
    SetupGeneratedRelinearizationComponentSource,
    SetupGeneratedRelinearizationRoundOneSourceAuthority,
    SetupGenerationRelinearizationRoundOnePreparationSource,
    SetupRelinearizationAggregateConstruction, SetupRelinearizationAggregateSourceReadRequest,
    construct_generated_relinearization_aggregate,
};
pub(crate) use self::prepackage_evaluator_source_catalog::{
    accepted_package_statement_source, commit_prepackage_galois_source,
    commit_prepackage_generated_evaluator_proof, commit_prepackage_generated_galois_source,
    commit_prepackage_generated_relinearization_aggregate,
    commit_prepackage_generated_relinearization_round_one_source,
    commit_prepackage_generated_relinearization_round_two_source,
    preflight_prepackage_galois_source_slot, preflight_prepackage_generated_evaluator_proof_slot,
    preflight_prepackage_generated_galois_source_slot,
    preflight_prepackage_generated_relinearization_aggregate_slot,
    preflight_prepackage_generated_relinearization_round_one_source_slot,
    preflight_prepackage_generated_relinearization_round_two_source_slot,
    restore_prepackage_evaluator_statement_source, restore_prepackage_galois_statement_source,
    take_prepackage_evaluator_statement_source, take_prepackage_galois_statement_source,
    with_completed_prepackage_evaluator_source_catalog,
    with_prepackage_evaluator_generation_sources, with_prepackage_generated_galois_source,
    with_prepackage_generated_relinearization_aggregate,
    with_prepackage_generated_relinearization_round_one_sources,
    with_prepackage_relinearization_source,
};
pub(crate) use self::verification_assembly::{
    commit_preflighted_verified_evaluator_key_store,
    commit_preflighted_verified_public_key_share_terminal,
    commit_preflighted_verified_same_secret_terminal, preflight_verified_evaluator_key_store_slot,
    preflight_verified_public_key_share_terminal_slot,
    preflight_verified_same_secret_terminal_slot, with_accepted_setup_verification_sources,
};
pub(in crate::bgv) use self::vss_qualification::VerifiedAcceptedSetupVssQualification;

use crate::{
    bgv::{
        evaluator::records::MAXIMUM_OPTION_COUNT,
        parameters::{bgv_parameters_hash, canonical_bgv_parameter_integer_decimal_string},
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    foundation::{
        FOUNDATION_PROFILE, FoundationRosterParameters, derive_foundation_roster_parameters,
        selected_sharing_data_prime_coordinates,
    },
    hashing::derive_canonical_object_hash,
};
use serde_json::{Value, json};

#[derive(Clone, Copy)]
pub(super) struct AcceptedRosterParameters {
    pub(super) participant_count: u64,
    pub(super) decryption_threshold: u64,
}

fn configurable_foundation_roster_parameters(
    participant_count: u64,
) -> Option<FoundationRosterParameters> {
    u16::try_from(participant_count)
        .ok()
        .and_then(derive_foundation_roster_parameters)
}

pub(super) fn participant_count_is_configurable(participant_count: u64) -> bool {
    configurable_foundation_roster_parameters(participant_count).is_some()
}

fn roster_parameters_from_participant_count(participant_count: u64) -> AcceptedRosterParameters {
    let roster = configurable_foundation_roster_parameters(participant_count)
        .expect("participant count must be configurable");
    AcceptedRosterParameters {
        participant_count: u64::from(roster.participant_count),
        decryption_threshold: u64::from(roster.reconstruction_threshold),
    }
}

fn foundation_roster_parameters() -> AcceptedRosterParameters {
    AcceptedRosterParameters {
        participant_count: u64::from(FOUNDATION_PROFILE.participant_count),
        decryption_threshold: u64::from(FOUNDATION_PROFILE.reconstruction_threshold),
    }
}

pub(crate) fn describe_collective_bgv_setup_parameters() -> CanonicalResult<Value> {
    describe_collective_bgv_setup_parameters_for_roster(&foundation_roster_parameters())
}

fn describe_collective_bgv_setup_parameters_for_roster(
    roster: &AcceptedRosterParameters,
) -> CanonicalResult<Value> {
    let sharing_prime_decimal_strings = selected_sharing_data_prime_coordinates()
        .map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "selected sharing coordinates are invalid",
            )
        })?
        .iter()
        .map(|(_, modulus)| canonical_bgv_parameter_integer_decimal_string(*modulus))
        .collect::<Vec<_>>();
    Ok(json!({
        "setupParametersHash": setup_parameters::setup_parameters_hash_for_roster(roster)?,
        "participantCount": roster.participant_count,
        "reconstructionThreshold": roster.decryption_threshold,
        "qShare": {
            "primes": sharing_prime_decimal_strings,
        },
        "evaluatorKeySchedule": setup_parameters::evaluator_key_schedule_value()?,
        "boundedDomainEvaluator": setup_parameters::bounded_domain_evaluator_value_for_roster(roster)?,
    }))
}

pub(crate) fn describe_collective_bgv_setup_parameters_for_participant_count(
    participant_count: u64,
) -> CanonicalResult<Value> {
    if !participant_count_is_configurable(participant_count) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "participantCount must be an integer from 3 through 20",
        ));
    }
    describe_collective_bgv_setup_parameters_for_roster(&roster_parameters_from_participant_count(
        participant_count,
    ))
}
