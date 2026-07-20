mod accepted_setup;
mod commitment;
mod sampling;
#[cfg(test)]
mod sharing;
#[cfg(test)]
mod vss;

#[cfg(test)]
mod tests;

pub(in crate::bgv) use accepted_setup::{
    BrowserOwnedAggregateThresholdShareLimb, CanonicalAcceptedSetupPackage,
    CanonicalPackageStreamKind, SetupGaloisGenerationPreparationError,
    SetupGeneratedCommittedMaterial, SetupGeneratedGaloisEntry,
    SetupGeneratedGaloisSourceAuthority, SetupGeneratedGaloisSourceComponent,
    SetupGeneratedKeySwitchComponent, SetupGeneratedRelinearizationAggregateSourceAuthority,
    SetupGeneratedRelinearizationComponentSource,
    SetupGeneratedRelinearizationRoundOneSourceAuthority, SetupGenerationAnchorOpening,
    SetupGenerationAuthorityHandle, SetupGenerationGaloisApplication,
    SetupGenerationGaloisBatchSource, SetupGenerationGaloisPreparationSource,
    SetupGenerationKeyRelationApplication, SetupGenerationKeyRelationPreparationSource,
    SetupGenerationKeyRelationSource, SetupGenerationPublicKeyShareSourceHandle,
    SetupGenerationRecipientPayloadSourceHandle, SetupGenerationRelinearizationRoundOneApplication,
    SetupGenerationRelinearizationRoundOnePreparationSource,
    SetupGenerationRelinearizationRoundOneSource, SetupGenerationRelinearizationRoundTwoActivation,
    SetupGenerationRelinearizationRoundTwoApplication,
    SetupGenerationRelinearizationRoundTwoPreparationSource,
    SetupGenerationRelinearizationRoundTwoSource, SetupGenerationVssApplication,
    SetupGenerationVssPreparationSource, SetupKeyRelationGenerationPreparationError,
    SetupKeyRelationProofFamily, SetupRelinearizationAggregateConstruction,
    SetupRelinearizationAggregateSourceReadRequest, SetupRelinearizationGenerationPreparationError,
    SetupVssGenerationPreparationError, VerifiedAcceptedSetupAuthority,
    VerifiedAcceptedSetupAuthorityHandle, VerifiedAcceptedSetupEvaluatorSourceCatalog,
    VerifiedAcceptedSetupParticipantTargetReleaseLease, VerifiedAcceptedSetupVssQualification,
    VerifiedEvaluatorCommonComponentAuthority, VerifiedEvaluatorExecutionAuthority,
    absorb_setup_generation_relinearization_round_two_activation_pair,
    accepted_package_statement_source,
    add_generated_proof_source_to_accepted_setup_package_builder,
    begin_setup_generation_relinearization_round_two_activation,
    cancel_collective_public_key_verification_terminal_source_reservation,
    cancel_setup_generation_public_key_share_body, cancel_setup_generation_recipient_vss_payload,
    commit_preflighted_verified_evaluator_key_store, commit_prepackage_galois_source,
    commit_prepackage_generated_evaluator_proof, commit_prepackage_generated_galois_source,
    commit_prepackage_generated_relinearization_aggregate,
    commit_prepackage_generated_relinearization_round_one_source,
    commit_prepackage_generated_relinearization_round_two_source,
    commit_reserved_collective_public_key_verification_terminal_source,
    construct_generated_relinearization_aggregate,
    contribute_generated_canonical_package_proof_and_stream_source,
    describe_collective_bgv_setup_parameters,
    describe_collective_bgv_setup_parameters_for_participant_count,
    finish_setup_generation_relinearization_round_two_activation,
    lease_verified_participant_target_release_source, open_setup_generation_public_key_share_body,
    open_setup_generation_recipient_vss_payload, populate_browser_owned_setup_generation_authority,
    preflight_prepackage_galois_source_slot, preflight_prepackage_generated_evaluator_proof_slot,
    preflight_prepackage_generated_galois_source_slot,
    preflight_prepackage_generated_relinearization_aggregate_slot,
    preflight_prepackage_generated_relinearization_round_one_source_slot,
    preflight_prepackage_generated_relinearization_round_two_source_slot,
    preflight_verified_evaluator_key_store_slot, read_setup_generation_public_key_share_body,
    read_setup_generation_recipient_vss_payload_chunk, release_setup_generation_authority,
    reserve_collective_public_key_verification_terminal_source,
    resolve_setup_generated_relinearization_round_one_source_authority,
    resolve_setup_generated_relinearization_round_two_source_authority,
    resolve_setup_generation_galois_preparation_source,
    resolve_setup_generation_key_relation_preparation_source,
    resolve_setup_generation_relinearization_round_one_preparation_source,
    resolve_setup_generation_relinearization_round_two_preparation_source,
    resolve_setup_generation_vss_preparation_source, restore_prepackage_evaluator_statement_source,
    restore_prepackage_galois_statement_source,
    retain_relinearization_round_one_aggregate_verification_terminal_source,
    retain_relinearization_round_one_verification_terminal_source,
    retain_relinearization_round_two_verification_terminal_source,
    setup_generation_public_key_share_body_byte_length,
    setup_generation_public_key_share_source_byte_length,
    setup_generation_recipient_vss_payload_byte_length,
    setup_generation_recipient_vss_payload_source_byte_length,
    setup_generation_recipient_vss_payload_source_recipient_roster_position,
    setup_generation_retained_memory_accounting, take_prepackage_evaluator_statement_source,
    take_prepackage_galois_statement_source, take_verified_evaluator_execution_authority,
    with_accepted_setup_verification_sources, with_completed_prepackage_evaluator_source_catalog,
    with_prepackage_evaluator_generation_sources, with_prepackage_generated_galois_source,
    with_prepackage_generated_relinearization_aggregate,
    with_prepackage_generated_relinearization_round_one_sources,
    with_prepackage_relinearization_source, with_setup_generation_galois_batch,
    with_setup_generation_galois_public_component_chunk, with_setup_generation_key_relation,
    with_setup_generation_relinearization_round_one,
    with_setup_generation_relinearization_round_one_component_chunk,
    with_setup_generation_relinearization_round_two,
    with_setup_generation_relinearization_round_two_component_chunk,
    with_setup_generation_relinearization_round_two_witness, with_setup_generation_vss_material,
    with_verified_accepted_setup_authority, with_verified_participant_target_release_source,
};
pub(crate) use accepted_setup::{
    SetupGenerationDealerPublicRecordSource, resolve_setup_generation_dealer_public_record_source,
};
pub(in crate::bgv) use accepted_setup::{
    VerifiedAggregateThresholdShareTerminal, VerifiedPublicRandomness,
    VerifiedVssQualificationTerminals, VerifiedVssShareLinkageTerminal,
    derive_recipient_input_root, verify_public_randomness_board_sources,
};
#[cfg(test)]
pub(crate) use commitment::LatticeAnchorCommitment;
pub(crate) use commitment::{
    SETUP_COMMITMENT_HIDING_ERROR_WIDTH, SETUP_COMMITMENT_HIDING_SECRET_WIDTH,
    SETUP_COMMITMENT_MODULE_RANK, SETUP_COMMITMENT_MODULUS_LIMB_INDICES,
    parse_lattice_anchor_commitment_canonical_bytes,
};
pub(crate) use commitment::{
    compute_lattice_anchor_commitment, lattice_anchor_commitment_canonical_bytes,
};
pub(in crate::bgv) use commitment::{
    setup_commitment_matrix_ntt_cache_coefficient_payload_byte_length,
    setup_commitment_matrix_polynomial,
};
pub(in crate::bgv) use sampling::{
    sample_collective_public_key_common_reference_limb, sample_galois_common_reference_limb,
    sample_relinearization_common_reference_limb,
};
