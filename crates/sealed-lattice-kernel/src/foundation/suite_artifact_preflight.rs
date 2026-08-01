//! Fail-closed semantic preflight for artifacts bound by a canonical suite record.

use num_bigint::BigUint;

use super::canonical_tuple::CanonicalDecodeBudget;
use super::schemas::{read_item, read_u16, read_u32, read_u64};
use super::suite::{read_unsigned16_list, read_unsigned64_list};
use super::{
    ArtifactKind, ArtifactReference, CanonicalDecodeLimits, CanonicalItemType, CanonicalTuple,
    FOUNDATION_PROFILE, FoundationSchemaError, RefusalReason, SuiteRecord,
};
use crate::bgv::direct_ballots::{
    PAIR_CHARACTER_AUXILIARY_COUNT, PAIR_CHARACTER_CIPHERTEXT_COUNT, PAIR_CHARACTER_LANE_COUNT,
    PAIR_CHARACTER_LANE_DEGREE, selected_pair_character_lane_assignments,
};
use crate::bgv::evaluator::program::verify_canonical_program_set;
use crate::bgv::evaluator::top_k::CANONICAL_TARGET_CIPHERTEXT_LEVEL;
use crate::bgv::parameters::{
    DATA_PRIMES, PLAINTEXT_EXTENSION_DEGREE, PLAINTEXT_EXTENSION_LANE_COUNT,
    PLAINTEXT_LANE_ORBIT_GENERATOR, PLAINTEXT_LANE_ROOT_GENERATOR, POLYNOMIAL_DEGREE,
    validate_supported_algebraic_parameters,
};
use crate::bgv::proof_suite::{
    selected_committed_material_profile, verify_canonical_proof_profile_set,
};
use crate::bgv::setup::{SETUP_COMMITMENT_MODULE_RANK, SETUP_COMMITMENT_MODULUS_LIMB_INDICES};

const MAXIMUM_EVALUATOR_PROGRAM_BYTE_LENGTH: usize = 64 * 1024 * 1024;
const MAXIMUM_EVALUATOR_PROGRAM_ITEM_BYTE_LENGTH: usize = 48 * 1024 * 1024;
const MAXIMUM_EVALUATOR_PROGRAM_WORK_BYTE_LENGTH: usize = 128 * 1024 * 1024;
const MAXIMUM_EVALUATOR_PROGRAM_ALLOCATION_BYTE_LENGTH: usize = 96 * 1024 * 1024;

pub(crate) fn verify_canonical_suite_artifact(
    canonical_suite_record_bytes: &[u8],
    artifact_kind_code: u16,
    canonical_artifact_bytes: &[u8],
) -> Result<(), FoundationSchemaError> {
    let suite_limits = CanonicalDecodeLimits::default();
    let suite = SuiteRecord::decode(canonical_suite_record_bytes, &suite_limits)?;
    if suite.encode()?.as_slice() != canonical_suite_record_bytes {
        return Err(malformed("suite record is not canonically encoded"));
    }

    let artifact_kind = ArtifactKind::from_canonical_code(artifact_kind_code)?;
    let expected_reference = *suite.artifact(artifact_kind);
    let actual_byte_length = u64::try_from(canonical_artifact_bytes.len())
        .map_err(|_| outside_profile("suite artifact byte length does not fit u64"))?;
    if actual_byte_length != expected_reference.byte_length() {
        return Err(wrong_length(
            "suite artifact byte length does not match its reference",
        ));
    }

    let artifact_limits = artifact_decode_limits(artifact_kind);
    let actual_reference = ArtifactReference::from_canonical_artifact_bytes(
        artifact_kind,
        canonical_artifact_bytes,
        &artifact_limits,
    )?;
    if actual_reference.artifact_hash() != expected_reference.artifact_hash() {
        return Err(wrong_hash(
            "suite artifact hash does not match its reference",
        ));
    }

    match artifact_kind {
        ArtifactKind::EncoderAndBallotLayout => {
            verify_encoder_and_ballot_layout(canonical_artifact_bytes, &artifact_limits)
        }
        ArtifactKind::VerifiableSecretSharingProfile => {
            verify_verifiable_secret_sharing_profile(canonical_artifact_bytes, &artifact_limits)
        }
        ArtifactKind::LatticeCommitmentProfile => {
            verify_lattice_commitment_profile(canonical_artifact_bytes, &artifact_limits)
        }
        ArtifactKind::ProofProfileSet => verify_canonical_proof_profile_set(
            canonical_artifact_bytes,
            suite
                .count_limits()
                .maximum_ballot_attempts_per_participant(),
        )
        .map_err(|_| unsupported_artifact("proof profile semantics are unsupported")),
        ArtifactKind::EvaluatorProgramSet => verify_canonical_program_set(canonical_artifact_bytes)
            .map_err(|_| unsupported_artifact("evaluator program semantics are unsupported")),
        ArtifactKind::TargetDecryptionProfile => {
            verify_target_decryption_profile(canonical_artifact_bytes, &artifact_limits)
        }
    }
}

fn artifact_decode_limits(artifact_kind: ArtifactKind) -> CanonicalDecodeLimits {
    if artifact_kind != ArtifactKind::EvaluatorProgramSet {
        return CanonicalDecodeLimits::default();
    }
    CanonicalDecodeLimits {
        maximum_tuple_byte_length: MAXIMUM_EVALUATOR_PROGRAM_BYTE_LENGTH,
        maximum_item_count: POLYNOMIAL_DEGREE,
        maximum_item_byte_length: MAXIMUM_EVALUATOR_PROGRAM_ITEM_BYTE_LENGTH,
        maximum_nesting_depth: 32,
        maximum_cumulative_work_byte_length: MAXIMUM_EVALUATOR_PROGRAM_WORK_BYTE_LENGTH,
        maximum_cumulative_allocation_byte_length: MAXIMUM_EVALUATOR_PROGRAM_ALLOCATION_BYTE_LENGTH,
    }
}

fn verify_encoder_and_ballot_layout(
    bytes: &[u8],
    limits: &CanonicalDecodeLimits,
) -> Result<(), FoundationSchemaError> {
    validate_supported_algebraic_parameters()
        .map_err(|_| unsupported_artifact("selected algebraic parameters are invalid"))?;
    let tuple = decode_exact(bytes, limits)?;
    require_exact_header(&tuple, 0x1300, 4, 12)?;
    let expected_assignments = selected_pair_character_lane_assignments()
        .map_err(|_| unsupported_artifact("pair-character assignment catalog is invalid"))?
        .into_iter()
        .flat_map(|assignment| {
            [
                assignment.ciphertext_ordinal(),
                assignment.lane_ordinal(),
                assignment.lower_option_ordinal(),
                assignment.higher_option_ordinal(),
            ]
        })
        .collect::<Vec<_>>();
    let matches_selected = usize::try_from(read_u32(&tuple.items[0])?).ok()
        == Some(POLYNOMIAL_DEGREE)
        && read_u64(&tuple.items[1])? == PLAINTEXT_LANE_ROOT_GENERATOR
        && usize::from(read_u16(&tuple.items[2])?) == PLAINTEXT_LANE_ORBIT_GENERATOR
        && usize::from(read_u16(&tuple.items[3])?) == PLAINTEXT_EXTENSION_DEGREE
        && usize::from(read_u16(&tuple.items[3])?) == PAIR_CHARACTER_LANE_DEGREE
        && usize::from(read_u16(&tuple.items[4])?) == PLAINTEXT_EXTENSION_LANE_COUNT
        && usize::from(read_u16(&tuple.items[4])?) == PAIR_CHARACTER_LANE_COUNT
        && usize::from(read_u16(&tuple.items[5])?) == PAIR_CHARACTER_CIPHERTEXT_COUNT
        && usize::from(read_u16(&tuple.items[6])?) == PAIR_CHARACTER_AUXILIARY_COUNT
        && read_u16(&tuple.items[7])? == FOUNDATION_PROFILE.option_count
        && read_u16(&tuple.items[8])? == FOUNDATION_PROFILE.minimum_score
        && read_u16(&tuple.items[9])? == FOUNDATION_PROFILE.maximum_score
        && read_u16(&tuple.items[10])? == 1
        && read_unsigned16_list(&tuple.items[11])? == expected_assignments;
    require_selected(
        matches_selected,
        "encoder and ballot layout does not match the suite",
    )
}

fn verify_verifiable_secret_sharing_profile(
    bytes: &[u8],
    limits: &CanonicalDecodeLimits,
) -> Result<(), FoundationSchemaError> {
    let mut budget = CanonicalDecodeBudget::new(limits);
    let tuple = CanonicalTuple::decode_with_budget(bytes, limits, &mut budget)?;
    require_exact_header(&tuple, 0x2120, 1, 1)?;
    let nested_bytes = read_item(&tuple.items[0], CanonicalItemType::NestedTuple)?;
    let (field, consumed) = CanonicalTuple::decode_prefix(nested_bytes, limits, &mut budget, 1)?;
    if consumed != nested_bytes.len() {
        return Err(malformed("VSS field profile contains trailing bytes"));
    }
    require_exact_header(&field, 0x2121, 1, 4)?;
    let selected = selected_committed_material_profile()
        .map_err(|_| unsupported_artifact("committed-material profile is invalid"))?;
    let matches_selected = read_u16(&field.items[0])? == 0
        && read_u64(&field.items[1])? == selected.evaluation_coset_offset()
        && usize::try_from(read_u32(&field.items[2])?).ok()
            == Some(selected.masking_polynomial_maximum_degree())
        && usize::try_from(read_u32(&field.items[3])?).ok()
            == Some(selected.committed_polynomial_degree_bound_exclusive());
    require_selected(matches_selected, "VSS profile does not match the suite")?;
    require_canonical(bytes, &tuple)
}

fn verify_lattice_commitment_profile(
    bytes: &[u8],
    limits: &CanonicalDecodeLimits,
) -> Result<(), FoundationSchemaError> {
    let tuple = decode_exact(bytes, limits)?;
    require_exact_header(&tuple, 0x2122, 3, 2)?;
    let expected_indexes = SETUP_COMMITMENT_MODULUS_LIMB_INDICES
        .iter()
        .copied()
        .map(u16::try_from)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| unsupported_artifact("commitment limb index does not fit u16"))?;
    require_selected(
        usize::from(read_u16(&tuple.items[0])?) == SETUP_COMMITMENT_MODULE_RANK
            && read_unsigned16_list(&tuple.items[1])? == expected_indexes,
        "lattice commitment profile does not match the suite",
    )
}

fn verify_target_decryption_profile(
    bytes: &[u8],
    limits: &CanonicalDecodeLimits,
) -> Result<(), FoundationSchemaError> {
    let tuple = decode_exact(bytes, limits)?;
    require_exact_header(&tuple, 0x1630, 1, 1)?;
    let words = read_unsigned64_list(&tuple.items[0])?;
    let target_modulus = DATA_PRIMES[..=CANONICAL_TARGET_CIPHERTEXT_LEVEL]
        .iter()
        .map(|modulus| BigUint::from(*modulus))
        .product::<BigUint>();
    let expected_word_count = usize::try_from(target_modulus.bits().div_ceil(u64::from(u64::BITS)))
        .map_err(|_| outside_profile("target modulus word count does not fit usize"))?;
    let flooding_bound = words.iter().rev().fold(BigUint::from(0_u8), |value, word| {
        (value << u64::BITS) + BigUint::from(*word)
    });
    require_selected(
        words.len() == expected_word_count
            && flooding_bound != BigUint::from(0_u8)
            && flooding_bound < target_modulus,
        "target-decryption flooding bound is outside the suite modulus",
    )
}

fn decode_exact(
    bytes: &[u8],
    limits: &CanonicalDecodeLimits,
) -> Result<CanonicalTuple, FoundationSchemaError> {
    let tuple = CanonicalTuple::decode(bytes, limits)?;
    require_canonical(bytes, &tuple)?;
    Ok(tuple)
}

fn require_canonical(bytes: &[u8], tuple: &CanonicalTuple) -> Result<(), FoundationSchemaError> {
    if tuple.encode()?.as_slice() != bytes {
        return Err(malformed("suite artifact is not canonically encoded"));
    }
    Ok(())
}

fn require_exact_header(
    tuple: &CanonicalTuple,
    schema_identifier: u16,
    schema_version: u16,
    item_count: usize,
) -> Result<(), FoundationSchemaError> {
    if tuple.schema_identifier != schema_identifier || tuple.items.len() != item_count {
        return Err(wrong_length("suite artifact has the wrong schema or shape"));
    }
    if tuple.schema_version != schema_version {
        return Err(unsupported_artifact(
            "suite artifact version is unsupported",
        ));
    }
    Ok(())
}

fn require_selected(
    matches_selected: bool,
    message: &'static str,
) -> Result<(), FoundationSchemaError> {
    if !matches_selected {
        return Err(unsupported_artifact(message));
    }
    Ok(())
}

fn malformed(message: &'static str) -> FoundationSchemaError {
    FoundationSchemaError::new(RefusalReason::MalformedEncoding, message)
}

fn unsupported_artifact(message: &'static str) -> FoundationSchemaError {
    FoundationSchemaError::new(RefusalReason::UnsupportedVersionOrSuite, message)
}

fn outside_profile(message: &'static str) -> FoundationSchemaError {
    FoundationSchemaError::new(RefusalReason::OutsideSupportedProfile, message)
}

fn wrong_length(message: &'static str) -> FoundationSchemaError {
    FoundationSchemaError::new(RefusalReason::WrongTypeOrLength, message)
}

fn wrong_hash(message: &'static str) -> FoundationSchemaError {
    FoundationSchemaError::new(RefusalReason::WrongHashOrRoot, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::CanonicalItem;
    use crate::foundation::selected_suite::derive_selected_suite_candidate_record;
    use crate::foundation::suite_artifacts::{
        selected_encoder_and_ballot_layout_artifact_bytes,
        selected_evaluator_program_artifact_bytes,
        selected_lattice_commitment_profile_artifact_bytes, selected_proof_profile_artifact_bytes,
        selected_target_decryption_profile_artifact_bytes,
        selected_verifiable_secret_sharing_profile_artifact_bytes,
    };

    fn candidate_artifacts(
        maximum_ballot_attempts_per_participant: u16,
    ) -> Vec<(ArtifactKind, Vec<u8>)> {
        vec![
            (
                ArtifactKind::EncoderAndBallotLayout,
                selected_encoder_and_ballot_layout_artifact_bytes()
                    .expect("encoder artifact derives"),
            ),
            (
                ArtifactKind::VerifiableSecretSharingProfile,
                selected_verifiable_secret_sharing_profile_artifact_bytes()
                    .expect("VSS artifact derives"),
            ),
            (
                ArtifactKind::LatticeCommitmentProfile,
                selected_lattice_commitment_profile_artifact_bytes()
                    .expect("commitment artifact derives"),
            ),
            (
                ArtifactKind::ProofProfileSet,
                selected_proof_profile_artifact_bytes(maximum_ballot_attempts_per_participant)
                    .expect("proof-profile artifact derives"),
            ),
            (
                ArtifactKind::EvaluatorProgramSet,
                selected_evaluator_program_artifact_bytes().expect("evaluator artifact derives"),
            ),
            (
                ArtifactKind::TargetDecryptionProfile,
                selected_target_decryption_profile_artifact_bytes()
                    .expect("target-decryption artifact derives"),
            ),
        ]
    }

    #[test]
    #[ignore = "guarded complete candidate-suite artifact semantic preflight evidence"]
    fn candidate_suite_artifacts_pass_semantic_preflight_and_refuse_mutations() {
        let suite = derive_selected_suite_candidate_record().expect("candidate suite derives");
        let suite_bytes = suite.encode().expect("candidate suite encodes");
        let artifacts = candidate_artifacts(
            suite
                .count_limits()
                .maximum_ballot_attempts_per_participant(),
        );
        for (artifact_kind, artifact_bytes) in &artifacts {
            verify_canonical_suite_artifact(
                &suite_bytes,
                artifact_kind.canonical_code(),
                artifact_bytes,
            )
            .unwrap_or_else(|error| {
                panic!(
                    "artifact {:?} must pass semantic preflight: {error:?}",
                    artifact_kind
                )
            });
        }
        for (artifact_kind, artifact_bytes) in &artifacts {
            let mut mutated_artifact_bytes = artifact_bytes.clone();
            let final_byte = mutated_artifact_bytes
                .last_mut()
                .expect("candidate artifacts are nonempty");
            *final_byte ^= 1;
            assert!(
                verify_canonical_suite_artifact(
                    &suite_bytes,
                    artifact_kind.canonical_code(),
                    &mutated_artifact_bytes,
                )
                .is_err(),
                "mutated {:?} bytes must refuse",
                artifact_kind
            );
        }

        let encoder_bytes = artifacts
            .first()
            .expect("the encoder artifact is first")
            .1
            .clone();
        let limits = CanonicalDecodeLimits::default();
        let mut encoder_tuple =
            CanonicalTuple::decode(&encoder_bytes, &limits).expect("encoder artifact decodes");
        encoder_tuple.items[0] = CanonicalItem::unsigned32(
            u32::try_from(POLYNOMIAL_DEGREE)
                .expect("selected degree fits u32")
                .checked_add(1)
                .expect("mutated degree fits u32"),
        );
        let invalid_encoder_bytes = encoder_tuple
            .encode()
            .expect("semantically invalid encoder still encodes canonically");
        let mut rebound_references = suite.artifacts().to_vec();
        rebound_references[0] = ArtifactReference::from_canonical_artifact_bytes(
            ArtifactKind::EncoderAndBallotLayout,
            &invalid_encoder_bytes,
            &limits,
        )
        .expect("invalid encoder reference derives from its exact bytes");
        let rebound_suite = SuiteRecord::new(suite.count_limits(), rebound_references)
            .expect("rebound candidate suite is structurally canonical");
        let error = verify_canonical_suite_artifact(
            &rebound_suite.encode().expect("rebound suite encodes"),
            ArtifactKind::EncoderAndBallotLayout.canonical_code(),
            &invalid_encoder_bytes,
        )
        .expect_err("self-consistent invalid encoder semantics must refuse");
        assert_eq!(
            error.refusal_reason,
            RefusalReason::UnsupportedVersionOrSuite
        );
    }
}
