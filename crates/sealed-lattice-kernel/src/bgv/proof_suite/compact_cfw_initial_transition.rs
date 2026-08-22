//! Project-specific initial CFW transition lemma and emitted-source binding.
//!
//! The CFW verifier's first random message contains one constraint-combining
//! scalar and the complete equality point. For a decoded predecessor witness,
//! a false-to-true transition is a root of
//!
//! `auxiliary_difference + combining_scalar * residual_extension(equality_point)`.
//!
//! The residual extension is multilinear in every equality coordinate. The
//! combining scalar is a separate variable, so the polynomial has total degree
//! at most `equality_coordinate_count + 1`. It is nonzero whenever the
//! predecessor is false: a nonzero auxiliary difference occupies the
//! combining-degree-zero slice, while a nonzero residual vector defines a
//! nonzero multilinear polynomial and occupies the combining-degree-one slice.
//! Schwartz--Zippel therefore bounds the interactive uniform-message event by
//! `(equality_coordinate_count + 1) / |F|`.
//!
//! This module is test-only evidence. It neither verifies proof bytes nor mints
//! a runtime capability. The separate fixed-tape and Fiat--Shamir owners remain
//! responsible for translating the interactive uniform-message statement to
//! the emitted non-interactive transcript.

use num_bigint::BigUint;
use p3_field::PrimeCharacteristicRing;

use super::compact_cfw::CompactChallengeField;
use super::compact_fixed_tape_source_correspondence::CompactFixedTapeSourceCorrespondence;
use super::compact_proof_contract::{
    CompactPublicKeyProofContract, CompactPublicKeyVerifierInputs,
};
use super::compact_transcript::compact_fiat_shamir_round_verifier_message_answer_prefix;
use super::{
    PROOF_BASE_FIELD_MODULUS, PROOF_CHALLENGE_EXTENSION_DEGREE, SourceVerifiedCompactPublicKeyProof,
};
use crate::foundation::Hash512;

const CFW_INITIAL_RANDOMNESS_ROLE_TAG: u8 = 3;
const CFW_CROSS_EPOCH_DISCLOSURE_RESPONSE_ROLE_TAG: u8 = 6;
const CFW_AUXILIARY_TARGET_RESPONSE_ROLE_TAG: u8 = 7;
const NON_EPOCH_TAG: u8 = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactCfwInitialTransitionBinding {
    ContractSource,
    CanonicalProof,
    CanonicalPublicInput,
    FixedTapeChronology,
    InitialVerifierMessageAnswerPrefix,
    InitialVerifierMessage,
    AuxiliaryTarget,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CompactCfwInitialTransitionError {
    ArithmeticOverflow,
    Contract,
    MissingInitialVerifierMove,
    DuplicateInitialVerifierMove,
    InvalidInitialVerifierChronology,
    InvalidInitialChallengeGeometry,
    InvalidResidualGeometry,
    ZeroPolynomial,
    IdentityDoesNotVanish,
    BindingMismatch(CompactCfwInitialTransitionBinding),
}

/// Compiler-derived interactive lemma for the selected initial CFW move.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactCfwInitialTransitionLemma {
    pub(crate) selected_contract_source_hash: Hash512,
    pub(crate) initial_verifier_move_ordinal: u32,
    pub(crate) preceding_prover_response_ordinal: u32,
    pub(crate) preceding_commitment_count: u32,
    pub(crate) equality_coordinate_count: u32,
    pub(crate) polynomial_variable_count: u32,
    pub(crate) maximum_total_degree: u64,
    pub(crate) soundness_numerator: u64,
    pub(crate) challenge_field_cardinality: BigUint,
}

/// Exact source binding for the initial verifier move in one accepted native
/// proof. All values are public transcript data retained only as development
/// evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactCfwInitialTransitionSourceEvidence {
    pub(crate) lemma: CompactCfwInitialTransitionLemma,
    pub(crate) canonical_proof_binding: [u8; Hash512::BYTE_LENGTH],
    pub(crate) canonical_public_input_binding: [u8; Hash512::BYTE_LENGTH],
    pub(crate) verifier_message_answer_prefix: [u8; Hash512::BYTE_LENGTH],
    pub(crate) auxiliary_target_coordinates: [u64; PROOF_CHALLENGE_EXTENSION_DEGREE],
    pub(crate) constraint_combining_challenge_coordinates: [u64; PROOF_CHALLENGE_EXTENSION_DEGREE],
    pub(crate) equality_point_coordinates: Box<[[u64; PROOF_CHALLENGE_EXTENSION_DEGREE]]>,
}

/// Derives the common conservative numerator without fixing a profile count.
pub(crate) fn compact_cfw_initial_transition_soundness_numerator(
    equality_coordinate_count: usize,
) -> Result<u64, CompactCfwInitialTransitionError> {
    u64::try_from(equality_coordinate_count)
        .map_err(|_| CompactCfwInitialTransitionError::ArithmeticOverflow)?
        .checked_add(1)
        .ok_or(CompactCfwInitialTransitionError::ArithmeticOverflow)
}

pub(crate) fn derive_selected_compact_cfw_initial_transition_lemma()
-> Result<CompactCfwInitialTransitionLemma, CompactCfwInitialTransitionError> {
    let contract = CompactPublicKeyProofContract::decode_selected()
        .map_err(|_| CompactCfwInitialTransitionError::Contract)?;
    derive_initial_transition_lemma(contract.verifier_inputs())
}

fn derive_initial_transition_lemma(
    verifier_inputs: CompactPublicKeyVerifierInputs<'_>,
) -> Result<CompactCfwInitialTransitionLemma, CompactCfwInitialTransitionError> {
    let equality_coordinate_count = verifier_inputs
        .cfw_configuration
        .geometry()
        .sumcheck_round_count();
    let relation_variable_count = verifier_inputs.relation.padded_witness_element_count();
    if !relation_variable_count.is_power_of_two() {
        return Err(CompactCfwInitialTransitionError::Contract);
    }
    let independently_derived_equality_coordinate_count = usize::try_from(
        relation_variable_count
            .ilog2()
            .checked_add(1)
            .ok_or(CompactCfwInitialTransitionError::ArithmeticOverflow)?,
    )
    .map_err(|_| CompactCfwInitialTransitionError::ArithmeticOverflow)?;
    if equality_coordinate_count != independently_derived_equality_coordinate_count {
        return Err(CompactCfwInitialTransitionError::Contract);
    }

    let mut initial_moves = verifier_inputs
        .verifier_moves
        .iter()
        .filter(|verifier_move| {
            verifier_move
                .role_coordinates
                .iter()
                .any(|coordinate| coordinate.role_tag == CFW_INITIAL_RANDOMNESS_ROLE_TAG)
        });
    let initial_move = initial_moves
        .next()
        .ok_or(CompactCfwInitialTransitionError::MissingInitialVerifierMove)?;
    if initial_moves.next().is_some() {
        return Err(CompactCfwInitialTransitionError::DuplicateInitialVerifierMove);
    }
    let [role] = initial_move.role_coordinates.as_slice() else {
        return Err(CompactCfwInitialTransitionError::InvalidInitialVerifierChronology);
    };
    let initial_challenge_count =
        compact_cfw_initial_transition_soundness_numerator(equality_coordinate_count)?;
    if role.role_tag != CFW_INITIAL_RANDOMNESS_ROLE_TAG
        || role.epoch != NON_EPOCH_TAG
        || role.batch_ordinal != 0
        || role.round_ordinal != 0
        || role.extension_output_start != 0
        || role.extension_output_end != initial_challenge_count
        || role.base_field_output_start != 0
        || role.base_field_output_end != 0
        || role.distinct_query_group_start != 0
        || role.distinct_query_group_end != 0
        || initial_move.message_geometry.extension_output_count() != initial_challenge_count
        || initial_move
            .message_geometry
            .excluded_extension_prefix_cardinality()
            != 0
        || initial_move.message_geometry.base_field_output_count() != 0
        || !initial_move
            .message_geometry
            .distinct_query_groups()
            .is_empty()
    {
        return Err(CompactCfwInitialTransitionError::InvalidInitialChallengeGeometry);
    }

    let response_index = usize::try_from(initial_move.ordinal)
        .map_err(|_| CompactCfwInitialTransitionError::ArithmeticOverflow)?;
    let response_roles = verifier_inputs
        .response_component_roles
        .get(response_index)
        .ok_or(CompactCfwInitialTransitionError::InvalidInitialVerifierChronology)?;
    if response_roles.len() != 2
        || response_roles[0].role_tag != CFW_CROSS_EPOCH_DISCLOSURE_RESPONSE_ROLE_TAG
        || response_roles[1].role_tag != CFW_AUXILIARY_TARGET_RESPONSE_ROLE_TAG
        || response_roles.iter().any(|response_role| {
            response_role.epoch != NON_EPOCH_TAG
                || response_role.batch_ordinal != 0
                || response_role.round_ordinal != 0
        })
        || initial_move.preceding_commitment_count < 4
    {
        return Err(CompactCfwInitialTransitionError::InvalidInitialVerifierChronology);
    }

    let polynomial_variable_count = u32::try_from(initial_challenge_count)
        .map_err(|_| CompactCfwInitialTransitionError::ArithmeticOverflow)?;
    let challenge_field_cardinality = BigUint::from(PROOF_BASE_FIELD_MODULUS).pow(
        u32::try_from(PROOF_CHALLENGE_EXTENSION_DEGREE)
            .map_err(|_| CompactCfwInitialTransitionError::ArithmeticOverflow)?,
    );
    if challenge_field_cardinality <= BigUint::from(initial_challenge_count) {
        return Err(CompactCfwInitialTransitionError::InvalidInitialChallengeGeometry);
    }

    Ok(CompactCfwInitialTransitionLemma {
        selected_contract_source_hash: verifier_inputs
            .canonical_source_hash()
            .map_err(|_| CompactCfwInitialTransitionError::Contract)?,
        initial_verifier_move_ordinal: initial_move.ordinal,
        preceding_prover_response_ordinal: initial_move.preceding_prover_response_ordinal,
        preceding_commitment_count: initial_move.preceding_commitment_count,
        equality_coordinate_count: u32::try_from(equality_coordinate_count)
            .map_err(|_| CompactCfwInitialTransitionError::ArithmeticOverflow)?,
        polynomial_variable_count,
        maximum_total_degree: initial_challenge_count,
        soundness_numerator: initial_challenge_count,
        challenge_field_cardinality,
    })
}

/// Independently validates one executable bad-transition certificate.
///
/// The direct Boolean-basis evaluation deliberately does not call the CFW
/// evaluator's fold routine. This keeps coordinate order and root checking
/// independent of the implementation that manufactured the certificate.
pub(crate) fn verify_compact_cfw_initial_transition_bad_event(
    auxiliary_difference: CompactChallengeField,
    masked_constraint_hypercube_residuals: &[CompactChallengeField],
    constraint_combining_challenge: CompactChallengeField,
    equality_point: &[CompactChallengeField],
) -> Result<u64, CompactCfwInitialTransitionError> {
    let expected_residual_count = 1_usize
        .checked_shl(
            u32::try_from(equality_point.len())
                .map_err(|_| CompactCfwInitialTransitionError::ArithmeticOverflow)?,
        )
        .ok_or(CompactCfwInitialTransitionError::ArithmeticOverflow)?;
    if masked_constraint_hypercube_residuals.len() != expected_residual_count {
        return Err(CompactCfwInitialTransitionError::InvalidResidualGeometry);
    }
    let residual_polynomial_is_nonzero = masked_constraint_hypercube_residuals
        .iter()
        .any(|residual| *residual != CompactChallengeField::ZERO);
    if auxiliary_difference == CompactChallengeField::ZERO && !residual_polynomial_is_nonzero {
        return Err(CompactCfwInitialTransitionError::ZeroPolynomial);
    }

    let residual_at_equality_point =
        independent_multilinear_evaluation(masked_constraint_hypercube_residuals, equality_point)?;
    if auxiliary_difference + constraint_combining_challenge * residual_at_equality_point
        != CompactChallengeField::ZERO
    {
        return Err(CompactCfwInitialTransitionError::IdentityDoesNotVanish);
    }

    compact_cfw_initial_transition_soundness_numerator(equality_point.len())
}

fn independent_multilinear_evaluation(
    hypercube_values: &[CompactChallengeField],
    point: &[CompactChallengeField],
) -> Result<CompactChallengeField, CompactCfwInitialTransitionError> {
    let expected_value_count = 1_usize
        .checked_shl(
            u32::try_from(point.len())
                .map_err(|_| CompactCfwInitialTransitionError::ArithmeticOverflow)?,
        )
        .ok_or(CompactCfwInitialTransitionError::ArithmeticOverflow)?;
    if hypercube_values.len() != expected_value_count {
        return Err(CompactCfwInitialTransitionError::InvalidResidualGeometry);
    }
    Ok(hypercube_values
        .iter()
        .enumerate()
        .map(|(boolean_ordinal, residual)| {
            point.iter().enumerate().fold(
                *residual,
                |weighted, (coordinate_ordinal, coordinate)| {
                    if (boolean_ordinal >> coordinate_ordinal) & 1 == 0 {
                        weighted * (CompactChallengeField::ONE - *coordinate)
                    } else {
                        weighted * *coordinate
                    }
                },
            )
        })
        .sum())
}

pub(crate) fn derive_source_verified_compact_cfw_initial_transition_evidence(
    proof: &SourceVerifiedCompactPublicKeyProof,
    fixed_tape_correspondence: &CompactFixedTapeSourceCorrespondence,
) -> Result<CompactCfwInitialTransitionSourceEvidence, CompactCfwInitialTransitionError> {
    let lemma = derive_selected_compact_cfw_initial_transition_lemma()?;
    let transport = proof.source_verified_transport();
    let verifier_inputs = transport.verifier_inputs();
    let public_input_view = transport.public_input_view();
    if verifier_inputs
        .canonical_source_hash()
        .map_err(|_| CompactCfwInitialTransitionError::Contract)?
        != lemma.selected_contract_source_hash
        || fixed_tape_correspondence.selected_contract_source_hash
            != lemma.selected_contract_source_hash
    {
        return Err(CompactCfwInitialTransitionError::BindingMismatch(
            CompactCfwInitialTransitionBinding::ContractSource,
        ));
    }
    if fixed_tape_correspondence.canonical_proof_binding != transport.canonical_proof_binding() {
        return Err(CompactCfwInitialTransitionError::BindingMismatch(
            CompactCfwInitialTransitionBinding::CanonicalProof,
        ));
    }
    if fixed_tape_correspondence.canonical_public_input_binding != public_input_view.binding() {
        return Err(CompactCfwInitialTransitionError::BindingMismatch(
            CompactCfwInitialTransitionBinding::CanonicalPublicInput,
        ));
    }
    if usize::try_from(fixed_tape_correspondence.logical_round_count).ok()
        != Some(transport.verifier_messages().len())
        || fixed_tape_correspondence.direct_xof_call_count
            != fixed_tape_correspondence.logical_round_count
        || fixed_tape_correspondence.rounds.len() != transport.verifier_messages().len()
        || fixed_tape_correspondence
            .rounds
            .iter()
            .enumerate()
            .any(|(round_index, round)| {
                usize::try_from(round.round_ordinal).ok() != Some(round_index)
            })
    {
        return Err(CompactCfwInitialTransitionError::BindingMismatch(
            CompactCfwInitialTransitionBinding::FixedTapeChronology,
        ));
    }

    let initial_move_index = usize::try_from(lemma.initial_verifier_move_ordinal)
        .map_err(|_| CompactCfwInitialTransitionError::ArithmeticOverflow)?;
    let fixed_tape_round = fixed_tape_correspondence
        .rounds
        .get(initial_move_index)
        .ok_or(CompactCfwInitialTransitionError::BindingMismatch(
            CompactCfwInitialTransitionBinding::InitialVerifierMessageAnswerPrefix,
        ))?;
    let production_answer_prefix = compact_fiat_shamir_round_verifier_message_answer_prefix(
        verifier_inputs.proof_wire_geometry,
        transport.proof_view().decoded(),
        transport.proof_view().canonical_bytes(),
        public_input_view.decoded(),
        public_input_view.canonical_bytes(),
        lemma.initial_verifier_move_ordinal,
    )
    .map_err(|_| {
        CompactCfwInitialTransitionError::BindingMismatch(
            CompactCfwInitialTransitionBinding::InitialVerifierMessageAnswerPrefix,
        )
    })?;
    let initial_move = verifier_inputs
        .verifier_moves
        .get(initial_move_index)
        .ok_or(CompactCfwInitialTransitionError::InvalidInitialVerifierChronology)?;
    if fixed_tape_round.verifier_message_answer_prefix != production_answer_prefix.into_bytes()
        || fixed_tape_round.message_byte_length
            != u64::try_from(
                initial_move
                    .message_geometry
                    .exact_message_byte_length()
                    .map_err(|_| {
                        CompactCfwInitialTransitionError::InvalidInitialChallengeGeometry
                    })?,
            )
            .map_err(|_| CompactCfwInitialTransitionError::ArithmeticOverflow)?
    {
        return Err(CompactCfwInitialTransitionError::BindingMismatch(
            CompactCfwInitialTransitionBinding::InitialVerifierMessageAnswerPrefix,
        ));
    }

    let initial_verifier_role = transport
        .verifier_role(CFW_INITIAL_RANDOMNESS_ROLE_TAG, NON_EPOCH_TAG, 0, 0)
        .map_err(|_| {
            CompactCfwInitialTransitionError::BindingMismatch(
                CompactCfwInitialTransitionBinding::InitialVerifierMessage,
            )
        })?;
    let challenge_values = initial_verifier_role.extension_elements();
    if !initial_verifier_role.base_field_elements().is_empty()
        || !initial_verifier_role.distinct_query_groups().is_empty()
        || challenge_values.len()
            != usize::try_from(lemma.polynomial_variable_count)
                .map_err(|_| CompactCfwInitialTransitionError::ArithmeticOverflow)?
    {
        return Err(CompactCfwInitialTransitionError::BindingMismatch(
            CompactCfwInitialTransitionBinding::InitialVerifierMessage,
        ));
    }
    let (constraint_combining_challenge, equality_point) =
        challenge_values
            .split_first()
            .ok_or(CompactCfwInitialTransitionError::BindingMismatch(
                CompactCfwInitialTransitionBinding::InitialVerifierMessage,
            ))?;

    let auxiliary_target = transport
        .opened_extension_role(CFW_AUXILIARY_TARGET_RESPONSE_ROLE_TAG, NON_EPOCH_TAG, 0, 0)
        .and_then(|role| role.complete_values())
        .map_err(|_| {
            CompactCfwInitialTransitionError::BindingMismatch(
                CompactCfwInitialTransitionBinding::AuxiliaryTarget,
            )
        })?;
    let [auxiliary_target] = auxiliary_target.as_slice() else {
        return Err(CompactCfwInitialTransitionError::BindingMismatch(
            CompactCfwInitialTransitionBinding::AuxiliaryTarget,
        ));
    };

    Ok(CompactCfwInitialTransitionSourceEvidence {
        lemma,
        canonical_proof_binding: transport.canonical_proof_binding(),
        canonical_public_input_binding: public_input_view.binding(),
        verifier_message_answer_prefix: fixed_tape_round.verifier_message_answer_prefix,
        auxiliary_target_coordinates: auxiliary_target.canonical_coordinates(),
        constraint_combining_challenge_coordinates: constraint_combining_challenge
            .canonical_coordinates(),
        equality_point_coordinates: equality_point
            .iter()
            .map(|coordinate| coordinate.canonical_coordinates())
            .collect::<Vec<_>>()
            .into_boxed_slice(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(value: u64) -> CompactChallengeField {
        CompactChallengeField::from_u64(value)
    }

    fn valid_root_event(
        residuals: Vec<CompactChallengeField>,
        equality_point: Vec<CompactChallengeField>,
    ) -> (
        CompactChallengeField,
        Vec<CompactChallengeField>,
        CompactChallengeField,
        Vec<CompactChallengeField>,
    ) {
        let residual_at_point = independent_multilinear_evaluation(&residuals, &equality_point)
            .expect("the fixture residual geometry is valid");
        assert_ne!(residual_at_point, CompactChallengeField::ZERO);
        let combining_challenge = field(17);
        let auxiliary_difference = -combining_challenge * residual_at_point;
        (
            auxiliary_difference,
            residuals,
            combining_challenge,
            equality_point,
        )
    }

    #[test]
    fn selected_compiler_and_contract_derive_the_initial_transition_lemma() {
        let lemma = derive_selected_compact_cfw_initial_transition_lemma()
            .expect("the selected initial-transition lemma derives");

        assert_eq!(lemma.initial_verifier_move_ordinal, 2);
        assert_eq!(lemma.equality_coordinate_count, 23);
        assert_eq!(lemma.polynomial_variable_count, 24);
        assert_eq!(lemma.maximum_total_degree, 24);
        assert_eq!(lemma.soundness_numerator, 24);
        assert_eq!(PROOF_CHALLENGE_EXTENSION_DEGREE, 5);
        assert_eq!(
            lemma.challenge_field_cardinality,
            BigUint::from(PROOF_BASE_FIELD_MODULUS).pow(
                u32::try_from(PROOF_CHALLENGE_EXTENSION_DEGREE)
                    .expect("the selected extension degree fits u32"),
            ),
        );
        assert_eq!(lemma.preceding_prover_response_ordinal, 5);
        assert_eq!(lemma.preceding_commitment_count, 5);
        assert_ne!(
            lemma.selected_contract_source_hash,
            Hash512::from_bytes([0_u8; Hash512::BYTE_LENGTH]),
        );
    }

    #[test]
    fn independent_bad_event_oracle_covers_boolean_basis_order_and_dense_residuals() {
        for (residuals, equality_point) in [
            (
                vec![field(1), field(0), field(0), field(0)],
                vec![field(2), field(3)],
            ),
            (
                vec![field(0), field(1), field(0), field(0)],
                vec![field(2), field(3)],
            ),
            (
                vec![field(0), field(0), field(1), field(0)],
                vec![field(2), field(3)],
            ),
            (
                vec![field(1), field(2), field(3), field(5)],
                vec![field(7), field(11)],
            ),
        ] {
            let (difference, residuals, challenge, point) =
                valid_root_event(residuals, equality_point);
            assert_eq!(
                verify_compact_cfw_initial_transition_bad_event(
                    difference, &residuals, challenge, &point,
                ),
                Ok(3),
            );
        }
    }

    #[test]
    fn independent_bad_event_oracle_rejects_every_semantic_fault_category() {
        let (difference, residuals, challenge, point) = valid_root_event(
            vec![field(1), field(2), field(3), field(5)],
            vec![field(7), field(11)],
        );

        assert_eq!(
            verify_compact_cfw_initial_transition_bad_event(
                difference,
                &residuals[..3],
                challenge,
                &point,
            ),
            Err(CompactCfwInitialTransitionError::InvalidResidualGeometry),
        );
        assert_eq!(
            verify_compact_cfw_initial_transition_bad_event(
                CompactChallengeField::ZERO,
                &[CompactChallengeField::ZERO; 4],
                challenge,
                &point,
            ),
            Err(CompactCfwInitialTransitionError::ZeroPolynomial),
        );
        for (changed_difference, changed_residuals, changed_challenge, changed_point) in [
            (
                difference + field(1),
                residuals.clone(),
                challenge,
                point.clone(),
            ),
            (
                difference,
                {
                    let mut changed = residuals.clone();
                    changed[2] += field(1);
                    changed
                },
                challenge,
                point.clone(),
            ),
            (
                difference,
                residuals.clone(),
                challenge + field(1),
                point.clone(),
            ),
            (
                difference,
                residuals.clone(),
                challenge,
                vec![point[0] + field(1), point[1]],
            ),
        ] {
            assert_eq!(
                verify_compact_cfw_initial_transition_bad_event(
                    changed_difference,
                    &changed_residuals,
                    changed_challenge,
                    &changed_point,
                ),
                Err(CompactCfwInitialTransitionError::IdentityDoesNotVanish),
            );
        }
    }
}
