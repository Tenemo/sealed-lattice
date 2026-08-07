//! Executable semantic states for the two verifier moves preceding CFW.
//!
//! Both owners consume the committed-code witnesses that the production
//! transcript actually binds. The lookup owner reads quotient values and table
//! multiplicities from the pre-challenge source commitment and keeps only the
//! challenge-dependent inverses as additional knowledge. The cross-epoch owner
//! checks the pre-challenge source against the copied prefix of the main CFW
//! source and reads both masking coefficients from the shared two-column mask
//! commitment. Every backward extractor reruns the selected canonical decoder;
//! no producer verdict or uncommitted idealized coefficient vector is trusted.

use super::*;
use crate::bgv::proof_suite::ProofBaseFieldElement;
use crate::bgv::proof_suite::compact_public_key_static_catalog::{
    GOLDILOCKS_BASE_FIELD_MODULUS, MaskGroupRole,
};
use crate::bgv::proof_suite::relation_plan::{
    CompactLookupRelationGeometry, CompactPublicKeyRelationCatalog,
};

/// One authoritative view of the production lookup and cross-epoch
/// coefficient ranges.
///
/// This adapter is derived from the compiled relation catalog. It is consumed
/// by the semantic state machine below, so the lookup inverses cannot be passed
/// as a free-standing idealized vector: they are sliced from the same complete
/// main witness that CFW and the cross-epoch copy relation consume.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct SemanticProductionOuterLayout {
    source_first_element: usize,
    source_element_count: usize,
    multiplicity_first_element: usize,
    table_value_count: usize,
    inverse_first_element: usize,
    inverse_element_count: usize,
    pre_challenge_message_element_count: usize,
    main_message_element_count: usize,
    soundness_numerator: u64,
}

impl SemanticProductionOuterLayout {
    pub(super) fn from_relation(
        relation: &CompactPublicKeyRelationCatalog,
    ) -> Result<Self, SemanticOuterError> {
        let geometry = relation
            .lookup_relation_geometry()
            .map_err(|_| SemanticOuterError::InvalidGeometry)?;
        Self::from_geometry(geometry)
    }

    fn from_geometry(geometry: CompactLookupRelationGeometry) -> Result<Self, SemanticOuterError> {
        if !geometry.challenge_excludes_base_subfield() {
            return Err(SemanticOuterError::InvalidGeometry);
        }
        Self::new(
            usize::try_from(geometry.source_first_element())
                .map_err(|_| SemanticOuterError::ArithmeticOverflow)?,
            usize::try_from(geometry.source_element_count())
                .map_err(|_| SemanticOuterError::ArithmeticOverflow)?,
            usize::try_from(geometry.multiplicity_first_element())
                .map_err(|_| SemanticOuterError::ArithmeticOverflow)?,
            usize::try_from(geometry.table_value_count())
                .map_err(|_| SemanticOuterError::ArithmeticOverflow)?,
            usize::try_from(geometry.inverse_first_element())
                .map_err(|_| SemanticOuterError::ArithmeticOverflow)?,
            usize::try_from(geometry.inverse_element_count())
                .map_err(|_| SemanticOuterError::ArithmeticOverflow)?,
            usize::try_from(geometry.pre_challenge_message_element_count())
                .map_err(|_| SemanticOuterError::ArithmeticOverflow)?,
            usize::try_from(geometry.main_message_element_count())
                .map_err(|_| SemanticOuterError::ArithmeticOverflow)?,
            geometry.soundness_numerator(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        source_first_element: usize,
        source_element_count: usize,
        multiplicity_first_element: usize,
        table_value_count: usize,
        inverse_first_element: usize,
        inverse_element_count: usize,
        pre_challenge_message_element_count: usize,
        main_message_element_count: usize,
        soundness_numerator: u64,
    ) -> Result<Self, SemanticOuterError> {
        let occupied_pre_challenge_element_count = source_element_count
            .checked_add(table_value_count)
            .ok_or(SemanticOuterError::ArithmeticOverflow)?;
        let expected_soundness_numerator = occupied_pre_challenge_element_count
            .checked_sub(1)
            .and_then(|count| u64::try_from(count).ok())
            .ok_or(SemanticOuterError::ArithmeticOverflow)?;
        let inverse_end = inverse_first_element
            .checked_add(inverse_element_count)
            .ok_or(SemanticOuterError::ArithmeticOverflow)?;
        if source_first_element != 0
            || source_element_count == 0
            || multiplicity_first_element != source_element_count
            || table_value_count == 0
            || inverse_element_count != source_element_count
            || occupied_pre_challenge_element_count > pre_challenge_message_element_count
            || !pre_challenge_message_element_count.is_power_of_two()
            || pre_challenge_message_element_count
                .checked_mul(2)
                .is_none_or(|expected| expected != main_message_element_count)
            || inverse_end > main_message_element_count
            || expected_soundness_numerator != soundness_numerator
        {
            return Err(SemanticOuterError::InvalidGeometry);
        }
        Ok(Self {
            source_first_element,
            source_element_count,
            multiplicity_first_element,
            table_value_count,
            inverse_first_element,
            inverse_element_count,
            pre_challenge_message_element_count,
            main_message_element_count,
            soundness_numerator,
        })
    }

    pub(super) const fn source_element_count(self) -> usize {
        self.source_element_count
    }

    pub(super) const fn table_value_count(self) -> usize {
        self.table_value_count
    }

    pub(super) const fn soundness_numerator(self) -> u64 {
        self.soundness_numerator
    }

    pub(super) fn variable_count(self) -> usize {
        self.pre_challenge_message_element_count.ilog2() as usize
    }
}

#[derive(Clone, Debug)]
pub(super) struct SemanticProductionOuterStatement {
    layout: SemanticProductionOuterLayout,
    pre_challenge_source_relation: CommittedCodeRelation,
    main_source_relation: CommittedCodeRelation,
    shared_mask_relation: CommittedMaskCodeRelation,
}

impl SemanticProductionOuterStatement {
    pub(super) fn new(
        layout: SemanticProductionOuterLayout,
        pre_challenge_source_relation: CommittedCodeRelation,
        main_source_relation: CommittedCodeRelation,
        shared_mask_relation: CommittedMaskCodeRelation,
    ) -> Result<Self, SemanticOuterError> {
        if committed_message_element_count(&pre_challenge_source_relation)?
            != layout.pre_challenge_message_element_count
            || committed_message_element_count(&main_source_relation)?
                != layout.main_message_element_count
            || shared_mask_relation.role != MaskGroupRole::CrossEpochOpening
            || committed_message_element_count(&shared_mask_relation.code)? != 2
        {
            return Err(SemanticOuterError::InvalidGeometry);
        }
        Ok(Self {
            layout,
            pre_challenge_source_relation,
            main_source_relation,
            shared_mask_relation,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SemanticProductionOuterWitness {
    pub(super) pre_challenge_source: SemanticCommittedCodeWitness,
    pub(super) main_source: SemanticCommittedCodeWitness,
    pub(super) shared_masks: SemanticCommittedCodeWitness,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SemanticProductionOuterCommitments {
    pub(super) pre_challenge_source: SemanticCommittedCodeInstance,
    pub(super) main_source: SemanticCommittedCodeInstance,
    pub(super) shared_masks: SemanticCommittedCodeInstance,
}

/// Canonical semantic prefixes for the two verifier moves before CFW.
///
/// Instances enter only at their prover-message boundary. In particular the
/// cross-epoch point prefix contains no evaluation disclosures; those belong
/// to the following prover move.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum SemanticProductionOuterPrefix {
    Empty,
    PreChallengeSourceCommitted {
        pre_challenge_source: SemanticCommittedCodeInstance,
    },
    LookupChallengeSampled {
        pre_challenge_source: SemanticCommittedCodeInstance,
        lookup_challenge: ProofChallengeExtensionElement,
    },
    PostLookupCommitments {
        commitments: SemanticProductionOuterCommitments,
        lookup_challenge: ProofChallengeExtensionElement,
    },
    CrossEpochPointSampled {
        commitments: SemanticProductionOuterCommitments,
        lookup_challenge: ProofChallengeExtensionElement,
        point: Vec<ProofChallengeExtensionElement>,
    },
    CrossEpochDisclosuresSent {
        commitments: SemanticProductionOuterCommitments,
        lookup_challenge: ProofChallengeExtensionElement,
        point: Vec<ProofChallengeExtensionElement>,
        disclosures: SemanticCrossEpochDisclosures,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SemanticProductionOuterExtraction {
    pub(super) witness: Option<SemanticProductionOuterWitness>,
    pub(super) field_operation_count: u128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum SemanticProductionOuterBadTransition {
    Lookup(SemanticLookupBadTransition),
    CrossEpoch(SemanticCrossEpochBadTransition),
}

#[derive(Clone, Debug)]
pub(super) struct SemanticLookupStatement {
    source_relation: CommittedCodeRelation,
    source_instance: SemanticCommittedCodeInstance,
    source_element_count: usize,
    table_value_count: usize,
}

impl SemanticLookupStatement {
    pub(super) fn new(
        source_relation: CommittedCodeRelation,
        source_instance: SemanticCommittedCodeInstance,
        source_element_count: usize,
        table_value_count: usize,
    ) -> Result<Self, SemanticOuterError> {
        if source_element_count == 0
            || table_value_count == 0
            || u64::try_from(source_element_count)
                .ok()
                .is_none_or(|count| count >= GOLDILOCKS_BASE_FIELD_MODULUS)
            || u64::try_from(table_value_count)
                .ok()
                .is_none_or(|count| count >= GOLDILOCKS_BASE_FIELD_MODULUS)
        {
            return Err(SemanticOuterError::InvalidGeometry);
        }
        let message_element_count = committed_message_element_count(&source_relation)?;
        let occupied_element_count = source_element_count
            .checked_add(table_value_count)
            .ok_or(SemanticOuterError::ArithmeticOverflow)?;
        if occupied_element_count > message_element_count {
            return Err(SemanticOuterError::InvalidGeometry);
        }
        validate_committed_instance_shape(&source_relation, &source_instance)?;
        Ok(Self {
            source_relation,
            source_instance,
            source_element_count,
            table_value_count,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SemanticLookupWitness {
    pub(super) pre_challenge_source: SemanticCommittedCodeWitness,
    pub(super) source_inverse_values: Vec<ProofChallengeExtensionElement>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct SemanticLookupPrefix {
    pub(super) lookup_challenge: Option<ProofChallengeExtensionElement>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum SemanticLookupMultiplicityDifference {
    SourceValueOutsideTable {
        source_ordinal: usize,
        value: ProofBaseFieldElement,
    },
    TableMultiplicity {
        table_value: usize,
        actual: ProofBaseFieldElement,
        claimed: ProofBaseFieldElement,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SemanticLookupBadTransition {
    pub(super) lookup_challenge: ProofChallengeExtensionElement,
    pub(super) source_element_count: usize,
    pub(super) table_entry_count: usize,
    pub(super) first_multiplicity_difference: SemanticLookupMultiplicityDifference,
}

impl SemanticLookupBadTransition {
    /// Degree bound after clearing the source and table denominators.
    pub(super) fn exact_error_numerator(&self) -> Result<u64, SemanticOuterError> {
        self.source_element_count
            .checked_add(self.table_entry_count)
            .and_then(|count| count.checked_sub(1))
            .and_then(|count| u64::try_from(count).ok())
            .ok_or(SemanticOuterError::ArithmeticOverflow)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SemanticLookupExtraction {
    pub(super) witness: Option<SemanticLookupWitness>,
    pub(super) field_operation_count: u128,
}

pub(super) fn semantic_lookup_kstate(
    statement: &SemanticLookupStatement,
    prefix: Option<&SemanticLookupPrefix>,
    witness: &SemanticLookupWitness,
) -> Result<bool, SemanticOuterError> {
    let (source_values, claimed_table_multiplicities) =
        match lookup_message_parts(statement, witness) {
            Ok(message_parts) => message_parts,
            Err(
                SemanticOuterError::WitnessOutsideDecodingRadius
                | SemanticOuterError::NonBaseLookupCoefficient
                | SemanticOuterError::NoncanonicalPadding
                | SemanticOuterError::Relation(SemanticRelationError::MalformedWitness),
            ) => return Ok(false),
            Err(error) => return Err(error),
        };
    let lookup_challenge = prefix.and_then(|prefix| prefix.lookup_challenge);
    let Some(lookup_challenge) = lookup_challenge else {
        return Ok(witness.source_inverse_values.is_empty()
            && first_lookup_multiplicity_difference(
                statement.table_value_count,
                &source_values,
                &claimed_table_multiplicities,
            )?
            .is_none());
    };
    if lookup_challenge_is_in_base_subfield(lookup_challenge) {
        return Err(SemanticOuterError::MalformedPrefix);
    }
    if witness.source_inverse_values.len() != statement.source_element_count {
        return Ok(false);
    }
    let mut source_reciprocal_sum = ProofChallengeExtensionElement::ZERO;
    for (&source_value, &inverse) in source_values.iter().zip(&witness.source_inverse_values) {
        let denominator =
            lookup_challenge.add(ProofChallengeExtensionElement::from_base(source_value));
        if denominator.multiply(inverse) != ProofChallengeExtensionElement::ONE {
            return Ok(false);
        }
        source_reciprocal_sum = source_reciprocal_sum.add(inverse);
    }
    let mut weighted_table_reciprocal_sum = ProofChallengeExtensionElement::ZERO;
    for (table_value, &multiplicity) in claimed_table_multiplicities.iter().enumerate() {
        let denominator = lookup_challenge.add(ProofChallengeExtensionElement::from_base(
            canonical_base_element(table_value)?,
        ));
        let reciprocal = denominator
            .inverse()
            .map_err(|_| SemanticOuterError::InvalidGeometry)?;
        weighted_table_reciprocal_sum =
            weighted_table_reciprocal_sum.add(reciprocal.multiply_base(multiplicity));
    }
    Ok(source_reciprocal_sum == weighted_table_reciprocal_sum)
}

pub(super) fn semantic_lookup_errbr(
    statement: &SemanticLookupStatement,
    extended_prefix: &SemanticLookupPrefix,
    _post_challenge_witness: &SemanticLookupWitness,
) -> Result<SemanticLookupExtraction, SemanticOuterError> {
    if extended_prefix.lookup_challenge.is_none() {
        return Err(SemanticOuterError::MalformedPrefix);
    }
    let (decoded_source, field_operation_count) = match extract_semantic_committed_code_witness(
        &statement.source_relation,
        &statement.source_instance,
    ) {
        Ok(decoded) => decoded,
        Err(SemanticRelationError::CodeCorrection(_)) => {
            return Ok(SemanticLookupExtraction {
                witness: None,
                field_operation_count: 0,
            });
        }
        Err(error) => return Err(error.into()),
    };
    let preceding_witness = SemanticLookupWitness {
        pre_challenge_source: decoded_source,
        source_inverse_values: Vec::new(),
    };
    Ok(SemanticLookupExtraction {
        witness: Some(preceding_witness),
        field_operation_count,
    })
}

pub(super) fn semantic_lookup_bad_transition(
    statement: &SemanticLookupStatement,
    extended_prefix: &SemanticLookupPrefix,
    post_challenge_witness: &SemanticLookupWitness,
) -> Result<Option<SemanticLookupBadTransition>, SemanticOuterError> {
    let lookup_challenge = extended_prefix
        .lookup_challenge
        .ok_or(SemanticOuterError::MalformedPrefix)?;
    if !semantic_lookup_kstate(statement, Some(extended_prefix), post_challenge_witness)? {
        return Ok(None);
    }
    let (decoded_source, _) = extract_semantic_committed_code_witness(
        &statement.source_relation,
        &statement.source_instance,
    )?;
    if decoded_source != post_challenge_witness.pre_challenge_source {
        return Err(SemanticOuterError::InconsistentBadTransition);
    }
    let preceding_witness = SemanticLookupWitness {
        pre_challenge_source: decoded_source,
        source_inverse_values: Vec::new(),
    };
    if semantic_lookup_kstate(statement, None, &preceding_witness)? {
        return Ok(None);
    }
    let (source_values, claimed_table_multiplicities) =
        lookup_message_parts(statement, &preceding_witness)?;
    let first_multiplicity_difference = first_lookup_multiplicity_difference(
        statement.table_value_count,
        &source_values,
        &claimed_table_multiplicities,
    )?
    .ok_or(SemanticOuterError::InconsistentBadTransition)?;
    Ok(Some(SemanticLookupBadTransition {
        lookup_challenge,
        source_element_count: statement.source_element_count,
        table_entry_count: statement.table_value_count,
        first_multiplicity_difference,
    }))
}

fn lookup_message_parts(
    statement: &SemanticLookupStatement,
    witness: &SemanticLookupWitness,
) -> Result<(Vec<ProofBaseFieldElement>, Vec<ProofBaseFieldElement>), SemanticOuterError> {
    if !semantic_committed_code_relation_holds(
        &statement.source_relation,
        &statement.source_instance,
        &witness.pre_challenge_source,
    )? {
        return Err(SemanticOuterError::WitnessOutsideDecodingRadius);
    }
    let flattened = flattened_base_messages(&witness.pre_challenge_source)?;
    let multiplicity_end = statement
        .source_element_count
        .checked_add(statement.table_value_count)
        .ok_or(SemanticOuterError::ArithmeticOverflow)?;
    let source_values = flattened
        .get(..statement.source_element_count)
        .ok_or(SemanticOuterError::InvalidGeometry)?
        .to_vec();
    let claimed_table_multiplicities = flattened
        .get(statement.source_element_count..multiplicity_end)
        .ok_or(SemanticOuterError::InvalidGeometry)?
        .to_vec();
    if flattened[multiplicity_end..]
        .iter()
        .any(|value| *value != ProofBaseFieldElement::ZERO)
    {
        return Err(SemanticOuterError::NoncanonicalPadding);
    }
    Ok((source_values, claimed_table_multiplicities))
}

fn first_lookup_multiplicity_difference(
    table_value_count: usize,
    source_values: &[ProofBaseFieldElement],
    claimed_table_multiplicities: &[ProofBaseFieldElement],
) -> Result<Option<SemanticLookupMultiplicityDifference>, SemanticOuterError> {
    if claimed_table_multiplicities.len() != table_value_count {
        return Err(SemanticOuterError::InvalidGeometry);
    }
    let mut actual_multiplicities = vec![0_usize; table_value_count];
    for (source_ordinal, &value) in source_values.iter().enumerate() {
        let canonical = value.canonical();
        let Ok(table_value) = usize::try_from(canonical) else {
            return Ok(Some(
                SemanticLookupMultiplicityDifference::SourceValueOutsideTable {
                    source_ordinal,
                    value,
                },
            ));
        };
        let Some(multiplicity) = actual_multiplicities.get_mut(table_value) else {
            return Ok(Some(
                SemanticLookupMultiplicityDifference::SourceValueOutsideTable {
                    source_ordinal,
                    value,
                },
            ));
        };
        *multiplicity = multiplicity
            .checked_add(1)
            .ok_or(SemanticOuterError::ArithmeticOverflow)?;
    }
    for (table_value, (&actual, &claimed)) in actual_multiplicities
        .iter()
        .zip(claimed_table_multiplicities)
        .enumerate()
    {
        let actual = canonical_base_element(actual)?;
        if actual != claimed {
            return Ok(Some(
                SemanticLookupMultiplicityDifference::TableMultiplicity {
                    table_value,
                    actual,
                    claimed,
                },
            ));
        }
    }
    Ok(None)
}

fn lookup_challenge_is_in_base_subfield(challenge: ProofChallengeExtensionElement) -> bool {
    challenge.canonical_coordinates()[1..]
        .iter()
        .all(|coordinate| *coordinate == 0)
}

fn canonical_base_element(value: usize) -> Result<ProofBaseFieldElement, SemanticOuterError> {
    ProofBaseFieldElement::from_canonical(
        u64::try_from(value).map_err(|_| SemanticOuterError::ArithmeticOverflow)?,
    )
    .map_err(|_| SemanticOuterError::InvalidGeometry)
}

#[derive(Clone, Debug)]
pub(super) struct SemanticCrossEpochStatement {
    pre_challenge_source_relation: CommittedCodeRelation,
    pre_challenge_source_instance: SemanticCommittedCodeInstance,
    main_source_relation: CommittedCodeRelation,
    main_source_instance: SemanticCommittedCodeInstance,
    mask_relation: CommittedMaskCodeRelation,
    mask_instance: SemanticCommittedCodeInstance,
    variable_count: usize,
    copied_message_element_count: usize,
}

impl SemanticCrossEpochStatement {
    pub(super) fn new(
        pre_challenge_source_relation: CommittedCodeRelation,
        pre_challenge_source_instance: SemanticCommittedCodeInstance,
        main_source_relation: CommittedCodeRelation,
        main_source_instance: SemanticCommittedCodeInstance,
        mask_relation: CommittedMaskCodeRelation,
        mask_instance: SemanticCommittedCodeInstance,
        variable_count: usize,
    ) -> Result<Self, SemanticOuterError> {
        if variable_count == 0 || variable_count >= usize::BITS as usize {
            return Err(SemanticOuterError::InvalidGeometry);
        }
        let copied_message_element_count = 1_usize
            .checked_shl(
                u32::try_from(variable_count)
                    .map_err(|_| SemanticOuterError::ArithmeticOverflow)?,
            )
            .ok_or(SemanticOuterError::ArithmeticOverflow)?;
        if committed_message_element_count(&pre_challenge_source_relation)?
            != copied_message_element_count
            || committed_message_element_count(&main_source_relation)?
                < copied_message_element_count
            || mask_relation.role != MaskGroupRole::CrossEpochOpening
            || committed_message_element_count(&mask_relation.code)? != 2
        {
            return Err(SemanticOuterError::InvalidGeometry);
        }
        validate_committed_instance_shape(
            &pre_challenge_source_relation,
            &pre_challenge_source_instance,
        )?;
        validate_committed_instance_shape(&main_source_relation, &main_source_instance)?;
        validate_committed_instance_shape(&mask_relation.code, &mask_instance)?;
        Ok(Self {
            pre_challenge_source_relation,
            pre_challenge_source_instance,
            main_source_relation,
            main_source_instance,
            mask_relation,
            mask_instance,
            variable_count,
            copied_message_element_count,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SemanticCrossEpochWitness {
    pub(super) pre_challenge_source: SemanticCommittedCodeWitness,
    pub(super) main_source: SemanticCommittedCodeWitness,
    pub(super) shared_masks: SemanticCommittedCodeWitness,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct SemanticCrossEpochDisclosures {
    pub(super) masked_pre_challenge_evaluation: ProofChallengeExtensionElement,
    pub(super) masked_main_evaluation: ProofChallengeExtensionElement,
    pub(super) mask_difference: ProofChallengeExtensionElement,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SemanticCrossEpochPrefix {
    pub(super) point: Option<Vec<ProofChallengeExtensionElement>>,
    pub(super) disclosures: Option<SemanticCrossEpochDisclosures>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SemanticCrossEpochBadTransition {
    pub(super) nonzero_difference_evaluations: Vec<ProofChallengeExtensionElement>,
    pub(super) point: Vec<ProofChallengeExtensionElement>,
}

impl SemanticCrossEpochBadTransition {
    pub(super) fn exact_error_numerator(&self) -> Result<u64, SemanticOuterError> {
        u64::try_from(self.point.len()).map_err(|_| SemanticOuterError::ArithmeticOverflow)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SemanticCrossEpochExtraction {
    pub(super) witness: Option<SemanticCrossEpochWitness>,
    pub(super) field_operation_count: u128,
}

pub(super) fn semantic_cross_epoch_kstate(
    statement: &SemanticCrossEpochStatement,
    prefix: Option<&SemanticCrossEpochPrefix>,
    witness: &SemanticCrossEpochWitness,
) -> Result<bool, SemanticOuterError> {
    let (pre_challenge_coefficients, main_copied_prefix, masks) =
        match cross_epoch_message_parts(statement, witness) {
            Ok(message_parts) => message_parts,
            Err(
                SemanticOuterError::WitnessOutsideDecodingRadius
                | SemanticOuterError::Relation(SemanticRelationError::MalformedWitness),
            ) => return Ok(false),
            Err(error) => return Err(error),
        };
    let Some(prefix) = prefix else {
        return Ok(pre_challenge_coefficients == main_copied_prefix);
    };
    let Some(point) = &prefix.point else {
        if prefix.disclosures.is_none() {
            return Ok(pre_challenge_coefficients == main_copied_prefix);
        }
        return Err(SemanticOuterError::MalformedPrefix);
    };
    if point.len() != statement.variable_count {
        return Err(SemanticOuterError::MalformedPrefix);
    }
    let pre_challenge_evaluation = multilinear_evaluation(&pre_challenge_coefficients, point)?;
    let main_evaluation = multilinear_evaluation(&main_copied_prefix, point)?;
    let point_equality_holds = pre_challenge_evaluation == main_evaluation;
    let Some(disclosures) = prefix.disclosures else {
        // This is the exact post-verifier state. The three masked values are
        // sent only by the following prover move, so they cannot be consulted
        // while proving the cross-epoch verifier transition.
        return Ok(point_equality_holds);
    };
    let [pre_challenge_mask, main_mask]: [ProofChallengeExtensionElement; 2] = masks
        .try_into()
        .map_err(|_| SemanticOuterError::InvalidGeometry)?;
    Ok(point_equality_holds
        && disclosures.masked_pre_challenge_evaluation
            == pre_challenge_evaluation.add(pre_challenge_mask)
        && disclosures.masked_main_evaluation == main_evaluation.add(main_mask)
        && disclosures.mask_difference == pre_challenge_mask.subtract(main_mask)
        && disclosures
            .masked_pre_challenge_evaluation
            .subtract(disclosures.masked_main_evaluation)
            .subtract(disclosures.mask_difference)
            .is_zero())
}

pub(super) fn semantic_cross_epoch_errbr(
    statement: &SemanticCrossEpochStatement,
    extended_prefix: &SemanticCrossEpochPrefix,
    _post_challenge_witness: &SemanticCrossEpochWitness,
) -> Result<SemanticCrossEpochExtraction, SemanticOuterError> {
    if extended_prefix.point.is_none() || extended_prefix.disclosures.is_some() {
        return Err(SemanticOuterError::MalformedPrefix);
    }
    let Some((decoded, field_operation_count)) = decode_cross_epoch_witness(statement)? else {
        return Ok(SemanticCrossEpochExtraction {
            witness: None,
            field_operation_count: 0,
        });
    };
    Ok(SemanticCrossEpochExtraction {
        witness: Some(decoded),
        field_operation_count,
    })
}

pub(super) fn semantic_cross_epoch_bad_transition(
    statement: &SemanticCrossEpochStatement,
    extended_prefix: &SemanticCrossEpochPrefix,
    post_challenge_witness: &SemanticCrossEpochWitness,
) -> Result<Option<SemanticCrossEpochBadTransition>, SemanticOuterError> {
    if extended_prefix.point.is_none() || extended_prefix.disclosures.is_some() {
        return Err(SemanticOuterError::MalformedPrefix);
    }
    if !semantic_cross_epoch_kstate(statement, Some(extended_prefix), post_challenge_witness)? {
        return Ok(None);
    }
    let (decoded, _) = decode_cross_epoch_witness(statement)?
        .ok_or(SemanticOuterError::InconsistentBadTransition)?;
    if decoded != *post_challenge_witness {
        return Err(SemanticOuterError::InconsistentBadTransition);
    }
    if semantic_cross_epoch_kstate(statement, None, &decoded)? {
        return Ok(None);
    }
    let (pre_challenge_coefficients, main_copied_prefix, _) =
        cross_epoch_message_parts(statement, &decoded)?;
    let point = extended_prefix
        .point
        .as_ref()
        .ok_or(SemanticOuterError::MalformedPrefix)?
        .clone();
    let nonzero_difference_evaluations = pre_challenge_coefficients
        .iter()
        .zip(main_copied_prefix)
        .map(|(&pre_challenge, main)| pre_challenge.subtract(main))
        .collect::<Vec<_>>();
    if nonzero_difference_evaluations
        .iter()
        .all(|difference| difference.is_zero())
        || !multilinear_evaluation(&nonzero_difference_evaluations, &point)?.is_zero()
    {
        return Err(SemanticOuterError::InconsistentBadTransition);
    }
    Ok(Some(SemanticCrossEpochBadTransition {
        nonzero_difference_evaluations,
        point,
    }))
}

fn cross_epoch_message_parts(
    statement: &SemanticCrossEpochStatement,
    witness: &SemanticCrossEpochWitness,
) -> Result<
    (
        Vec<ProofChallengeExtensionElement>,
        Vec<ProofChallengeExtensionElement>,
        Vec<ProofChallengeExtensionElement>,
    ),
    SemanticOuterError,
> {
    for (relation, instance, code_witness) in [
        (
            &statement.pre_challenge_source_relation,
            &statement.pre_challenge_source_instance,
            &witness.pre_challenge_source,
        ),
        (
            &statement.main_source_relation,
            &statement.main_source_instance,
            &witness.main_source,
        ),
        (
            &statement.mask_relation.code,
            &statement.mask_instance,
            &witness.shared_masks,
        ),
    ] {
        if !semantic_committed_code_relation_holds(relation, instance, code_witness)? {
            return Err(SemanticOuterError::WitnessOutsideDecodingRadius);
        }
    }
    let pre_challenge_coefficients = witness.pre_challenge_source.flattened_messages();
    let main_message = witness.main_source.flattened_messages();
    let main_copied_prefix = main_message
        .get(..statement.copied_message_element_count)
        .ok_or(SemanticOuterError::InvalidGeometry)?
        .to_vec();
    let masks = witness.shared_masks.flattened_messages();
    if pre_challenge_coefficients.len() != statement.copied_message_element_count
        || masks.len() != 2
    {
        return Err(SemanticOuterError::InvalidGeometry);
    }
    Ok((pre_challenge_coefficients, main_copied_prefix, masks))
}

fn decode_cross_epoch_witness(
    statement: &SemanticCrossEpochStatement,
) -> Result<Option<(SemanticCrossEpochWitness, u128)>, SemanticOuterError> {
    let mut field_operation_count = 0_u128;
    let mut decode = |relation: &CommittedCodeRelation,
                      instance: &SemanticCommittedCodeInstance|
     -> Result<Option<SemanticCommittedCodeWitness>, SemanticOuterError> {
        match extract_semantic_committed_code_witness(relation, instance) {
            Ok((witness, operation_count)) => {
                field_operation_count = field_operation_count
                    .checked_add(operation_count)
                    .ok_or(SemanticOuterError::ArithmeticOverflow)?;
                Ok(Some(witness))
            }
            Err(SemanticRelationError::CodeCorrection(_)) => Ok(None),
            Err(error) => Err(error.into()),
        }
    };
    let Some(pre_challenge_source) = decode(
        &statement.pre_challenge_source_relation,
        &statement.pre_challenge_source_instance,
    )?
    else {
        return Ok(None);
    };
    let Some(main_source) = decode(
        &statement.main_source_relation,
        &statement.main_source_instance,
    )?
    else {
        return Ok(None);
    };
    let Some(shared_masks) = decode(&statement.mask_relation.code, &statement.mask_instance)?
    else {
        return Ok(None);
    };
    Ok(Some((
        SemanticCrossEpochWitness {
            pre_challenge_source,
            main_source,
            shared_masks,
        },
        field_operation_count,
    )))
}

/// Prefix-wise knowledge state for the complete production outer reduction.
///
/// The empty state is the raw quotient-multiset relation. Each prover prefix
/// only adds constraints to the same witness. A verifier challenge replaces
/// the preceding exact identity by its challenge-selected relaxed relation,
/// which is the only place a bad transition can occur.
pub(super) fn semantic_production_outer_kstate(
    statement: &SemanticProductionOuterStatement,
    prefix: &SemanticProductionOuterPrefix,
    witness: &SemanticProductionOuterWitness,
) -> Result<bool, SemanticOuterError> {
    match prefix {
        SemanticProductionOuterPrefix::Empty => {
            production_lookup_input_relation_holds(statement, witness)
        }
        SemanticProductionOuterPrefix::PreChallengeSourceCommitted {
            pre_challenge_source,
        } => {
            if !production_lookup_input_relation_holds(statement, witness)? {
                return Ok(false);
            }
            semantic_committed_code_relation_holds(
                &statement.pre_challenge_source_relation,
                pre_challenge_source,
                &witness.pre_challenge_source,
            )
            .map_err(Into::into)
        }
        SemanticProductionOuterPrefix::LookupChallengeSampled {
            pre_challenge_source,
            lookup_challenge,
        } => production_lookup_post_state_holds(
            statement,
            pre_challenge_source,
            *lookup_challenge,
            witness,
        ),
        SemanticProductionOuterPrefix::PostLookupCommitments {
            commitments,
            lookup_challenge,
        } => production_post_lookup_state_holds(
            statement,
            commitments,
            *lookup_challenge,
            None,
            witness,
        ),
        SemanticProductionOuterPrefix::CrossEpochPointSampled {
            commitments,
            lookup_challenge,
            point,
        } => production_post_lookup_state_holds(
            statement,
            commitments,
            *lookup_challenge,
            Some(&SemanticCrossEpochPrefix {
                point: Some(point.clone()),
                disclosures: None,
            }),
            witness,
        ),
        SemanticProductionOuterPrefix::CrossEpochDisclosuresSent {
            commitments,
            lookup_challenge,
            point,
            disclosures,
        } => production_post_lookup_state_holds(
            statement,
            commitments,
            *lookup_challenge,
            Some(&SemanticCrossEpochPrefix {
                point: Some(point.clone()),
                disclosures: Some(*disclosures),
            }),
            witness,
        ),
    }
}

/// Deterministic `ERRBR` at either outer verifier move.
pub(super) fn semantic_production_outer_errbr(
    statement: &SemanticProductionOuterStatement,
    extended_prefix: &SemanticProductionOuterPrefix,
    post_challenge_witness: &SemanticProductionOuterWitness,
) -> Result<SemanticProductionOuterExtraction, SemanticOuterError> {
    match extended_prefix {
        SemanticProductionOuterPrefix::LookupChallengeSampled {
            pre_challenge_source,
            lookup_challenge,
        } => {
            let lookup_statement =
                production_lookup_statement(statement, pre_challenge_source.clone())?;
            let lookup_witness = production_lookup_witness(statement, post_challenge_witness)?;
            let extraction = semantic_lookup_errbr(
                &lookup_statement,
                &SemanticLookupPrefix {
                    lookup_challenge: Some(*lookup_challenge),
                },
                &lookup_witness,
            )?;
            let Some(preceding_lookup_witness) = extraction.witness else {
                return Ok(SemanticProductionOuterExtraction {
                    witness: None,
                    field_operation_count: extraction.field_operation_count,
                });
            };
            let preceding_witness = SemanticProductionOuterWitness {
                pre_challenge_source: preceding_lookup_witness.pre_challenge_source,
                main_source: post_challenge_witness.main_source.clone(),
                shared_masks: post_challenge_witness.shared_masks.clone(),
            };
            Ok(SemanticProductionOuterExtraction {
                witness: Some(preceding_witness),
                field_operation_count: extraction.field_operation_count,
            })
        }
        SemanticProductionOuterPrefix::CrossEpochPointSampled {
            commitments,
            lookup_challenge: _,
            point,
        } => {
            let cross_statement = production_cross_epoch_statement(statement, commitments)?;
            let cross_witness = production_cross_epoch_witness(post_challenge_witness);
            let extraction = semantic_cross_epoch_errbr(
                &cross_statement,
                &SemanticCrossEpochPrefix {
                    point: Some(point.clone()),
                    disclosures: None,
                },
                &cross_witness,
            )?;
            let Some(preceding_cross_witness) = extraction.witness else {
                return Ok(SemanticProductionOuterExtraction {
                    witness: None,
                    field_operation_count: extraction.field_operation_count,
                });
            };
            let preceding_witness = SemanticProductionOuterWitness {
                pre_challenge_source: preceding_cross_witness.pre_challenge_source,
                main_source: preceding_cross_witness.main_source,
                shared_masks: preceding_cross_witness.shared_masks,
            };
            Ok(SemanticProductionOuterExtraction {
                witness: Some(preceding_witness),
                field_operation_count: extraction.field_operation_count,
            })
        }
        SemanticProductionOuterPrefix::Empty
        | SemanticProductionOuterPrefix::PreChallengeSourceCommitted { .. }
        | SemanticProductionOuterPrefix::PostLookupCommitments { .. }
        | SemanticProductionOuterPrefix::CrossEpochDisclosuresSent { .. } => {
            Err(SemanticOuterError::MalformedPrefix)
        }
    }
}

/// Derives the concrete bad-transition certificate for an outer verifier move.
pub(super) fn semantic_production_outer_bad_transition(
    statement: &SemanticProductionOuterStatement,
    extended_prefix: &SemanticProductionOuterPrefix,
    post_challenge_witness: &SemanticProductionOuterWitness,
) -> Result<Option<SemanticProductionOuterBadTransition>, SemanticOuterError> {
    if !semantic_production_outer_kstate(statement, extended_prefix, post_challenge_witness)? {
        return Ok(None);
    }
    match extended_prefix {
        SemanticProductionOuterPrefix::LookupChallengeSampled {
            pre_challenge_source,
            lookup_challenge,
        } => {
            let lookup_statement =
                production_lookup_statement(statement, pre_challenge_source.clone())?;
            let lookup_witness = production_lookup_witness(statement, post_challenge_witness)?;
            semantic_lookup_bad_transition(
                &lookup_statement,
                &SemanticLookupPrefix {
                    lookup_challenge: Some(*lookup_challenge),
                },
                &lookup_witness,
            )
            .map(|certificate| certificate.map(SemanticProductionOuterBadTransition::Lookup))
        }
        SemanticProductionOuterPrefix::CrossEpochPointSampled {
            commitments, point, ..
        } => semantic_cross_epoch_bad_transition(
            &production_cross_epoch_statement(statement, commitments)?,
            &SemanticCrossEpochPrefix {
                point: Some(point.clone()),
                disclosures: None,
            },
            &production_cross_epoch_witness(post_challenge_witness),
        )
        .map(|certificate| certificate.map(SemanticProductionOuterBadTransition::CrossEpoch)),
        SemanticProductionOuterPrefix::Empty
        | SemanticProductionOuterPrefix::PreChallengeSourceCommitted { .. }
        | SemanticProductionOuterPrefix::PostLookupCommitments { .. }
        | SemanticProductionOuterPrefix::CrossEpochDisclosuresSent { .. } => {
            Err(SemanticOuterError::MalformedPrefix)
        }
    }
}

fn production_lookup_input_relation_holds(
    statement: &SemanticProductionOuterStatement,
    witness: &SemanticProductionOuterWitness,
) -> Result<bool, SemanticOuterError> {
    if witness
        .pre_challenge_source
        .coefficient_columns(&statement.pre_challenge_source_relation)
        .is_err()
    {
        return Ok(false);
    }
    let flattened = match flattened_base_messages(&witness.pre_challenge_source) {
        Ok(flattened) => flattened,
        Err(SemanticOuterError::NonBaseLookupCoefficient) => return Ok(false),
        Err(error) => return Err(error),
    };
    if flattened.len() != statement.layout.pre_challenge_message_element_count {
        return Ok(false);
    }
    let source_end = statement
        .layout
        .source_first_element
        .checked_add(statement.layout.source_element_count)
        .ok_or(SemanticOuterError::ArithmeticOverflow)?;
    let multiplicity_end = statement
        .layout
        .multiplicity_first_element
        .checked_add(statement.layout.table_value_count)
        .ok_or(SemanticOuterError::ArithmeticOverflow)?;
    let source_values = flattened
        .get(statement.layout.source_first_element..source_end)
        .ok_or(SemanticOuterError::InvalidGeometry)?;
    let multiplicities = flattened
        .get(statement.layout.multiplicity_first_element..multiplicity_end)
        .ok_or(SemanticOuterError::InvalidGeometry)?;
    if flattened[multiplicity_end..]
        .iter()
        .any(|value| *value != ProofBaseFieldElement::ZERO)
    {
        return Ok(false);
    }
    Ok(first_lookup_multiplicity_difference(
        statement.layout.table_value_count,
        source_values,
        multiplicities,
    )?
    .is_none())
}

fn production_lookup_statement(
    statement: &SemanticProductionOuterStatement,
    pre_challenge_source: SemanticCommittedCodeInstance,
) -> Result<SemanticLookupStatement, SemanticOuterError> {
    SemanticLookupStatement::new(
        statement.pre_challenge_source_relation.clone(),
        pre_challenge_source,
        statement.layout.source_element_count,
        statement.layout.table_value_count,
    )
}

fn production_lookup_witness(
    statement: &SemanticProductionOuterStatement,
    witness: &SemanticProductionOuterWitness,
) -> Result<SemanticLookupWitness, SemanticOuterError> {
    let expected_width = usize::try_from(statement.main_source_relation.interleaving_width)
        .map_err(|_| SemanticOuterError::ArithmeticOverflow)?;
    let expected_column_length = usize::try_from(statement.main_source_relation.message_length)
        .map_err(|_| SemanticOuterError::ArithmeticOverflow)?;
    if witness.main_source.message_columns.len() != expected_width
        || witness
            .main_source
            .message_columns
            .iter()
            .any(|column| column.len() != expected_column_length)
    {
        return Err(SemanticOuterError::Relation(
            SemanticRelationError::MalformedWitness,
        ));
    }
    let main_message = witness.main_source.flattened_messages();
    if main_message.len() != statement.layout.main_message_element_count {
        return Err(SemanticOuterError::Relation(
            SemanticRelationError::MalformedWitness,
        ));
    }
    let inverse_end = statement
        .layout
        .inverse_first_element
        .checked_add(statement.layout.inverse_element_count)
        .ok_or(SemanticOuterError::ArithmeticOverflow)?;
    let source_inverse_values = main_message
        .get(statement.layout.inverse_first_element..inverse_end)
        .ok_or(SemanticOuterError::InvalidGeometry)?
        .to_vec();
    Ok(SemanticLookupWitness {
        pre_challenge_source: witness.pre_challenge_source.clone(),
        source_inverse_values,
    })
}

fn production_lookup_post_state_holds(
    statement: &SemanticProductionOuterStatement,
    pre_challenge_source: &SemanticCommittedCodeInstance,
    lookup_challenge: ProofChallengeExtensionElement,
    witness: &SemanticProductionOuterWitness,
) -> Result<bool, SemanticOuterError> {
    let lookup_witness = match production_lookup_witness(statement, witness) {
        Ok(witness) => witness,
        Err(SemanticOuterError::Relation(SemanticRelationError::MalformedWitness)) => {
            return Ok(false);
        }
        Err(error) => return Err(error),
    };
    semantic_lookup_kstate(
        &production_lookup_statement(statement, pre_challenge_source.clone())?,
        Some(&SemanticLookupPrefix {
            lookup_challenge: Some(lookup_challenge),
        }),
        &lookup_witness,
    )
}

fn production_post_lookup_state_holds(
    statement: &SemanticProductionOuterStatement,
    commitments: &SemanticProductionOuterCommitments,
    lookup_challenge: ProofChallengeExtensionElement,
    cross_prefix: Option<&SemanticCrossEpochPrefix>,
    witness: &SemanticProductionOuterWitness,
) -> Result<bool, SemanticOuterError> {
    if !production_lookup_post_state_holds(
        statement,
        &commitments.pre_challenge_source,
        lookup_challenge,
        witness,
    )? {
        return Ok(false);
    }
    semantic_cross_epoch_kstate(
        &production_cross_epoch_statement(statement, commitments)?,
        cross_prefix,
        &production_cross_epoch_witness(witness),
    )
}

fn production_cross_epoch_statement(
    statement: &SemanticProductionOuterStatement,
    commitments: &SemanticProductionOuterCommitments,
) -> Result<SemanticCrossEpochStatement, SemanticOuterError> {
    SemanticCrossEpochStatement::new(
        statement.pre_challenge_source_relation.clone(),
        commitments.pre_challenge_source.clone(),
        statement.main_source_relation.clone(),
        commitments.main_source.clone(),
        statement.shared_mask_relation.clone(),
        commitments.shared_masks.clone(),
        statement.layout.variable_count(),
    )
}

fn production_cross_epoch_witness(
    witness: &SemanticProductionOuterWitness,
) -> SemanticCrossEpochWitness {
    SemanticCrossEpochWitness {
        pre_challenge_source: witness.pre_challenge_source.clone(),
        main_source: witness.main_source.clone(),
        shared_masks: witness.shared_masks.clone(),
    }
}

fn committed_message_element_count(
    relation: &CommittedCodeRelation,
) -> Result<usize, SemanticOuterError> {
    relation
        .message_length
        .checked_mul(relation.interleaving_width)
        .and_then(|count| usize::try_from(count).ok())
        .ok_or(SemanticOuterError::ArithmeticOverflow)
}

fn validate_committed_instance_shape(
    relation: &CommittedCodeRelation,
    instance: &SemanticCommittedCodeInstance,
) -> Result<(), SemanticOuterError> {
    let geometry = semantic_code_geometry(relation)?;
    if instance.received_rows.len() != geometry.block_length()
        || instance
            .received_rows
            .iter()
            .any(|row| row.len() != geometry.interleaving_width())
    {
        return Err(SemanticOuterError::InvalidGeometry);
    }
    Ok(())
}

fn flattened_base_messages(
    witness: &SemanticCommittedCodeWitness,
) -> Result<Vec<ProofBaseFieldElement>, SemanticOuterError> {
    witness
        .flattened_messages()
        .into_iter()
        .map(|value| {
            let coordinates = value.canonical_coordinates();
            if coordinates[1..].iter().any(|coordinate| *coordinate != 0) {
                return Err(SemanticOuterError::NonBaseLookupCoefficient);
            }
            ProofBaseFieldElement::from_canonical(coordinates[0])
                .map_err(|_| SemanticOuterError::InvalidGeometry)
        })
        .collect()
}

fn multilinear_evaluation(
    evaluations: &[ProofChallengeExtensionElement],
    point: &[ProofChallengeExtensionElement],
) -> Result<ProofChallengeExtensionElement, SemanticOuterError> {
    if evaluations.len()
        != 1_usize
            .checked_shl(
                u32::try_from(point.len()).map_err(|_| SemanticOuterError::ArithmeticOverflow)?,
            )
            .ok_or(SemanticOuterError::ArithmeticOverflow)?
    {
        return Err(SemanticOuterError::InvalidGeometry);
    }
    let mut folded = evaluations.to_vec();
    for &coordinate in point {
        if folded.len() % 2 != 0 {
            return Err(SemanticOuterError::InvalidGeometry);
        }
        let half = folded.len() / 2;
        let one_minus_coordinate = ProofChallengeExtensionElement::ONE.subtract(coordinate);
        for ordinal in 0..half {
            folded[ordinal] = one_minus_coordinate
                .multiply(folded[ordinal])
                .add(coordinate.multiply(folded[half + ordinal]));
        }
        folded.truncate(half);
    }
    folded
        .first()
        .copied()
        .filter(|_| folded.len() == 1)
        .ok_or(SemanticOuterError::InvalidGeometry)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SemanticOuterError {
    ArithmeticOverflow,
    InconsistentBadTransition,
    InvalidGeometry,
    MalformedPrefix,
    NonBaseLookupCoefficient,
    NoncanonicalPadding,
    Relation(SemanticRelationError),
    WitnessOutsideDecodingRadius,
}

impl From<SemanticRelationError> for SemanticOuterError {
    fn from(error: SemanticRelationError) -> Self {
        Self::Relation(error)
    }
}

#[cfg(test)]
mod tests;
