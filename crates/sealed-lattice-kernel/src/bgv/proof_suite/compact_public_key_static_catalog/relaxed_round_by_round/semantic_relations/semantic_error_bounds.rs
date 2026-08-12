//! Error bounds derived from the executable bad-transition owners.
//!
//! The chronology and numerical soundness ledgers are comparison inputs only.
//! This module starts from the semantic owner assigned to each factor-one
//! verifier move, enumerates every bad-event family that owner can emit, and
//! derives its probability from the production relation, code, and challenge
//! geometry. The sum is then required to equal the independently constructed
//! transition ledger.

use num_bigint::BigUint;
use num_traits::CheckedSub;

use super::super::{
    CodeRole, ExactProbability, GOLDILOCKS_BASE_FIELD_MODULUS, RelaxedRoundByRoundCatalog,
    TranscriptEpoch, UniqueDecodingCode, WHIR_ROUND_COUNT, extension_field_order,
};
use super::semantic_composition::{
    SemanticCfwAndPreWhirOpeningBadTransition, SemanticPreWhirFinalAndMainOpeningBadTransition,
};
use super::semantic_execution::{
    SemanticFactorOneMoveDescriptor, SemanticFactorOneSchedule, SemanticVerifierMoveBadTransition,
    SemanticVerifierMoveOwner,
};
use super::semantic_outer::{
    SemanticCrossEpochBadTransition, SemanticProductionOuterBadTransition,
    SemanticProductionOuterLayout,
};
use super::semantic_whir::{
    SemanticWhirBadTransition, SemanticWhirBaseCombinationBadTransition,
    SemanticWhirBaseOracleRole, SemanticWhirBaseQueryEscape, SemanticWhirCodeSwitchBadTransition,
    SemanticWhirMcaCertificate, SemanticWhirOpeningBatchingBadTransition,
    SemanticWhirVerifierTransition,
};
use super::{SemanticCfwBadTransition, SemanticCfwVerifierTransition};
use crate::bgv::proof_suite::ProofChallengeExtensionElement;
use crate::bgv::proof_suite::compact_cfw::{
    COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH, COMPACT_CFW_ZERO_EVADER_EXPONENTS, CompactCfwGeometry,
    CompactChallengeField, compact_cfw_zero_evader_weights,
};
use crate::bgv::proof_suite::compact_public_key_static_catalog::{
    CompactStaticCatalogError, SUMCHECK_MASK_MESSAGE_LENGTH, WhirStaticLedger,
    cfw_reduction::CfwReductionCatalog,
};
use crate::bgv::proof_suite::relation_plan::CompactPublicKeyRelationCatalog;
use p3_field::PrimeCharacteristicRing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SemanticBadEventFamily {
    LookupRationalIdentity,
    CrossEpochMultilinearIdentity,
    CfwInitialConsistencyIdentity,
    CfwSumcheckIdentity,
    CfwZeroEvaderIdentity,
    WhirOpeningBatchingIdentity,
    WhirMaskedCombinationIdentity,
    WhirBinaryMutualCorrelatedAgreement,
    WhirMaskedSumcheckIdentity,
    WhirDistinctQueryEscape { code_role: CodeRole },
    WhirCodeSwitchCombinationIdentity,
    WhirBaseMutualCorrelatedAgreement { code_role: CodeRole },
    WhirBaseCombinationIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SemanticBadEventBound {
    pub(super) family: SemanticBadEventFamily,
    pub(super) probability: ExactProbability,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in super::super) struct SemanticMoveErrorBound {
    pub(in super::super) verifier_move_ordinal: u32,
    pub(super) owner: SemanticVerifierMoveOwner,
    pub(super) events: Vec<SemanticBadEventBound>,
    pub(in super::super) total_probability: ExactProbability,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in super::super) struct SemanticFactorOneErrorTheorem {
    pub(in super::super) moves: Vec<SemanticMoveErrorBound>,
    pub(in super::super) maximum_per_move_error: ExactProbability,
}

/// Independently interprets one concrete executable bad-transition
/// certificate as the exact event charged by the semantic error theorem.
///
/// This is the bridge between `ERRBR` and the numerical ledger. It exhaustively
/// matches the certificate variant, verifier-move owner, component ordinal,
/// polynomial root, MCA geometry, or distinct-query escape. A label alone is
/// insufficient: malformed or cross-owner certificates are rejected.
pub(super) fn derive_bad_transition_certificate_events(
    descriptor: &SemanticFactorOneMoveDescriptor,
    bad_transition: &SemanticVerifierMoveBadTransition,
) -> Result<Vec<SemanticBadEventBound>, CompactStaticCatalogError> {
    let owner = descriptor.owner();
    let events = match (owner, bad_transition) {
        (
            SemanticVerifierMoveOwner::LookupChallenge,
            SemanticVerifierMoveBadTransition::ProductionOuter(
                SemanticProductionOuterBadTransition::Lookup(certificate),
            ),
        ) => vec![semantic_root_event(
            SemanticBadEventFamily::LookupRationalIdentity,
            certificate
                .exact_error_numerator()
                .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?,
            GOLDILOCKS_BASE_FIELD_MODULUS,
        )?],
        (
            SemanticVerifierMoveOwner::CrossEpochPoint,
            SemanticVerifierMoveBadTransition::ProductionOuter(
                SemanticProductionOuterBadTransition::CrossEpoch(certificate),
            ),
        ) => {
            validate_cross_epoch_certificate(certificate)?;
            vec![semantic_root_event(
                SemanticBadEventFamily::CrossEpochMultilinearIdentity,
                certificate
                    .exact_error_numerator()
                    .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?,
                0,
            )?]
        }
        (
            SemanticVerifierMoveOwner::CfwInitialRandomness,
            SemanticVerifierMoveBadTransition::Cfw(certificate),
        ) => {
            validate_cfw_initial_certificate(certificate)?;
            vec![semantic_root_event(
                SemanticBadEventFamily::CfwInitialConsistencyIdentity,
                certificate
                    .polynomial_identity_numerator()
                    .ok_or(CompactStaticCatalogError::InvalidGeometry)?,
                0,
            )?]
        }
        (
            SemanticVerifierMoveOwner::CfwSumcheckRound { round_ordinal },
            SemanticVerifierMoveBadTransition::Cfw(SemanticCfwBadTransition::NonzeroPolynomial {
                transition:
                    SemanticCfwVerifierTransition::SumcheckRound {
                        round_ordinal: certificate_round_ordinal,
                    },
                coefficients,
                challenge,
            }),
        ) if usize::try_from(round_ordinal).ok() == Some(*certificate_round_ordinal) => {
            let numerator = compact_polynomial_root_degree(coefficients, *challenge)?;
            vec![semantic_root_event(
                SemanticBadEventFamily::CfwSumcheckIdentity,
                numerator,
                descriptor_extension_exclusion(descriptor),
            )?]
        }
        (
            SemanticVerifierMoveOwner::CfwJointAndPreWhirOpening,
            SemanticVerifierMoveBadTransition::CfwAndPreWhirOpening(certificate),
        ) => combined_cfw_and_opening_certificate_events(certificate)?,
        (
            SemanticVerifierMoveOwner::WhirMaskedSumcheckCombination { .. },
            SemanticVerifierMoveBadTransition::WhirMaskedSumcheck(
                SemanticWhirBadTransition::NonzeroPolynomialRoot {
                    transition: SemanticWhirVerifierTransition::CombiningChallenge,
                    coefficients,
                    challenge,
                },
            ),
        ) => vec![proof_polynomial_root_event(
            SemanticBadEventFamily::WhirMaskedCombinationIdentity,
            coefficients,
            *challenge,
        )?],
        (
            SemanticVerifierMoveOwner::WhirFolding { round_ordinal, .. },
            SemanticVerifierMoveBadTransition::WhirMaskedSumcheck(certificate),
        ) => vec![whir_folding_certificate_event(round_ordinal, certificate)?],
        (
            SemanticVerifierMoveOwner::WhirCodeSwitch {
                epoch,
                round_ordinal,
            },
            SemanticVerifierMoveBadTransition::WhirCodeSwitch(certificate),
        ) => vec![whir_code_switch_certificate_event(
            epoch,
            round_ordinal,
            certificate,
        )?],
        (
            SemanticVerifierMoveOwner::WhirBaseCombination { epoch },
            SemanticVerifierMoveBadTransition::WhirBaseCombination(certificate),
        ) => vec![whir_base_combination_certificate_event(epoch, certificate)?],
        (
            SemanticVerifierMoveOwner::PreWhirFinalAndMainWhirOpening,
            SemanticVerifierMoveBadTransition::PreWhirFinalAndMainWhirOpening(certificate),
        ) => pre_final_and_main_opening_certificate_events(certificate)?,
        (
            SemanticVerifierMoveOwner::MainWhirFinalQueries,
            SemanticVerifierMoveBadTransition::WhirFinalQueries(escapes),
        ) if !escapes.is_empty() => escapes
            .iter()
            .map(|escape| final_query_escape_event(TranscriptEpoch::Main, escape))
            .collect::<Result<Vec<_>, _>>()?,
        _ => return Err(CompactStaticCatalogError::InvalidGeometry),
    };
    if events.is_empty() {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    Ok(events)
}

pub(in super::super) fn derive_factor_one_semantic_error_theorem(
    catalog: &RelaxedRoundByRoundCatalog,
    relation: &CompactPublicKeyRelationCatalog,
    cfw_reduction: &CfwReductionCatalog,
    pre_challenge_whir: &WhirStaticLedger,
    main_whir: &WhirStaticLedger,
) -> Result<SemanticFactorOneErrorTheorem, CompactStaticCatalogError> {
    let schedule = SemanticFactorOneSchedule::from_catalog(catalog)
        .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?;
    let production_layout = SemanticProductionOuterLayout::from_relation(relation)
        .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?;
    let cfw_geometry = CompactCfwGeometry::derive(
        usize::try_from(relation.padded_witness_element_count())
            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
    )
    .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?;
    let expected_initial_numerator = u64::try_from(
        cfw_geometry
            .sumcheck_round_count()
            .checked_add(1)
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?,
    )
    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
    let expected_sumcheck_numerator = u64::try_from(COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH)
        .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
    let expected_joint_numerator = COMPACT_CFW_ZERO_EVADER_EXPONENTS
        .into_iter()
        .max()
        .map(u64::from)
        .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
    if expected_initial_numerator != cfw_reduction.initial_consistency_soundness_numerator()
        || expected_sumcheck_numerator != cfw_reduction.per_round_soundness_numerator()
        || expected_joint_numerator != cfw_reduction.joint_constraint_soundness_numerator()
        || u32::try_from(cfw_geometry.sumcheck_round_count()).ok()
            != Some(cfw_reduction.sumcheck_round_count())
    {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }

    let mut moves = Vec::with_capacity(schedule.moves().len());
    let mut maximum_per_move_error = ExactProbability::zero();
    for descriptor in schedule.moves() {
        let events = semantic_events_for_owner(
            descriptor.owner(),
            catalog,
            production_layout,
            cfw_reduction,
            pre_challenge_whir,
            main_whir,
        )?;
        if events.is_empty() {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        let total_probability = events
            .iter()
            .try_fold(ExactProbability::zero(), |sum, event| {
                sum.add(&event.probability)
            })?;
        if total_probability.is_greater_than(&maximum_per_move_error) {
            maximum_per_move_error = total_probability.clone();
        }
        moves.push(SemanticMoveErrorBound {
            verifier_move_ordinal: descriptor.verifier_move_ordinal(),
            owner: descriptor.owner(),
            events,
            total_probability,
        });
    }
    Ok(SemanticFactorOneErrorTheorem {
        moves,
        maximum_per_move_error,
    })
}

fn semantic_events_for_owner(
    owner: SemanticVerifierMoveOwner,
    catalog: &RelaxedRoundByRoundCatalog,
    production_layout: SemanticProductionOuterLayout,
    cfw_reduction: &CfwReductionCatalog,
    pre_challenge_whir: &WhirStaticLedger,
    main_whir: &WhirStaticLedger,
) -> Result<Vec<SemanticBadEventBound>, CompactStaticCatalogError> {
    let root_event = |family, numerator, excluded_element_count| {
        semantic_root_event(family, numerator, excluded_element_count)
    };
    match owner {
        SemanticVerifierMoveOwner::LookupChallenge => Ok(vec![root_event(
            SemanticBadEventFamily::LookupRationalIdentity,
            production_layout.soundness_numerator(),
            GOLDILOCKS_BASE_FIELD_MODULUS,
        )?]),
        SemanticVerifierMoveOwner::CrossEpochPoint => Ok(vec![root_event(
            SemanticBadEventFamily::CrossEpochMultilinearIdentity,
            u64::try_from(production_layout.variable_count())
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
            0,
        )?]),
        SemanticVerifierMoveOwner::CfwInitialRandomness => Ok(vec![root_event(
            SemanticBadEventFamily::CfwInitialConsistencyIdentity,
            cfw_reduction.initial_consistency_soundness_numerator(),
            0,
        )?]),
        SemanticVerifierMoveOwner::CfwSumcheckRound { round_ordinal } => {
            if round_ordinal >= cfw_reduction.sumcheck_round_count() {
                return Err(CompactStaticCatalogError::InvalidGeometry);
            }
            Ok(vec![root_event(
                SemanticBadEventFamily::CfwSumcheckIdentity,
                cfw_reduction.per_round_soundness_numerator(),
                if round_ordinal + 1 == cfw_reduction.sumcheck_round_count() {
                    cfw_reduction.last_round_excluded_element_count()
                } else {
                    0
                },
            )?])
        }
        SemanticVerifierMoveOwner::CfwJointAndPreWhirOpening => Ok(vec![
            root_event(
                SemanticBadEventFamily::CfwZeroEvaderIdentity,
                cfw_reduction.joint_constraint_soundness_numerator(),
                0,
            )?,
            opening_batching_event(pre_challenge_whir)?,
        ]),
        SemanticVerifierMoveOwner::WhirMaskedSumcheckCombination { .. } => Ok(vec![root_event(
            SemanticBadEventFamily::WhirMaskedCombinationIdentity,
            1,
            0,
        )?]),
        SemanticVerifierMoveOwner::WhirFolding {
            epoch,
            batch_ordinal,
            round_ordinal,
        } => {
            let source_code = unique_code(
                catalog,
                CodeRole::WhirSource {
                    epoch,
                    batch_ordinal,
                },
            )?;
            let whir = match epoch {
                TranscriptEpoch::PreChallenge => pre_challenge_whir,
                TranscriptEpoch::Main => main_whir,
            };
            let batch_ordinal = usize::from(batch_ordinal);
            if usize::from(round_ordinal)
                >= usize::try_from(
                    *whir
                        .folding_schedule
                        .get(batch_ordinal)
                        .ok_or(CompactStaticCatalogError::InvalidGeometry)?,
                )
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?
                || source_code.block_length
                    != *whir
                        .oracle_heights
                        .get(batch_ordinal)
                        .ok_or(CompactStaticCatalogError::InvalidGeometry)?
            {
                return Err(CompactStaticCatalogError::InvalidGeometry);
            }
            Ok(vec![
                root_event(
                    SemanticBadEventFamily::WhirBinaryMutualCorrelatedAgreement,
                    source_code.block_length,
                    0,
                )?,
                root_event(
                    SemanticBadEventFamily::WhirMaskedSumcheckIdentity,
                    SUMCHECK_MASK_MESSAGE_LENGTH,
                    0,
                )?,
            ])
        }
        SemanticVerifierMoveOwner::WhirCodeSwitch {
            epoch,
            round_ordinal,
        } => {
            let code_role = CodeRole::WhirSource {
                epoch,
                batch_ordinal: round_ordinal,
            };
            let code = unique_code(catalog, code_role)?;
            Ok(vec![
                SemanticBadEventBound {
                    family: SemanticBadEventFamily::WhirDistinctQueryEscape { code_role },
                    probability: code.exact_query_failure()?,
                },
                root_event(
                    SemanticBadEventFamily::WhirCodeSwitchCombinationIdentity,
                    code.hiding_randomness_length
                        .checked_add(1)
                        .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?,
                    0,
                )?,
            ])
        }
        SemanticVerifierMoveOwner::WhirBaseCombination { epoch } => {
            let mut events = Vec::new();
            for code_role in whir_final_code_roles(catalog, epoch)? {
                let code = unique_code(catalog, code_role)?;
                events.push(root_event(
                    SemanticBadEventFamily::WhirBaseMutualCorrelatedAgreement { code_role },
                    code.block_length,
                    0,
                )?);
            }
            events.push(root_event(
                SemanticBadEventFamily::WhirBaseCombinationIdentity,
                1,
                0,
            )?);
            Ok(events)
        }
        SemanticVerifierMoveOwner::PreWhirFinalAndMainWhirOpening => {
            let mut events = final_query_events(catalog, TranscriptEpoch::PreChallenge)?;
            events.push(opening_batching_event(main_whir)?);
            Ok(events)
        }
        SemanticVerifierMoveOwner::MainWhirFinalQueries => {
            final_query_events(catalog, TranscriptEpoch::Main)
        }
    }
}

fn combined_cfw_and_opening_certificate_events(
    certificate: &SemanticCfwAndPreWhirOpeningBadTransition,
) -> Result<Vec<SemanticBadEventBound>, CompactStaticCatalogError> {
    let mut events = Vec::with_capacity(2);
    if let Some(cfw) = &certificate.cfw {
        validate_cfw_zero_evader_certificate(cfw)?;
        events.push(semantic_root_event(
            SemanticBadEventFamily::CfwZeroEvaderIdentity,
            cfw.polynomial_identity_numerator()
                .ok_or(CompactStaticCatalogError::InvalidGeometry)?,
            0,
        )?);
    }
    if let Some(opening) = &certificate.pre_challenge_opening {
        events.push(opening_batching_certificate_event(opening)?);
    }
    if events.is_empty() {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    Ok(events)
}

fn pre_final_and_main_opening_certificate_events(
    certificate: &SemanticPreWhirFinalAndMainOpeningBadTransition,
) -> Result<Vec<SemanticBadEventBound>, CompactStaticCatalogError> {
    let mut events = Vec::new();
    if let Some(escapes) = &certificate.pre_challenge_query_escapes {
        if escapes.is_empty() {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        events.extend(
            escapes
                .iter()
                .map(|escape| final_query_escape_event(TranscriptEpoch::PreChallenge, escape))
                .collect::<Result<Vec<_>, _>>()?,
        );
    }
    if let Some(opening) = &certificate.main_opening {
        events.push(opening_batching_certificate_event(opening)?);
    }
    if events.is_empty() {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    Ok(events)
}

fn validate_cross_epoch_certificate(
    certificate: &SemanticCrossEpochBadTransition,
) -> Result<(), CompactStaticCatalogError> {
    if certificate
        .nonzero_difference_evaluations
        .iter()
        .all(|difference| difference.is_zero())
        || !proof_multilinear_evaluation(
            &certificate.nonzero_difference_evaluations,
            &certificate.point,
        )?
        .is_zero()
    {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    Ok(())
}

fn validate_cfw_initial_certificate(
    certificate: &SemanticCfwBadTransition,
) -> Result<(), CompactStaticCatalogError> {
    let SemanticCfwBadTransition::InitialConsistency {
        auxiliary_difference,
        masked_constraint_hypercube_residuals,
        constraint_combining_challenge,
        equality_point,
    } = certificate
    else {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    };
    if *auxiliary_difference == CompactChallengeField::ZERO
        && masked_constraint_hypercube_residuals
            .iter()
            .all(|residual| *residual == CompactChallengeField::ZERO)
    {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    let residual_at_equality_point = super::compact_multilinear_evaluation(
        masked_constraint_hypercube_residuals,
        equality_point,
    )
    .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?;
    if *auxiliary_difference + *constraint_combining_challenge * residual_at_equality_point
        != CompactChallengeField::ZERO
    {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    Ok(())
}

fn validate_cfw_zero_evader_certificate(
    certificate: &SemanticCfwBadTransition,
) -> Result<(), CompactStaticCatalogError> {
    let SemanticCfwBadTransition::ZeroEvader {
        residuals,
        weights,
        challenge,
    } = certificate
    else {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    };
    if residuals
        .iter()
        .all(|residual| *residual == CompactChallengeField::ZERO)
        || *weights != compact_cfw_zero_evader_weights(*challenge)
    {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    let evaluation = residuals
        .iter()
        .zip(weights)
        .fold(CompactChallengeField::ZERO, |sum, (residual, weight)| {
            sum + *residual * *weight
        });
    if evaluation != CompactChallengeField::ZERO {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    Ok(())
}

fn whir_folding_certificate_event(
    round_ordinal: u8,
    certificate: &SemanticWhirBadTransition,
) -> Result<SemanticBadEventBound, CompactStaticCatalogError> {
    match certificate {
        SemanticWhirBadTransition::MutualCorrelatedAgreement {
            transition:
                SemanticWhirVerifierTransition::SumcheckRound {
                    round_ordinal: certificate_round_ordinal,
                },
            certificate,
        } if usize::from(round_ordinal) == *certificate_round_ordinal => mca_certificate_event(
            SemanticBadEventFamily::WhirBinaryMutualCorrelatedAgreement,
            certificate,
        ),
        SemanticWhirBadTransition::NonzeroPolynomialRoot {
            transition:
                SemanticWhirVerifierTransition::SumcheckRound {
                    round_ordinal: certificate_round_ordinal,
                },
            coefficients,
            challenge,
        } if usize::from(round_ordinal) == *certificate_round_ordinal => {
            proof_polynomial_root_event(
                SemanticBadEventFamily::WhirMaskedSumcheckIdentity,
                coefficients,
                *challenge,
            )
        }
        _ => Err(CompactStaticCatalogError::InvalidGeometry),
    }
}

fn whir_code_switch_certificate_event(
    epoch: TranscriptEpoch,
    round_ordinal: u8,
    certificate: &SemanticWhirCodeSwitchBadTransition,
) -> Result<SemanticBadEventBound, CompactStaticCatalogError> {
    match certificate {
        SemanticWhirCodeSwitchBadTransition::QueryEscape {
            domain_size,
            selected_decoding_error_count,
            differing_row_count,
            query_positions,
        } => query_escape_event(
            SemanticBadEventFamily::WhirDistinctQueryEscape {
                code_role: CodeRole::WhirSource {
                    epoch,
                    batch_ordinal: round_ordinal,
                },
            },
            *domain_size,
            *selected_decoding_error_count,
            *differing_row_count,
            query_positions,
        ),
        SemanticWhirCodeSwitchBadTransition::NonzeroCombinationPolynomialRoot {
            coefficients,
            challenge,
        } => proof_polynomial_root_event(
            SemanticBadEventFamily::WhirCodeSwitchCombinationIdentity,
            coefficients,
            *challenge,
        ),
    }
}

fn whir_base_combination_certificate_event(
    epoch: TranscriptEpoch,
    certificate: &SemanticWhirBaseCombinationBadTransition,
) -> Result<SemanticBadEventBound, CompactStaticCatalogError> {
    match certificate {
        SemanticWhirBaseCombinationBadTransition::MutualCorrelatedAgreement {
            role,
            certificate,
        } => mca_certificate_event(
            SemanticBadEventFamily::WhirBaseMutualCorrelatedAgreement {
                code_role: final_code_role(epoch, *role)?,
            },
            certificate,
        ),
        SemanticWhirBaseCombinationBadTransition::NonzeroPolynomialRoot {
            coefficients,
            challenge,
        } => proof_polynomial_root_event(
            SemanticBadEventFamily::WhirBaseCombinationIdentity,
            coefficients,
            *challenge,
        ),
    }
}

fn final_query_escape_event(
    epoch: TranscriptEpoch,
    escape: &SemanticWhirBaseQueryEscape,
) -> Result<SemanticBadEventBound, CompactStaticCatalogError> {
    query_escape_event(
        SemanticBadEventFamily::WhirDistinctQueryEscape {
            code_role: final_code_role(epoch, escape.role)?,
        },
        escape.domain_size,
        escape.selected_decoding_error_count,
        escape.differing_row_count,
        &escape.query_positions,
    )
}

fn final_code_role(
    epoch: TranscriptEpoch,
    role: SemanticWhirBaseOracleRole,
) -> Result<CodeRole, CompactStaticCatalogError> {
    Ok(match role {
        SemanticWhirBaseOracleRole::Source => CodeRole::WhirSource {
            epoch,
            batch_ordinal: u8::try_from(WHIR_ROUND_COUNT)
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
        },
        SemanticWhirBaseOracleRole::MaskGroup { group_ordinal } => CodeRole::WhirMask {
            epoch,
            group_ordinal: u8::try_from(group_ordinal)
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
        },
    })
}

fn opening_batching_certificate_event(
    certificate: &SemanticWhirOpeningBatchingBadTransition,
) -> Result<SemanticBadEventBound, CompactStaticCatalogError> {
    proof_polynomial_root_event(
        SemanticBadEventFamily::WhirOpeningBatchingIdentity,
        &certificate.coefficients,
        certificate.challenge,
    )
}

fn mca_certificate_event(
    family: SemanticBadEventFamily,
    certificate: &SemanticWhirMcaCertificate,
) -> Result<SemanticBadEventBound, CompactStaticCatalogError> {
    if certificate.target_domain_size == 0
        || certificate.selected_decoding_error_count >= certificate.target_domain_size
        || certificate.agreement_positions.is_empty()
        || !strictly_increasing_and_bounded(
            &certificate.agreement_positions,
            certificate.target_domain_size,
        )
    {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    semantic_root_event(
        family,
        certificate
            .exact_error_numerator()
            .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?,
        0,
    )
}

fn query_escape_event(
    family: SemanticBadEventFamily,
    domain_size: usize,
    selected_decoding_error_count: usize,
    differing_row_count: usize,
    query_positions: &[usize],
) -> Result<SemanticBadEventBound, CompactStaticCatalogError> {
    if domain_size == 0
        || !domain_size.is_power_of_two()
        || selected_decoding_error_count >= domain_size
        || differing_row_count <= selected_decoding_error_count
        || differing_row_count > domain_size
        || query_positions.is_empty()
        || !strictly_increasing_and_bounded(query_positions, domain_size)
    {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    let agreement_count = domain_size
        .checked_sub(differing_row_count)
        .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
    if query_positions.len() > agreement_count {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    Ok(SemanticBadEventBound {
        family,
        probability: ExactProbability::new(
            ordered_selection_count(agreement_count, query_positions.len())?,
            ordered_selection_count(domain_size, query_positions.len())?,
        )?,
    })
}

fn strictly_increasing_and_bounded(values: &[usize], bound: usize) -> bool {
    values.iter().all(|value| *value < bound)
        && values.windows(2).all(|window| window[0] < window[1])
}

fn ordered_selection_count(
    population_size: usize,
    selection_count: usize,
) -> Result<BigUint, CompactStaticCatalogError> {
    if selection_count == 0 || selection_count > population_size {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    Ok(
        (0..selection_count).fold(BigUint::from(1_u8), |product, offset| {
            product * BigUint::from(population_size - offset)
        }),
    )
}

fn compact_polynomial_root_degree(
    coefficients: &[CompactChallengeField],
    challenge: CompactChallengeField,
) -> Result<u64, CompactStaticCatalogError> {
    let degree = coefficients
        .iter()
        .rposition(|coefficient| *coefficient != CompactChallengeField::ZERO)
        .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
    let evaluation = coefficients
        .iter()
        .rev()
        .fold(CompactChallengeField::ZERO, |value, coefficient| {
            value * challenge + *coefficient
        });
    if evaluation != CompactChallengeField::ZERO {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    u64::try_from(degree).map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)
}

fn proof_polynomial_root_event(
    family: SemanticBadEventFamily,
    coefficients: &[ProofChallengeExtensionElement],
    challenge: ProofChallengeExtensionElement,
) -> Result<SemanticBadEventBound, CompactStaticCatalogError> {
    let degree = coefficients
        .iter()
        .rposition(|coefficient| !coefficient.is_zero())
        .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
    let evaluation = coefficients.iter().rev().fold(
        ProofChallengeExtensionElement::ZERO,
        |value, coefficient| value.multiply(challenge).add(*coefficient),
    );
    if !evaluation.is_zero() {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    semantic_root_event(
        family,
        u64::try_from(degree).map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
        0,
    )
}

fn proof_multilinear_evaluation(
    evaluations: &[ProofChallengeExtensionElement],
    point: &[ProofChallengeExtensionElement],
) -> Result<ProofChallengeExtensionElement, CompactStaticCatalogError> {
    if evaluations.is_empty()
        || !evaluations.len().is_power_of_two()
        || point.len() != evaluations.len().ilog2() as usize
    {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    let mut folded = evaluations.to_vec();
    for challenge in point {
        let half = folded.len() / 2;
        for index in 0..half {
            let left = folded[index];
            let right = folded[index + half];
            folded[index] = left.add(right.subtract(left).multiply(*challenge));
        }
        folded.truncate(half);
    }
    folded
        .first()
        .copied()
        .ok_or(CompactStaticCatalogError::InvalidGeometry)
}

fn descriptor_extension_exclusion(descriptor: &SemanticFactorOneMoveDescriptor) -> u64 {
    match descriptor.challenge_space() {
        super::super::ExactChallengeSpace::ExtensionVector {
            excluded_element_count,
            ..
        } => *excluded_element_count,
        _ => 0,
    }
}

fn semantic_root_event(
    family: SemanticBadEventFamily,
    numerator: u64,
    excluded_element_count: u64,
) -> Result<SemanticBadEventBound, CompactStaticCatalogError> {
    let denominator = extension_field_order()
        .checked_sub(&BigUint::from(excluded_element_count))
        .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
    Ok(SemanticBadEventBound {
        family,
        probability: ExactProbability::new(BigUint::from(numerator), denominator)?,
    })
}

fn opening_batching_event(
    whir: &WhirStaticLedger,
) -> Result<SemanticBadEventBound, CompactStaticCatalogError> {
    semantic_root_event(
        SemanticBadEventFamily::WhirOpeningBatchingIdentity,
        whir.opening_batching_claim_count
            .checked_sub(1)
            .ok_or(CompactStaticCatalogError::InvalidGeometry)?,
        0,
    )
}

fn final_query_events(
    catalog: &RelaxedRoundByRoundCatalog,
    epoch: TranscriptEpoch,
) -> Result<Vec<SemanticBadEventBound>, CompactStaticCatalogError> {
    whir_final_code_roles(catalog, epoch)?
        .into_iter()
        .map(|code_role| {
            Ok(SemanticBadEventBound {
                family: SemanticBadEventFamily::WhirDistinctQueryEscape { code_role },
                probability: unique_code(catalog, code_role)?.exact_query_failure()?,
            })
        })
        .collect()
}

fn whir_final_code_roles(
    catalog: &RelaxedRoundByRoundCatalog,
    epoch: TranscriptEpoch,
) -> Result<Vec<CodeRole>, CompactStaticCatalogError> {
    let final_batch_ordinal = u8::try_from(WHIR_ROUND_COUNT)
        .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
    let mut roles = vec![CodeRole::WhirSource {
        epoch,
        batch_ordinal: final_batch_ordinal,
    }];
    let mut mask_ordinals = catalog
        .codes
        .iter()
        .filter_map(|code| match code.role {
            CodeRole::WhirMask {
                epoch: code_epoch,
                group_ordinal,
            } if code_epoch == epoch => Some(group_ordinal),
            _ => None,
        })
        .collect::<Vec<_>>();
    mask_ordinals.sort_unstable();
    for (expected_ordinal, group_ordinal) in mask_ordinals.into_iter().enumerate() {
        if usize::from(group_ordinal) != expected_ordinal {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        roles.push(CodeRole::WhirMask {
            epoch,
            group_ordinal,
        });
    }
    Ok(roles)
}

fn unique_code(
    catalog: &RelaxedRoundByRoundCatalog,
    role: CodeRole,
) -> Result<&UniqueDecodingCode, CompactStaticCatalogError> {
    let mut matches = catalog.codes.iter().filter(|code| code.role == role);
    let code = matches
        .next()
        .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
    if matches.next().is_some() {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::super::super::super::CompactPublicKeyStaticCatalog;
    use super::super::semantic_execution::SemanticExecutionError;
    use super::super::semantic_outer::{
        SemanticLookupBadTransition, SemanticLookupMultiplicityDifference,
    };
    use super::super::semantic_whir::{
        SemanticWhirMcaCombination, SemanticWhirMcaUncorrectableComponent,
    };
    use super::*;
    use crate::bgv::proof_suite::ProofBaseFieldElement;

    fn extension_field(value: u64) -> ProofChallengeExtensionElement {
        ProofChallengeExtensionElement::from_base(
            ProofBaseFieldElement::from_canonical(value).expect("small field value"),
        )
    }

    fn compact_field(value: u64) -> CompactChallengeField {
        CompactChallengeField::from_u64(value)
    }

    fn descriptor(owner: SemanticVerifierMoveOwner) -> SemanticFactorOneMoveDescriptor {
        SemanticFactorOneMoveDescriptor::for_focused_test(owner)
    }

    fn families(
        owner: SemanticVerifierMoveOwner,
        bad_transition: SemanticVerifierMoveBadTransition,
    ) -> Vec<SemanticBadEventFamily> {
        derive_bad_transition_certificate_events(&descriptor(owner), &bad_transition)
            .expect("the concrete certificate is covered")
            .into_iter()
            .map(|event| event.family)
            .collect()
    }

    #[test]
    fn factor_one_semantic_bad_event_families_rederive_every_move_error() {
        let relation =
            crate::bgv::proof_suite::relation_plan::selected_compact_public_key_relation_catalog()
                .expect("selected relation derives");
        let catalog =
            CompactPublicKeyStaticCatalog::derive().expect("compact public-key catalog derives");
        let factor_one = &catalog.selected;
        let theorem = derive_factor_one_semantic_error_theorem(
            &factor_one.relaxed_round_by_round,
            &relation,
            &catalog.cfw_reduction,
            &factor_one.pre_challenge_whir,
            &factor_one.main_whir,
        )
        .expect("semantic error theorem derives");

        assert_eq!(theorem.moves.len(), 82);
        assert!(theorem.moves.iter().all(|move_bound| {
            !move_bound.events.is_empty()
                && move_bound.total_probability
                    == factor_one.relaxed_round_by_round.transitions
                        [usize::try_from(move_bound.verifier_move_ordinal).unwrap()]
                    .extraction_error
        }));
        assert_eq!(
            theorem.maximum_per_move_error,
            factor_one
                .relaxed_round_by_round
                .maximum_per_move_extraction_error
        );
        assert!(theorem.moves.iter().any(|move_bound| {
            move_bound.events.iter().any(|event| {
                matches!(
                    event.family,
                    SemanticBadEventFamily::WhirBinaryMutualCorrelatedAgreement
                )
            })
        }));
        assert!(theorem.moves.iter().any(|move_bound| {
            move_bound.events.iter().any(|event| {
                matches!(
                    event.family,
                    SemanticBadEventFamily::WhirDistinctQueryEscape { .. }
                )
            })
        }));
    }

    #[test]
    fn executable_bad_transition_certificates_map_to_every_charged_event_family() {
        let lookup = SemanticVerifierMoveBadTransition::ProductionOuter(
            SemanticProductionOuterBadTransition::Lookup(SemanticLookupBadTransition {
                lookup_challenge: extension_field(3),
                source_element_count: 2,
                table_entry_count: 2,
                first_multiplicity_difference:
                    SemanticLookupMultiplicityDifference::TableMultiplicity {
                        table_value: 0,
                        actual: ProofBaseFieldElement::from_canonical(1).unwrap(),
                        claimed: ProofBaseFieldElement::from_canonical(2).unwrap(),
                    },
            }),
        );
        assert_eq!(
            families(SemanticVerifierMoveOwner::LookupChallenge, lookup),
            [SemanticBadEventFamily::LookupRationalIdentity]
        );

        let cross_epoch = SemanticVerifierMoveBadTransition::ProductionOuter(
            SemanticProductionOuterBadTransition::CrossEpoch(SemanticCrossEpochBadTransition {
                nonzero_difference_evaluations: vec![
                    ProofChallengeExtensionElement::ZERO,
                    extension_field(1),
                ],
                point: vec![ProofChallengeExtensionElement::ZERO],
            }),
        );
        assert_eq!(
            families(SemanticVerifierMoveOwner::CrossEpochPoint, cross_epoch),
            [SemanticBadEventFamily::CrossEpochMultilinearIdentity]
        );

        let cfw_initial =
            SemanticVerifierMoveBadTransition::Cfw(SemanticCfwBadTransition::InitialConsistency {
                auxiliary_difference: CompactChallengeField::ZERO,
                masked_constraint_hypercube_residuals: vec![
                    CompactChallengeField::ZERO,
                    compact_field(1),
                ],
                constraint_combining_challenge: compact_field(7),
                equality_point: vec![CompactChallengeField::ZERO],
            });
        assert_eq!(
            families(SemanticVerifierMoveOwner::CfwInitialRandomness, cfw_initial,),
            [SemanticBadEventFamily::CfwInitialConsistencyIdentity]
        );

        let cfw_sumcheck =
            SemanticVerifierMoveBadTransition::Cfw(SemanticCfwBadTransition::NonzeroPolynomial {
                transition: SemanticCfwVerifierTransition::SumcheckRound { round_ordinal: 0 },
                coefficients: vec![CompactChallengeField::ZERO, compact_field(1)],
                challenge: CompactChallengeField::ZERO,
            });
        assert_eq!(
            families(
                SemanticVerifierMoveOwner::CfwSumcheckRound { round_ordinal: 0 },
                cfw_sumcheck,
            ),
            [SemanticBadEventFamily::CfwSumcheckIdentity]
        );

        let cfw_zero_evader = SemanticCfwBadTransition::ZeroEvader {
            residuals: [
                CompactChallengeField::ZERO,
                compact_field(1),
                CompactChallengeField::ZERO,
            ],
            weights: compact_cfw_zero_evader_weights(CompactChallengeField::ZERO),
            challenge: CompactChallengeField::ZERO,
        };
        let opening = SemanticWhirOpeningBatchingBadTransition {
            coefficients: vec![ProofChallengeExtensionElement::ZERO, extension_field(1)],
            challenge: ProofChallengeExtensionElement::ZERO,
        };
        let combined = SemanticVerifierMoveBadTransition::CfwAndPreWhirOpening(
            SemanticCfwAndPreWhirOpeningBadTransition {
                cfw: Some(cfw_zero_evader),
                pre_challenge_opening: Some(opening.clone()),
            },
        );
        assert_eq!(
            families(
                SemanticVerifierMoveOwner::CfwJointAndPreWhirOpening,
                combined,
            ),
            [
                SemanticBadEventFamily::CfwZeroEvaderIdentity,
                SemanticBadEventFamily::WhirOpeningBatchingIdentity,
            ]
        );

        let combining = SemanticVerifierMoveBadTransition::WhirMaskedSumcheck(
            SemanticWhirBadTransition::NonzeroPolynomialRoot {
                transition: SemanticWhirVerifierTransition::CombiningChallenge,
                coefficients: vec![ProofChallengeExtensionElement::ZERO, extension_field(1)],
                challenge: ProofChallengeExtensionElement::ZERO,
            },
        );
        assert_eq!(
            families(
                SemanticVerifierMoveOwner::WhirMaskedSumcheckCombination {
                    epoch: TranscriptEpoch::PreChallenge,
                    batch_ordinal: 0,
                },
                combining,
            ),
            [SemanticBadEventFamily::WhirMaskedCombinationIdentity]
        );

        let folding_root = SemanticVerifierMoveBadTransition::WhirMaskedSumcheck(
            SemanticWhirBadTransition::NonzeroPolynomialRoot {
                transition: SemanticWhirVerifierTransition::SumcheckRound { round_ordinal: 0 },
                coefficients: vec![ProofChallengeExtensionElement::ZERO, extension_field(1)],
                challenge: ProofChallengeExtensionElement::ZERO,
            },
        );
        assert_eq!(
            families(
                SemanticVerifierMoveOwner::WhirFolding {
                    epoch: TranscriptEpoch::PreChallenge,
                    batch_ordinal: 0,
                    round_ordinal: 0,
                },
                folding_root,
            ),
            [SemanticBadEventFamily::WhirMaskedSumcheckIdentity]
        );

        let mca_certificate = SemanticWhirMcaCertificate {
            combination: SemanticWhirMcaCombination::AffineFold,
            challenge: extension_field(11),
            agreement_positions: (0..8).collect(),
            target_domain_size: 8,
            selected_decoding_error_count: 2,
            uncorrectable_component: SemanticWhirMcaUncorrectableComponent::First,
        };
        let folding_mca = SemanticVerifierMoveBadTransition::WhirMaskedSumcheck(
            SemanticWhirBadTransition::MutualCorrelatedAgreement {
                transition: SemanticWhirVerifierTransition::SumcheckRound { round_ordinal: 0 },
                certificate: mca_certificate.clone(),
            },
        );
        assert_eq!(
            families(
                SemanticVerifierMoveOwner::WhirFolding {
                    epoch: TranscriptEpoch::PreChallenge,
                    batch_ordinal: 0,
                    round_ordinal: 0,
                },
                folding_mca,
            ),
            [SemanticBadEventFamily::WhirBinaryMutualCorrelatedAgreement]
        );

        let code_switch_query = SemanticVerifierMoveBadTransition::WhirCodeSwitch(
            SemanticWhirCodeSwitchBadTransition::QueryEscape {
                domain_size: 8,
                selected_decoding_error_count: 2,
                differing_row_count: 3,
                query_positions: vec![0, 1],
            },
        );
        let code_switch_events = derive_bad_transition_certificate_events(
            &descriptor(SemanticVerifierMoveOwner::WhirCodeSwitch {
                epoch: TranscriptEpoch::PreChallenge,
                round_ordinal: 0,
            }),
            &code_switch_query,
        )
        .unwrap();
        assert_eq!(
            code_switch_events,
            [SemanticBadEventBound {
                family: SemanticBadEventFamily::WhirDistinctQueryEscape {
                    code_role: CodeRole::WhirSource {
                        epoch: TranscriptEpoch::PreChallenge,
                        batch_ordinal: 0,
                    },
                },
                probability: ExactProbability::new(BigUint::from(20_u8), BigUint::from(56_u8))
                    .unwrap(),
            }]
        );

        let code_switch_root = SemanticVerifierMoveBadTransition::WhirCodeSwitch(
            SemanticWhirCodeSwitchBadTransition::NonzeroCombinationPolynomialRoot {
                coefficients: vec![ProofChallengeExtensionElement::ZERO, extension_field(1)],
                challenge: ProofChallengeExtensionElement::ZERO,
            },
        );
        assert_eq!(
            families(
                SemanticVerifierMoveOwner::WhirCodeSwitch {
                    epoch: TranscriptEpoch::PreChallenge,
                    round_ordinal: 0,
                },
                code_switch_root,
            ),
            [SemanticBadEventFamily::WhirCodeSwitchCombinationIdentity]
        );

        let base_mca = SemanticVerifierMoveBadTransition::WhirBaseCombination(
            SemanticWhirBaseCombinationBadTransition::MutualCorrelatedAgreement {
                role: SemanticWhirBaseOracleRole::Source,
                certificate: mca_certificate,
            },
        );
        assert_eq!(
            families(
                SemanticVerifierMoveOwner::WhirBaseCombination {
                    epoch: TranscriptEpoch::Main,
                },
                base_mca,
            ),
            [SemanticBadEventFamily::WhirBaseMutualCorrelatedAgreement {
                code_role: CodeRole::WhirSource {
                    epoch: TranscriptEpoch::Main,
                    batch_ordinal: u8::try_from(WHIR_ROUND_COUNT).unwrap(),
                },
            }]
        );

        let base_root = SemanticVerifierMoveBadTransition::WhirBaseCombination(
            SemanticWhirBaseCombinationBadTransition::NonzeroPolynomialRoot {
                coefficients: vec![ProofChallengeExtensionElement::ZERO, extension_field(1)],
                challenge: ProofChallengeExtensionElement::ZERO,
            },
        );
        assert_eq!(
            families(
                SemanticVerifierMoveOwner::WhirBaseCombination {
                    epoch: TranscriptEpoch::Main,
                },
                base_root,
            ),
            [SemanticBadEventFamily::WhirBaseCombinationIdentity]
        );

        let final_escape = SemanticWhirBaseQueryEscape {
            role: SemanticWhirBaseOracleRole::Source,
            domain_size: 8,
            selected_decoding_error_count: 2,
            differing_row_count: 3,
            query_positions: vec![0, 1],
        };
        let atomic = SemanticVerifierMoveBadTransition::PreWhirFinalAndMainWhirOpening(
            SemanticPreWhirFinalAndMainOpeningBadTransition {
                pre_challenge_query_escapes: Some(vec![final_escape.clone()]),
                main_opening: Some(opening),
            },
        );
        assert_eq!(
            families(
                SemanticVerifierMoveOwner::PreWhirFinalAndMainWhirOpening,
                atomic,
            ),
            [
                SemanticBadEventFamily::WhirDistinctQueryEscape {
                    code_role: CodeRole::WhirSource {
                        epoch: TranscriptEpoch::PreChallenge,
                        batch_ordinal: u8::try_from(WHIR_ROUND_COUNT).unwrap(),
                    },
                },
                SemanticBadEventFamily::WhirOpeningBatchingIdentity,
            ]
        );

        let final_queries = SemanticVerifierMoveBadTransition::WhirFinalQueries(vec![final_escape]);
        assert_eq!(
            families(
                SemanticVerifierMoveOwner::MainWhirFinalQueries,
                final_queries,
            ),
            [SemanticBadEventFamily::WhirDistinctQueryEscape {
                code_role: CodeRole::WhirSource {
                    epoch: TranscriptEpoch::Main,
                    batch_ordinal: u8::try_from(WHIR_ROUND_COUNT).unwrap(),
                },
            }]
        );
    }

    #[test]
    fn bad_transition_certificate_mapping_refuses_wrong_owner_and_query_geometry() {
        let certificate = SemanticVerifierMoveBadTransition::WhirCodeSwitch(
            SemanticWhirCodeSwitchBadTransition::QueryEscape {
                domain_size: 8,
                selected_decoding_error_count: 2,
                differing_row_count: 3,
                query_positions: vec![0, 1],
            },
        );
        assert_eq!(
            derive_bad_transition_certificate_events(
                &descriptor(SemanticVerifierMoveOwner::WhirMaskedSumcheckCombination {
                    epoch: TranscriptEpoch::PreChallenge,
                    batch_ordinal: 0,
                }),
                &certificate,
            ),
            Err(CompactStaticCatalogError::InvalidGeometry)
        );

        let zero_error_descriptor = descriptor(SemanticVerifierMoveOwner::WhirCodeSwitch {
            epoch: TranscriptEpoch::PreChallenge,
            round_ordinal: 0,
        })
        .with_extraction_error_for_focused_test(ExactProbability::zero());
        assert_eq!(
            super::super::semantic_execution::validate_bad_transition_certificate_bound(
                &zero_error_descriptor,
                &certificate,
            ),
            Err(SemanticExecutionError::BadTransitionProbabilityBoundExceeded)
        );

        for malformed in [
            SemanticWhirCodeSwitchBadTransition::QueryEscape {
                domain_size: 8,
                selected_decoding_error_count: 2,
                differing_row_count: 2,
                query_positions: vec![0, 1],
            },
            SemanticWhirCodeSwitchBadTransition::QueryEscape {
                domain_size: 8,
                selected_decoding_error_count: 2,
                differing_row_count: 3,
                query_positions: vec![1, 1],
            },
            SemanticWhirCodeSwitchBadTransition::QueryEscape {
                domain_size: 8,
                selected_decoding_error_count: 2,
                differing_row_count: 7,
                query_positions: vec![0, 1],
            },
        ] {
            assert_eq!(
                derive_bad_transition_certificate_events(
                    &descriptor(SemanticVerifierMoveOwner::WhirCodeSwitch {
                        epoch: TranscriptEpoch::PreChallenge,
                        round_ordinal: 0,
                    }),
                    &SemanticVerifierMoveBadTransition::WhirCodeSwitch(malformed),
                ),
                Err(CompactStaticCatalogError::InvalidGeometry)
            );
        }
    }
}
