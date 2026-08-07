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
use super::semantic_execution::{SemanticFactorOneSchedule, SemanticVerifierMoveOwner};
use super::semantic_outer::SemanticProductionOuterLayout;
use crate::bgv::proof_suite::compact_cfw::{
    COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH, COMPACT_CFW_ZERO_EVADER_EXPONENTS, CompactCfwGeometry,
};
use crate::bgv::proof_suite::compact_public_key_static_catalog::{
    CompactStaticCatalogError, SUMCHECK_MASK_MESSAGE_LENGTH, WhirStaticLedger,
    cfw_reduction::CfwReductionCatalog,
};
use crate::bgv::proof_suite::relation_plan::CompactPublicKeyRelationCatalog;

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
    use super::*;

    #[test]
    fn factor_one_semantic_bad_event_families_rederive_every_move_error() {
        let relation =
            crate::bgv::proof_suite::relation_plan::selected_compact_public_key_relation_catalog()
                .expect("selected relation derives");
        let catalog =
            CompactPublicKeyStaticCatalog::derive().expect("compact public-key catalog derives");
        let factor_one = catalog
            .factor_catalogs
            .iter()
            .find(|factor| factor.packing_factor == 1)
            .expect("factor one exists");
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
}
