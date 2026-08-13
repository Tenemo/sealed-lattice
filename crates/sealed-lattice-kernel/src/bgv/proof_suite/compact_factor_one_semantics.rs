//! Test-only contract-derived factor-one semantic error authority.
//!
//! This module binds every verifier move in the selected compact proof
//! contract to its executable semantic owner and recomputes the exact bad-event
//! bound for that owner. It is a source-level executable semantic authority,
//! not proof acceptance: dynamic proof bytes still require the separate CFW
//! and WHIR verifier equations before this development authority can be
//! consumed by a production acceptance path.

use core::cmp::Ordering;

use num_bigint::BigUint;
use num_traits::{CheckedSub, One, Zero};

use super::compact_cdhz_theorem::{
    CompactCdhzAppendixAOneError, CompactRelaxedRoundByRoundKnowledgeBound,
};
use super::compact_cfw_geometry::CompactCfwVerifierConfiguration;
use super::compact_proof_contract::{
    CompactPublicKeyVerifierInputs, CompactVerifierMoveContract, CompactVerifierRoleCoordinate,
    CompactWhirEpochContract, CompactWhirFoldContract, CompactWhirMaskGroupContract,
    validate_exact_verifier_chronology,
};
use super::compact_reed_solomon::CanonicalReedSolomonGeometry;
use super::fixed_uniform_verifier_message::{
    FixedUniformDistinctQueryGeometry, FixedUniformVerifierMessageGeometry,
};
use super::relation_plan::CompactPublicKeyRelationCatalog;
use super::{PROOF_BASE_FIELD_MODULUS, PROOF_CHALLENGE_EXTENSION_DEGREE};

mod executable;
mod public_covector;

pub(crate) use public_covector::{
    CompactFactorOneCarriedCovector, CompactFactorOnePublicCovectorAuthority,
    CompactFactorOnePublicCovectorDerivation, CompactFactorOnePublicCovectorError,
    CompactFactorOnePublicCovectorPoll,
};

pub(super) const SELECTED_FACTOR_ONE_VERIFIER_MOVE_COUNT: usize = 82;
const SELECTED_WHIR_EPOCH_COUNT: usize = 2;
const SELECTED_WHIR_FOLD_COUNT_PER_EPOCH: usize = 4;
pub(super) const SELECTED_WHIR_ROUND_COUNT: usize = SELECTED_WHIR_FOLD_COUNT_PER_EPOCH - 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactFactorOneSemanticError {
    ArithmeticOverflow,
    InvalidGeometry,
    InvalidContractGeometry,
    InvalidOwnerChronology,
    InvalidChallengeGeometry,
    InvalidProbability,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CompactFactorOneEpoch {
    PreChallenge,
    Main,
}

impl CompactFactorOneEpoch {
    pub(super) const fn contract_tag(self) -> u8 {
        match self {
            Self::PreChallenge => 1,
            Self::Main => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CompactFactorOneSemanticOwner {
    LookupChallenge,
    CrossEpochPoint,
    CfwInitialRandomness,
    CfwSumcheckRound {
        round_ordinal: u32,
    },
    CfwJointAndPreWhirOpening,
    WhirMaskedSumcheckCombination {
        epoch: CompactFactorOneEpoch,
        batch_ordinal: u8,
    },
    WhirFolding {
        epoch: CompactFactorOneEpoch,
        batch_ordinal: u8,
        round_ordinal: u8,
    },
    WhirCodeSwitch {
        epoch: CompactFactorOneEpoch,
        round_ordinal: u8,
    },
    WhirBaseCombination {
        epoch: CompactFactorOneEpoch,
    },
    PreWhirFinalAndMainWhirOpening,
    MainWhirFinalQueries,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CompactFactorOneCodeRole {
    WhirSource {
        epoch: CompactFactorOneEpoch,
        batch_ordinal: u8,
    },
    WhirMask {
        epoch: CompactFactorOneEpoch,
        group_ordinal: u8,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CompactFactorOneBadEventFamily {
    LookupRationalIdentity,
    CrossEpochMultilinearIdentity,
    CfwInitialConsistencyIdentity,
    CfwSumcheckIdentity,
    CfwZeroEvaderIdentity,
    WhirOpeningBatchingIdentity,
    WhirMaskedCombinationIdentity,
    WhirBinaryMutualCorrelatedAgreement,
    WhirMaskedSumcheckIdentity,
    WhirDistinctQueryEscape { code_role: CompactFactorOneCodeRole },
    WhirCodeSwitchCombinationIdentity,
    WhirBaseMutualCorrelatedAgreement { code_role: CompactFactorOneCodeRole },
    WhirBaseCombinationIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CompactFactorOneExactProbability {
    pub(super) numerator: BigUint,
    pub(super) denominator: BigUint,
}

impl CompactFactorOneExactProbability {
    pub(super) fn new(
        numerator: BigUint,
        denominator: BigUint,
    ) -> Result<Self, CompactFactorOneSemanticError> {
        if denominator.is_zero() || numerator > denominator {
            return Err(CompactFactorOneSemanticError::InvalidProbability);
        }
        let greatest_common_divisor =
            greatest_common_divisor(numerator.clone(), denominator.clone());
        Ok(Self {
            numerator: numerator / &greatest_common_divisor,
            denominator: denominator / greatest_common_divisor,
        })
    }

    pub(super) fn zero() -> Self {
        Self {
            numerator: BigUint::zero(),
            denominator: BigUint::one(),
        }
    }

    pub(super) fn add(&self, right: &Self) -> Result<Self, CompactFactorOneSemanticError> {
        let common_divisor =
            greatest_common_divisor(self.denominator.clone(), right.denominator.clone());
        let left_scale = &right.denominator / &common_divisor;
        let right_scale = &self.denominator / &common_divisor;
        Self::new(
            &self.numerator * &left_scale + &right.numerator * &right_scale,
            &self.denominator * left_scale,
        )
    }

    pub(super) fn is_greater_than(&self, right: &Self) -> bool {
        self > right
    }
}

impl PartialOrd for CompactFactorOneExactProbability {
    fn partial_cmp(&self, right: &Self) -> Option<Ordering> {
        Some(self.cmp(right))
    }
}

impl Ord for CompactFactorOneExactProbability {
    fn cmp(&self, right: &Self) -> Ordering {
        (&self.numerator * &right.denominator).cmp(&(&right.numerator * &self.denominator))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CompactFactorOneBadEventBound {
    pub(super) family: CompactFactorOneBadEventFamily,
    pub(super) probability: CompactFactorOneExactProbability,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MaskGroupRole {
    CrossEpochOpening,
    CfwInner,
    CfwOuter,
    WhirSumcheck { batch_ordinal: u8 },
    WhirCodeSwitch { round_ordinal: u8 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CommittedCodeRelation {
    pub(super) message_length: u64,
    pub(super) hiding_randomness_length: u64,
    pub(super) block_length: u64,
    pub(super) interleaving_width: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CommittedMaskCodeRelation {
    pub(super) role: MaskGroupRole,
    pub(super) code: CommittedCodeRelation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct GeneralizedCommittedRelation {
    pub(super) source_code: CommittedCodeRelation,
    pub(super) mask_codes: Vec<CommittedMaskCodeRelation>,
    pub(super) source_message_element_count: u64,
    pub(super) source_hiding_element_count: u64,
    pub(super) mask_message_element_count: u64,
    pub(super) covector_extension_element_count: u64,
    pub(super) opening_evaluation_claim_count: u64,
    pub(super) carried_reduction_claim_count: u64,
    pub(super) claim_count: u64,
}

pub(super) type TranscriptEpoch = CompactFactorOneEpoch;
pub(super) type CodeRole = CompactFactorOneCodeRole;
pub(super) type ExactProbability = CompactFactorOneExactProbability;
pub(super) const GOLDILOCKS_BASE_FIELD_MODULUS: u64 = PROOF_BASE_FIELD_MODULUS;
pub(super) const WHIR_ROUND_COUNT: usize = SELECTED_WHIR_ROUND_COUNT;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum ExactChallengeSpace {
    ExtensionVector {
        element_count: u32,
        excluded_element_count: u64,
    },
    BaseElementExtensionVectorAndDistinctQueries {
        extension_element_count: u32,
        groups: Vec<FixedUniformDistinctQueryGeometry>,
    },
    ExtensionVectorAndDistinctQueries {
        extension_element_count: u32,
        groups: Vec<FixedUniformDistinctQueryGeometry>,
    },
    DistinctQueries {
        groups: Vec<FixedUniformDistinctQueryGeometry>,
    },
}

impl ExactChallengeSpace {
    fn from_geometry(
        geometry: &FixedUniformVerifierMessageGeometry,
    ) -> Result<Self, CompactFactorOneSemanticError> {
        let extension_element_count = u32::try_from(geometry.extension_output_count())
            .map_err(|_| CompactFactorOneSemanticError::ArithmeticOverflow)?;
        let groups = geometry.distinct_query_groups().to_vec();
        match (
            geometry.base_field_output_count(),
            extension_element_count,
            groups.is_empty(),
        ) {
            (0, count, true) if count > 0 => Ok(Self::ExtensionVector {
                element_count: count,
                excluded_element_count: geometry.excluded_extension_prefix_cardinality(),
            }),
            (1, count, false) if count > 0 => {
                Ok(Self::BaseElementExtensionVectorAndDistinctQueries {
                    extension_element_count: count,
                    groups,
                })
            }
            (0, count, false) if count > 0 => Ok(Self::ExtensionVectorAndDistinctQueries {
                extension_element_count: count,
                groups,
            }),
            (0, 0, false) => Ok(Self::DistinctQueries { groups }),
            _ => Err(CompactFactorOneSemanticError::InvalidChallengeGeometry),
        }
    }
}

pub(super) fn extension_field_order() -> BigUint {
    challenge_field_order()
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct CompactFactorOneMoveErrorBound {
    verifier_move_ordinal: u32,
    owner: CompactFactorOneSemanticOwner,
    events: Vec<CompactFactorOneBadEventBound>,
    total_probability: CompactFactorOneExactProbability,
}

/// Opaque executable authority for the selected factor-one semantic error bound.
///
/// The move ledger and exact ratio are deliberately not exposed outside the
/// source-level arithmetic tests.
pub(crate) struct CompactFactorOneSemanticErrorTheorem {
    #[cfg(test)]
    moves: Vec<CompactFactorOneMoveErrorBound>,
    maximum_per_move_error: CompactFactorOneExactProbability,
}

impl CompactFactorOneSemanticErrorTheorem {
    pub(crate) fn into_knowledge_bound(
        self,
    ) -> Result<CompactRelaxedRoundByRoundKnowledgeBound, CompactCdhzAppendixAOneError> {
        CompactRelaxedRoundByRoundKnowledgeBound::from_factor_one_semantic_theorem(self)
    }

    pub(super) fn into_maximum_error_parts(self) -> (BigUint, BigUint) {
        (
            self.maximum_per_move_error.numerator,
            self.maximum_per_move_error.denominator,
        )
    }
}

#[derive(Clone, Copy)]
pub(super) struct CompactFactorOneContractView<'a> {
    pub(super) relation: &'a CompactPublicKeyRelationCatalog,
    pub(super) cfw_configuration: CompactCfwVerifierConfiguration,
    pub(super) verifier_moves: &'a [CompactVerifierMoveContract],
    pub(super) whir_epochs: &'a [CompactWhirEpochContract],
    pub(super) whir_folds: &'a [CompactWhirFoldContract],
}

impl<'view, 'contract: 'view> From<&'view CompactPublicKeyVerifierInputs<'contract>>
    for CompactFactorOneContractView<'view>
{
    fn from(inputs: &'view CompactPublicKeyVerifierInputs<'contract>) -> Self {
        Self {
            relation: inputs.relation,
            cfw_configuration: inputs.cfw_configuration,
            verifier_moves: inputs.verifier_moves,
            whir_epochs: inputs.whir_epochs,
            whir_folds: inputs.whir_folds,
        }
    }
}

/// Recomputes the selected factor-one semantic theorem from verifier-owned
/// contract inputs. This does not inspect or accept a proof transcript.
pub(crate) fn derive_compact_factor_one_semantic_error_theorem(
    inputs: &CompactPublicKeyVerifierInputs<'_>,
) -> Result<CompactFactorOneSemanticErrorTheorem, CompactFactorOneSemanticError> {
    derive_from_contract(CompactFactorOneContractView::from(inputs))
}

fn derive_from_contract(
    contract: CompactFactorOneContractView<'_>,
) -> Result<CompactFactorOneSemanticErrorTheorem, CompactFactorOneSemanticError> {
    validate_contract_geometry(contract)?;
    for verifier_move in contract.verifier_moves {
        let owner = semantic_owner(verifier_move)?;
        validate_challenge_geometry(contract, verifier_move, owner)?;
    }
    executable::derive_factor_one_semantic_error_theorem(contract)
}

fn validate_contract_geometry(
    contract: CompactFactorOneContractView<'_>,
) -> Result<(), CompactFactorOneSemanticError> {
    validate_exact_verifier_chronology(
        contract.verifier_moves,
        contract.cfw_configuration,
        contract.whir_epochs,
        contract.whir_folds,
    )
    .map_err(|_| CompactFactorOneSemanticError::InvalidOwnerChronology)?;
    if contract.whir_epochs.len() != SELECTED_WHIR_EPOCH_COUNT
        || contract.whir_folds.len()
            != SELECTED_WHIR_EPOCH_COUNT * SELECTED_WHIR_FOLD_COUNT_PER_EPOCH
        || contract.relation.padded_witness_element_count()
            != u64::try_from(contract.cfw_configuration.geometry().witness_length())
                .map_err(|_| CompactFactorOneSemanticError::ArithmeticOverflow)?
    {
        return Err(CompactFactorOneSemanticError::InvalidContractGeometry);
    }
    for (epoch_index, epoch) in contract.whir_epochs.iter().enumerate() {
        epoch
            .validate(epoch_index)
            .map_err(|_| CompactFactorOneSemanticError::InvalidContractGeometry)?;
    }
    for (fold_index, fold) in contract.whir_folds.iter().copied().enumerate() {
        fold.validate(fold_index)
            .map_err(|_| CompactFactorOneSemanticError::InvalidContractGeometry)?;
    }
    let cross_epoch = contract
        .relation
        .cross_epoch_copy_geometry()
        .map_err(|_| CompactFactorOneSemanticError::InvalidContractGeometry)?;
    let configured_cross_epoch = contract.cfw_configuration.cross_epoch();
    if cross_epoch.copied_ring_vector_count() != configured_cross_epoch.copied_ring_vector_count
        || cross_epoch.copied_element_count() != configured_cross_epoch.copied_element_count
        || cross_epoch.pre_challenge_message_element_count()
            != configured_cross_epoch.pre_challenge_message_element_count
        || cross_epoch.main_message_element_count()
            != configured_cross_epoch.main_message_element_count
        || cross_epoch.point_coordinate_count() != configured_cross_epoch.point_coordinate_count
    {
        return Err(CompactFactorOneSemanticError::InvalidContractGeometry);
    }
    for epoch in [
        CompactFactorOneEpoch::PreChallenge,
        CompactFactorOneEpoch::Main,
    ] {
        let (epoch_contract, folds) = epoch_and_folds(contract, epoch)?;
        for (batch_ordinal, fold) in folds.iter().enumerate() {
            validate_code(CompactFactorOneCodeDescriptor {
                role: CompactFactorOneCodeRole::WhirSource {
                    epoch,
                    batch_ordinal: u8::try_from(batch_ordinal)
                        .map_err(|_| CompactFactorOneSemanticError::ArithmeticOverflow)?,
                },
                message_length: fold.message_length,
                hiding_randomness_length: fold.hiding_randomness_length,
                block_length: fold.block_length,
                interleaving_width: fold.oracle_width,
                query_count: fold.query_count,
                selected_decoding_error_count: fold.unique_decoding_radius,
            })?;
        }
        for (group_ordinal, group) in epoch_contract
            .external_mask_groups
            .iter()
            .chain(&epoch_contract.internal_mask_groups)
            .enumerate()
        {
            mask_code_descriptor(epoch, group_ordinal, epoch_contract, group)?;
        }
    }
    Ok(())
}

pub(super) fn expected_owner_chronology(
    contract: CompactFactorOneContractView<'_>,
) -> Result<Vec<CompactFactorOneSemanticOwner>, CompactFactorOneSemanticError> {
    let cfw_round_count =
        u32::try_from(contract.cfw_configuration.geometry().sumcheck_round_count())
            .map_err(|_| CompactFactorOneSemanticError::ArithmeticOverflow)?;
    let mut owners = Vec::with_capacity(SELECTED_FACTOR_ONE_VERIFIER_MOVE_COUNT);
    owners.push(CompactFactorOneSemanticOwner::LookupChallenge);
    owners.push(CompactFactorOneSemanticOwner::CrossEpochPoint);
    owners.push(CompactFactorOneSemanticOwner::CfwInitialRandomness);
    owners
        .extend((0..cfw_round_count).map(|round_ordinal| {
            CompactFactorOneSemanticOwner::CfwSumcheckRound { round_ordinal }
        }));
    owners.push(CompactFactorOneSemanticOwner::CfwJointAndPreWhirOpening);
    append_whir_owner_chronology(&mut owners, contract, CompactFactorOneEpoch::PreChallenge)?;
    owners.push(CompactFactorOneSemanticOwner::PreWhirFinalAndMainWhirOpening);
    append_whir_owner_chronology(&mut owners, contract, CompactFactorOneEpoch::Main)?;
    owners.push(CompactFactorOneSemanticOwner::MainWhirFinalQueries);
    Ok(owners)
}

fn append_whir_owner_chronology(
    owners: &mut Vec<CompactFactorOneSemanticOwner>,
    contract: CompactFactorOneContractView<'_>,
    epoch: CompactFactorOneEpoch,
) -> Result<(), CompactFactorOneSemanticError> {
    let (epoch_contract, _) = epoch_and_folds(contract, epoch)?;
    for (batch_ordinal, folding_round_count) in
        epoch_contract.folding_schedule.into_iter().enumerate()
    {
        let batch_ordinal = u8::try_from(batch_ordinal)
            .map_err(|_| CompactFactorOneSemanticError::ArithmeticOverflow)?;
        owners.push(
            CompactFactorOneSemanticOwner::WhirMaskedSumcheckCombination {
                epoch,
                batch_ordinal,
            },
        );
        for round_ordinal in 0..folding_round_count {
            owners.push(CompactFactorOneSemanticOwner::WhirFolding {
                epoch,
                batch_ordinal,
                round_ordinal: u8::try_from(round_ordinal)
                    .map_err(|_| CompactFactorOneSemanticError::ArithmeticOverflow)?,
            });
        }
        if usize::from(batch_ordinal) < SELECTED_WHIR_ROUND_COUNT {
            owners.push(CompactFactorOneSemanticOwner::WhirCodeSwitch {
                epoch,
                round_ordinal: batch_ordinal,
            });
        }
    }
    owners.push(CompactFactorOneSemanticOwner::WhirBaseCombination { epoch });
    Ok(())
}

pub(super) fn semantic_owner(
    verifier_move: &CompactVerifierMoveContract,
) -> Result<CompactFactorOneSemanticOwner, CompactFactorOneSemanticError> {
    let roles = verifier_move.role_coordinates.as_slice();
    let owner = match roles {
        [role] if non_epoch_role(*role, 1, 0) => CompactFactorOneSemanticOwner::LookupChallenge,
        [role] if non_epoch_role(*role, 2, 0) => CompactFactorOneSemanticOwner::CrossEpochPoint,
        [role] if non_epoch_role(*role, 3, 0) => {
            CompactFactorOneSemanticOwner::CfwInitialRandomness
        }
        [role] if non_epoch_role(*role, 4, role.round_ordinal) => {
            CompactFactorOneSemanticOwner::CfwSumcheckRound {
                round_ordinal: role.round_ordinal,
            }
        }
        [joint, opening]
            if non_epoch_role(*joint, 5, 0)
                && epoch_role(*opening, 6, CompactFactorOneEpoch::PreChallenge, 0, 0) =>
        {
            CompactFactorOneSemanticOwner::CfwJointAndPreWhirOpening
        }
        [role] if role.role_tag == 7 && role.round_ordinal == 0 => {
            CompactFactorOneSemanticOwner::WhirMaskedSumcheckCombination {
                epoch: epoch_from_tag(role.epoch)?,
                batch_ordinal: role.batch_ordinal,
            }
        }
        [role] if role.role_tag == 8 => CompactFactorOneSemanticOwner::WhirFolding {
            epoch: epoch_from_tag(role.epoch)?,
            batch_ordinal: role.batch_ordinal,
            round_ordinal: u8::try_from(role.round_ordinal)
                .map_err(|_| CompactFactorOneSemanticError::InvalidOwnerChronology)?,
        },
        [role] if role.role_tag == 9 && role.batch_ordinal == 0 => {
            CompactFactorOneSemanticOwner::WhirCodeSwitch {
                epoch: epoch_from_tag(role.epoch)?,
                round_ordinal: u8::try_from(role.round_ordinal)
                    .map_err(|_| CompactFactorOneSemanticError::InvalidOwnerChronology)?,
            }
        }
        [role] if role.role_tag == 10 && role.batch_ordinal == 0 && role.round_ordinal == 0 => {
            CompactFactorOneSemanticOwner::WhirBaseCombination {
                epoch: epoch_from_tag(role.epoch)?,
            }
        }
        [final_queries, opening]
            if epoch_role(
                *final_queries,
                11,
                CompactFactorOneEpoch::PreChallenge,
                0,
                0,
            ) && epoch_role(*opening, 6, CompactFactorOneEpoch::Main, 0, 0) =>
        {
            CompactFactorOneSemanticOwner::PreWhirFinalAndMainWhirOpening
        }
        [role] if epoch_role(*role, 11, CompactFactorOneEpoch::Main, 0, 0) => {
            CompactFactorOneSemanticOwner::MainWhirFinalQueries
        }
        _ => return Err(CompactFactorOneSemanticError::InvalidOwnerChronology),
    };
    Ok(owner)
}

fn non_epoch_role(role: CompactVerifierRoleCoordinate, role_tag: u8, round_ordinal: u32) -> bool {
    role.role_tag == role_tag
        && role.epoch == 0
        && role.batch_ordinal == 0
        && role.round_ordinal == round_ordinal
}

fn epoch_role(
    role: CompactVerifierRoleCoordinate,
    role_tag: u8,
    epoch: CompactFactorOneEpoch,
    batch_ordinal: u8,
    round_ordinal: u32,
) -> bool {
    role.role_tag == role_tag
        && role.epoch == epoch.contract_tag()
        && role.batch_ordinal == batch_ordinal
        && role.round_ordinal == round_ordinal
}

fn epoch_from_tag(tag: u8) -> Result<CompactFactorOneEpoch, CompactFactorOneSemanticError> {
    match tag {
        1 => Ok(CompactFactorOneEpoch::PreChallenge),
        2 => Ok(CompactFactorOneEpoch::Main),
        _ => Err(CompactFactorOneSemanticError::InvalidOwnerChronology),
    }
}

fn validate_challenge_geometry(
    contract: CompactFactorOneContractView<'_>,
    verifier_move: &CompactVerifierMoveContract,
    owner: CompactFactorOneSemanticOwner,
) -> Result<(), CompactFactorOneSemanticError> {
    validate_role_ranges(verifier_move, owner)?;
    let geometry = &verifier_move.message_geometry;
    let no_groups: &[(u64, u64)] = &[];
    match owner {
        CompactFactorOneSemanticOwner::LookupChallenge => {
            validate_message_geometry(geometry, 1, PROOF_BASE_FIELD_MODULUS, 0, no_groups)
        }
        CompactFactorOneSemanticOwner::CrossEpochPoint => validate_message_geometry(
            geometry,
            u64::from(
                contract
                    .cfw_configuration
                    .cross_epoch()
                    .point_coordinate_count,
            ),
            0,
            0,
            no_groups,
        ),
        CompactFactorOneSemanticOwner::CfwInitialRandomness => {
            let extension_count =
                u64::try_from(contract.cfw_configuration.geometry().sumcheck_round_count())
                    .map_err(|_| CompactFactorOneSemanticError::ArithmeticOverflow)?
                    .checked_add(1)
                    .ok_or(CompactFactorOneSemanticError::ArithmeticOverflow)?;
            validate_message_geometry(geometry, extension_count, 0, 0, no_groups)
        }
        CompactFactorOneSemanticOwner::CfwSumcheckRound { round_ordinal } => {
            let round_count =
                u32::try_from(contract.cfw_configuration.geometry().sumcheck_round_count())
                    .map_err(|_| CompactFactorOneSemanticError::ArithmeticOverflow)?;
            let excluded_count = if round_ordinal + 1 == round_count {
                u64::try_from(
                    contract
                        .cfw_configuration
                        .last_round_excluded_canonical_elements()
                        .len(),
                )
                .map_err(|_| CompactFactorOneSemanticError::ArithmeticOverflow)?
            } else {
                0
            };
            validate_message_geometry(geometry, 1, excluded_count, 0, no_groups)
        }
        CompactFactorOneSemanticOwner::CfwJointAndPreWhirOpening => {
            validate_message_geometry(geometry, 2, 0, 0, no_groups)
        }
        CompactFactorOneSemanticOwner::WhirMaskedSumcheckCombination { .. }
        | CompactFactorOneSemanticOwner::WhirFolding { .. }
        | CompactFactorOneSemanticOwner::WhirBaseCombination { .. } => {
            validate_message_geometry(geometry, 1, 0, 0, no_groups)
        }
        CompactFactorOneSemanticOwner::WhirCodeSwitch {
            epoch,
            round_ordinal,
        } => {
            let code = source_code_descriptor(contract, epoch, round_ordinal)?;
            let groups = [(code.block_length, code.query_count)];
            validate_message_geometry(geometry, 1, 0, 1, &groups)
        }
        CompactFactorOneSemanticOwner::PreWhirFinalAndMainWhirOpening => {
            let groups = final_query_group_geometry(contract, CompactFactorOneEpoch::PreChallenge)?;
            validate_message_geometry(geometry, 1, 0, 0, &groups)
        }
        CompactFactorOneSemanticOwner::MainWhirFinalQueries => {
            let groups = final_query_group_geometry(contract, CompactFactorOneEpoch::Main)?;
            validate_message_geometry(geometry, 0, 0, 0, &groups)
        }
    }
}

fn validate_role_ranges(
    verifier_move: &CompactVerifierMoveContract,
    owner: CompactFactorOneSemanticOwner,
) -> Result<(), CompactFactorOneSemanticError> {
    let geometry = &verifier_move.message_geometry;
    let extension_count = geometry.extension_output_count();
    let base_count = geometry.base_field_output_count();
    let query_group_count = u64::try_from(geometry.distinct_query_groups().len())
        .map_err(|_| CompactFactorOneSemanticError::ArithmeticOverflow)?;
    let roles = verifier_move.role_coordinates.as_slice();
    let valid = match (owner, roles) {
        (CompactFactorOneSemanticOwner::CfwJointAndPreWhirOpening, [joint, opening]) => {
            exact_ranges(*joint, [0, 1], [0, 0], [0, 0])
                && exact_ranges(*opening, [1, 2], [0, 0], [0, 0])
                && extension_count == 2
                && base_count == 0
                && query_group_count == 0
        }
        (
            CompactFactorOneSemanticOwner::PreWhirFinalAndMainWhirOpening,
            [final_queries, opening],
        ) => {
            exact_ranges(*final_queries, [0, 0], [0, 0], [0, query_group_count])
                && exact_ranges(*opening, [0, 1], [0, 0], [0, 0])
                && extension_count == 1
                && base_count == 0
        }
        (_, [role]) => exact_ranges(
            *role,
            [0, extension_count],
            [0, base_count],
            [0, query_group_count],
        ),
        _ => false,
    };
    if !valid {
        return Err(CompactFactorOneSemanticError::InvalidChallengeGeometry);
    }
    Ok(())
}

fn exact_ranges(
    role: CompactVerifierRoleCoordinate,
    extension: [u64; 2],
    base: [u64; 2],
    queries: [u64; 2],
) -> bool {
    [role.extension_output_start, role.extension_output_end] == extension
        && [role.base_field_output_start, role.base_field_output_end] == base
        && [
            role.distinct_query_group_start,
            role.distinct_query_group_end,
        ] == queries
}

fn validate_message_geometry(
    geometry: &FixedUniformVerifierMessageGeometry,
    extension_output_count: u64,
    excluded_extension_prefix_cardinality: u64,
    base_field_output_count: u64,
    expected_groups: &[(u64, u64)],
) -> Result<(), CompactFactorOneSemanticError> {
    if geometry.extension_output_count() != extension_output_count
        || geometry.excluded_extension_prefix_cardinality() != excluded_extension_prefix_cardinality
        || geometry.base_field_output_count() != base_field_output_count
        || geometry.distinct_query_groups().len() != expected_groups.len()
        || geometry
            .distinct_query_groups()
            .iter()
            .zip(expected_groups)
            .any(|(actual, expected)| {
                (actual.domain_cardinality(), actual.query_count()) != *expected
            })
    {
        return Err(CompactFactorOneSemanticError::InvalidChallengeGeometry);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct CompactFactorOneCodeDescriptor {
    pub(super) role: CompactFactorOneCodeRole,
    pub(super) message_length: u64,
    pub(super) hiding_randomness_length: u64,
    pub(super) block_length: u64,
    pub(super) interleaving_width: u64,
    pub(super) query_count: u64,
    pub(super) selected_decoding_error_count: u64,
}

impl CompactFactorOneCodeDescriptor {
    pub(super) fn exact_query_failure(
        &self,
    ) -> Result<CompactFactorOneExactProbability, CompactFactorOneSemanticError> {
        exact_query_failure(*self)
    }
}

fn validate_code(
    code: CompactFactorOneCodeDescriptor,
) -> Result<CompactFactorOneCodeDescriptor, CompactFactorOneSemanticError> {
    let reed_solomon_geometry = CanonicalReedSolomonGeometry::new(
        usize::try_from(code.message_length)
            .map_err(|_| CompactFactorOneSemanticError::ArithmeticOverflow)?,
        usize::try_from(code.hiding_randomness_length)
            .map_err(|_| CompactFactorOneSemanticError::ArithmeticOverflow)?,
        usize::try_from(code.block_length)
            .map_err(|_| CompactFactorOneSemanticError::ArithmeticOverflow)?,
        usize::try_from(code.interleaving_width)
            .map_err(|_| CompactFactorOneSemanticError::ArithmeticOverflow)?,
    )
    .map_err(|_| CompactFactorOneSemanticError::InvalidContractGeometry)?;
    let selected_decoding_error_count =
        u64::try_from(reed_solomon_geometry.selected_decoding_error_count())
            .map_err(|_| CompactFactorOneSemanticError::ArithmeticOverflow)?;
    let maximum_bad_agreement_count = code
        .block_length
        .checked_sub(selected_decoding_error_count)
        .and_then(|count| count.checked_sub(1))
        .ok_or(CompactFactorOneSemanticError::InvalidContractGeometry)?;
    if code.selected_decoding_error_count != selected_decoding_error_count
        || code.query_count == 0
        || code.query_count > maximum_bad_agreement_count
    {
        return Err(CompactFactorOneSemanticError::InvalidContractGeometry);
    }
    Ok(code)
}

pub(super) fn source_code_descriptor(
    contract: CompactFactorOneContractView<'_>,
    epoch: CompactFactorOneEpoch,
    batch_ordinal: u8,
) -> Result<CompactFactorOneCodeDescriptor, CompactFactorOneSemanticError> {
    let (_, folds) = epoch_and_folds(contract, epoch)?;
    let fold = folds
        .get(usize::from(batch_ordinal))
        .ok_or(CompactFactorOneSemanticError::InvalidContractGeometry)?;
    validate_code(CompactFactorOneCodeDescriptor {
        role: CompactFactorOneCodeRole::WhirSource {
            epoch,
            batch_ordinal,
        },
        message_length: fold.message_length,
        hiding_randomness_length: fold.hiding_randomness_length,
        block_length: fold.block_length,
        interleaving_width: fold.oracle_width,
        query_count: fold.query_count,
        selected_decoding_error_count: fold.unique_decoding_radius,
    })
}

pub(super) fn mask_code_descriptor(
    epoch: CompactFactorOneEpoch,
    group_ordinal: usize,
    epoch_contract: &CompactWhirEpochContract,
    group: &CompactWhirMaskGroupContract,
) -> Result<CompactFactorOneCodeDescriptor, CompactFactorOneSemanticError> {
    let dimension = group
        .message_length
        .checked_add(group.randomness_length)
        .ok_or(CompactFactorOneSemanticError::ArithmeticOverflow)?;
    let selected_decoding_error_count = group
        .domain_size
        .checked_sub(dimension)
        .and_then(|distance| distance.checked_sub(1))
        .ok_or(CompactFactorOneSemanticError::InvalidContractGeometry)?
        / 2;
    validate_code(CompactFactorOneCodeDescriptor {
        role: CompactFactorOneCodeRole::WhirMask {
            epoch,
            group_ordinal: u8::try_from(group_ordinal)
                .map_err(|_| CompactFactorOneSemanticError::ArithmeticOverflow)?,
        },
        message_length: group.message_length,
        hiding_randomness_length: group.randomness_length,
        block_length: group.domain_size,
        interleaving_width: group.width,
        query_count: epoch_contract.mask_query_count,
        selected_decoding_error_count,
    })
}

pub(super) fn final_code_descriptors(
    contract: CompactFactorOneContractView<'_>,
    epoch: CompactFactorOneEpoch,
) -> Result<Vec<CompactFactorOneCodeDescriptor>, CompactFactorOneSemanticError> {
    let (epoch_contract, _) = epoch_and_folds(contract, epoch)?;
    let mut codes = Vec::with_capacity(
        1 + epoch_contract.external_mask_groups.len() + epoch_contract.internal_mask_groups.len(),
    );
    codes.push(source_code_descriptor(
        contract,
        epoch,
        u8::try_from(SELECTED_WHIR_FOLD_COUNT_PER_EPOCH - 1)
            .map_err(|_| CompactFactorOneSemanticError::ArithmeticOverflow)?,
    )?);
    for (group_ordinal, group) in epoch_contract
        .external_mask_groups
        .iter()
        .chain(&epoch_contract.internal_mask_groups)
        .enumerate()
    {
        codes.push(mask_code_descriptor(
            epoch,
            group_ordinal,
            epoch_contract,
            group,
        )?);
    }
    Ok(codes)
}

fn final_query_group_geometry(
    contract: CompactFactorOneContractView<'_>,
    epoch: CompactFactorOneEpoch,
) -> Result<Vec<(u64, u64)>, CompactFactorOneSemanticError> {
    final_code_descriptors(contract, epoch).map(|codes| {
        codes
            .into_iter()
            .map(|code| (code.block_length, code.query_count))
            .collect()
    })
}

pub(super) fn sumcheck_mask_message_length(
    epoch: &CompactWhirEpochContract,
    batch_ordinal: u8,
) -> Result<u64, CompactFactorOneSemanticError> {
    let mut matches = epoch
        .internal_mask_groups
        .iter()
        .filter(|group| group.role_tag == 4 && group.coordinate == batch_ordinal);
    let message_length = matches
        .next()
        .map(|group| group.message_length)
        .ok_or(CompactFactorOneSemanticError::InvalidContractGeometry)?;
    if matches.next().is_some() || message_length == 0 {
        return Err(CompactFactorOneSemanticError::InvalidContractGeometry);
    }
    Ok(message_length)
}

pub(super) fn epoch_and_folds(
    contract: CompactFactorOneContractView<'_>,
    epoch: CompactFactorOneEpoch,
) -> Result<(&CompactWhirEpochContract, &[CompactWhirFoldContract]), CompactFactorOneSemanticError>
{
    let epoch_index = usize::from(epoch.contract_tag() - 1);
    let epoch_contract = contract
        .whir_epochs
        .get(epoch_index)
        .filter(|epoch_contract| epoch_contract.epoch == epoch.contract_tag())
        .ok_or(CompactFactorOneSemanticError::InvalidContractGeometry)?;
    let first_fold = epoch_index
        .checked_mul(SELECTED_WHIR_FOLD_COUNT_PER_EPOCH)
        .ok_or(CompactFactorOneSemanticError::ArithmeticOverflow)?;
    let folds = contract
        .whir_folds
        .get(first_fold..first_fold + SELECTED_WHIR_FOLD_COUNT_PER_EPOCH)
        .ok_or(CompactFactorOneSemanticError::InvalidContractGeometry)?;
    if folds.iter().enumerate().any(|(batch_ordinal, fold)| {
        fold.epoch != epoch.contract_tag() || usize::from(fold.batch_ordinal) != batch_ordinal
    }) {
        return Err(CompactFactorOneSemanticError::InvalidContractGeometry);
    }
    Ok((epoch_contract, folds))
}

fn exact_query_failure(
    code: CompactFactorOneCodeDescriptor,
) -> Result<CompactFactorOneExactProbability, CompactFactorOneSemanticError> {
    let maximum_bad_agreement_count = code
        .block_length
        .checked_sub(code.selected_decoding_error_count)
        .and_then(|count| count.checked_sub(1))
        .ok_or(CompactFactorOneSemanticError::InvalidContractGeometry)?;
    CompactFactorOneExactProbability::new(
        falling_factorial(maximum_bad_agreement_count, code.query_count)?,
        falling_factorial(code.block_length, code.query_count)?,
    )
}

fn falling_factorial(
    population_size: u64,
    selection_count: u64,
) -> Result<BigUint, CompactFactorOneSemanticError> {
    if selection_count == 0 || selection_count > population_size {
        return Err(CompactFactorOneSemanticError::InvalidContractGeometry);
    }
    Ok(
        (0..selection_count).fold(BigUint::one(), |product, selected_count| {
            product * BigUint::from(population_size - selected_count)
        }),
    )
}

fn root_event(
    family: CompactFactorOneBadEventFamily,
    numerator: u64,
    excluded_element_count: u64,
) -> Result<CompactFactorOneBadEventBound, CompactFactorOneSemanticError> {
    let denominator = challenge_field_order()
        .checked_sub(&BigUint::from(excluded_element_count))
        .ok_or(CompactFactorOneSemanticError::InvalidProbability)?;
    Ok(CompactFactorOneBadEventBound {
        family,
        probability: CompactFactorOneExactProbability::new(BigUint::from(numerator), denominator)?,
    })
}

fn challenge_field_order() -> BigUint {
    BigUint::from(PROOF_BASE_FIELD_MODULUS).pow(
        u32::try_from(PROOF_CHALLENGE_EXTENSION_DEGREE)
            .expect("the selected extension degree fits u32"),
    )
}

fn greatest_common_divisor(mut left: BigUint, mut right: BigUint) -> BigUint {
    while !right.is_zero() {
        let remainder = &left % &right;
        left = right;
        right = remainder;
    }
    left
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::compact_cdhz_theorem::compact_cfw_direct_initial_transition_bound;
    use crate::bgv::proof_suite::compact_proof_contract::CompactPublicKeyProofContract;
    use crate::bgv::proof_suite::fixed_uniform_verifier_message::FixedUniformDistinctQueryGeometry;

    fn selected_contract() -> CompactPublicKeyProofContract {
        CompactPublicKeyProofContract::decode_selected().expect("selected contract decodes")
    }

    #[test]
    fn selected_contract_derives_all_factor_one_semantic_owners_and_event_families() {
        let contract = selected_contract();
        let inputs = contract.verifier_inputs();
        let theorem = derive_compact_factor_one_semantic_error_theorem(&inputs)
            .expect("selected semantic theorem derives");

        assert_eq!(theorem.moves.len(), SELECTED_FACTOR_ONE_VERIFIER_MOVE_COUNT);
        assert!(
            theorem
                .moves
                .iter()
                .enumerate()
                .all(|(ordinal, move_bound)| {
                    usize::try_from(move_bound.verifier_move_ordinal).ok() == Some(ordinal)
                        && !move_bound.events.is_empty()
                        && move_bound.total_probability
                            == move_bound
                                .events
                                .iter()
                                .fold(CompactFactorOneExactProbability::zero(), |total, event| {
                                    total.add(&event.probability).unwrap()
                                })
                })
        );

        let families = theorem
            .moves
            .iter()
            .flat_map(|move_bound| move_bound.events.iter().map(|event| event.family))
            .collect::<Vec<_>>();
        for expected in [
            CompactFactorOneBadEventFamily::LookupRationalIdentity,
            CompactFactorOneBadEventFamily::CrossEpochMultilinearIdentity,
            CompactFactorOneBadEventFamily::CfwInitialConsistencyIdentity,
            CompactFactorOneBadEventFamily::CfwSumcheckIdentity,
            CompactFactorOneBadEventFamily::CfwZeroEvaderIdentity,
            CompactFactorOneBadEventFamily::WhirOpeningBatchingIdentity,
            CompactFactorOneBadEventFamily::WhirMaskedCombinationIdentity,
            CompactFactorOneBadEventFamily::WhirBinaryMutualCorrelatedAgreement,
            CompactFactorOneBadEventFamily::WhirMaskedSumcheckIdentity,
            CompactFactorOneBadEventFamily::WhirCodeSwitchCombinationIdentity,
            CompactFactorOneBadEventFamily::WhirBaseCombinationIdentity,
        ] {
            assert!(families.contains(&expected));
        }
        assert!(families.iter().any(|family| matches!(
            family,
            CompactFactorOneBadEventFamily::WhirDistinctQueryEscape { .. }
        )));
        assert!(families.iter().any(|family| matches!(
            family,
            CompactFactorOneBadEventFamily::WhirBaseMutualCorrelatedAgreement { .. }
        )));
    }

    #[test]
    fn selected_owner_counts_match_the_exact_interleaved_chronology() {
        let contract = selected_contract();
        let inputs = contract.verifier_inputs();
        let theorem = derive_compact_factor_one_semantic_error_theorem(&inputs)
            .expect("selected semantic theorem derives");

        let count = |predicate: fn(CompactFactorOneSemanticOwner) -> bool| {
            theorem
                .moves
                .iter()
                .filter(|move_bound| predicate(move_bound.owner))
                .count()
        };
        assert_eq!(
            count(|owner| matches!(
                owner,
                CompactFactorOneSemanticOwner::CfwSumcheckRound { .. }
            )),
            23
        );
        assert_eq!(
            count(|owner| matches!(
                owner,
                CompactFactorOneSemanticOwner::WhirMaskedSumcheckCombination { .. }
            )),
            8
        );
        assert_eq!(
            count(|owner| matches!(owner, CompactFactorOneSemanticOwner::WhirFolding { .. })),
            37
        );
        assert_eq!(
            count(|owner| matches!(owner, CompactFactorOneSemanticOwner::WhirCodeSwitch { .. })),
            6
        );
        assert_eq!(
            count(|owner| matches!(
                owner,
                CompactFactorOneSemanticOwner::WhirBaseCombination { .. }
            )),
            2
        );
    }

    #[test]
    fn semantic_theorem_consumes_into_the_opaque_cdhz_bound() {
        let contract = selected_contract();
        let inputs = contract.verifier_inputs();
        let knowledge_bound = derive_compact_factor_one_semantic_error_theorem(&inputs)
            .expect("selected semantic theorem derives")
            .into_knowledge_bound()
            .expect("selected semantic theorem converts");

        assert!(knowledge_bound.maximum_error() >= &compact_cfw_direct_initial_transition_bound());
    }

    #[test]
    fn changed_owner_tag_cannot_mint_the_semantic_theorem() {
        let contract = selected_contract();
        let inputs = contract.verifier_inputs();
        let mut verifier_moves = inputs.verifier_moves.to_vec();
        verifier_moves[0].role_coordinates[0].role_tag = 2;
        let hostile = CompactFactorOneContractView {
            verifier_moves: &verifier_moves,
            ..CompactFactorOneContractView::from(&inputs)
        };

        assert!(matches!(
            derive_from_contract(hostile),
            Err(CompactFactorOneSemanticError::InvalidOwnerChronology)
        ));
    }

    #[test]
    fn changed_response_predecessor_cannot_mint_the_semantic_theorem() {
        let contract = selected_contract();
        let inputs = contract.verifier_inputs();
        let mut verifier_moves = inputs.verifier_moves.to_vec();
        verifier_moves[53].preceding_prover_response_ordinal -= 1;
        let hostile = CompactFactorOneContractView {
            verifier_moves: &verifier_moves,
            ..CompactFactorOneContractView::from(&inputs)
        };

        assert!(matches!(
            derive_from_contract(hostile),
            Err(CompactFactorOneSemanticError::InvalidOwnerChronology)
        ));
    }

    #[test]
    fn changed_commitment_predecessor_cannot_mint_the_semantic_theorem() {
        let contract = selected_contract();
        let inputs = contract.verifier_inputs();
        let mut verifier_moves = inputs.verifier_moves.to_vec();
        verifier_moves[52].preceding_commitment_count -= 1;
        let hostile = CompactFactorOneContractView {
            verifier_moves: &verifier_moves,
            ..CompactFactorOneContractView::from(&inputs)
        };

        assert!(matches!(
            derive_from_contract(hostile),
            Err(CompactFactorOneSemanticError::InvalidOwnerChronology)
        ));
    }

    #[test]
    fn changed_code_radius_cannot_mint_the_semantic_theorem() {
        let contract = selected_contract();
        let inputs = contract.verifier_inputs();
        let mut whir_folds = inputs.whir_folds.to_vec();
        whir_folds[0].unique_decoding_radius += 1;
        let hostile = CompactFactorOneContractView {
            whir_folds: &whir_folds,
            ..CompactFactorOneContractView::from(&inputs)
        };

        assert!(matches!(
            derive_from_contract(hostile),
            Err(CompactFactorOneSemanticError::InvalidContractGeometry)
        ));
    }

    #[test]
    fn changed_code_switch_query_geometry_cannot_mint_the_semantic_theorem() {
        let contract = selected_contract();
        let inputs = contract.verifier_inputs();
        let mut verifier_moves = inputs.verifier_moves.to_vec();
        let code_switch = verifier_moves
            .iter_mut()
            .find(|verifier_move| verifier_move.role_coordinates[0].role_tag == 9)
            .expect("selected chronology has a code-switch move");
        let source_group = code_switch.message_geometry.distinct_query_groups()[0];
        code_switch.message_geometry = FixedUniformVerifierMessageGeometry::new(
            1,
            0,
            1,
            vec![FixedUniformDistinctQueryGeometry::new(
                source_group.domain_cardinality(),
                source_group.query_count() + 1,
            )],
        )
        .expect("hostile geometry remains structurally valid");
        let hostile = CompactFactorOneContractView {
            verifier_moves: &verifier_moves,
            ..CompactFactorOneContractView::from(&inputs)
        };

        assert!(matches!(
            derive_from_contract(hostile),
            Err(CompactFactorOneSemanticError::InvalidOwnerChronology)
        ));
    }
}
