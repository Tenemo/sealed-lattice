//! Logical BCS response-vector geometry for the compact public-key slice.
//!
//! CDHZ Construction 11.7 commits each complete prover response as one vector.
//! The vector below contains the actual oracle rows and scalar messages in
//! disjoint ranges; it never treats an already-hashed inner root as an IOR
//! symbol. Every vector is padded to a power of two for the standard salted
//! Merkle construction of CDHZ Definition 8.2. The padding is committed but is
//! never queried. This ledger independently reconstructs the verifier-owned
//! production codec geometry; it does not claim that the complete proof path
//! already emits the layout.

use super::cfw_reduction::CfwReductionCatalog;
use super::transcript_chronology::{
    PackingTranscriptChronology, TranscriptEpoch, VerifierMove, VerifierMoveRole,
};
use super::uniform_verifier_randomness::PackingUniformVerifierRandomness;
use super::{
    BASE_FIELD_ELEMENT_BYTE_LENGTH, CROSS_EPOCH_DISCLOSED_VALUE_COUNT, CompactStaticCatalogError,
    EXTENSION_FIELD_ELEMENT_BYTE_LENGTH, MERKLE_DIGEST_BYTE_LENGTH,
    MERKLE_FRONTIER_COUNT_BYTE_LENGTH, MaskGroupRole, MaskGroupStaticLedger,
    PRIVATE_LEAF_SALT_BYTE_LENGTH, WHIR_ROUND_COUNT, WhirStaticLedger, checked_add,
    checked_product, maximum_frontier_byte_length, maximum_frontier_parent_hash_count,
};
use crate::bgv::proof_suite::compact_proof_wire::{
    COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH, CompactProofResponseWireGeometry,
    CompactProofWireError, VARIABLE_RESPONSE_COUNT_BYTE_LENGTH,
};
#[cfg(test)]
use crate::bgv::proof_suite::compact_response_merkle::CompactResponseQuerySchedule;
use crate::bgv::proof_suite::compact_response_merkle::{
    CompactResponseComponentGeometry, CompactResponseLeafValueKind, CompactResponseMerkleError,
    CompactResponseMerkleGeometry, CompactResponseQuerySelection,
};
use crate::bgv::proof_suite::compact_transcript::compact_vector_commitment_oracle_identifier;

const WHIR_SUMCHECK_WIRE_EXTENSION_ELEMENT_COUNT: u64 = 2;
const WHIR_AUXILIARY_TARGET_COUNT: u64 = 1;
const WHIR_BASE_MASKED_CLAIM_COUNT: u64 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ResponseComponentRole {
    PreChallengeSource,
    CfwInnerMasks,
    MainSource,
    CfwOuterMasks,
    CrossEpochMasks,
    CrossEpochOpeningEvaluations,
    CfwAuxiliaryTarget,
    CfwSumcheckPolynomial {
        round_ordinal: u32,
    },
    CfwOuterEvaluations,
    CfwFinalValues,
    WhirSumcheckMask {
        epoch: TranscriptEpoch,
        batch_ordinal: u8,
    },
    WhirSumcheckAuxiliaryTarget {
        epoch: TranscriptEpoch,
        batch_ordinal: u8,
    },
    WhirSumcheckWire {
        epoch: TranscriptEpoch,
        batch_ordinal: u8,
        round_ordinal: u8,
    },
    WhirNextSource {
        epoch: TranscriptEpoch,
        round_ordinal: u8,
    },
    WhirCodeSwitchMask {
        epoch: TranscriptEpoch,
        round_ordinal: u8,
    },
    WhirFreshSourceMask {
        epoch: TranscriptEpoch,
    },
    WhirFreshMaskGroup {
        epoch: TranscriptEpoch,
        group_ordinal: u8,
    },
    WhirBaseMaskedClaim {
        epoch: TranscriptEpoch,
    },
    WhirBlindedSourceMessage {
        epoch: TranscriptEpoch,
    },
    WhirBlindedSourceRandomness {
        epoch: TranscriptEpoch,
    },
    WhirBlindedMaskGroup {
        epoch: TranscriptEpoch,
        group_ordinal: u8,
    },
    Padding,
}

impl ResponseComponentRole {
    pub(super) const fn contract_coordinates(self) -> (u8, u8, u8, u32) {
        use ResponseComponentRole::*;

        match self {
            PreChallengeSource => (1, 0, 0, 0),
            CfwInnerMasks => (2, 0, 0, 0),
            MainSource => (3, 0, 0, 0),
            CfwOuterMasks => (4, 0, 0, 0),
            CrossEpochMasks => (5, 0, 0, 0),
            CrossEpochOpeningEvaluations => (6, 0, 0, 0),
            CfwAuxiliaryTarget => (7, 0, 0, 0),
            CfwSumcheckPolynomial { round_ordinal } => (8, 0, 0, round_ordinal),
            CfwOuterEvaluations => (9, 0, 0, 0),
            CfwFinalValues => (10, 0, 0, 0),
            WhirSumcheckMask {
                epoch,
                batch_ordinal,
            } => (11, contract_epoch(epoch), batch_ordinal, 0),
            WhirSumcheckAuxiliaryTarget {
                epoch,
                batch_ordinal,
            } => (12, contract_epoch(epoch), batch_ordinal, 0),
            WhirSumcheckWire {
                epoch,
                batch_ordinal,
                round_ordinal,
            } => (
                13,
                contract_epoch(epoch),
                batch_ordinal,
                round_ordinal as u32,
            ),
            WhirNextSource {
                epoch,
                round_ordinal,
            } => (14, contract_epoch(epoch), 0, round_ordinal as u32),
            WhirCodeSwitchMask {
                epoch,
                round_ordinal,
            } => (15, contract_epoch(epoch), 0, round_ordinal as u32),
            WhirFreshSourceMask { epoch } => (16, contract_epoch(epoch), 0, 0),
            WhirFreshMaskGroup {
                epoch,
                group_ordinal,
            } => (17, contract_epoch(epoch), group_ordinal, 0),
            WhirBaseMaskedClaim { epoch } => (18, contract_epoch(epoch), 0, 0),
            WhirBlindedSourceMessage { epoch } => (19, contract_epoch(epoch), 0, 0),
            WhirBlindedSourceRandomness { epoch } => (20, contract_epoch(epoch), 0, 0),
            WhirBlindedMaskGroup {
                epoch,
                group_ordinal,
            } => (21, contract_epoch(epoch), group_ordinal, 0),
            Padding => (22, 0, 0, 0),
        }
    }
}

const fn contract_epoch(epoch: TranscriptEpoch) -> u8 {
    match epoch {
        TranscriptEpoch::PreChallenge => 1,
        TranscriptEpoch::Main => 2,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ResponseComponentLedger {
    pub(super) role: ResponseComponentRole,
    pub(super) first_leaf_ordinal: u64,
    pub(super) leaf_count: u64,
    pub(super) minimum_queried_leaf_count: u64,
    pub(super) queried_leaf_count: u64,
    pub(super) query_selection: CompactResponseQuerySelection,
    pub(super) value_byte_length_per_leaf: u64,
}

impl ResponseComponentLedger {
    fn minimum_queried_value_byte_length(&self) -> Result<u64, CompactStaticCatalogError> {
        checked_product(&[
            self.minimum_queried_leaf_count,
            self.value_byte_length_per_leaf,
        ])
    }

    fn queried_value_byte_length(&self) -> Result<u64, CompactStaticCatalogError> {
        checked_product(&[self.queried_leaf_count, self.value_byte_length_per_leaf])
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ResponseVectorLedger {
    pub(super) ordinal: u32,
    pub(super) vector_commitment_oracle_identifier: u32,
    pub(super) verifier_move_roles: Vec<VerifierMoveRole>,
    pub(super) components: Vec<ResponseComponentLedger>,
    pub(super) meaningful_leaf_count: u64,
    pub(super) merkle_leaf_count: u64,
    pub(super) minimum_queried_leaf_count: u64,
    pub(super) queried_leaf_count: u64,
    minimum_queried_value_byte_length: u64,
    queried_value_byte_length: u64,
    fiat_shamir_round_salt_byte_length: u64,
    transported_leaf_salt_byte_length: u64,
    maximum_authentication_frontier_byte_length: u64,
    maximum_opening_parent_hash_count: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ResponseTreeGeometry {
    pub(super) ordinal: u32,
    pub(super) merkle_leaf_count: u64,
    pub(super) queried_leaf_count: u64,
    pub(super) maximum_frontier_node_count: u64,
}

impl ResponseVectorLedger {
    fn derive(
        verifier_move: &VerifierMove,
        chronology: &PackingTranscriptChronology,
        pre_challenge_whir: &WhirStaticLedger,
        main_whir: &WhirStaticLedger,
        cfw_reduction: &CfwReductionCatalog,
    ) -> Result<Self, CompactStaticCatalogError> {
        let mut builder = ResponseVectorBuilder::new();
        append_response_components(
            &mut builder,
            verifier_move,
            pre_challenge_whir,
            main_whir,
            cfw_reduction,
        )?;
        let mut ledger = builder.finish(verifier_move)?;
        for component in &mut ledger.components {
            component.query_selection = query_selection_for_component(
                component.role,
                verifier_move.ordinal,
                chronology,
                pre_challenge_whir,
                main_whir,
            )?;
        }
        ledger.check()?;
        Ok(ledger)
    }

    fn check(&self) -> Result<(), CompactStaticCatalogError> {
        if self.components.is_empty()
            || self.verifier_move_roles.is_empty()
            || self.vector_commitment_oracle_identifier
                != compact_vector_commitment_oracle_identifier(self.ordinal)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?
            || self.meaningful_leaf_count == 0
            || self.merkle_leaf_count < self.meaningful_leaf_count
            || !self.merkle_leaf_count.is_power_of_two()
            || self.minimum_queried_leaf_count == 0
            || self.minimum_queried_leaf_count > self.queried_leaf_count
            || self.queried_leaf_count > self.meaningful_leaf_count
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }

        let mut expected_first_leaf_ordinal = 0_u64;
        let mut minimum_queried_leaf_count = 0_u64;
        let mut queried_leaf_count = 0_u64;
        let mut minimum_queried_value_byte_length = 0_u64;
        let mut queried_value_byte_length = 0_u64;
        let mut saw_padding = false;
        for component in &self.components {
            if component.first_leaf_ordinal != expected_first_leaf_ordinal
                || component.leaf_count == 0
                || component.minimum_queried_leaf_count > component.queried_leaf_count
                || component.queried_leaf_count > component.leaf_count
                || (saw_padding && component.role != ResponseComponentRole::Padding)
            {
                return Err(CompactStaticCatalogError::InvalidGeometry);
            }
            match component.query_selection {
                CompactResponseQuerySelection::Unqueried => {
                    if component.minimum_queried_leaf_count != 0
                        || component.queried_leaf_count != 0
                    {
                        return Err(CompactStaticCatalogError::InvalidGeometry);
                    }
                }
                CompactResponseQuerySelection::EveryLeaf => {
                    if component.minimum_queried_leaf_count != component.leaf_count
                        || component.queried_leaf_count != component.leaf_count
                    {
                        return Err(CompactStaticCatalogError::InvalidGeometry);
                    }
                }
                CompactResponseQuerySelection::VerifierMessageDistinctGroup {
                    logical_verifier_move_ordinal,
                    ..
                } => {
                    if component.minimum_queried_leaf_count == 0
                        || component.minimum_queried_leaf_count != component.queried_leaf_count
                        || component.queried_leaf_count == component.leaf_count
                        || logical_verifier_move_ordinal < self.ordinal
                    {
                        return Err(CompactStaticCatalogError::InvalidGeometry);
                    }
                }
                CompactResponseQuerySelection::VerifierMessageDistinctGroupUnion {
                    first_logical_verifier_move_ordinal,
                    second_logical_verifier_move_ordinal,
                    ..
                } => {
                    if component.minimum_queried_leaf_count == 0
                        || first_logical_verifier_move_ordinal < self.ordinal
                        || second_logical_verifier_move_ordinal < self.ordinal
                        || first_logical_verifier_move_ordinal
                            >= second_logical_verifier_move_ordinal
                    {
                        return Err(CompactStaticCatalogError::InvalidGeometry);
                    }
                }
            }
            if component.role == ResponseComponentRole::Padding {
                saw_padding = true;
                if component.query_selection != CompactResponseQuerySelection::Unqueried
                    || component.minimum_queried_leaf_count != 0
                    || component.queried_leaf_count != 0
                    || component.value_byte_length_per_leaf != 0
                {
                    return Err(CompactStaticCatalogError::InvalidGeometry);
                }
            } else if component.value_byte_length_per_leaf == 0 {
                return Err(CompactStaticCatalogError::InvalidGeometry);
            }
            expected_first_leaf_ordinal =
                checked_add(expected_first_leaf_ordinal, component.leaf_count)?;
            minimum_queried_leaf_count = checked_add(
                minimum_queried_leaf_count,
                component.minimum_queried_leaf_count,
            )?;
            queried_leaf_count = checked_add(queried_leaf_count, component.queried_leaf_count)?;
            minimum_queried_value_byte_length = checked_add(
                minimum_queried_value_byte_length,
                component.minimum_queried_value_byte_length()?,
            )?;
            queried_value_byte_length = checked_add(
                queried_value_byte_length,
                component.queried_value_byte_length()?,
            )?;
        }

        if expected_first_leaf_ordinal != self.merkle_leaf_count
            || minimum_queried_leaf_count != self.minimum_queried_leaf_count
            || queried_leaf_count != self.queried_leaf_count
            || minimum_queried_value_byte_length != self.minimum_queried_value_byte_length
            || queried_value_byte_length != self.queried_value_byte_length
            || self.fiat_shamir_round_salt_byte_length
                != u64::try_from(COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?
            || self.transported_leaf_salt_byte_length
                != checked_product(&[self.queried_leaf_count, PRIVATE_LEAF_SALT_BYTE_LENGTH])?
            || self.maximum_authentication_frontier_byte_length
                != maximum_frontier_byte_length_over_query_range(
                    self.merkle_leaf_count,
                    self.minimum_queried_leaf_count,
                    self.queried_leaf_count,
                )?
            || self.maximum_opening_parent_hash_count
                != maximum_frontier_parent_hash_count_over_query_range(
                    self.merkle_leaf_count,
                    self.minimum_queried_leaf_count,
                    self.queried_leaf_count,
                )?
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        Ok(())
    }

    fn maximum_opening_byte_length(&self) -> Result<u64, CompactStaticCatalogError> {
        [
            MERKLE_DIGEST_BYTE_LENGTH,
            self.fiat_shamir_round_salt_byte_length,
            if self.minimum_queried_leaf_count != self.queried_leaf_count {
                u64::try_from(VARIABLE_RESPONSE_COUNT_BYTE_LENGTH)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?
            } else {
                0
            },
            self.queried_value_byte_length,
            self.transported_leaf_salt_byte_length,
            self.maximum_authentication_frontier_byte_length,
        ]
        .into_iter()
        .try_fold(0_u64, checked_add)
    }

    fn production_wire_geometry(
        &self,
        verifier_message_geometry: crate::bgv::proof_suite::fixed_uniform_verifier_message::FixedUniformVerifierMessageGeometry,
    ) -> Result<CompactProofResponseWireGeometry, CompactStaticCatalogError> {
        let mut minimum_queried_base_field_element_count = 0_u64;
        let mut maximum_queried_base_field_element_count = 0_u64;
        let mut minimum_queried_extension_field_element_count = 0_u64;
        let mut maximum_queried_extension_field_element_count = 0_u64;
        for component in self
            .components
            .iter()
            .filter(|component| component.role != ResponseComponentRole::Padding)
        {
            let (
                element_byte_length,
                accumulated_minimum_element_count,
                accumulated_maximum_element_count,
            ) = if component.role == ResponseComponentRole::PreChallengeSource {
                (
                    BASE_FIELD_ELEMENT_BYTE_LENGTH,
                    &mut minimum_queried_base_field_element_count,
                    &mut maximum_queried_base_field_element_count,
                )
            } else {
                (
                    EXTENSION_FIELD_ELEMENT_BYTE_LENGTH,
                    &mut minimum_queried_extension_field_element_count,
                    &mut maximum_queried_extension_field_element_count,
                )
            };
            if component.value_byte_length_per_leaf % element_byte_length != 0 {
                return Err(CompactStaticCatalogError::InvalidGeometry);
            }
            *accumulated_minimum_element_count = checked_add(
                *accumulated_minimum_element_count,
                checked_product(&[
                    component.minimum_queried_leaf_count,
                    component.value_byte_length_per_leaf / element_byte_length,
                ])?,
            )?;
            *accumulated_maximum_element_count = checked_add(
                *accumulated_maximum_element_count,
                checked_product(&[
                    component.queried_leaf_count,
                    component.value_byte_length_per_leaf / element_byte_length,
                ])?,
            )?;
        }
        if checked_add(
            checked_product(&[
                minimum_queried_base_field_element_count,
                BASE_FIELD_ELEMENT_BYTE_LENGTH,
            ])?,
            checked_product(&[
                minimum_queried_extension_field_element_count,
                EXTENSION_FIELD_ELEMENT_BYTE_LENGTH,
            ])?,
        )? != self.minimum_queried_value_byte_length
            || checked_add(
                checked_product(&[
                    maximum_queried_base_field_element_count,
                    BASE_FIELD_ELEMENT_BYTE_LENGTH,
                ])?,
                checked_product(&[
                    maximum_queried_extension_field_element_count,
                    EXTENSION_FIELD_ELEMENT_BYTE_LENGTH,
                ])?,
            )? != self.queried_value_byte_length
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }

        let frontier_digest_byte_length = self
            .maximum_authentication_frontier_byte_length
            .checked_sub(MERKLE_FRONTIER_COUNT_BYTE_LENGTH)
            .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
        if frontier_digest_byte_length % MERKLE_DIGEST_BYTE_LENGTH != 0 {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        CompactProofResponseWireGeometry::new_with_count_ranges(
            self.ordinal,
            minimum_queried_base_field_element_count,
            maximum_queried_base_field_element_count,
            minimum_queried_extension_field_element_count,
            maximum_queried_extension_field_element_count,
            self.minimum_queried_leaf_count,
            self.queried_leaf_count,
            frontier_digest_byte_length / MERKLE_DIGEST_BYTE_LENGTH,
            verifier_message_geometry,
        )
        .map_err(map_production_wire_error)
    }

    fn production_merkle_geometry(
        &self,
    ) -> Result<CompactResponseMerkleGeometry, CompactStaticCatalogError> {
        let components = self
            .components
            .iter()
            .map(|component| {
                let (value_kind, element_byte_length) = match component.role {
                    ResponseComponentRole::PreChallengeSource => (
                        CompactResponseLeafValueKind::BaseField,
                        BASE_FIELD_ELEMENT_BYTE_LENGTH,
                    ),
                    ResponseComponentRole::Padding => (CompactResponseLeafValueKind::Padding, 1),
                    _ => (
                        CompactResponseLeafValueKind::ExtensionField,
                        EXTENSION_FIELD_ELEMENT_BYTE_LENGTH,
                    ),
                };
                if component.value_byte_length_per_leaf % element_byte_length != 0 {
                    return Err(CompactStaticCatalogError::InvalidGeometry);
                }
                Ok(
                    CompactResponseComponentGeometry::new_with_query_count_range(
                        component.first_leaf_ordinal,
                        component.leaf_count,
                        component.minimum_queried_leaf_count,
                        component.queried_leaf_count,
                        component.query_selection,
                        value_kind,
                        component.value_byte_length_per_leaf / element_byte_length,
                    ),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let geometry = CompactResponseMerkleGeometry::new(self.ordinal, components)
            .map_err(map_response_merkle_error)?;
        if geometry.vector_commitment_oracle_identifier()
            != self.vector_commitment_oracle_identifier
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        Ok(geometry)
    }
}

struct ResponseVectorBuilder {
    components: Vec<ResponseComponentLedger>,
    meaningful_leaf_count: u64,
    minimum_queried_leaf_count: u64,
    queried_leaf_count: u64,
    minimum_queried_value_byte_length: u64,
    queried_value_byte_length: u64,
}

impl ResponseVectorBuilder {
    const fn new() -> Self {
        Self {
            components: Vec::new(),
            meaningful_leaf_count: 0,
            minimum_queried_leaf_count: 0,
            queried_leaf_count: 0,
            minimum_queried_value_byte_length: 0,
            queried_value_byte_length: 0,
        }
    }

    fn push(
        &mut self,
        role: ResponseComponentRole,
        leaf_count: u64,
        queried_leaf_count: u64,
        value_byte_length_per_leaf: u64,
    ) -> Result<(), CompactStaticCatalogError> {
        self.push_with_query_count_range(
            role,
            leaf_count,
            queried_leaf_count,
            queried_leaf_count,
            value_byte_length_per_leaf,
        )
    }

    fn push_with_query_count_range(
        &mut self,
        role: ResponseComponentRole,
        leaf_count: u64,
        minimum_queried_leaf_count: u64,
        maximum_queried_leaf_count: u64,
        value_byte_length_per_leaf: u64,
    ) -> Result<(), CompactStaticCatalogError> {
        if role == ResponseComponentRole::Padding
            || leaf_count == 0
            || minimum_queried_leaf_count > maximum_queried_leaf_count
            || maximum_queried_leaf_count > leaf_count
            || value_byte_length_per_leaf == 0
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        self.components.push(ResponseComponentLedger {
            role,
            first_leaf_ordinal: self.meaningful_leaf_count,
            leaf_count,
            minimum_queried_leaf_count,
            queried_leaf_count: maximum_queried_leaf_count,
            query_selection: if minimum_queried_leaf_count == leaf_count {
                CompactResponseQuerySelection::EveryLeaf
            } else {
                CompactResponseQuerySelection::Unqueried
            },
            value_byte_length_per_leaf,
        });
        self.meaningful_leaf_count = checked_add(self.meaningful_leaf_count, leaf_count)?;
        self.minimum_queried_leaf_count =
            checked_add(self.minimum_queried_leaf_count, minimum_queried_leaf_count)?;
        self.queried_leaf_count = checked_add(self.queried_leaf_count, maximum_queried_leaf_count)?;
        self.minimum_queried_value_byte_length = checked_add(
            self.minimum_queried_value_byte_length,
            checked_product(&[minimum_queried_leaf_count, value_byte_length_per_leaf])?,
        )?;
        self.queried_value_byte_length = checked_add(
            self.queried_value_byte_length,
            checked_product(&[maximum_queried_leaf_count, value_byte_length_per_leaf])?,
        )?;
        Ok(())
    }

    fn finish(
        mut self,
        verifier_move: &VerifierMove,
    ) -> Result<ResponseVectorLedger, CompactStaticCatalogError> {
        if self.meaningful_leaf_count == 0 || self.minimum_queried_leaf_count == 0 {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        let merkle_leaf_count = self
            .meaningful_leaf_count
            .checked_next_power_of_two()
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
        if merkle_leaf_count > self.meaningful_leaf_count {
            self.components.push(ResponseComponentLedger {
                role: ResponseComponentRole::Padding,
                first_leaf_ordinal: self.meaningful_leaf_count,
                leaf_count: merkle_leaf_count - self.meaningful_leaf_count,
                minimum_queried_leaf_count: 0,
                queried_leaf_count: 0,
                query_selection: CompactResponseQuerySelection::Unqueried,
                value_byte_length_per_leaf: 0,
            });
        }
        let ledger = ResponseVectorLedger {
            ordinal: verifier_move.ordinal,
            vector_commitment_oracle_identifier: compact_vector_commitment_oracle_identifier(
                verifier_move.ordinal,
            )
            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
            verifier_move_roles: verifier_move.roles.clone(),
            components: self.components,
            meaningful_leaf_count: self.meaningful_leaf_count,
            merkle_leaf_count,
            minimum_queried_leaf_count: self.minimum_queried_leaf_count,
            queried_leaf_count: self.queried_leaf_count,
            minimum_queried_value_byte_length: self.minimum_queried_value_byte_length,
            queried_value_byte_length: self.queried_value_byte_length,
            fiat_shamir_round_salt_byte_length: u64::try_from(
                COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH,
            )
            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
            transported_leaf_salt_byte_length: checked_product(&[
                self.queried_leaf_count,
                PRIVATE_LEAF_SALT_BYTE_LENGTH,
            ])?,
            maximum_authentication_frontier_byte_length:
                maximum_frontier_byte_length_over_query_range(
                    merkle_leaf_count,
                    self.minimum_queried_leaf_count,
                    self.queried_leaf_count,
                )?,
            maximum_opening_parent_hash_count: maximum_frontier_parent_hash_count_over_query_range(
                merkle_leaf_count,
                self.minimum_queried_leaf_count,
                self.queried_leaf_count,
            )?,
        };
        Ok(ledger)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PackingResponseCommitmentCatalog {
    responses: Vec<ResponseVectorLedger>,
    bcs_response_root_count: u64,
    minimum_proof_oracle_query_count: u64,
    proof_oracle_query_count: u64,
    maximum_proof_oracle_length: u64,
    maximum_leaf_value_byte_length: u64,
    maximum_opening_byte_length: u64,
    committed_leaf_count: u64,
    commitment_parent_hash_count: u64,
    maximum_opening_parent_hash_count: u64,
}

impl PackingResponseCommitmentCatalog {
    pub(super) fn derive(
        chronology: &PackingTranscriptChronology,
        pre_challenge_whir: &WhirStaticLedger,
        main_whir: &WhirStaticLedger,
        cfw_reduction: &CfwReductionCatalog,
    ) -> Result<Self, CompactStaticCatalogError> {
        let responses = chronology
            .verifier_moves
            .iter()
            .map(|verifier_move| {
                ResponseVectorLedger::derive(
                    verifier_move,
                    chronology,
                    pre_challenge_whir,
                    main_whir,
                    cfw_reduction,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let catalog = derive_catalog_fields(responses)?;
        catalog.check(chronology)?;
        Ok(catalog)
    }

    pub(super) const fn bcs_response_root_count(&self) -> u64 {
        self.bcs_response_root_count
    }

    pub(super) const fn proof_oracle_query_count(&self) -> u64 {
        self.proof_oracle_query_count
    }

    pub(super) const fn minimum_proof_oracle_query_count(&self) -> u64 {
        self.minimum_proof_oracle_query_count
    }

    pub(super) const fn maximum_proof_oracle_length(&self) -> u64 {
        self.maximum_proof_oracle_length
    }

    pub(super) const fn maximum_leaf_value_byte_length(&self) -> u64 {
        self.maximum_leaf_value_byte_length
    }

    pub(super) const fn committed_leaf_count(&self) -> u64 {
        self.committed_leaf_count
    }

    pub(super) const fn commitment_parent_hash_count(&self) -> u64 {
        self.commitment_parent_hash_count
    }

    pub(super) const fn maximum_opening_parent_hash_count(&self) -> u64 {
        self.maximum_opening_parent_hash_count
    }

    pub(super) fn responses(&self) -> &[ResponseVectorLedger] {
        &self.responses
    }

    pub(super) fn production_wire_geometries(
        &self,
        uniform_verifier_randomness: &PackingUniformVerifierRandomness,
    ) -> Result<Vec<CompactProofResponseWireGeometry>, CompactStaticCatalogError> {
        if self.responses.len() != uniform_verifier_randomness.move_count() {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        self.responses
            .iter()
            .enumerate()
            .map(|(response_ordinal, response)| {
                let wire_geometry = response.production_wire_geometry(
                    uniform_verifier_randomness.fixed_message_geometry(response_ordinal)?,
                )?;
                response
                    .production_merkle_geometry()?
                    .validate_wire_geometry(&wire_geometry)
                    .map_err(map_response_merkle_error)?;
                Ok(wire_geometry)
            })
            .collect()
    }

    pub(super) fn production_merkle_geometries(
        &self,
    ) -> Result<Vec<CompactResponseMerkleGeometry>, CompactStaticCatalogError> {
        self.responses
            .iter()
            .map(ResponseVectorLedger::production_merkle_geometry)
            .collect()
    }

    pub(super) fn maximum_response_query_schedule_heap_byte_length(
        &self,
    ) -> Result<u64, CompactStaticCatalogError> {
        self.responses
            .iter()
            .map(|response| response_query_schedule_byte_length(response.queried_leaf_count))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .max()
            .ok_or(CompactStaticCatalogError::InvalidGeometry)
    }

    pub(super) fn maximum_verifier_merkle_hash_query_count(
        &self,
    ) -> Result<u64, CompactStaticCatalogError> {
        checked_add(
            self.proof_oracle_query_count,
            self.maximum_opening_parent_hash_count,
        )
    }

    pub(super) fn response_tree_geometries(
        &self,
    ) -> Result<Vec<ResponseTreeGeometry>, CompactStaticCatalogError> {
        self.responses
            .iter()
            .map(|response| {
                let frontier_digest_byte_length = response
                    .maximum_authentication_frontier_byte_length
                    .checked_sub(MERKLE_FRONTIER_COUNT_BYTE_LENGTH)
                    .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
                if frontier_digest_byte_length % MERKLE_DIGEST_BYTE_LENGTH != 0 {
                    return Err(CompactStaticCatalogError::InvalidGeometry);
                }
                Ok(ResponseTreeGeometry {
                    ordinal: response.ordinal,
                    merkle_leaf_count: response.merkle_leaf_count,
                    queried_leaf_count: response.queried_leaf_count,
                    maximum_frontier_node_count: frontier_digest_byte_length
                        / MERKLE_DIGEST_BYTE_LENGTH,
                })
            })
            .collect()
    }

    fn check(
        &self,
        chronology: &PackingTranscriptChronology,
    ) -> Result<(), CompactStaticCatalogError> {
        if self.responses.is_empty()
            || !self.responses.windows(2).all(|pair| {
                pair[0].vector_commitment_oracle_identifier
                    < pair[1].vector_commitment_oracle_identifier
            })
            || self
                .responses
                .iter()
                .any(|response| response.check().is_err())
            || self.bcs_response_root_count != chronology.logical_verifier_move_count()?
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        Ok(())
    }
}

fn map_production_wire_error(error: CompactProofWireError) -> CompactStaticCatalogError {
    match error {
        CompactProofWireError::LengthOverflow => CompactStaticCatalogError::ArithmeticOverflow,
        _ => CompactStaticCatalogError::InvalidGeometry,
    }
}

fn map_response_merkle_error(error: CompactResponseMerkleError) -> CompactStaticCatalogError {
    match error {
        CompactResponseMerkleError::CountOverflow => CompactStaticCatalogError::ArithmeticOverflow,
        _ => CompactStaticCatalogError::InvalidGeometry,
    }
}

fn response_query_schedule_byte_length(
    queried_leaf_count: u64,
) -> Result<u64, CompactStaticCatalogError> {
    checked_product(&[
        queried_leaf_count,
        u64::try_from(core::mem::size_of::<u64>())
            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
    ])
}

fn maximum_frontier_byte_length_over_query_range(
    leaf_count: u64,
    minimum_query_count: u64,
    maximum_query_count: u64,
) -> Result<u64, CompactStaticCatalogError> {
    if minimum_query_count == 0 || minimum_query_count > maximum_query_count {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    (minimum_query_count..=maximum_query_count).try_fold(0_u64, |maximum, query_count| {
        maximum_frontier_byte_length(leaf_count, query_count).map(|current| maximum.max(current))
    })
}

fn maximum_frontier_parent_hash_count_over_query_range(
    leaf_count: u64,
    minimum_query_count: u64,
    maximum_query_count: u64,
) -> Result<u64, CompactStaticCatalogError> {
    if minimum_query_count == 0 || minimum_query_count > maximum_query_count {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    (minimum_query_count..=maximum_query_count).try_fold(0_u64, |maximum, query_count| {
        maximum_frontier_parent_hash_count(leaf_count, query_count)
            .map(|current| maximum.max(current))
    })
}

fn derive_catalog_fields(
    responses: Vec<ResponseVectorLedger>,
) -> Result<PackingResponseCommitmentCatalog, CompactStaticCatalogError> {
    let bcs_response_root_count = u64::try_from(responses.len())
        .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
    let minimum_proof_oracle_query_count =
        responses.iter().try_fold(0_u64, |count, response| {
            checked_add(count, response.minimum_queried_leaf_count)
        })?;
    let proof_oracle_query_count = responses.iter().try_fold(0_u64, |count, response| {
        checked_add(count, response.queried_leaf_count)
    })?;
    let maximum_proof_oracle_length = responses
        .iter()
        .map(|response| response.merkle_leaf_count)
        .max()
        .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
    let maximum_leaf_value_byte_length = responses
        .iter()
        .flat_map(|response| &response.components)
        .filter(|component| component.role != ResponseComponentRole::Padding)
        .map(|component| component.value_byte_length_per_leaf)
        .max()
        .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
    let maximum_opening_byte_length = responses.iter().try_fold(0_u64, |count, response| {
        checked_add(count, response.maximum_opening_byte_length()?)
    })?;
    let committed_leaf_count = responses.iter().try_fold(0_u64, |count, response| {
        checked_add(count, response.merkle_leaf_count)
    })?;
    let commitment_parent_hash_count = responses.iter().try_fold(0_u64, |count, response| {
        checked_add(
            count,
            response
                .merkle_leaf_count
                .checked_sub(1)
                .ok_or(CompactStaticCatalogError::InvalidGeometry)?,
        )
    })?;
    let maximum_opening_parent_hash_count =
        responses.iter().try_fold(0_u64, |count, response| {
            checked_add(count, response.maximum_opening_parent_hash_count)
        })?;
    Ok(PackingResponseCommitmentCatalog {
        responses,
        bcs_response_root_count,
        minimum_proof_oracle_query_count,
        proof_oracle_query_count,
        maximum_proof_oracle_length,
        maximum_leaf_value_byte_length,
        maximum_opening_byte_length,
        committed_leaf_count,
        commitment_parent_hash_count,
        maximum_opening_parent_hash_count,
    })
}

fn append_response_components(
    builder: &mut ResponseVectorBuilder,
    verifier_move: &VerifierMove,
    pre_challenge_whir: &WhirStaticLedger,
    main_whir: &WhirStaticLedger,
    cfw_reduction: &CfwReductionCatalog,
) -> Result<(), CompactStaticCatalogError> {
    match verifier_move.roles.as_slice() {
        [VerifierMoveRole::LookupChallenge] => append_source_oracle(
            builder,
            ResponseComponentRole::PreChallengeSource,
            pre_challenge_whir,
            0,
        ),
        [VerifierMoveRole::CrossEpochPoint] => {
            append_mask_oracle(
                builder,
                ResponseComponentRole::CfwInnerMasks,
                mask_group(main_whir, MaskGroupRole::CfwInner)?,
                main_whir.mask_query_count,
            )?;
            append_source_oracle(builder, ResponseComponentRole::MainSource, main_whir, 0)?;
            append_mask_oracle(
                builder,
                ResponseComponentRole::CfwOuterMasks,
                mask_group(main_whir, MaskGroupRole::CfwOuter)?,
                main_whir.mask_query_count,
            )?;
            append_shared_cross_epoch_mask_oracle(builder, pre_challenge_whir, main_whir)
        }
        [VerifierMoveRole::CfwInitialRandomness] => {
            append_extension_scalars(
                builder,
                ResponseComponentRole::CrossEpochOpeningEvaluations,
                CROSS_EPOCH_DISCLOSED_VALUE_COUNT,
            )?;
            append_extension_scalars(
                builder,
                ResponseComponentRole::CfwAuxiliaryTarget,
                cfw_reduction.auxiliary_target_count(),
            )
        }
        [VerifierMoveRole::CfwSumcheckRound { round_ordinal }] => {
            if *round_ordinal >= cfw_reduction.sumcheck_round_count() {
                return Err(CompactStaticCatalogError::InvalidGeometry);
            }
            append_extension_scalars(
                builder,
                ResponseComponentRole::CfwSumcheckPolynomial {
                    round_ordinal: *round_ordinal,
                },
                cfw_reduction.sumcheck_polynomial_element_count_per_round(),
            )
        }
        [
            VerifierMoveRole::CfwJointConstraint,
            VerifierMoveRole::WhirOpeningBatching {
                epoch: TranscriptEpoch::PreChallenge,
            },
        ] => {
            append_extension_scalars(
                builder,
                ResponseComponentRole::CfwOuterEvaluations,
                cfw_reduction.outer_evaluation_count(),
            )?;
            append_extension_scalars(
                builder,
                ResponseComponentRole::CfwFinalValues,
                cfw_reduction.final_value_count(),
            )
        }
        [
            VerifierMoveRole::WhirMaskedSumcheckCombination {
                epoch,
                batch_ordinal,
            },
        ] => append_sumcheck_mask_response(
            builder,
            *epoch,
            *batch_ordinal,
            whir_for_epoch(*epoch, pre_challenge_whir, main_whir),
        ),
        [
            VerifierMoveRole::WhirFolding {
                epoch,
                batch_ordinal,
                round_ordinal,
            },
        ] => append_extension_scalars(
            builder,
            ResponseComponentRole::WhirSumcheckWire {
                epoch: *epoch,
                batch_ordinal: *batch_ordinal,
                round_ordinal: *round_ordinal,
            },
            WHIR_SUMCHECK_WIRE_EXTENSION_ELEMENT_COUNT,
        ),
        [
            VerifierMoveRole::WhirRoundQueryAndCombination {
                epoch,
                round_ordinal,
            },
        ] => append_code_switch_response(
            builder,
            *epoch,
            *round_ordinal,
            whir_for_epoch(*epoch, pre_challenge_whir, main_whir),
        ),
        [VerifierMoveRole::WhirBaseCombination { epoch }] => append_base_response(
            builder,
            *epoch,
            whir_for_epoch(*epoch, pre_challenge_whir, main_whir),
        ),
        [
            VerifierMoveRole::WhirFinalQueries {
                epoch: TranscriptEpoch::PreChallenge,
            },
            VerifierMoveRole::WhirOpeningBatching {
                epoch: TranscriptEpoch::Main,
            },
        ] => append_blinded_response(builder, TranscriptEpoch::PreChallenge, pre_challenge_whir),
        [
            VerifierMoveRole::WhirFinalQueries {
                epoch: TranscriptEpoch::Main,
            },
        ] => append_blinded_response(builder, TranscriptEpoch::Main, main_whir),
        _ => Err(CompactStaticCatalogError::InvalidGeometry),
    }
}

fn append_source_oracle(
    builder: &mut ResponseVectorBuilder,
    role: ResponseComponentRole,
    whir: &WhirStaticLedger,
    oracle_ordinal: usize,
) -> Result<(), CompactStaticCatalogError> {
    let width = *whir
        .oracle_widths
        .get(oracle_ordinal)
        .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
    let height = *whir
        .oracle_heights
        .get(oracle_ordinal)
        .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
    let query_count = *whir
        .query_counts
        .get(oracle_ordinal)
        .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
    let element_byte_length = if oracle_ordinal == 0 {
        whir.initial_oracle_value_byte_length
    } else {
        EXTENSION_FIELD_ELEMENT_BYTE_LENGTH
    };
    builder.push(
        role,
        height,
        query_count,
        checked_product(&[width, element_byte_length])?,
    )
}

fn append_mask_oracle(
    builder: &mut ResponseVectorBuilder,
    role: ResponseComponentRole,
    group: &MaskGroupStaticLedger,
    query_count: u64,
) -> Result<(), CompactStaticCatalogError> {
    builder.push(
        role,
        group.domain_size,
        query_count,
        checked_product(&[group.width, EXTENSION_FIELD_ELEMENT_BYTE_LENGTH])?,
    )
}

fn append_shared_cross_epoch_mask_oracle(
    builder: &mut ResponseVectorBuilder,
    pre_challenge_whir: &WhirStaticLedger,
    main_whir: &WhirStaticLedger,
) -> Result<(), CompactStaticCatalogError> {
    let pre_challenge_group = mask_group(pre_challenge_whir, MaskGroupRole::CrossEpochOpening)?;
    let main_group = mask_group(main_whir, MaskGroupRole::CrossEpochOpening)?;
    if (
        pre_challenge_group.width,
        pre_challenge_group.domain_size,
        pre_challenge_group.message_length,
        pre_challenge_group.randomness_length,
    ) != (
        main_group.width,
        main_group.domain_size,
        main_group.message_length,
        main_group.randomness_length,
    ) {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    let combined_query_count = checked_add(
        pre_challenge_whir.mask_query_count,
        main_whir.mask_query_count,
    )?;
    let minimum_union_count = combined_query_count
        .saturating_sub(pre_challenge_group.domain_size)
        .max(pre_challenge_whir.mask_query_count)
        .max(main_whir.mask_query_count);
    let maximum_union_count = combined_query_count.min(pre_challenge_group.domain_size);
    builder.push_with_query_count_range(
        ResponseComponentRole::CrossEpochMasks,
        pre_challenge_group.domain_size,
        minimum_union_count,
        maximum_union_count,
        checked_product(&[
            pre_challenge_group.width,
            EXTENSION_FIELD_ELEMENT_BYTE_LENGTH,
        ])?,
    )
}

fn append_extension_scalars(
    builder: &mut ResponseVectorBuilder,
    role: ResponseComponentRole,
    element_count: u64,
) -> Result<(), CompactStaticCatalogError> {
    builder.push(
        role,
        element_count,
        element_count,
        EXTENSION_FIELD_ELEMENT_BYTE_LENGTH,
    )
}

fn append_sumcheck_mask_response(
    builder: &mut ResponseVectorBuilder,
    epoch: TranscriptEpoch,
    batch_ordinal: u8,
    whir: &WhirStaticLedger,
) -> Result<(), CompactStaticCatalogError> {
    let group = mask_group(whir, MaskGroupRole::WhirSumcheck { batch_ordinal })?;
    append_mask_oracle(
        builder,
        ResponseComponentRole::WhirSumcheckMask {
            epoch,
            batch_ordinal,
        },
        group,
        whir.mask_query_count,
    )?;
    append_extension_scalars(
        builder,
        ResponseComponentRole::WhirSumcheckAuxiliaryTarget {
            epoch,
            batch_ordinal,
        },
        WHIR_AUXILIARY_TARGET_COUNT,
    )
}

fn append_code_switch_response(
    builder: &mut ResponseVectorBuilder,
    epoch: TranscriptEpoch,
    round_ordinal: u8,
    whir: &WhirStaticLedger,
) -> Result<(), CompactStaticCatalogError> {
    let round_index = usize::from(round_ordinal);
    if round_index >= WHIR_ROUND_COUNT {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    append_source_oracle(
        builder,
        ResponseComponentRole::WhirNextSource {
            epoch,
            round_ordinal,
        },
        whir,
        round_index + 1,
    )?;
    append_mask_oracle(
        builder,
        ResponseComponentRole::WhirCodeSwitchMask {
            epoch,
            round_ordinal,
        },
        mask_group(whir, MaskGroupRole::WhirCodeSwitch { round_ordinal })?,
        whir.mask_query_count,
    )
}

fn append_base_response(
    builder: &mut ResponseVectorBuilder,
    epoch: TranscriptEpoch,
    whir: &WhirStaticLedger,
) -> Result<(), CompactStaticCatalogError> {
    let final_oracle_ordinal = WHIR_ROUND_COUNT;
    builder.push(
        ResponseComponentRole::WhirFreshSourceMask { epoch },
        whir.oracle_heights[final_oracle_ordinal],
        whir.query_counts[final_oracle_ordinal],
        EXTENSION_FIELD_ELEMENT_BYTE_LENGTH,
    )?;
    for (group_ordinal, group) in whir.mask_groups_in_commitment_order().enumerate() {
        append_mask_oracle(
            builder,
            ResponseComponentRole::WhirFreshMaskGroup {
                epoch,
                group_ordinal: u8::try_from(group_ordinal)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
            },
            group,
            whir.mask_query_count,
        )?;
    }
    append_extension_scalars(
        builder,
        ResponseComponentRole::WhirBaseMaskedClaim { epoch },
        WHIR_BASE_MASKED_CLAIM_COUNT,
    )
}

fn append_blinded_response(
    builder: &mut ResponseVectorBuilder,
    epoch: TranscriptEpoch,
    whir: &WhirStaticLedger,
) -> Result<(), CompactStaticCatalogError> {
    let source_message_element_count = 1_u64
        .checked_shl(whir.final_variable_count)
        .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
    append_extension_scalars(
        builder,
        ResponseComponentRole::WhirBlindedSourceMessage { epoch },
        source_message_element_count,
    )?;
    append_extension_scalars(
        builder,
        ResponseComponentRole::WhirBlindedSourceRandomness { epoch },
        whir.query_counts[WHIR_ROUND_COUNT],
    )?;
    for (group_ordinal, group) in whir.mask_groups_in_commitment_order().enumerate() {
        append_extension_scalars(
            builder,
            ResponseComponentRole::WhirBlindedMaskGroup {
                epoch,
                group_ordinal: u8::try_from(group_ordinal)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
            },
            checked_product(&[
                group.width,
                checked_add(group.message_length, group.randomness_length)?,
            ])?,
        )?;
    }
    Ok(())
}

fn mask_group(
    whir: &WhirStaticLedger,
    role: MaskGroupRole,
) -> Result<&MaskGroupStaticLedger, CompactStaticCatalogError> {
    whir.mask_groups_in_commitment_order()
        .find(|group| group.role == role)
        .ok_or(CompactStaticCatalogError::InvalidGeometry)
}

const fn whir_for_epoch<'a>(
    epoch: TranscriptEpoch,
    pre_challenge_whir: &'a WhirStaticLedger,
    main_whir: &'a WhirStaticLedger,
) -> &'a WhirStaticLedger {
    match epoch {
        TranscriptEpoch::PreChallenge => pre_challenge_whir,
        TranscriptEpoch::Main => main_whir,
    }
}

fn query_selection_for_component(
    role: ResponseComponentRole,
    response_ordinal: u32,
    chronology: &PackingTranscriptChronology,
    pre_challenge_whir: &WhirStaticLedger,
    main_whir: &WhirStaticLedger,
) -> Result<CompactResponseQuerySelection, CompactStaticCatalogError> {
    let selection = match role {
        ResponseComponentRole::PreChallengeSource => {
            whir_source_query_selection(chronology, TranscriptEpoch::PreChallenge, 0)?
        }
        ResponseComponentRole::CfwInnerMasks => query_selection_for_verifier_role(
            chronology,
            VerifierMoveRole::WhirFinalQueries {
                epoch: TranscriptEpoch::Main,
            },
            final_mask_query_group_ordinal(main_whir, MaskGroupRole::CfwInner)?,
        )?,
        ResponseComponentRole::MainSource => {
            whir_source_query_selection(chronology, TranscriptEpoch::Main, 0)?
        }
        ResponseComponentRole::CfwOuterMasks => query_selection_for_verifier_role(
            chronology,
            VerifierMoveRole::WhirFinalQueries {
                epoch: TranscriptEpoch::Main,
            },
            final_mask_query_group_ordinal(main_whir, MaskGroupRole::CfwOuter)?,
        )?,
        ResponseComponentRole::CrossEpochMasks => {
            let CompactResponseQuerySelection::VerifierMessageDistinctGroup {
                logical_verifier_move_ordinal: first_logical_verifier_move_ordinal,
                distinct_query_group_ordinal: first_distinct_query_group_ordinal,
            } = query_selection_for_verifier_role(
                chronology,
                VerifierMoveRole::WhirFinalQueries {
                    epoch: TranscriptEpoch::PreChallenge,
                },
                final_mask_query_group_ordinal(
                    pre_challenge_whir,
                    MaskGroupRole::CrossEpochOpening,
                )?,
            )?
            else {
                return Err(CompactStaticCatalogError::InvalidGeometry);
            };
            let CompactResponseQuerySelection::VerifierMessageDistinctGroup {
                logical_verifier_move_ordinal: second_logical_verifier_move_ordinal,
                distinct_query_group_ordinal: second_distinct_query_group_ordinal,
            } = query_selection_for_verifier_role(
                chronology,
                VerifierMoveRole::WhirFinalQueries {
                    epoch: TranscriptEpoch::Main,
                },
                final_mask_query_group_ordinal(main_whir, MaskGroupRole::CrossEpochOpening)?,
            )?
            else {
                return Err(CompactStaticCatalogError::InvalidGeometry);
            };
            CompactResponseQuerySelection::VerifierMessageDistinctGroupUnion {
                first_logical_verifier_move_ordinal,
                first_distinct_query_group_ordinal,
                second_logical_verifier_move_ordinal,
                second_distinct_query_group_ordinal,
            }
        }
        ResponseComponentRole::WhirSumcheckMask {
            epoch,
            batch_ordinal,
        } => {
            let whir = whir_for_epoch(epoch, pre_challenge_whir, main_whir);
            query_selection_for_verifier_role(
                chronology,
                VerifierMoveRole::WhirFinalQueries { epoch },
                final_mask_query_group_ordinal(
                    whir,
                    MaskGroupRole::WhirSumcheck { batch_ordinal },
                )?,
            )?
        }
        ResponseComponentRole::WhirNextSource {
            epoch,
            round_ordinal,
        } => whir_source_query_selection(
            chronology,
            epoch,
            round_ordinal
                .checked_add(1)
                .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?,
        )?,
        ResponseComponentRole::WhirCodeSwitchMask {
            epoch,
            round_ordinal,
        } => {
            let whir = whir_for_epoch(epoch, pre_challenge_whir, main_whir);
            query_selection_for_verifier_role(
                chronology,
                VerifierMoveRole::WhirFinalQueries { epoch },
                final_mask_query_group_ordinal(
                    whir,
                    MaskGroupRole::WhirCodeSwitch { round_ordinal },
                )?,
            )?
        }
        ResponseComponentRole::WhirFreshSourceMask { epoch } => query_selection_for_verifier_role(
            chronology,
            VerifierMoveRole::WhirFinalQueries { epoch },
            0,
        )?,
        ResponseComponentRole::WhirFreshMaskGroup {
            epoch,
            group_ordinal,
        } => {
            let whir = whir_for_epoch(epoch, pre_challenge_whir, main_whir);
            if whir
                .mask_groups_in_commitment_order()
                .nth(usize::from(group_ordinal))
                .is_none()
            {
                return Err(CompactStaticCatalogError::InvalidGeometry);
            }
            query_selection_for_verifier_role(
                chronology,
                VerifierMoveRole::WhirFinalQueries { epoch },
                u32::from(group_ordinal)
                    .checked_add(1)
                    .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?,
            )?
        }
        ResponseComponentRole::Padding => CompactResponseQuerySelection::Unqueried,
        ResponseComponentRole::CrossEpochOpeningEvaluations
        | ResponseComponentRole::CfwAuxiliaryTarget
        | ResponseComponentRole::CfwSumcheckPolynomial { .. }
        | ResponseComponentRole::CfwOuterEvaluations
        | ResponseComponentRole::CfwFinalValues
        | ResponseComponentRole::WhirSumcheckAuxiliaryTarget { .. }
        | ResponseComponentRole::WhirSumcheckWire { .. }
        | ResponseComponentRole::WhirBaseMaskedClaim { .. }
        | ResponseComponentRole::WhirBlindedSourceMessage { .. }
        | ResponseComponentRole::WhirBlindedSourceRandomness { .. }
        | ResponseComponentRole::WhirBlindedMaskGroup { .. } => {
            CompactResponseQuerySelection::EveryLeaf
        }
    };
    if let CompactResponseQuerySelection::VerifierMessageDistinctGroup {
        logical_verifier_move_ordinal,
        ..
    } = selection
        && logical_verifier_move_ordinal < response_ordinal
    {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    Ok(selection)
}

fn query_selection_for_verifier_role(
    chronology: &PackingTranscriptChronology,
    verifier_move_role: VerifierMoveRole,
    distinct_query_group_ordinal: u32,
) -> Result<CompactResponseQuerySelection, CompactStaticCatalogError> {
    let mut matching_moves = chronology
        .verifier_moves
        .iter()
        .filter(|verifier_move| verifier_move.roles.contains(&verifier_move_role));
    let logical_verifier_move_ordinal = matching_moves
        .next()
        .ok_or(CompactStaticCatalogError::InvalidGeometry)?
        .ordinal;
    if matching_moves.next().is_some() {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    Ok(
        CompactResponseQuerySelection::VerifierMessageDistinctGroup {
            logical_verifier_move_ordinal,
            distinct_query_group_ordinal,
        },
    )
}

fn whir_source_query_selection(
    chronology: &PackingTranscriptChronology,
    epoch: TranscriptEpoch,
    oracle_ordinal: u8,
) -> Result<CompactResponseQuerySelection, CompactStaticCatalogError> {
    if usize::from(oracle_ordinal) < WHIR_ROUND_COUNT {
        query_selection_for_verifier_role(
            chronology,
            VerifierMoveRole::WhirRoundQueryAndCombination {
                epoch,
                round_ordinal: oracle_ordinal,
            },
            0,
        )
    } else if usize::from(oracle_ordinal) == WHIR_ROUND_COUNT {
        query_selection_for_verifier_role(
            chronology,
            VerifierMoveRole::WhirFinalQueries { epoch },
            0,
        )
    } else {
        Err(CompactStaticCatalogError::InvalidGeometry)
    }
}

fn final_mask_query_group_ordinal(
    whir: &WhirStaticLedger,
    mask_group_role: MaskGroupRole,
) -> Result<u32, CompactStaticCatalogError> {
    whir.mask_groups_in_commitment_order()
        .position(|group| group.role == mask_group_role)
        .ok_or(CompactStaticCatalogError::InvalidGeometry)
        .and_then(|group_index| {
            u32::try_from(group_index).map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)
        })?
        .checked_add(1)
        .ok_or(CompactStaticCatalogError::ArithmeticOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::compact_proof_wire::{
        CompactPublicInputBindings, decode_compact_public_input, encode_compact_public_input,
    };
    use crate::bgv::proof_suite::compact_public_key_static_catalog::CompactPublicKeyStaticCatalog;
    use crate::bgv::proof_suite::compact_transcript::CompactProverTranscript;
    use crate::bgv::proof_suite::field::ProofBaseFieldElement;
    use crate::foundation::Hash512;

    #[test]
    fn factor_one_responses_have_complete_disjoint_merkle_vectors() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");
        let factor = &catalog.selected;
        let expected_response_count = 82;
        let expected_maximum_length = 262_144;
        let expected_query_count = 79_310;
        let responses = &factor.response_commitments;
        assert_eq!(responses.bcs_response_root_count, expected_response_count);
        assert_eq!(responses.responses.len(), expected_response_count as usize);
        assert_eq!(
            responses.maximum_proof_oracle_length,
            expected_maximum_length
        );
        assert_eq!(responses.proof_oracle_query_count, expected_query_count);
        assert!(responses.minimum_proof_oracle_query_count < responses.proof_oracle_query_count);
        assert_eq!(responses.maximum_opening_byte_length, 26_567_284);
        assert_eq!(responses.committed_leaf_count, 639_270);
        assert_eq!(responses.commitment_parent_hash_count, 639_188);
        assert_eq!(responses.maximum_opening_parent_hash_count, 169_157);
        for (response_ordinal, response) in responses.responses.iter().enumerate() {
            assert_eq!(response.ordinal as usize, response_ordinal);
            assert_eq!(
                response.vector_commitment_oracle_identifier as usize,
                response_ordinal + 1
            );
            assert_eq!(
                response.fiat_shamir_round_salt_byte_length,
                COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH as u64
            );
            response.check().expect("complete response vector");
        }
    }

    #[test]
    fn production_wire_geometry_matches_every_independently_derived_response() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");

        let factor = &catalog.selected;
        let wire_geometries = factor
            .response_commitments
            .production_wire_geometries(&factor.uniform_verifier_randomness)
            .expect("production response wire geometries");
        assert_eq!(
            wire_geometries.len(),
            factor.response_commitments.responses.len()
        );
        assert_eq!(
            wire_geometries
                .iter()
                .map(CompactProofResponseWireGeometry::queried_leaf_count)
                .sum::<u64>(),
            factor.response_commitments.proof_oracle_query_count
        );

        for (response_ordinal, (response, wire_geometry)) in factor
            .response_commitments
            .responses
            .iter()
            .zip(&wire_geometries)
            .enumerate()
        {
            assert_eq!(wire_geometry.ordinal() as usize, response_ordinal);
            assert_eq!(
                wire_geometry.queried_leaf_count(),
                response.queried_leaf_count
            );
            assert_eq!(
                wire_geometry.minimum_queried_leaf_count(),
                response.minimum_queried_leaf_count
            );
            assert_eq!(
                wire_geometry.maximum_frontier_node_count(),
                (response.maximum_authentication_frontier_byte_length
                    - MERKLE_FRONTIER_COUNT_BYTE_LENGTH)
                    / MERKLE_DIGEST_BYTE_LENGTH
            );
            if response_ordinal == 0 {
                assert!(wire_geometry.queried_base_field_element_count() > 0);
                assert_eq!(wire_geometry.queried_extension_field_element_count(), 0);
            } else {
                assert_eq!(wire_geometry.queried_base_field_element_count(), 0);
                assert!(wire_geometry.queried_extension_field_element_count() > 0);
            }
            assert_eq!(
                wire_geometry.verifier_message_geometry(),
                &factor
                    .uniform_verifier_randomness
                    .fixed_message_geometry(response_ordinal)
                    .expect("fixed verifier-message geometry")
            );
        }

        let factor_one = &catalog.selected;
        let mut malformed_response = factor_one.response_commitments.responses[0].clone();
        malformed_response.components[0].value_byte_length_per_leaf += 1;
        assert_eq!(
            malformed_response.production_wire_geometry(
                factor_one
                    .uniform_verifier_randomness
                    .fixed_message_geometry(0)
                    .expect("first fixed verifier-message geometry"),
            ),
            Err(CompactStaticCatalogError::InvalidGeometry)
        );
    }

    #[test]
    fn production_merkle_geometry_matches_every_response_and_wire_shape() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");

        let factor = &catalog.selected;
        let merkle_geometries = factor
            .response_commitments
            .production_merkle_geometries()
            .expect("production response Merkle geometries");
        let tree_geometries = factor
            .response_commitments
            .response_tree_geometries()
            .expect("response tree geometries");
        let wire_geometries = factor
            .response_commitments
            .production_wire_geometries(&factor.uniform_verifier_randomness)
            .expect("production response wire geometries");
        assert_eq!(merkle_geometries.len(), tree_geometries.len());
        assert_eq!(merkle_geometries.len(), wire_geometries.len());
        CompactResponseQuerySchedule::validate_registry(&merkle_geometries, &wire_geometries)
            .expect("every fixed verifier-message query group has an explicit response source");

        for ((merkle_geometry, tree_geometry), wire_geometry) in merkle_geometries
            .iter()
            .zip(&tree_geometries)
            .zip(&wire_geometries)
        {
            assert_eq!(merkle_geometry.response_ordinal(), tree_geometry.ordinal);
            assert_eq!(
                merkle_geometry.vector_commitment_oracle_identifier(),
                compact_vector_commitment_oracle_identifier(tree_geometry.ordinal).unwrap()
            );
            assert_eq!(
                merkle_geometry.merkle_leaf_count(),
                tree_geometry.merkle_leaf_count
            );
            assert_eq!(
                merkle_geometry.queried_leaf_count(),
                tree_geometry.queried_leaf_count
            );
            assert_eq!(
                merkle_geometry.minimum_queried_leaf_count(),
                wire_geometry.minimum_queried_leaf_count()
            );
            assert_eq!(
                merkle_geometry.maximum_queried_leaf_count(),
                wire_geometry.maximum_queried_leaf_count()
            );
            merkle_geometry
                .validate_wire_geometry(wire_geometry)
                .expect("Merkle and wire response shapes agree");
        }
    }

    #[test]
    fn every_production_response_derives_one_exact_schedule_at_its_live_last_query_boundary() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");
        let mut complete_response_schedule_count = 0_usize;

        let factor = &catalog.selected;
        let wire_geometries = factor
            .response_commitments
            .production_wire_geometries(&factor.uniform_verifier_randomness)
            .expect("production response wire geometries");
        let merkle_geometries = factor
            .response_commitments
            .production_merkle_geometries()
            .expect("production response Merkle geometries");
        CompactResponseQuerySchedule::validate_registry(&merkle_geometries, &wire_geometries)
            .expect("complete production response query registry");
        let public_input_bindings = CompactPublicInputBindings::new(
            Hash512::from_bytes([0x21_u8; Hash512::BYTE_LENGTH]),
            Hash512::from_bytes([0x22_u8; Hash512::BYTE_LENGTH]),
            Hash512::from_bytes([0x23_u8; Hash512::BYTE_LENGTH]),
            Hash512::from_bytes(catalog.relation_plan_hash),
        );
        let public_input_values =
            vec![
                ProofBaseFieldElement::ZERO;
                usize::try_from(factor.public_input_wire_geometry.field_element_count())
                    .expect("production public-input count fits usize")
            ];
        let canonical_public_input_bytes = encode_compact_public_input(
            factor.public_input_wire_geometry,
            public_input_bindings,
            &public_input_values,
        )
        .expect("production public input encodes canonically");
        drop(public_input_values);
        let decoded_public_input = decode_compact_public_input(
            factor.public_input_wire_geometry,
            public_input_bindings,
            &canonical_public_input_bytes,
        )
        .expect("production public input decodes canonically");
        let mut transcript = CompactProverTranscript::new(
            &factor.proof_wire_geometry,
            &decoded_public_input,
            &canonical_public_input_bytes,
        )
        .expect("production transcript starts");
        let mut verifier_messages = Vec::with_capacity(wire_geometries.len());
        for response_ordinal in 0..wire_geometries.len() {
            let response_ordinal =
                u32::try_from(response_ordinal).expect("production response ordinal fits u32");
            let mut response_root = [0x41_u8; Hash512::BYTE_LENGTH];
            response_root[8..12].copy_from_slice(&response_ordinal.to_le_bytes());
            let mut fiat_shamir_round_salt = [0x51_u8; COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH];
            fiat_shamir_round_salt[8..12].copy_from_slice(&response_ordinal.to_le_bytes());
            transcript
                .record_response_commitment(response_root, fiat_shamir_round_salt)
                .expect("production response commitment enters the transcript");
            verifier_messages.push(
                transcript
                    .derive_verifier_message()
                    .expect("production verifier message derives from the live prefix"),
            );
        }
        transcript
            .finish()
            .expect("production transcript consumes every response");
        assert_eq!(
            verifier_messages.len(),
            factor.uniform_verifier_randomness.move_count()
        );

        let mut total_queried_leaf_count = 0_u64;
        let mut maximum_schedule_heap_byte_length = 0_u64;
        for (response_ordinal, (merkle_geometry, response)) in merkle_geometries
            .iter()
            .zip(&factor.response_commitments.responses)
            .enumerate()
        {
            let schedule = CompactResponseQuerySchedule::derive(
                merkle_geometry,
                &wire_geometries,
                &verifier_messages,
            )
            .expect("one production response query schedule");
            let last_query_message_count = usize::try_from(
                merkle_geometry
                    .last_query_verifier_move_ordinal()
                    .checked_add(1)
                    .expect("last-query message count fits u32"),
            )
            .expect("last-query message count fits usize");
            let live_schedule = CompactResponseQuerySchedule::derive_at_last_query_boundary(
                merkle_geometry,
                &wire_geometries,
                &verifier_messages[..last_query_message_count],
            )
            .expect("live last-query prefix derives the exact schedule");
            assert_eq!(live_schedule, schedule);
            assert_eq!(
                CompactResponseQuerySchedule::derive_at_last_query_boundary(
                    merkle_geometry,
                    &wire_geometries,
                    &verifier_messages[..last_query_message_count - 1],
                ),
                Err(CompactResponseMerkleError::InvalidOpeningIndices)
            );
            let mut delayed_message_prefix = verifier_messages[..last_query_message_count].to_vec();
            delayed_message_prefix.push(verifier_messages[last_query_message_count - 1].clone());
            assert_eq!(
                CompactResponseQuerySchedule::derive_at_last_query_boundary(
                    merkle_geometry,
                    &wire_geometries,
                    &delayed_message_prefix,
                ),
                Err(CompactResponseMerkleError::InvalidOpeningIndices)
            );
            assert_eq!(
                usize::try_from(merkle_geometry.response_ordinal()).unwrap(),
                response_ordinal
            );
            assert!(
                (response.minimum_queried_leaf_count..=response.queried_leaf_count)
                    .contains(&u64::try_from(schedule.as_slice().len()).unwrap())
            );
            assert!(schedule.as_slice().windows(2).all(|pair| pair[0] < pair[1]));
            let schedule_heap_byte_length = schedule
                .owned_heap_byte_length()
                .expect("exact query-schedule heap");
            assert_eq!(
                schedule_heap_byte_length,
                response_query_schedule_byte_length(response.queried_leaf_count).unwrap()
            );
            total_queried_leaf_count = checked_add(
                total_queried_leaf_count,
                u64::try_from(schedule.as_slice().len()).unwrap(),
            )
            .unwrap();
            maximum_schedule_heap_byte_length =
                maximum_schedule_heap_byte_length.max(schedule_heap_byte_length);
            complete_response_schedule_count += 1;
        }
        assert!(
            (factor
                .response_commitments
                .minimum_proof_oracle_query_count()
                ..=factor.response_commitments.proof_oracle_query_count)
                .contains(&total_queried_leaf_count)
        );
        assert_eq!(
            maximum_schedule_heap_byte_length,
            factor
                .response_commitments
                .maximum_response_query_schedule_heap_byte_length()
                .unwrap()
        );

        let mut truncated_message_registry = verifier_messages;
        truncated_message_registry.pop();
        assert_eq!(
            CompactResponseQuerySchedule::derive(
                &merkle_geometries[0],
                &wire_geometries,
                &truncated_message_registry,
            ),
            Err(CompactResponseMerkleError::InvalidOpeningIndices)
        );
        assert_eq!(complete_response_schedule_count, 82);
    }

    #[test]
    fn response_catalog_owns_the_cfw_scalar_messages_without_a_status_field() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");
        let responses = &catalog.selected.response_commitments.responses;

        let cfw_scalar_leaf_count = responses
            .iter()
            .flat_map(|response| &response.components)
            .filter(|component| {
                matches!(
                    component.role,
                    ResponseComponentRole::CfwAuxiliaryTarget
                        | ResponseComponentRole::CfwSumcheckPolynomial { .. }
                        | ResponseComponentRole::CfwOuterEvaluations
                        | ResponseComponentRole::CfwFinalValues
                )
            })
            .map(|component| component.leaf_count)
            .sum::<u64>();
        assert_eq!(cfw_scalar_leaf_count, 211);

        let cross_epoch_openings = responses
            .iter()
            .flat_map(|response| &response.components)
            .find(|component| component.role == ResponseComponentRole::CrossEpochOpeningEvaluations)
            .expect("three cross-epoch disclosures");
        assert_eq!(cross_epoch_openings.leaf_count, 3);
        assert_eq!(cross_epoch_openings.queried_leaf_count, 3);
    }

    #[test]
    fn response_catalog_owns_one_shared_cross_epoch_oracle_and_both_query_groups() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");
        let factor = &catalog.selected;
        let cross_epoch_response = factor
            .response_commitments
            .responses
            .iter()
            .find(|response| response.verifier_move_roles == [VerifierMoveRole::CrossEpochPoint])
            .expect("one response precedes the cross-epoch point");
        let shared_component = cross_epoch_response
            .components
            .iter()
            .find(|component| component.role == ResponseComponentRole::CrossEpochMasks)
            .expect("shared cross-epoch mask rows have one response-vector owner");
        let shared_group = mask_group(&factor.pre_challenge_whir, MaskGroupRole::CrossEpochOpening)
            .expect("pre-challenge shared mask group");
        assert_eq!(shared_component.leaf_count, shared_group.domain_size);
        assert_eq!(shared_component.minimum_queried_leaf_count, 399);
        assert_eq!(shared_component.queried_leaf_count, 798);
        assert_eq!(
            shared_component.value_byte_length_per_leaf,
            2 * EXTENSION_FIELD_ELEMENT_BYTE_LENGTH
        );
        let CompactResponseQuerySelection::VerifierMessageDistinctGroupUnion {
            first_logical_verifier_move_ordinal,
            second_logical_verifier_move_ordinal,
            ..
        } = shared_component.query_selection
        else {
            panic!("shared cross-epoch rows must use the two final-query groups")
        };
        assert!(first_logical_verifier_move_ordinal < second_logical_verifier_move_ordinal);

        let wire_geometries = factor
            .response_commitments
            .production_wire_geometries(&factor.uniform_verifier_randomness)
            .expect("production response wire geometries");
        let wire_geometry = &wire_geometries
            [usize::try_from(cross_epoch_response.ordinal).expect("response ordinal")];
        assert!(wire_geometry.has_variable_counts());
        assert_eq!(
            wire_geometry.maximum_queried_leaf_count() - wire_geometry.minimum_queried_leaf_count(),
            399
        );
        assert_eq!(
            wire_geometry.maximum_queried_extension_field_element_count()
                - wire_geometry.minimum_queried_extension_field_element_count(),
            798
        );
    }

    #[test]
    fn response_catalog_refuses_overlap_padding_and_query_mutations() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");
        let response = &catalog.selected.response_commitments.responses[1];

        let mut overlapping = response.clone();
        overlapping.components[1].first_leaf_ordinal -= 1;
        assert_eq!(
            overlapping.check(),
            Err(CompactStaticCatalogError::InvalidGeometry)
        );

        let mut queried_padding = response.clone();
        let padding = queried_padding
            .components
            .last_mut()
            .expect("padded cross-epoch response");
        assert_eq!(padding.role, ResponseComponentRole::Padding);
        padding.queried_leaf_count = 1;
        assert_eq!(
            queried_padding.check(),
            Err(CompactStaticCatalogError::InvalidGeometry)
        );

        let mut excessive_queries = response.clone();
        excessive_queries.components[0].queried_leaf_count =
            excessive_queries.components[0].leaf_count + 1;
        assert_eq!(
            excessive_queries.check(),
            Err(CompactStaticCatalogError::InvalidGeometry)
        );
    }

    #[test]
    fn scalar_only_responses_are_not_misclassified_as_empty_rounds() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");
        let factor = &catalog.selected;
        assert!(
            factor
                .response_commitments
                .responses
                .iter()
                .all(|response| {
                    response.meaningful_leaf_count > 0 && response.queried_leaf_count > 0
                })
        );
        assert!(
            factor
                .response_commitments
                .responses
                .iter()
                .filter(|response| {
                    response
                        .verifier_move_roles
                        .iter()
                        .any(|role| matches!(role, VerifierMoveRole::CfwSumcheckRound { .. }))
                })
                .all(|response| {
                    response.meaningful_leaf_count
                        == catalog
                            .cfw_reduction
                            .sumcheck_polynomial_element_count_per_round()
                        && response.queried_leaf_count
                            == catalog
                                .cfw_reduction
                                .sumcheck_polynomial_element_count_per_round()
                })
        );
    }

    #[test]
    fn pre_challenge_source_rows_remain_base_field_symbols() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");
        let factor = &catalog.selected;
        let source = &factor.response_commitments.responses[0].components[0];
        assert_eq!(source.role, ResponseComponentRole::PreChallengeSource);
        assert_eq!(
            source.value_byte_length_per_leaf,
            factor.pre_challenge_whir.oracle_widths[0] * BASE_FIELD_ELEMENT_BYTE_LENGTH
        );
    }

    #[test]
    fn cfw_mask_messages_match_the_construction_lengths() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");
        assert_eq!(catalog.cfw_reduction.inner_mask_message_length(), 4);
        assert_eq!(catalog.cfw_reduction.outer_mask_message_length(), 8);
    }
}
