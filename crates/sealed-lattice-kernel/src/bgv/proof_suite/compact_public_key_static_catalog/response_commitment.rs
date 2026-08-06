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
    BASE_FIELD_ELEMENT_BYTE_LENGTH, CROSS_EPOCH_EXPLICIT_OPENING_COUNT, CompactStaticCatalogError,
    EXTENSION_FIELD_ELEMENT_BYTE_LENGTH, MERKLE_DIGEST_BYTE_LENGTH,
    MERKLE_FRONTIER_COUNT_BYTE_LENGTH, MaskGroupRole, MaskGroupStaticLedger,
    PRIVATE_LEAF_SALT_BYTE_LENGTH, WHIR_ROUND_COUNT, WhirStaticLedger, checked_add,
    checked_product, maximum_frontier_byte_length, maximum_frontier_parent_hash_count,
};
use crate::bgv::proof_suite::compact_proof_wire::{
    COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH, CompactProofResponseWireGeometry,
    CompactProofWireError,
};
use crate::bgv::proof_suite::compact_response_merkle::{
    CompactResponseComponentGeometry, CompactResponseFrontierScannerHeapGeometry,
    CompactResponseLeafValueKind, CompactResponseMerkleError, CompactResponseMerkleGeometry,
    CompactResponsePostorderWriterHeapGeometry, CompactResponseQuerySchedule,
    CompactResponseQuerySelection,
};
use crate::bgv::proof_suite::compact_response_tree_external::{
    CompactResponseTreeExternalMemoryGeometry, CompactResponseTreeExternalMemorySetupError,
};
use crate::bgv::proof_suite::compact_transcript::compact_vector_commitment_oracle_identifier;

const WHIR_SUMCHECK_WIRE_EXTENSION_ELEMENT_COUNT: u64 = 2;
const WHIR_AUXILIARY_TARGET_COUNT: u64 = 1;
const WHIR_BASE_MASKED_CLAIM_COUNT: u64 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResponseComponentRole {
    PreChallengeSource,
    CfwInnerMasks,
    MainSource,
    CfwOuterMasks,
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

#[derive(Clone, Debug, PartialEq, Eq)]
struct ResponseComponentLedger {
    role: ResponseComponentRole,
    first_leaf_ordinal: u64,
    leaf_count: u64,
    queried_leaf_count: u64,
    query_selection: CompactResponseQuerySelection,
    value_byte_length_per_leaf: u64,
}

impl ResponseComponentLedger {
    fn queried_value_byte_length(&self) -> Result<u64, CompactStaticCatalogError> {
        checked_product(&[self.queried_leaf_count, self.value_byte_length_per_leaf])
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ResponseVectorLedger {
    ordinal: u32,
    vector_commitment_oracle_identifier: u32,
    verifier_move_roles: Vec<VerifierMoveRole>,
    components: Vec<ResponseComponentLedger>,
    meaningful_leaf_count: u64,
    merkle_leaf_count: u64,
    queried_leaf_count: u64,
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
            || self.queried_leaf_count == 0
            || self.queried_leaf_count > self.meaningful_leaf_count
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }

        let mut expected_first_leaf_ordinal = 0_u64;
        let mut queried_leaf_count = 0_u64;
        let mut queried_value_byte_length = 0_u64;
        let mut saw_padding = false;
        for component in &self.components {
            if component.first_leaf_ordinal != expected_first_leaf_ordinal
                || component.leaf_count == 0
                || component.queried_leaf_count > component.leaf_count
                || (saw_padding && component.role != ResponseComponentRole::Padding)
            {
                return Err(CompactStaticCatalogError::InvalidGeometry);
            }
            match component.query_selection {
                CompactResponseQuerySelection::Unqueried => {
                    if component.queried_leaf_count != 0 {
                        return Err(CompactStaticCatalogError::InvalidGeometry);
                    }
                }
                CompactResponseQuerySelection::EveryLeaf => {
                    if component.queried_leaf_count != component.leaf_count {
                        return Err(CompactStaticCatalogError::InvalidGeometry);
                    }
                }
                CompactResponseQuerySelection::VerifierMessageDistinctGroup {
                    logical_verifier_move_ordinal,
                    ..
                } => {
                    if component.queried_leaf_count == 0
                        || component.queried_leaf_count == component.leaf_count
                        || logical_verifier_move_ordinal < self.ordinal
                    {
                        return Err(CompactStaticCatalogError::InvalidGeometry);
                    }
                }
            }
            if component.role == ResponseComponentRole::Padding {
                saw_padding = true;
                if component.query_selection != CompactResponseQuerySelection::Unqueried
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
            queried_leaf_count = checked_add(queried_leaf_count, component.queried_leaf_count)?;
            queried_value_byte_length = checked_add(
                queried_value_byte_length,
                component.queried_value_byte_length()?,
            )?;
        }

        if expected_first_leaf_ordinal != self.merkle_leaf_count
            || queried_leaf_count != self.queried_leaf_count
            || queried_value_byte_length != self.queried_value_byte_length
            || self.fiat_shamir_round_salt_byte_length
                != u64::try_from(COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?
            || self.transported_leaf_salt_byte_length
                != checked_product(&[self.queried_leaf_count, PRIVATE_LEAF_SALT_BYTE_LENGTH])?
            || self.maximum_authentication_frontier_byte_length
                != maximum_frontier_byte_length(self.merkle_leaf_count, self.queried_leaf_count)?
            || self.maximum_opening_parent_hash_count
                != maximum_frontier_parent_hash_count(
                    self.merkle_leaf_count,
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
        let mut queried_base_field_element_count = 0_u64;
        let mut queried_extension_field_element_count = 0_u64;
        for component in self
            .components
            .iter()
            .filter(|component| component.role != ResponseComponentRole::Padding)
        {
            let (element_byte_length, accumulated_element_count) =
                if component.role == ResponseComponentRole::PreChallengeSource {
                    (
                        BASE_FIELD_ELEMENT_BYTE_LENGTH,
                        &mut queried_base_field_element_count,
                    )
                } else {
                    (
                        EXTENSION_FIELD_ELEMENT_BYTE_LENGTH,
                        &mut queried_extension_field_element_count,
                    )
                };
            if component.value_byte_length_per_leaf % element_byte_length != 0 {
                return Err(CompactStaticCatalogError::InvalidGeometry);
            }
            *accumulated_element_count = checked_add(
                *accumulated_element_count,
                checked_product(&[
                    component.queried_leaf_count,
                    component.value_byte_length_per_leaf / element_byte_length,
                ])?,
            )?;
        }
        if checked_add(
            checked_product(&[
                queried_base_field_element_count,
                BASE_FIELD_ELEMENT_BYTE_LENGTH,
            ])?,
            checked_product(&[
                queried_extension_field_element_count,
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
        CompactProofResponseWireGeometry::new(
            self.ordinal,
            queried_base_field_element_count,
            queried_extension_field_element_count,
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
                Ok(CompactResponseComponentGeometry::new(
                    component.first_leaf_ordinal,
                    component.leaf_count,
                    component.queried_leaf_count,
                    component.query_selection,
                    value_kind,
                    component.value_byte_length_per_leaf / element_byte_length,
                ))
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
    queried_leaf_count: u64,
    queried_value_byte_length: u64,
}

impl ResponseVectorBuilder {
    const fn new() -> Self {
        Self {
            components: Vec::new(),
            meaningful_leaf_count: 0,
            queried_leaf_count: 0,
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
        if role == ResponseComponentRole::Padding
            || leaf_count == 0
            || queried_leaf_count > leaf_count
            || value_byte_length_per_leaf == 0
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        self.components.push(ResponseComponentLedger {
            role,
            first_leaf_ordinal: self.meaningful_leaf_count,
            leaf_count,
            queried_leaf_count,
            query_selection: if queried_leaf_count == leaf_count {
                CompactResponseQuerySelection::EveryLeaf
            } else {
                CompactResponseQuerySelection::Unqueried
            },
            value_byte_length_per_leaf,
        });
        self.meaningful_leaf_count = checked_add(self.meaningful_leaf_count, leaf_count)?;
        self.queried_leaf_count = checked_add(self.queried_leaf_count, queried_leaf_count)?;
        self.queried_value_byte_length = checked_add(
            self.queried_value_byte_length,
            checked_product(&[queried_leaf_count, value_byte_length_per_leaf])?,
        )?;
        Ok(())
    }

    fn finish(
        mut self,
        verifier_move: &VerifierMove,
    ) -> Result<ResponseVectorLedger, CompactStaticCatalogError> {
        if self.meaningful_leaf_count == 0 || self.queried_leaf_count == 0 {
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
            queried_leaf_count: self.queried_leaf_count,
            queried_value_byte_length: self.queried_value_byte_length,
            fiat_shamir_round_salt_byte_length: u64::try_from(
                COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH,
            )
            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
            transported_leaf_salt_byte_length: checked_product(&[
                self.queried_leaf_count,
                PRIVATE_LEAF_SALT_BYTE_LENGTH,
            ])?,
            maximum_authentication_frontier_byte_length: maximum_frontier_byte_length(
                merkle_leaf_count,
                self.queried_leaf_count,
            )?,
            maximum_opening_parent_hash_count: maximum_frontier_parent_hash_count(
                merkle_leaf_count,
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
        catalog.check(chronology, pre_challenge_whir, main_whir, cfw_reduction)?;
        Ok(catalog)
    }

    pub(super) const fn bcs_response_root_count(&self) -> u64 {
        self.bcs_response_root_count
    }

    pub(super) const fn proof_oracle_query_count(&self) -> u64 {
        self.proof_oracle_query_count
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

    pub(super) fn maximum_postorder_writer_heap_geometry(
        &self,
    ) -> Result<CompactResponsePostorderWriterHeapGeometry, CompactStaticCatalogError> {
        self.production_merkle_geometries()?
            .iter()
            .map(|geometry| {
                CompactResponsePostorderWriterHeapGeometry::derive(geometry)
                    .map_err(map_response_merkle_error)
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .max_by_key(|geometry| geometry.maximum_owned_heap_byte_length())
            .ok_or(CompactStaticCatalogError::InvalidGeometry)
    }

    pub(super) fn maximum_frontier_scanner_heap_geometry(
        &self,
    ) -> Result<CompactResponseFrontierScannerHeapGeometry, CompactStaticCatalogError> {
        let maximum_frontier_node_count = self
            .response_tree_geometries()?
            .iter()
            .map(|geometry| geometry.maximum_frontier_node_count)
            .max()
            .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
        CompactResponseFrontierScannerHeapGeometry::derive(maximum_frontier_node_count)
            .map_err(map_response_merkle_error)
    }

    pub(super) fn maximum_external_memory_geometry(
        &self,
    ) -> Result<CompactResponseTreeExternalMemoryGeometry, CompactStaticCatalogError> {
        self.production_merkle_geometries()?
            .iter()
            .map(|geometry| {
                CompactResponseTreeExternalMemoryGeometry::derive(geometry)
                    .map_err(map_response_tree_setup_error)
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .max_by_key(|geometry| geometry.tree_byte_length())
            .ok_or(CompactStaticCatalogError::InvalidGeometry)
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

    pub(super) fn maximum_response_input_heap_payload_byte_length(
        &self,
    ) -> Result<u64, CompactStaticCatalogError> {
        self.responses
            .iter()
            .map(|response| {
                let frontier_digest_byte_length = response
                    .maximum_authentication_frontier_byte_length
                    .checked_sub(MERKLE_FRONTIER_COUNT_BYTE_LENGTH)
                    .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
                checked_add(
                    response.queried_value_byte_length,
                    checked_add(
                        response.transported_leaf_salt_byte_length,
                        checked_add(
                            frontier_digest_byte_length,
                            response_query_schedule_byte_length(response.queried_leaf_count)?,
                        )?,
                    )?,
                )
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .max()
            .ok_or(CompactStaticCatalogError::InvalidGeometry)
    }

    pub(super) fn maximum_response_tree_kernel_heap_byte_length(
        &self,
    ) -> Result<u64, CompactStaticCatalogError> {
        let merkle_geometries = self.production_merkle_geometries()?;
        if merkle_geometries.len() != self.responses.len() {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        merkle_geometries
            .iter()
            .zip(&self.responses)
            .map(|(merkle_geometry, response)| {
                let external_memory_geometry =
                    CompactResponseTreeExternalMemoryGeometry::derive(merkle_geometry)
                        .map_err(map_response_tree_setup_error)?;
                let control_byte_length = checked_add(
                    external_memory_geometry.driver_inline_byte_length(),
                    external_memory_geometry.executor_owned_heap_byte_length(),
                )?;
                let query_schedule_byte_length =
                    response_query_schedule_byte_length(response.queried_leaf_count)?;
                let writer_live_byte_length = checked_add(
                    control_byte_length,
                    CompactResponsePostorderWriterHeapGeometry::derive(merkle_geometry)
                        .map_err(map_response_merkle_error)?
                        .maximum_owned_heap_byte_length(),
                )?;
                let frontier_digest_byte_length = response
                    .maximum_authentication_frontier_byte_length
                    .checked_sub(MERKLE_FRONTIER_COUNT_BYTE_LENGTH)
                    .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
                let maximum_frontier_node_count = frontier_digest_byte_length
                    .checked_div(MERKLE_DIGEST_BYTE_LENGTH)
                    .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
                let scanner_live_byte_length = checked_add(
                    control_byte_length,
                    checked_add(
                        CompactResponseFrontierScannerHeapGeometry::derive(
                            maximum_frontier_node_count,
                        )
                        .map_err(map_response_merkle_error)?
                        .maximum_owned_heap_byte_length(),
                        query_schedule_byte_length,
                    )?,
                )?;
                let response_input_live_byte_length = checked_add(
                    response.queried_value_byte_length,
                    checked_add(
                        response.transported_leaf_salt_byte_length,
                        checked_add(frontier_digest_byte_length, query_schedule_byte_length)?,
                    )?,
                )?;
                Ok(writer_live_byte_length
                    .max(scanner_live_byte_length)
                    .max(response_input_live_byte_length))
            })
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
        pre_challenge_whir: &WhirStaticLedger,
        main_whir: &WhirStaticLedger,
        cfw_reduction: &CfwReductionCatalog,
    ) -> Result<(), CompactStaticCatalogError> {
        let expected_responses = chronology
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
        let expected = derive_catalog_fields(expected_responses)?;
        if self != &expected
            || self.responses.is_empty()
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

fn map_response_tree_setup_error(
    error: CompactResponseTreeExternalMemorySetupError,
) -> CompactStaticCatalogError {
    match error {
        CompactResponseTreeExternalMemorySetupError::Merkle(error) => {
            map_response_merkle_error(error)
        }
        CompactResponseTreeExternalMemorySetupError::ExternalMemory(_) => {
            CompactStaticCatalogError::InvalidGeometry
        }
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

fn derive_catalog_fields(
    responses: Vec<ResponseVectorLedger>,
) -> Result<PackingResponseCommitmentCatalog, CompactStaticCatalogError> {
    let bcs_response_root_count = u64::try_from(responses.len())
        .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
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
            )
        }
        [VerifierMoveRole::CfwInitialRandomness] => {
            append_extension_scalars(
                builder,
                ResponseComponentRole::CrossEpochOpeningEvaluations,
                CROSS_EPOCH_EXPLICIT_OPENING_COUNT,
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
    use crate::bgv::proof_suite::compact_public_key_static_catalog::CompactPublicKeyStaticCatalog;
    use crate::bgv::proof_suite::fixed_uniform_verifier_message::derive_fixed_uniform_verifier_message;
    use crate::foundation::Hash512;

    #[test]
    fn every_logical_response_has_one_complete_disjoint_merkle_vector() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");
        let expected_response_counts = [82, 80, 78, 76];
        let expected_maximum_lengths = [262_144, 524_288, 1_048_576, 2_097_152];
        let expected_proof_oracle_query_counts = [74_517, 73_983, 72_775, 72_559];
        let expected_maximum_opening_byte_lengths =
            [25_509_792, 24_576_472, 23_858_784, 23_898_984];
        let expected_committed_leaf_counts = [639_270, 1_065_250, 1_917_214, 3_621_146];
        let expected_commitment_parent_hash_counts = [639_188, 1_065_170, 1_917_136, 3_621_070];
        let expected_maximum_opening_parent_hash_counts = [161_420, 164_975, 167_499, 171_483];

        for (factor_ordinal, factor) in catalog.factor_catalogs.iter().enumerate() {
            let expected_response_count = expected_response_counts[factor_ordinal];
            let expected_maximum_length = expected_maximum_lengths[factor_ordinal];
            let expected_query_count = expected_proof_oracle_query_counts[factor_ordinal];
            let responses = &factor.response_commitments;
            assert_eq!(responses.bcs_response_root_count, expected_response_count);
            assert_eq!(responses.responses.len(), expected_response_count as usize);
            assert_eq!(
                responses.maximum_proof_oracle_length,
                expected_maximum_length
            );
            assert_eq!(responses.proof_oracle_query_count, expected_query_count);
            assert_eq!(
                responses.maximum_opening_byte_length,
                expected_maximum_opening_byte_lengths[factor_ordinal]
            );
            assert_eq!(
                responses.committed_leaf_count,
                expected_committed_leaf_counts[factor_ordinal]
            );
            assert_eq!(
                responses.commitment_parent_hash_count,
                expected_commitment_parent_hash_counts[factor_ordinal]
            );
            assert_eq!(
                responses.maximum_opening_parent_hash_count,
                expected_maximum_opening_parent_hash_counts[factor_ordinal]
            );
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
    }

    #[test]
    fn production_wire_geometry_matches_every_independently_derived_response() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");

        for factor in &catalog.factor_catalogs {
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
        }

        let factor_eight = &catalog.factor_catalogs[3];
        let mut malformed_response = factor_eight.response_commitments.responses[0].clone();
        malformed_response.components[0].value_byte_length_per_leaf += 1;
        assert_eq!(
            malformed_response.production_wire_geometry(
                factor_eight
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

        for factor in &catalog.factor_catalogs {
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
                merkle_geometry
                    .validate_wire_geometry(wire_geometry)
                    .expect("Merkle and wire response shapes agree");
                let external_memory_geometry =
                    CompactResponseTreeExternalMemoryGeometry::derive(merkle_geometry)
                        .expect("response tree external-memory geometry");
                assert_eq!(
                    external_memory_geometry.tree_byte_length(),
                    (2 * tree_geometry.merkle_leaf_count - 1) * MERKLE_DIGEST_BYTE_LENGTH
                );
            }
        }
    }

    #[test]
    fn every_production_response_derives_one_exact_schedule_from_complete_messages() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");

        for factor in &catalog.factor_catalogs {
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
            let verifier_messages = (0..factor.uniform_verifier_randomness.move_count())
                .map(|move_ordinal| {
                    let mut starting_transcript_state_bytes = [0_u8; Hash512::BYTE_LENGTH];
                    starting_transcript_state_bytes[..8]
                        .copy_from_slice(&factor.packing_factor.to_le_bytes());
                    starting_transcript_state_bytes[8..16].copy_from_slice(
                        &u64::try_from(move_ordinal)
                            .expect("move ordinal fits u64")
                            .to_le_bytes(),
                    );
                    derive_fixed_uniform_verifier_message(
                        Hash512::from_bytes(starting_transcript_state_bytes),
                        u32::try_from(move_ordinal).expect("move ordinal fits u32"),
                        &factor
                            .uniform_verifier_randomness
                            .fixed_message_geometry(move_ordinal)
                            .expect("fixed verifier-message geometry"),
                    )
                    .expect("complete decoded verifier message")
                })
                .collect::<Vec<_>>();

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
                assert_eq!(
                    usize::try_from(merkle_geometry.response_ordinal()).unwrap(),
                    response_ordinal
                );
                assert_eq!(
                    u64::try_from(schedule.as_slice().len()).unwrap(),
                    response.queried_leaf_count
                );
                assert!(schedule.as_slice().windows(2).all(|pair| pair[0] < pair[1]));
                let schedule_heap_byte_length = schedule
                    .owned_heap_byte_length()
                    .expect("exact query-schedule heap");
                assert_eq!(
                    schedule_heap_byte_length,
                    response_query_schedule_byte_length(response.queried_leaf_count).unwrap()
                );
                total_queried_leaf_count =
                    checked_add(total_queried_leaf_count, response.queried_leaf_count).unwrap();
                maximum_schedule_heap_byte_length =
                    maximum_schedule_heap_byte_length.max(schedule_heap_byte_length);
            }
            assert_eq!(
                total_queried_leaf_count,
                factor.response_commitments.proof_oracle_query_count
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
        }
    }

    #[test]
    fn response_catalog_owns_the_cfw_scalar_messages_without_a_status_field() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");
        let responses = &catalog.factor_catalogs[3].response_commitments.responses;

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
            .expect("two explicit cross-epoch openings");
        assert_eq!(cross_epoch_openings.leaf_count, 2);
        assert_eq!(cross_epoch_openings.queried_leaf_count, 2);
    }

    #[test]
    fn response_catalog_refuses_overlap_padding_and_query_mutations() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");
        let response = &catalog.factor_catalogs[3].response_commitments.responses[1];

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
        for factor in &catalog.factor_catalogs {
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
    }

    #[test]
    fn pre_challenge_source_rows_remain_base_field_symbols() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");
        for factor in &catalog.factor_catalogs {
            let source = &factor.response_commitments.responses[0].components[0];
            assert_eq!(source.role, ResponseComponentRole::PreChallengeSource);
            assert_eq!(
                source.value_byte_length_per_leaf,
                factor.pre_challenge_whir.oracle_widths[0] * BASE_FIELD_ELEMENT_BYTE_LENGTH
            );
        }
    }

    #[test]
    fn cfw_mask_messages_match_the_construction_lengths() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");
        assert_eq!(catalog.cfw_reduction.inner_mask_message_length(), 4);
        assert_eq!(catalog.cfw_reduction.outer_mask_message_length(), 8);
    }
}
