//! Pollable production materialization for the compact public-key family.
//!
//! This state owns the authenticated assignment loader, accepts the lookup
//! challenge only through the exact compact transcript authority, performs the
//! bounded batch inversion, and prepares the production structured-row source.
//! It does not yet execute CFW or either WHIR epoch and therefore cannot emit a
//! proof or mint a workflow capability.

use std::rc::Rc;

use crate::bgv::proof_suite::{
    compact_proof_wire::{
        CompactProofWireGeometry, CompactPublicInputBindings, DecodedCompactPublicInput,
    },
    compact_response_generation::CompactVerifierMessageAuthority,
    compact_response_merkle::CompactResponseMerkleGeometry,
    fixed_uniform_verifier_message::{
        DecodedFixedUniformVerifierMessage, FixedUniformVerifierMessageGeometry,
    },
    prover::CommonProofProverError,
};
use crate::foundation::Hash512;

use super::{
    CompactPublicKeyRelationCatalog, PreparedCompactPublicKeyAssignmentSources,
    PreparedCompactPublicKeyBaseAssignment,
    authenticated_assignment::{
        CompactAuthenticatedAssignmentPoll, CompactLookupInverseMaterializationPoll,
        CompactLookupInverseMaterializer, CompactPublicKeyAssignment,
        CompactPublicKeyBaseAssignment,
    },
    structured_r1cs::{
        CompactStructuredR1csRowSource, CompactStructuredR1csRowSourcePreparation,
        CompactStructuredR1csRowSourcePreparationPoll,
        CompactStructuredR1csRowSourcePreparationStep,
    },
};

type SelectedCompactPublicKeyAssignment = Rc<CompactPublicKeyAssignment>;
type SelectedCompactPublicKeyRowSource =
    CompactStructuredR1csRowSource<SelectedCompactPublicKeyAssignment>;
type SelectedCompactPublicKeyRowSourcePreparation =
    CompactStructuredR1csRowSourcePreparation<SelectedCompactPublicKeyAssignment>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactPublicKeyFamilyMaterializationError {
    WrongPhase,
    InvalidWorkBudget,
    InvalidVerifierMessage,
    Prover(CommonProofProverError),
}

impl From<CommonProofProverError> for CompactPublicKeyFamilyMaterializationError {
    fn from(error: CommonProofProverError) -> Self {
        Self::Prover(error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactPublicKeyFamilyMaterializationPoll {
    AuthenticatedSourceReadRequired,
    SourceLoaded {
        column_ordinal: u32,
    },
    SourcesComplete,
    LookupVerifierMessageRequired,
    LookupInverseArithmeticStepCompleted {
        processed_element_count: u64,
    },
    StructuredRowSourceStepCompleted {
        step: CompactStructuredR1csRowSourcePreparationStep,
        completed_work_unit_count: u64,
    },
    Complete,
}

struct CompactPublicKeyFamilyMetadata {
    relation: Rc<CompactPublicKeyRelationCatalog>,
    public_input_bindings: CompactPublicInputBindings,
    canonical_public_input_bytes: Vec<u8>,
    decoded_public_input: DecodedCompactPublicInput,
    proof_wire_geometry: CompactProofWireGeometry,
    response_merkle_geometries: Vec<CompactResponseMerkleGeometry>,
    compact_construction_identity_hash: [u8; Hash512::BYTE_LENGTH],
    checkpoint_schedule_digest: Hash512,
    source_replay_binding: [u8; Hash512::BYTE_LENGTH],
}

impl CompactPublicKeyFamilyMetadata {
    fn from_prepared_assignment(
        prepared: PreparedCompactPublicKeyBaseAssignment,
    ) -> (Self, CompactPublicKeyBaseAssignment) {
        let PreparedCompactPublicKeyBaseAssignment {
            relation,
            base_assignment,
            public_input_bindings,
            canonical_public_input_bytes,
            decoded_public_input,
            proof_wire_geometry,
            response_merkle_geometries,
            compact_construction_identity_hash,
            checkpoint_schedule_digest,
        } = prepared;
        let source_replay_binding = base_assignment.source_replay_binding();
        (
            Self {
                relation: Rc::new(relation),
                public_input_bindings,
                canonical_public_input_bytes,
                decoded_public_input,
                proof_wire_geometry,
                response_merkle_geometries,
                compact_construction_identity_hash,
                checkpoint_schedule_digest,
                source_replay_binding,
            },
            base_assignment,
        )
    }
}

enum CompactPublicKeyFamilyMaterializationPhase {
    LoadingSources(Box<PreparedCompactPublicKeyAssignmentSources>),
    AwaitingLookupVerifierMessage(PreparedCompactPublicKeyBaseAssignment),
    MaterializingLookupInverses {
        metadata: CompactPublicKeyFamilyMetadata,
        materializer: CompactLookupInverseMaterializer,
    },
    PreparingStructuredRowSource {
        metadata: CompactPublicKeyFamilyMetadata,
        preparation: Box<SelectedCompactPublicKeyRowSourcePreparation>,
    },
    Ready(Option<CompactPublicKeyFamilyMaterial>),
    Cancelled,
    Transitioning,
}

pub(crate) struct CompactPublicKeyFamilyMaterializationState {
    phase: CompactPublicKeyFamilyMaterializationPhase,
}

#[derive(Clone, Copy)]
pub(crate) struct CompactPublicKeyPreLookupMaterialView<'state> {
    public_input_bindings: CompactPublicInputBindings,
    canonical_public_input_bytes: &'state [u8],
    decoded_public_input: &'state DecodedCompactPublicInput,
    proof_wire_geometry: &'state CompactProofWireGeometry,
    response_merkle_geometries: &'state [CompactResponseMerkleGeometry],
    compact_construction_identity_hash: [u8; Hash512::BYTE_LENGTH],
    checkpoint_schedule_digest: Hash512,
    source_replay_binding: [u8; Hash512::BYTE_LENGTH],
}

pub(crate) struct CompactPublicKeyFamilyMaterial {
    metadata: CompactPublicKeyFamilyMetadata,
    row_source: SelectedCompactPublicKeyRowSource,
}

impl CompactPublicKeyFamilyMaterializationState {
    pub(crate) fn new(sources: PreparedCompactPublicKeyAssignmentSources) -> Self {
        Self {
            phase: CompactPublicKeyFamilyMaterializationPhase::LoadingSources(Box::new(sources)),
        }
    }

    pub(crate) fn pre_lookup_material(&self) -> Option<CompactPublicKeyPreLookupMaterialView<'_>> {
        let CompactPublicKeyFamilyMaterializationPhase::AwaitingLookupVerifierMessage(prepared) =
            &self.phase
        else {
            return None;
        };
        Some(CompactPublicKeyPreLookupMaterialView {
            public_input_bindings: prepared.public_input_bindings,
            canonical_public_input_bytes: &prepared.canonical_public_input_bytes,
            decoded_public_input: &prepared.decoded_public_input,
            proof_wire_geometry: &prepared.proof_wire_geometry,
            response_merkle_geometries: &prepared.response_merkle_geometries,
            compact_construction_identity_hash: prepared.compact_construction_identity_hash,
            checkpoint_schedule_digest: prepared.checkpoint_schedule_digest,
            source_replay_binding: prepared.base_assignment.source_replay_binding(),
        })
    }

    pub(crate) fn supply_lookup_verifier_message(
        &mut self,
        authority: CompactVerifierMessageAuthority<'_>,
    ) -> Result<(), CompactPublicKeyFamilyMaterializationError> {
        let prepared = match &self.phase {
            CompactPublicKeyFamilyMaterializationPhase::AwaitingLookupVerifierMessage(prepared) => {
                prepared
            }
            _ => return Err(CompactPublicKeyFamilyMaterializationError::WrongPhase),
        };
        if authority.logical_verifier_move_ordinal() != 0
            || authority.proof_wire_geometry() != &prepared.proof_wire_geometry
            || authority.canonical_public_input_bytes()
                != prepared.canonical_public_input_bytes.as_slice()
        {
            return Err(CompactPublicKeyFamilyMaterializationError::InvalidVerifierMessage);
        }
        let lookup_message_geometry = prepared
            .proof_wire_geometry
            .responses()
            .first()
            .ok_or(CompactPublicKeyFamilyMaterializationError::InvalidVerifierMessage)?
            .verifier_message_geometry();
        let lookup_challenge =
            lookup_challenge_from_verifier_message(lookup_message_geometry, authority.message())?;

        let CompactPublicKeyFamilyMaterializationPhase::AwaitingLookupVerifierMessage(prepared) =
            core::mem::replace(
                &mut self.phase,
                CompactPublicKeyFamilyMaterializationPhase::Transitioning,
            )
        else {
            self.phase = CompactPublicKeyFamilyMaterializationPhase::Cancelled;
            return Err(CompactPublicKeyFamilyMaterializationError::WrongPhase);
        };
        let (metadata, base_assignment) =
            CompactPublicKeyFamilyMetadata::from_prepared_assignment(prepared);
        let materializer =
            match base_assignment.begin_lookup_inverse_materialization(lookup_challenge) {
                Ok(materializer) => materializer,
                Err(error) => {
                    self.phase = CompactPublicKeyFamilyMaterializationPhase::Cancelled;
                    return Err(error.into());
                }
            };
        self.phase = CompactPublicKeyFamilyMaterializationPhase::MaterializingLookupInverses {
            metadata,
            materializer,
        };
        Ok(())
    }

    pub(crate) fn poll(
        &mut self,
        maximum_work_unit_count: u64,
    ) -> Result<CompactPublicKeyFamilyMaterializationPoll, CompactPublicKeyFamilyMaterializationError>
    {
        if maximum_work_unit_count == 0 {
            return Err(CompactPublicKeyFamilyMaterializationError::InvalidWorkBudget);
        }
        match &mut self.phase {
            CompactPublicKeyFamilyMaterializationPhase::LoadingSources(sources) => {
                match sources.poll_source_loading()? {
                    CompactAuthenticatedAssignmentPoll::AuthenticatedSourceReadRequired => Ok(
                        CompactPublicKeyFamilyMaterializationPoll::AuthenticatedSourceReadRequired,
                    ),
                    CompactAuthenticatedAssignmentPoll::SourceLoaded { column_ordinal } => Ok(
                        CompactPublicKeyFamilyMaterializationPoll::SourceLoaded { column_ordinal },
                    ),
                    CompactAuthenticatedAssignmentPoll::Complete => {
                        self.finish_source_loading()?;
                        Ok(CompactPublicKeyFamilyMaterializationPoll::SourcesComplete)
                    }
                }
            }
            CompactPublicKeyFamilyMaterializationPhase::AwaitingLookupVerifierMessage(_) => {
                Ok(CompactPublicKeyFamilyMaterializationPoll::LookupVerifierMessageRequired)
            }
            CompactPublicKeyFamilyMaterializationPhase::MaterializingLookupInverses {
                materializer,
                ..
            } => match materializer.advance(maximum_work_unit_count)? {
                CompactLookupInverseMaterializationPoll::ArithmeticStepCompleted {
                    processed_element_count,
                } => Ok(
                    CompactPublicKeyFamilyMaterializationPoll::LookupInverseArithmeticStepCompleted {
                        processed_element_count,
                    },
                ),
                CompactLookupInverseMaterializationPoll::Complete => {
                    self.finish_lookup_materialization()?;
                    self.poll(maximum_work_unit_count)
                }
            },
            CompactPublicKeyFamilyMaterializationPhase::PreparingStructuredRowSource {
                preparation,
                ..
            } => match preparation.advance(maximum_work_unit_count)? {
                CompactStructuredR1csRowSourcePreparationPoll::StepCompleted {
                    step,
                    completed_work_unit_count,
                } => Ok(
                    CompactPublicKeyFamilyMaterializationPoll::StructuredRowSourceStepCompleted {
                        step,
                        completed_work_unit_count,
                    },
                ),
                CompactStructuredR1csRowSourcePreparationPoll::Complete(row_source) => {
                    self.finish_structured_row_source(row_source)?;
                    Ok(CompactPublicKeyFamilyMaterializationPoll::Complete)
                }
            },
            CompactPublicKeyFamilyMaterializationPhase::Ready(_) => {
                Ok(CompactPublicKeyFamilyMaterializationPoll::Complete)
            }
            CompactPublicKeyFamilyMaterializationPhase::Cancelled
            | CompactPublicKeyFamilyMaterializationPhase::Transitioning => {
                Err(CompactPublicKeyFamilyMaterializationError::WrongPhase)
            }
        }
    }

    pub(crate) fn finish(
        mut self,
    ) -> Result<CompactPublicKeyFamilyMaterial, CompactPublicKeyFamilyMaterializationError> {
        let CompactPublicKeyFamilyMaterializationPhase::Ready(material) = &mut self.phase else {
            return Err(CompactPublicKeyFamilyMaterializationError::WrongPhase);
        };
        material
            .take()
            .ok_or(CompactPublicKeyFamilyMaterializationError::WrongPhase)
    }

    fn finish_source_loading(&mut self) -> Result<(), CompactPublicKeyFamilyMaterializationError> {
        let CompactPublicKeyFamilyMaterializationPhase::LoadingSources(sources) =
            core::mem::replace(
                &mut self.phase,
                CompactPublicKeyFamilyMaterializationPhase::Transitioning,
            )
        else {
            self.phase = CompactPublicKeyFamilyMaterializationPhase::Cancelled;
            return Err(CompactPublicKeyFamilyMaterializationError::WrongPhase);
        };
        match (*sources).finish_source_loading() {
            Ok(prepared) => {
                self.phase =
                    CompactPublicKeyFamilyMaterializationPhase::AwaitingLookupVerifierMessage(
                        prepared,
                    );
                Ok(())
            }
            Err(error) => {
                self.phase = CompactPublicKeyFamilyMaterializationPhase::Cancelled;
                Err(error.into())
            }
        }
    }

    fn finish_lookup_materialization(
        &mut self,
    ) -> Result<(), CompactPublicKeyFamilyMaterializationError> {
        let CompactPublicKeyFamilyMaterializationPhase::MaterializingLookupInverses {
            metadata,
            materializer,
        } = core::mem::replace(
            &mut self.phase,
            CompactPublicKeyFamilyMaterializationPhase::Transitioning,
        )
        else {
            self.phase = CompactPublicKeyFamilyMaterializationPhase::Cancelled;
            return Err(CompactPublicKeyFamilyMaterializationError::WrongPhase);
        };
        let assignment = match materializer.finish() {
            Ok(assignment) => Rc::new(assignment),
            Err(error) => {
                self.phase = CompactPublicKeyFamilyMaterializationPhase::Cancelled;
                return Err(error.into());
            }
        };
        let preparation = match CompactStructuredR1csRowSourcePreparation::new(
            Rc::clone(&metadata.relation),
            assignment,
        ) {
            Ok(preparation) => preparation,
            Err(error) => {
                self.phase = CompactPublicKeyFamilyMaterializationPhase::Cancelled;
                return Err(error.into());
            }
        };
        self.phase = CompactPublicKeyFamilyMaterializationPhase::PreparingStructuredRowSource {
            metadata,
            preparation: Box::new(preparation),
        };
        Ok(())
    }

    fn finish_structured_row_source(
        &mut self,
        row_source: Box<SelectedCompactPublicKeyRowSource>,
    ) -> Result<(), CompactPublicKeyFamilyMaterializationError> {
        let CompactPublicKeyFamilyMaterializationPhase::PreparingStructuredRowSource {
            metadata,
            ..
        } = core::mem::replace(
            &mut self.phase,
            CompactPublicKeyFamilyMaterializationPhase::Transitioning,
        )
        else {
            self.phase = CompactPublicKeyFamilyMaterializationPhase::Cancelled;
            return Err(CompactPublicKeyFamilyMaterializationError::WrongPhase);
        };
        self.phase = CompactPublicKeyFamilyMaterializationPhase::Ready(Some(
            CompactPublicKeyFamilyMaterial {
                metadata,
                row_source: *row_source,
            },
        ));
        Ok(())
    }
}

impl CompactPublicKeyPreLookupMaterialView<'_> {
    pub(crate) const fn public_input_bindings(&self) -> CompactPublicInputBindings {
        self.public_input_bindings
    }

    pub(crate) const fn canonical_public_input_bytes(&self) -> &[u8] {
        self.canonical_public_input_bytes
    }

    pub(crate) const fn decoded_public_input(&self) -> &DecodedCompactPublicInput {
        self.decoded_public_input
    }

    pub(crate) const fn proof_wire_geometry(&self) -> &CompactProofWireGeometry {
        self.proof_wire_geometry
    }

    pub(crate) const fn response_merkle_geometries(&self) -> &[CompactResponseMerkleGeometry] {
        self.response_merkle_geometries
    }

    pub(crate) const fn compact_construction_identity_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.compact_construction_identity_hash
    }

    pub(crate) const fn checkpoint_schedule_digest(&self) -> Hash512 {
        self.checkpoint_schedule_digest
    }

    pub(crate) const fn source_replay_binding(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.source_replay_binding
    }
}

impl CompactPublicKeyFamilyMaterial {
    pub(crate) fn relation(&self) -> &CompactPublicKeyRelationCatalog {
        &self.metadata.relation
    }

    pub(crate) const fn public_input_bindings(&self) -> CompactPublicInputBindings {
        self.metadata.public_input_bindings
    }

    pub(crate) fn canonical_public_input_bytes(&self) -> &[u8] {
        &self.metadata.canonical_public_input_bytes
    }

    pub(crate) const fn decoded_public_input(&self) -> &DecodedCompactPublicInput {
        &self.metadata.decoded_public_input
    }

    pub(crate) const fn proof_wire_geometry(&self) -> &CompactProofWireGeometry {
        &self.metadata.proof_wire_geometry
    }

    pub(crate) fn response_merkle_geometries(&self) -> &[CompactResponseMerkleGeometry] {
        &self.metadata.response_merkle_geometries
    }

    pub(crate) const fn compact_construction_identity_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.metadata.compact_construction_identity_hash
    }

    pub(crate) const fn checkpoint_schedule_digest(&self) -> Hash512 {
        self.metadata.checkpoint_schedule_digest
    }

    pub(crate) const fn source_replay_binding(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.metadata.source_replay_binding
    }

    pub(crate) const fn witness_length(&self) -> u64 {
        self.row_source.witness_length()
    }

    pub(crate) const fn row_count(&self) -> u64 {
        self.row_source.row_count()
    }

    pub(super) const fn row_source(&self) -> &SelectedCompactPublicKeyRowSource {
        &self.row_source
    }
}

fn lookup_challenge_from_verifier_message(
    expected_geometry: &FixedUniformVerifierMessageGeometry,
    message: &DecodedFixedUniformVerifierMessage,
) -> Result<
    crate::bgv::proof_suite::ProofChallengeExtensionElement,
    CompactPublicKeyFamilyMaterializationError,
> {
    if expected_geometry.extension_output_count() != 1
        || expected_geometry.base_field_output_count() != 0
        || !expected_geometry.distinct_query_groups().is_empty()
        || !message.base_field_elements().is_empty()
        || !message.distinct_query_groups().is_empty()
    {
        return Err(CompactPublicKeyFamilyMaterializationError::InvalidVerifierMessage);
    }
    let [lookup_challenge] = message.extension_elements() else {
        return Err(CompactPublicKeyFamilyMaterializationError::InvalidVerifierMessage);
    };
    if lookup_challenge.canonical_coordinates()[1..]
        .iter()
        .all(|coordinate| *coordinate == 0)
    {
        return Err(CompactPublicKeyFamilyMaterializationError::InvalidVerifierMessage);
    }
    Ok(*lookup_challenge)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::fixed_uniform_verifier_message::{
        FixedUniformDistinctQueryGeometry, derive_fixed_uniform_verifier_message,
    };

    #[test]
    fn lookup_challenge_requires_the_exact_first_message_shape() {
        let contract = crate::bgv::proof_suite::compact_proof_contract::selected_compact_public_key_proof_contract()
            .expect("selected compact contract decodes");
        let geometry = contract.verifier_inputs().proof_wire_geometry.responses()[0]
            .verifier_message_geometry();
        let message = derive_fixed_uniform_verifier_message(
            Hash512::from_bytes([0x31; Hash512::BYTE_LENGTH]),
            0,
            geometry,
        )
        .expect("the exact lookup message derives");
        let challenge = lookup_challenge_from_verifier_message(geometry, &message)
            .expect("the exact first-message shape supplies the lookup challenge");
        assert!(
            challenge.canonical_coordinates()[1..]
                .iter()
                .any(|coordinate| *coordinate != 0)
        );

        for wrong_geometry in [
            FixedUniformVerifierMessageGeometry::new(2, 0, 0, Vec::new())
                .expect("two-extension geometry"),
            FixedUniformVerifierMessageGeometry::new(1, 0, 1, Vec::new())
                .expect("unexpected base-field geometry"),
            FixedUniformVerifierMessageGeometry::new(
                1,
                0,
                0,
                vec![FixedUniformDistinctQueryGeometry::new(16, 2)],
            )
            .expect("unexpected query geometry"),
        ] {
            let wrong_message = derive_fixed_uniform_verifier_message(
                Hash512::from_bytes([0x32; Hash512::BYTE_LENGTH]),
                0,
                &wrong_geometry,
            )
            .expect("the alternate typed message derives");
            assert_eq!(
                lookup_challenge_from_verifier_message(geometry, &wrong_message),
                Err(CompactPublicKeyFamilyMaterializationError::InvalidVerifierMessage)
            );
        }
    }
}
