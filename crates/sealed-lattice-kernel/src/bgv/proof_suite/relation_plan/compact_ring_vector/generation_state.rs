//! Pollable production materialization for the compact public-key family.
//!
//! This state owns the authenticated assignment loader, encodes and retains the
//! pre-challenge source before the lookup challenge, accepts that challenge
//! only through the exact compact transcript authority, performs the bounded
//! batch inversion, and prepares the production structured-row source. It does
//! not yet execute CFW or either complete WHIR epoch and therefore cannot emit
//! a proof or mint a workflow capability.

use std::rc::Rc;

use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_matrix::Matrix;

use crate::bgv::proof_suite::{
    ProofBaseFieldElement,
    compact_generation_randomness::CompactGenerationAttemptRandomness,
    compact_proof_contract::selected_compact_public_key_proof_contract,
    compact_proof_wire::{
        CompactProofWireGeometry, CompactPublicInputBindings, DecodedCompactPublicInput,
    },
    compact_response_generation::{CompactOwnedResponseLeaf, CompactVerifierMessageAuthority},
    compact_response_merkle::{CompactResponseLeafValueKind, CompactResponseMerkleGeometry},
    compact_whir::{
        CompactWhirEncodedInitialOracle, CompactWhirError, compact_whir_configuration_from_contract,
    },
    fixed_uniform_verifier_message::{
        DecodedFixedUniformVerifierMessage, FixedUniformVerifierMessageGeometry,
    },
    prover::{CommonProofPrivateCoinSource, CommonProofProverError},
};
use crate::foundation::Hash512;
use crate::hashing::hash_framed_parts_512;

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

const COMPACT_PUBLIC_KEY_PRIVATE_COIN_BINDING_DOMAIN: &str =
    "sealed-lattice/compact-public-key/private-coin-binding/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactPublicKeyFamilyMaterializationError {
    WrongPhase,
    InvalidWorkBudget,
    InvalidVerifierMessage,
    InvalidPreChallengeSource,
    AllocationLimitExceeded,
    Whir(CompactWhirError),
    Prover(CommonProofProverError),
}

impl From<CommonProofProverError> for CompactPublicKeyFamilyMaterializationError {
    fn from(error: CommonProofProverError) -> Self {
        Self::Prover(error)
    }
}

impl From<CompactWhirError> for CompactPublicKeyFamilyMaterializationError {
    fn from(error: CompactWhirError) -> Self {
        Self::Whir(error)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CompactPublicKeyPreChallengeEncodingError<PrivateCoinError> {
    Materialization(CompactPublicKeyFamilyMaterializationError),
    PrivateCoin(PrivateCoinError),
}

impl<PrivateCoinError> From<CompactPublicKeyFamilyMaterializationError>
    for CompactPublicKeyPreChallengeEncodingError<PrivateCoinError>
{
    fn from(error: CompactPublicKeyFamilyMaterializationError) -> Self {
        Self::Materialization(error)
    }
}

impl<PrivateCoinError> From<CommonProofProverError>
    for CompactPublicKeyPreChallengeEncodingError<PrivateCoinError>
{
    fn from(error: CommonProofProverError) -> Self {
        Self::Materialization(error.into())
    }
}

impl<PrivateCoinError> From<CompactWhirError>
    for CompactPublicKeyPreChallengeEncodingError<PrivateCoinError>
{
    fn from(error: CompactWhirError) -> Self {
        Self::Materialization(error.into())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactPublicKeyFamilyMaterializationPoll {
    AuthenticatedSourceReadRequired,
    SourceLoaded {
        column_ordinal: u32,
    },
    SourcesComplete,
    PreChallengeEncodingRequired,
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
    pre_challenge: CompactPublicKeyPreChallengeMaterial,
}

impl CompactPublicKeyFamilyMetadata {
    fn from_prepared_assignment(
        prepared: PreparedCompactPublicKeyBaseAssignment,
        pre_challenge: CompactPublicKeyPreChallengeMaterial,
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
                pre_challenge,
            },
            base_assignment,
        )
    }
}

enum CompactPublicKeyFamilyMaterializationPhase {
    LoadingSources(Box<PreparedCompactPublicKeyAssignmentSources>),
    AwaitingPreChallengeEncoding(PreparedCompactPublicKeyBaseAssignment),
    AwaitingLookupVerifierMessage {
        prepared: PreparedCompactPublicKeyBaseAssignment,
        pre_challenge: CompactPublicKeyPreChallengeMaterial,
    },
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

pub(crate) struct CompactPublicKeyPreChallengeMaterial {
    encoded_oracle: CompactWhirEncodedInitialOracle,
    randomness: CompactGenerationAttemptRandomness,
    response_leaf_count: u64,
    response_field_element_count_per_leaf: u64,
}

impl CompactPublicKeyFamilyMaterializationState {
    pub(crate) fn new(sources: PreparedCompactPublicKeyAssignmentSources) -> Self {
        Self {
            phase: CompactPublicKeyFamilyMaterializationPhase::LoadingSources(Box::new(sources)),
        }
    }

    pub(crate) fn pre_lookup_material(&self) -> Option<CompactPublicKeyPreLookupMaterialView<'_>> {
        let prepared = match &self.phase {
            CompactPublicKeyFamilyMaterializationPhase::AwaitingPreChallengeEncoding(prepared)
            | CompactPublicKeyFamilyMaterializationPhase::AwaitingLookupVerifierMessage {
                prepared,
                ..
            } => prepared,
            _ => return None,
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

    pub(crate) fn pre_challenge_material(&self) -> Option<&CompactPublicKeyPreChallengeMaterial> {
        match &self.phase {
            CompactPublicKeyFamilyMaterializationPhase::AwaitingLookupVerifierMessage {
                pre_challenge,
                ..
            } => Some(pre_challenge),
            _ => None,
        }
    }

    pub(crate) fn encode_pre_challenge_source<Coins: CommonProofPrivateCoinSource>(
        &mut self,
        private_coins: &mut Coins,
        proof_attempt_identifier: [u8; 32],
    ) -> Result<(), CompactPublicKeyPreChallengeEncodingError<Coins::Error>> {
        let CompactPublicKeyFamilyMaterializationPhase::AwaitingPreChallengeEncoding(prepared) =
            core::mem::replace(
                &mut self.phase,
                CompactPublicKeyFamilyMaterializationPhase::Transitioning,
            )
        else {
            self.phase = CompactPublicKeyFamilyMaterializationPhase::Cancelled;
            return Err(CompactPublicKeyFamilyMaterializationError::WrongPhase.into());
        };
        let result =
            prepare_pre_challenge_material(&prepared, private_coins, proof_attempt_identifier);
        match result {
            Ok(pre_challenge) => {
                self.phase =
                    CompactPublicKeyFamilyMaterializationPhase::AwaitingLookupVerifierMessage {
                        prepared,
                        pre_challenge,
                    };
                Ok(())
            }
            Err(error) => {
                self.phase = CompactPublicKeyFamilyMaterializationPhase::Cancelled;
                Err(error)
            }
        }
    }

    pub(crate) fn supply_lookup_verifier_message(
        &mut self,
        authority: CompactVerifierMessageAuthority<'_>,
    ) -> Result<(), CompactPublicKeyFamilyMaterializationError> {
        let prepared = match &self.phase {
            CompactPublicKeyFamilyMaterializationPhase::AwaitingLookupVerifierMessage {
                prepared,
                ..
            } => prepared,
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

        let CompactPublicKeyFamilyMaterializationPhase::AwaitingLookupVerifierMessage {
            prepared,
            pre_challenge,
        } = core::mem::replace(
            &mut self.phase,
            CompactPublicKeyFamilyMaterializationPhase::Transitioning,
        )
        else {
            self.phase = CompactPublicKeyFamilyMaterializationPhase::Cancelled;
            return Err(CompactPublicKeyFamilyMaterializationError::WrongPhase);
        };
        let (metadata, base_assignment) =
            CompactPublicKeyFamilyMetadata::from_prepared_assignment(prepared, pre_challenge);
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
            CompactPublicKeyFamilyMaterializationPhase::AwaitingPreChallengeEncoding(_) => {
                Ok(CompactPublicKeyFamilyMaterializationPoll::PreChallengeEncodingRequired)
            }
            CompactPublicKeyFamilyMaterializationPhase::AwaitingLookupVerifierMessage { .. } => {
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
                    CompactPublicKeyFamilyMaterializationPhase::AwaitingPreChallengeEncoding(
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

    pub(crate) fn private_coin_derivation_binding_hash(&self) -> Hash512 {
        Hash512::from_bytes(hash_framed_parts_512(
            COMPACT_PUBLIC_KEY_PRIVATE_COIN_BINDING_DOMAIN,
            &[
                &self.compact_construction_identity_hash,
                self.canonical_public_input_bytes,
                &self.source_replay_binding,
            ],
        ))
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

    pub(crate) const fn pre_challenge_material(&self) -> &CompactPublicKeyPreChallengeMaterial {
        &self.metadata.pre_challenge
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

impl CompactPublicKeyPreChallengeMaterial {
    pub(crate) const fn response_leaf_count(&self) -> u64 {
        self.response_leaf_count
    }

    pub(crate) const fn response_field_element_count_per_leaf(&self) -> u64 {
        self.response_field_element_count_per_leaf
    }

    pub(crate) const fn proof_attempt_identifier(&self) -> [u8; 32] {
        self.randomness.proof_attempt_identifier()
    }

    pub(crate) fn fiat_shamir_round_salt(
        &self,
    ) -> [u8; crate::bgv::proof_suite::compact_proof_wire::COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH]
    {
        self.randomness.fiat_shamir_round_salt(0)
    }

    pub(crate) fn response_leaf(
        &self,
        leaf_ordinal: u64,
    ) -> Result<CompactOwnedResponseLeaf, CompactPublicKeyFamilyMaterializationError> {
        if leaf_ordinal >= self.response_leaf_count {
            return Err(CompactPublicKeyFamilyMaterializationError::InvalidPreChallengeSource);
        }
        let row = self
            .encoded_oracle
            .encoded_row(usize::try_from(leaf_ordinal).map_err(|_| {
                CompactPublicKeyFamilyMaterializationError::InvalidPreChallengeSource
            })?)
            .ok_or(CompactPublicKeyFamilyMaterializationError::InvalidPreChallengeSource)?;
        let mut values = Vec::new();
        values
            .try_reserve_exact(row.len())
            .map_err(|_| CompactPublicKeyFamilyMaterializationError::AllocationLimitExceeded)?;
        values.extend(row.iter().map(|value| {
            ProofBaseFieldElement::from_canonical(value.as_canonical_u64())
                .expect("a Goldilocks value is a canonical production base-field value")
        }));
        Ok(CompactOwnedResponseLeaf::base_field(values))
    }

    pub(crate) fn response_leaf_salt(
        &self,
        leaf_ordinal: u64,
        leaf: &CompactOwnedResponseLeaf,
    ) -> [u8; crate::bgv::proof_suite::COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH] {
        self.randomness
            .private_leaf_salt(0, self.response_leaf_count, leaf_ordinal, leaf)
    }
}

fn prepare_pre_challenge_material<Coins: CommonProofPrivateCoinSource>(
    prepared: &PreparedCompactPublicKeyBaseAssignment,
    private_coins: &mut Coins,
    proof_attempt_identifier: [u8; 32],
) -> Result<
    CompactPublicKeyPreChallengeMaterial,
    CompactPublicKeyPreChallengeEncodingError<Coins::Error>,
> {
    let contract = selected_compact_public_key_proof_contract()
        .map_err(|_| CompactPublicKeyFamilyMaterializationError::InvalidPreChallengeSource)?;
    let verifier_inputs = contract.verifier_inputs();
    let [pre_challenge_epoch, _main_epoch] = verifier_inputs.whir_epochs else {
        return Err(CompactPublicKeyFamilyMaterializationError::InvalidPreChallengeSource.into());
    };
    let configuration = compact_whir_configuration_from_contract(pre_challenge_epoch)?;
    let cross_epoch_copy = prepared
        .relation
        .cross_epoch_copy_geometry()
        .map_err(|_| CompactPublicKeyFamilyMaterializationError::InvalidPreChallengeSource)?;
    let copied_element_count = usize::try_from(cross_epoch_copy.copied_element_count())
        .map_err(|_| CompactPublicKeyFamilyMaterializationError::InvalidPreChallengeSource)?;
    let message_element_count =
        usize::try_from(cross_epoch_copy.pre_challenge_message_element_count())
            .map_err(|_| CompactPublicKeyFamilyMaterializationError::InvalidPreChallengeSource)?;
    if !message_element_count.is_power_of_two()
        || configuration.num_variables != message_element_count.ilog2() as usize
        || copied_element_count == 0
        || copied_element_count > message_element_count
    {
        return Err(CompactPublicKeyFamilyMaterializationError::InvalidPreChallengeSource.into());
    }
    let mut source = Vec::new();
    source
        .try_reserve_exact(message_element_count)
        .map_err(|_| CompactPublicKeyFamilyMaterializationError::AllocationLimitExceeded)?;
    for element_ordinal in 0..copied_element_count {
        let value = prepared.base_assignment.witness_base_value(
            u64::try_from(element_ordinal).map_err(|_| {
                CompactPublicKeyFamilyMaterializationError::InvalidPreChallengeSource
            })?,
        )?;
        source.push(Goldilocks::from_u64(value.canonical()));
    }
    source.resize(message_element_count, Goldilocks::ZERO);

    let [source_response_component] = prepared
        .response_merkle_geometries
        .first()
        .ok_or(CompactPublicKeyFamilyMaterializationError::InvalidPreChallengeSource)?
        .components()
    else {
        return Err(CompactPublicKeyFamilyMaterializationError::InvalidPreChallengeSource.into());
    };
    if source_response_component.value_kind() != CompactResponseLeafValueKind::BaseField {
        return Err(CompactPublicKeyFamilyMaterializationError::InvalidPreChallengeSource.into());
    }

    let mut randomness = CompactGenerationAttemptRandomness::from_private_coins(
        private_coins,
        proof_attempt_identifier,
    )
    .map_err(CompactPublicKeyPreChallengeEncodingError::PrivateCoin)?;
    let encoded_oracle = CompactWhirEncodedInitialOracle::encode(
        &configuration,
        source,
        randomness.whir_random_source_mut(),
    )?;
    let matrix = encoded_oracle.encoded_matrix();
    if u64::try_from(matrix.height()) != Ok(source_response_component.leaf_count())
        || u64::try_from(matrix.width())
            != Ok(source_response_component.field_element_count_per_leaf())
    {
        return Err(CompactPublicKeyFamilyMaterializationError::InvalidPreChallengeSource.into());
    }
    Ok(CompactPublicKeyPreChallengeMaterial {
        encoded_oracle,
        randomness,
        response_leaf_count: source_response_component.leaf_count(),
        response_field_element_count_per_leaf: source_response_component
            .field_element_count_per_leaf(),
    })
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
