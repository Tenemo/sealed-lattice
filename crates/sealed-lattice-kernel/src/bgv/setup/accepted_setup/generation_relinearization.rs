use core::mem::size_of;

use zeroize::Zeroizing;

use crate::{
    bgv::{
        evaluator::key_switch::special_basis_modulus_residue,
        key_switch_topology::{KEY_SWITCH_DATA_PRIMES_PER_BLOCK, canonical_residue_byte_length},
        modular_arithmetic::{add_mod_fast, mul_mod_fast, sub_mod_fast},
        parameters::PLAINTEXT_MODULUS,
        proof_suite::{
            ComponentMaterialOwnershipBinding, KeySwitchComponentMaterialTopology,
            SelectedEvaluatorEntryKind, SelectedEvaluatorEntryPosition,
            SetupPublicPolynomialContext, SetupPublicPolynomialRootBuilder,
            SetupPublicPolynomialRootRole, VerifiedKeySwitchComponentMaterial,
            VerifiedKeySwitchComponentMaterialStream,
            canonical_selected_relinearization_round_one_aggregate_statement,
            canonical_selected_relinearization_round_one_statement,
            canonical_selected_relinearization_round_two_statement,
            selected_evaluator_entry_positions, verified_application_statement_hash,
        },
        setup::{
            sample_relinearization_common_reference_limb,
            sampling::{DATA_MODULUS_CATALOG_IDENTIFIER, SPECIAL_MODULUS_CATALOG_IDENTIFIER},
        },
    },
    foundation::{
        ActionPrivateRandomness, CanonicalItem, CanonicalStreamDomain,
        CanonicalStreamReadbackVerifier, CanonicalStreamVerifier, CanonicalTuple,
        FOUNDATION_PROFILE, Hash512, PrivateRandomnessAttemptIdentifier, PrivateRandomnessDomain,
        ProofApplicationSlotCeilings, RefusalReason, SelectedSuiteCapability, StreamDescriptor,
        derive_canonical_stream_descriptor, hash_foundation_tuple_512,
    },
};

use super::{
    generation_authority::SetupGeneratedKeySwitchComponent,
    generation_population::{
        centered_i8_residue, sample_centered_binomial_polynomial,
        sample_centered_ternary_polynomial,
    },
};
use crate::bgv::setup::sampling::negacyclic_product_mod;

const FOUNDATION_SCHEMA_VERSION: u16 = 1;
const RELINEARIZATION_PRIVATE_POLYNOMIAL_CONTEXT_SCHEMA_IDENTIFIER: u16 = 0x1210;
const RELINEARIZATION_PRIVATE_POLYNOMIAL_CONTEXT_HASH_DOMAIN: &str =
    "sealed-lattice/setup/relinearization-private-polynomial-context/v1";
const RELINEARIZATION_EPHEMERAL_SECRET_DISTRIBUTION_PURPOSE: u16 = 3;
const RELINEARIZATION_ROUND_ONE_LEFT_ERROR_DISTRIBUTION_PURPOSE: u16 = 4;
const RELINEARIZATION_ROUND_ONE_RIGHT_ERROR_DISTRIBUTION_PURPOSE: u16 = 5;
const RELINEARIZATION_ROUND_TWO_ERROR_DISTRIBUTION_PURPOSE: u16 = 6;
const RELINEARIZATION_ERROR_CENTERED_BINOMIAL_PARAMETER: u16 = 2;

pub(crate) struct SetupGeneratedRelinearizationComponentSource {
    material: VerifiedKeySwitchComponentMaterial,
    contribution_root: [u8; Hash512::BYTE_LENGTH],
    public_polynomial_context_hash: [u8; Hash512::BYTE_LENGTH],
}

impl SetupGeneratedRelinearizationComponentSource {
    pub(crate) const fn material(&self) -> &VerifiedKeySwitchComponentMaterial {
        &self.material
    }

    pub(crate) const fn topology(&self) -> &KeySwitchComponentMaterialTopology {
        self.material.topology()
    }

    pub(crate) const fn stream_descriptor(&self) -> &StreamDescriptor {
        self.material.stream_descriptor()
    }

    pub(crate) const fn material_root(&self) -> Hash512 {
        self.material.material_root()
    }

    pub(crate) const fn contribution_root(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.contribution_root
    }

    pub(crate) const fn public_polynomial_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.public_polynomial_context_hash
    }

    pub(crate) fn begin_authenticated_readback(
        &self,
    ) -> Result<CanonicalStreamReadbackVerifier, RefusalReason> {
        self.material.begin_authenticated_readback()
    }
}

pub(crate) struct SetupGeneratedRelinearizationRoundOneSourceAuthority {
    protocol_version: u16,
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
    action_context_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    roster_position: u16,
    schedule_position: u32,
    anchor_commitment_roots: [[u8; Hash512::BYTE_LENGTH]; 3],
    canonical_application_statement_bytes: Box<[u8]>,
    components: [SetupGeneratedRelinearizationComponentSource; 2],
}

#[derive(Clone)]
pub(crate) struct SetupGenerationRelinearizationRoundOnePreparationSource {
    protocol_version: u16,
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    manifest_hash: [u8; Hash512::BYTE_LENGTH],
    ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
    action_context_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    source_setup_intent_object_hash: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    roster_position: u16,
    action_randomness_authorization_hash: [u8; Hash512::BYTE_LENGTH],
    schedule_position: u32,
    root_pair: [[u8; Hash512::BYTE_LENGTH]; 2],
    canonical_application_statement_bytes: Box<[u8]>,
}

impl SetupGenerationRelinearizationRoundOnePreparationSource {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_generated_source(
        source: &SetupGeneratedRelinearizationRoundOneSourceAuthority,
        manifest_hash: [u8; Hash512::BYTE_LENGTH],
        source_setup_intent_object_hash: [u8; Hash512::BYTE_LENGTH],
        action_randomness_authorization_hash: [u8; Hash512::BYTE_LENGTH],
    ) -> Self {
        Self {
            protocol_version: source.protocol_version,
            suite_identifier: source.suite_identifier,
            manifest_hash,
            ceremony_context_hash: source.ceremony_context_hash,
            action_context_hash: source.action_context_hash,
            roster_hash: source.roster_hash,
            setup_proof_context_hash: source.setup_proof_context_hash,
            source_setup_intent_object_hash,
            participant_identity: source.participant_identity,
            roster_position: source.roster_position,
            action_randomness_authorization_hash,
            schedule_position: source.schedule_position,
            root_pair: source.root_pair(),
            canonical_application_statement_bytes: source
                .canonical_application_statement_bytes
                .clone(),
        }
    }

    pub(crate) const fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    pub(crate) const fn suite_identifier(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.suite_identifier
    }

    pub(crate) const fn manifest_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.manifest_hash
    }

    pub(crate) const fn ceremony_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.ceremony_context_hash
    }

    pub(crate) const fn action_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.action_context_hash
    }

    pub(crate) const fn roster_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.roster_hash
    }

    pub(crate) const fn setup_proof_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.setup_proof_context_hash
    }

    pub(crate) const fn source_setup_intent_object_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.source_setup_intent_object_hash
    }

    pub(crate) const fn participant_identity(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.participant_identity
    }

    pub(crate) const fn roster_position(&self) -> u16 {
        self.roster_position
    }

    pub(crate) const fn action_randomness_authorization_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.action_randomness_authorization_hash
    }

    pub(crate) const fn schedule_position(&self) -> u32 {
        self.schedule_position
    }

    pub(crate) const fn root_pair(&self) -> [[u8; Hash512::BYTE_LENGTH]; 2] {
        self.root_pair
    }

    pub(crate) fn canonical_application_statement_bytes(&self) -> &[u8] {
        &self.canonical_application_statement_bytes
    }
}

impl SetupGeneratedRelinearizationRoundOneSourceAuthority {
    pub(crate) const fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    pub(crate) const fn suite_identifier(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.suite_identifier
    }

    pub(crate) const fn ceremony_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.ceremony_context_hash
    }

    pub(crate) const fn action_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.action_context_hash
    }

    pub(crate) const fn roster_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.roster_hash
    }

    pub(crate) const fn setup_proof_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.setup_proof_context_hash
    }

    pub(crate) const fn participant_identity(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.participant_identity
    }

    pub(crate) const fn roster_position(&self) -> u16 {
        self.roster_position
    }

    pub(crate) const fn schedule_position(&self) -> u32 {
        self.schedule_position
    }

    pub(crate) const fn anchor_commitment_roots(&self) -> [[u8; Hash512::BYTE_LENGTH]; 3] {
        self.anchor_commitment_roots
    }

    pub(crate) fn canonical_application_statement_bytes(&self) -> &[u8] {
        &self.canonical_application_statement_bytes
    }

    pub(crate) const fn components(&self) -> &[SetupGeneratedRelinearizationComponentSource; 2] {
        &self.components
    }

    pub(crate) const fn root_pair(&self) -> [[u8; Hash512::BYTE_LENGTH]; 2] {
        [
            self.components[0].contribution_root(),
            self.components[1].contribution_root(),
        ]
    }
}

pub(crate) struct SetupGeneratedRelinearizationRoundTwoSourceAuthority {
    protocol_version: u16,
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
    action_context_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    roster_position: u16,
    schedule_position: u32,
    anchor_commitment_roots: [[u8; Hash512::BYTE_LENGTH]; 3],
    round_one_root_pair: [[u8; Hash512::BYTE_LENGTH]; 2],
    aggregate_round_one_root_pair: [[u8; Hash512::BYTE_LENGTH]; 2],
    canonical_application_statement_bytes: Box<[u8]>,
    component: SetupGeneratedRelinearizationComponentSource,
}

pub(crate) struct SetupGeneratedRelinearizationAggregateSourceAuthority {
    protocol_version: u16,
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
    action_context_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    schedule_position: u32,
    evaluator_position: SelectedEvaluatorEntryPosition,
    ordered_participant_identities: Box<[[u8; Hash512::BYTE_LENGTH]]>,
    ordered_anchor_commitment_roots: Box<[[[u8; Hash512::BYTE_LENGTH]; 3]]>,
    ordered_round_one_proof_stream_descriptors: Box<[StreamDescriptor]>,
    ordered_source_root_pairs: Box<[[[u8; Hash512::BYTE_LENGTH]; 2]]>,
    canonical_application_statement_bytes: Box<[u8]>,
    components: [SetupGeneratedRelinearizationComponentSource; 2],
}

impl SetupGeneratedRelinearizationAggregateSourceAuthority {
    pub(crate) const fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    pub(crate) const fn suite_identifier(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.suite_identifier
    }

    pub(crate) const fn ceremony_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.ceremony_context_hash
    }

    pub(crate) const fn action_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.action_context_hash
    }

    pub(crate) const fn roster_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.roster_hash
    }

    pub(crate) const fn setup_proof_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.setup_proof_context_hash
    }

    pub(crate) const fn schedule_position(&self) -> u32 {
        self.schedule_position
    }

    pub(crate) const fn evaluator_position(&self) -> SelectedEvaluatorEntryPosition {
        self.evaluator_position
    }

    pub(crate) fn ordered_participant_identities(&self) -> &[[u8; Hash512::BYTE_LENGTH]] {
        &self.ordered_participant_identities
    }

    pub(crate) fn ordered_anchor_commitment_roots(&self) -> &[[[u8; Hash512::BYTE_LENGTH]; 3]] {
        &self.ordered_anchor_commitment_roots
    }

    pub(crate) fn ordered_round_one_proof_stream_descriptors(&self) -> &[StreamDescriptor] {
        &self.ordered_round_one_proof_stream_descriptors
    }

    pub(crate) fn ordered_source_root_pairs(&self) -> &[[[u8; Hash512::BYTE_LENGTH]; 2]] {
        &self.ordered_source_root_pairs
    }

    pub(crate) fn canonical_application_statement_bytes(&self) -> &[u8] {
        &self.canonical_application_statement_bytes
    }

    pub(crate) const fn components(&self) -> &[SetupGeneratedRelinearizationComponentSource; 2] {
        &self.components
    }

    pub(crate) const fn root_pair(&self) -> [[u8; Hash512::BYTE_LENGTH]; 2] {
        [
            self.components[0].contribution_root(),
            self.components[1].contribution_root(),
        ]
    }
}

pub(crate) struct SetupGeneratedRelinearizationAggregateGeneration {
    components: [SetupGeneratedKeySwitchComponent; 2],
    source_authority: SetupGeneratedRelinearizationAggregateSourceAuthority,
}

impl SetupGeneratedRelinearizationAggregateGeneration {
    pub(crate) const fn components(&self) -> &[SetupGeneratedKeySwitchComponent; 2] {
        &self.components
    }

    pub(crate) const fn source_authority(
        &self,
    ) -> &SetupGeneratedRelinearizationAggregateSourceAuthority {
        &self.source_authority
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        [SetupGeneratedKeySwitchComponent; 2],
        SetupGeneratedRelinearizationAggregateSourceAuthority,
    ) {
        (self.components, self.source_authority)
    }
}

pub(crate) struct SetupGeneratedRelinearizationRoundTwoGeneration {
    component: SetupGeneratedKeySwitchComponent,
    source_authority: SetupGeneratedRelinearizationRoundTwoSourceAuthority,
    evaluation_domain_size: usize,
}

impl SetupGeneratedRelinearizationRoundTwoGeneration {
    pub(crate) const fn component(&self) -> &SetupGeneratedKeySwitchComponent {
        &self.component
    }

    pub(crate) const fn source_authority(
        &self,
    ) -> &SetupGeneratedRelinearizationRoundTwoSourceAuthority {
        &self.source_authority
    }

    pub(crate) fn recreate_source_authority(
        &self,
    ) -> Result<SetupGeneratedRelinearizationRoundTwoSourceAuthority, RefusalReason> {
        let retained = &self.source_authority;
        let context = participant_component_context(
            retained.setup_proof_context_hash,
            SetupPublicPolynomialRootRole::RelinearizationRoundTwo,
            retained.participant_identity,
            retained.roster_position,
            retained.schedule_position,
        )?;
        let public_polynomial_root = recompute_setup_generated_component_public_polynomial_root(
            &self.component,
            &context,
            self.evaluation_domain_size,
        )?;
        if public_polynomial_root.public_polynomial_context_hash()
            != retained.component.public_polynomial_context_hash()
            || public_polynomial_root.root() != retained.component.contribution_root()
        {
            return Err(RefusalReason::WrongHashOrRoot);
        }
        let application_statement_hash = verified_application_statement_hash(
            retained.protocol_version,
            retained.suite_identifier,
            ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER,
            &retained.canonical_application_statement_bytes,
        );
        let material_ownership = ComponentMaterialOwnershipBinding::from_generated_application(
            retained.suite_identifier,
            retained.action_context_hash,
            application_statement_hash,
        );
        let component = generated_component_source(
            &self.component,
            material_ownership,
            public_polynomial_root,
        )?;
        Ok(SetupGeneratedRelinearizationRoundTwoSourceAuthority {
            protocol_version: retained.protocol_version,
            suite_identifier: retained.suite_identifier,
            ceremony_context_hash: retained.ceremony_context_hash,
            action_context_hash: retained.action_context_hash,
            roster_hash: retained.roster_hash,
            setup_proof_context_hash: retained.setup_proof_context_hash,
            participant_identity: retained.participant_identity,
            roster_position: retained.roster_position,
            schedule_position: retained.schedule_position,
            anchor_commitment_roots: retained.anchor_commitment_roots,
            round_one_root_pair: retained.round_one_root_pair,
            aggregate_round_one_root_pair: retained.aggregate_round_one_root_pair,
            canonical_application_statement_bytes: retained
                .canonical_application_statement_bytes
                .clone(),
            component,
        })
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        SetupGeneratedKeySwitchComponent,
        SetupGeneratedRelinearizationRoundTwoSourceAuthority,
    ) {
        (self.component, self.source_authority)
    }

    pub(super) fn retained_coefficient_payload_byte_length(&self) -> Result<u64, RefusalReason> {
        u64::try_from(self.component.canonical_bytes().len())
            .map_err(|_| RefusalReason::OutsideSupportedProfile)
    }
}

impl SetupGeneratedRelinearizationRoundTwoSourceAuthority {
    pub(crate) const fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    pub(crate) const fn suite_identifier(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.suite_identifier
    }

    pub(crate) const fn ceremony_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.ceremony_context_hash
    }

    pub(crate) const fn action_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.action_context_hash
    }

    pub(crate) const fn roster_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.roster_hash
    }

    pub(crate) const fn setup_proof_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.setup_proof_context_hash
    }

    pub(crate) const fn participant_identity(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.participant_identity
    }

    pub(crate) const fn roster_position(&self) -> u16 {
        self.roster_position
    }

    pub(crate) const fn schedule_position(&self) -> u32 {
        self.schedule_position
    }

    pub(crate) const fn anchor_commitment_roots(&self) -> [[u8; Hash512::BYTE_LENGTH]; 3] {
        self.anchor_commitment_roots
    }

    pub(crate) const fn round_one_root_pair(&self) -> [[u8; Hash512::BYTE_LENGTH]; 2] {
        self.round_one_root_pair
    }

    pub(crate) const fn aggregate_round_one_root_pair(&self) -> [[u8; Hash512::BYTE_LENGTH]; 2] {
        self.aggregate_round_one_root_pair
    }

    pub(crate) fn canonical_application_statement_bytes(&self) -> &[u8] {
        &self.canonical_application_statement_bytes
    }

    pub(crate) const fn component(&self) -> &SetupGeneratedRelinearizationComponentSource {
        &self.component
    }
}

struct SetupRelinearizationRoundTwoGenerationContext {
    protocol_version: u16,
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
    action_context_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    roster_position: u16,
    schedule_position: u32,
    anchor_commitment_roots: [[u8; Hash512::BYTE_LENGTH]; 3],
    round_one_root_pair: [[u8; Hash512::BYTE_LENGTH]; 2],
    aggregate_round_one_root_pair: [[u8; Hash512::BYTE_LENGTH]; 2],
}

/// Bounded, key-resident construction state for the streamed RKG round-two
/// activation. Only one paired residue row and the generated component are
/// retained; neither aggregate input component enters this authority.
pub(crate) struct SetupRelinearizationRoundTwoConstruction {
    evaluator_position: SelectedEvaluatorEntryPosition,
    topology: KeySwitchComponentMaterialTopology,
    evaluation_domain_size: usize,
    generation_context: SetupRelinearizationRoundTwoGenerationContext,
    canonical_bytes: Zeroizing<Vec<u8>>,
    aggregate_left_row: Zeroizing<Vec<u64>>,
    aggregate_right_row: Zeroizing<Vec<u64>>,
    partial_left_residue: Zeroizing<[u8; 8]>,
    partial_right_residue: Zeroizing<[u8; 8]>,
    partial_residue_byte_length: usize,
    decomposition_block_index: usize,
    extended_limb_ordinal: usize,
    absorbed_byte_length: u64,
}

impl SetupRelinearizationRoundTwoConstruction {
    fn new(
        evaluator_position: SelectedEvaluatorEntryPosition,
        topology: KeySwitchComponentMaterialTopology,
        evaluation_domain_size: usize,
        generation_context: SetupRelinearizationRoundTwoGenerationContext,
    ) -> Result<Self, RefusalReason> {
        let expected_byte_length = usize::try_from(topology.expected_byte_length())
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        let ring_degree = topology.polynomial_degree();
        if evaluation_domain_size == 0 || ring_degree == 0 || expected_byte_length == 0 {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        Ok(Self {
            evaluator_position,
            topology,
            evaluation_domain_size,
            generation_context,
            canonical_bytes: Zeroizing::new(Vec::with_capacity(expected_byte_length)),
            aggregate_left_row: Zeroizing::new(Vec::with_capacity(ring_degree)),
            aggregate_right_row: Zeroizing::new(Vec::with_capacity(ring_degree)),
            partial_left_residue: Zeroizing::new([0_u8; 8]),
            partial_right_residue: Zeroizing::new([0_u8; 8]),
            partial_residue_byte_length: 0,
            decomposition_block_index: 0,
            extended_limb_ordinal: 0,
            absorbed_byte_length: 0,
        })
    }

    pub(crate) const fn topology(&self) -> &KeySwitchComponentMaterialTopology {
        &self.topology
    }

    pub(crate) const fn evaluation_domain_size(&self) -> usize {
        self.evaluation_domain_size
    }

    pub(crate) fn pre_root_retained_payload_byte_length(&self) -> Result<u64, RefusalReason> {
        let canonical_component_byte_length = self.canonical_bytes.capacity();
        let aggregate_source_row_byte_length = self
            .aggregate_left_row
            .capacity()
            .checked_add(self.aggregate_right_row.capacity())
            .and_then(|coefficient_count| coefficient_count.checked_mul(size_of::<u64>()))
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        u64::try_from(
            canonical_component_byte_length
                .checked_add(aggregate_source_row_byte_length)
                .ok_or(RefusalReason::OutsideSupportedProfile)?,
        )
        .map_err(|_| RefusalReason::OutsideSupportedProfile)
    }

    pub(crate) fn root_overlap_retained_payload_byte_length(&self) -> Result<u64, RefusalReason> {
        u64::try_from(self.canonical_bytes.capacity())
            .map_err(|_| RefusalReason::OutsideSupportedProfile)
    }

    /// Peak temporary coefficient payload in one residue-row generation.
    /// The second product overlaps two centered-residue inputs, the first
    /// retained product, and the two vectors internal to the NTT product.
    /// The ephemeral input is dropped before the third product, so no later
    /// point has more than these five full-degree vectors live.
    pub(crate) fn generation_workspace_payload_peak_byte_length(
        &self,
    ) -> Result<u64, RefusalReason> {
        u64::try_from(self.topology.polynomial_degree())
            .ok()
            .and_then(|degree| degree.checked_mul(5))
            .and_then(|coefficient_count| {
                u64::try_from(size_of::<u64>())
                    .ok()
                    .and_then(|byte_length| coefficient_count.checked_mul(byte_length))
            })
            .ok_or(RefusalReason::OutsideSupportedProfile)
    }

    fn release_aggregate_source_row_allocations(&mut self) {
        self.aggregate_left_row = Zeroizing::new(Vec::new());
        self.aggregate_right_row = Zeroizing::new(Vec::new());
    }

    pub(crate) fn absorb_authenticated_source_pair(
        &mut self,
        common_secret_coefficients: &[i8],
        ephemeral_secret_coefficients: &[i8],
        round_two_errors_by_block: &[Zeroizing<Vec<i8>>],
        aggregate_left_bytes: &[u8],
        aggregate_right_bytes: &[u8],
    ) -> Result<(), RefusalReason> {
        if aggregate_left_bytes.is_empty()
            || aggregate_left_bytes.len() != aggregate_right_bytes.len()
            || self.decomposition_block_index >= self.topology.data_block_count()
            || self
                .absorbed_byte_length
                .checked_add(
                    u64::try_from(aggregate_left_bytes.len())
                        .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
                )
                .is_none_or(|length| length > self.topology.expected_byte_length())
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        let mut source_byte_offset = 0_usize;
        while source_byte_offset < aggregate_left_bytes.len() {
            let modulus = self
                .topology
                .ordered_moduli()
                .get(self.extended_limb_ordinal)
                .copied()
                .ok_or(RefusalReason::WrongTypeOrLength)?;
            let residue_byte_length = canonical_residue_byte_length(modulus)
                .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)?;
            let remaining_residue_byte_length = residue_byte_length
                .checked_sub(self.partial_residue_byte_length)
                .ok_or(RefusalReason::WrongTypeOrLength)?;
            let copied_byte_length =
                remaining_residue_byte_length.min(aggregate_left_bytes.len() - source_byte_offset);
            let partial_end = self
                .partial_residue_byte_length
                .checked_add(copied_byte_length)
                .ok_or(RefusalReason::OutsideSupportedProfile)?;
            let source_end = source_byte_offset
                .checked_add(copied_byte_length)
                .ok_or(RefusalReason::OutsideSupportedProfile)?;
            self.partial_left_residue[self.partial_residue_byte_length..partial_end]
                .copy_from_slice(&aggregate_left_bytes[source_byte_offset..source_end]);
            self.partial_right_residue[self.partial_residue_byte_length..partial_end]
                .copy_from_slice(&aggregate_right_bytes[source_byte_offset..source_end]);
            self.partial_residue_byte_length = partial_end;
            source_byte_offset = source_end;
            if self.partial_residue_byte_length != residue_byte_length {
                continue;
            }
            let aggregate_left_residue = u64::from_le_bytes(*self.partial_left_residue);
            let aggregate_right_residue = u64::from_le_bytes(*self.partial_right_residue);
            self.partial_left_residue.fill(0);
            self.partial_right_residue.fill(0);
            self.partial_residue_byte_length = 0;
            if aggregate_left_residue >= modulus || aggregate_right_residue >= modulus {
                return Err(RefusalReason::MalformedEncoding);
            }
            self.aggregate_left_row.push(aggregate_left_residue);
            self.aggregate_right_row.push(aggregate_right_residue);
            if self.aggregate_left_row.len() == self.topology.polynomial_degree() {
                self.finish_current_residue_row(
                    common_secret_coefficients,
                    ephemeral_secret_coefficients,
                    round_two_errors_by_block,
                    modulus,
                    residue_byte_length,
                )?;
            }
        }
        self.absorbed_byte_length = self
            .absorbed_byte_length
            .checked_add(
                u64::try_from(aggregate_left_bytes.len())
                    .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
            )
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        Ok(())
    }

    fn finish_current_residue_row(
        &mut self,
        common_secret_coefficients: &[i8],
        ephemeral_secret_coefficients: &[i8],
        round_two_errors_by_block: &[Zeroizing<Vec<i8>>],
        modulus: u64,
        residue_byte_length: usize,
    ) -> Result<(), RefusalReason> {
        let ring_degree = self.topology.polynomial_degree();
        let round_two_errors = round_two_errors_by_block
            .get(self.decomposition_block_index)
            .filter(|errors| errors.len() == ring_degree)
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        if common_secret_coefficients.len() != ring_degree
            || ephemeral_secret_coefficients.len() != ring_degree
            || self.aggregate_left_row.len() != ring_degree
            || self.aggregate_right_row.len() != ring_degree
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        let secret_residues = common_secret_coefficients
            .iter()
            .copied()
            .map(|coefficient| centered_i8_residue(coefficient, modulus))
            .collect::<Vec<_>>();
        let ephemeral_residues = ephemeral_secret_coefficients
            .iter()
            .copied()
            .map(|coefficient| centered_i8_residue(coefficient, modulus))
            .collect::<Vec<_>>();
        let secret_times_left =
            negacyclic_product_mod(&secret_residues, &self.aggregate_left_row, modulus)
                .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
        let ephemeral_times_right =
            negacyclic_product_mod(&ephemeral_residues, &self.aggregate_right_row, modulus)
                .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
        drop(ephemeral_residues);
        let secret_times_right =
            negacyclic_product_mod(&secret_residues, &self.aggregate_right_row, modulus)
                .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
        for coefficient_ordinal in 0..ring_degree {
            let round_two = add_mod_fast(
                sub_mod_fast(
                    add_mod_fast(
                        secret_times_left[coefficient_ordinal],
                        ephemeral_times_right[coefficient_ordinal],
                        modulus,
                    ),
                    secret_times_right[coefficient_ordinal],
                    modulus,
                ),
                mul_mod_fast(
                    PLAINTEXT_MODULUS % modulus,
                    centered_i8_residue(round_two_errors[coefficient_ordinal], modulus),
                    modulus,
                ),
                modulus,
            );
            self.canonical_bytes
                .extend_from_slice(&round_two.to_le_bytes()[..residue_byte_length]);
        }
        self.aggregate_left_row.clear();
        self.aggregate_right_row.clear();
        self.extended_limb_ordinal = self
            .extended_limb_ordinal
            .checked_add(1)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        if self.extended_limb_ordinal == self.topology.extended_limb_count() {
            self.extended_limb_ordinal = 0;
            self.decomposition_block_index = self
                .decomposition_block_index
                .checked_add(1)
                .ok_or(RefusalReason::OutsideSupportedProfile)?;
        }
        Ok(())
    }

    pub(crate) fn finish(
        &mut self,
    ) -> Result<SetupGeneratedRelinearizationRoundTwoGeneration, RefusalReason> {
        if self.absorbed_byte_length != self.topology.expected_byte_length()
            || self.decomposition_block_index != self.topology.data_block_count()
            || self.extended_limb_ordinal != 0
            || self.partial_residue_byte_length != 0
            || !self.aggregate_left_row.is_empty()
            || !self.aggregate_right_row.is_empty()
            || u64::try_from(self.canonical_bytes.len()).ok()
                != Some(self.topology.expected_byte_length())
        {
            return Err(RefusalReason::MissingPrerequisite);
        }
        self.release_aggregate_source_row_allocations();
        let generation_context = &self.generation_context;
        let component_context = participant_component_context(
            generation_context.setup_proof_context_hash,
            SetupPublicPolynomialRootRole::RelinearizationRoundTwo,
            generation_context.participant_identity,
            generation_context.roster_position,
            generation_context.schedule_position,
        )?;
        let public_polynomial_root =
            recompute_setup_generated_component_public_polynomial_root_from_bytes(
                &self.topology,
                &self.canonical_bytes,
                &component_context,
                self.evaluation_domain_size,
            )?;
        let canonical_application_statement_bytes =
            canonical_selected_relinearization_round_two_statement(
                generation_context.setup_proof_context_hash,
                generation_context.participant_identity,
                generation_context.roster_position,
                generation_context.schedule_position,
                &generation_context.anchor_commitment_roots,
                generation_context.round_one_root_pair[0],
                generation_context.round_one_root_pair[1],
                generation_context.aggregate_round_one_root_pair[0],
                generation_context.aggregate_round_one_root_pair[1],
                public_polynomial_root.root(),
            )
            .map_err(|_| RefusalReason::WrongContext)?;
        let application_statement_hash = verified_application_statement_hash(
            generation_context.protocol_version,
            generation_context.suite_identifier,
            ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER,
            &canonical_application_statement_bytes,
        );
        let material_ownership = ComponentMaterialOwnershipBinding::from_generated_application(
            generation_context.suite_identifier,
            generation_context.action_context_hash,
            application_statement_hash,
        );
        let stream_descriptor = derive_canonical_stream_descriptor(
            CanonicalStreamDomain::EvaluatorKeyStore,
            &self.canonical_bytes,
        )?;
        let component_source = generated_component_source_from_canonical_bytes(
            &self.topology,
            &self.canonical_bytes,
            &stream_descriptor,
            material_ownership,
            public_polynomial_root,
        )?;
        let canonical_bytes = core::mem::take(&mut *self.canonical_bytes);
        let component = SetupGeneratedKeySwitchComponent::from_authenticated_canonical_bytes(
            self.evaluator_position,
            self.topology.clone(),
            stream_descriptor,
            canonical_bytes,
        );
        Ok(SetupGeneratedRelinearizationRoundTwoGeneration {
            component,
            evaluation_domain_size: self.evaluation_domain_size,
            source_authority: SetupGeneratedRelinearizationRoundTwoSourceAuthority {
                protocol_version: generation_context.protocol_version,
                suite_identifier: generation_context.suite_identifier,
                ceremony_context_hash: generation_context.ceremony_context_hash,
                action_context_hash: generation_context.action_context_hash,
                roster_hash: generation_context.roster_hash,
                setup_proof_context_hash: generation_context.setup_proof_context_hash,
                participant_identity: generation_context.participant_identity,
                roster_position: generation_context.roster_position,
                schedule_position: generation_context.schedule_position,
                anchor_commitment_roots: generation_context.anchor_commitment_roots,
                round_one_root_pair: generation_context.round_one_root_pair,
                aggregate_round_one_root_pair: generation_context.aggregate_round_one_root_pair,
                canonical_application_statement_bytes: canonical_application_statement_bytes
                    .into_boxed_slice(),
                component: component_source,
            },
        })
    }
}

/// Exact generation-only witness and public component material for one
/// participant's suite-fixed relinearization schedule entry. The ephemeral
/// secret and all three error families remain process-local and are reused by
/// the two separate proof phases through the retained setup authority.
pub(crate) struct SetupGeneratedRelinearizationMaterial {
    evaluator_position: SelectedEvaluatorEntryPosition,
    schedule_position: u32,
    ephemeral_secret_coefficients: Zeroizing<Vec<i8>>,
    round_one_left_component: SetupGeneratedKeySwitchComponent,
    round_one_right_component: SetupGeneratedKeySwitchComponent,
    round_one_left_errors_by_block: Box<[Zeroizing<Vec<i8>>]>,
    round_one_right_errors_by_block: Box<[Zeroizing<Vec<i8>>]>,
    round_two_errors_by_block: Box<[Zeroizing<Vec<i8>>]>,
}

impl SetupGeneratedRelinearizationMaterial {
    pub(crate) const fn evaluator_position(&self) -> SelectedEvaluatorEntryPosition {
        self.evaluator_position
    }

    pub(crate) const fn schedule_position(&self) -> u32 {
        self.schedule_position
    }

    pub(crate) fn ephemeral_secret_coefficients(&self) -> &[i8] {
        &self.ephemeral_secret_coefficients
    }

    pub(crate) const fn round_one_left_component(&self) -> &SetupGeneratedKeySwitchComponent {
        &self.round_one_left_component
    }

    pub(crate) const fn round_one_right_component(&self) -> &SetupGeneratedKeySwitchComponent {
        &self.round_one_right_component
    }

    pub(crate) fn round_one_left_errors_by_block(&self) -> &[Zeroizing<Vec<i8>>] {
        &self.round_one_left_errors_by_block
    }

    pub(crate) fn round_one_right_errors_by_block(&self) -> &[Zeroizing<Vec<i8>>] {
        &self.round_one_right_errors_by_block
    }

    pub(crate) fn round_two_errors_by_block(&self) -> &[Zeroizing<Vec<i8>>] {
        &self.round_two_errors_by_block
    }

    pub(super) fn retained_coefficient_payload_byte_length(&self) -> Result<u64, RefusalReason> {
        let component_byte_length = self
            .round_one_left_component
            .canonical_bytes()
            .len()
            .checked_add(self.round_one_right_component.canonical_bytes().len())
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        let private_coefficient_byte_length = self
            .round_one_left_errors_by_block
            .iter()
            .chain(self.round_one_right_errors_by_block.iter())
            .chain(self.round_two_errors_by_block.iter())
            .try_fold(
                self.ephemeral_secret_coefficients.capacity(),
                |total, polynomial| {
                    total
                        .checked_add(polynomial.capacity())
                        .ok_or(RefusalReason::OutsideSupportedProfile)
                },
            )?;
        u64::try_from(
            component_byte_length
                .checked_add(private_coefficient_byte_length)
                .ok_or(RefusalReason::OutsideSupportedProfile)?,
        )
        .map_err(|_| RefusalReason::OutsideSupportedProfile)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn generated_round_one_source_authority(
        &self,
        suite_identifier: [u8; Hash512::BYTE_LENGTH],
        ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
        action_context_hash: [u8; Hash512::BYTE_LENGTH],
        roster_hash: [u8; Hash512::BYTE_LENGTH],
        setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
        participant_identity: [u8; Hash512::BYTE_LENGTH],
        roster_position: u16,
        anchor_commitment_roots: [[u8; Hash512::BYTE_LENGTH]; 3],
        evaluation_domain_size: usize,
    ) -> Result<SetupGeneratedRelinearizationRoundOneSourceAuthority, RefusalReason> {
        let left_context = participant_component_context(
            setup_proof_context_hash,
            SetupPublicPolynomialRootRole::RelinearizationRoundOneLeft,
            participant_identity,
            roster_position,
            self.schedule_position,
        )?;
        let right_context = participant_component_context(
            setup_proof_context_hash,
            SetupPublicPolynomialRootRole::RelinearizationRoundOneRight,
            participant_identity,
            roster_position,
            self.schedule_position,
        )?;
        let left_root = recompute_setup_generated_component_public_polynomial_root(
            &self.round_one_left_component,
            &left_context,
            evaluation_domain_size,
        )?;
        let right_root = recompute_setup_generated_component_public_polynomial_root(
            &self.round_one_right_component,
            &right_context,
            evaluation_domain_size,
        )?;
        let canonical_application_statement_bytes =
            canonical_selected_relinearization_round_one_statement(
                setup_proof_context_hash,
                participant_identity,
                roster_position,
                self.schedule_position,
                &anchor_commitment_roots,
                left_root.root(),
                right_root.root(),
            )
            .map_err(|_| RefusalReason::WrongContext)?;
        let application_statement_hash = verified_application_statement_hash(
            FOUNDATION_PROFILE.protocol_version,
            suite_identifier,
            ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER,
            &canonical_application_statement_bytes,
        );
        let material_ownership = ComponentMaterialOwnershipBinding::from_generated_application(
            suite_identifier,
            action_context_hash,
            application_statement_hash,
        );
        let components = [
            generated_component_source(
                &self.round_one_left_component,
                material_ownership,
                left_root,
            )?,
            generated_component_source(
                &self.round_one_right_component,
                material_ownership,
                right_root,
            )?,
        ];
        Ok(SetupGeneratedRelinearizationRoundOneSourceAuthority {
            protocol_version: FOUNDATION_PROFILE.protocol_version,
            suite_identifier,
            ceremony_context_hash,
            action_context_hash,
            roster_hash,
            setup_proof_context_hash,
            participant_identity,
            roster_position,
            schedule_position: self.schedule_position,
            anchor_commitment_roots,
            canonical_application_statement_bytes: canonical_application_statement_bytes
                .into_boxed_slice(),
            components,
        })
    }

    pub(crate) fn begin_round_two_construction(
        &self,
        selected_suite: &SelectedSuiteCapability,
        round_one_source: &SetupGeneratedRelinearizationRoundOneSourceAuthority,
        generated_aggregate: &SetupGeneratedRelinearizationAggregateSourceAuthority,
        evaluation_domain_size: usize,
    ) -> Result<SetupRelinearizationRoundTwoConstruction, RefusalReason> {
        let aggregate_root_pair = generated_aggregate.root_pair();
        let topology = self.round_one_left_component.topology().clone();
        if generated_aggregate.protocol_version() != round_one_source.protocol_version
            || generated_aggregate.suite_identifier() != round_one_source.suite_identifier
            || generated_aggregate.ceremony_context_hash() != round_one_source.ceremony_context_hash
            || generated_aggregate.action_context_hash() != round_one_source.action_context_hash
            || generated_aggregate.roster_hash() != round_one_source.roster_hash
            || generated_aggregate.setup_proof_context_hash()
                != round_one_source.setup_proof_context_hash
            || generated_aggregate.schedule_position() != self.schedule_position
            || generated_aggregate.evaluator_position() != self.evaluator_position
            || round_one_source.schedule_position != self.schedule_position
            || self.round_one_right_component.topology() != &topology
            || generated_aggregate.components()[0].topology() != &topology
            || generated_aggregate.components()[1].topology() != &topology
            || generated_aggregate.components()[0]
                .stream_descriptor()
                .total_byte_length
                != topology.expected_byte_length()
            || generated_aggregate.components()[1]
                .stream_descriptor()
                .total_byte_length
                != topology.expected_byte_length()
        {
            return Err(RefusalReason::WrongContext);
        }
        let _active_data_modulus_count = active_data_modulus_count(&topology, selected_suite)?;
        SetupRelinearizationRoundTwoConstruction::new(
            self.evaluator_position,
            topology,
            evaluation_domain_size,
            SetupRelinearizationRoundTwoGenerationContext {
                protocol_version: round_one_source.protocol_version,
                suite_identifier: round_one_source.suite_identifier,
                ceremony_context_hash: round_one_source.ceremony_context_hash,
                action_context_hash: round_one_source.action_context_hash,
                roster_hash: round_one_source.roster_hash,
                setup_proof_context_hash: round_one_source.setup_proof_context_hash,
                participant_identity: round_one_source.participant_identity,
                roster_position: round_one_source.roster_position,
                schedule_position: self.schedule_position,
                anchor_commitment_roots: round_one_source.anchor_commitment_roots,
                round_one_root_pair: round_one_source.root_pair(),
                aggregate_round_one_root_pair: aggregate_root_pair,
            },
        )
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn construct_relinearization_material(
    selected_suite: &SelectedSuiteCapability,
    action_private_randomness: &ActionPrivateRandomness,
    source_setup_intent_object_hash: [u8; Hash512::BYTE_LENGTH],
    setup_attempt_identifier: PrivateRandomnessAttemptIdentifier,
    public_setup_seed: [u8; Hash512::BYTE_LENGTH],
    common_secret_coefficients: &[i8],
) -> Result<SetupGeneratedRelinearizationMaterial, RefusalReason> {
    let evaluator_position = selected_relinearization_position()?;
    let SelectedEvaluatorEntryKind::Relinearization { catalog_level } =
        evaluator_position.key_kind()
    else {
        return Err(RefusalReason::UnsupportedVersionOrSuite);
    };
    let schedule_position = evaluator_position.schedule_position();
    let topology = KeySwitchComponentMaterialTopology::from_selected_suite_at_level(
        selected_suite,
        catalog_level,
    )?;
    let ring_degree = topology.polynomial_degree();
    if common_secret_coefficients.len() != ring_degree {
        return Err(RefusalReason::WrongTypeOrLength);
    }
    let ephemeral_secret_coefficients = sample_centered_ternary_polynomial(
        selected_suite,
        action_private_randomness,
        PrivateRandomnessDomain::setup_suite_distribution(
            RELINEARIZATION_EPHEMERAL_SECRET_DISTRIBUTION_PURPOSE,
        )
        .map_err(|error| error.refusal_reason)?,
        relinearization_private_polynomial_context_hash(
            source_setup_intent_object_hash,
            schedule_position,
            RELINEARIZATION_EPHEMERAL_SECRET_DISTRIBUTION_PURPOSE,
            None,
        )?,
        setup_attempt_identifier,
        ring_degree,
    )?;
    let mut round_one_left_errors_by_block = Vec::with_capacity(topology.data_block_count());
    let mut round_one_right_errors_by_block = Vec::with_capacity(topology.data_block_count());
    let mut round_two_errors_by_block = Vec::with_capacity(topology.data_block_count());
    for decomposition_block_index in 0..topology.data_block_count() {
        let decomposition_block_index = u16::try_from(decomposition_block_index)
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        round_one_left_errors_by_block.push(sample_relinearization_error(
            action_private_randomness,
            source_setup_intent_object_hash,
            setup_attempt_identifier,
            schedule_position,
            decomposition_block_index,
            RELINEARIZATION_ROUND_ONE_LEFT_ERROR_DISTRIBUTION_PURPOSE,
            ring_degree,
        )?);
        round_one_right_errors_by_block.push(sample_relinearization_error(
            action_private_randomness,
            source_setup_intent_object_hash,
            setup_attempt_identifier,
            schedule_position,
            decomposition_block_index,
            RELINEARIZATION_ROUND_ONE_RIGHT_ERROR_DISTRIBUTION_PURPOSE,
            ring_degree,
        )?);
        round_two_errors_by_block.push(sample_relinearization_error(
            action_private_randomness,
            source_setup_intent_object_hash,
            setup_attempt_identifier,
            schedule_position,
            decomposition_block_index,
            RELINEARIZATION_ROUND_TWO_ERROR_DISTRIBUTION_PURPOSE,
            ring_degree,
        )?);
    }
    let (round_one_left_bytes, round_one_right_bytes) = construct_round_one_component_bytes(
        selected_suite,
        &topology,
        schedule_position,
        common_secret_coefficients,
        &ephemeral_secret_coefficients,
        &round_one_left_errors_by_block,
        &round_one_right_errors_by_block,
        &public_setup_seed,
    )?;
    Ok(SetupGeneratedRelinearizationMaterial {
        evaluator_position,
        schedule_position,
        ephemeral_secret_coefficients,
        round_one_left_component: SetupGeneratedKeySwitchComponent::from_canonical_bytes(
            evaluator_position,
            topology.clone(),
            round_one_left_bytes,
        )?,
        round_one_right_component: SetupGeneratedKeySwitchComponent::from_canonical_bytes(
            evaluator_position,
            topology,
            round_one_right_bytes,
        )?,
        round_one_left_errors_by_block: round_one_left_errors_by_block.into_boxed_slice(),
        round_one_right_errors_by_block: round_one_right_errors_by_block.into_boxed_slice(),
        round_two_errors_by_block: round_two_errors_by_block.into_boxed_slice(),
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SetupRelinearizationAggregateSourceReadRequest {
    roster_position: u16,
    component_ordinal: u16,
    source_material_root: [u8; Hash512::BYTE_LENGTH],
    source_stream_byte_offset: u64,
    source_corpus_byte_offset: u64,
    source_stream_full_object_digest: [u8; Hash512::BYTE_LENGTH],
    source_stream_total_byte_length: u64,
    chunk_index: usize,
    byte_length: usize,
}

impl SetupRelinearizationAggregateSourceReadRequest {
    pub(crate) const fn roster_position(&self) -> u16 {
        self.roster_position
    }

    pub(crate) const fn component_ordinal(&self) -> u16 {
        self.component_ordinal
    }

    pub(crate) const fn source_material_root(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.source_material_root
    }

    pub(crate) const fn source_corpus_byte_offset(&self) -> u64 {
        self.source_corpus_byte_offset
    }

    pub(crate) const fn source_stream_byte_offset(&self) -> u64 {
        self.source_stream_byte_offset
    }

    pub(crate) const fn source_stream_full_object_digest(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.source_stream_full_object_digest
    }

    pub(crate) const fn source_stream_total_byte_length(&self) -> u64 {
        self.source_stream_total_byte_length
    }

    pub(crate) const fn chunk_index(&self) -> usize {
        self.chunk_index
    }

    pub(crate) const fn byte_length(&self) -> usize {
        self.byte_length
    }
}

/// Compact exact-list construction for the two public RKG round-one sums.
/// One authenticated transport chunk and one incomplete residue are consumed
/// at a time; the twenty complete source streams are never resident together.
pub(crate) struct SetupRelinearizationAggregateConstruction {
    protocol_version: u16,
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
    action_context_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    schedule_position: u32,
    evaluation_domain_size: usize,
    topology: KeySwitchComponentMaterialTopology,
    ordered_participant_identities: Box<[[u8; Hash512::BYTE_LENGTH]]>,
    ordered_anchor_commitment_roots: Box<[[[u8; Hash512::BYTE_LENGTH]; 3]]>,
    ordered_round_one_proof_stream_descriptors: Box<[StreamDescriptor]>,
    ordered_source_root_pairs: Box<[[[u8; Hash512::BYTE_LENGTH]; 2]]>,
    ordered_component_material_roots: Box<[[[u8; Hash512::BYTE_LENGTH]; 2]]>,
    ordered_component_stream_descriptors: Box<[[StreamDescriptor; 2]]>,
    ordered_component_corpus_byte_offsets: Box<[[u64; 2]]>,
    source_corpus_byte_length: u64,
    aggregate_component_bytes: [Vec<u8>; 2],
    current_component_ordinal: usize,
    current_roster_ordinal: usize,
    current_chunk_index: usize,
    current_stream_verifier: Option<CanonicalStreamVerifier>,
    completed_residue_byte_length: usize,
    current_block_index: usize,
    current_limb_index: usize,
    current_coefficient_index: usize,
    partial_residue_bytes: [u8; 8],
    partial_residue_byte_length: usize,
    refusal_reason: Option<RefusalReason>,
}

impl SetupRelinearizationAggregateConstruction {
    pub(crate) const fn source_corpus_byte_length(&self) -> u64 {
        self.source_corpus_byte_length
    }

    pub(crate) fn next_read_request(
        &self,
    ) -> Result<Option<SetupRelinearizationAggregateSourceReadRequest>, RefusalReason> {
        if let Some(refusal_reason) = self.refusal_reason {
            return Err(refusal_reason);
        }
        if self.current_component_ordinal >= 2 {
            return Ok(None);
        }
        let descriptor = self.current_stream_descriptor()?;
        let chunk_byte_length = FOUNDATION_PROFILE.stream_chunk_byte_length;
        let byte_start = self
            .current_chunk_index
            .checked_mul(chunk_byte_length)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        let total_byte_length = usize::try_from(descriptor.total_byte_length)
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        let byte_length = byte_start
            .checked_add(chunk_byte_length)
            .map(|byte_end| byte_end.min(total_byte_length))
            .and_then(|byte_end| byte_end.checked_sub(byte_start))
            .filter(|byte_length| {
                *byte_length > 0
                    && self.current_chunk_index < descriptor.ordered_chunk_digests.len()
            })
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        Ok(Some(SetupRelinearizationAggregateSourceReadRequest {
            roster_position: u16::try_from(self.current_roster_ordinal)
                .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
            component_ordinal: u16::try_from(self.current_component_ordinal)
                .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
            source_material_root: self
                .ordered_component_material_roots
                .get(self.current_roster_ordinal)
                .and_then(|roots| roots.get(self.current_component_ordinal))
                .copied()
                .ok_or(RefusalReason::WrongTypeOrLength)?,
            source_stream_byte_offset: u64::try_from(byte_start)
                .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
            source_corpus_byte_offset: self
                .ordered_component_corpus_byte_offsets
                .get(self.current_roster_ordinal)
                .and_then(|offsets| offsets.get(self.current_component_ordinal))
                .copied()
                .and_then(|source_byte_offset| {
                    u64::try_from(byte_start)
                        .ok()
                        .and_then(|chunk_byte_offset| {
                            source_byte_offset.checked_add(chunk_byte_offset)
                        })
                })
                .ok_or(RefusalReason::OutsideSupportedProfile)?,
            source_stream_full_object_digest: descriptor.full_object_digest.into_bytes(),
            source_stream_total_byte_length: descriptor.total_byte_length,
            chunk_index: self.current_chunk_index,
            byte_length,
        }))
    }

    pub(crate) fn supply_authenticated_source_chunk(
        &mut self,
        request: &SetupRelinearizationAggregateSourceReadRequest,
        bytes: &[u8],
    ) -> Result<(), RefusalReason> {
        if let Some(refusal_reason) = self.refusal_reason {
            return Err(refusal_reason);
        }
        let result = self.supply_authenticated_source_chunk_inner(request, bytes);
        if let Err(refusal_reason) = result {
            self.refusal_reason = Some(refusal_reason);
        }
        result
    }

    pub(crate) fn finish(
        self,
    ) -> Result<SetupGeneratedRelinearizationAggregateGeneration, RefusalReason> {
        if let Some(refusal_reason) = self.refusal_reason {
            return Err(refusal_reason);
        }
        if self.current_component_ordinal != 2
            || self.current_roster_ordinal != 0
            || self.current_chunk_index != 0
            || self.current_stream_verifier.is_some()
            || self.completed_residue_byte_length != 0
            || self.partial_residue_byte_length != 0
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        finish_generated_relinearization_aggregate(self)
    }

    fn current_stream_descriptor(&self) -> Result<&StreamDescriptor, RefusalReason> {
        self.ordered_component_stream_descriptors
            .get(self.current_roster_ordinal)
            .and_then(|descriptors| descriptors.get(self.current_component_ordinal))
            .ok_or(RefusalReason::WrongTypeOrLength)
    }

    fn supply_authenticated_source_chunk_inner(
        &mut self,
        request: &SetupRelinearizationAggregateSourceReadRequest,
        bytes: &[u8],
    ) -> Result<(), RefusalReason> {
        let expected_request = self
            .next_read_request()?
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        if request != &expected_request || bytes.len() != request.byte_length {
            return Err(RefusalReason::WrongContext);
        }
        self.current_stream_verifier
            .as_mut()
            .ok_or(RefusalReason::WrongTypeOrLength)?
            .absorb_chunk(self.current_chunk_index, bytes)
            .into_result()?;
        self.absorb_component_bytes(bytes)?;
        self.current_chunk_index = self
            .current_chunk_index
            .checked_add(1)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        if self.current_chunk_index
            == self
                .current_stream_descriptor()?
                .ordered_chunk_digests
                .len()
        {
            self.finish_current_stream_and_advance()?;
        }
        Ok(())
    }

    fn absorb_component_bytes(&mut self, mut bytes: &[u8]) -> Result<(), RefusalReason> {
        while !bytes.is_empty() {
            let modulus = self
                .topology
                .ordered_moduli()
                .get(self.current_limb_index)
                .copied()
                .ok_or(RefusalReason::WrongTypeOrLength)?;
            let residue_byte_length = canonical_residue_byte_length(modulus)
                .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)?;
            if residue_byte_length == 0 || residue_byte_length > self.partial_residue_bytes.len() {
                return Err(RefusalReason::UnsupportedVersionOrSuite);
            }
            if self.partial_residue_byte_length != 0 {
                let missing_byte_length = residue_byte_length
                    .checked_sub(self.partial_residue_byte_length)
                    .ok_or(RefusalReason::WrongTypeOrLength)?;
                let copied_byte_length = missing_byte_length.min(bytes.len());
                let partial_end = self
                    .partial_residue_byte_length
                    .checked_add(copied_byte_length)
                    .ok_or(RefusalReason::OutsideSupportedProfile)?;
                self.partial_residue_bytes[self.partial_residue_byte_length..partial_end]
                    .copy_from_slice(&bytes[..copied_byte_length]);
                self.partial_residue_byte_length = partial_end;
                bytes = &bytes[copied_byte_length..];
                if partial_end == residue_byte_length {
                    let residue_bytes = self.partial_residue_bytes;
                    self.absorb_complete_residue(&residue_bytes[..residue_byte_length])?;
                    self.partial_residue_bytes = [0_u8; 8];
                    self.partial_residue_byte_length = 0;
                }
                continue;
            }
            if bytes.len() < residue_byte_length {
                self.partial_residue_bytes[..bytes.len()].copy_from_slice(bytes);
                self.partial_residue_byte_length = bytes.len();
                return Ok(());
            }
            self.absorb_complete_residue(&bytes[..residue_byte_length])?;
            bytes = &bytes[residue_byte_length..];
        }
        Ok(())
    }

    fn absorb_complete_residue(&mut self, encoded: &[u8]) -> Result<(), RefusalReason> {
        let modulus = self
            .topology
            .ordered_moduli()
            .get(self.current_limb_index)
            .copied()
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        let residue_byte_length = canonical_residue_byte_length(modulus)
            .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)?;
        if encoded.len() != residue_byte_length {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        let source_residue = decode_canonical_residue(encoded, 0, residue_byte_length, modulus)?;
        let aggregate_bytes = self
            .aggregate_component_bytes
            .get_mut(self.current_component_ordinal)
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        let aggregate_residue = decode_canonical_residue(
            aggregate_bytes,
            self.completed_residue_byte_length,
            residue_byte_length,
            modulus,
        )?;
        let aggregate = add_mod_fast(aggregate_residue, source_residue, modulus);
        let byte_end = self
            .completed_residue_byte_length
            .checked_add(residue_byte_length)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        aggregate_bytes[self.completed_residue_byte_length..byte_end]
            .copy_from_slice(&aggregate.to_le_bytes()[..residue_byte_length]);
        self.completed_residue_byte_length = byte_end;
        self.current_coefficient_index = self
            .current_coefficient_index
            .checked_add(1)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        if self.current_coefficient_index == self.topology.polynomial_degree() {
            self.current_coefficient_index = 0;
            self.current_limb_index = self
                .current_limb_index
                .checked_add(1)
                .ok_or(RefusalReason::OutsideSupportedProfile)?;
            if self.current_limb_index == self.topology.extended_limb_count() {
                self.current_limb_index = 0;
                self.current_block_index = self
                    .current_block_index
                    .checked_add(1)
                    .ok_or(RefusalReason::OutsideSupportedProfile)?;
            }
        }
        Ok(())
    }

    fn finish_current_stream_and_advance(&mut self) -> Result<(), RefusalReason> {
        let expected_byte_length =
            usize::try_from(self.current_stream_descriptor()?.total_byte_length)
                .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        if self.partial_residue_byte_length != 0
            || self.completed_residue_byte_length != expected_byte_length
            || self.current_block_index != self.topology.data_block_count()
            || self.current_limb_index != 0
            || self.current_coefficient_index != 0
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        self.current_stream_verifier
            .take()
            .ok_or(RefusalReason::WrongTypeOrLength)?
            .finish()
            .into_result()?;
        self.current_roster_ordinal = self
            .current_roster_ordinal
            .checked_add(1)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        if self.current_roster_ordinal == usize::from(FOUNDATION_PROFILE.participant_count) {
            self.current_roster_ordinal = 0;
            self.current_component_ordinal = self
                .current_component_ordinal
                .checked_add(1)
                .ok_or(RefusalReason::OutsideSupportedProfile)?;
        }
        self.current_chunk_index = 0;
        self.completed_residue_byte_length = 0;
        self.current_block_index = 0;
        self.current_limb_index = 0;
        self.current_coefficient_index = 0;
        self.partial_residue_bytes = [0_u8; 8];
        self.partial_residue_byte_length = 0;
        if self.current_component_ordinal < 2 {
            self.current_stream_verifier = Some(CanonicalStreamVerifier::new(
                CanonicalStreamDomain::EvaluatorKeyStore,
                self.current_stream_descriptor()?.clone(),
            )?);
        }
        Ok(())
    }
}

pub(crate) fn construct_generated_relinearization_aggregate(
    ordered_sources: &[&SetupGeneratedRelinearizationRoundOneSourceAuthority],
    ordered_round_one_proof_stream_descriptors: &[StreamDescriptor],
    evaluation_domain_size: usize,
) -> Result<SetupRelinearizationAggregateConstruction, RefusalReason> {
    if ordered_sources.len() != usize::from(FOUNDATION_PROFILE.participant_count)
        || ordered_round_one_proof_stream_descriptors.len() != ordered_sources.len()
        || FOUNDATION_PROFILE.participant_count != 10
        || evaluation_domain_size == 0
    {
        return Err(RefusalReason::WrongTypeOrLength);
    }
    let first_source = ordered_sources
        .first()
        .copied()
        .ok_or(RefusalReason::MissingPrerequisite)?;
    let schedule_position = first_source.schedule_position();
    let [first_left_material, first_right_material] = first_source.components();
    if first_left_material.topology() != first_right_material.topology() {
        return Err(RefusalReason::WrongTypeOrLength);
    }
    let topology = first_left_material.topology().clone();
    let mut ordered_participant_identities = Vec::with_capacity(ordered_sources.len());
    let mut ordered_anchor_commitment_roots = Vec::with_capacity(ordered_sources.len());
    let mut ordered_source_root_pairs = Vec::with_capacity(ordered_sources.len());
    let mut ordered_component_material_roots = Vec::with_capacity(ordered_sources.len());
    let mut ordered_component_stream_descriptors = Vec::with_capacity(ordered_sources.len());
    for (roster_ordinal, source) in ordered_sources.iter().copied().enumerate() {
        let roster_position =
            u16::try_from(roster_ordinal).map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        let [left_material, right_material] = source.components();
        if source.protocol_version() != first_source.protocol_version()
            || source.suite_identifier() != first_source.suite_identifier()
            || source.ceremony_context_hash() != first_source.ceremony_context_hash()
            || source.action_context_hash() != first_source.action_context_hash()
            || source.roster_hash() != first_source.roster_hash()
            || source.setup_proof_context_hash() != first_source.setup_proof_context_hash()
            || source.roster_position() != roster_position
            || source.schedule_position() != schedule_position
            || left_material.topology() != &topology
            || right_material.topology() != &topology
            || ordered_participant_identities.contains(&source.participant_identity())
        {
            return Err(RefusalReason::WrongContext);
        }
        ordered_participant_identities.push(source.participant_identity());
        ordered_anchor_commitment_roots.push(source.anchor_commitment_roots());
        ordered_source_root_pairs.push(source.root_pair());
        ordered_component_material_roots.push([
            left_material.material_root().into_bytes(),
            right_material.material_root().into_bytes(),
        ]);
        ordered_component_stream_descriptors.push([
            left_material.stream_descriptor().clone(),
            right_material.stream_descriptor().clone(),
        ]);
    }
    let mut ordered_component_corpus_byte_offsets = vec![[0_u64; 2]; ordered_sources.len()];
    let mut source_corpus_byte_length = 0_u64;
    for component_ordinal in 0..2 {
        for (source_ordinal, descriptors) in ordered_component_stream_descriptors.iter().enumerate()
        {
            ordered_component_corpus_byte_offsets[source_ordinal][component_ordinal] =
                source_corpus_byte_length;
            source_corpus_byte_length = source_corpus_byte_length
                .checked_add(descriptors[component_ordinal].total_byte_length)
                .ok_or(RefusalReason::OutsideSupportedProfile)?;
        }
    }
    let component_byte_length = usize::try_from(topology.expected_byte_length())
        .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
    let current_stream_verifier = Some(CanonicalStreamVerifier::new(
        CanonicalStreamDomain::EvaluatorKeyStore,
        ordered_component_stream_descriptors[0][0].clone(),
    )?);
    Ok(SetupRelinearizationAggregateConstruction {
        protocol_version: first_source.protocol_version(),
        suite_identifier: first_source.suite_identifier(),
        ceremony_context_hash: first_source.ceremony_context_hash(),
        action_context_hash: first_source.action_context_hash(),
        roster_hash: first_source.roster_hash(),
        setup_proof_context_hash: first_source.setup_proof_context_hash(),
        schedule_position,
        evaluation_domain_size,
        topology,
        ordered_participant_identities: ordered_participant_identities.into_boxed_slice(),
        ordered_anchor_commitment_roots: ordered_anchor_commitment_roots.into_boxed_slice(),
        ordered_round_one_proof_stream_descriptors: ordered_round_one_proof_stream_descriptors
            .to_vec()
            .into_boxed_slice(),
        ordered_source_root_pairs: ordered_source_root_pairs.into_boxed_slice(),
        ordered_component_material_roots: ordered_component_material_roots.into_boxed_slice(),
        ordered_component_stream_descriptors: ordered_component_stream_descriptors
            .into_boxed_slice(),
        ordered_component_corpus_byte_offsets: ordered_component_corpus_byte_offsets
            .into_boxed_slice(),
        source_corpus_byte_length,
        aggregate_component_bytes: [
            vec![0_u8; component_byte_length],
            vec![0_u8; component_byte_length],
        ],
        current_component_ordinal: 0,
        current_roster_ordinal: 0,
        current_chunk_index: 0,
        current_stream_verifier,
        completed_residue_byte_length: 0,
        current_block_index: 0,
        current_limb_index: 0,
        current_coefficient_index: 0,
        partial_residue_bytes: [0_u8; 8],
        partial_residue_byte_length: 0,
        refusal_reason: None,
    })
}

fn finish_generated_relinearization_aggregate(
    construction: SetupRelinearizationAggregateConstruction,
) -> Result<SetupGeneratedRelinearizationAggregateGeneration, RefusalReason> {
    let evaluator_position = selected_relinearization_position()?;
    let [aggregate_left_bytes, aggregate_right_bytes] = construction.aggregate_component_bytes;
    let aggregate_components = [
        SetupGeneratedKeySwitchComponent::from_canonical_bytes(
            evaluator_position,
            construction.topology.clone(),
            aggregate_left_bytes,
        )?,
        SetupGeneratedKeySwitchComponent::from_canonical_bytes(
            evaluator_position,
            construction.topology,
            aggregate_right_bytes,
        )?,
    ];
    let contexts = [
        unowned_component_context(
            construction.setup_proof_context_hash,
            SetupPublicPolynomialRootRole::RelinearizationAggregateRoundOneLeft,
            construction.schedule_position,
        )?,
        unowned_component_context(
            construction.setup_proof_context_hash,
            SetupPublicPolynomialRootRole::RelinearizationAggregateRoundOneRight,
            construction.schedule_position,
        )?,
    ];
    let public_polynomial_roots = [
        recompute_setup_generated_component_public_polynomial_root(
            &aggregate_components[0],
            &contexts[0],
            construction.evaluation_domain_size,
        )?,
        recompute_setup_generated_component_public_polynomial_root(
            &aggregate_components[1],
            &contexts[1],
            construction.evaluation_domain_size,
        )?,
    ];
    let canonical_application_statement_bytes =
        canonical_selected_relinearization_round_one_aggregate_statement(
            construction.setup_proof_context_hash,
            construction.schedule_position,
            &construction.ordered_source_root_pairs,
            public_polynomial_roots[0].root(),
            public_polynomial_roots[1].root(),
        )
        .map_err(|_| RefusalReason::WrongContext)?;
    let application_statement_hash = verified_application_statement_hash(
        construction.protocol_version,
        construction.suite_identifier,
        ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        &canonical_application_statement_bytes,
    );
    let material_ownership = ComponentMaterialOwnershipBinding::from_generated_application(
        construction.suite_identifier,
        construction.action_context_hash,
        application_statement_hash,
    );
    let component_sources = [
        generated_component_source(
            &aggregate_components[0],
            material_ownership,
            public_polynomial_roots[0],
        )?,
        generated_component_source(
            &aggregate_components[1],
            material_ownership,
            public_polynomial_roots[1],
        )?,
    ];
    Ok(SetupGeneratedRelinearizationAggregateGeneration {
        components: aggregate_components,
        source_authority: SetupGeneratedRelinearizationAggregateSourceAuthority {
            protocol_version: construction.protocol_version,
            suite_identifier: construction.suite_identifier,
            ceremony_context_hash: construction.ceremony_context_hash,
            action_context_hash: construction.action_context_hash,
            roster_hash: construction.roster_hash,
            setup_proof_context_hash: construction.setup_proof_context_hash,
            schedule_position: construction.schedule_position,
            evaluator_position,
            ordered_participant_identities: construction.ordered_participant_identities,
            ordered_anchor_commitment_roots: construction.ordered_anchor_commitment_roots,
            ordered_round_one_proof_stream_descriptors: construction
                .ordered_round_one_proof_stream_descriptors,
            ordered_source_root_pairs: construction.ordered_source_root_pairs,
            canonical_application_statement_bytes: canonical_application_statement_bytes
                .into_boxed_slice(),
            components: component_sources,
        },
    })
}

fn selected_relinearization_position() -> Result<SelectedEvaluatorEntryPosition, RefusalReason> {
    let matches = selected_evaluator_entry_positions(FOUNDATION_PROFILE.option_count)
        .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)?
        .into_iter()
        .filter(|position| {
            matches!(
                position.key_kind(),
                SelectedEvaluatorEntryKind::Relinearization { .. }
            )
        })
        .collect::<Vec<_>>();
    let [position] = matches.as_slice() else {
        return Err(RefusalReason::UnsupportedVersionOrSuite);
    };
    Ok(*position)
}

#[allow(clippy::too_many_arguments)]
fn sample_relinearization_error(
    action_private_randomness: &ActionPrivateRandomness,
    source_setup_intent_object_hash: [u8; Hash512::BYTE_LENGTH],
    setup_attempt_identifier: PrivateRandomnessAttemptIdentifier,
    schedule_position: u32,
    decomposition_block_index: u16,
    distribution_purpose: u16,
    ring_degree: usize,
) -> Result<Zeroizing<Vec<i8>>, RefusalReason> {
    sample_centered_binomial_polynomial(
        action_private_randomness,
        PrivateRandomnessDomain::setup_suite_distribution(distribution_purpose)
            .map_err(|error| error.refusal_reason)?,
        relinearization_private_polynomial_context_hash(
            source_setup_intent_object_hash,
            schedule_position,
            distribution_purpose,
            Some(decomposition_block_index),
        )?,
        setup_attempt_identifier,
        RELINEARIZATION_ERROR_CENTERED_BINOMIAL_PARAMETER,
        ring_degree,
    )
}

fn relinearization_private_polynomial_context_hash(
    source_setup_intent_object_hash: [u8; Hash512::BYTE_LENGTH],
    schedule_position: u32,
    distribution_purpose: u16,
    decomposition_block_index: Option<u16>,
) -> Result<Hash512, RefusalReason> {
    let block_coordinate = decomposition_block_index.map_or(u32::MAX, u32::from);
    let canonical_bytes = CanonicalTuple::new(
        RELINEARIZATION_PRIVATE_POLYNOMIAL_CONTEXT_SCHEMA_IDENTIFIER,
        FOUNDATION_SCHEMA_VERSION,
        vec![
            CanonicalItem::hash512(source_setup_intent_object_hash),
            CanonicalItem::unsigned32(schedule_position),
            CanonicalItem::unsigned16(distribution_purpose),
            CanonicalItem::unsigned32(block_coordinate),
        ],
    )
    .encode()
    .map_err(|_| RefusalReason::MalformedEncoding)?;
    hash_foundation_tuple_512(
        RELINEARIZATION_PRIVATE_POLYNOMIAL_CONTEXT_HASH_DOMAIN,
        &[CanonicalItem::variable_bytes(canonical_bytes)
            .map_err(|_| RefusalReason::MalformedEncoding)?],
    )
    .map_err(|_| RefusalReason::MalformedEncoding)
}

#[allow(clippy::too_many_arguments)]
fn construct_round_one_component_bytes(
    selected_suite: &SelectedSuiteCapability,
    topology: &KeySwitchComponentMaterialTopology,
    schedule_position: u32,
    common_secret_coefficients: &[i8],
    ephemeral_secret_coefficients: &[i8],
    round_one_left_errors_by_block: &[Zeroizing<Vec<i8>>],
    round_one_right_errors_by_block: &[Zeroizing<Vec<i8>>],
    public_setup_seed: &[u8; Hash512::BYTE_LENGTH],
) -> Result<(Vec<u8>, Vec<u8>), RefusalReason> {
    let active_data_modulus_count = active_data_modulus_count(topology, selected_suite)?;
    let data_primes_per_block = usize::from(selected_suite.key_switch_data_primes_per_block());
    let ring_degree = topology.polynomial_degree();
    if common_secret_coefficients.len() != ring_degree
        || ephemeral_secret_coefficients.len() != ring_degree
        || round_one_left_errors_by_block.len() != topology.data_block_count()
        || round_one_right_errors_by_block.len() != topology.data_block_count()
    {
        return Err(RefusalReason::WrongTypeOrLength);
    }
    let mut left_bytes = Vec::with_capacity(
        usize::try_from(topology.expected_byte_length())
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
    );
    let mut right_bytes = Vec::with_capacity(left_bytes.capacity());
    for decomposition_block_index in 0..topology.data_block_count() {
        let block_start = decomposition_block_index
            .checked_mul(data_primes_per_block)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        let block_end = block_start
            .checked_add(data_primes_per_block)
            .map(|end| end.min(active_data_modulus_count))
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        for (extended_limb_ordinal, modulus) in
            topology.ordered_moduli().iter().copied().enumerate()
        {
            let (modulus_catalog_identifier, modulus_index) =
                modulus_coordinate(extended_limb_ordinal, active_data_modulus_count)?;
            let common_reference = sample_relinearization_common_reference_limb(
                public_setup_seed,
                schedule_position,
                u16::try_from(decomposition_block_index)
                    .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
                modulus_catalog_identifier,
                modulus_index,
                ring_degree,
            )
            .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
            let secret_residues = common_secret_coefficients
                .iter()
                .copied()
                .map(|coefficient| centered_i8_residue(coefficient, modulus))
                .collect::<Vec<_>>();
            let ephemeral_residues = ephemeral_secret_coefficients
                .iter()
                .copied()
                .map(|coefficient| centered_i8_residue(coefficient, modulus))
                .collect::<Vec<_>>();
            let common_reference_times_secret =
                negacyclic_product_mod(&common_reference, &secret_residues, modulus)
                    .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
            let common_reference_times_ephemeral =
                negacyclic_product_mod(&common_reference, &ephemeral_residues, modulus)
                    .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
            let gadget_coefficient = (extended_limb_ordinal >= block_start
                && extended_limb_ordinal < block_end)
                .then(|| special_basis_modulus_residue(modulus));
            let residue_byte_length = canonical_residue_byte_length(modulus)
                .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)?;
            for coefficient_ordinal in 0..ring_degree {
                let scaled_left_error = mul_mod_fast(
                    PLAINTEXT_MODULUS % modulus,
                    centered_i8_residue(
                        round_one_left_errors_by_block[decomposition_block_index]
                            [coefficient_ordinal],
                        modulus,
                    ),
                    modulus,
                );
                let mut left = sub_mod_fast(
                    scaled_left_error,
                    common_reference_times_ephemeral[coefficient_ordinal],
                    modulus,
                );
                if let Some(gadget_coefficient) = gadget_coefficient {
                    left = add_mod_fast(
                        left,
                        mul_mod_fast(
                            gadget_coefficient,
                            secret_residues[coefficient_ordinal],
                            modulus,
                        ),
                        modulus,
                    );
                }
                let right = add_mod_fast(
                    common_reference_times_secret[coefficient_ordinal],
                    mul_mod_fast(
                        PLAINTEXT_MODULUS % modulus,
                        centered_i8_residue(
                            round_one_right_errors_by_block[decomposition_block_index]
                                [coefficient_ordinal],
                            modulus,
                        ),
                        modulus,
                    ),
                    modulus,
                );
                left_bytes.extend_from_slice(&left.to_le_bytes()[..residue_byte_length]);
                right_bytes.extend_from_slice(&right.to_le_bytes()[..residue_byte_length]);
            }
        }
    }
    require_component_byte_lengths(topology, &left_bytes, &right_bytes)?;
    Ok((left_bytes, right_bytes))
}

fn participant_component_context(
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    root_role: SetupPublicPolynomialRootRole,
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    roster_position: u16,
    schedule_position: u32,
) -> Result<SetupPublicPolynomialContext, RefusalReason> {
    SetupPublicPolynomialContext::new(
        setup_proof_context_hash,
        root_role,
        Some(participant_identity),
        Some(roster_position),
        Some(schedule_position),
        None,
    )
    .map_err(|_| RefusalReason::WrongContext)
}

fn unowned_component_context(
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    root_role: SetupPublicPolynomialRootRole,
    schedule_position: u32,
) -> Result<SetupPublicPolynomialContext, RefusalReason> {
    SetupPublicPolynomialContext::new(
        setup_proof_context_hash,
        root_role,
        None,
        None,
        Some(schedule_position),
        None,
    )
    .map_err(|_| RefusalReason::WrongContext)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct SetupGeneratedComponentPublicPolynomialRoot {
    public_polynomial_context_hash: [u8; Hash512::BYTE_LENGTH],
    root: [u8; Hash512::BYTE_LENGTH],
}

impl SetupGeneratedComponentPublicPolynomialRoot {
    pub(super) const fn public_polynomial_context_hash(self) -> [u8; Hash512::BYTE_LENGTH] {
        self.public_polynomial_context_hash
    }

    pub(super) const fn root(self) -> [u8; Hash512::BYTE_LENGTH] {
        self.root
    }
}

pub(super) fn recompute_setup_generated_component_public_polynomial_root(
    component: &SetupGeneratedKeySwitchComponent,
    context: &SetupPublicPolynomialContext,
    evaluation_domain_size: usize,
) -> Result<SetupGeneratedComponentPublicPolynomialRoot, RefusalReason> {
    recompute_setup_generated_component_public_polynomial_root_from_bytes(
        component.topology(),
        component.canonical_bytes(),
        context,
        evaluation_domain_size,
    )
}

fn recompute_setup_generated_component_public_polynomial_root_from_bytes(
    topology: &KeySwitchComponentMaterialTopology,
    canonical_bytes: &[u8],
    context: &SetupPublicPolynomialContext,
    evaluation_domain_size: usize,
) -> Result<SetupGeneratedComponentPublicPolynomialRoot, RefusalReason> {
    if u64::try_from(canonical_bytes.len()).ok() != Some(topology.expected_byte_length()) {
        return Err(RefusalReason::WrongTypeOrLength);
    }
    let trace_column_count = topology.trace_column_count()?;
    let row_width =
        u32::try_from(trace_column_count).map_err(|_| RefusalReason::OutsideSupportedProfile)?;
    let mut root_builder = SetupPublicPolynomialRootBuilder::new(
        context,
        evaluation_domain_size,
        topology.half_polynomial_degree_bound_exclusive()?,
        row_width,
    )
    .map_err(|_| RefusalReason::WrongHashOrRoot)?;
    for column_ordinal in 0..trace_column_count {
        let trace_column = topology.trace_column(column_ordinal)?;
        let byte_start = usize::try_from(trace_column.byte_offset())
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        let byte_end = usize::try_from(
            trace_column
                .byte_offset()
                .checked_add(trace_column.byte_length())
                .ok_or(RefusalReason::OutsideSupportedProfile)?,
        )
        .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        let trace_column_bytes = canonical_bytes
            .get(byte_start..byte_end)
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        root_builder
            .absorb_canonical_residue_trace_row(
                trace_column_bytes,
                trace_column.residue_byte_length(),
                trace_column.modulus(),
            )
            .map_err(|_| RefusalReason::WrongHashOrRoot)?;
    }
    let (public_polynomial_context_hash, root) = root_builder
        .finish()
        .map_err(|_| RefusalReason::WrongHashOrRoot)?;
    Ok(SetupGeneratedComponentPublicPolynomialRoot {
        public_polynomial_context_hash,
        root,
    })
}

fn generated_component_source(
    component: &SetupGeneratedKeySwitchComponent,
    material_ownership: ComponentMaterialOwnershipBinding,
    public_polynomial_root: SetupGeneratedComponentPublicPolynomialRoot,
) -> Result<SetupGeneratedRelinearizationComponentSource, RefusalReason> {
    generated_component_source_from_canonical_bytes(
        component.topology(),
        component.canonical_bytes(),
        component.stream_descriptor(),
        material_ownership,
        public_polynomial_root,
    )
}

fn generated_component_source_from_canonical_bytes(
    topology: &KeySwitchComponentMaterialTopology,
    canonical_bytes: &[u8],
    stream_descriptor: &StreamDescriptor,
    material_ownership: ComponentMaterialOwnershipBinding,
    public_polynomial_root: SetupGeneratedComponentPublicPolynomialRoot,
) -> Result<SetupGeneratedRelinearizationComponentSource, RefusalReason> {
    let material = authenticate_setup_generated_component_material(
        topology,
        canonical_bytes,
        stream_descriptor,
        material_ownership,
    )?;
    Ok(SetupGeneratedRelinearizationComponentSource {
        material,
        contribution_root: public_polynomial_root.root(),
        public_polynomial_context_hash: public_polynomial_root.public_polynomial_context_hash(),
    })
}

pub(super) fn authenticate_setup_generated_component_material(
    topology: &KeySwitchComponentMaterialTopology,
    canonical_bytes: &[u8],
    stream_descriptor: &StreamDescriptor,
    material_ownership: ComponentMaterialOwnershipBinding,
) -> Result<VerifiedKeySwitchComponentMaterial, RefusalReason> {
    if u64::try_from(canonical_bytes.len()).ok() != Some(topology.expected_byte_length()) {
        return Err(RefusalReason::WrongTypeOrLength);
    }
    let mut stream = VerifiedKeySwitchComponentMaterialStream::begin(
        topology.clone(),
        material_ownership,
        stream_descriptor.clone(),
    )?;
    for (chunk_index, chunk_bytes) in canonical_bytes
        .chunks(FOUNDATION_PROFILE.stream_chunk_byte_length)
        .enumerate()
    {
        stream
            .absorb_chunk(chunk_index, chunk_bytes)
            .into_result()?;
    }
    stream.finish().into_result()
}

fn active_data_modulus_count(
    topology: &KeySwitchComponentMaterialTopology,
    selected_suite: &SelectedSuiteCapability,
) -> Result<usize, RefusalReason> {
    let special_modulus_count = selected_suite.ordered_special_primes().len();
    let active_data_modulus_count = topology
        .extended_limb_count()
        .checked_sub(special_modulus_count)
        .ok_or(RefusalReason::UnsupportedVersionOrSuite)?;
    if active_data_modulus_count == 0
        || topology.data_block_count()
            != active_data_modulus_count.div_ceil(KEY_SWITCH_DATA_PRIMES_PER_BLOCK)
    {
        return Err(RefusalReason::UnsupportedVersionOrSuite);
    }
    Ok(active_data_modulus_count)
}

fn modulus_coordinate(
    extended_limb_ordinal: usize,
    active_data_modulus_count: usize,
) -> Result<(u16, u16), RefusalReason> {
    if extended_limb_ordinal < active_data_modulus_count {
        Ok((
            DATA_MODULUS_CATALOG_IDENTIFIER,
            u16::try_from(extended_limb_ordinal)
                .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
        ))
    } else {
        Ok((
            SPECIAL_MODULUS_CATALOG_IDENTIFIER,
            u16::try_from(extended_limb_ordinal - active_data_modulus_count)
                .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
        ))
    }
}

fn decode_canonical_residue(
    bytes: &[u8],
    byte_offset: usize,
    residue_byte_length: usize,
    modulus: u64,
) -> Result<u64, RefusalReason> {
    let end = byte_offset
        .checked_add(residue_byte_length)
        .ok_or(RefusalReason::OutsideSupportedProfile)?;
    let encoded = bytes
        .get(byte_offset..end)
        .ok_or(RefusalReason::WrongTypeOrLength)?;
    let mut little_endian = [0_u8; 8];
    little_endian
        .get_mut(..residue_byte_length)
        .ok_or(RefusalReason::WrongTypeOrLength)?
        .copy_from_slice(encoded);
    let residue = u64::from_le_bytes(little_endian);
    if residue >= modulus {
        return Err(RefusalReason::MalformedEncoding);
    }
    Ok(residue)
}

fn require_component_byte_lengths(
    topology: &KeySwitchComponentMaterialTopology,
    left_bytes: &[u8],
    right_bytes: &[u8],
) -> Result<(), RefusalReason> {
    let expected = usize::try_from(topology.expected_byte_length())
        .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
    if left_bytes.len() != expected || right_bytes.len() != expected {
        return Err(RefusalReason::WrongTypeOrLength);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::{SetupPublicPolynomialTree, SetupPublicPolynomialTreeInput};
    use crate::foundation::derive_canonical_stream_descriptor;

    fn test_topology() -> KeySwitchComponentMaterialTopology {
        KeySwitchComponentMaterialTopology::for_test_suite(&[257, 769], &[12_289], 1, 8)
            .expect("test topology")
    }

    fn encoded_component(topology: &KeySwitchComponentMaterialTopology, residue: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        for _ in 0..topology.data_block_count() {
            for modulus in topology.ordered_moduli().iter().copied() {
                let residue_byte_length =
                    canonical_residue_byte_length(modulus).expect("residue byte length");
                let canonical_residue = residue % modulus;
                for _ in 0..topology.polynomial_degree() {
                    bytes
                        .extend_from_slice(&canonical_residue.to_le_bytes()[..residue_byte_length]);
                }
            }
        }
        assert_eq!(
            u64::try_from(bytes.len()).expect("component length"),
            topology.expected_byte_length()
        );
        bytes
    }

    fn accumulator_for_test(
        topology: KeySwitchComponentMaterialTopology,
    ) -> SetupRelinearizationAggregateConstruction {
        let component_byte_length =
            usize::try_from(topology.expected_byte_length()).expect("component byte length");
        let descriptor = derive_canonical_stream_descriptor(
            CanonicalStreamDomain::EvaluatorKeyStore,
            &vec![0_u8; component_byte_length],
        )
        .expect("descriptor");
        SetupRelinearizationAggregateConstruction {
            protocol_version: FOUNDATION_PROFILE.protocol_version,
            suite_identifier: [0x11; Hash512::BYTE_LENGTH],
            ceremony_context_hash: [0x22; Hash512::BYTE_LENGTH],
            action_context_hash: [0x33; Hash512::BYTE_LENGTH],
            roster_hash: [0x44; Hash512::BYTE_LENGTH],
            setup_proof_context_hash: [0x55; Hash512::BYTE_LENGTH],
            schedule_position: 0,
            evaluation_domain_size: 16,
            topology,
            ordered_participant_identities: vec![
                [0x66; Hash512::BYTE_LENGTH];
                usize::from(FOUNDATION_PROFILE.participant_count)
            ]
            .into_boxed_slice(),
            ordered_anchor_commitment_roots: vec![
                [[0x77; Hash512::BYTE_LENGTH]; 3];
                usize::from(FOUNDATION_PROFILE.participant_count)
            ]
            .into_boxed_slice(),
            ordered_round_one_proof_stream_descriptors: vec![
                descriptor.clone();
                usize::from(
                    FOUNDATION_PROFILE.participant_count
                )
            ]
            .into_boxed_slice(),
            ordered_source_root_pairs: vec![
                [[0x88; Hash512::BYTE_LENGTH]; 2];
                usize::from(FOUNDATION_PROFILE.participant_count)
            ]
            .into_boxed_slice(),
            ordered_component_material_roots: vec![
                [[0x99; Hash512::BYTE_LENGTH]; 2];
                usize::from(FOUNDATION_PROFILE.participant_count)
            ]
            .into_boxed_slice(),
            ordered_component_stream_descriptors: vec![
                [descriptor.clone(), descriptor];
                usize::from(
                    FOUNDATION_PROFILE.participant_count
                )
            ]
            .into_boxed_slice(),
            ordered_component_corpus_byte_offsets: vec![
                [0_u64; 2];
                usize::from(
                    FOUNDATION_PROFILE.participant_count
                )
            ]
            .into_boxed_slice(),
            source_corpus_byte_length: 0,
            aggregate_component_bytes: [
                vec![0_u8; component_byte_length],
                vec![0_u8; component_byte_length],
            ],
            current_component_ordinal: 0,
            current_roster_ordinal: 0,
            current_chunk_index: 0,
            current_stream_verifier: None,
            completed_residue_byte_length: 0,
            current_block_index: 0,
            current_limb_index: 0,
            current_coefficient_index: 0,
            partial_residue_bytes: [0_u8; 8],
            partial_residue_byte_length: 0,
            refusal_reason: None,
        }
    }

    #[test]
    fn streamed_component_root_is_byte_identical_to_the_canonical_retained_tree() {
        let topology = test_topology();
        let canonical_bytes = encoded_component(&topology, 7);
        let context = participant_component_context(
            [0x51; Hash512::BYTE_LENGTH],
            SetupPublicPolynomialRootRole::RelinearizationRoundTwo,
            [0x61; Hash512::BYTE_LENGTH],
            2,
            3,
        )
        .expect("test component context");
        let evaluation_domain_size = 16;
        let streamed = recompute_setup_generated_component_public_polynomial_root_from_bytes(
            &topology,
            &canonical_bytes,
            &context,
            evaluation_domain_size,
        )
        .expect("streamed setup root");

        let ordered_trace_rows = (0..topology.trace_column_count().expect("trace count"))
            .map(|column_ordinal| {
                let column = topology.trace_column(column_ordinal).expect("trace column");
                let byte_start = usize::try_from(column.byte_offset()).expect("byte start");
                let byte_end =
                    usize::try_from(column.byte_offset() + column.byte_length()).expect("byte end");
                column
                    .decode_authenticated_bytes(&canonical_bytes[byte_start..byte_end])
                    .expect("canonical trace row")
            })
            .collect::<Vec<_>>();
        let retained_tree = SetupPublicPolynomialTree::construct(SetupPublicPolynomialTreeInput {
            context: &context,
            evaluation_domain_size,
            source_polynomial_degree_bound_exclusive: topology
                .half_polynomial_degree_bound_exclusive()
                .expect("half degree"),
            ordered_trace_rows: &ordered_trace_rows,
        })
        .expect("canonical retained tree");

        assert_eq!(
            streamed.public_polynomial_context_hash(),
            retained_tree.public_polynomial_context_hash()
        );
        assert_eq!(streamed.root(), retained_tree.root());
    }

    #[test]
    fn aggregate_frontier_handles_split_residues_and_rejects_noncanonical_input() {
        let topology = test_topology();
        let one_component = encoded_component(&topology, 1);
        let expected_two_component = encoded_component(&topology, 2);
        let mut construction = accumulator_for_test(topology.clone());
        for chunk in one_component.chunks(3) {
            construction
                .absorb_component_bytes(chunk)
                .expect("first source chunk");
        }
        assert_eq!(
            construction.completed_residue_byte_length,
            one_component.len()
        );
        assert_eq!(
            construction.current_block_index,
            topology.data_block_count()
        );
        construction.completed_residue_byte_length = 0;
        construction.current_block_index = 0;
        construction.current_limb_index = 0;
        construction.current_coefficient_index = 0;
        for chunk in one_component.chunks(5) {
            construction
                .absorb_component_bytes(chunk)
                .expect("second source chunk");
        }
        assert_eq!(
            construction.aggregate_component_bytes[0],
            expected_two_component
        );

        let mut malformed_construction = accumulator_for_test(topology.clone());
        let first_modulus = topology.ordered_moduli()[0];
        let width = canonical_residue_byte_length(first_modulus).expect("width");
        let malformed_residue = &first_modulus.to_le_bytes()[..width];
        assert_eq!(
            malformed_construction.absorb_component_bytes(malformed_residue),
            Err(RefusalReason::MalformedEncoding)
        );
    }
}
