use std::{cell::RefCell, collections::BTreeMap, mem::size_of, rc::Rc, sync::Arc};

use zeroize::{Zeroize, Zeroizing};

use super::generation_relinearization::{
    SetupGeneratedRelinearizationAggregateSourceAuthority, SetupGeneratedRelinearizationMaterial,
    SetupGeneratedRelinearizationRoundOneSourceAuthority,
    SetupGeneratedRelinearizationRoundTwoGeneration,
    SetupGeneratedRelinearizationRoundTwoSourceAuthority,
    SetupGenerationRelinearizationRoundOnePreparationSource,
    SetupRelinearizationRoundTwoConstruction, authenticate_setup_generated_component_material,
    recompute_setup_generated_component_public_polynomial_root,
};

use crate::{
    bgv::parameters::{DATA_PRIMES, POLYNOMIAL_DEGREE},
    bgv::proof_suite::{
        AuthenticatedCompactCommittedMaterialSource, CommittedMaterialContext,
        CommittedMaterialRole, CommittedMaterialSourcePolynomialAdapter, CommittedMaterialTree,
        CommonProofGenerationAuthorization, CommonProofGenerationPreparationError,
        CommonProofGenerationSources, CommonProofPrivateCoinCoordinateCapacity,
        CommonProofProverError, CommonProofRelationPlanCapability, CommonProofRuntimeError,
        CommonProofRuntimeLimits, CompactCommittedMaterialSource,
        ComponentMaterialOwnershipBinding, GaloisKeyShareSourcePolynomialAdapter,
        KeySwitchComponentMaterialTopology, MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH,
        PreparedCommonProofGeneration, PrivateRandomnessCommonProofCoinSource, RelationPlanVariant,
        RelinearizationRoundOneSourcePolynomialAdapter,
        RelinearizationRoundTwoAuthenticatedAggregateSourcePlan,
        RelinearizationRoundTwoSourcePolynomialAdapter, SelectedEvaluatorEntryKind,
        SelectedEvaluatorEntryPosition, SelectedVssShareLinkageStatement,
        SetupKeyRelationSourcePolynomialAdapter, SetupPublicPolynomialContext,
        SetupPublicPolynomialRootBuilder, SetupPublicPolynomialTree,
        VerifiedEvaluatorAuxiliaryRoot, VerifiedKeySwitchComponentMaterial,
        canonical_selected_galois_key_share_statement,
        canonical_selected_public_key_share_statement, canonical_selected_same_secret_statement,
        canonical_selected_vss_share_linkage_statement,
        compile_galois_key_share_relation_with_source_layout,
        compile_public_key_share_relation_with_source_layout,
        compile_relinearization_round_one_relation_with_source_layout,
        compile_relinearization_round_two_relation_with_source_layout,
        compile_same_secret_relation_with_source_layout, compile_vss_share_linkage_relation_plan,
        decode_recipient_private_vss_payload, galois_relation_tree_inputs,
        public_key_share_relation_tree_inputs, relinearization_round_one_relation_tree_inputs,
        relinearization_round_two_relation_tree_inputs, same_secret_relation_tree_inputs,
        selected_committed_material_profile, selected_committed_material_relation_plan_input,
        selected_evaluator_galois_entry_positions, selected_galois_key_share_batch_schedule,
        selected_galois_key_share_relation_plan_input,
        selected_public_key_share_relation_plan_input, selected_relation_plan_check_context,
        selected_relation_plans, selected_relinearization_relation_plan_inputs,
        selected_same_secret_relation_plan_input,
        setup_public_polynomial_wasm_compact_root_memory_plan, verified_application_statement_hash,
    },
    bgv::setup::{
        SETUP_COMMITMENT_HIDING_ERROR_WIDTH, SETUP_COMMITMENT_HIDING_SECRET_WIDTH,
        SETUP_COMMITMENT_MODULE_RANK, SETUP_COMMITMENT_MODULUS_LIMB_INDICES,
        parse_lattice_anchor_commitment_canonical_bytes, sample_galois_common_reference_limb,
        sampling::{DATA_MODULUS_CATALOG_IDENTIFIER, SPECIAL_MODULUS_CATALOG_IDENTIFIER},
        setup_commitment_matrix_ntt_cache_coefficient_payload_byte_length,
    },
    foundation::{
        ActionPrivateRandomness, CanonicalStreamDomain, CanonicalStreamReadbackVerifier,
        FOUNDATION_PROFILE, Hash512, ParticipantIdentity, PersistentProofCoinInput,
        PersistentProofWitnessCoinBinding, PreparedActionProofAttemptSource,
        ProofApplicationSlotCeilings, RefusalReason, Roster, SelectedSuiteCapability,
        StreamDescriptor, WitnessBoundPreparedActionProofAttemptSource,
        bind_prepared_action_proof_attempt_to_canonical_witness,
        derive_canonical_stream_descriptor,
    },
};

use crate::bgv::proof_suite::{RelationPlanCheckContext, RelationProofTreeInput};

const MAXIMUM_RETAINED_SETUP_GENERATION_AUTHORITY_COUNT: usize = 16;
const MAXIMUM_RETAINED_SETUP_GENERATION_PUBLIC_KEY_SHARE_SOURCE_COUNT: usize =
    MAXIMUM_RETAINED_SETUP_GENERATION_AUTHORITY_COUNT;
const MAXIMUM_RETAINED_SETUP_GENERATION_RECIPIENT_PAYLOAD_SOURCE_COUNT: usize =
    MAXIMUM_RETAINED_SETUP_GENERATION_AUTHORITY_COUNT
        * FOUNDATION_PROFILE.participant_count as usize;
const PUBLIC_KEY_SHARE_COEFFICIENT_BYTE_LENGTH: usize = size_of::<u64>();
pub(crate) const SELECTED_SETUP_GENERATION_PUBLIC_KEY_SHARE_BODY_BYTE_LENGTH: u64 =
    DATA_PRIMES.len() as u64
        * POLYNOMIAL_DEGREE as u64
        * PUBLIC_KEY_SHARE_COEFFICIENT_BYTE_LENGTH as u64;
const GALOIS_KEY_SHARE_CANONICAL_SEMANTIC_WITNESS_DOMAIN: &[u8] =
    b"sealed-lattice/galois-key-share/canonical-semantic-witness/v1";
const RELINEARIZATION_ROUND_ONE_CANONICAL_SEMANTIC_WITNESS_DOMAIN: &[u8] =
    b"sealed-lattice/relinearization-round-one/canonical-semantic-witness/v1";
const RELINEARIZATION_ROUND_TWO_CANONICAL_SEMANTIC_WITNESS_DOMAIN: &[u8] =
    b"sealed-lattice/relinearization-round-two/canonical-semantic-witness/v1";
const SAME_SECRET_CANONICAL_SEMANTIC_WITNESS_DOMAIN: &[u8] =
    b"sealed-lattice/same-secret/canonical-semantic-witness/v1";
const PUBLIC_KEY_SHARE_CANONICAL_SEMANTIC_WITNESS_DOMAIN: &[u8] =
    b"sealed-lattice/public-key-share/canonical-semantic-witness/v1";

/// Opaque browser-owned setup-generation capability. It is deliberately not
/// cloneable or serializable; JavaScript can retain only the numeric handle
/// returned by the worker command that creates it.
pub(crate) struct SetupGenerationAuthorityHandle(u32);

impl SetupGenerationAuthorityHandle {
    pub(crate) const fn from_identifier(identifier: u32) -> Self {
        Self(identifier)
    }

    pub(crate) const fn identifier(&self) -> u32 {
        self.0
    }
}

/// Nonserialized live-set accounting for the mutually exclusive setup
/// authority lifetimes. Shared VSS sources are split from their wrappers so a
/// prepared proof adapter can borrow the same Arc allocations without making
/// a second resident-memory owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SetupGenerationRetainedMemoryAccounting {
    all_family_payload_byte_length: u64,
    post_release_payload_byte_length: u64,
    vss_proof_phase_is_active: bool,
}

impl SetupGenerationRetainedMemoryAccounting {
    pub(crate) const fn all_family_payload_byte_length(self) -> u64 {
        self.all_family_payload_byte_length
    }

    pub(crate) const fn vss_proof_phase_is_active(self) -> bool {
        self.vss_proof_phase_is_active
    }

    pub(crate) const fn active_payload_byte_length(self) -> u64 {
        if self.vss_proof_phase_is_active {
            self.post_release_payload_byte_length
        } else {
            self.all_family_payload_byte_length
        }
    }
}

/// Exact live overlap for streamed relinearization round-two activation. The
/// aggregate source rows are released before root reconstruction, so the
/// ingestion and root phases are accounted independently instead of summing
/// mutually exclusive allocations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SetupGenerationRelinearizationRoundTwoActivationMemoryAccounting {
    maximum_overlap_byte_length: u64,
}

impl SetupGenerationRelinearizationRoundTwoActivationMemoryAccounting {
    fn from_live_phase_payloads(
        retained_authority_payload_byte_length: u64,
        activation_binding_payload_byte_length: u64,
        setup_matrix_cache_payload_byte_length: u64,
        pre_root_construction_payload_byte_length: u64,
        generation_workspace_payload_peak_byte_length: u64,
        root_overlap_construction_payload_byte_length: u64,
        streamed_root_transient_payload_byte_length: u64,
    ) -> Result<Self, RefusalReason> {
        let common_payload_byte_length = retained_authority_payload_byte_length
            .checked_add(activation_binding_payload_byte_length)
            .ok_or(RefusalReason::OutsideSupportedProfile)?
            .checked_add(setup_matrix_cache_payload_byte_length)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        let ingestion_peak_byte_length = common_payload_byte_length
            .checked_add(pre_root_construction_payload_byte_length)
            .and_then(|length| length.checked_add(generation_workspace_payload_peak_byte_length))
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        let root_reconstruction_peak_byte_length = common_payload_byte_length
            .checked_add(root_overlap_construction_payload_byte_length)
            .and_then(|length| length.checked_add(streamed_root_transient_payload_byte_length))
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        Ok(Self {
            maximum_overlap_byte_length: ingestion_peak_byte_length
                .max(root_reconstruction_peak_byte_length),
        })
    }

    pub(crate) const fn fits_absolute_wasm_resident_bound(self) -> bool {
        self.maximum_overlap_byte_length <= MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SetupKeyRelationProofFamily {
    SameSecret,
    PublicKeyShare,
}

impl SetupKeyRelationProofFamily {
    pub(crate) const fn statement_schema_identifier(self) -> u16 {
        match self {
            Self::SameSecret => {
                ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER
            }
            Self::PublicKeyShare => {
                ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER
            }
        }
    }
}

pub(crate) struct SetupGenerationRecipientPayloadSourceHandle(u32);

impl SetupGenerationRecipientPayloadSourceHandle {
    pub(crate) const fn from_identifier(identifier: u32) -> Self {
        Self(identifier)
    }

    pub(crate) const fn identifier(&self) -> u32 {
        self.0
    }
}

pub(crate) struct SetupGenerationPublicKeyShareSourceHandle(u32);

impl SetupGenerationPublicKeyShareSourceHandle {
    pub(crate) const fn from_identifier(identifier: u32) -> Self {
        Self(identifier)
    }

    pub(crate) const fn identifier(&self) -> u32 {
        self.0
    }
}

/// Canonical compact bytes for one D-block key-switch B component. The bytes
/// are public output, while their descriptor and topology remain adjacent so
/// a family adapter cannot substitute a different stream shape.
pub(crate) struct SetupGeneratedKeySwitchComponent {
    evaluator_position: SelectedEvaluatorEntryPosition,
    topology: KeySwitchComponentMaterialTopology,
    stream_descriptor: StreamDescriptor,
    canonical_bytes: Box<[u8]>,
}

impl SetupGeneratedKeySwitchComponent {
    pub(crate) fn from_canonical_bytes(
        evaluator_position: SelectedEvaluatorEntryPosition,
        topology: KeySwitchComponentMaterialTopology,
        canonical_bytes: Vec<u8>,
    ) -> Result<Self, RefusalReason> {
        if u64::try_from(canonical_bytes.len()).ok() != Some(topology.expected_byte_length()) {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        let stream_descriptor = derive_canonical_stream_descriptor(
            CanonicalStreamDomain::EvaluatorKeyStore,
            &canonical_bytes,
        )?;
        Ok(Self {
            evaluator_position,
            topology,
            stream_descriptor,
            canonical_bytes: canonical_bytes.into_boxed_slice(),
        })
    }

    /// Installs bytes whose length, descriptor and public-polynomial source
    /// were already recomputed successfully by the streamed setup generator.
    /// Keeping this final move infallible preserves activation phase atomicity
    /// without cloning the complete component.
    pub(crate) fn from_authenticated_canonical_bytes(
        evaluator_position: SelectedEvaluatorEntryPosition,
        topology: KeySwitchComponentMaterialTopology,
        stream_descriptor: StreamDescriptor,
        canonical_bytes: Vec<u8>,
    ) -> Self {
        debug_assert_eq!(
            u64::try_from(canonical_bytes.len()).ok(),
            Some(topology.expected_byte_length())
        );
        debug_assert_eq!(
            u64::try_from(canonical_bytes.len()).ok(),
            Some(stream_descriptor.total_byte_length)
        );
        Self {
            evaluator_position,
            topology,
            stream_descriptor,
            canonical_bytes: canonical_bytes.into_boxed_slice(),
        }
    }

    pub(crate) const fn evaluator_position(&self) -> SelectedEvaluatorEntryPosition {
        self.evaluator_position
    }

    pub(crate) const fn topology(&self) -> &KeySwitchComponentMaterialTopology {
        &self.topology
    }

    pub(crate) const fn stream_descriptor(&self) -> &StreamDescriptor {
        &self.stream_descriptor
    }

    pub(crate) fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
}

/// One exact generated Galois B component retained only as input to the
/// suite-fixed evaluator aggregate prover. This is generation authority, not
/// verification authority: accepted setup can obtain the corresponding
/// source only by positively verifying the package-bound `0x1217` proof.
pub(crate) struct SetupGeneratedGaloisSourceComponent {
    evaluator_position: SelectedEvaluatorEntryPosition,
    material: VerifiedKeySwitchComponentMaterial,
    contribution_root: [u8; Hash512::BYTE_LENGTH],
    public_polynomial_context_hash: [u8; Hash512::BYTE_LENGTH],
}

impl SetupGeneratedGaloisSourceComponent {
    pub(crate) const fn evaluator_position(&self) -> SelectedEvaluatorEntryPosition {
        self.evaluator_position
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

/// Non-cloneable, generation-only authority for one participant's exact
/// suite-fixed Galois source batch. It is consumed by `0x1218` proving and is
/// never admitted to the verified evaluator-source catalog.
pub(crate) struct SetupGeneratedGaloisSourceAuthority {
    protocol_version: u16,
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
    action_context_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    roster_position: u16,
    batch_schedule_position: u32,
    anchor_commitment_roots: [[u8; Hash512::BYTE_LENGTH]; 3],
    canonical_application_statement_bytes: Box<[u8]>,
    ordered_auxiliary_roots: Box<[VerifiedEvaluatorAuxiliaryRoot]>,
    ordered_components: Box<[SetupGeneratedGaloisSourceComponent]>,
}

impl SetupGeneratedGaloisSourceAuthority {
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

    pub(crate) const fn batch_schedule_position(&self) -> u32 {
        self.batch_schedule_position
    }

    pub(crate) const fn anchor_commitment_roots(&self) -> [[u8; Hash512::BYTE_LENGTH]; 3] {
        self.anchor_commitment_roots
    }

    pub(crate) fn canonical_application_statement_bytes(&self) -> &[u8] {
        &self.canonical_application_statement_bytes
    }

    pub(crate) fn ordered_auxiliary_roots(&self) -> &[VerifiedEvaluatorAuxiliaryRoot] {
        &self.ordered_auxiliary_roots
    }

    pub(crate) fn ordered_components(&self) -> &[SetupGeneratedGaloisSourceComponent] {
        &self.ordered_components
    }
}

/// One Galois relation witness entry. Error polynomials are retained by data
/// block because the same centered integer must be represented in every
/// extended Q/P limb of that block.
pub(crate) struct SetupGeneratedGaloisEntry {
    component: SetupGeneratedKeySwitchComponent,
    centered_error_polynomials_by_block: Box<[Zeroizing<Vec<i8>>]>,
}

/// One reset-stable public-key share generated from the authority-owned
/// common secret and one eta-two error polynomial. The tree root is recomputed
/// from these exact coefficients; no separately supplied root is retained.
pub(crate) struct SetupGeneratedPublicKeyShare {
    public_polynomial_context_hash: [u8; Hash512::BYTE_LENGTH],
    root: [u8; Hash512::BYTE_LENGTH],
    ordered_data_modulus_indices: Box<[u16]>,
    ordered_limb_coefficients: Box<[Zeroizing<Vec<u64>>]>,
    centered_error_coefficients: Zeroizing<Vec<i8>>,
}

impl SetupGeneratedPublicKeyShare {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_browser_owned_witness(
        setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
        participant_identity: [u8; Hash512::BYTE_LENGTH],
        roster_position: u16,
        evaluation_domain_size: usize,
        ring_degree: usize,
        ordered_data_modulus_indices: Vec<u16>,
        ordered_limb_coefficients: Vec<Zeroizing<Vec<u64>>>,
        centered_error_coefficients: Zeroizing<Vec<i8>>,
    ) -> Result<Self, RefusalReason> {
        if ring_degree == 0
            || !ring_degree.is_power_of_two()
            || ordered_data_modulus_indices.is_empty()
            || ordered_data_modulus_indices.len() != ordered_limb_coefficients.len()
            || centered_error_coefficients.len() != ring_degree
            || centered_error_coefficients
                .iter()
                .any(|coefficient| !(-2..=2).contains(coefficient))
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        let context = SetupPublicPolynomialContext::public_key_share(
            setup_proof_context_hash,
            participant_identity,
            roster_position,
        )
        .map_err(|_| RefusalReason::WrongContext)?;
        let trace_half_degree = ring_degree
            .checked_div(2)
            .filter(|half_degree| *half_degree > 0 && *half_degree * 2 == ring_degree)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        for (data_modulus_index, coefficients) in ordered_data_modulus_indices
            .iter()
            .copied()
            .zip(&ordered_limb_coefficients)
        {
            let modulus = *crate::bgv::parameters::DATA_PRIMES
                .get(usize::from(data_modulus_index))
                .ok_or(RefusalReason::UnsupportedVersionOrSuite)?;
            if coefficients.len() != ring_degree
                || coefficients
                    .iter()
                    .any(|coefficient| *coefficient >= modulus)
            {
                return Err(RefusalReason::WrongTypeOrLength);
            }
        }
        let row_width = ordered_limb_coefficients
            .len()
            .checked_mul(2)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        let ordered_trace_rows = ordered_limb_coefficients
            .iter()
            .flat_map(|coefficients| coefficients.chunks_exact(trace_half_degree));
        let (public_polynomial_context_hash, root) =
            SetupPublicPolynomialTree::construct_root_from_canonical_trace_rows(
                &context,
                evaluation_domain_size,
                trace_half_degree,
                row_width,
                ordered_trace_rows,
            )
            .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
        Ok(Self {
            public_polynomial_context_hash,
            root,
            ordered_data_modulus_indices: ordered_data_modulus_indices.into_boxed_slice(),
            ordered_limb_coefficients: ordered_limb_coefficients.into_boxed_slice(),
            centered_error_coefficients,
        })
    }

    pub(crate) const fn public_polynomial_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.public_polynomial_context_hash
    }

    pub(crate) const fn root(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.root
    }

    pub(crate) fn ordered_data_modulus_indices(&self) -> &[u16] {
        &self.ordered_data_modulus_indices
    }

    pub(crate) fn ordered_limb_coefficients(&self) -> &[Zeroizing<Vec<u64>>] {
        &self.ordered_limb_coefficients
    }

    pub(crate) fn centered_error_coefficients(&self) -> &[i8] {
        &self.centered_error_coefficients
    }

    fn body_byte_length(&self) -> Result<usize, RefusalReason> {
        self.ordered_limb_coefficients
            .iter()
            .try_fold(0_usize, |byte_length, coefficients| {
                coefficients
                    .len()
                    .checked_mul(PUBLIC_KEY_SHARE_COEFFICIENT_BYTE_LENGTH)
                    .and_then(|limb_byte_length| byte_length.checked_add(limb_byte_length))
                    .ok_or(RefusalReason::OutsideSupportedProfile)
            })
    }

    fn selected_body_byte_length(&self) -> Result<usize, RefusalReason> {
        if self.ordered_data_modulus_indices.len() != DATA_PRIMES.len()
            || self
                .ordered_data_modulus_indices
                .iter()
                .copied()
                .enumerate()
                .any(|(expected_index, data_modulus_index)| {
                    usize::from(data_modulus_index) != expected_index
                })
            || self
                .ordered_limb_coefficients
                .iter()
                .any(|coefficients| coefficients.len() != POLYNOMIAL_DEGREE)
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        let body_byte_length = self.body_byte_length()?;
        if u64::try_from(body_byte_length).ok()
            != Some(SELECTED_SETUP_GENERATION_PUBLIC_KEY_SHARE_BODY_BYTE_LENGTH)
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        Ok(body_byte_length)
    }

    fn write_body_range(
        &self,
        expected_offset: usize,
        output: &mut [u8],
    ) -> Result<bool, RefusalReason> {
        if output.is_empty() {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        let body_byte_length = self.body_byte_length()?;
        let range_end = expected_offset
            .checked_add(output.len())
            .filter(|range_end| *range_end <= body_byte_length)
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        let ring_degree = self
            .ordered_limb_coefficients
            .first()
            .map(|coefficients| coefficients.len())
            .filter(|ring_degree| *ring_degree > 0)
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        if self
            .ordered_limb_coefficients
            .iter()
            .any(|coefficients| coefficients.len() != ring_degree)
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }

        let mut body_offset = expected_offset;
        let mut output_offset = 0_usize;
        while output_offset < output.len() {
            let coefficient_ordinal = body_offset / PUBLIC_KEY_SHARE_COEFFICIENT_BYTE_LENGTH;
            let coefficient_byte_offset = body_offset % PUBLIC_KEY_SHARE_COEFFICIENT_BYTE_LENGTH;
            let limb_ordinal = coefficient_ordinal / ring_degree;
            let coefficient_index = coefficient_ordinal % ring_degree;
            let coefficient_bytes = self
                .ordered_limb_coefficients
                .get(limb_ordinal)
                .and_then(|coefficients| coefficients.get(coefficient_index))
                .ok_or(RefusalReason::WrongTypeOrLength)?
                .to_le_bytes();
            let copied_byte_length = (PUBLIC_KEY_SHARE_COEFFICIENT_BYTE_LENGTH
                - coefficient_byte_offset)
                .min(output.len() - output_offset);
            output[output_offset..output_offset + copied_byte_length].copy_from_slice(
                &coefficient_bytes
                    [coefficient_byte_offset..coefficient_byte_offset + copied_byte_length],
            );
            output_offset += copied_byte_length;
            body_offset += copied_byte_length;
        }
        Ok(range_end == body_byte_length)
    }
}

/// One exact lattice-anchor authentication root and its browser-owned
/// reset-safe opening.
/// Canonical commitment bytes are retained beside the recomputed root; trace
/// rows are decoded only when a relation column requests them. Neither a
/// transported root nor detached opening polynomials can construct this
/// source.
pub(crate) struct SetupGenerationAnchorOpening {
    commitment_data_prime_index: u16,
    canonical_commitment_bytes: Box<[u8]>,
    public_polynomial_context_hash: [u8; Hash512::BYTE_LENGTH],
    root: [u8; Hash512::BYTE_LENGTH],
    source_polynomial_degree_bound_exclusive: usize,
    hiding_secret_polynomials: Box<[Zeroizing<Vec<i8>>]>,
    hiding_error_polynomials: Box<[Zeroizing<Vec<i8>>]>,
}

impl SetupGenerationAnchorOpening {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_browser_owned_witness(
        setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
        participant_identity: [u8; Hash512::BYTE_LENGTH],
        roster_position: u16,
        commitment_data_prime_index: u16,
        evaluation_domain_size: usize,
        canonical_commitment_bytes: Vec<u8>,
        hiding_secret_polynomials: Vec<Zeroizing<Vec<i8>>>,
        hiding_error_polynomials: Vec<Zeroizing<Vec<i8>>>,
    ) -> Result<Self, RefusalReason> {
        let context = SetupPublicPolynomialContext::lattice_anchor(
            setup_proof_context_hash,
            participant_identity,
            roster_position,
            commitment_data_prime_index,
        )
        .map_err(|_| RefusalReason::WrongContext)?;
        let (
            public_polynomial_context_hash,
            root,
            source_polynomial_degree_bound_exclusive,
            row_width,
        ) = SetupPublicPolynomialTree::construct_lattice_anchor_root_from_canonical_bytes(
            &context,
            evaluation_domain_size,
            &canonical_commitment_bytes,
        )
        .map_err(|_| RefusalReason::MalformedEncoding)?;
        let ring_degree = source_polynomial_degree_bound_exclusive
            .checked_mul(2)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        if usize::try_from(row_width).ok() != Some((SETUP_COMMITMENT_MODULE_RANK + 1) * 2)
            || hiding_secret_polynomials.len() != SETUP_COMMITMENT_HIDING_SECRET_WIDTH
            || hiding_error_polynomials.len() != SETUP_COMMITMENT_HIDING_ERROR_WIDTH
            || hiding_secret_polynomials.iter().any(|polynomial| {
                polynomial.len() != ring_degree
                    || polynomial
                        .iter()
                        .any(|coefficient| !(-1..=1).contains(coefficient))
            })
            || hiding_error_polynomials.iter().any(|polynomial| {
                polynomial.len() != ring_degree
                    || polynomial
                        .iter()
                        .any(|coefficient| !(-1..=1).contains(coefficient))
            })
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        Ok(Self {
            commitment_data_prime_index,
            canonical_commitment_bytes: canonical_commitment_bytes.into_boxed_slice(),
            public_polynomial_context_hash,
            root,
            source_polynomial_degree_bound_exclusive,
            hiding_secret_polynomials: hiding_secret_polynomials.into_boxed_slice(),
            hiding_error_polynomials: hiding_error_polynomials.into_boxed_slice(),
        })
    }

    pub(crate) const fn commitment_data_prime_index(&self) -> u16 {
        self.commitment_data_prime_index
    }

    pub(crate) fn canonical_commitment_bytes(&self) -> &[u8] {
        &self.canonical_commitment_bytes
    }

    pub(crate) const fn public_polynomial_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.public_polynomial_context_hash
    }

    pub(crate) const fn root(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.root
    }

    pub(crate) const fn source_polynomial_degree_bound_exclusive(&self) -> usize {
        self.source_polynomial_degree_bound_exclusive
    }

    pub(crate) fn commitment_trace_row_half(
        &self,
        row_ordinal: usize,
        half_ordinal: usize,
    ) -> Result<Zeroizing<Vec<i128>>, RefusalReason> {
        let commitment =
            parse_lattice_anchor_commitment_canonical_bytes(&self.canonical_commitment_bytes)
                .map_err(|_| RefusalReason::MalformedEncoding)?;
        let logical_row = commitment
            .rows
            .get(row_ordinal)
            .filter(|row| row.len() == commitment.ring_degree)
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        let coefficient_start = half_ordinal
            .checked_mul(self.source_polynomial_degree_bound_exclusive)
            .filter(|start| half_ordinal < 2 && *start < logical_row.len())
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        let coefficient_end = coefficient_start
            .checked_add(self.source_polynomial_degree_bound_exclusive)
            .filter(|end| *end <= logical_row.len())
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        Ok(Zeroizing::new(
            logical_row[coefficient_start..coefficient_end]
                .iter()
                .copied()
                .map(i128::from)
                .collect(),
        ))
    }

    pub(crate) fn commitment_row(&self, row_ordinal: usize) -> Result<Vec<i128>, RefusalReason> {
        let commitment =
            parse_lattice_anchor_commitment_canonical_bytes(&self.canonical_commitment_bytes)
                .map_err(|_| RefusalReason::MalformedEncoding)?;
        commitment
            .rows
            .get(row_ordinal)
            .filter(|row| row.len() == commitment.ring_degree)
            .map(|row| row.iter().copied().map(i128::from).collect())
            .ok_or(RefusalReason::WrongTypeOrLength)
    }

    pub(crate) fn hiding_secret_polynomials(&self) -> &[Zeroizing<Vec<i8>>] {
        &self.hiding_secret_polynomials
    }

    pub(crate) fn hiding_error_polynomials(&self) -> &[Zeroizing<Vec<i8>>] {
        &self.hiding_error_polynomials
    }
}

/// One compact committed-material source joined to the exact canonical
/// coefficients that authenticated its root. Trace rows are derived only for
/// the currently requested proof column and are never retained as a catalog.
pub(crate) struct SetupGeneratedCommittedMaterial {
    authenticated_source: AuthenticatedCompactCommittedMaterialSource,
}

impl SetupGeneratedCommittedMaterial {
    pub(crate) fn from_recomputed_tree_and_canonical_message(
        tree: CommittedMaterialTree,
        canonical_message: Zeroizing<Box<[u64]>>,
        canonical_modulus: u64,
    ) -> Result<Self, RefusalReason> {
        Ok(Self {
            authenticated_source:
                AuthenticatedCompactCommittedMaterialSource::from_recomputed_tree_and_canonical_message(
                    tree,
                    canonical_message,
                    canonical_modulus,
                )
                .map_err(|_| RefusalReason::WrongHashOrRoot)?,
        })
    }

    pub(crate) fn compact_source(&self) -> &CompactCommittedMaterialSource {
        self.authenticated_source.compact_source()
    }

    pub(crate) fn owned_authenticated_source(&self) -> AuthenticatedCompactCommittedMaterialSource {
        self.authenticated_source.clone()
    }
}

pub(crate) struct SetupGeneratedRecipientPrivateVssPayload {
    recipient_roster_position: u16,
    canonical_bytes: Zeroizing<Vec<u8>>,
}

impl SetupGeneratedRecipientPrivateVssPayload {
    pub(crate) fn from_canonical_bytes(
        recipient_roster_position: u16,
        canonical_bytes: Zeroizing<Vec<u8>>,
    ) -> Result<Self, RefusalReason> {
        let decoded = decode_recipient_private_vss_payload(&canonical_bytes)
            .map_err(|_| RefusalReason::MalformedEncoding)?;
        if decoded.recipient_roster_position() != recipient_roster_position {
            return Err(RefusalReason::WrongContext);
        }
        Ok(Self {
            recipient_roster_position,
            canonical_bytes,
        })
    }
}

pub(crate) struct SetupGeneratedVssMaterial {
    ordered_coefficient_materials: Box<[SetupGeneratedCommittedMaterial]>,
    ordered_recipient_share_materials: Box<[SetupGeneratedCommittedMaterial]>,
    recipient_private_payloads: Box<[Option<SetupGeneratedRecipientPrivateVssPayload>]>,
}

impl SetupGeneratedVssMaterial {
    pub(crate) fn from_browser_owned_material(
        ordered_coefficient_materials: Vec<SetupGeneratedCommittedMaterial>,
        ordered_recipient_share_materials: Vec<SetupGeneratedCommittedMaterial>,
        recipient_private_payloads: Vec<SetupGeneratedRecipientPrivateVssPayload>,
    ) -> Result<Self, RefusalReason> {
        let first_profile = ordered_coefficient_materials
            .first()
            .map(|material| material.compact_source().profile())
            .ok_or(RefusalReason::MissingPrerequisite)?;
        let selected_relation_input = selected_committed_material_relation_plan_input()
            .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)?;
        let expected_coefficient_material_count = selected_relation_input
            .sharing_data_modulus_indices
            .len()
            .checked_mul(usize::from(FOUNDATION_PROFILE.reconstruction_threshold))
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        let expected_recipient_share_material_count = selected_relation_input
            .sharing_data_modulus_indices
            .len()
            .checked_mul(usize::from(FOUNDATION_PROFILE.participant_count))
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        if ordered_coefficient_materials.len() != expected_coefficient_material_count
            || ordered_recipient_share_materials.len() != expected_recipient_share_material_count
            || recipient_private_payloads.len() != usize::from(FOUNDATION_PROFILE.participant_count)
            || recipient_private_payloads.iter().enumerate().any(
                |(recipient_roster_position, payload)| {
                    usize::from(payload.recipient_roster_position) != recipient_roster_position
                },
            )
            || ordered_coefficient_materials
                .iter()
                .chain(&ordered_recipient_share_materials)
                .any(|material| material.compact_source().profile() != first_profile)
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        Ok(Self {
            ordered_coefficient_materials: ordered_coefficient_materials.into_boxed_slice(),
            ordered_recipient_share_materials: ordered_recipient_share_materials.into_boxed_slice(),
            recipient_private_payloads: recipient_private_payloads
                .into_iter()
                .map(Some)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        })
    }

    pub(crate) fn ordered_coefficient_materials(&self) -> &[SetupGeneratedCommittedMaterial] {
        &self.ordered_coefficient_materials
    }

    pub(crate) fn ordered_recipient_share_materials(&self) -> &[SetupGeneratedCommittedMaterial] {
        &self.ordered_recipient_share_materials
    }

    fn recipient_private_payload_byte_length(
        &self,
        recipient_roster_position: u16,
    ) -> Result<u64, RefusalReason> {
        let payload = self
            .recipient_private_payloads
            .get(usize::from(recipient_roster_position))
            .and_then(Option::as_ref)
            .ok_or(RefusalReason::ConsumedState)?;
        u64::try_from(payload.canonical_bytes.len())
            .map_err(|_| RefusalReason::OutsideSupportedProfile)
    }

    fn take_recipient_private_payload(
        &mut self,
        recipient_roster_position: u16,
    ) -> Result<SetupGeneratedRecipientPrivateVssPayload, RefusalReason> {
        self.recipient_private_payloads
            .get_mut(usize::from(recipient_roster_position))
            .ok_or(RefusalReason::WrongTypeOrLength)?
            .take()
            .ok_or(RefusalReason::ConsumedState)
    }

    fn private_payloads_are_all_moved_out(&self) -> bool {
        self.recipient_private_payloads.iter().all(Option::is_none)
    }

    fn into_proof_materials(
        self,
    ) -> (
        Box<[SetupGeneratedCommittedMaterial]>,
        Box<[SetupGeneratedCommittedMaterial]>,
    ) {
        debug_assert!(self.private_payloads_are_all_moved_out());
        (
            self.ordered_coefficient_materials,
            self.ordered_recipient_share_materials,
        )
    }
}

impl SetupGeneratedGaloisEntry {
    pub(crate) fn from_browser_owned_witness(
        component: SetupGeneratedKeySwitchComponent,
        centered_error_polynomials_by_block: Vec<Zeroizing<Vec<i8>>>,
    ) -> Result<Self, RefusalReason> {
        if !matches!(
            component.evaluator_position().key_kind(),
            SelectedEvaluatorEntryKind::Galois { .. }
        ) || centered_error_polynomials_by_block.len() != component.topology().data_block_count()
            || centered_error_polynomials_by_block
                .iter()
                .any(|polynomial| {
                    polynomial.len() != component.topology().polynomial_degree()
                        || polynomial
                            .iter()
                            .any(|coefficient| !(-2..=2).contains(coefficient))
                })
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        Ok(Self {
            component,
            centered_error_polynomials_by_block: centered_error_polynomials_by_block
                .into_boxed_slice(),
        })
    }

    pub(crate) const fn component(&self) -> &SetupGeneratedKeySwitchComponent {
        &self.component
    }

    pub(crate) fn centered_error_polynomials_by_block(&self) -> &[Zeroizing<Vec<i8>>] {
        &self.centered_error_polynomials_by_block
    }
}

/// Inputs retained only inside the browser worker after the action-randomness
/// reservation and setup source have been authenticated. The constructor is
/// crate-private and accepts typed values rather than a transport encoding.
pub(crate) struct SetupGenerationAuthorityInput {
    pub(crate) suite_identifier: [u8; Hash512::BYTE_LENGTH],
    pub(crate) manifest_hash: [u8; Hash512::BYTE_LENGTH],
    pub(crate) ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
    pub(crate) action_context_hash: [u8; Hash512::BYTE_LENGTH],
    pub(crate) roster_hash: [u8; Hash512::BYTE_LENGTH],
    pub(crate) ordered_roster: Box<[[u8; Hash512::BYTE_LENGTH]]>,
    pub(crate) setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    pub(crate) source_setup_intent_object_hash: [u8; Hash512::BYTE_LENGTH],
    pub(crate) participant_identity: [u8; Hash512::BYTE_LENGTH],
    pub(crate) roster_position: u16,
    pub(crate) setup_attempt_identifier: [u8; 32],
    pub(crate) action_randomness_authorization_hash: [u8; Hash512::BYTE_LENGTH],
    pub(crate) action_private_randomness: Rc<ActionPrivateRandomness>,
    pub(crate) public_setup_seed: [u8; Hash512::BYTE_LENGTH],
    pub(crate) anchor_commitment_roots: [[u8; Hash512::BYTE_LENGTH]; 3],
    pub(crate) anchor_openings: Vec<SetupGenerationAnchorOpening>,
    pub(crate) common_secret_coefficients: Zeroizing<Vec<i8>>,
    pub(crate) public_key_share: SetupGeneratedPublicKeyShare,
    pub(crate) vss_material: SetupGeneratedVssMaterial,
    pub(crate) relinearization_material: SetupGeneratedRelinearizationMaterial,
    pub(crate) galois_batch_schedule_position: u32,
    pub(crate) ordered_galois_entries: Vec<SetupGeneratedGaloisEntry>,
}

struct PinnedProofAttempt {
    attempt_identifier: [u8; 32],
    application_slot_hash: [u8; Hash512::BYTE_LENGTH],
    application_statement_hash: [u8; Hash512::BYTE_LENGTH],
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SetupGenerationVssPublicRecordBinding {
    ordered_recipient_envelope_hashes: Box<[Hash512]>,
    share_linkage_proof: StreamDescriptor,
}

impl SetupGenerationVssPublicRecordBinding {
    fn pin_exact(
        retained_binding: &mut Option<Self>,
        ordered_recipient_envelope_hashes: &[Hash512],
        share_linkage_proof: &StreamDescriptor,
    ) -> Result<(), RefusalReason> {
        let candidate_binding = Self {
            ordered_recipient_envelope_hashes: ordered_recipient_envelope_hashes.into(),
            share_linkage_proof: share_linkage_proof.clone(),
        };
        if let Some(existing_binding) = retained_binding {
            if existing_binding != &candidate_binding {
                return Err(RefusalReason::ConsumedState);
            }
        } else {
            *retained_binding = Some(candidate_binding);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SetupGenerationVssSourceAllocationAccounting {
    canonical_coefficient_byte_length: u64,
    compact_source_byte_length: u64,
    shared_source_byte_length: u64,
    allocation_wrapper_byte_length: u64,
}

fn retained_stream_descriptor_digest_allocation_byte_length(
    ordered_chunk_count: u64,
) -> Result<u64, RefusalReason> {
    let arc_header_byte_length = size_of::<usize>()
        .checked_mul(2)
        .and_then(|length| u64::try_from(length).ok())
        .ok_or(RefusalReason::OutsideSupportedProfile)?;
    ordered_chunk_count
        .checked_mul(Hash512::BYTE_LENGTH as u64)
        .and_then(|length| length.checked_add(arc_header_byte_length))
        .ok_or(RefusalReason::OutsideSupportedProfile)
}

#[derive(Default)]
struct SetupGenerationDescriptorAllocationAccumulator {
    byte_length: u64,
    descriptor_digest_owner_byte_lengths: BTreeMap<usize, u64>,
}

impl SetupGenerationDescriptorAllocationAccumulator {
    fn add_usize_byte_length(&mut self, byte_length: usize) -> Result<(), RefusalReason> {
        self.byte_length = self
            .byte_length
            .checked_add(
                u64::try_from(byte_length).map_err(|_| RefusalReason::OutsideSupportedProfile)?,
            )
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        Ok(())
    }

    fn add_stream_descriptor(
        &mut self,
        descriptor: &StreamDescriptor,
    ) -> Result<(), RefusalReason> {
        let owner_identifier =
            Arc::as_ptr(&descriptor.ordered_chunk_digests) as *const Hash512 as usize;
        let digest_payload_byte_length = descriptor
            .ordered_chunk_digests
            .len()
            .checked_mul(size_of::<Hash512>())
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        let digest_payload_byte_length = u64::try_from(digest_payload_byte_length)
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        if let Some(retained_byte_length) = self
            .descriptor_digest_owner_byte_lengths
            .get(&owner_identifier)
        {
            if *retained_byte_length != digest_payload_byte_length {
                return Err(RefusalReason::WrongTypeOrLength);
            }
            return Ok(());
        }
        self.descriptor_digest_owner_byte_lengths
            .insert(owner_identifier, digest_payload_byte_length);
        self.byte_length = self
            .byte_length
            .checked_add(retained_stream_descriptor_digest_allocation_byte_length(
                u64::try_from(descriptor.ordered_chunk_digests.len())
                    .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
            )?)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        Ok(())
    }

    fn add_topology(
        &mut self,
        topology: &KeySwitchComponentMaterialTopology,
    ) -> Result<(), RefusalReason> {
        self.add_usize_byte_length(
            topology
                .retained_heap_payload_byte_length()
                .ok_or(RefusalReason::OutsideSupportedProfile)?,
        )
    }
}

fn setup_generation_vss_source_allocation_accounting<'material>(
    materials: impl Iterator<Item = &'material SetupGeneratedCommittedMaterial>,
) -> Result<SetupGenerationVssSourceAllocationAccounting, RefusalReason> {
    let mut compact_source_owner_byte_lengths = BTreeMap::<usize, u64>::new();
    let mut canonical_message_owner_byte_lengths = BTreeMap::<usize, u64>::new();
    for material in materials {
        let authenticated_source = &material.authenticated_source;
        let (compact_source_owner, canonical_message_owner) =
            authenticated_source.shared_allocation_owner_identifiers();
        let compact_source_byte_length =
            u64::try_from(authenticated_source.compact_source().retained_byte_length())
                .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        let canonical_message_byte_length =
            u64::try_from(authenticated_source.retained_canonical_coefficient_byte_length())
                .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        for (owners, owner_identifier, byte_length) in [
            (
                &mut compact_source_owner_byte_lengths,
                compact_source_owner,
                compact_source_byte_length,
            ),
            (
                &mut canonical_message_owner_byte_lengths,
                canonical_message_owner,
                canonical_message_byte_length,
            ),
        ] {
            if let Some(retained_byte_length) = owners.get(&owner_identifier) {
                if *retained_byte_length != byte_length {
                    return Err(RefusalReason::WrongTypeOrLength);
                }
            } else {
                owners.insert(owner_identifier, byte_length);
            }
        }
    }
    let compact_source_byte_length =
        compact_source_owner_byte_lengths
            .values()
            .try_fold(0_u64, |total, byte_length| {
                total
                    .checked_add(*byte_length)
                    .ok_or(RefusalReason::OutsideSupportedProfile)
            })?;
    let canonical_coefficient_byte_length = canonical_message_owner_byte_lengths
        .values()
        .try_fold(0_u64, |total, byte_length| {
            total
                .checked_add(*byte_length)
                .ok_or(RefusalReason::OutsideSupportedProfile)
        })?;
    let shared_source_byte_length = compact_source_byte_length
        .checked_add(canonical_coefficient_byte_length)
        .ok_or(RefusalReason::OutsideSupportedProfile)?;
    let compact_source_arc_header_byte_length = compact_source_owner_byte_lengths
        .len()
        .checked_mul(
            size_of::<usize>()
                .checked_mul(2)
                .ok_or(RefusalReason::OutsideSupportedProfile)?,
        )
        .ok_or(RefusalReason::OutsideSupportedProfile)?;
    let canonical_message_allocation_wrapper_byte_length = canonical_message_owner_byte_lengths
        .len()
        .checked_mul(
            size_of::<usize>()
                .checked_mul(2)
                .and_then(|length| length.checked_add(size_of::<Zeroizing<Box<[u64]>>>()))
                .ok_or(RefusalReason::OutsideSupportedProfile)?,
        )
        .ok_or(RefusalReason::OutsideSupportedProfile)?;
    let allocation_wrapper_byte_length = compact_source_arc_header_byte_length
        .checked_add(canonical_message_allocation_wrapper_byte_length)
        .and_then(|length| u64::try_from(length).ok())
        .ok_or(RefusalReason::OutsideSupportedProfile)?;
    Ok(SetupGenerationVssSourceAllocationAccounting {
        canonical_coefficient_byte_length,
        compact_source_byte_length,
        shared_source_byte_length,
        allocation_wrapper_byte_length,
    })
}

fn add_key_switch_component_allocations(
    accounting: &mut SetupGenerationDescriptorAllocationAccumulator,
    component: &SetupGeneratedKeySwitchComponent,
) -> Result<(), RefusalReason> {
    accounting.add_topology(component.topology())?;
    accounting.add_stream_descriptor(component.stream_descriptor())
}

fn add_verified_key_switch_component_allocations(
    accounting: &mut SetupGenerationDescriptorAllocationAccumulator,
    material: &VerifiedKeySwitchComponentMaterial,
) -> Result<(), RefusalReason> {
    accounting.add_topology(material.topology())?;
    accounting.add_stream_descriptor(material.stream_descriptor())
}

fn add_relinearization_aggregate_binding_allocations(
    accounting: &mut SetupGenerationDescriptorAllocationAccumulator,
    aggregate_binding: &SetupGenerationRelinearizationAggregateBinding,
) -> Result<(), RefusalReason> {
    accounting.add_usize_byte_length(
        aggregate_binding
            .ordered_participant_identities
            .len()
            .checked_mul(size_of::<[u8; Hash512::BYTE_LENGTH]>())
            .ok_or(RefusalReason::OutsideSupportedProfile)?,
    )?;
    accounting.add_usize_byte_length(
        aggregate_binding
            .ordered_anchor_commitment_roots
            .len()
            .checked_mul(size_of::<[[u8; Hash512::BYTE_LENGTH]; 3]>())
            .ok_or(RefusalReason::OutsideSupportedProfile)?,
    )?;
    accounting.add_usize_byte_length(
        aggregate_binding
            .ordered_round_one_proof_stream_descriptors
            .len()
            .checked_mul(size_of::<StreamDescriptor>())
            .ok_or(RefusalReason::OutsideSupportedProfile)?,
    )?;
    accounting.add_usize_byte_length(
        aggregate_binding
            .ordered_source_root_pairs
            .len()
            .checked_mul(size_of::<[[u8; Hash512::BYTE_LENGTH]; 2]>())
            .ok_or(RefusalReason::OutsideSupportedProfile)?,
    )?;
    for descriptor in aggregate_binding
        .ordered_round_one_proof_stream_descriptors
        .iter()
        .chain([
            &aggregate_binding.proof_stream_descriptor,
            &aggregate_binding.aggregate_left_stream_descriptor,
            &aggregate_binding.aggregate_right_stream_descriptor,
        ])
    {
        accounting.add_stream_descriptor(descriptor)?;
    }
    Ok(())
}

fn setup_generation_vss_post_release_memory_accounting(
    ordered_roster: &[[u8; Hash512::BYTE_LENGTH]],
    ordered_coefficient_materials: &[SetupGeneratedCommittedMaterial],
    ordered_recipient_share_materials: &[SetupGeneratedCommittedMaterial],
    pinned_vss_public_record_binding: Option<&SetupGenerationVssPublicRecordBinding>,
) -> Result<(u64, u64, u64), RefusalReason> {
    let source_accounting = setup_generation_vss_source_allocation_accounting(
        ordered_coefficient_materials
            .iter()
            .chain(ordered_recipient_share_materials),
    )?;
    let mut binding_wrapper_and_catalog_byte_length = 0_u64;
    if let Some(binding) = pinned_vss_public_record_binding {
        let mut binding_wrappers = SetupGenerationDescriptorAllocationAccumulator::default();
        binding_wrappers.add_usize_byte_length(
            binding
                .ordered_recipient_envelope_hashes
                .len()
                .checked_mul(size_of::<Hash512>())
                .ok_or(RefusalReason::OutsideSupportedProfile)?,
        )?;
        binding_wrappers.add_stream_descriptor(&binding.share_linkage_proof)?;
        binding_wrapper_and_catalog_byte_length = binding_wrappers.byte_length;
    }
    setup_generation_vss_post_release_memory_accounting_from_dimensions(
        ordered_roster.len(),
        ordered_coefficient_materials
            .len()
            .checked_add(ordered_recipient_share_materials.len())
            .ok_or(RefusalReason::OutsideSupportedProfile)?,
        source_accounting,
        binding_wrapper_and_catalog_byte_length,
    )
}

fn setup_generation_vss_post_release_memory_accounting_from_dimensions(
    roster_count: usize,
    material_count: usize,
    source_accounting: SetupGenerationVssSourceAllocationAccounting,
    binding_wrapper_and_catalog_byte_length: u64,
) -> Result<(u64, u64, u64), RefusalReason> {
    let mut wrapper_and_catalog_byte_length =
        u64::try_from(size_of::<SetupGenerationVssProofAuthority>())
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
    for byte_length in [
        roster_count
            .checked_mul(size_of::<[u8; Hash512::BYTE_LENGTH]>())
            .ok_or(RefusalReason::OutsideSupportedProfile)?,
        material_count
            .checked_mul(size_of::<SetupGeneratedCommittedMaterial>())
            .ok_or(RefusalReason::OutsideSupportedProfile)?,
        size_of::<usize>()
            .checked_mul(2)
            .and_then(|header| header.checked_add(size_of::<ActionPrivateRandomness>()))
            .ok_or(RefusalReason::OutsideSupportedProfile)?,
    ] {
        wrapper_and_catalog_byte_length = wrapper_and_catalog_byte_length
            .checked_add(
                u64::try_from(byte_length).map_err(|_| RefusalReason::OutsideSupportedProfile)?,
            )
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
    }
    wrapper_and_catalog_byte_length = wrapper_and_catalog_byte_length
        .checked_add(source_accounting.allocation_wrapper_byte_length)
        .and_then(|length| length.checked_add(binding_wrapper_and_catalog_byte_length))
        .ok_or(RefusalReason::OutsideSupportedProfile)?;
    let post_release_payload_byte_length = source_accounting
        .shared_source_byte_length
        .checked_add(wrapper_and_catalog_byte_length)
        .ok_or(RefusalReason::OutsideSupportedProfile)?;
    Ok((
        source_accounting.shared_source_byte_length,
        wrapper_and_catalog_byte_length,
        post_release_payload_byte_length,
    ))
}

impl SetupGenerationVssProofAuthority {
    fn ordered_coefficient_materials(&self) -> &[SetupGeneratedCommittedMaterial] {
        &self.ordered_coefficient_materials
    }

    fn ordered_recipient_share_materials(&self) -> &[SetupGeneratedCommittedMaterial] {
        &self.ordered_recipient_share_materials
    }

    fn retained_memory_accounting(&self) -> Result<(u64, u64, u64), RefusalReason> {
        setup_generation_vss_post_release_memory_accounting(
            &self.ordered_roster,
            self.ordered_coefficient_materials(),
            self.ordered_recipient_share_materials(),
            self.pinned_vss_public_record_binding.as_ref(),
        )
    }

    fn vss_preparation_source(&self) -> Result<SetupGenerationVssPreparationSource, RefusalReason> {
        let ordered_coefficient_material_roots = self
            .ordered_coefficient_materials()
            .iter()
            .map(|material| material.compact_source().root())
            .collect::<Vec<_>>();
        let ordered_recipient_share_material_roots = self
            .ordered_recipient_share_materials()
            .iter()
            .map(|material| material.compact_source().root())
            .collect::<Vec<_>>();
        let canonical_application_statement_bytes = canonical_selected_vss_share_linkage_statement(
            self.protocol_version,
            self.suite_identifier,
            self.ceremony_context_hash,
            self.action_context_hash,
            self.roster_hash,
            self.public_setup_seed,
            self.participant_identity,
            self.roster_position,
            &ordered_coefficient_material_roots,
            &ordered_recipient_share_material_roots,
        )
        .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        Ok(SetupGenerationVssPreparationSource {
            protocol_version: self.protocol_version,
            suite_identifier: self.suite_identifier,
            manifest_hash: self.manifest_hash,
            ceremony_context_hash: self.ceremony_context_hash,
            action_context_hash: self.action_context_hash,
            roster_hash: self.roster_hash,
            setup_proof_context_hash: self.setup_proof_context_hash,
            source_setup_intent_object_hash: self.source_setup_intent_object_hash,
            participant_identity: self.participant_identity,
            roster_position: self.roster_position,
            action_randomness_authorization_hash: self.action_randomness_authorization_hash,
            public_setup_seed: self.public_setup_seed,
            canonical_application_statement_bytes,
        })
    }

    fn pin_vss_application(
        &mut self,
        application: &SetupGenerationVssApplication<'_>,
    ) -> Result<(), RefusalReason> {
        let application_slot = application.prepared_attempt.application_slot();
        if application.statement.protocol_version() != self.protocol_version
            || application.statement.suite_identifier() != self.suite_identifier
            || application.statement.ceremony_context_hash() != self.ceremony_context_hash
            || application.statement.action_context_hash() != self.action_context_hash
            || application.statement.roster_hash() != self.roster_hash
            || application.statement.public_setup_seed() != self.public_setup_seed
            || application.statement.participant_identity() != self.participant_identity
            || application.statement.roster_position() != self.roster_position
            || application_slot.suite_identifier().into_bytes() != self.suite_identifier
            || application_slot.ceremony_context_hash().into_bytes() != self.ceremony_context_hash
            || application_slot.action_context_hash().into_bytes() != self.action_context_hash
            || application_slot.application_statement_schema_identifier()
                != ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER
            || application_slot.roster_position() != Some(self.roster_position)
            || application_slot.schedule_position().is_some()
            || application_slot.producer_sequence().is_some()
            || application
                .statement
                .ordered_coefficient_material_roots()
                .len()
                != self.ordered_coefficient_materials.len()
            || application
                .statement
                .ordered_recipient_share_material_roots()
                .len()
                != self.ordered_recipient_share_materials.len()
            || application
                .statement
                .ordered_coefficient_material_roots()
                .iter()
                .zip(self.ordered_coefficient_materials())
                .any(|(expected_root, material)| *expected_root != material.compact_source().root())
            || application
                .statement
                .ordered_recipient_share_material_roots()
                .iter()
                .zip(self.ordered_recipient_share_materials())
                .any(|(expected_root, material)| *expected_root != material.compact_source().root())
            || application
                .prepared_attempt
                .application_statement_hash()
                .into_bytes()
                != verified_application_statement_hash(
                    self.protocol_version,
                    self.suite_identifier,
                    ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
                    application.canonical_application_statement_bytes,
                )
        {
            return Err(RefusalReason::WrongContext);
        }
        let pinned = PinnedProofAttempt {
            attempt_identifier: application.prepared_attempt.attempt_identifier(),
            application_slot_hash: application
                .prepared_attempt
                .application_slot_hash()
                .into_bytes(),
            application_statement_hash: application
                .prepared_attempt
                .application_statement_hash()
                .into_bytes(),
        };
        if let Some(existing) = &self.pinned_vss_proof_attempt {
            if existing.attempt_identifier != pinned.attempt_identifier
                || existing.application_slot_hash != pinned.application_slot_hash
                || existing.application_statement_hash != pinned.application_statement_hash
            {
                return Err(RefusalReason::ConsumedState);
            }
        } else {
            self.pinned_vss_proof_attempt = Some(pinned);
        }
        Ok(())
    }

    fn dealer_public_record_source(
        &mut self,
        action_private_randomness: &ActionPrivateRandomness,
        roster: &Roster,
        roster_hash: Hash512,
        source_roster_position: u16,
        ordered_recipient_envelope_hashes: &[Hash512],
        share_linkage_proof: &StreamDescriptor,
    ) -> Result<SetupGenerationDealerPublicRecordSource, RefusalReason> {
        let ordered_roster = roster
            .entries
            .iter()
            .map(|entry| {
                entry
                    .participant_identity()
                    .map(ParticipantIdentity::into_bytes)
                    .map_err(|_| RefusalReason::WrongContext)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let derivation_input = action_private_randomness.derivation_input();
        let expected_authorization_hash = action_private_randomness
            .setup_action_randomness_authorization(roster_hash)
            .map_err(|_| RefusalReason::WrongContext)?;
        if self.pinned_vss_proof_attempt.is_none()
            || !std::ptr::eq(
                self.action_private_randomness.as_ref(),
                action_private_randomness,
            )
            || self.suite_identifier != derivation_input.suite_identifier().into_bytes()
            || self.ceremony_context_hash != derivation_input.ceremony_context_hash().into_bytes()
            || self.action_context_hash != derivation_input.action_context_hash().into_bytes()
            || self.participant_identity != derivation_input.participant_identity().into_bytes()
            || self.roster_hash != roster_hash.into_bytes()
            || self.ordered_roster.as_ref() != ordered_roster.as_slice()
            || self.roster_position != source_roster_position
            || &self.setup_attempt_identifier
                != action_private_randomness
                    .setup_attempt_identifier()
                    .as_bytes()
            || self.action_randomness_authorization_hash != expected_authorization_hash.into_bytes()
            || ordered_recipient_envelope_hashes.len()
                != usize::from(FOUNDATION_PROFILE.participant_count)
        {
            return Err(RefusalReason::WrongContext);
        }

        let ordered_coefficient_material_roots = self
            .ordered_coefficient_materials()
            .iter()
            .map(|material| Hash512::from_bytes(material.compact_source().root()))
            .collect::<Vec<_>>();
        let ordered_recipient_share_material_roots = self
            .ordered_recipient_share_materials()
            .iter()
            .map(|material| Hash512::from_bytes(material.compact_source().root()))
            .collect::<Vec<_>>();
        let relation_input = selected_committed_material_relation_plan_input()
            .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)?;
        let expected_coefficient_material_count = relation_input
            .sharing_data_modulus_indices
            .len()
            .checked_mul(usize::from(FOUNDATION_PROFILE.reconstruction_threshold))
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        let expected_recipient_share_material_count = relation_input
            .sharing_data_modulus_indices
            .len()
            .checked_mul(usize::from(FOUNDATION_PROFILE.participant_count))
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        if ordered_coefficient_material_roots.len() != expected_coefficient_material_count
            || ordered_recipient_share_material_roots.len()
                != expected_recipient_share_material_count
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        SetupGenerationVssPublicRecordBinding::pin_exact(
            &mut self.pinned_vss_public_record_binding,
            ordered_recipient_envelope_hashes,
            share_linkage_proof,
        )?;
        Ok(SetupGenerationDealerPublicRecordSource {
            suite_identifier: Hash512::from_bytes(self.suite_identifier),
            ceremony_context_hash: Hash512::from_bytes(self.ceremony_context_hash),
            action_context_hash: Hash512::from_bytes(self.action_context_hash),
            participant_identity: ParticipantIdentity::from_bytes(self.participant_identity),
            roster_position: self.roster_position,
            public_setup_seed: Hash512::from_bytes(self.public_setup_seed),
            ordered_coefficient_material_roots: ordered_coefficient_material_roots
                .into_boxed_slice(),
            ordered_recipient_share_material_roots: ordered_recipient_share_material_roots
                .into_boxed_slice(),
            ordered_recipient_envelope_hashes: ordered_recipient_envelope_hashes.into(),
            share_linkage_proof: share_linkage_proof.clone(),
        })
    }
}

/// Exact generated aggregate identity retained between round-two activation
/// and fresh or resumed proof generation. The aggregate and its proof
/// descriptor come from the prepackage catalog after the generated proof has
/// been bound to its canonical statement; no transport-facing constructor
/// accepts any of these bindings separately.
struct SetupGenerationRelinearizationAggregateBinding {
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
    proof_stream_descriptor: StreamDescriptor,
    aggregate_left_material_root: Hash512,
    aggregate_left_stream_descriptor: StreamDescriptor,
    aggregate_right_material_root: Hash512,
    aggregate_right_stream_descriptor: StreamDescriptor,
}

impl SetupGenerationRelinearizationAggregateBinding {
    fn from_generated(
        aggregate: &SetupGeneratedRelinearizationAggregateSourceAuthority,
        proof_stream_descriptor: &StreamDescriptor,
    ) -> Self {
        Self {
            protocol_version: aggregate.protocol_version(),
            suite_identifier: aggregate.suite_identifier(),
            ceremony_context_hash: aggregate.ceremony_context_hash(),
            action_context_hash: aggregate.action_context_hash(),
            roster_hash: aggregate.roster_hash(),
            setup_proof_context_hash: aggregate.setup_proof_context_hash(),
            schedule_position: aggregate.schedule_position(),
            evaluator_position: aggregate.evaluator_position(),
            ordered_participant_identities: aggregate.ordered_participant_identities().into(),
            ordered_anchor_commitment_roots: aggregate.ordered_anchor_commitment_roots().into(),
            ordered_round_one_proof_stream_descriptors: aggregate
                .ordered_round_one_proof_stream_descriptors()
                .into(),
            ordered_source_root_pairs: aggregate.ordered_source_root_pairs().into(),
            proof_stream_descriptor: proof_stream_descriptor.clone(),
            aggregate_left_material_root: aggregate.components()[0].material_root(),
            aggregate_left_stream_descriptor: aggregate.components()[0].stream_descriptor().clone(),
            aggregate_right_material_root: aggregate.components()[1].material_root(),
            aggregate_right_stream_descriptor: aggregate.components()[1]
                .stream_descriptor()
                .clone(),
        }
    }

    fn binds(
        &self,
        aggregate: &SetupGeneratedRelinearizationAggregateSourceAuthority,
        proof_stream_descriptor: &StreamDescriptor,
    ) -> bool {
        self.protocol_version == aggregate.protocol_version()
            && self.suite_identifier == aggregate.suite_identifier()
            && self.ceremony_context_hash == aggregate.ceremony_context_hash()
            && self.action_context_hash == aggregate.action_context_hash()
            && self.roster_hash == aggregate.roster_hash()
            && self.setup_proof_context_hash == aggregate.setup_proof_context_hash()
            && self.schedule_position == aggregate.schedule_position()
            && self.evaluator_position == aggregate.evaluator_position()
            && self.ordered_participant_identities.as_ref()
                == aggregate.ordered_participant_identities()
            && self.ordered_anchor_commitment_roots.as_ref()
                == aggregate.ordered_anchor_commitment_roots()
            && self.ordered_round_one_proof_stream_descriptors.as_ref()
                == aggregate.ordered_round_one_proof_stream_descriptors()
            && self.ordered_source_root_pairs.as_ref() == aggregate.ordered_source_root_pairs()
            && self.proof_stream_descriptor == *proof_stream_descriptor
            && self.aggregate_left_material_root == aggregate.components()[0].material_root()
            && self.aggregate_left_stream_descriptor
                == *aggregate.components()[0].stream_descriptor()
            && self.aggregate_right_material_root == aggregate.components()[1].material_root()
            && self.aggregate_right_stream_descriptor
                == *aggregate.components()[1].stream_descriptor()
    }
}

/// Uncommitted round-two activation state. The aggregate binding is retained
/// beside the bounded construction until finish reopens the same catalog
/// source and installs both authority fields atomically.
pub(crate) struct SetupGenerationRelinearizationRoundTwoActivation {
    aggregate_binding: Option<SetupGenerationRelinearizationAggregateBinding>,
    construction: SetupRelinearizationRoundTwoConstruction,
}

impl SetupGenerationRelinearizationRoundTwoActivation {
    pub(crate) const fn topology(&self) -> &KeySwitchComponentMaterialTopology {
        self.construction.topology()
    }

    fn memory_accounting(
        &self,
        retained_authority: SetupGenerationRetainedMemoryAccounting,
    ) -> Result<SetupGenerationRelinearizationRoundTwoActivationMemoryAccounting, RefusalReason>
    {
        if retained_authority.vss_proof_phase_is_active() {
            return Err(RefusalReason::ConsumedState);
        }
        let retained_authority_payload_byte_length =
            retained_authority.all_family_payload_byte_length();
        let mut activation_binding_accounting =
            SetupGenerationDescriptorAllocationAccumulator::default();
        add_relinearization_aggregate_binding_allocations(
            &mut activation_binding_accounting,
            self.aggregate_binding
                .as_ref()
                .ok_or(RefusalReason::ConsumedState)?,
        )?;
        let activation_binding_payload_byte_length = activation_binding_accounting.byte_length;
        let setup_matrix_cache_payload_byte_length =
            setup_commitment_matrix_ntt_cache_coefficient_payload_byte_length(
                self.topology().polynomial_degree(),
            )
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        let pre_root_construction_payload_byte_length =
            self.construction.pre_root_retained_payload_byte_length()?;
        let generation_workspace_payload_peak_byte_length = self
            .construction
            .generation_workspace_payload_peak_byte_length()?;
        let root_overlap_construction_payload_byte_length = self
            .construction
            .root_overlap_retained_payload_byte_length()?;
        let streamed_root_transient_payload_byte_length =
            setup_public_polynomial_wasm_compact_root_memory_plan(
                self.construction.evaluation_domain_size(),
                self.topology().half_polynomial_degree_bound_exclusive()?,
                u32::try_from(self.topology().trace_column_count()?)
                    .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
            )
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?
            .owned_payload_peak_byte_length();
        SetupGenerationRelinearizationRoundTwoActivationMemoryAccounting::from_live_phase_payloads(
            retained_authority_payload_byte_length,
            activation_binding_payload_byte_length,
            setup_matrix_cache_payload_byte_length,
            pre_root_construction_payload_byte_length,
            generation_workspace_payload_peak_byte_length,
            root_overlap_construction_payload_byte_length,
            streamed_root_transient_payload_byte_length,
        )
    }
}

struct SetupGenerationAuthority {
    protocol_version: u16,
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    manifest_hash: [u8; Hash512::BYTE_LENGTH],
    ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
    action_context_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    ordered_roster: Box<[[u8; Hash512::BYTE_LENGTH]]>,
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    source_setup_intent_object_hash: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    roster_position: u16,
    setup_attempt_identifier: [u8; 32],
    action_randomness_authorization_hash: [u8; Hash512::BYTE_LENGTH],
    action_private_randomness: Rc<ActionPrivateRandomness>,
    public_setup_seed: [u8; Hash512::BYTE_LENGTH],
    anchor_commitment_roots: [[u8; Hash512::BYTE_LENGTH]; 3],
    anchor_openings: Box<[SetupGenerationAnchorOpening]>,
    common_secret_coefficients: Zeroizing<Vec<i8>>,
    public_key_share: SetupGeneratedPublicKeyShare,
    public_key_share_body_source_opened: bool,
    public_key_share_body_stream_completed: bool,
    vss_material: SetupGeneratedVssMaterial,
    completed_recipient_private_payload_count: usize,
    relinearization_material: SetupGeneratedRelinearizationMaterial,
    relinearization_aggregate_binding: Option<SetupGenerationRelinearizationAggregateBinding>,
    generated_relinearization_round_two: Option<SetupGeneratedRelinearizationRoundTwoGeneration>,
    galois_batch_schedule_position: u32,
    ordered_galois_entries: Box<[SetupGeneratedGaloisEntry]>,
    pinned_vss_proof_attempt: Option<PinnedProofAttempt>,
    pinned_vss_public_record_binding: Option<SetupGenerationVssPublicRecordBinding>,
    pinned_relinearization_round_one_proof_attempt: Option<PinnedProofAttempt>,
    pinned_relinearization_round_two_proof_attempt: Option<PinnedProofAttempt>,
    pinned_galois_proof_attempt: Option<PinnedProofAttempt>,
    pinned_same_secret_proof_attempt: Option<PinnedProofAttempt>,
    pinned_public_key_share_proof_attempt: Option<PinnedProofAttempt>,
}

/// Checkpoint-stable final setup proof authority. Entering this phase moves
/// only the VSS committed sources and their transcript bindings out of the
/// all-family setup authority; every superseded setup, RKG and Galois witness
/// allocation is dropped before common-proof preparation begins.
struct SetupGenerationVssProofAuthority {
    protocol_version: u16,
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    manifest_hash: [u8; Hash512::BYTE_LENGTH],
    ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
    action_context_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    ordered_roster: Box<[[u8; Hash512::BYTE_LENGTH]]>,
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    source_setup_intent_object_hash: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    roster_position: u16,
    setup_attempt_identifier: [u8; 32],
    action_randomness_authorization_hash: [u8; Hash512::BYTE_LENGTH],
    action_private_randomness: Rc<ActionPrivateRandomness>,
    public_setup_seed: [u8; Hash512::BYTE_LENGTH],
    ordered_coefficient_materials: Box<[SetupGeneratedCommittedMaterial]>,
    ordered_recipient_share_materials: Box<[SetupGeneratedCommittedMaterial]>,
    pinned_vss_proof_attempt: Option<PinnedProofAttempt>,
    pinned_vss_public_record_binding: Option<SetupGenerationVssPublicRecordBinding>,
}

impl SetupGenerationAuthority {
    fn from_browser_owned_input(
        input: SetupGenerationAuthorityInput,
    ) -> Result<Self, RefusalReason> {
        let participant_index = usize::from(input.roster_position);
        let Some(roster_participant) = input.ordered_roster.get(participant_index) else {
            return Err(RefusalReason::WrongTypeOrLength);
        };
        let ring_degree = input
            .ordered_galois_entries
            .first()
            .map(|entry| entry.component().topology().polynomial_degree())
            .ok_or(RefusalReason::MissingPrerequisite)?;
        let action_randomness_derivation_input = input.action_private_randomness.derivation_input();
        let expected_action_randomness_authorization_hash = input
            .action_private_randomness
            .setup_action_randomness_authorization(Hash512::from_bytes(input.roster_hash))
            .map_err(|_| RefusalReason::WrongContext)?
            .into_bytes();
        let expected_public_key_share_context_hash =
            SetupPublicPolynomialContext::public_key_share(
                input.setup_proof_context_hash,
                input.participant_identity,
                input.roster_position,
            )
            .and_then(|context| context.context_hash())
            .map_err(|_| RefusalReason::WrongContext)?;
        if *roster_participant != input.participant_identity
            || input.ordered_roster.len() != usize::from(FOUNDATION_PROFILE.participant_count)
            || action_randomness_derivation_input
                .suite_identifier()
                .into_bytes()
                != input.suite_identifier
            || action_randomness_derivation_input
                .ceremony_context_hash()
                .into_bytes()
                != input.ceremony_context_hash
            || action_randomness_derivation_input
                .action_context_hash()
                .into_bytes()
                != input.action_context_hash
            || action_randomness_derivation_input
                .participant_identity()
                .into_bytes()
                != input.participant_identity
            || input
                .action_private_randomness
                .setup_attempt_identifier()
                .as_bytes()
                != &input.setup_attempt_identifier
            || expected_action_randomness_authorization_hash
                != input.action_randomness_authorization_hash
            || input.common_secret_coefficients.len() != ring_degree
            || input
                .common_secret_coefficients
                .iter()
                .any(|coefficient| !(-1..=1).contains(coefficient))
            || input.public_key_share.ordered_data_modulus_indices()
                != selected_public_key_share_relation_plan_input()
                    .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)?
                    .data_modulus_indices
            || input.public_key_share.centered_error_coefficients().len() != ring_degree
            || input.public_key_share.public_polynomial_context_hash()
                != expected_public_key_share_context_hash
            || input
                .ordered_galois_entries
                .iter()
                .any(|entry| entry.component().topology().polynomial_degree() != ring_degree)
            || input.anchor_openings.len() != SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len()
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        for (anchor_ordinal, (anchor, expected_data_prime_index)) in input
            .anchor_openings
            .iter()
            .zip(SETUP_COMMITMENT_MODULUS_LIMB_INDICES)
            .enumerate()
        {
            let expected_context_hash = SetupPublicPolynomialContext::lattice_anchor(
                input.setup_proof_context_hash,
                input.participant_identity,
                input.roster_position,
                u16::try_from(expected_data_prime_index)
                    .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
            )
            .and_then(|context| context.context_hash())
            .map_err(|_| RefusalReason::WrongContext)?;
            if usize::from(anchor.commitment_data_prime_index()) != expected_data_prime_index
                || anchor.public_polynomial_context_hash() != expected_context_hash
                || anchor.source_polynomial_degree_bound_exclusive() != ring_degree / 2
                || anchor.root() != input.anchor_commitment_roots[anchor_ordinal]
            {
                return Err(RefusalReason::WrongHashOrRoot);
            }
        }
        let selected_material_profile = selected_committed_material_profile()
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        let selected_relation_input = selected_committed_material_relation_plan_input()
            .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)?;
        let reconstruction_threshold = usize::from(FOUNDATION_PROFILE.reconstruction_threshold);
        for (material_ordinal, material) in input
            .vss_material
            .ordered_coefficient_materials()
            .iter()
            .enumerate()
        {
            let sharing_limb_index = selected_relation_input
                .sharing_data_modulus_indices
                .get(material_ordinal / reconstruction_threshold)
                .copied()
                .ok_or(RefusalReason::WrongTypeOrLength)?;
            let coefficient_index = u16::try_from(material_ordinal % reconstruction_threshold)
                .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
            let expected_context_hash = CommittedMaterialContext::new(
                input.suite_identifier,
                input.ceremony_context_hash,
                input.action_context_hash,
                input.participant_identity,
                CommittedMaterialRole::Coefficient,
                sharing_limb_index,
                coefficient_index,
            )
            .context_hash()
            .map_err(|_| RefusalReason::WrongContext)?;
            if material.compact_source().profile() != selected_material_profile
                || material.compact_source().material_context_hash() != expected_context_hash
            {
                return Err(RefusalReason::WrongContext);
            }
        }
        let participant_count = usize::from(FOUNDATION_PROFILE.participant_count);
        for (material_ordinal, material) in input
            .vss_material
            .ordered_recipient_share_materials()
            .iter()
            .enumerate()
        {
            let sharing_limb_index = selected_relation_input
                .sharing_data_modulus_indices
                .get(material_ordinal / participant_count)
                .copied()
                .ok_or(RefusalReason::WrongTypeOrLength)?;
            let recipient_roster_position = u16::try_from(material_ordinal % participant_count)
                .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
            let expected_context_hash = CommittedMaterialContext::new(
                input.suite_identifier,
                input.ceremony_context_hash,
                input.action_context_hash,
                input.participant_identity,
                CommittedMaterialRole::RecipientShare,
                sharing_limb_index,
                recipient_roster_position,
            )
            .context_hash()
            .map_err(|_| RefusalReason::WrongContext)?;
            if material.compact_source().profile() != selected_material_profile
                || material.compact_source().material_context_hash() != expected_context_hash
            {
                return Err(RefusalReason::WrongContext);
            }
        }
        let [expected_batch_schedule_position] = selected_galois_key_share_batch_schedule();
        let expected_galois_positions = selected_evaluator_galois_entry_positions()
            .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)?;
        let expected_relinearization_positions =
            crate::bgv::proof_suite::selected_evaluator_entry_positions(
                FOUNDATION_PROFILE.option_count,
            )
            .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)?
            .into_iter()
            .filter(|position| {
                matches!(
                    position.key_kind(),
                    SelectedEvaluatorEntryKind::Relinearization { .. }
                )
            })
            .collect::<Vec<_>>();
        let [expected_relinearization_position] = expected_relinearization_positions.as_slice()
        else {
            return Err(RefusalReason::UnsupportedVersionOrSuite);
        };
        let relinearization_material = &input.relinearization_material;
        let relinearization_topology = relinearization_material
            .round_one_left_component()
            .topology();
        if input.galois_batch_schedule_position != expected_batch_schedule_position
            || input
                .ordered_galois_entries
                .iter()
                .map(|entry| entry.component().evaluator_position())
                .ne(expected_galois_positions)
            || relinearization_material.evaluator_position() != *expected_relinearization_position
            || relinearization_material.schedule_position()
                != expected_relinearization_position.schedule_position()
            || relinearization_material
                .ephemeral_secret_coefficients()
                .len()
                != ring_degree
            || relinearization_material
                .ephemeral_secret_coefficients()
                .iter()
                .any(|coefficient| !(-1..=1).contains(coefficient))
            || relinearization_material
                .round_one_left_component()
                .evaluator_position()
                != *expected_relinearization_position
            || relinearization_material
                .round_one_right_component()
                .evaluator_position()
                != *expected_relinearization_position
            || relinearization_material
                .round_one_right_component()
                .topology()
                != relinearization_topology
            || relinearization_topology.polynomial_degree() != ring_degree
            || [
                relinearization_material.round_one_left_errors_by_block(),
                relinearization_material.round_one_right_errors_by_block(),
                relinearization_material.round_two_errors_by_block(),
            ]
            .into_iter()
            .any(|errors_by_block| {
                errors_by_block.len() != relinearization_topology.data_block_count()
                    || errors_by_block.iter().any(|error| {
                        error.len() != ring_degree
                            || error
                                .iter()
                                .any(|coefficient| !(-2..=2).contains(coefficient))
                    })
            })
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        Ok(Self {
            protocol_version: FOUNDATION_PROFILE.protocol_version,
            suite_identifier: input.suite_identifier,
            manifest_hash: input.manifest_hash,
            ceremony_context_hash: input.ceremony_context_hash,
            action_context_hash: input.action_context_hash,
            roster_hash: input.roster_hash,
            ordered_roster: input.ordered_roster,
            setup_proof_context_hash: input.setup_proof_context_hash,
            source_setup_intent_object_hash: input.source_setup_intent_object_hash,
            participant_identity: input.participant_identity,
            roster_position: input.roster_position,
            setup_attempt_identifier: input.setup_attempt_identifier,
            action_randomness_authorization_hash: input.action_randomness_authorization_hash,
            action_private_randomness: input.action_private_randomness,
            public_setup_seed: input.public_setup_seed,
            anchor_commitment_roots: input.anchor_commitment_roots,
            anchor_openings: input.anchor_openings.into_boxed_slice(),
            common_secret_coefficients: input.common_secret_coefficients,
            public_key_share: input.public_key_share,
            public_key_share_body_source_opened: false,
            public_key_share_body_stream_completed: false,
            vss_material: input.vss_material,
            completed_recipient_private_payload_count: 0,
            relinearization_material: input.relinearization_material,
            relinearization_aggregate_binding: None,
            generated_relinearization_round_two: None,
            galois_batch_schedule_position: input.galois_batch_schedule_position,
            ordered_galois_entries: input.ordered_galois_entries.into_boxed_slice(),
            pinned_vss_proof_attempt: None,
            pinned_vss_public_record_binding: None,
            pinned_relinearization_round_one_proof_attempt: None,
            pinned_relinearization_round_two_proof_attempt: None,
            pinned_galois_proof_attempt: None,
            pinned_same_secret_proof_attempt: None,
            pinned_public_key_share_proof_attempt: None,
        })
    }

    fn degree_zero_material_count(&self) -> Result<usize, RefusalReason> {
        selected_committed_material_relation_plan_input()
            .map(|input| input.sharing_data_modulus_indices.len())
            .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)
    }

    fn degree_zero_material(
        &self,
        degree_zero_material_ordinal: usize,
    ) -> Result<&SetupGeneratedCommittedMaterial, RefusalReason> {
        if degree_zero_material_ordinal >= self.degree_zero_material_count()? {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        let reconstruction_threshold = usize::from(FOUNDATION_PROFILE.reconstruction_threshold);
        let material_ordinal = degree_zero_material_ordinal
            .checked_mul(reconstruction_threshold)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        self.vss_material
            .ordered_coefficient_materials()
            .get(material_ordinal)
            .ok_or(RefusalReason::WrongTypeOrLength)
    }

    fn canonical_key_relation_statement(
        &self,
        family: SetupKeyRelationProofFamily,
    ) -> Result<Vec<u8>, RefusalReason> {
        match family {
            SetupKeyRelationProofFamily::SameSecret => {
                let ordered_degree_zero_commitment_roots = (0..self
                    .degree_zero_material_count()?)
                    .map(|material_ordinal| {
                        self.degree_zero_material(material_ordinal)
                            .map(|material| material.compact_source().root())
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                canonical_selected_same_secret_statement(
                    self.setup_proof_context_hash,
                    self.participant_identity,
                    self.roster_position,
                    &ordered_degree_zero_commitment_roots,
                    &self.anchor_commitment_roots,
                )
                .map_err(|_| RefusalReason::OutsideSupportedProfile)
            }
            SetupKeyRelationProofFamily::PublicKeyShare => {
                canonical_selected_public_key_share_statement(
                    self.setup_proof_context_hash,
                    self.participant_identity,
                    self.roster_position,
                    &self.anchor_commitment_roots,
                    self.public_key_share.root(),
                )
                .map_err(|_| RefusalReason::OutsideSupportedProfile)
            }
        }
    }

    fn key_relation_preparation_source(
        &self,
        family: SetupKeyRelationProofFamily,
    ) -> Result<SetupGenerationKeyRelationPreparationSource, RefusalReason> {
        Ok(SetupGenerationKeyRelationPreparationSource {
            family,
            protocol_version: self.protocol_version,
            suite_identifier: self.suite_identifier,
            manifest_hash: self.manifest_hash,
            ceremony_context_hash: self.ceremony_context_hash,
            action_context_hash: self.action_context_hash,
            roster_hash: self.roster_hash,
            setup_proof_context_hash: self.setup_proof_context_hash,
            source_setup_intent_object_hash: self.source_setup_intent_object_hash,
            participant_identity: self.participant_identity,
            roster_position: self.roster_position,
            action_randomness_authorization_hash: self.action_randomness_authorization_hash,
            public_setup_seed: self.public_setup_seed,
            canonical_application_statement_bytes: self.canonical_key_relation_statement(family)?,
        })
    }

    fn generated_relinearization_round_one_source_authority(
        &self,
    ) -> Result<SetupGeneratedRelinearizationRoundOneSourceAuthority, RefusalReason> {
        let statement_schema_identifier =
            ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER;
        let selected_plan = selected_relation_plans()
            .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)?
            .into_iter()
            .find(|artifact| {
                artifact.application_statement_schema_identifier() == statement_schema_identifier
            })
            .ok_or(RefusalReason::UnsupportedVersionOrSuite)?;
        let variant = selected_plan
            .compiled_plan()
            .select_variant(
                Some(self.relinearization_material.schedule_position()),
                None,
            )
            .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)?;
        let evaluation_domain_size = usize::try_from(variant.evaluation_domain_size())
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        self.relinearization_material
            .generated_round_one_source_authority(
                self.suite_identifier,
                self.ceremony_context_hash,
                self.action_context_hash,
                self.roster_hash,
                self.setup_proof_context_hash,
                self.participant_identity,
                self.roster_position,
                self.anchor_commitment_roots,
                evaluation_domain_size,
            )
    }

    fn relinearization_round_one_preparation_source(
        &self,
    ) -> Result<SetupGenerationRelinearizationRoundOnePreparationSource, RefusalReason> {
        let generated_source = self.generated_relinearization_round_one_source_authority()?;
        Ok(
            SetupGenerationRelinearizationRoundOnePreparationSource::from_generated_source(
                &generated_source,
                self.manifest_hash,
                self.source_setup_intent_object_hash,
                self.action_randomness_authorization_hash,
            ),
        )
    }

    fn relinearization_round_two_evaluation_domain_size(&self) -> Result<usize, RefusalReason> {
        let statement_schema_identifier =
            ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER;
        let selected_plan = selected_relation_plans()
            .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)?
            .into_iter()
            .find(|artifact| {
                artifact.application_statement_schema_identifier() == statement_schema_identifier
            })
            .ok_or(RefusalReason::UnsupportedVersionOrSuite)?;
        let variant = selected_plan
            .compiled_plan()
            .select_variant(
                Some(self.relinearization_material.schedule_position()),
                None,
            )
            .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)?;
        usize::try_from(variant.evaluation_domain_size())
            .map_err(|_| RefusalReason::OutsideSupportedProfile)
    }

    fn exact_local_round_one_source_in_generated_aggregate(
        &self,
        round_one_source: &SetupGeneratedRelinearizationRoundOneSourceAuthority,
        generated_aggregate: &SetupGeneratedRelinearizationAggregateSourceAuthority,
    ) -> Result<(), RefusalReason> {
        let roster_index = usize::from(self.roster_position);
        let round_one_root_pair = round_one_source.root_pair();
        if generated_aggregate.ordered_participant_identities().len()
            != usize::from(FOUNDATION_PROFILE.participant_count)
            || generated_aggregate.ordered_anchor_commitment_roots().len()
                != usize::from(FOUNDATION_PROFILE.participant_count)
            || generated_aggregate.ordered_source_root_pairs().len()
                != usize::from(FOUNDATION_PROFILE.participant_count)
            || generated_aggregate
                .ordered_round_one_proof_stream_descriptors()
                .len()
                != usize::from(FOUNDATION_PROFILE.participant_count)
            || generated_aggregate
                .ordered_participant_identities()
                .get(roster_index)
                != Some(&self.participant_identity)
            || generated_aggregate
                .ordered_anchor_commitment_roots()
                .get(roster_index)
                != Some(&self.anchor_commitment_roots)
            || generated_aggregate
                .ordered_source_root_pairs()
                .get(roster_index)
                != Some(&round_one_root_pair)
        {
            return Err(RefusalReason::WrongContext);
        }
        Ok(())
    }

    fn begin_relinearization_round_two_activation(
        &self,
        selected_suite: &SelectedSuiteCapability,
        generated_aggregate: &SetupGeneratedRelinearizationAggregateSourceAuthority,
        aggregate_proof_stream_descriptor: &StreamDescriptor,
    ) -> Result<SetupGenerationRelinearizationRoundTwoActivation, RefusalReason> {
        if self.generated_relinearization_round_two.is_some()
            || self.relinearization_aggregate_binding.is_some()
        {
            return Err(RefusalReason::ConsumedState);
        }
        if self
            .pinned_relinearization_round_one_proof_attempt
            .is_none()
        {
            return Err(RefusalReason::MissingPrerequisite);
        }
        let round_one_source = self.generated_relinearization_round_one_source_authority()?;
        self.exact_local_round_one_source_in_generated_aggregate(
            &round_one_source,
            generated_aggregate,
        )?;
        let construction = self.relinearization_material.begin_round_two_construction(
            selected_suite,
            &round_one_source,
            generated_aggregate,
            self.relinearization_round_two_evaluation_domain_size()?,
        )?;
        Ok(SetupGenerationRelinearizationRoundTwoActivation {
            aggregate_binding: Some(
                SetupGenerationRelinearizationAggregateBinding::from_generated(
                    generated_aggregate,
                    aggregate_proof_stream_descriptor,
                ),
            ),
            construction,
        })
    }

    fn absorb_relinearization_round_two_activation_pair(
        &self,
        activation: &mut SetupGenerationRelinearizationRoundTwoActivation,
        aggregate_left_bytes: &[u8],
        aggregate_right_bytes: &[u8],
    ) -> Result<(), RefusalReason> {
        if self.generated_relinearization_round_two.is_some()
            || self.relinearization_aggregate_binding.is_some()
            || self
                .pinned_relinearization_round_one_proof_attempt
                .is_none()
            || activation.aggregate_binding.is_none()
        {
            return Err(RefusalReason::ConsumedState);
        }
        activation.construction.absorb_authenticated_source_pair(
            &self.common_secret_coefficients,
            self.relinearization_material
                .ephemeral_secret_coefficients(),
            self.relinearization_material.round_two_errors_by_block(),
            aggregate_left_bytes,
            aggregate_right_bytes,
        )
    }

    fn finish_relinearization_round_two_activation(
        &mut self,
        activation: &mut SetupGenerationRelinearizationRoundTwoActivation,
        generated_aggregate: &SetupGeneratedRelinearizationAggregateSourceAuthority,
        aggregate_proof_stream_descriptor: &StreamDescriptor,
    ) -> Result<SetupGenerationRelinearizationRoundTwoPreparationSource, RefusalReason> {
        if self.generated_relinearization_round_two.is_some()
            || self.relinearization_aggregate_binding.is_some()
            || self
                .pinned_relinearization_round_one_proof_attempt
                .is_none()
        {
            return Err(RefusalReason::ConsumedState);
        }
        let round_one_source = self.generated_relinearization_round_one_source_authority()?;
        self.exact_local_round_one_source_in_generated_aggregate(
            &round_one_source,
            generated_aggregate,
        )?;
        let aggregate_binding = activation
            .aggregate_binding
            .as_ref()
            .filter(|binding| binding.binds(generated_aggregate, aggregate_proof_stream_descriptor))
            .ok_or(RefusalReason::WrongContext)?;
        let _ = aggregate_binding;
        let generated_round_two = activation.construction.finish()?;
        let preparation_source =
            SetupGenerationRelinearizationRoundTwoPreparationSource::from_generated_source(
                generated_round_two.source_authority(),
                self.manifest_hash,
                self.source_setup_intent_object_hash,
                self.action_randomness_authorization_hash,
            );
        self.relinearization_aggregate_binding = activation.aggregate_binding.take();
        self.generated_relinearization_round_two = Some(generated_round_two);
        Ok(preparation_source)
    }

    fn relinearization_round_two_preparation_source(
        &self,
    ) -> Result<SetupGenerationRelinearizationRoundTwoPreparationSource, RefusalReason> {
        let generated = self
            .generated_relinearization_round_two
            .as_ref()
            .ok_or(RefusalReason::MissingPrerequisite)?;
        if self.relinearization_aggregate_binding.is_none() {
            return Err(RefusalReason::MissingPrerequisite);
        }
        Ok(
            SetupGenerationRelinearizationRoundTwoPreparationSource::from_generated_source(
                generated.source_authority(),
                self.manifest_hash,
                self.source_setup_intent_object_hash,
                self.action_randomness_authorization_hash,
            ),
        )
    }

    fn validate_relinearization_round_two_aggregate(
        &self,
        generated_aggregate: &SetupGeneratedRelinearizationAggregateSourceAuthority,
        aggregate_proof_stream_descriptor: &StreamDescriptor,
    ) -> Result<(), RefusalReason> {
        let binding = self
            .relinearization_aggregate_binding
            .as_ref()
            .ok_or(RefusalReason::MissingPrerequisite)?;
        if !binding.binds(generated_aggregate, aggregate_proof_stream_descriptor) {
            return Err(RefusalReason::WrongContext);
        }
        Ok(())
    }

    fn galois_preparation_source(
        &self,
    ) -> Result<SetupGenerationGaloisPreparationSource, RefusalReason> {
        let statement_schema_identifier =
            ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER;
        let selected_plan = selected_relation_plans()
            .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)?
            .into_iter()
            .find(|artifact| {
                artifact.application_statement_schema_identifier() == statement_schema_identifier
            })
            .ok_or(RefusalReason::UnsupportedVersionOrSuite)?;
        let variant = selected_plan
            .compiled_plan()
            .select_variant(Some(self.galois_batch_schedule_position), None)
            .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)?;
        let evaluation_domain_size = usize::try_from(variant.evaluation_domain_size())
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        let mut ordered_contribution_roots = Vec::with_capacity(self.ordered_galois_entries.len());
        for (entry_ordinal, entry) in self.ordered_galois_entries.iter().enumerate() {
            let logical_schedule_position =
                u32::try_from(entry_ordinal).map_err(|_| RefusalReason::OutsideSupportedProfile)?;
            let context = SetupPublicPolynomialContext::new(
                self.setup_proof_context_hash,
                crate::bgv::proof_suite::SetupPublicPolynomialRootRole::GaloisKeyShare,
                Some(self.participant_identity),
                Some(self.roster_position),
                Some(logical_schedule_position),
                None,
            )
            .map_err(|_| RefusalReason::WrongContext)?;
            let public_polynomial_root =
                recompute_setup_generated_component_public_polynomial_root(
                    entry.component(),
                    &context,
                    evaluation_domain_size,
                )?;
            ordered_contribution_roots.push(public_polynomial_root.root());
        }
        let canonical_application_statement_bytes = canonical_selected_galois_key_share_statement(
            self.setup_proof_context_hash,
            self.participant_identity,
            self.roster_position,
            self.galois_batch_schedule_position,
            &self.anchor_commitment_roots,
            &ordered_contribution_roots,
        )
        .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        Ok(SetupGenerationGaloisPreparationSource {
            protocol_version: self.protocol_version,
            suite_identifier: self.suite_identifier,
            manifest_hash: self.manifest_hash,
            ceremony_context_hash: self.ceremony_context_hash,
            action_context_hash: self.action_context_hash,
            roster_hash: self.roster_hash,
            setup_proof_context_hash: self.setup_proof_context_hash,
            source_setup_intent_object_hash: self.source_setup_intent_object_hash,
            participant_identity: self.participant_identity,
            roster_position: self.roster_position,
            action_randomness_authorization_hash: self.action_randomness_authorization_hash,
            batch_schedule_position: self.galois_batch_schedule_position,
            ordered_contribution_roots: ordered_contribution_roots.into_boxed_slice(),
            canonical_application_statement_bytes,
        })
    }

    fn vss_preparation_source(&self) -> Result<SetupGenerationVssPreparationSource, RefusalReason> {
        let ordered_coefficient_material_roots = self
            .vss_material
            .ordered_coefficient_materials()
            .iter()
            .map(|material| material.compact_source().root())
            .collect::<Vec<_>>();
        let ordered_recipient_share_material_roots = self
            .vss_material
            .ordered_recipient_share_materials()
            .iter()
            .map(|material| material.compact_source().root())
            .collect::<Vec<_>>();
        let canonical_application_statement_bytes = canonical_selected_vss_share_linkage_statement(
            self.protocol_version,
            self.suite_identifier,
            self.ceremony_context_hash,
            self.action_context_hash,
            self.roster_hash,
            self.public_setup_seed,
            self.participant_identity,
            self.roster_position,
            &ordered_coefficient_material_roots,
            &ordered_recipient_share_material_roots,
        )
        .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        Ok(SetupGenerationVssPreparationSource {
            protocol_version: self.protocol_version,
            suite_identifier: self.suite_identifier,
            manifest_hash: self.manifest_hash,
            ceremony_context_hash: self.ceremony_context_hash,
            action_context_hash: self.action_context_hash,
            roster_hash: self.roster_hash,
            setup_proof_context_hash: self.setup_proof_context_hash,
            source_setup_intent_object_hash: self.source_setup_intent_object_hash,
            participant_identity: self.participant_identity,
            roster_position: self.roster_position,
            action_randomness_authorization_hash: self.action_randomness_authorization_hash,
            public_setup_seed: self.public_setup_seed,
            canonical_application_statement_bytes,
        })
    }

    fn pin_key_relation_application(
        &mut self,
        application: &SetupGenerationKeyRelationApplication<'_>,
    ) -> Result<(), RefusalReason> {
        let application_slot = application.prepared_attempt.application_slot();
        let statement_schema_identifier = application.family.statement_schema_identifier();
        let canonical_application_statement_bytes =
            self.canonical_key_relation_statement(application.family)?;
        if application.canonical_application_statement_bytes
            != canonical_application_statement_bytes
            || application.setup_proof_context_hash != self.setup_proof_context_hash
            || application.roster_hash != self.roster_hash
            || application.participant_identity != self.participant_identity
            || application.roster_position != self.roster_position
            || application_slot.suite_identifier().into_bytes() != self.suite_identifier
            || application_slot.ceremony_context_hash().into_bytes() != self.ceremony_context_hash
            || application_slot.action_context_hash().into_bytes() != self.action_context_hash
            || application_slot.application_statement_schema_identifier()
                != statement_schema_identifier
            || application_slot.roster_position() != Some(self.roster_position)
            || application_slot.schedule_position().is_some()
            || application_slot.producer_sequence().is_some()
            || application
                .prepared_attempt
                .application_statement_hash()
                .into_bytes()
                != verified_application_statement_hash(
                    self.protocol_version,
                    self.suite_identifier,
                    statement_schema_identifier,
                    &canonical_application_statement_bytes,
                )
        {
            return Err(RefusalReason::WrongContext);
        }
        let pinned = PinnedProofAttempt {
            attempt_identifier: application.prepared_attempt.attempt_identifier(),
            application_slot_hash: application
                .prepared_attempt
                .application_slot_hash()
                .into_bytes(),
            application_statement_hash: application
                .prepared_attempt
                .application_statement_hash()
                .into_bytes(),
        };
        let pinned_attempt = match application.family {
            SetupKeyRelationProofFamily::SameSecret => &mut self.pinned_same_secret_proof_attempt,
            SetupKeyRelationProofFamily::PublicKeyShare => {
                &mut self.pinned_public_key_share_proof_attempt
            }
        };
        if let Some(existing) = pinned_attempt {
            if existing.attempt_identifier != pinned.attempt_identifier
                || existing.application_slot_hash != pinned.application_slot_hash
                || existing.application_statement_hash != pinned.application_statement_hash
            {
                return Err(RefusalReason::ConsumedState);
            }
        } else {
            *pinned_attempt = Some(pinned);
        }
        Ok(())
    }

    fn pin_relinearization_round_one_application(
        &mut self,
        application: &SetupGenerationRelinearizationRoundOneApplication<'_>,
    ) -> Result<(), RefusalReason> {
        let application_slot = application.prepared_attempt.application_slot();
        if application.setup_proof_context_hash != self.setup_proof_context_hash
            || application.participant_identity != self.participant_identity
            || application.roster_position != self.roster_position
            || application.schedule_position != self.relinearization_material.schedule_position()
            || application_slot.suite_identifier().into_bytes() != self.suite_identifier
            || application_slot.ceremony_context_hash().into_bytes() != self.ceremony_context_hash
            || application_slot.action_context_hash().into_bytes() != self.action_context_hash
            || application_slot.application_statement_schema_identifier()
                != ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER
            || application_slot.roster_position() != Some(self.roster_position)
            || application_slot.schedule_position()
                != Some(self.relinearization_material.schedule_position())
            || application_slot.producer_sequence().is_some()
            || application
                .prepared_attempt
                .application_statement_hash()
                .into_bytes()
                != verified_application_statement_hash(
                    self.protocol_version,
                    self.suite_identifier,
                    ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER,
                    application.canonical_application_statement_bytes,
                )
        {
            return Err(RefusalReason::WrongContext);
        }
        let pinned = PinnedProofAttempt {
            attempt_identifier: application.prepared_attempt.attempt_identifier(),
            application_slot_hash: application
                .prepared_attempt
                .application_slot_hash()
                .into_bytes(),
            application_statement_hash: application
                .prepared_attempt
                .application_statement_hash()
                .into_bytes(),
        };
        if let Some(existing) = &self.pinned_relinearization_round_one_proof_attempt {
            if existing.attempt_identifier != pinned.attempt_identifier
                || existing.application_slot_hash != pinned.application_slot_hash
                || existing.application_statement_hash != pinned.application_statement_hash
            {
                return Err(RefusalReason::ConsumedState);
            }
        } else {
            self.pinned_relinearization_round_one_proof_attempt = Some(pinned);
        }
        Ok(())
    }

    fn pin_relinearization_round_two_application(
        &mut self,
        application: &SetupGenerationRelinearizationRoundTwoApplication<'_>,
    ) -> Result<(), RefusalReason> {
        let generated = self
            .generated_relinearization_round_two
            .as_ref()
            .ok_or(RefusalReason::MissingPrerequisite)?;
        if self.relinearization_aggregate_binding.is_none() {
            return Err(RefusalReason::MissingPrerequisite);
        }
        let source = generated.source_authority();
        let round_one_attempt = self
            .pinned_relinearization_round_one_proof_attempt
            .as_ref()
            .ok_or(RefusalReason::MissingPrerequisite)?;
        let application_slot = application.prepared_attempt.application_slot();
        if application.prepared_attempt.attempt_identifier()
            == round_one_attempt.attempt_identifier
            || application.setup_proof_context_hash != source.setup_proof_context_hash()
            || application.participant_identity != source.participant_identity()
            || application.roster_position != source.roster_position()
            || application.schedule_position != source.schedule_position()
            || application.anchor_commitment_roots != source.anchor_commitment_roots()
            || application.round_one_root_pair != source.round_one_root_pair()
            || application.aggregate_round_one_root_pair
                != source.aggregate_round_one_root_pair()
            || application.contribution_root != source.component().contribution_root()
            || application.canonical_application_statement_bytes
                != source.canonical_application_statement_bytes()
            || application_slot.suite_identifier().into_bytes() != self.suite_identifier
            || application_slot.ceremony_context_hash().into_bytes() != self.ceremony_context_hash
            || application_slot.action_context_hash().into_bytes() != self.action_context_hash
            || application_slot.application_statement_schema_identifier()
                != ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER
            || application_slot.roster_position() != Some(self.roster_position)
            || application_slot.schedule_position()
                != Some(self.relinearization_material.schedule_position())
            || application_slot.producer_sequence().is_some()
            || application
                .prepared_attempt
                .application_statement_hash()
                .into_bytes()
                != verified_application_statement_hash(
                    self.protocol_version,
                    self.suite_identifier,
                    ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER,
                    application.canonical_application_statement_bytes,
                )
        {
            return Err(RefusalReason::WrongContext);
        }
        let pinned = PinnedProofAttempt {
            attempt_identifier: application.prepared_attempt.attempt_identifier(),
            application_slot_hash: application
                .prepared_attempt
                .application_slot_hash()
                .into_bytes(),
            application_statement_hash: application
                .prepared_attempt
                .application_statement_hash()
                .into_bytes(),
        };
        if let Some(existing) = &self.pinned_relinearization_round_two_proof_attempt {
            if existing.attempt_identifier != pinned.attempt_identifier
                || existing.application_slot_hash != pinned.application_slot_hash
                || existing.application_statement_hash != pinned.application_statement_hash
            {
                return Err(RefusalReason::ConsumedState);
            }
        } else {
            self.pinned_relinearization_round_two_proof_attempt = Some(pinned);
        }
        Ok(())
    }

    fn pin_galois_application(
        &mut self,
        application: &SetupGenerationGaloisApplication<'_>,
    ) -> Result<(), RefusalReason> {
        let application_slot = application.prepared_attempt.application_slot();
        if application.setup_proof_context_hash != self.setup_proof_context_hash
            || application.roster_hash != self.roster_hash
            || application.participant_identity != self.participant_identity
            || application.roster_position != self.roster_position
            || application.batch_schedule_position != self.galois_batch_schedule_position
            || application_slot.suite_identifier().into_bytes() != self.suite_identifier
            || application_slot.ceremony_context_hash().into_bytes() != self.ceremony_context_hash
            || application_slot.action_context_hash().into_bytes() != self.action_context_hash
            || application_slot.application_statement_schema_identifier()
                != ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER
            || application_slot.roster_position() != Some(self.roster_position)
            || application_slot.schedule_position() != Some(self.galois_batch_schedule_position)
            || application_slot.producer_sequence().is_some()
            || application
                .prepared_attempt
                .application_statement_hash()
                .into_bytes()
                != verified_application_statement_hash(
                    self.protocol_version,
                    self.suite_identifier,
                    ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
                    application.canonical_application_statement_bytes,
                )
        {
            return Err(RefusalReason::WrongContext);
        }
        let pinned = PinnedProofAttempt {
            attempt_identifier: application.prepared_attempt.attempt_identifier(),
            application_slot_hash: application
                .prepared_attempt
                .application_slot_hash()
                .into_bytes(),
            application_statement_hash: application
                .prepared_attempt
                .application_statement_hash()
                .into_bytes(),
        };
        if let Some(existing) = &self.pinned_galois_proof_attempt {
            if existing.attempt_identifier != pinned.attempt_identifier
                || existing.application_slot_hash != pinned.application_slot_hash
                || existing.application_statement_hash != pinned.application_statement_hash
            {
                return Err(RefusalReason::ConsumedState);
            }
        } else {
            self.pinned_galois_proof_attempt = Some(pinned);
        }
        Ok(())
    }

    fn pin_vss_application(
        &mut self,
        application: &SetupGenerationVssApplication<'_>,
    ) -> Result<(), RefusalReason> {
        let application_slot = application.prepared_attempt.application_slot();
        if application.statement.protocol_version() != self.protocol_version
            || application.statement.suite_identifier() != self.suite_identifier
            || application.statement.ceremony_context_hash() != self.ceremony_context_hash
            || application.statement.action_context_hash() != self.action_context_hash
            || application.statement.roster_hash() != self.roster_hash
            || application.statement.public_setup_seed() != self.public_setup_seed
            || application.statement.participant_identity() != self.participant_identity
            || application.statement.roster_position() != self.roster_position
            || application_slot.suite_identifier().into_bytes() != self.suite_identifier
            || application_slot.ceremony_context_hash().into_bytes() != self.ceremony_context_hash
            || application_slot.action_context_hash().into_bytes() != self.action_context_hash
            || application_slot.application_statement_schema_identifier()
                != ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER
            || application_slot.roster_position() != Some(self.roster_position)
            || application_slot.schedule_position().is_some()
            || application_slot.producer_sequence().is_some()
            || application
                .statement
                .ordered_coefficient_material_roots()
                .len()
                != self.vss_material.ordered_coefficient_materials().len()
            || application
                .statement
                .ordered_recipient_share_material_roots()
                .len()
                != self.vss_material.ordered_recipient_share_materials().len()
            || application
                .statement
                .ordered_coefficient_material_roots()
                .iter()
                .zip(self.vss_material.ordered_coefficient_materials())
                .any(|(expected_root, material)| *expected_root != material.compact_source().root())
            || application
                .statement
                .ordered_recipient_share_material_roots()
                .iter()
                .zip(self.vss_material.ordered_recipient_share_materials())
                .any(|(expected_root, material)| *expected_root != material.compact_source().root())
            || application
                .prepared_attempt
                .application_statement_hash()
                .into_bytes()
                != verified_application_statement_hash(
                    self.protocol_version,
                    self.suite_identifier,
                    ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
                    application.canonical_application_statement_bytes,
                )
        {
            return Err(RefusalReason::WrongContext);
        }
        let pinned = PinnedProofAttempt {
            attempt_identifier: application.prepared_attempt.attempt_identifier(),
            application_slot_hash: application
                .prepared_attempt
                .application_slot_hash()
                .into_bytes(),
            application_statement_hash: application
                .prepared_attempt
                .application_statement_hash()
                .into_bytes(),
        };
        if let Some(existing) = &self.pinned_vss_proof_attempt {
            if existing.attempt_identifier != pinned.attempt_identifier
                || existing.application_slot_hash != pinned.application_slot_hash
                || existing.application_statement_hash != pinned.application_statement_hash
            {
                return Err(RefusalReason::ConsumedState);
            }
        } else {
            self.pinned_vss_proof_attempt = Some(pinned);
        }
        Ok(())
    }
    fn retained_coefficient_and_canonical_payload_byte_length(&self) -> Result<u64, RefusalReason> {
        let checked_add = |total: u64, byte_length: usize| {
            total
                .checked_add(
                    u64::try_from(byte_length)
                        .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
                )
                .ok_or(RefusalReason::OutsideSupportedProfile)
        };
        let mut total = checked_add(
            0,
            self.ordered_roster
                .len()
                .checked_mul(Hash512::BYTE_LENGTH)
                .ok_or(RefusalReason::OutsideSupportedProfile)?,
        )?;
        for anchor in &self.anchor_openings {
            total = checked_add(total, anchor.canonical_commitment_bytes.len())?;
            for polynomial in anchor
                .hiding_secret_polynomials
                .iter()
                .chain(anchor.hiding_error_polynomials.iter())
            {
                total = checked_add(total, polynomial.capacity())?;
            }
        }
        total = checked_add(total, self.common_secret_coefficients.capacity())?;
        total = checked_add(
            total,
            self.public_key_share
                .ordered_data_modulus_indices
                .len()
                .checked_mul(size_of::<u16>())
                .ok_or(RefusalReason::OutsideSupportedProfile)?,
        )?;
        for coefficients in &self.public_key_share.ordered_limb_coefficients {
            total = checked_add(
                total,
                coefficients
                    .capacity()
                    .checked_mul(size_of::<u64>())
                    .ok_or(RefusalReason::OutsideSupportedProfile)?,
            )?;
        }
        total = checked_add(
            total,
            self.public_key_share.centered_error_coefficients.capacity(),
        )?;
        let vss_source_accounting = setup_generation_vss_source_allocation_accounting(
            self.vss_material
                .ordered_coefficient_materials()
                .iter()
                .chain(self.vss_material.ordered_recipient_share_materials()),
        )?;
        total = total
            .checked_add(vss_source_accounting.canonical_coefficient_byte_length)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        for payload in self
            .vss_material
            .recipient_private_payloads
            .iter()
            .flatten()
        {
            total = checked_add(total, payload.canonical_bytes.capacity())?;
        }
        total = total
            .checked_add(
                self.relinearization_material
                    .retained_coefficient_payload_byte_length()?,
            )
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        if let Some(generated_round_two) = &self.generated_relinearization_round_two {
            total = total
                .checked_add(generated_round_two.retained_coefficient_payload_byte_length()?)
                .ok_or(RefusalReason::OutsideSupportedProfile)?;
        }
        for entry in &self.ordered_galois_entries {
            total = checked_add(total, entry.component.canonical_bytes.len())?;
            for polynomial in &entry.centered_error_polynomials_by_block {
                total = checked_add(total, polynomial.capacity())?;
            }
        }
        Ok(total)
    }

    fn retained_wrapper_and_catalog_byte_length(&self) -> Result<u64, RefusalReason> {
        let mut accounting = SetupGenerationDescriptorAllocationAccumulator::default();
        accounting.add_usize_byte_length(size_of::<Self>())?;
        accounting.add_usize_byte_length(
            size_of::<usize>()
                .checked_mul(2)
                .and_then(|header| header.checked_add(size_of::<ActionPrivateRandomness>()))
                .ok_or(RefusalReason::OutsideSupportedProfile)?,
        )?;

        accounting.add_usize_byte_length(
            self.anchor_openings
                .len()
                .checked_mul(size_of::<SetupGenerationAnchorOpening>())
                .ok_or(RefusalReason::OutsideSupportedProfile)?,
        )?;
        for anchor in &self.anchor_openings {
            accounting.add_usize_byte_length(
                anchor
                    .hiding_secret_polynomials
                    .len()
                    .checked_add(anchor.hiding_error_polynomials.len())
                    .and_then(|count| count.checked_mul(size_of::<Zeroizing<Vec<i8>>>()))
                    .ok_or(RefusalReason::OutsideSupportedProfile)?,
            )?;
        }
        accounting.add_usize_byte_length(
            self.public_key_share
                .ordered_limb_coefficients
                .len()
                .checked_mul(size_of::<Zeroizing<Vec<u64>>>())
                .ok_or(RefusalReason::OutsideSupportedProfile)?,
        )?;

        let vss_material_count = self
            .vss_material
            .ordered_coefficient_materials()
            .len()
            .checked_add(self.vss_material.ordered_recipient_share_materials().len())
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        accounting.add_usize_byte_length(
            vss_material_count
                .checked_mul(size_of::<SetupGeneratedCommittedMaterial>())
                .ok_or(RefusalReason::OutsideSupportedProfile)?,
        )?;
        accounting.add_usize_byte_length(
            self.vss_material
                .recipient_private_payloads
                .len()
                .checked_mul(size_of::<Option<SetupGeneratedRecipientPrivateVssPayload>>())
                .ok_or(RefusalReason::OutsideSupportedProfile)?,
        )?;
        let vss_source_accounting = setup_generation_vss_source_allocation_accounting(
            self.vss_material
                .ordered_coefficient_materials()
                .iter()
                .chain(self.vss_material.ordered_recipient_share_materials()),
        )?;
        accounting.byte_length = accounting
            .byte_length
            .checked_add(vss_source_accounting.compact_source_byte_length)
            .and_then(|length| {
                length.checked_add(vss_source_accounting.allocation_wrapper_byte_length)
            })
            .ok_or(RefusalReason::OutsideSupportedProfile)?;

        let relinearization_material = &self.relinearization_material;
        for component in [
            relinearization_material.round_one_left_component(),
            relinearization_material.round_one_right_component(),
        ] {
            add_key_switch_component_allocations(&mut accounting, component)?;
        }
        for error_catalog in [
            relinearization_material.round_one_left_errors_by_block(),
            relinearization_material.round_one_right_errors_by_block(),
            relinearization_material.round_two_errors_by_block(),
        ] {
            accounting.add_usize_byte_length(
                error_catalog
                    .len()
                    .checked_mul(size_of::<Zeroizing<Vec<i8>>>())
                    .ok_or(RefusalReason::OutsideSupportedProfile)?,
            )?;
        }

        if let Some(aggregate_binding) = &self.relinearization_aggregate_binding {
            add_relinearization_aggregate_binding_allocations(&mut accounting, aggregate_binding)?;
        }

        if let Some(generated_round_two) = &self.generated_relinearization_round_two {
            add_key_switch_component_allocations(&mut accounting, generated_round_two.component())?;
            accounting.add_usize_byte_length(
                generated_round_two
                    .source_authority()
                    .canonical_application_statement_bytes()
                    .len(),
            )?;
            add_verified_key_switch_component_allocations(
                &mut accounting,
                generated_round_two
                    .source_authority()
                    .component()
                    .material(),
            )?;
        }

        accounting.add_usize_byte_length(
            self.ordered_galois_entries
                .len()
                .checked_mul(size_of::<SetupGeneratedGaloisEntry>())
                .ok_or(RefusalReason::OutsideSupportedProfile)?,
        )?;
        for entry in &self.ordered_galois_entries {
            add_key_switch_component_allocations(&mut accounting, entry.component())?;
            accounting.add_usize_byte_length(
                entry
                    .centered_error_polynomials_by_block()
                    .len()
                    .checked_mul(size_of::<Zeroizing<Vec<i8>>>())
                    .ok_or(RefusalReason::OutsideSupportedProfile)?,
            )?;
        }

        if let Some(binding) = &self.pinned_vss_public_record_binding {
            accounting.add_usize_byte_length(
                binding
                    .ordered_recipient_envelope_hashes
                    .len()
                    .checked_mul(size_of::<Hash512>())
                    .ok_or(RefusalReason::OutsideSupportedProfile)?,
            )?;
            accounting.add_stream_descriptor(&binding.share_linkage_proof)?;
        }
        Ok(accounting.byte_length)
    }

    fn require_vss_proof_phase_release_prerequisites(&self) -> Result<(), RefusalReason> {
        if !self.public_key_share_body_stream_completed
            || self.completed_recipient_private_payload_count
                != usize::from(FOUNDATION_PROFILE.participant_count)
            || !self.vss_material.private_payloads_are_all_moved_out()
            || self.relinearization_aggregate_binding.is_none()
            || self.generated_relinearization_round_two.is_none()
            || self.pinned_vss_proof_attempt.is_none()
            || self
                .pinned_relinearization_round_one_proof_attempt
                .is_none()
            || self
                .pinned_relinearization_round_two_proof_attempt
                .is_none()
            || self.pinned_galois_proof_attempt.is_none()
            || self.pinned_same_secret_proof_attempt.is_none()
            || self.pinned_public_key_share_proof_attempt.is_none()
        {
            return Err(RefusalReason::MissingPrerequisite);
        }
        Ok(())
    }

    fn into_vss_proof_authority(self) -> SetupGenerationVssProofAuthority {
        debug_assert!(self.require_vss_proof_phase_release_prerequisites().is_ok());
        let Self {
            protocol_version,
            suite_identifier,
            manifest_hash,
            ceremony_context_hash,
            action_context_hash,
            roster_hash,
            ordered_roster,
            setup_proof_context_hash,
            source_setup_intent_object_hash,
            participant_identity,
            roster_position,
            setup_attempt_identifier,
            action_randomness_authorization_hash,
            action_private_randomness,
            public_setup_seed,
            vss_material,
            pinned_vss_proof_attempt,
            pinned_vss_public_record_binding,
            ..
        } = self;
        let (ordered_coefficient_materials, ordered_recipient_share_materials) =
            vss_material.into_proof_materials();
        SetupGenerationVssProofAuthority {
            protocol_version,
            suite_identifier,
            manifest_hash,
            ceremony_context_hash,
            action_context_hash,
            roster_hash,
            ordered_roster,
            setup_proof_context_hash,
            source_setup_intent_object_hash,
            participant_identity,
            roster_position,
            setup_attempt_identifier,
            action_randomness_authorization_hash,
            action_private_randomness,
            public_setup_seed,
            ordered_coefficient_materials,
            ordered_recipient_share_materials,
            pinned_vss_proof_attempt,
            pinned_vss_public_record_binding,
        }
    }
}

/// Public record facts recomputed from one live browser-owned setup authority.
/// The roots stay inside Rust and are exposed only to the canonical carrier
/// encoder in this WASM instance.
pub(crate) struct SetupGenerationDealerPublicRecordSource {
    suite_identifier: Hash512,
    ceremony_context_hash: Hash512,
    action_context_hash: Hash512,
    participant_identity: ParticipantIdentity,
    roster_position: u16,
    public_setup_seed: Hash512,
    ordered_coefficient_material_roots: Box<[Hash512]>,
    ordered_recipient_share_material_roots: Box<[Hash512]>,
    ordered_recipient_envelope_hashes: Box<[Hash512]>,
    share_linkage_proof: StreamDescriptor,
}

impl SetupGenerationDealerPublicRecordSource {
    pub(crate) const fn suite_identifier(&self) -> Hash512 {
        self.suite_identifier
    }

    pub(crate) const fn ceremony_context_hash(&self) -> Hash512 {
        self.ceremony_context_hash
    }

    pub(crate) const fn action_context_hash(&self) -> Hash512 {
        self.action_context_hash
    }

    pub(crate) const fn participant_identity(&self) -> ParticipantIdentity {
        self.participant_identity
    }

    pub(crate) const fn roster_position(&self) -> u16 {
        self.roster_position
    }

    pub(crate) const fn public_setup_seed(&self) -> Hash512 {
        self.public_setup_seed
    }

    pub(crate) fn ordered_coefficient_material_roots(&self) -> &[Hash512] {
        &self.ordered_coefficient_material_roots
    }

    pub(crate) fn ordered_recipient_share_material_roots(&self) -> &[Hash512] {
        &self.ordered_recipient_share_material_roots
    }

    pub(crate) fn ordered_recipient_envelope_hashes(&self) -> &[Hash512] {
        &self.ordered_recipient_envelope_hashes
    }

    pub(crate) const fn share_linkage_proof(&self) -> &StreamDescriptor {
        &self.share_linkage_proof
    }
}

/// Public, process-local facts for the exact suite-fixed Galois batch. The
/// statement roots are recomputed from the authority-owned component bytes;
/// no caller-provided root enters the proof attempt.
#[derive(Clone)]
pub(crate) struct SetupGenerationGaloisPreparationSource {
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
    batch_schedule_position: u32,
    ordered_contribution_roots: Box<[[u8; Hash512::BYTE_LENGTH]]>,
    canonical_application_statement_bytes: Vec<u8>,
}

impl SetupGenerationGaloisPreparationSource {
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

    pub(crate) const fn batch_schedule_position(&self) -> u32 {
        self.batch_schedule_position
    }

    pub(crate) fn ordered_contribution_roots(&self) -> &[[u8; Hash512::BYTE_LENGTH]] {
        &self.ordered_contribution_roots
    }

    pub(crate) fn canonical_application_statement_bytes(&self) -> &[u8] {
        &self.canonical_application_statement_bytes
    }
}

/// Public, process-local preparation facts derived from one retained setup
/// generation authority. The canonical `0x2110` statement is constructed from
/// recomputed committed-material roots; no caller-supplied statement or root
/// can enter the prover adapter.
#[derive(Clone)]
pub(crate) struct SetupGenerationVssPreparationSource {
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
    public_setup_seed: [u8; Hash512::BYTE_LENGTH],
    canonical_application_statement_bytes: Vec<u8>,
}

impl SetupGenerationVssPreparationSource {
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

    pub(crate) const fn public_setup_seed(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.public_setup_seed
    }

    pub(crate) fn canonical_application_statement_bytes(&self) -> &[u8] {
        &self.canonical_application_statement_bytes
    }
}

/// Public preparation facts for one exact selected setup key relation. Every
/// statement root is recomputed from retained browser-owned setup material.
#[derive(Clone)]
pub(crate) struct SetupGenerationKeyRelationPreparationSource {
    family: SetupKeyRelationProofFamily,
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
    public_setup_seed: [u8; Hash512::BYTE_LENGTH],
    canonical_application_statement_bytes: Vec<u8>,
}

impl SetupGenerationKeyRelationPreparationSource {
    pub(crate) const fn family(&self) -> SetupKeyRelationProofFamily {
        self.family
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

    pub(crate) const fn public_setup_seed(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.public_setup_seed
    }

    pub(crate) fn canonical_application_statement_bytes(&self) -> &[u8] {
        &self.canonical_application_statement_bytes
    }
}

/// Exact reset-safe attempt binding for one authority-derived setup key
/// relation. The caller cannot supply a witness or statement root.
pub(crate) struct SetupGenerationKeyRelationApplication<'statement> {
    family: SetupKeyRelationProofFamily,
    prepared_attempt: PreparedActionProofAttemptSource,
    canonical_application_statement_bytes: &'statement [u8],
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    roster_position: u16,
}

impl<'statement> SetupGenerationKeyRelationApplication<'statement> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn from_runtime_binding(
        family: SetupKeyRelationProofFamily,
        prepared_attempt: PreparedActionProofAttemptSource,
        canonical_application_statement_bytes: &'statement [u8],
        setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
        roster_hash: [u8; Hash512::BYTE_LENGTH],
        participant_identity: [u8; Hash512::BYTE_LENGTH],
        roster_position: u16,
    ) -> Self {
        Self {
            family,
            prepared_attempt,
            canonical_application_statement_bytes,
            setup_proof_context_hash,
            roster_hash,
            participant_identity,
            roster_position,
        }
    }
}

/// Borrowed, non-serializable source for the selected same-secret and public-
/// key-share provers. Secret reads remain inside the authority callback.
pub(crate) struct SetupGenerationKeyRelationSource<'authority, 'statement> {
    authority_identifier: u32,
    authority: &'authority SetupGenerationAuthority,
    application: &'authority SetupGenerationKeyRelationApplication<'statement>,
}

pub(crate) struct PreparedExactSameSecretGenerationSources {
    pub(crate) authorization: CommonProofGenerationAuthorization,
    pub(crate) relation_plan: CommonProofRelationPlanCapability,
    pub(crate) relation_plan_variant: RelationPlanVariant,
    pub(crate) relation_context: RelationPlanCheckContext,
    pub(crate) relation_trees: Vec<RelationProofTreeInput>,
    pub(crate) source_polynomials: SetupKeyRelationSourcePolynomialAdapter,
    pub(crate) private_coins: PrivateRandomnessCommonProofCoinSource,
    pub(crate) canonical_application_statement_bytes: Vec<u8>,
    pub(crate) generation_binding_hash: [u8; Hash512::BYTE_LENGTH],
    pub(crate) action_context_hash: [u8; Hash512::BYTE_LENGTH],
    pub(crate) public_setup_seed: [u8; Hash512::BYTE_LENGTH],
}

impl SetupGenerationKeyRelationSource<'_, '_> {
    pub(crate) const fn authority_identifier(&self) -> u32 {
        self.authority_identifier
    }

    pub(crate) const fn family(&self) -> SetupKeyRelationProofFamily {
        self.application.family
    }

    pub(crate) const fn protocol_version(&self) -> u16 {
        self.authority.protocol_version
    }

    pub(crate) const fn suite_identifier(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.authority.suite_identifier
    }

    pub(crate) const fn roster_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.authority.roster_hash
    }

    pub(crate) const fn action_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.authority.action_context_hash
    }

    pub(crate) const fn setup_proof_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.authority.setup_proof_context_hash
    }

    pub(crate) const fn source_setup_intent_object_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.authority.source_setup_intent_object_hash
    }

    pub(crate) const fn participant_identity(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.authority.participant_identity
    }

    pub(crate) const fn roster_position(&self) -> u16 {
        self.authority.roster_position
    }

    pub(crate) const fn setup_attempt_identifier(&self) -> [u8; 32] {
        self.authority.setup_attempt_identifier
    }

    pub(crate) const fn action_randomness_authorization_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.authority.action_randomness_authorization_hash
    }

    pub(crate) const fn public_setup_seed(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.authority.public_setup_seed
    }

    pub(crate) fn common_secret_coefficients(&self) -> &[i8] {
        self.authority.common_secret_coefficients.as_slice()
    }

    pub(crate) fn ring_degree(&self) -> usize {
        self.authority.common_secret_coefficients.len()
    }

    pub(crate) fn anchor_openings(&self) -> &[SetupGenerationAnchorOpening] {
        &self.authority.anchor_openings
    }

    pub(crate) const fn public_key_share(&self) -> &SetupGeneratedPublicKeyShare {
        &self.authority.public_key_share
    }

    pub(crate) fn degree_zero_material(
        &self,
        degree_zero_material_ordinal: usize,
    ) -> Result<&SetupGeneratedCommittedMaterial, RefusalReason> {
        self.authority
            .degree_zero_material(degree_zero_material_ordinal)
    }

    pub(crate) const fn prepared_attempt(&self) -> &PreparedActionProofAttemptSource {
        &self.application.prepared_attempt
    }

    pub(crate) fn canonical_application_statement_bytes(&self) -> &[u8] {
        self.application.canonical_application_statement_bytes
    }

    fn absorb_anchor_opening_witness(
        &self,
        binding: &mut PersistentProofWitnessCoinBinding,
    ) -> Result<(), RefusalReason> {
        binding
            .absorb_canonical_bytes(
                &u64::try_from(self.anchor_openings().len())
                    .map_err(|_| RefusalReason::OutsideSupportedProfile)?
                    .to_le_bytes(),
            )
            .map_err(|error| error.refusal_reason)?;
        for (anchor_ordinal, anchor) in self.anchor_openings().iter().enumerate() {
            binding
                .absorb_canonical_bytes(
                    &u64::try_from(anchor_ordinal)
                        .map_err(|_| RefusalReason::OutsideSupportedProfile)?
                        .to_le_bytes(),
                )
                .map_err(|error| error.refusal_reason)?;
            binding
                .absorb_canonical_bytes(&anchor.commitment_data_prime_index().to_le_bytes())
                .map_err(|error| error.refusal_reason)?;
            binding
                .absorb_canonical_bytes(&anchor.public_polynomial_context_hash())
                .map_err(|error| error.refusal_reason)?;
            binding
                .absorb_canonical_bytes(&anchor.root())
                .map_err(|error| error.refusal_reason)?;
            binding
                .absorb_canonical_bytes(anchor.canonical_commitment_bytes())
                .map_err(|error| error.refusal_reason)?;
            binding
                .absorb_canonical_bytes(
                    &u64::try_from(anchor.hiding_secret_polynomials().len())
                        .map_err(|_| RefusalReason::OutsideSupportedProfile)?
                        .to_le_bytes(),
                )
                .map_err(|error| error.refusal_reason)?;
            for (polynomial_ordinal, polynomial) in
                anchor.hiding_secret_polynomials().iter().enumerate()
            {
                binding
                    .absorb_canonical_bytes(
                        &u64::try_from(polynomial_ordinal)
                            .map_err(|_| RefusalReason::OutsideSupportedProfile)?
                            .to_le_bytes(),
                    )
                    .map_err(|error| error.refusal_reason)?;
                binding
                    .absorb_canonical_i8_values(polynomial)
                    .map_err(|error| error.refusal_reason)?;
            }
            binding
                .absorb_canonical_bytes(
                    &u64::try_from(anchor.hiding_error_polynomials().len())
                        .map_err(|_| RefusalReason::OutsideSupportedProfile)?
                        .to_le_bytes(),
                )
                .map_err(|error| error.refusal_reason)?;
            for (polynomial_ordinal, polynomial) in
                anchor.hiding_error_polynomials().iter().enumerate()
            {
                binding
                    .absorb_canonical_bytes(
                        &u64::try_from(polynomial_ordinal)
                            .map_err(|_| RefusalReason::OutsideSupportedProfile)?
                            .to_le_bytes(),
                    )
                    .map_err(|error| error.refusal_reason)?;
                binding
                    .absorb_canonical_i8_values(polynomial)
                    .map_err(|error| error.refusal_reason)?;
            }
        }
        Ok(())
    }

    pub(crate) fn witness_bound_attempt(
        &self,
    ) -> Result<WitnessBoundPreparedActionProofAttemptSource, RefusalReason> {
        let persistent_proof_coin_input = PersistentProofCoinInput::new(
            self.prepared_attempt().application_slot(),
            self.prepared_attempt().application_statement_hash(),
        )
        .map_err(|error| error.refusal_reason)?;
        let mut binding = self
            .authority
            .action_private_randomness
            .begin_persistent_proof_witness_coin_binding(&persistent_proof_coin_input)
            .map_err(|error| error.refusal_reason)?;
        let witness_domain = match self.family() {
            SetupKeyRelationProofFamily::SameSecret => {
                SAME_SECRET_CANONICAL_SEMANTIC_WITNESS_DOMAIN
            }
            SetupKeyRelationProofFamily::PublicKeyShare => {
                PUBLIC_KEY_SHARE_CANONICAL_SEMANTIC_WITNESS_DOMAIN
            }
        };
        binding
            .absorb_canonical_bytes(witness_domain)
            .map_err(|error| error.refusal_reason)?;
        binding
            .absorb_canonical_i8_values(self.common_secret_coefficients())
            .map_err(|error| error.refusal_reason)?;
        self.absorb_anchor_opening_witness(&mut binding)?;
        match self.family() {
            SetupKeyRelationProofFamily::SameSecret => {
                let material_count = self.authority.degree_zero_material_count()?;
                binding
                    .absorb_canonical_bytes(
                        &u64::try_from(material_count)
                            .map_err(|_| RefusalReason::OutsideSupportedProfile)?
                            .to_le_bytes(),
                    )
                    .map_err(|error| error.refusal_reason)?;
                for material_ordinal in 0..material_count {
                    let material = self.degree_zero_material(material_ordinal)?;
                    let authenticated_source = material.owned_authenticated_source();
                    binding
                        .absorb_canonical_bytes(
                            &u64::try_from(material_ordinal)
                                .map_err(|_| RefusalReason::OutsideSupportedProfile)?
                                .to_le_bytes(),
                        )
                        .map_err(|error| error.refusal_reason)?;
                    binding
                        .absorb_canonical_bytes(
                            &authenticated_source
                                .compact_source()
                                .material_context_hash(),
                        )
                        .map_err(|error| error.refusal_reason)?;
                    binding
                        .absorb_canonical_bytes(&authenticated_source.compact_source().root())
                        .map_err(|error| error.refusal_reason)?;
                    binding
                        .absorb_canonical_bytes(
                            &authenticated_source.canonical_modulus().to_le_bytes(),
                        )
                        .map_err(|error| error.refusal_reason)?;
                    binding
                        .absorb_canonical_u64_values(authenticated_source.canonical_message())
                        .map_err(|error| error.refusal_reason)?;
                }
            }
            SetupKeyRelationProofFamily::PublicKeyShare => {
                let public_key_share = self.public_key_share();
                binding
                    .absorb_canonical_bytes(&public_key_share.public_polynomial_context_hash())
                    .map_err(|error| error.refusal_reason)?;
                binding
                    .absorb_canonical_bytes(&public_key_share.root())
                    .map_err(|error| error.refusal_reason)?;
                binding
                    .absorb_canonical_bytes(
                        &u64::try_from(public_key_share.ordered_limb_coefficients().len())
                            .map_err(|_| RefusalReason::OutsideSupportedProfile)?
                            .to_le_bytes(),
                    )
                    .map_err(|error| error.refusal_reason)?;
                for (limb_ordinal, (data_modulus_index, coefficients)) in public_key_share
                    .ordered_data_modulus_indices()
                    .iter()
                    .copied()
                    .zip(public_key_share.ordered_limb_coefficients())
                    .enumerate()
                {
                    binding
                        .absorb_canonical_bytes(
                            &u64::try_from(limb_ordinal)
                                .map_err(|_| RefusalReason::OutsideSupportedProfile)?
                                .to_le_bytes(),
                        )
                        .map_err(|error| error.refusal_reason)?;
                    binding
                        .absorb_canonical_bytes(&data_modulus_index.to_le_bytes())
                        .map_err(|error| error.refusal_reason)?;
                    binding
                        .absorb_canonical_u64_values(coefficients)
                        .map_err(|error| error.refusal_reason)?;
                }
                binding
                    .absorb_canonical_i8_values(public_key_share.centered_error_coefficients())
                    .map_err(|error| error.refusal_reason)?;
            }
        }
        bind_prepared_action_proof_attempt_to_canonical_witness(*self.prepared_attempt(), binding)
            .map_err(|error| error.refusal_reason)
    }

    fn private_coin_source(
        &self,
        pre_output_generation_binding_hash: [u8; Hash512::BYTE_LENGTH],
        relation_plan_variant: &RelationPlanVariant,
        witness_bound_attempt: WitnessBoundPreparedActionProofAttemptSource,
    ) -> Result<PrivateRandomnessCommonProofCoinSource, RefusalReason> {
        if pre_output_generation_binding_hash == [0_u8; Hash512::BYTE_LENGTH]
            || witness_bound_attempt.application_slot()
                != self.application.prepared_attempt.application_slot()
            || witness_bound_attempt.application_statement_hash()
                != self
                    .application
                    .prepared_attempt
                    .application_statement_hash()
        {
            return Err(RefusalReason::WrongContext);
        }
        let coordinate_capacity =
            CommonProofPrivateCoinCoordinateCapacity::from_relation_plan_variant(
                relation_plan_variant,
            )
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        PrivateRandomnessCommonProofCoinSource::new(
            Rc::clone(&self.authority.action_private_randomness),
            self.family().statement_schema_identifier(),
            Hash512::from_bytes(pre_output_generation_binding_hash),
            witness_bound_attempt.private_randomness_attempt_identifier(),
            coordinate_capacity,
        )
        .map_err(|_| RefusalReason::WrongContext)
    }

    pub(crate) fn prepare_exact_same_secret_generation_sources(
        &self,
        relation_plan: CommonProofRelationPlanCapability,
    ) -> Result<PreparedExactSameSecretGenerationSources, SetupKeyRelationGenerationPreparationError>
    {
        if self.family() != SetupKeyRelationProofFamily::SameSecret {
            return Err(RefusalReason::WrongContext.into());
        }
        let statement_schema_identifier = self.family().statement_schema_identifier();
        let relation_context = selected_relation_plan_check_context(statement_schema_identifier)
            .ok_or(RefusalReason::UnsupportedVersionOrSuite)?;
        let input = selected_same_secret_relation_plan_input()
            .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)?;
        let compiled_relation =
            compile_same_secret_relation_with_source_layout(&input, &relation_context)
                .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)?;
        let relation_plan_variant = compiled_relation
            .relation_plan
            .select_variant(None, None)
            .map_err(|_| CommonProofProverError::InvalidColumn)?
            .clone();
        let relation_trees = same_secret_relation_tree_inputs(
            self,
            &relation_plan_variant,
            &compiled_relation.source_layout,
        )?;
        let source_polynomials = SetupKeyRelationSourcePolynomialAdapter::new_same_secret(
            self,
            &relation_plan,
            relation_plan_variant.clone(),
            relation_context.clone(),
            self.ring_degree(),
            compiled_relation.source_layout,
        )?;
        let witness_bound_attempt = self.witness_bound_attempt()?;
        let authorization =
            CommonProofGenerationAuthorization::from_witness_bound_authenticated_attempt(
                witness_bound_attempt,
                &relation_plan,
                self.protocol_version(),
                self.canonical_application_statement_bytes(),
            )?;
        let generation_binding_hash = authorization.binding_hash();
        let private_coins = self.private_coin_source(
            generation_binding_hash,
            &relation_plan_variant,
            witness_bound_attempt,
        )?;
        Ok(PreparedExactSameSecretGenerationSources {
            authorization,
            relation_plan,
            relation_plan_variant,
            relation_context,
            relation_trees,
            source_polynomials,
            private_coins,
            canonical_application_statement_bytes: self
                .canonical_application_statement_bytes()
                .to_vec(),
            generation_binding_hash,
            action_context_hash: self.action_context_hash(),
            public_setup_seed: self.public_setup_seed(),
        })
    }

    pub(crate) fn prepare_common_generation(
        &self,
        relation_plan: CommonProofRelationPlanCapability,
        limits: CommonProofRuntimeLimits,
    ) -> Result<PreparedCommonProofGeneration, SetupKeyRelationGenerationPreparationError> {
        if self.family() == SetupKeyRelationProofFamily::SameSecret {
            let prepared = self.prepare_exact_same_secret_generation_sources(relation_plan)?;
            if prepared.generation_binding_hash != prepared.authorization.binding_hash()
                || prepared.action_context_hash != self.action_context_hash()
                || prepared.public_setup_seed != self.public_setup_seed()
                || prepared
                    .relation_plan_variant
                    .canonical_hash()
                    .map_err(|_| CommonProofProverError::InvalidInput)?
                    != prepared.relation_plan.relation_plan_variant_hash()
                || &prepared.relation_context
                    != selected_relation_plan_check_context(
                        SetupKeyRelationProofFamily::SameSecret.statement_schema_identifier(),
                    )
                    .as_ref()
                    .ok_or(RefusalReason::UnsupportedVersionOrSuite)?
            {
                return Err(RefusalReason::WrongContext.into());
            }
            return PreparedCommonProofGeneration::from_row_code_whir_sources(
                prepared.authorization,
                prepared.relation_plan,
                prepared.canonical_application_statement_bytes,
                prepared.relation_trees,
                limits,
                CommonProofGenerationSources::new(
                    prepared.private_coins,
                    prepared.source_polynomials,
                ),
            )
            .map_err(SetupKeyRelationGenerationPreparationError::from);
        }
        let statement_schema_identifier = self.family().statement_schema_identifier();
        let relation_context = selected_relation_plan_check_context(statement_schema_identifier)
            .ok_or(RefusalReason::UnsupportedVersionOrSuite)?;
        let ring_degree = self.ring_degree();
        let input = selected_public_key_share_relation_plan_input()
            .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)?;
        let compiled_relation =
            compile_public_key_share_relation_with_source_layout(&input, &relation_context)
                .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)?;
        let relation_plan_variant = compiled_relation
            .relation_plan
            .select_variant(None, None)
            .map_err(|_| CommonProofProverError::InvalidColumn)?
            .clone();
        let relation_trees = public_key_share_relation_tree_inputs(
            self,
            &relation_plan_variant,
            &compiled_relation.source_layout,
        )?;
        let source_polynomials = SetupKeyRelationSourcePolynomialAdapter::new_public_key_share(
            self,
            &relation_plan,
            relation_plan_variant.clone(),
            relation_context,
            ring_degree,
            compiled_relation.source_layout,
        )?;
        let witness_bound_attempt = self.witness_bound_attempt()?;
        let authorization =
            CommonProofGenerationAuthorization::from_witness_bound_authenticated_attempt(
                witness_bound_attempt,
                &relation_plan,
                self.protocol_version(),
                self.canonical_application_statement_bytes(),
            )?;
        let private_coins = self.private_coin_source(
            authorization.binding_hash(),
            &relation_plan_variant,
            witness_bound_attempt,
        )?;
        PreparedCommonProofGeneration::from_exact_family_sources(
            authorization,
            relation_plan,
            self.canonical_application_statement_bytes().to_vec(),
            relation_trees,
            limits,
            CommonProofGenerationSources::new(private_coins, source_polynomials),
        )
        .map_err(SetupKeyRelationGenerationPreparationError::from)
    }
}

/// Exact decoded `0x2110` statement joined to the reset-safe proof attempt.
/// The root arrays remain borrowed from the canonical decoder and are matched
/// in order against the recomputed browser-owned committed-material trees.
pub(crate) struct SetupGenerationVssApplication<'statement> {
    prepared_attempt: PreparedActionProofAttemptSource,
    canonical_application_statement_bytes: &'statement [u8],
    statement: &'statement SelectedVssShareLinkageStatement,
}

#[derive(Debug)]
pub(crate) enum SetupKeyRelationGenerationPreparationError {
    Refusal(RefusalReason),
    Prover(CommonProofProverError),
    Runtime(CommonProofRuntimeError),
    Preparation(CommonProofGenerationPreparationError),
}

impl From<RefusalReason> for SetupKeyRelationGenerationPreparationError {
    fn from(error: RefusalReason) -> Self {
        Self::Refusal(error)
    }
}

impl From<CommonProofProverError> for SetupKeyRelationGenerationPreparationError {
    fn from(error: CommonProofProverError) -> Self {
        Self::Prover(error)
    }
}

impl From<CommonProofRuntimeError> for SetupKeyRelationGenerationPreparationError {
    fn from(error: CommonProofRuntimeError) -> Self {
        Self::Runtime(error)
    }
}

impl From<CommonProofGenerationPreparationError> for SetupKeyRelationGenerationPreparationError {
    fn from(error: CommonProofGenerationPreparationError) -> Self {
        Self::Preparation(error)
    }
}

#[derive(Debug)]
pub(crate) enum SetupGaloisGenerationPreparationError {
    Refusal(RefusalReason),
    Prover(CommonProofProverError),
    Runtime(CommonProofRuntimeError),
    Preparation(CommonProofGenerationPreparationError),
}

#[derive(Debug)]
pub(crate) enum SetupRelinearizationGenerationPreparationError {
    Refusal(RefusalReason),
    Prover(CommonProofProverError),
    Runtime(CommonProofRuntimeError),
    Preparation(CommonProofGenerationPreparationError),
}

impl From<RefusalReason> for SetupRelinearizationGenerationPreparationError {
    fn from(error: RefusalReason) -> Self {
        Self::Refusal(error)
    }
}

impl From<CommonProofProverError> for SetupRelinearizationGenerationPreparationError {
    fn from(error: CommonProofProverError) -> Self {
        Self::Prover(error)
    }
}

impl From<CommonProofRuntimeError> for SetupRelinearizationGenerationPreparationError {
    fn from(error: CommonProofRuntimeError) -> Self {
        Self::Runtime(error)
    }
}

impl From<CommonProofGenerationPreparationError>
    for SetupRelinearizationGenerationPreparationError
{
    fn from(error: CommonProofGenerationPreparationError) -> Self {
        Self::Preparation(error)
    }
}

impl From<RefusalReason> for SetupGaloisGenerationPreparationError {
    fn from(error: RefusalReason) -> Self {
        Self::Refusal(error)
    }
}

impl From<CommonProofProverError> for SetupGaloisGenerationPreparationError {
    fn from(error: CommonProofProverError) -> Self {
        Self::Prover(error)
    }
}

impl From<CommonProofRuntimeError> for SetupGaloisGenerationPreparationError {
    fn from(error: CommonProofRuntimeError) -> Self {
        Self::Runtime(error)
    }
}

impl From<CommonProofGenerationPreparationError> for SetupGaloisGenerationPreparationError {
    fn from(error: CommonProofGenerationPreparationError) -> Self {
        Self::Preparation(error)
    }
}

#[derive(Debug)]
pub(crate) enum SetupVssGenerationPreparationError {
    Refusal(RefusalReason),
    Prover(CommonProofProverError),
    Runtime(CommonProofRuntimeError),
    Preparation(CommonProofGenerationPreparationError),
}

impl From<RefusalReason> for SetupVssGenerationPreparationError {
    fn from(error: RefusalReason) -> Self {
        Self::Refusal(error)
    }
}

impl From<CommonProofProverError> for SetupVssGenerationPreparationError {
    fn from(error: CommonProofProverError) -> Self {
        Self::Prover(error)
    }
}

impl From<CommonProofRuntimeError> for SetupVssGenerationPreparationError {
    fn from(error: CommonProofRuntimeError) -> Self {
        Self::Runtime(error)
    }
}

impl From<CommonProofGenerationPreparationError> for SetupVssGenerationPreparationError {
    fn from(error: CommonProofGenerationPreparationError) -> Self {
        Self::Preparation(error)
    }
}

impl<'statement> SetupGenerationVssApplication<'statement> {
    pub(crate) const fn from_decoded_statement(
        prepared_attempt: PreparedActionProofAttemptSource,
        canonical_application_statement_bytes: &'statement [u8],
        statement: &'statement SelectedVssShareLinkageStatement,
    ) -> Self {
        Self {
            prepared_attempt,
            canonical_application_statement_bytes,
            statement,
        }
    }
}

/// Borrowed, non-serializable VSS generation source. Both public tree material
/// and secret witness values remain inside the Rust callback that constructs
/// the exact family adapter.
pub(crate) struct SetupGenerationVssSource<'authority, 'statement> {
    authority: &'authority SetupGenerationVssProofAuthority,
    application: &'authority SetupGenerationVssApplication<'statement>,
}

impl SetupGenerationVssSource<'_, '_> {
    pub(crate) const fn protocol_version(&self) -> u16 {
        self.authority.protocol_version
    }

    pub(crate) const fn suite_identifier(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.authority.suite_identifier
    }

    pub(crate) fn ordered_coefficient_materials(&self) -> &[SetupGeneratedCommittedMaterial] {
        self.authority.ordered_coefficient_materials()
    }

    pub(crate) fn ordered_recipient_share_materials(&self) -> &[SetupGeneratedCommittedMaterial] {
        self.authority.ordered_recipient_share_materials()
    }

    pub(crate) const fn prepared_attempt(&self) -> &PreparedActionProofAttemptSource {
        &self.application.prepared_attempt
    }

    pub(crate) fn canonical_application_statement_bytes(&self) -> &[u8] {
        self.application.canonical_application_statement_bytes
    }

    pub(crate) fn private_coin_source(
        &self,
        pre_output_generation_binding_hash: [u8; Hash512::BYTE_LENGTH],
        relation_plan_variant: &RelationPlanVariant,
        witness_bound_attempt: WitnessBoundPreparedActionProofAttemptSource,
    ) -> Result<PrivateRandomnessCommonProofCoinSource, RefusalReason> {
        if pre_output_generation_binding_hash == [0_u8; Hash512::BYTE_LENGTH] {
            return Err(RefusalReason::WrongContext);
        }
        if witness_bound_attempt.application_slot()
            != self.application.prepared_attempt.application_slot()
            || witness_bound_attempt.application_statement_hash()
                != self
                    .application
                    .prepared_attempt
                    .application_statement_hash()
        {
            return Err(RefusalReason::WrongContext);
        }
        let attempt_identifier = witness_bound_attempt.private_randomness_attempt_identifier();
        let coordinate_capacity =
            CommonProofPrivateCoinCoordinateCapacity::from_relation_plan_variant(
                relation_plan_variant,
            )
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        PrivateRandomnessCommonProofCoinSource::new(
            Rc::clone(&self.authority.action_private_randomness),
            ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
            Hash512::from_bytes(pre_output_generation_binding_hash),
            attempt_identifier,
            coordinate_capacity,
        )
        .map_err(|_| RefusalReason::WrongContext)
    }

    fn source_polynomial_adapter(
        &self,
        relation_plan: &CommonProofRelationPlanCapability,
        compiled_relation_plan: &crate::bgv::proof_suite::CompiledRelationPlan,
        input: crate::bgv::proof_suite::CommittedMaterialRelationPlanInput,
        context: &crate::bgv::proof_suite::RelationPlanCheckContext,
    ) -> Result<CommittedMaterialSourcePolynomialAdapter, CommonProofProverError> {
        let sharing_limb_count = input.sharing_data_modulus_indices.len();
        let threshold = usize::from(FOUNDATION_PROFILE.reconstruction_threshold);
        let participant_count = usize::from(FOUNDATION_PROFILE.participant_count);
        let expected_root_count = sharing_limb_count
            .checked_mul(
                threshold
                    .checked_add(participant_count)
                    .ok_or(CommonProofProverError::CountOverflow)?,
            )
            .ok_or(CommonProofProverError::CountOverflow)?;
        let mut ordered_sources = Vec::with_capacity(expected_root_count);
        for sharing_limb_ordinal in 0..sharing_limb_count {
            for coefficient_ordinal in 0..threshold {
                let material_ordinal = sharing_limb_ordinal
                    .checked_mul(threshold)
                    .and_then(|offset| offset.checked_add(coefficient_ordinal))
                    .ok_or(CommonProofProverError::CountOverflow)?;
                let material = self
                    .ordered_coefficient_materials()
                    .get(material_ordinal)
                    .ok_or(CommonProofProverError::InvalidColumn)?;
                ordered_sources.push(material.owned_authenticated_source());
            }
            for recipient_ordinal in 0..participant_count {
                let material_ordinal = sharing_limb_ordinal
                    .checked_mul(participant_count)
                    .and_then(|offset| offset.checked_add(recipient_ordinal))
                    .ok_or(CommonProofProverError::CountOverflow)?;
                let material = self
                    .ordered_recipient_share_materials()
                    .get(material_ordinal)
                    .ok_or(CommonProofProverError::InvalidColumn)?;
                ordered_sources.push(material.owned_authenticated_source());
            }
        }
        CommittedMaterialSourcePolynomialAdapter::new_vss_share_linkage(
            input,
            context,
            compiled_relation_plan,
            self.protocol_version(),
            self.suite_identifier(),
            self.prepared_attempt()
                .application_statement_hash()
                .into_bytes(),
            relation_plan,
            ordered_sources,
        )
    }

    pub(crate) fn prepare_common_generation(
        &self,
        relation_plan: CommonProofRelationPlanCapability,
        limits: CommonProofRuntimeLimits,
    ) -> Result<PreparedCommonProofGeneration, SetupVssGenerationPreparationError> {
        let context = selected_relation_plan_check_context(
            ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
        )
        .ok_or(RefusalReason::UnsupportedVersionOrSuite)?;
        let input = selected_committed_material_relation_plan_input()
            .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)?;
        let compiled_relation_plan = compile_vss_share_linkage_relation_plan(&input, &context)
            .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)?;
        let variant = compiled_relation_plan
            .select_variant(None, None)
            .map_err(|_| CommonProofProverError::InvalidColumn)?;
        let mut source_polynomials = self.source_polynomial_adapter(
            &relation_plan,
            &compiled_relation_plan,
            input,
            &context,
        )?;
        let persistent_proof_coin_input = PersistentProofCoinInput::new(
            self.prepared_attempt().application_slot(),
            self.prepared_attempt().application_statement_hash(),
        )
        .map_err(|_| RefusalReason::WrongContext)?;
        let mut witness_binding = self
            .authority
            .action_private_randomness
            .begin_persistent_proof_witness_coin_binding(&persistent_proof_coin_input)
            .map_err(|_| RefusalReason::WrongContext)?;
        source_polynomials
            .absorb_canonical_semantic_witness(&mut witness_binding)
            .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
        let witness_bound_attempt = bind_prepared_action_proof_attempt_to_canonical_witness(
            *self.prepared_attempt(),
            witness_binding,
        )
        .map_err(|_| RefusalReason::WrongContext)?;
        let authorization =
            CommonProofGenerationAuthorization::from_witness_bound_authenticated_attempt(
                witness_bound_attempt,
                &relation_plan,
                self.protocol_version(),
                self.canonical_application_statement_bytes(),
            )?;
        let relation_trees = source_polynomials.relation_tree_inputs()?;
        let private_coins =
            self.private_coin_source(authorization.binding_hash(), variant, witness_bound_attempt)?;
        PreparedCommonProofGeneration::from_exact_family_sources(
            authorization,
            relation_plan,
            self.canonical_application_statement_bytes().to_vec(),
            relation_trees,
            limits,
            CommonProofGenerationSources::new(private_coins, source_polynomials),
        )
        .map_err(SetupVssGenerationPreparationError::from)
    }
}

pub(crate) struct SetupGenerationRelinearizationRoundOneApplication<'statement> {
    prepared_attempt: PreparedActionProofAttemptSource,
    canonical_application_statement_bytes: &'statement [u8],
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    roster_position: u16,
    schedule_position: u32,
}

impl<'statement> SetupGenerationRelinearizationRoundOneApplication<'statement> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn from_decoded_statement(
        prepared_attempt: PreparedActionProofAttemptSource,
        canonical_application_statement_bytes: &'statement [u8],
        setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
        participant_identity: [u8; Hash512::BYTE_LENGTH],
        roster_position: u16,
        schedule_position: u32,
    ) -> Self {
        Self {
            prepared_attempt,
            canonical_application_statement_bytes,
            setup_proof_context_hash,
            participant_identity,
            roster_position,
            schedule_position,
        }
    }
}

pub(crate) struct SetupGenerationRelinearizationRoundOneSource<'authority, 'statement> {
    authority_identifier: u32,
    authority: &'authority SetupGenerationAuthority,
    application: &'authority SetupGenerationRelinearizationRoundOneApplication<'statement>,
}

impl SetupGenerationRelinearizationRoundOneSource<'_, '_> {
    pub(crate) const fn authority_identifier(&self) -> u32 {
        self.authority_identifier
    }

    pub(crate) const fn protocol_version(&self) -> u16 {
        self.authority.protocol_version
    }

    pub(crate) const fn suite_identifier(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.authority.suite_identifier
    }

    pub(crate) const fn roster_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.authority.roster_hash
    }

    pub(crate) const fn setup_proof_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.authority.setup_proof_context_hash
    }

    pub(crate) const fn source_setup_intent_object_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.authority.source_setup_intent_object_hash
    }

    pub(crate) const fn participant_identity(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.authority.participant_identity
    }

    pub(crate) const fn roster_position(&self) -> u16 {
        self.authority.roster_position
    }

    pub(crate) const fn setup_attempt_identifier(&self) -> [u8; 32] {
        self.authority.setup_attempt_identifier
    }

    pub(crate) const fn action_randomness_authorization_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.authority.action_randomness_authorization_hash
    }

    pub(crate) const fn public_setup_seed(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.authority.public_setup_seed
    }

    pub(crate) fn anchor_openings(&self) -> &[SetupGenerationAnchorOpening] {
        &self.authority.anchor_openings
    }

    pub(crate) fn common_secret_coefficients(&self) -> &[i8] {
        &self.authority.common_secret_coefficients
    }

    pub(crate) fn ephemeral_secret_coefficients(&self) -> &[i8] {
        self.authority
            .relinearization_material
            .ephemeral_secret_coefficients()
    }

    pub(crate) const fn schedule_position(&self) -> u32 {
        self.authority.relinearization_material.schedule_position()
    }

    pub(crate) const fn round_one_left_component(&self) -> &SetupGeneratedKeySwitchComponent {
        self.authority
            .relinearization_material
            .round_one_left_component()
    }

    pub(crate) const fn round_one_right_component(&self) -> &SetupGeneratedKeySwitchComponent {
        self.authority
            .relinearization_material
            .round_one_right_component()
    }

    pub(crate) fn round_one_left_errors_by_block(&self) -> &[Zeroizing<Vec<i8>>] {
        self.authority
            .relinearization_material
            .round_one_left_errors_by_block()
    }

    pub(crate) fn round_one_right_errors_by_block(&self) -> &[Zeroizing<Vec<i8>>] {
        self.authority
            .relinearization_material
            .round_one_right_errors_by_block()
    }

    pub(crate) const fn prepared_attempt(&self) -> &PreparedActionProofAttemptSource {
        &self.application.prepared_attempt
    }

    pub(crate) fn canonical_application_statement_bytes(&self) -> &[u8] {
        self.application.canonical_application_statement_bytes
    }

    pub(crate) fn generated_source_authority(
        &self,
    ) -> Result<SetupGeneratedRelinearizationRoundOneSourceAuthority, RefusalReason> {
        self.authority
            .generated_relinearization_round_one_source_authority()
    }

    pub(crate) fn witness_bound_attempt(
        &self,
    ) -> Result<WitnessBoundPreparedActionProofAttemptSource, RefusalReason> {
        let persistent_proof_coin_input = PersistentProofCoinInput::new(
            self.prepared_attempt().application_slot(),
            self.prepared_attempt().application_statement_hash(),
        )
        .map_err(|error| error.refusal_reason)?;
        let mut binding = self
            .authority
            .action_private_randomness
            .begin_persistent_proof_witness_coin_binding(&persistent_proof_coin_input)
            .map_err(|error| error.refusal_reason)?;
        binding
            .absorb_canonical_bytes(RELINEARIZATION_ROUND_ONE_CANONICAL_SEMANTIC_WITNESS_DOMAIN)
            .map_err(|error| error.refusal_reason)?;
        binding
            .absorb_canonical_bytes(&self.schedule_position().to_le_bytes())
            .map_err(|error| error.refusal_reason)?;
        binding
            .absorb_canonical_i8_values(self.common_secret_coefficients())
            .map_err(|error| error.refusal_reason)?;
        binding
            .absorb_canonical_i8_values(self.ephemeral_secret_coefficients())
            .map_err(|error| error.refusal_reason)?;
        for anchor in self.anchor_openings() {
            binding
                .absorb_canonical_bytes(&anchor.commitment_data_prime_index().to_le_bytes())
                .map_err(|error| error.refusal_reason)?;
            for polynomial in anchor.hiding_secret_polynomials() {
                binding
                    .absorb_canonical_i8_values(polynomial)
                    .map_err(|error| error.refusal_reason)?;
            }
            for polynomial in anchor.hiding_error_polynomials() {
                binding
                    .absorb_canonical_i8_values(polynomial)
                    .map_err(|error| error.refusal_reason)?;
            }
        }
        for errors_by_block in [
            self.round_one_left_errors_by_block(),
            self.round_one_right_errors_by_block(),
        ] {
            for polynomial in errors_by_block {
                binding
                    .absorb_canonical_i8_values(polynomial)
                    .map_err(|error| error.refusal_reason)?;
            }
        }
        bind_prepared_action_proof_attempt_to_canonical_witness(*self.prepared_attempt(), binding)
            .map_err(|error| error.refusal_reason)
    }

    pub(crate) fn private_coin_source(
        &self,
        pre_output_generation_binding_hash: [u8; Hash512::BYTE_LENGTH],
        relation_plan_variant: &RelationPlanVariant,
        witness_bound_attempt: WitnessBoundPreparedActionProofAttemptSource,
    ) -> Result<PrivateRandomnessCommonProofCoinSource, RefusalReason> {
        if pre_output_generation_binding_hash == [0_u8; Hash512::BYTE_LENGTH]
            || witness_bound_attempt.application_slot()
                != self.prepared_attempt().application_slot()
            || witness_bound_attempt.application_statement_hash()
                != self.prepared_attempt().application_statement_hash()
        {
            return Err(RefusalReason::WrongContext);
        }
        let coordinate_capacity =
            CommonProofPrivateCoinCoordinateCapacity::from_relation_plan_variant(
                relation_plan_variant,
            )
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        PrivateRandomnessCommonProofCoinSource::new(
            Rc::clone(&self.authority.action_private_randomness),
            self.prepared_attempt()
                .application_statement_schema_identifier(),
            Hash512::from_bytes(pre_output_generation_binding_hash),
            witness_bound_attempt.private_randomness_attempt_identifier(),
            coordinate_capacity,
        )
        .map_err(|_| RefusalReason::WrongContext)
    }

    pub(crate) fn prepare_common_generation(
        &self,
        relation_plan: CommonProofRelationPlanCapability,
        limits: CommonProofRuntimeLimits,
    ) -> Result<PreparedCommonProofGeneration, SetupRelinearizationGenerationPreparationError> {
        let statement_schema_identifier =
            ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER;
        let relation_context = selected_relation_plan_check_context(statement_schema_identifier)
            .ok_or(RefusalReason::UnsupportedVersionOrSuite)?;
        let (relation_input, _) = selected_relinearization_relation_plan_inputs()
            .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)?;
        if relation_input.schedule_position != self.schedule_position() {
            return Err(RefusalReason::WrongContext.into());
        }
        let compiled_relation = compile_relinearization_round_one_relation_with_source_layout(
            &relation_input,
            &relation_context,
        )
        .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)?;
        let relation_plan_variant = compiled_relation
            .relation_plan
            .select_variant(Some(self.schedule_position()), None)
            .map_err(|_| CommonProofProverError::InvalidColumn)?
            .clone();
        let relation_trees = relinearization_round_one_relation_tree_inputs(
            self,
            &relation_plan_variant,
            &compiled_relation.source_layout,
        )?;
        let source_polynomials = RelinearizationRoundOneSourcePolynomialAdapter::new(
            self,
            &relation_plan,
            relation_plan_variant.clone(),
            relation_context,
            relation_input.geometry,
            compiled_relation.source_layout,
        )?;
        let witness_bound_attempt = self.witness_bound_attempt()?;
        let authorization =
            CommonProofGenerationAuthorization::from_witness_bound_authenticated_attempt(
                witness_bound_attempt,
                &relation_plan,
                self.protocol_version(),
                self.canonical_application_statement_bytes(),
            )?;
        let private_coins = self.private_coin_source(
            authorization.binding_hash(),
            &relation_plan_variant,
            witness_bound_attempt,
        )?;
        PreparedCommonProofGeneration::from_exact_family_sources(
            authorization,
            relation_plan,
            self.canonical_application_statement_bytes().to_vec(),
            relation_trees,
            limits,
            CommonProofGenerationSources::new(private_coins, source_polynomials),
        )
        .map_err(SetupRelinearizationGenerationPreparationError::from)
    }
}

/// Public preparation facts derived from the retained round-two generation.
/// The generated component and generated aggregate binding remain in
/// the setup-generation authority across fresh and resumed proof attempts.
#[derive(Clone)]
pub(crate) struct SetupGenerationRelinearizationRoundTwoPreparationSource {
    protocol_version: u16,
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    manifest_hash: [u8; Hash512::BYTE_LENGTH],
    ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
    action_context_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    source_setup_intent_object_hash: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    roster_position: u16,
    action_randomness_authorization_hash: [u8; Hash512::BYTE_LENGTH],
    schedule_position: u32,
    canonical_application_statement_bytes: Box<[u8]>,
}

impl SetupGenerationRelinearizationRoundTwoPreparationSource {
    fn from_generated_source(
        source: &SetupGeneratedRelinearizationRoundTwoSourceAuthority,
        manifest_hash: [u8; Hash512::BYTE_LENGTH],
        source_setup_intent_object_hash: [u8; Hash512::BYTE_LENGTH],
        action_randomness_authorization_hash: [u8; Hash512::BYTE_LENGTH],
    ) -> Self {
        Self {
            protocol_version: source.protocol_version(),
            suite_identifier: source.suite_identifier(),
            manifest_hash,
            ceremony_context_hash: source.ceremony_context_hash(),
            action_context_hash: source.action_context_hash(),
            roster_hash: source.roster_hash(),
            source_setup_intent_object_hash,
            participant_identity: source.participant_identity(),
            roster_position: source.roster_position(),
            action_randomness_authorization_hash,
            schedule_position: source.schedule_position(),
            canonical_application_statement_bytes: source
                .canonical_application_statement_bytes()
                .into(),
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

    pub(crate) fn canonical_application_statement_bytes(&self) -> &[u8] {
        &self.canonical_application_statement_bytes
    }
}

/// Exact decoded `0x1216` statement facts joined to one reset-safe proof
/// attempt. Construction remains inside the relation adapter after canonical
/// statement decoding.
pub(crate) struct SetupGenerationRelinearizationRoundTwoApplication<'statement> {
    prepared_attempt: PreparedActionProofAttemptSource,
    canonical_application_statement_bytes: &'statement [u8],
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    roster_position: u16,
    schedule_position: u32,
    anchor_commitment_roots: [[u8; Hash512::BYTE_LENGTH]; 3],
    round_one_root_pair: [[u8; Hash512::BYTE_LENGTH]; 2],
    aggregate_round_one_root_pair: [[u8; Hash512::BYTE_LENGTH]; 2],
    contribution_root: [u8; Hash512::BYTE_LENGTH],
}

impl<'statement> SetupGenerationRelinearizationRoundTwoApplication<'statement> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn from_decoded_statement(
        prepared_attempt: PreparedActionProofAttemptSource,
        canonical_application_statement_bytes: &'statement [u8],
        setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
        participant_identity: [u8; Hash512::BYTE_LENGTH],
        roster_position: u16,
        schedule_position: u32,
        anchor_commitment_roots: [[u8; Hash512::BYTE_LENGTH]; 3],
        round_one_root_pair: [[u8; Hash512::BYTE_LENGTH]; 2],
        aggregate_round_one_root_pair: [[u8; Hash512::BYTE_LENGTH]; 2],
        contribution_root: [u8; Hash512::BYTE_LENGTH],
    ) -> Self {
        Self {
            prepared_attempt,
            canonical_application_statement_bytes,
            setup_proof_context_hash,
            participant_identity,
            roster_position,
            schedule_position,
            anchor_commitment_roots,
            round_one_root_pair,
            aggregate_round_one_root_pair,
            contribution_root,
        }
    }
}

/// Retained browser-worker authority for the exact `0x1216` witness and its
/// generated round-one aggregate. Aggregate identity remains bound to the
/// catalog-retained generated proof; the caller cannot replace it with
/// detached roots, descriptors, or statement bytes.
pub(crate) struct SetupGenerationRelinearizationRoundTwoSource<'authority, 'statement> {
    authority_identifier: u32,
    authority: &'authority SetupGenerationAuthority,
    application: &'authority SetupGenerationRelinearizationRoundTwoApplication<'statement>,
    generated_round_two: &'authority SetupGeneratedRelinearizationRoundTwoGeneration,
}

impl SetupGenerationRelinearizationRoundTwoSource<'_, '_> {
    pub(crate) const fn authority_identifier(&self) -> u32 {
        self.authority_identifier
    }

    pub(crate) const fn protocol_version(&self) -> u16 {
        self.authority.protocol_version
    }

    pub(crate) const fn suite_identifier(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.authority.suite_identifier
    }

    pub(crate) const fn roster_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.authority.roster_hash
    }

    pub(crate) const fn setup_proof_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.authority.setup_proof_context_hash
    }

    pub(crate) const fn source_setup_intent_object_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.authority.source_setup_intent_object_hash
    }

    pub(crate) const fn participant_identity(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.authority.participant_identity
    }

    pub(crate) const fn roster_position(&self) -> u16 {
        self.authority.roster_position
    }

    pub(crate) const fn setup_attempt_identifier(&self) -> [u8; 32] {
        self.authority.setup_attempt_identifier
    }

    pub(crate) const fn action_randomness_authorization_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.authority.action_randomness_authorization_hash
    }

    pub(crate) const fn public_setup_seed(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.authority.public_setup_seed
    }

    pub(crate) const fn anchor_commitment_roots(&self) -> [[u8; Hash512::BYTE_LENGTH]; 3] {
        self.authority.anchor_commitment_roots
    }

    pub(crate) fn anchor_openings(&self) -> &[SetupGenerationAnchorOpening] {
        &self.authority.anchor_openings
    }

    pub(crate) fn common_secret_coefficients(&self) -> &[i8] {
        &self.authority.common_secret_coefficients
    }

    pub(crate) fn ephemeral_secret_coefficients(&self) -> &[i8] {
        self.authority
            .relinearization_material
            .ephemeral_secret_coefficients()
    }

    pub(crate) const fn schedule_position(&self) -> u32 {
        self.authority.relinearization_material.schedule_position()
    }

    pub(crate) const fn round_one_left_component(&self) -> &SetupGeneratedKeySwitchComponent {
        self.authority
            .relinearization_material
            .round_one_left_component()
    }

    pub(crate) const fn round_one_right_component(&self) -> &SetupGeneratedKeySwitchComponent {
        self.authority
            .relinearization_material
            .round_one_right_component()
    }

    pub(crate) fn round_one_left_errors_by_block(&self) -> &[Zeroizing<Vec<i8>>] {
        self.authority
            .relinearization_material
            .round_one_left_errors_by_block()
    }

    pub(crate) fn round_one_right_errors_by_block(&self) -> &[Zeroizing<Vec<i8>>] {
        self.authority
            .relinearization_material
            .round_one_right_errors_by_block()
    }

    pub(crate) fn round_two_errors_by_block(&self) -> &[Zeroizing<Vec<i8>>] {
        self.authority
            .relinearization_material
            .round_two_errors_by_block()
    }

    pub(crate) const fn round_two_component(&self) -> &SetupGeneratedKeySwitchComponent {
        self.generated_round_two.component()
    }

    pub(crate) const fn generated_source_authority(
        &self,
    ) -> &SetupGeneratedRelinearizationRoundTwoSourceAuthority {
        self.generated_round_two.source_authority()
    }

    pub(crate) fn generated_round_one_source_authority(
        &self,
    ) -> Result<SetupGeneratedRelinearizationRoundOneSourceAuthority, RefusalReason> {
        self.authority
            .generated_relinearization_round_one_source_authority()
    }

    pub(crate) const fn prepared_attempt(&self) -> &PreparedActionProofAttemptSource {
        &self.application.prepared_attempt
    }

    pub(crate) fn canonical_application_statement_bytes(&self) -> &[u8] {
        self.application.canonical_application_statement_bytes
    }

    pub(crate) fn witness_bound_attempt(
        &self,
    ) -> Result<WitnessBoundPreparedActionProofAttemptSource, RefusalReason> {
        let persistent_proof_coin_input = PersistentProofCoinInput::new(
            self.prepared_attempt().application_slot(),
            self.prepared_attempt().application_statement_hash(),
        )
        .map_err(|error| error.refusal_reason)?;
        let mut binding = self
            .authority
            .action_private_randomness
            .begin_persistent_proof_witness_coin_binding(&persistent_proof_coin_input)
            .map_err(|error| error.refusal_reason)?;
        binding
            .absorb_canonical_bytes(RELINEARIZATION_ROUND_TWO_CANONICAL_SEMANTIC_WITNESS_DOMAIN)
            .map_err(|error| error.refusal_reason)?;
        binding
            .absorb_canonical_bytes(&self.schedule_position().to_le_bytes())
            .map_err(|error| error.refusal_reason)?;
        binding
            .absorb_canonical_i8_values(self.common_secret_coefficients())
            .map_err(|error| error.refusal_reason)?;
        binding
            .absorb_canonical_i8_values(self.ephemeral_secret_coefficients())
            .map_err(|error| error.refusal_reason)?;
        for anchor in self.anchor_openings() {
            binding
                .absorb_canonical_bytes(&anchor.commitment_data_prime_index().to_le_bytes())
                .map_err(|error| error.refusal_reason)?;
            for polynomial in anchor.hiding_secret_polynomials() {
                binding
                    .absorb_canonical_i8_values(polynomial)
                    .map_err(|error| error.refusal_reason)?;
            }
            for polynomial in anchor.hiding_error_polynomials() {
                binding
                    .absorb_canonical_i8_values(polynomial)
                    .map_err(|error| error.refusal_reason)?;
            }
        }
        for errors_by_block in [
            self.round_one_left_errors_by_block(),
            self.round_one_right_errors_by_block(),
            self.round_two_errors_by_block(),
        ] {
            for polynomial in errors_by_block {
                binding
                    .absorb_canonical_i8_values(polynomial)
                    .map_err(|error| error.refusal_reason)?;
            }
        }
        bind_prepared_action_proof_attempt_to_canonical_witness(*self.prepared_attempt(), binding)
            .map_err(|error| error.refusal_reason)
    }

    pub(crate) fn private_coin_source(
        &self,
        pre_output_generation_binding_hash: [u8; Hash512::BYTE_LENGTH],
        relation_plan_variant: &RelationPlanVariant,
        witness_bound_attempt: WitnessBoundPreparedActionProofAttemptSource,
    ) -> Result<PrivateRandomnessCommonProofCoinSource, RefusalReason> {
        if pre_output_generation_binding_hash == [0_u8; Hash512::BYTE_LENGTH]
            || witness_bound_attempt.application_slot()
                != self.prepared_attempt().application_slot()
            || witness_bound_attempt.application_statement_hash()
                != self.prepared_attempt().application_statement_hash()
        {
            return Err(RefusalReason::WrongContext);
        }
        let coordinate_capacity =
            CommonProofPrivateCoinCoordinateCapacity::from_relation_plan_variant(
                relation_plan_variant,
            )
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        PrivateRandomnessCommonProofCoinSource::new(
            Rc::clone(&self.authority.action_private_randomness),
            self.prepared_attempt()
                .application_statement_schema_identifier(),
            Hash512::from_bytes(pre_output_generation_binding_hash),
            witness_bound_attempt.private_randomness_attempt_identifier(),
            coordinate_capacity,
        )
        .map_err(|_| RefusalReason::WrongContext)
    }

    pub(crate) fn prepare_common_generation(
        &self,
        relation_plan: CommonProofRelationPlanCapability,
        limits: CommonProofRuntimeLimits,
        aggregate_source_plan: RelinearizationRoundTwoAuthenticatedAggregateSourcePlan,
    ) -> Result<PreparedCommonProofGeneration, SetupRelinearizationGenerationPreparationError> {
        let statement_schema_identifier =
            ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER;
        let relation_context = selected_relation_plan_check_context(statement_schema_identifier)
            .ok_or(RefusalReason::UnsupportedVersionOrSuite)?;
        let (_, relation_input) = selected_relinearization_relation_plan_inputs()
            .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)?;
        if relation_input.schedule_position != self.schedule_position() {
            return Err(RefusalReason::WrongContext.into());
        }
        let compiled_relation = compile_relinearization_round_two_relation_with_source_layout(
            &relation_input,
            &relation_context,
        )
        .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)?;
        let relation_plan_variant = compiled_relation
            .relation_plan
            .select_variant(Some(self.schedule_position()), None)
            .map_err(|_| CommonProofProverError::InvalidColumn)?
            .clone();
        let relation_trees = relinearization_round_two_relation_tree_inputs(
            self,
            &relation_plan_variant,
            &compiled_relation.source_layout,
        )?;
        let source_polynomials = RelinearizationRoundTwoSourcePolynomialAdapter::new(
            self,
            &relation_plan,
            relation_plan_variant.clone(),
            relation_context,
            relation_input.geometry,
            compiled_relation.source_layout,
            aggregate_source_plan,
        )?;
        let witness_bound_attempt = self.witness_bound_attempt()?;
        let authorization =
            CommonProofGenerationAuthorization::from_witness_bound_authenticated_attempt(
                witness_bound_attempt,
                &relation_plan,
                self.protocol_version(),
                self.canonical_application_statement_bytes(),
            )?;
        let private_coins = self.private_coin_source(
            authorization.binding_hash(),
            &relation_plan_variant,
            witness_bound_attempt,
        )?;
        PreparedCommonProofGeneration::from_exact_family_sources(
            authorization,
            relation_plan,
            self.canonical_application_statement_bytes().to_vec(),
            relation_trees,
            limits,
            CommonProofGenerationSources::new(private_coins, source_polynomials),
        )
        .map_err(SetupRelinearizationGenerationPreparationError::from)
    }
}

/// Exact decoded 0x1217 statement facts joined to the reset-safe proof attempt
/// and its authenticated checkpoint lineage. The Galois family adapter creates
/// this value only after decoding the canonical statement.
pub(crate) struct SetupGenerationGaloisApplication<'statement> {
    prepared_attempt: PreparedActionProofAttemptSource,
    canonical_application_statement_bytes: &'statement [u8],
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    roster_position: u16,
    batch_schedule_position: u32,
}

impl<'statement> SetupGenerationGaloisApplication<'statement> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn from_decoded_statement(
        prepared_attempt: PreparedActionProofAttemptSource,
        canonical_application_statement_bytes: &'statement [u8],
        setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
        roster_hash: [u8; Hash512::BYTE_LENGTH],
        participant_identity: [u8; Hash512::BYTE_LENGTH],
        roster_position: u16,
        batch_schedule_position: u32,
    ) -> Self {
        Self {
            prepared_attempt,
            canonical_application_statement_bytes,
            setup_proof_context_hash,
            roster_hash,
            participant_identity,
            roster_position,
            batch_schedule_position,
        }
    }
}

/// Borrowed generation source passed only to the family adapter callback. It
/// exposes secret witnesses within Rust and cannot be encoded as a worker
/// response.
pub(crate) struct SetupGenerationGaloisBatchSource<'authority, 'statement> {
    authority_identifier: u32,
    authority: &'authority SetupGenerationAuthority,
    application: &'authority SetupGenerationGaloisApplication<'statement>,
}

impl SetupGenerationGaloisBatchSource<'_, '_> {
    pub(crate) const fn authority_identifier(&self) -> u32 {
        self.authority_identifier
    }

    pub(crate) const fn protocol_version(&self) -> u16 {
        self.authority.protocol_version
    }

    pub(crate) const fn suite_identifier(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.authority.suite_identifier
    }

    pub(crate) const fn ceremony_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.authority.ceremony_context_hash
    }

    pub(crate) const fn action_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.authority.action_context_hash
    }

    pub(crate) const fn roster_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.authority.roster_hash
    }

    pub(crate) const fn setup_proof_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.authority.setup_proof_context_hash
    }

    pub(crate) const fn source_setup_intent_object_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.authority.source_setup_intent_object_hash
    }

    pub(crate) const fn participant_identity(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.authority.participant_identity
    }

    pub(crate) const fn roster_position(&self) -> u16 {
        self.authority.roster_position
    }

    pub(crate) const fn setup_attempt_identifier(&self) -> [u8; 32] {
        self.authority.setup_attempt_identifier
    }

    pub(crate) const fn action_randomness_authorization_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.authority.action_randomness_authorization_hash
    }

    pub(crate) const fn public_setup_seed(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.authority.public_setup_seed
    }

    pub(crate) fn anchor_openings(&self) -> &[SetupGenerationAnchorOpening] {
        &self.authority.anchor_openings
    }

    pub(crate) fn common_secret_coefficients(&self) -> &[i8] {
        self.authority.common_secret_coefficients.as_slice()
    }

    pub(crate) const fn batch_schedule_position(&self) -> u32 {
        self.authority.galois_batch_schedule_position
    }

    pub(crate) fn ordered_entries(&self) -> &[SetupGeneratedGaloisEntry] {
        &self.authority.ordered_galois_entries
    }

    pub(crate) const fn prepared_attempt(&self) -> &PreparedActionProofAttemptSource {
        &self.application.prepared_attempt
    }

    pub(crate) fn canonical_application_statement_bytes(&self) -> &[u8] {
        self.application.canonical_application_statement_bytes
    }

    pub(crate) fn witness_bound_attempt(
        &self,
    ) -> Result<WitnessBoundPreparedActionProofAttemptSource, RefusalReason> {
        let persistent_proof_coin_input = PersistentProofCoinInput::new(
            self.application.prepared_attempt.application_slot(),
            self.application
                .prepared_attempt
                .application_statement_hash(),
        )
        .map_err(|error| error.refusal_reason)?;
        let mut binding = self
            .authority
            .action_private_randomness
            .begin_persistent_proof_witness_coin_binding(&persistent_proof_coin_input)
            .map_err(|error| error.refusal_reason)?;
        binding
            .absorb_canonical_bytes(GALOIS_KEY_SHARE_CANONICAL_SEMANTIC_WITNESS_DOMAIN)
            .map_err(|error| error.refusal_reason)?;
        binding
            .absorb_canonical_bytes(&self.batch_schedule_position().to_le_bytes())
            .map_err(|error| error.refusal_reason)?;
        binding
            .absorb_canonical_i8_values(self.common_secret_coefficients())
            .map_err(|error| error.refusal_reason)?;

        binding
            .absorb_canonical_bytes(
                &u64::try_from(self.anchor_openings().len())
                    .map_err(|_| RefusalReason::OutsideSupportedProfile)?
                    .to_le_bytes(),
            )
            .map_err(|error| error.refusal_reason)?;
        for (anchor_ordinal, anchor) in self.anchor_openings().iter().enumerate() {
            binding
                .absorb_canonical_bytes(
                    &u64::try_from(anchor_ordinal)
                        .map_err(|_| RefusalReason::OutsideSupportedProfile)?
                        .to_le_bytes(),
                )
                .map_err(|error| error.refusal_reason)?;
            binding
                .absorb_canonical_bytes(&anchor.commitment_data_prime_index().to_le_bytes())
                .map_err(|error| error.refusal_reason)?;
            binding
                .absorb_canonical_bytes(
                    &u64::try_from(anchor.hiding_secret_polynomials().len())
                        .map_err(|_| RefusalReason::OutsideSupportedProfile)?
                        .to_le_bytes(),
                )
                .map_err(|error| error.refusal_reason)?;
            for (polynomial_ordinal, polynomial) in
                anchor.hiding_secret_polynomials().iter().enumerate()
            {
                binding
                    .absorb_canonical_bytes(
                        &u64::try_from(polynomial_ordinal)
                            .map_err(|_| RefusalReason::OutsideSupportedProfile)?
                            .to_le_bytes(),
                    )
                    .map_err(|error| error.refusal_reason)?;
                binding
                    .absorb_canonical_i8_values(polynomial)
                    .map_err(|error| error.refusal_reason)?;
            }
            binding
                .absorb_canonical_bytes(
                    &u64::try_from(anchor.hiding_error_polynomials().len())
                        .map_err(|_| RefusalReason::OutsideSupportedProfile)?
                        .to_le_bytes(),
                )
                .map_err(|error| error.refusal_reason)?;
            for (polynomial_ordinal, polynomial) in
                anchor.hiding_error_polynomials().iter().enumerate()
            {
                binding
                    .absorb_canonical_bytes(
                        &u64::try_from(polynomial_ordinal)
                            .map_err(|_| RefusalReason::OutsideSupportedProfile)?
                            .to_le_bytes(),
                    )
                    .map_err(|error| error.refusal_reason)?;
                binding
                    .absorb_canonical_i8_values(polynomial)
                    .map_err(|error| error.refusal_reason)?;
            }
        }

        binding
            .absorb_canonical_bytes(
                &u64::try_from(self.ordered_entries().len())
                    .map_err(|_| RefusalReason::OutsideSupportedProfile)?
                    .to_le_bytes(),
            )
            .map_err(|error| error.refusal_reason)?;
        for (entry_ordinal, entry) in self.ordered_entries().iter().enumerate() {
            let evaluator_position = entry.component().evaluator_position();
            let SelectedEvaluatorEntryKind::Galois {
                galois_element,
                catalog_level,
            } = evaluator_position.key_kind()
            else {
                return Err(RefusalReason::WrongTypeOrLength);
            };
            binding
                .absorb_canonical_bytes(
                    &u64::try_from(entry_ordinal)
                        .map_err(|_| RefusalReason::OutsideSupportedProfile)?
                        .to_le_bytes(),
                )
                .map_err(|error| error.refusal_reason)?;
            binding
                .absorb_canonical_bytes(&evaluator_position.schedule_position().to_le_bytes())
                .map_err(|error| error.refusal_reason)?;
            binding
                .absorb_canonical_bytes(
                    &u64::try_from(galois_element)
                        .map_err(|_| RefusalReason::OutsideSupportedProfile)?
                        .to_le_bytes(),
                )
                .map_err(|error| error.refusal_reason)?;
            binding
                .absorb_canonical_bytes(
                    &u64::try_from(catalog_level)
                        .map_err(|_| RefusalReason::OutsideSupportedProfile)?
                        .to_le_bytes(),
                )
                .map_err(|error| error.refusal_reason)?;
            binding
                .absorb_canonical_bytes(
                    &u64::try_from(entry.centered_error_polynomials_by_block().len())
                        .map_err(|_| RefusalReason::OutsideSupportedProfile)?
                        .to_le_bytes(),
                )
                .map_err(|error| error.refusal_reason)?;
            for (data_block_ordinal, polynomial) in entry
                .centered_error_polynomials_by_block()
                .iter()
                .enumerate()
            {
                binding
                    .absorb_canonical_bytes(
                        &u64::try_from(data_block_ordinal)
                            .map_err(|_| RefusalReason::OutsideSupportedProfile)?
                            .to_le_bytes(),
                    )
                    .map_err(|error| error.refusal_reason)?;
                binding
                    .absorb_canonical_i8_values(polynomial)
                    .map_err(|error| error.refusal_reason)?;
            }
        }

        bind_prepared_action_proof_attempt_to_canonical_witness(
            self.application.prepared_attempt,
            binding,
        )
        .map_err(|error| error.refusal_reason)
    }

    /// Creates the owned private-coin source for this exact relation plan.
    /// Resume intentionally starts from counter zero: the worker deterministically
    /// replays to the authenticated checkpoint boundary before releasing output.
    pub(crate) fn private_coin_source(
        &self,
        pre_output_generation_binding_hash: [u8; Hash512::BYTE_LENGTH],
        relation_plan_variant: &RelationPlanVariant,
        witness_bound_attempt: WitnessBoundPreparedActionProofAttemptSource,
    ) -> Result<PrivateRandomnessCommonProofCoinSource, RefusalReason> {
        if pre_output_generation_binding_hash == [0_u8; Hash512::BYTE_LENGTH] {
            return Err(RefusalReason::WrongContext);
        }
        if witness_bound_attempt.application_slot()
            != self.application.prepared_attempt.application_slot()
            || witness_bound_attempt.application_statement_hash()
                != self
                    .application
                    .prepared_attempt
                    .application_statement_hash()
        {
            return Err(RefusalReason::WrongContext);
        }
        let attempt_identifier = witness_bound_attempt.private_randomness_attempt_identifier();
        let coordinate_capacity =
            CommonProofPrivateCoinCoordinateCapacity::from_relation_plan_variant(
                relation_plan_variant,
            )
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        PrivateRandomnessCommonProofCoinSource::new(
            Rc::clone(&self.authority.action_private_randomness),
            self.application
                .prepared_attempt
                .application_statement_schema_identifier(),
            Hash512::from_bytes(pre_output_generation_binding_hash),
            attempt_identifier,
            coordinate_capacity,
        )
        .map_err(|_| RefusalReason::WrongContext)
    }

    fn recompute_galois_common_auxiliary_root(
        &self,
        entry: &SetupGeneratedGaloisEntry,
        evaluation_domain_size: usize,
    ) -> Result<VerifiedEvaluatorAuxiliaryRoot, RefusalReason> {
        let component = entry.component();
        let position = component.evaluator_position();
        let SelectedEvaluatorEntryKind::Galois {
            galois_element,
            catalog_level,
        } = position.key_kind()
        else {
            return Err(RefusalReason::WrongTypeOrLength);
        };
        let topology = component.topology();
        let active_data_limb_count = catalog_level
            .checked_add(1)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        let polynomial_degree = topology.polynomial_degree();
        let extended_limb_count = topology.extended_limb_count();
        let trace_half_degree_bound_exclusive = polynomial_degree / 2;
        if active_data_limb_count > extended_limb_count
            || trace_half_degree_bound_exclusive == 0
            || trace_half_degree_bound_exclusive.checked_mul(2) != Some(polynomial_degree)
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }

        let expected_column_count = topology.trace_column_count()?;
        let public_setup_seed = self.public_setup_seed();
        let public_polynomial_context = SetupPublicPolynomialContext::galois_common(
            self.setup_proof_context_hash(),
            position.schedule_position(),
        )
        .map_err(|_| RefusalReason::WrongContext)?;
        let mut root_builder = SetupPublicPolynomialRootBuilder::new(
            &public_polynomial_context,
            evaluation_domain_size,
            trace_half_degree_bound_exclusive,
            u32::try_from(expected_column_count)
                .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
        )
        .map_err(|_| RefusalReason::WrongHashOrRoot)?;
        let mut absorbed_column_count = 0_usize;
        for decomposition_block_index in 0..topology.data_block_count() {
            let decomposition_block_coordinate = u16::try_from(decomposition_block_index)
                .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
            for extended_limb_index in 0..extended_limb_count {
                let (modulus_catalog_identifier, modulus_index) =
                    if extended_limb_index < active_data_limb_count {
                        (
                            DATA_MODULUS_CATALOG_IDENTIFIER,
                            u16::try_from(extended_limb_index)
                                .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
                        )
                    } else {
                        (
                            SPECIAL_MODULUS_CATALOG_IDENTIFIER,
                            u16::try_from(extended_limb_index - active_data_limb_count)
                                .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
                        )
                    };
                let common_reference_coefficients = sample_galois_common_reference_limb(
                    &public_setup_seed,
                    position.schedule_position(),
                    decomposition_block_coordinate,
                    modulus_catalog_identifier,
                    modulus_index,
                    polynomial_degree,
                )
                .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
                if common_reference_coefficients.len() != polynomial_degree {
                    return Err(RefusalReason::WrongTypeOrLength);
                }
                for half_ordinal in 0_usize..2_usize {
                    let coefficient_start = half_ordinal
                        .checked_mul(trace_half_degree_bound_exclusive)
                        .ok_or(RefusalReason::OutsideSupportedProfile)?;
                    let physical_column = &common_reference_coefficients
                        [coefficient_start..coefficient_start + trace_half_degree_bound_exclusive];
                    root_builder
                        .absorb_canonical_trace_row(physical_column)
                        .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
                    absorbed_column_count = absorbed_column_count
                        .checked_add(1)
                        .ok_or(RefusalReason::OutsideSupportedProfile)?;
                }
            }
        }
        if absorbed_column_count != expected_column_count {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        let (public_polynomial_context_hash, root) = root_builder
            .finish()
            .map_err(|_| RefusalReason::WrongHashOrRoot)?;
        VerifiedEvaluatorAuxiliaryRoot::from_recomputed_galois_common_public_polynomial_root(
            position.schedule_position(),
            galois_element,
            catalog_level,
            &public_polynomial_context,
            public_polynomial_context_hash,
            root,
        )
        .map_err(|_| RefusalReason::WrongContext)
    }

    pub(crate) fn generated_source_authority(
        &self,
    ) -> Result<SetupGeneratedGaloisSourceAuthority, RefusalReason> {
        let statement_schema_identifier =
            ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER;
        let selected_plan = selected_relation_plans()
            .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)?
            .into_iter()
            .find(|artifact| {
                artifact.application_statement_schema_identifier() == statement_schema_identifier
            })
            .ok_or(RefusalReason::UnsupportedVersionOrSuite)?;
        let relation_plan_variant = selected_plan
            .compiled_plan()
            .select_variant(Some(self.batch_schedule_position()), None)
            .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)?;
        let evaluation_domain_size =
            usize::try_from(relation_plan_variant.evaluation_domain_size())
                .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        let mut ordered_public_polynomial_contexts =
            Vec::with_capacity(self.ordered_entries().len());
        let mut ordered_public_polynomial_roots = Vec::with_capacity(self.ordered_entries().len());
        let mut ordered_contribution_roots = Vec::with_capacity(self.ordered_entries().len());
        for (component_ordinal, entry) in self.ordered_entries().iter().enumerate() {
            let logical_schedule_position = u32::try_from(component_ordinal)
                .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
            let public_polynomial_context = SetupPublicPolynomialContext::new(
                self.setup_proof_context_hash(),
                crate::bgv::proof_suite::SetupPublicPolynomialRootRole::GaloisKeyShare,
                Some(self.participant_identity()),
                Some(self.roster_position()),
                Some(logical_schedule_position),
                None,
            )
            .map_err(|_| RefusalReason::WrongContext)?;
            let component = entry.component();
            let public_polynomial_root =
                recompute_setup_generated_component_public_polynomial_root(
                    component,
                    &public_polynomial_context,
                    evaluation_domain_size,
                )?;
            let contribution_root = public_polynomial_root.root();
            ordered_contribution_roots.push(contribution_root);
            ordered_public_polynomial_contexts.push(public_polynomial_context);
            ordered_public_polynomial_roots.push(public_polynomial_root);
        }
        let canonical_application_statement_bytes = canonical_selected_galois_key_share_statement(
            self.setup_proof_context_hash(),
            self.participant_identity(),
            self.roster_position(),
            self.batch_schedule_position(),
            &self.authority.anchor_commitment_roots,
            &ordered_contribution_roots,
        )
        .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        if canonical_application_statement_bytes != self.canonical_application_statement_bytes() {
            return Err(RefusalReason::WrongHashOrRoot);
        }
        let application_statement_hash = verified_application_statement_hash(
            self.protocol_version(),
            self.suite_identifier(),
            statement_schema_identifier,
            &canonical_application_statement_bytes,
        );
        let material_ownership = ComponentMaterialOwnershipBinding::from_generated_application(
            self.suite_identifier(),
            self.action_context_hash(),
            application_statement_hash,
        );
        let mut ordered_components = Vec::with_capacity(self.ordered_entries().len());
        for ((entry, public_polynomial_context), public_polynomial_root) in self
            .ordered_entries()
            .iter()
            .zip(ordered_public_polynomial_contexts)
            .zip(ordered_public_polynomial_roots)
        {
            let component = entry.component();
            let material = authenticate_setup_generated_component_material(
                &component.topology,
                &component.canonical_bytes,
                &component.stream_descriptor,
                material_ownership,
            )?;
            if public_polynomial_context
                .context_hash()
                .map_err(|_| RefusalReason::WrongContext)?
                != public_polynomial_root.public_polynomial_context_hash()
            {
                return Err(RefusalReason::WrongHashOrRoot);
            }
            ordered_components.push(SetupGeneratedGaloisSourceComponent {
                evaluator_position: component.evaluator_position,
                material,
                contribution_root: public_polynomial_root.root(),
                public_polynomial_context_hash: public_polynomial_root
                    .public_polynomial_context_hash(),
            });
        }
        let ordered_auxiliary_roots = self
            .ordered_entries()
            .iter()
            .map(|entry| self.recompute_galois_common_auxiliary_root(entry, evaluation_domain_size))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(SetupGeneratedGaloisSourceAuthority {
            protocol_version: self.protocol_version(),
            suite_identifier: self.suite_identifier(),
            ceremony_context_hash: self.ceremony_context_hash(),
            action_context_hash: self.action_context_hash(),
            roster_hash: self.roster_hash(),
            setup_proof_context_hash: self.setup_proof_context_hash(),
            participant_identity: self.participant_identity(),
            roster_position: self.roster_position(),
            batch_schedule_position: self.batch_schedule_position(),
            anchor_commitment_roots: self.authority.anchor_commitment_roots,
            canonical_application_statement_bytes: canonical_application_statement_bytes
                .into_boxed_slice(),
            ordered_auxiliary_roots: ordered_auxiliary_roots.into_boxed_slice(),
            ordered_components: ordered_components.into_boxed_slice(),
        })
    }

    pub(crate) fn prepare_common_generation(
        &self,
        relation_plan: CommonProofRelationPlanCapability,
        limits: CommonProofRuntimeLimits,
    ) -> Result<PreparedCommonProofGeneration, SetupGaloisGenerationPreparationError> {
        let statement_schema_identifier =
            ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER;
        let relation_context = selected_relation_plan_check_context(statement_schema_identifier)
            .ok_or(RefusalReason::UnsupportedVersionOrSuite)?;
        let relation_input = selected_galois_key_share_relation_plan_input()
            .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)?;
        let compiled_relation = compile_galois_key_share_relation_with_source_layout(
            &relation_input,
            &relation_context,
        )
        .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)?;
        let relation_plan_variant = compiled_relation
            .relation_plan
            .select_variant(Some(self.batch_schedule_position()), None)
            .map_err(|_| CommonProofProverError::InvalidColumn)?
            .clone();
        let preparation_source = self.authority.galois_preparation_source()?;
        if preparation_source.canonical_application_statement_bytes()
            != self.canonical_application_statement_bytes()
        {
            return Err(RefusalReason::WrongHashOrRoot.into());
        }
        let relation_trees = galois_relation_tree_inputs(
            self,
            &relation_plan_variant,
            &compiled_relation.source_layout,
            preparation_source.ordered_contribution_roots(),
        )?;
        let source_polynomials = GaloisKeyShareSourcePolynomialAdapter::new(
            self,
            &relation_plan,
            relation_plan_variant.clone(),
            relation_context,
            relation_input.geometry,
            compiled_relation.source_layout,
        )?;
        let witness_bound_attempt = self.witness_bound_attempt()?;
        let authorization =
            CommonProofGenerationAuthorization::from_witness_bound_authenticated_attempt(
                witness_bound_attempt,
                &relation_plan,
                self.protocol_version(),
                self.canonical_application_statement_bytes(),
            )?;
        let private_coins = self.private_coin_source(
            authorization.binding_hash(),
            &relation_plan_variant,
            witness_bound_attempt,
        )?;
        PreparedCommonProofGeneration::from_exact_family_sources(
            authorization,
            relation_plan,
            self.canonical_application_statement_bytes().to_vec(),
            relation_trees,
            limits,
            CommonProofGenerationSources::new(private_coins, source_polynomials),
        )
        .map_err(SetupGaloisGenerationPreparationError::from)
    }
}

#[derive(Default)]
struct SetupGenerationAuthorityRegistry {
    next_handle: u32,
    authorities: BTreeMap<u32, SetupGenerationAuthority>,
}

#[derive(Default)]
struct SetupGenerationVssProofAuthorityRegistry {
    authorities: BTreeMap<u32, SetupGenerationVssProofAuthority>,
}

struct SetupGenerationPublicKeyShareSource {
    owner_authority_identifier: u32,
    body_byte_length: usize,
    next_offset: usize,
}

impl SetupGenerationPublicKeyShareSource {
    fn read_into(
        &mut self,
        public_key_share: &SetupGeneratedPublicKeyShare,
        expected_offset: usize,
        output: &mut [u8],
    ) -> Result<bool, RefusalReason> {
        if self.next_offset != expected_offset {
            return Err(RefusalReason::WrongContext);
        }
        if public_key_share.body_byte_length()? != self.body_byte_length {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        let finished = public_key_share.write_body_range(expected_offset, output)?;
        self.next_offset = self
            .next_offset
            .checked_add(output.len())
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        if finished != (self.next_offset == self.body_byte_length) {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        Ok(finished)
    }
}

#[derive(Default)]
struct SetupGenerationPublicKeyShareSourceRegistry {
    next_handle: u32,
    sources: BTreeMap<u32, SetupGenerationPublicKeyShareSource>,
}

impl SetupGenerationPublicKeyShareSourceRegistry {
    fn next_available_handle(
        &self,
    ) -> Result<SetupGenerationPublicKeyShareSourceHandle, RefusalReason> {
        if self.sources.len() >= MAXIMUM_RETAINED_SETUP_GENERATION_PUBLIC_KEY_SHARE_SOURCE_COUNT {
            return Err(RefusalReason::OutsideSupportedProfile);
        }
        self.next_handle
            .checked_add(1)
            .map(SetupGenerationPublicKeyShareSourceHandle)
            .ok_or(RefusalReason::OutsideSupportedProfile)
    }

    fn retain_at(
        &mut self,
        handle: SetupGenerationPublicKeyShareSourceHandle,
        source: SetupGenerationPublicKeyShareSource,
    ) -> SetupGenerationPublicKeyShareSourceHandle {
        self.next_handle = handle.0;
        let replaced = self.sources.insert(handle.0, source);
        debug_assert!(replaced.is_none());
        handle
    }

    fn release_for_authority(&mut self, authority_identifier: u32) {
        self.sources
            .retain(|_, source| source.owner_authority_identifier != authority_identifier);
    }

    fn contains_source_for_authority(&self, authority_identifier: u32) -> bool {
        self.sources
            .values()
            .any(|source| source.owner_authority_identifier == authority_identifier)
    }
}

struct SetupGenerationRecipientPayloadSource {
    owner_authority_identifier: u32,
    recipient_roster_position: u16,
    canonical_bytes: Zeroizing<Vec<u8>>,
    next_offset: usize,
}

impl SetupGenerationRecipientPayloadSource {
    fn read_chunk(
        &mut self,
        expected_offset: usize,
        requested_byte_length: usize,
    ) -> Result<(Zeroizing<Vec<u8>>, bool), RefusalReason> {
        if requested_byte_length == 0 {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        if self.next_offset != expected_offset {
            return Err(RefusalReason::WrongContext);
        }
        let end = self
            .next_offset
            .checked_add(requested_byte_length)
            .filter(|end| *end <= self.canonical_bytes.len())
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        let chunk = Zeroizing::new(self.canonical_bytes[self.next_offset..end].to_vec());
        self.canonical_bytes[self.next_offset..end].zeroize();
        self.next_offset = end;
        Ok((chunk, end == self.canonical_bytes.len()))
    }
}

#[derive(Default)]
struct SetupGenerationRecipientPayloadSourceRegistry {
    next_handle: u32,
    sources: BTreeMap<u32, SetupGenerationRecipientPayloadSource>,
}

impl SetupGenerationRecipientPayloadSourceRegistry {
    fn next_available_handle(
        &self,
    ) -> Result<SetupGenerationRecipientPayloadSourceHandle, RefusalReason> {
        if self.sources.len() >= MAXIMUM_RETAINED_SETUP_GENERATION_RECIPIENT_PAYLOAD_SOURCE_COUNT {
            return Err(RefusalReason::OutsideSupportedProfile);
        }
        self.next_handle
            .checked_add(1)
            .map(SetupGenerationRecipientPayloadSourceHandle)
            .ok_or(RefusalReason::OutsideSupportedProfile)
    }

    fn retain_at(
        &mut self,
        handle: SetupGenerationRecipientPayloadSourceHandle,
        source: SetupGenerationRecipientPayloadSource,
    ) -> SetupGenerationRecipientPayloadSourceHandle {
        self.next_handle = handle.0;
        let replaced = self.sources.insert(handle.0, source);
        debug_assert!(replaced.is_none());
        handle
    }

    fn release_for_authority(&mut self, authority_identifier: u32) {
        self.sources
            .retain(|_, source| source.owner_authority_identifier != authority_identifier);
    }

    fn contains_source_for_authority(&self, authority_identifier: u32) -> bool {
        self.sources
            .values()
            .any(|source| source.owner_authority_identifier == authority_identifier)
    }

    fn read_chunk_and_record_completion<CompletionRecorder>(
        &mut self,
        source_handle: &SetupGenerationRecipientPayloadSourceHandle,
        expected_offset: usize,
        requested_byte_length: usize,
        record_completion: CompletionRecorder,
    ) -> Result<Zeroizing<Vec<u8>>, RefusalReason>
    where
        CompletionRecorder: FnOnce(u32) -> Result<(), RefusalReason>,
    {
        let (chunk, finished, owner_authority_identifier) = {
            let source = self
                .sources
                .get_mut(&source_handle.0)
                .ok_or(RefusalReason::ConsumedState)?;
            let owner_authority_identifier = source.owner_authority_identifier;
            let (chunk, finished) = source.read_chunk(expected_offset, requested_byte_length)?;
            (chunk, finished, owner_authority_identifier)
        };
        if finished {
            record_completion(owner_authority_identifier)?;
            let removed_source = self.sources.remove(&source_handle.0);
            debug_assert!(removed_source.is_some());
        }
        Ok(chunk)
    }
}

impl SetupGenerationAuthorityRegistry {
    fn retain(
        &mut self,
        authority: SetupGenerationAuthority,
    ) -> Result<SetupGenerationAuthorityHandle, RefusalReason> {
        if self.authorities.len() >= MAXIMUM_RETAINED_SETUP_GENERATION_AUTHORITY_COUNT {
            return Err(RefusalReason::OutsideSupportedProfile);
        }
        self.next_handle = self
            .next_handle
            .checked_add(1)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        self.authorities.insert(self.next_handle, authority);
        Ok(SetupGenerationAuthorityHandle(self.next_handle))
    }
}

fn require_setup_generation_authority_capacity(
    all_family_authority_count: usize,
    vss_proof_authority_count: usize,
) -> Result<(), RefusalReason> {
    if all_family_authority_count
        .checked_add(vss_proof_authority_count)
        .filter(|retained_count| {
            *retained_count < MAXIMUM_RETAINED_SETUP_GENERATION_AUTHORITY_COUNT
        })
        .is_none()
    {
        return Err(RefusalReason::OutsideSupportedProfile);
    }
    Ok(())
}

thread_local! {
    static SETUP_GENERATION_AUTHORITY_REGISTRY: RefCell<SetupGenerationAuthorityRegistry> =
        RefCell::new(SetupGenerationAuthorityRegistry::default());
    static SETUP_GENERATION_PUBLIC_KEY_SHARE_SOURCE_REGISTRY:
        RefCell<SetupGenerationPublicKeyShareSourceRegistry> =
            RefCell::new(SetupGenerationPublicKeyShareSourceRegistry::default());
    static SETUP_GENERATION_RECIPIENT_PAYLOAD_SOURCE_REGISTRY:
        RefCell<SetupGenerationRecipientPayloadSourceRegistry> =
            RefCell::new(SetupGenerationRecipientPayloadSourceRegistry::default());
    static SETUP_GENERATION_VSS_PROOF_AUTHORITY_REGISTRY:
        RefCell<SetupGenerationVssProofAuthorityRegistry> =
            RefCell::new(SetupGenerationVssProofAuthorityRegistry::default());
}

pub(super) fn retain_browser_owned_setup_generation_authority(
    input: SetupGenerationAuthorityInput,
) -> Result<SetupGenerationAuthorityHandle, RefusalReason> {
    let authority = SetupGenerationAuthority::from_browser_owned_input(input)?;
    let vss_proof_authority_count =
        SETUP_GENERATION_VSS_PROOF_AUTHORITY_REGISTRY.with(|registry| {
            registry
                .try_borrow()
                .map(|registry| registry.authorities.len())
                .map_err(|_| RefusalReason::ConsumedState)
        })?;
    SETUP_GENERATION_AUTHORITY_REGISTRY.with(|registry| {
        let mut registry = registry
            .try_borrow_mut()
            .map_err(|_| RefusalReason::ConsumedState)?;
        require_setup_generation_authority_capacity(
            registry.authorities.len(),
            vss_proof_authority_count,
        )?;
        registry.retain(authority)
    })
}

pub(crate) fn setup_generation_retained_memory_accounting(
    handle: &SetupGenerationAuthorityHandle,
) -> Result<SetupGenerationRetainedMemoryAccounting, RefusalReason> {
    let all_family_accounting = SETUP_GENERATION_AUTHORITY_REGISTRY.with(|registry| {
        registry
            .try_borrow()
            .map_err(|_| RefusalReason::ConsumedState)?
            .authorities
            .get(&handle.0)
            .map(|authority| {
                let coefficient_and_canonical_payload_byte_length =
                    authority.retained_coefficient_and_canonical_payload_byte_length()?;
                let wrapper_and_catalog_byte_length =
                    authority.retained_wrapper_and_catalog_byte_length()?;
                let all_family_payload_byte_length = coefficient_and_canonical_payload_byte_length
                    .checked_add(wrapper_and_catalog_byte_length)
                    .ok_or(RefusalReason::OutsideSupportedProfile)?;
                let (_, _, post_release_payload_byte_length) =
                    setup_generation_vss_post_release_memory_accounting(
                        &authority.ordered_roster,
                        authority.vss_material.ordered_coefficient_materials(),
                        authority.vss_material.ordered_recipient_share_materials(),
                        authority.pinned_vss_public_record_binding.as_ref(),
                    )?;
                Ok::<_, RefusalReason>((
                    all_family_payload_byte_length,
                    post_release_payload_byte_length,
                ))
            })
            .transpose()
    })?;
    let vss_proof_accounting = SETUP_GENERATION_VSS_PROOF_AUTHORITY_REGISTRY.with(|registry| {
        registry
            .try_borrow()
            .map_err(|_| RefusalReason::ConsumedState)?
            .authorities
            .get(&handle.0)
            .map(SetupGenerationVssProofAuthority::retained_memory_accounting)
            .transpose()
    })?;
    match (all_family_accounting, vss_proof_accounting) {
        (Some((all_family_payload_byte_length, post_release_payload_byte_length)), None) => {
            Ok(SetupGenerationRetainedMemoryAccounting {
                all_family_payload_byte_length,
                post_release_payload_byte_length,
                vss_proof_phase_is_active: false,
            })
        }
        (None, Some((_, _, post_release_payload_byte_length))) => {
            Ok(SetupGenerationRetainedMemoryAccounting {
                all_family_payload_byte_length: 0,
                post_release_payload_byte_length,
                vss_proof_phase_is_active: true,
            })
        }
        _ => Err(RefusalReason::ConsumedState),
    }
}

pub(crate) fn resolve_setup_generation_key_relation_preparation_source(
    handle: &SetupGenerationAuthorityHandle,
    family: SetupKeyRelationProofFamily,
) -> Result<SetupGenerationKeyRelationPreparationSource, RefusalReason> {
    SETUP_GENERATION_AUTHORITY_REGISTRY.with(|registry| {
        registry
            .try_borrow()
            .map_err(|_| RefusalReason::ConsumedState)?
            .authorities
            .get(&handle.0)
            .ok_or(RefusalReason::ConsumedState)?
            .key_relation_preparation_source(family)
    })
}

pub(crate) fn with_setup_generation_key_relation<Value, Error>(
    handle: &SetupGenerationAuthorityHandle,
    application: &SetupGenerationKeyRelationApplication<'_>,
    operation: impl FnOnce(SetupGenerationKeyRelationSource<'_, '_>) -> Result<Value, Error>,
) -> Result<Value, Error>
where
    Error: From<RefusalReason>,
{
    SETUP_GENERATION_AUTHORITY_REGISTRY.with(|registry| {
        let mut registry = registry
            .try_borrow_mut()
            .map_err(|_| Error::from(RefusalReason::ConsumedState))?;
        let authority = registry
            .authorities
            .get_mut(&handle.0)
            .ok_or_else(|| Error::from(RefusalReason::ConsumedState))?;
        authority
            .pin_key_relation_application(application)
            .map_err(Error::from)?;
        operation(SetupGenerationKeyRelationSource {
            authority_identifier: handle.0,
            authority,
            application,
        })
    })
}

pub(crate) fn resolve_setup_generation_vss_preparation_source(
    handle: &SetupGenerationAuthorityHandle,
) -> Result<SetupGenerationVssPreparationSource, RefusalReason> {
    let retained_source = SETUP_GENERATION_AUTHORITY_REGISTRY.with(|registry| {
        let registry = registry
            .try_borrow()
            .map_err(|_| RefusalReason::ConsumedState)?;
        registry
            .authorities
            .get(&handle.0)
            .map(SetupGenerationAuthority::vss_preparation_source)
            .transpose()
    })?;
    if let Some(source) = retained_source {
        return Ok(source);
    }
    SETUP_GENERATION_VSS_PROOF_AUTHORITY_REGISTRY.with(|registry| {
        registry
            .try_borrow()
            .map_err(|_| RefusalReason::ConsumedState)?
            .authorities
            .get(&handle.0)
            .ok_or(RefusalReason::ConsumedState)?
            .vss_preparation_source()
    })
}

pub(crate) fn resolve_setup_generation_dealer_public_record_source(
    authority_identifier: u32,
    action_private_randomness: &ActionPrivateRandomness,
    roster: &Roster,
    roster_hash: Hash512,
    source_roster_position: u16,
    ordered_recipient_envelope_hashes: &[Hash512],
    share_linkage_proof: &StreamDescriptor,
) -> Result<SetupGenerationDealerPublicRecordSource, RefusalReason> {
    SETUP_GENERATION_VSS_PROOF_AUTHORITY_REGISTRY.with(|registry| {
        registry
            .try_borrow_mut()
            .map_err(|_| RefusalReason::ConsumedState)?
            .authorities
            .get_mut(&authority_identifier)
            .ok_or(RefusalReason::ConsumedState)?
            .dealer_public_record_source(
                action_private_randomness,
                roster,
                roster_hash,
                source_roster_position,
                ordered_recipient_envelope_hashes,
                share_linkage_proof,
            )
    })
}

pub(crate) fn resolve_setup_generation_galois_preparation_source(
    handle: &SetupGenerationAuthorityHandle,
) -> Result<SetupGenerationGaloisPreparationSource, RefusalReason> {
    SETUP_GENERATION_AUTHORITY_REGISTRY.with(|registry| {
        registry
            .try_borrow()
            .map_err(|_| RefusalReason::ConsumedState)?
            .authorities
            .get(&handle.0)
            .ok_or(RefusalReason::ConsumedState)?
            .galois_preparation_source()
    })
}

pub(crate) fn resolve_setup_generation_relinearization_round_one_preparation_source(
    handle: &SetupGenerationAuthorityHandle,
) -> Result<SetupGenerationRelinearizationRoundOnePreparationSource, RefusalReason> {
    SETUP_GENERATION_AUTHORITY_REGISTRY.with(|registry| {
        registry
            .try_borrow()
            .map_err(|_| RefusalReason::ConsumedState)?
            .authorities
            .get(&handle.0)
            .ok_or(RefusalReason::ConsumedState)?
            .relinearization_round_one_preparation_source()
    })
}

pub(crate) fn resolve_setup_generated_relinearization_round_one_source_authority(
    handle: &SetupGenerationAuthorityHandle,
) -> Result<SetupGeneratedRelinearizationRoundOneSourceAuthority, RefusalReason> {
    SETUP_GENERATION_AUTHORITY_REGISTRY.with(|registry| {
        registry
            .try_borrow()
            .map_err(|_| RefusalReason::ConsumedState)?
            .authorities
            .get(&handle.0)
            .ok_or(RefusalReason::ConsumedState)?
            .generated_relinearization_round_one_source_authority()
    })
}

pub(crate) fn resolve_setup_generated_relinearization_round_two_source_authority(
    handle: &SetupGenerationAuthorityHandle,
) -> Result<SetupGeneratedRelinearizationRoundTwoSourceAuthority, RefusalReason> {
    SETUP_GENERATION_AUTHORITY_REGISTRY.with(|registry| {
        registry
            .try_borrow()
            .map_err(|_| RefusalReason::ConsumedState)?
            .authorities
            .get(&handle.0)
            .ok_or(RefusalReason::ConsumedState)?
            .generated_relinearization_round_two
            .as_ref()
            .ok_or(RefusalReason::MissingPrerequisite)?
            .recreate_source_authority()
    })
}

/// Begins the one suite-fixed round-two generation without changing the
/// retained setup authority. The returned state is installed only after its
/// two catalog-owned streams have been authenticated completely.
pub(crate) fn begin_setup_generation_relinearization_round_two_activation(
    handle: &SetupGenerationAuthorityHandle,
    selected_suite: &SelectedSuiteCapability,
    generated_aggregate: &SetupGeneratedRelinearizationAggregateSourceAuthority,
    aggregate_proof_stream_descriptor: &StreamDescriptor,
) -> Result<SetupGenerationRelinearizationRoundTwoActivation, RefusalReason> {
    let activation = SETUP_GENERATION_AUTHORITY_REGISTRY.with(|registry| {
        let registry = registry
            .try_borrow()
            .map_err(|_| RefusalReason::ConsumedState)?;
        registry
            .authorities
            .get(&handle.0)
            .ok_or(RefusalReason::ConsumedState)?
            .begin_relinearization_round_two_activation(
                selected_suite,
                generated_aggregate,
                aggregate_proof_stream_descriptor,
            )
    })?;
    let memory_accounting =
        setup_generation_relinearization_round_two_activation_memory_accounting(
            handle,
            &activation,
        )?;
    if !memory_accounting.fits_absolute_wasm_resident_bound() {
        return Err(RefusalReason::OutsideSupportedProfile);
    }
    Ok(activation)
}

pub(crate) fn setup_generation_relinearization_round_two_activation_memory_accounting(
    handle: &SetupGenerationAuthorityHandle,
    activation: &SetupGenerationRelinearizationRoundTwoActivation,
) -> Result<SetupGenerationRelinearizationRoundTwoActivationMemoryAccounting, RefusalReason> {
    activation.memory_accounting(setup_generation_retained_memory_accounting(handle)?)
}

pub(crate) fn absorb_setup_generation_relinearization_round_two_activation_pair(
    handle: &SetupGenerationAuthorityHandle,
    activation: &mut SetupGenerationRelinearizationRoundTwoActivation,
    aggregate_left_bytes: &[u8],
    aggregate_right_bytes: &[u8],
) -> Result<(), RefusalReason> {
    SETUP_GENERATION_AUTHORITY_REGISTRY.with(|registry| {
        let registry = registry
            .try_borrow()
            .map_err(|_| RefusalReason::ConsumedState)?;
        registry
            .authorities
            .get(&handle.0)
            .ok_or(RefusalReason::ConsumedState)?
            .absorb_relinearization_round_two_activation_pair(
                activation,
                aggregate_left_bytes,
                aggregate_right_bytes,
            )
    })
}

pub(crate) fn finish_setup_generation_relinearization_round_two_activation(
    handle: &SetupGenerationAuthorityHandle,
    activation: &mut SetupGenerationRelinearizationRoundTwoActivation,
    generated_aggregate: &SetupGeneratedRelinearizationAggregateSourceAuthority,
    aggregate_proof_stream_descriptor: &StreamDescriptor,
) -> Result<SetupGenerationRelinearizationRoundTwoPreparationSource, RefusalReason> {
    SETUP_GENERATION_AUTHORITY_REGISTRY.with(|registry| {
        let mut registry = registry
            .try_borrow_mut()
            .map_err(|_| RefusalReason::ConsumedState)?;
        registry
            .authorities
            .get_mut(&handle.0)
            .ok_or(RefusalReason::ConsumedState)?
            .finish_relinearization_round_two_activation(
                activation,
                generated_aggregate,
                aggregate_proof_stream_descriptor,
            )
    })
}

/// Reopens the public preparation facts after activation without regenerating
/// the retained round-two component. This is the reset-safe checkpoint-resume
/// path; the generated aggregate binding remains inside the authority.
pub(crate) fn resolve_setup_generation_relinearization_round_two_preparation_source(
    handle: &SetupGenerationAuthorityHandle,
) -> Result<SetupGenerationRelinearizationRoundTwoPreparationSource, RefusalReason> {
    SETUP_GENERATION_AUTHORITY_REGISTRY.with(|registry| {
        registry
            .try_borrow()
            .map_err(|_| RefusalReason::ConsumedState)?
            .authorities
            .get(&handle.0)
            .ok_or(RefusalReason::ConsumedState)?
            .relinearization_round_two_preparation_source()
    })
}

pub(crate) fn with_setup_generation_relinearization_round_one<Value, Error>(
    handle: &SetupGenerationAuthorityHandle,
    application: &SetupGenerationRelinearizationRoundOneApplication<'_>,
    operation: impl FnOnce(SetupGenerationRelinearizationRoundOneSource<'_, '_>) -> Result<Value, Error>,
) -> Result<Value, Error>
where
    Error: From<RefusalReason>,
{
    SETUP_GENERATION_AUTHORITY_REGISTRY.with(|registry| {
        let mut registry = registry
            .try_borrow_mut()
            .map_err(|_| Error::from(RefusalReason::ConsumedState))?;
        let authority = registry
            .authorities
            .get_mut(&handle.0)
            .ok_or_else(|| Error::from(RefusalReason::ConsumedState))?;
        authority
            .pin_relinearization_round_one_application(application)
            .map_err(Error::from)?;
        operation(SetupGenerationRelinearizationRoundOneSource {
            authority_identifier: handle.0,
            authority,
            application,
        })
    })
}

pub(crate) fn with_setup_generation_relinearization_round_two<Value, Error>(
    handle: &SetupGenerationAuthorityHandle,
    application: &SetupGenerationRelinearizationRoundTwoApplication<'_>,
    generated_aggregate: &SetupGeneratedRelinearizationAggregateSourceAuthority,
    aggregate_proof_stream_descriptor: &StreamDescriptor,
    operation: impl FnOnce(SetupGenerationRelinearizationRoundTwoSource<'_, '_>) -> Result<Value, Error>,
) -> Result<Value, Error>
where
    Error: From<RefusalReason>,
{
    SETUP_GENERATION_AUTHORITY_REGISTRY.with(|registry| {
        let mut registry = registry
            .try_borrow_mut()
            .map_err(|_| Error::from(RefusalReason::ConsumedState))?;
        let authority = registry
            .authorities
            .get_mut(&handle.0)
            .ok_or_else(|| Error::from(RefusalReason::ConsumedState))?;
        authority
            .validate_relinearization_round_two_aggregate(
                generated_aggregate,
                aggregate_proof_stream_descriptor,
            )
            .map_err(Error::from)?;
        authority
            .pin_relinearization_round_two_application(application)
            .map_err(Error::from)?;
        let generated_round_two = authority
            .generated_relinearization_round_two
            .as_ref()
            .ok_or_else(|| Error::from(RefusalReason::MissingPrerequisite))?;
        operation(SetupGenerationRelinearizationRoundTwoSource {
            authority_identifier: handle.0,
            authority,
            application,
            generated_round_two,
        })
    })
}

/// Reenters the retained round-two witness after its aggregate bytes and
/// generated binding were authenticated during activation. This is the proof
/// provider's restart path; it accepts no caller-described aggregate roots,
/// descriptors, topology, or bytes.
pub(crate) fn with_setup_generation_relinearization_round_two_witness<Value, Error>(
    handle: &SetupGenerationAuthorityHandle,
    application: &SetupGenerationRelinearizationRoundTwoApplication<'_>,
    operation: impl FnOnce(SetupGenerationRelinearizationRoundTwoSource<'_, '_>) -> Result<Value, Error>,
) -> Result<Value, Error>
where
    Error: From<RefusalReason>,
{
    SETUP_GENERATION_AUTHORITY_REGISTRY.with(|registry| {
        let mut registry = registry
            .try_borrow_mut()
            .map_err(|_| Error::from(RefusalReason::ConsumedState))?;
        let authority = registry
            .authorities
            .get_mut(&handle.0)
            .ok_or_else(|| Error::from(RefusalReason::ConsumedState))?;
        authority
            .pin_relinearization_round_two_application(application)
            .map_err(Error::from)?;
        let generated_round_two = authority
            .generated_relinearization_round_two
            .as_ref()
            .ok_or_else(|| Error::from(RefusalReason::MissingPrerequisite))?;
        operation(SetupGenerationRelinearizationRoundTwoSource {
            authority_identifier: handle.0,
            authority,
            application,
            generated_round_two,
        })
    })
}

pub(crate) fn with_setup_generation_galois_batch<Value, Error>(
    handle: &SetupGenerationAuthorityHandle,
    application: &SetupGenerationGaloisApplication<'_>,
    operation: impl FnOnce(SetupGenerationGaloisBatchSource<'_, '_>) -> Result<Value, Error>,
) -> Result<Value, Error>
where
    Error: From<RefusalReason>,
{
    SETUP_GENERATION_AUTHORITY_REGISTRY.with(|registry| {
        let mut registry = registry
            .try_borrow_mut()
            .map_err(|_| Error::from(RefusalReason::ConsumedState))?;
        let authority = registry
            .authorities
            .get_mut(&handle.0)
            .ok_or_else(|| Error::from(RefusalReason::ConsumedState))?;
        authority
            .pin_galois_application(application)
            .map_err(Error::from)?;
        operation(SetupGenerationGaloisBatchSource {
            authority_identifier: handle.0,
            authority,
            application,
        })
    })
}

/// Borrows one exact public Galois component chunk from the retained setup
/// generation authority. The expected descriptor is minted by the matching
/// generated-source authority, so this seam cannot be used to select a
/// caller-described byte stream or expose any secret witness material.
pub(crate) fn with_setup_generation_galois_public_component_chunk<Value>(
    handle: &SetupGenerationAuthorityHandle,
    component_ordinal: usize,
    expected_stream_descriptor: &StreamDescriptor,
    chunk_index: usize,
    operation: impl FnOnce(&[u8]) -> Value,
) -> Result<Value, RefusalReason> {
    SETUP_GENERATION_AUTHORITY_REGISTRY.with(|registry| {
        let registry = registry
            .try_borrow()
            .map_err(|_| RefusalReason::ConsumedState)?;
        let authority = registry
            .authorities
            .get(&handle.0)
            .ok_or(RefusalReason::ConsumedState)?;
        let component = authority
            .ordered_galois_entries
            .get(component_ordinal)
            .map(SetupGeneratedGaloisEntry::component)
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        if component.stream_descriptor() != expected_stream_descriptor
            || u64::try_from(component.canonical_bytes().len()).ok()
                != Some(expected_stream_descriptor.total_byte_length)
        {
            return Err(RefusalReason::WrongHashOrRoot);
        }
        let chunk_byte_length = FOUNDATION_PROFILE.stream_chunk_byte_length;
        let byte_start = chunk_index
            .checked_mul(chunk_byte_length)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        let byte_end = byte_start
            .checked_add(chunk_byte_length)
            .map(|end| end.min(component.canonical_bytes().len()))
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        let chunk = component
            .canonical_bytes()
            .get(byte_start..byte_end)
            .filter(|chunk| {
                chunk_index < expected_stream_descriptor.ordered_chunk_digests.len()
                    && !chunk.is_empty()
            })
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        Ok(operation(chunk))
    })
}

pub(crate) fn with_setup_generation_relinearization_round_one_component_chunk<Value>(
    handle: &SetupGenerationAuthorityHandle,
    component_ordinal: usize,
    expected_stream_descriptor: &StreamDescriptor,
    chunk_index: usize,
    operation: impl FnOnce(&[u8]) -> Value,
) -> Result<Value, RefusalReason> {
    SETUP_GENERATION_AUTHORITY_REGISTRY.with(|registry| {
        let registry = registry
            .try_borrow()
            .map_err(|_| RefusalReason::ConsumedState)?;
        let authority = registry
            .authorities
            .get(&handle.0)
            .ok_or(RefusalReason::ConsumedState)?;
        let component = match component_ordinal {
            0 => authority
                .relinearization_material
                .round_one_left_component(),
            1 => authority
                .relinearization_material
                .round_one_right_component(),
            _ => return Err(RefusalReason::WrongTypeOrLength),
        };
        if component.stream_descriptor() != expected_stream_descriptor
            || u64::try_from(component.canonical_bytes().len()).ok()
                != Some(expected_stream_descriptor.total_byte_length)
        {
            return Err(RefusalReason::WrongHashOrRoot);
        }
        let chunk_byte_length = FOUNDATION_PROFILE.stream_chunk_byte_length;
        let byte_start = chunk_index
            .checked_mul(chunk_byte_length)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        let byte_end = byte_start
            .checked_add(chunk_byte_length)
            .map(|end| end.min(component.canonical_bytes().len()))
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        let chunk = component
            .canonical_bytes()
            .get(byte_start..byte_end)
            .filter(|chunk| {
                chunk_index < expected_stream_descriptor.ordered_chunk_digests.len()
                    && !chunk.is_empty()
            })
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        Ok(operation(chunk))
    })
}

pub(crate) fn with_setup_generation_relinearization_round_two_component_chunk<Value>(
    handle: &SetupGenerationAuthorityHandle,
    expected_stream_descriptor: &StreamDescriptor,
    chunk_index: usize,
    operation: impl FnOnce(&[u8]) -> Value,
) -> Result<Value, RefusalReason> {
    SETUP_GENERATION_AUTHORITY_REGISTRY.with(|registry| {
        let registry = registry
            .try_borrow()
            .map_err(|_| RefusalReason::ConsumedState)?;
        let authority = registry
            .authorities
            .get(&handle.0)
            .ok_or(RefusalReason::ConsumedState)?;
        let component = authority
            .generated_relinearization_round_two
            .as_ref()
            .map(SetupGeneratedRelinearizationRoundTwoGeneration::component)
            .ok_or(RefusalReason::MissingPrerequisite)?;
        if component.stream_descriptor() != expected_stream_descriptor
            || u64::try_from(component.canonical_bytes().len()).ok()
                != Some(expected_stream_descriptor.total_byte_length)
        {
            return Err(RefusalReason::WrongHashOrRoot);
        }
        let chunk_byte_length = FOUNDATION_PROFILE.stream_chunk_byte_length;
        let byte_start = chunk_index
            .checked_mul(chunk_byte_length)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        let byte_end = byte_start
            .checked_add(chunk_byte_length)
            .map(|end| end.min(component.canonical_bytes().len()))
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        let chunk = component
            .canonical_bytes()
            .get(byte_start..byte_end)
            .filter(|chunk| {
                chunk_index < expected_stream_descriptor.ordered_chunk_digests.len()
                    && !chunk.is_empty()
            })
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        Ok(operation(chunk))
    })
}

pub(crate) fn with_setup_generation_vss_material<Value, Error>(
    handle: &SetupGenerationAuthorityHandle,
    application: &SetupGenerationVssApplication<'_>,
    operation: impl FnOnce(SetupGenerationVssSource<'_, '_>) -> Result<Value, Error>,
) -> Result<Value, Error>
where
    Error: From<RefusalReason>,
{
    let vss_phase_is_already_active =
        SETUP_GENERATION_VSS_PROOF_AUTHORITY_REGISTRY.with(|registry| {
            registry
                .try_borrow()
                .map(|registry| registry.authorities.contains_key(&handle.0))
                .map_err(|_| Error::from(RefusalReason::ConsumedState))
        })?;
    if !vss_phase_is_already_active {
        let public_key_source_is_live =
            SETUP_GENERATION_PUBLIC_KEY_SHARE_SOURCE_REGISTRY.with(|registry| {
                registry
                    .try_borrow()
                    .map(|registry| registry.contains_source_for_authority(handle.0))
                    .map_err(|_| Error::from(RefusalReason::ConsumedState))
            })?;
        let recipient_source_is_live =
            SETUP_GENERATION_RECIPIENT_PAYLOAD_SOURCE_REGISTRY.with(|registry| {
                registry
                    .try_borrow()
                    .map(|registry| registry.contains_source_for_authority(handle.0))
                    .map_err(|_| Error::from(RefusalReason::ConsumedState))
            })?;
        if public_key_source_is_live || recipient_source_is_live {
            return Err(Error::from(RefusalReason::MissingPrerequisite));
        }
        SETUP_GENERATION_VSS_PROOF_AUTHORITY_REGISTRY.with(|registry| {
            let mut registry = registry
                .try_borrow_mut()
                .map_err(|_| Error::from(RefusalReason::ConsumedState))?;
            if registry.authorities.contains_key(&handle.0)
                || registry.authorities.len() >= MAXIMUM_RETAINED_SETUP_GENERATION_AUTHORITY_COUNT
            {
                return Err(Error::from(RefusalReason::ConsumedState));
            }
            let vss_proof_authority = SETUP_GENERATION_AUTHORITY_REGISTRY.with(|registry| {
                let mut registry = registry
                    .try_borrow_mut()
                    .map_err(|_| Error::from(RefusalReason::ConsumedState))?;
                let authority = registry
                    .authorities
                    .get_mut(&handle.0)
                    .ok_or_else(|| Error::from(RefusalReason::ConsumedState))?;
                authority
                    .pin_vss_application(application)
                    .map_err(Error::from)?;
                authority
                    .require_vss_proof_phase_release_prerequisites()
                    .map_err(Error::from)?;
                registry
                    .authorities
                    .remove(&handle.0)
                    .map(SetupGenerationAuthority::into_vss_proof_authority)
                    .ok_or_else(|| Error::from(RefusalReason::ConsumedState))
            })?;
            let replaced = registry.authorities.insert(handle.0, vss_proof_authority);
            debug_assert!(replaced.is_none());
            Ok::<_, Error>(())
        })?;
    }
    SETUP_GENERATION_VSS_PROOF_AUTHORITY_REGISTRY.with(|registry| {
        let mut registry = registry
            .try_borrow_mut()
            .map_err(|_| Error::from(RefusalReason::ConsumedState))?;
        let authority = registry
            .authorities
            .get_mut(&handle.0)
            .ok_or_else(|| Error::from(RefusalReason::ConsumedState))?;
        authority
            .pin_vss_application(application)
            .map_err(Error::from)?;
        operation(SetupGenerationVssSource {
            authority,
            application,
        })
    })
}

pub(crate) fn release_setup_generation_authority(
    handle: SetupGenerationAuthorityHandle,
) -> Result<(), RefusalReason> {
    SETUP_GENERATION_RECIPIENT_PAYLOAD_SOURCE_REGISTRY.with(|recipient_source_registry| {
        let mut recipient_source_registry = recipient_source_registry
            .try_borrow_mut()
            .map_err(|_| RefusalReason::ConsumedState)?;
        SETUP_GENERATION_PUBLIC_KEY_SHARE_SOURCE_REGISTRY.with(|public_source_registry| {
            let mut public_source_registry = public_source_registry
                .try_borrow_mut()
                .map_err(|_| RefusalReason::ConsumedState)?;
            SETUP_GENERATION_VSS_PROOF_AUTHORITY_REGISTRY.with(|vss_authority_registry| {
                let mut vss_authority_registry = vss_authority_registry
                    .try_borrow_mut()
                    .map_err(|_| RefusalReason::ConsumedState)?;
                SETUP_GENERATION_AUTHORITY_REGISTRY.with(|authority_registry| {
                    let mut authority_registry = authority_registry
                        .try_borrow_mut()
                        .map_err(|_| RefusalReason::ConsumedState)?;
                    if !authority_registry.authorities.contains_key(&handle.0)
                        && !vss_authority_registry.authorities.contains_key(&handle.0)
                    {
                        return Err(RefusalReason::ConsumedState);
                    }
                    recipient_source_registry.release_for_authority(handle.0);
                    public_source_registry.release_for_authority(handle.0);
                    authority_registry.authorities.remove(&handle.0);
                    vss_authority_registry.authorities.remove(&handle.0);
                    Ok(())
                })
            })
        })
    })
}

pub(crate) fn setup_generation_public_key_share_body_byte_length(
    authority_handle: &SetupGenerationAuthorityHandle,
) -> Result<u64, RefusalReason> {
    SETUP_GENERATION_AUTHORITY_REGISTRY.with(|registry| {
        let registry = registry
            .try_borrow()
            .map_err(|_| RefusalReason::ConsumedState)?;
        let authority = registry
            .authorities
            .get(&authority_handle.0)
            .ok_or(RefusalReason::ConsumedState)?;
        u64::try_from(authority.public_key_share.selected_body_byte_length()?)
            .map_err(|_| RefusalReason::OutsideSupportedProfile)
    })
}

pub(crate) fn open_setup_generation_public_key_share_body(
    authority_handle: &SetupGenerationAuthorityHandle,
) -> Result<SetupGenerationPublicKeyShareSourceHandle, RefusalReason> {
    SETUP_GENERATION_PUBLIC_KEY_SHARE_SOURCE_REGISTRY.with(|source_registry| {
        let mut source_registry = source_registry
            .try_borrow_mut()
            .map_err(|_| RefusalReason::ConsumedState)?;
        let source_handle = source_registry.next_available_handle()?;
        SETUP_GENERATION_AUTHORITY_REGISTRY.with(|authority_registry| {
            let mut authority_registry = authority_registry
                .try_borrow_mut()
                .map_err(|_| RefusalReason::ConsumedState)?;
            let authority = authority_registry
                .authorities
                .get_mut(&authority_handle.0)
                .ok_or(RefusalReason::ConsumedState)?;
            if authority.public_key_share_body_source_opened {
                return Err(RefusalReason::ConsumedState);
            }
            let body_byte_length = authority.public_key_share.selected_body_byte_length()?;
            authority.public_key_share_body_source_opened = true;
            Ok(source_registry.retain_at(
                source_handle,
                SetupGenerationPublicKeyShareSource {
                    owner_authority_identifier: authority_handle.0,
                    body_byte_length,
                    next_offset: 0,
                },
            ))
        })
    })
}

pub(crate) fn setup_generation_public_key_share_source_byte_length(
    source_handle: &SetupGenerationPublicKeyShareSourceHandle,
) -> Result<u64, RefusalReason> {
    SETUP_GENERATION_PUBLIC_KEY_SHARE_SOURCE_REGISTRY.with(|registry| {
        let registry = registry
            .try_borrow()
            .map_err(|_| RefusalReason::ConsumedState)?;
        let source = registry
            .sources
            .get(&source_handle.0)
            .ok_or(RefusalReason::ConsumedState)?;
        u64::try_from(source.body_byte_length).map_err(|_| RefusalReason::OutsideSupportedProfile)
    })
}

pub(crate) fn read_setup_generation_public_key_share_body(
    source_handle: &SetupGenerationPublicKeyShareSourceHandle,
    expected_offset: u64,
    output: &mut [u8],
) -> Result<(), RefusalReason> {
    let expected_offset =
        usize::try_from(expected_offset).map_err(|_| RefusalReason::OutsideSupportedProfile)?;
    SETUP_GENERATION_PUBLIC_KEY_SHARE_SOURCE_REGISTRY.with(|source_registry| {
        let mut source_registry = source_registry
            .try_borrow_mut()
            .map_err(|_| RefusalReason::ConsumedState)?;
        let finished = {
            let source = source_registry
                .sources
                .get_mut(&source_handle.0)
                .ok_or(RefusalReason::ConsumedState)?;
            SETUP_GENERATION_AUTHORITY_REGISTRY.with(|authority_registry| {
                let mut authority_registry = authority_registry
                    .try_borrow_mut()
                    .map_err(|_| RefusalReason::ConsumedState)?;
                let authority = authority_registry
                    .authorities
                    .get_mut(&source.owner_authority_identifier)
                    .ok_or(RefusalReason::ConsumedState)?;
                let finished =
                    source.read_into(&authority.public_key_share, expected_offset, output)?;
                if finished {
                    authority.public_key_share_body_stream_completed = true;
                }
                Ok(finished)
            })?
        };
        if finished {
            let removed_source = source_registry.sources.remove(&source_handle.0);
            debug_assert!(removed_source.is_some());
        }
        Ok(())
    })
}

pub(crate) fn cancel_setup_generation_public_key_share_body(
    source_handle: SetupGenerationPublicKeyShareSourceHandle,
) -> Result<(), RefusalReason> {
    SETUP_GENERATION_PUBLIC_KEY_SHARE_SOURCE_REGISTRY.with(|registry| {
        registry
            .try_borrow_mut()
            .map_err(|_| RefusalReason::ConsumedState)?
            .sources
            .remove(&source_handle.0)
            .map(|_| ())
            .ok_or(RefusalReason::ConsumedState)
    })
}

pub(crate) fn setup_generation_recipient_vss_payload_byte_length(
    authority_handle: &SetupGenerationAuthorityHandle,
    recipient_roster_position: u16,
) -> Result<u64, RefusalReason> {
    SETUP_GENERATION_AUTHORITY_REGISTRY.with(|registry| {
        registry
            .try_borrow()
            .map_err(|_| RefusalReason::ConsumedState)?
            .authorities
            .get(&authority_handle.0)
            .ok_or(RefusalReason::ConsumedState)?
            .vss_material
            .recipient_private_payload_byte_length(recipient_roster_position)
    })
}

pub(crate) fn open_setup_generation_recipient_vss_payload(
    authority_handle: &SetupGenerationAuthorityHandle,
    recipient_roster_position: u16,
) -> Result<SetupGenerationRecipientPayloadSourceHandle, RefusalReason> {
    if recipient_roster_position >= FOUNDATION_PROFILE.participant_count {
        return Err(RefusalReason::WrongTypeOrLength);
    }
    SETUP_GENERATION_RECIPIENT_PAYLOAD_SOURCE_REGISTRY.with(|source_registry| {
        let mut source_registry = source_registry
            .try_borrow_mut()
            .map_err(|_| RefusalReason::ConsumedState)?;
        let source_handle = source_registry.next_available_handle()?;
        SETUP_GENERATION_AUTHORITY_REGISTRY.with(|authority_registry| {
            let mut authority_registry = authority_registry
                .try_borrow_mut()
                .map_err(|_| RefusalReason::ConsumedState)?;
            let authority = authority_registry
                .authorities
                .get_mut(&authority_handle.0)
                .ok_or(RefusalReason::ConsumedState)?;
            let payload = authority
                .vss_material
                .take_recipient_private_payload(recipient_roster_position)?;
            debug_assert_eq!(payload.recipient_roster_position, recipient_roster_position);
            Ok(source_registry.retain_at(
                source_handle,
                SetupGenerationRecipientPayloadSource {
                    owner_authority_identifier: authority_handle.0,
                    recipient_roster_position,
                    canonical_bytes: payload.canonical_bytes,
                    next_offset: 0,
                },
            ))
        })
    })
}

pub(crate) fn setup_generation_recipient_vss_payload_source_byte_length(
    source_handle: &SetupGenerationRecipientPayloadSourceHandle,
) -> Result<u64, RefusalReason> {
    SETUP_GENERATION_RECIPIENT_PAYLOAD_SOURCE_REGISTRY.with(|registry| {
        let registry = registry
            .try_borrow()
            .map_err(|_| RefusalReason::ConsumedState)?;
        let source = registry
            .sources
            .get(&source_handle.0)
            .ok_or(RefusalReason::ConsumedState)?;
        u64::try_from(source.canonical_bytes.len())
            .map_err(|_| RefusalReason::OutsideSupportedProfile)
    })
}

pub(crate) fn setup_generation_recipient_vss_payload_source_recipient_roster_position(
    source_handle: &SetupGenerationRecipientPayloadSourceHandle,
) -> Result<u16, RefusalReason> {
    SETUP_GENERATION_RECIPIENT_PAYLOAD_SOURCE_REGISTRY.with(|registry| {
        registry
            .try_borrow()
            .map_err(|_| RefusalReason::ConsumedState)?
            .sources
            .get(&source_handle.0)
            .map(|source| source.recipient_roster_position)
            .ok_or(RefusalReason::ConsumedState)
    })
}

pub(crate) fn read_setup_generation_recipient_vss_payload_chunk(
    source_handle: &SetupGenerationRecipientPayloadSourceHandle,
    expected_offset: u64,
    requested_byte_length: usize,
) -> Result<Zeroizing<Vec<u8>>, RefusalReason> {
    let expected_offset =
        usize::try_from(expected_offset).map_err(|_| RefusalReason::OutsideSupportedProfile)?;
    SETUP_GENERATION_RECIPIENT_PAYLOAD_SOURCE_REGISTRY.with(|registry| {
        let mut registry = registry
            .try_borrow_mut()
            .map_err(|_| RefusalReason::ConsumedState)?;
        registry.read_chunk_and_record_completion(
            source_handle,
            expected_offset,
            requested_byte_length,
            |owner_authority_identifier| {
                SETUP_GENERATION_AUTHORITY_REGISTRY.with(|authority_registry| {
                    let mut authority_registry = authority_registry
                        .try_borrow_mut()
                        .map_err(|_| RefusalReason::ConsumedState)?;
                    let authority = authority_registry
                        .authorities
                        .get_mut(&owner_authority_identifier)
                        .ok_or(RefusalReason::ConsumedState)?;
                    authority.completed_recipient_private_payload_count = authority
                        .completed_recipient_private_payload_count
                        .checked_add(1)
                        .filter(|count| *count <= usize::from(FOUNDATION_PROFILE.participant_count))
                        .ok_or(RefusalReason::OutsideSupportedProfile)?;
                    Ok(())
                })
            },
        )
    })
}

pub(crate) fn cancel_setup_generation_recipient_vss_payload(
    source_handle: SetupGenerationRecipientPayloadSourceHandle,
) -> Result<(), RefusalReason> {
    SETUP_GENERATION_RECIPIENT_PAYLOAD_SOURCE_REGISTRY.with(|registry| {
        registry
            .try_borrow_mut()
            .map_err(|_| RefusalReason::ConsumedState)?
            .sources
            .remove(&source_handle.0)
            .map(|_| ())
            .ok_or(RefusalReason::ConsumedState)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(marker: u8) -> Hash512 {
        Hash512::from_bytes([marker; Hash512::BYTE_LENGTH])
    }

    fn stream_descriptor(marker: u8) -> StreamDescriptor {
        StreamDescriptor::new(1, vec![hash(marker)], hash(marker.wrapping_add(1))).unwrap()
    }

    #[test]
    fn round_two_activation_accounting_keeps_mutually_exclusive_phase_peaks_separate() {
        let root_dominant =
            SetupGenerationRelinearizationRoundTwoActivationMemoryAccounting::from_live_phase_payloads(
                300, 10, 40, 90, 30, 20, 100,
            )
            .unwrap();
        assert_eq!(root_dominant.maximum_overlap_byte_length, 470);

        let ingestion_dominant =
            SetupGenerationRelinearizationRoundTwoActivationMemoryAccounting::from_live_phase_payloads(
                300, 10, 40, 190, 30, 20, 100,
            )
            .unwrap();
        assert_eq!(ingestion_dominant.maximum_overlap_byte_length, 570);
    }

    #[test]
    fn round_two_activation_accounting_rejects_every_overflow_boundary() {
        for (
            retained_authority_payload_byte_length,
            activation_binding_payload_byte_length,
            setup_matrix_cache_payload_byte_length,
            pre_root_construction_payload_byte_length,
            generation_workspace_payload_peak_byte_length,
            root_overlap_construction_payload_byte_length,
            streamed_root_transient_payload_byte_length,
        ) in [
            (u64::MAX, 1, 0, 0, 0, 0, 0),
            (u64::MAX - 1, 1, 1, 0, 0, 0, 0),
            (u64::MAX - 2, 1, 1, 1, 0, 0, 0),
            (u64::MAX - 2, 1, 1, 0, 1, 0, 0),
            (u64::MAX - 2, 1, 1, 0, 0, 1, 0),
            (u64::MAX - 2, 1, 1, 0, 0, 0, 1),
        ] {
            assert_eq!(
                SetupGenerationRelinearizationRoundTwoActivationMemoryAccounting::from_live_phase_payloads(
                    retained_authority_payload_byte_length,
                    activation_binding_payload_byte_length,
                    setup_matrix_cache_payload_byte_length,
                    pre_root_construction_payload_byte_length,
                    generation_workspace_payload_peak_byte_length,
                    root_overlap_construction_payload_byte_length,
                    streamed_root_transient_payload_byte_length,
                )
                .unwrap_err(),
                RefusalReason::OutsideSupportedProfile
            );
        }
    }

    #[test]
    fn setup_generation_capacity_is_shared_across_both_lifecycle_registries() {
        let maximum = MAXIMUM_RETAINED_SETUP_GENERATION_AUTHORITY_COUNT;
        assert_eq!(
            require_setup_generation_authority_capacity(maximum - 1, 0),
            Ok(())
        );
        assert_eq!(
            require_setup_generation_authority_capacity(0, maximum - 1),
            Ok(())
        );
        assert_eq!(
            require_setup_generation_authority_capacity(maximum / 2, maximum / 2),
            Err(RefusalReason::OutsideSupportedProfile)
        );
        assert_eq!(
            require_setup_generation_authority_capacity(usize::MAX, 1),
            Err(RefusalReason::OutsideSupportedProfile)
        );
    }

    #[test]
    fn vss_public_record_binding_is_reset_safe_and_refuses_forks() {
        let ordered_recipient_envelope_hashes = (0..FOUNDATION_PROFILE.participant_count)
            .map(|roster_position| hash(u8::try_from(roster_position).unwrap().wrapping_add(10)))
            .collect::<Vec<_>>();
        let share_linkage_proof = stream_descriptor(40);
        let mut retained_binding = None;

        SetupGenerationVssPublicRecordBinding::pin_exact(
            &mut retained_binding,
            &ordered_recipient_envelope_hashes,
            &share_linkage_proof,
        )
        .unwrap();
        SetupGenerationVssPublicRecordBinding::pin_exact(
            &mut retained_binding,
            &ordered_recipient_envelope_hashes,
            &share_linkage_proof,
        )
        .unwrap();

        assert_eq!(
            SetupGenerationVssPublicRecordBinding::pin_exact(
                &mut retained_binding,
                &ordered_recipient_envelope_hashes,
                &stream_descriptor(50),
            )
            .unwrap_err(),
            RefusalReason::ConsumedState
        );
        let mut changed_recipient_envelope_hashes = ordered_recipient_envelope_hashes.clone();
        changed_recipient_envelope_hashes[3] = hash(90);
        assert_eq!(
            SetupGenerationVssPublicRecordBinding::pin_exact(
                &mut retained_binding,
                &changed_recipient_envelope_hashes,
                &share_linkage_proof,
            )
            .unwrap_err(),
            RefusalReason::ConsumedState
        );
        assert_eq!(
            retained_binding.unwrap(),
            SetupGenerationVssPublicRecordBinding {
                ordered_recipient_envelope_hashes: ordered_recipient_envelope_hashes
                    .into_boxed_slice(),
                share_linkage_proof,
            }
        );
    }

    fn recipient_payload_source(
        owner_authority_identifier: u32,
        recipient_roster_position: u16,
        canonical_bytes: &[u8],
    ) -> SetupGenerationRecipientPayloadSource {
        SetupGenerationRecipientPayloadSource {
            owner_authority_identifier,
            recipient_roster_position,
            canonical_bytes: Zeroizing::new(canonical_bytes.to_vec()),
            next_offset: 0,
        }
    }

    fn public_key_share_for_source_test(
        ordered_limb_coefficients: &[&[u64]],
    ) -> SetupGeneratedPublicKeyShare {
        SetupGeneratedPublicKeyShare {
            public_polynomial_context_hash: [1_u8; Hash512::BYTE_LENGTH],
            root: [2_u8; Hash512::BYTE_LENGTH],
            ordered_data_modulus_indices: (0..ordered_limb_coefficients.len())
                .map(|data_modulus_index| u16::try_from(data_modulus_index).unwrap())
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            ordered_limb_coefficients: ordered_limb_coefficients
                .iter()
                .map(|coefficients| Zeroizing::new(coefficients.to_vec()))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            centered_error_coefficients: Zeroizing::new(vec![
                0;
                ordered_limb_coefficients[0].len()
            ]),
        }
    }

    fn public_key_share_source(
        owner_authority_identifier: u32,
        body_byte_length: usize,
    ) -> SetupGenerationPublicKeyShareSource {
        SetupGenerationPublicKeyShareSource {
            owner_authority_identifier,
            body_byte_length,
            next_offset: 0,
        }
    }

    #[test]
    fn selected_public_key_share_body_has_the_exact_full_q_length() {
        assert_eq!(DATA_PRIMES.len(), 23);
        assert_eq!(POLYNOMIAL_DEGREE, 32_768);
        assert_eq!(
            SELECTED_SETUP_GENERATION_PUBLIC_KEY_SHARE_BODY_BYTE_LENGTH,
            6_029_312
        );
    }

    #[test]
    fn public_key_share_body_ranges_follow_limb_coefficient_little_endian_order() {
        let first_limb = [0x0807_0605_0403_0201_u64, 0x1817_1615_1413_1211_u64];
        let second_limb = [0x2827_2625_2423_2221_u64, 0x3837_3635_3433_3231_u64];
        let public_key_share = public_key_share_for_source_test(&[&first_limb, &second_limb]);
        let expected_body = first_limb
            .into_iter()
            .chain(second_limb)
            .flat_map(u64::to_le_bytes)
            .collect::<Vec<_>>();
        assert_eq!(
            public_key_share.body_byte_length().unwrap(),
            expected_body.len()
        );

        let mut unaligned_range = [0_u8; 19];
        assert!(
            !public_key_share
                .write_body_range(5, &mut unaligned_range)
                .unwrap()
        );
        assert_eq!(unaligned_range.as_slice(), &expected_body[5..24]);

        let mut final_range = [0_u8; 8];
        assert!(
            public_key_share
                .write_body_range(expected_body.len() - final_range.len(), &mut final_range)
                .unwrap()
        );
        assert_eq!(
            final_range.as_slice(),
            &expected_body[expected_body.len() - final_range.len()..]
        );
        assert_eq!(
            public_key_share
                .write_body_range(expected_body.len(), &mut [0_u8; 1])
                .unwrap_err(),
            RefusalReason::WrongTypeOrLength
        );
    }

    #[test]
    fn public_key_share_source_requires_monotonic_nonempty_ranges() {
        let limb = [0x0807_0605_0403_0201_u64, 0x1817_1615_1413_1211_u64];
        let public_key_share = public_key_share_for_source_test(&[&limb]);
        let mut source = public_key_share_source(17, 16);

        assert_eq!(
            source
                .read_into(&public_key_share, 1, &mut [0_u8; 4])
                .unwrap_err(),
            RefusalReason::WrongContext
        );
        assert_eq!(
            source.read_into(&public_key_share, 0, &mut []).unwrap_err(),
            RefusalReason::WrongTypeOrLength
        );
        assert_eq!(source.next_offset, 0);

        let mut first_range = [0_u8; 7];
        assert!(
            !source
                .read_into(&public_key_share, 0, &mut first_range)
                .unwrap()
        );
        assert_eq!(first_range, [1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(source.next_offset, 7);
        assert_eq!(
            source
                .read_into(&public_key_share, 0, &mut [0_u8; 1])
                .unwrap_err(),
            RefusalReason::WrongContext
        );

        let mut final_range = [0_u8; 9];
        assert!(
            source
                .read_into(&public_key_share, 7, &mut final_range)
                .unwrap()
        );
        assert_eq!(final_range, [8, 17, 18, 19, 20, 21, 22, 23, 24]);
        assert_eq!(source.next_offset, 16);
    }

    #[test]
    fn public_key_share_source_registry_uses_monotonic_handles_and_release_invalidates() {
        let mut registry = SetupGenerationPublicKeyShareSourceRegistry::default();
        let first_handle = {
            let reserved_handle = registry.next_available_handle().unwrap();
            assert_eq!(reserved_handle.identifier(), 1);
            registry.retain_at(reserved_handle, public_key_share_source(7, 16))
        };
        let second_handle = {
            let reserved_handle = registry.next_available_handle().unwrap();
            assert_eq!(reserved_handle.identifier(), 2);
            registry.retain_at(reserved_handle, public_key_share_source(8, 24))
        };

        registry.release_for_authority(7);

        assert!(!registry.sources.contains_key(&first_handle.identifier()));
        assert!(registry.sources.contains_key(&second_handle.identifier()));
        assert_eq!(
            registry
                .sources
                .get(&second_handle.identifier())
                .unwrap()
                .body_byte_length,
            24
        );
    }

    #[test]
    fn cancelling_public_key_share_source_invalidates_the_handle() {
        let source_handle = SETUP_GENERATION_PUBLIC_KEY_SHARE_SOURCE_REGISTRY.with(|registry| {
            let mut registry = registry.borrow_mut();
            let handle = registry.next_available_handle().unwrap();
            registry.retain_at(handle, public_key_share_source(23, 32))
        });

        assert_eq!(
            setup_generation_public_key_share_source_byte_length(&source_handle).unwrap(),
            32
        );
        let source_identifier = source_handle.identifier();
        cancel_setup_generation_public_key_share_body(source_handle).unwrap();
        assert_eq!(
            setup_generation_public_key_share_source_byte_length(
                &SetupGenerationPublicKeyShareSourceHandle::from_identifier(source_identifier)
            )
            .unwrap_err(),
            RefusalReason::ConsumedState
        );
    }

    #[test]
    fn recipient_payload_source_requires_exact_sequential_nonempty_ranges() {
        let mut source = recipient_payload_source(17, 4, &[10, 20, 30, 40, 50]);

        assert_eq!(
            source.read_chunk(1, 2).unwrap_err(),
            RefusalReason::WrongContext
        );
        assert_eq!(
            source.read_chunk(0, 0).unwrap_err(),
            RefusalReason::WrongTypeOrLength
        );
        assert_eq!(
            source.read_chunk(0, 6).unwrap_err(),
            RefusalReason::WrongTypeOrLength
        );
        assert_eq!(source.next_offset, 0);
        assert_eq!(source.canonical_bytes.as_slice(), &[10, 20, 30, 40, 50]);

        let (first_chunk, first_chunk_finished) = source.read_chunk(0, 2).unwrap();
        assert_eq!(first_chunk.as_slice(), &[10, 20]);
        assert!(!first_chunk_finished);
        assert_eq!(source.next_offset, 2);
        assert_eq!(source.canonical_bytes.as_slice(), &[0, 0, 30, 40, 50]);

        assert_eq!(
            source.read_chunk(0, 1).unwrap_err(),
            RefusalReason::WrongContext
        );
        assert_eq!(source.next_offset, 2);

        let (final_chunk, final_chunk_finished) = source.read_chunk(2, 3).unwrap();
        assert_eq!(final_chunk.as_slice(), &[30, 40, 50]);
        assert!(final_chunk_finished);
        assert_eq!(source.canonical_bytes.as_slice(), &[0, 0, 0, 0, 0]);
    }

    #[test]
    fn recipient_payload_source_registry_reserves_monotonic_handles_and_releases_by_owner() {
        let mut registry = SetupGenerationRecipientPayloadSourceRegistry::default();
        let first_handle = {
            let reserved_handle = registry.next_available_handle().unwrap();
            assert_eq!(reserved_handle.identifier(), 1);
            registry.retain_at(reserved_handle, recipient_payload_source(7, 0, &[1]))
        };
        let second_handle = {
            let reserved_handle = registry.next_available_handle().unwrap();
            assert_eq!(reserved_handle.identifier(), 2);
            registry.retain_at(reserved_handle, recipient_payload_source(8, 1, &[2]))
        };
        let third_handle = {
            let reserved_handle = registry.next_available_handle().unwrap();
            registry.retain_at(reserved_handle, recipient_payload_source(7, 2, &[3]))
        };

        registry.release_for_authority(7);

        assert!(!registry.sources.contains_key(&first_handle.identifier()));
        assert!(registry.sources.contains_key(&second_handle.identifier()));
        assert!(!registry.sources.contains_key(&third_handle.identifier()));
        assert_eq!(
            registry
                .sources
                .get(&second_handle.identifier())
                .unwrap()
                .recipient_roster_position,
            1
        );
    }

    #[test]
    fn recipient_payload_source_registry_refuses_capacity_and_handle_overflow() {
        let mut full_registry = SetupGenerationRecipientPayloadSourceRegistry::default();
        for identifier in
            1..=u32::try_from(MAXIMUM_RETAINED_SETUP_GENERATION_RECIPIENT_PAYLOAD_SOURCE_COUNT)
                .unwrap()
        {
            full_registry
                .sources
                .insert(identifier, recipient_payload_source(identifier, 0, &[1]));
        }
        assert!(matches!(
            full_registry.next_available_handle(),
            Err(RefusalReason::OutsideSupportedProfile)
        ));

        let overflow_registry = SetupGenerationRecipientPayloadSourceRegistry {
            next_handle: u32::MAX,
            sources: BTreeMap::new(),
        };
        assert!(matches!(
            overflow_registry.next_available_handle(),
            Err(RefusalReason::OutsideSupportedProfile)
        ));
    }

    #[test]
    fn retained_recipient_payload_source_reports_binding_and_removes_itself_at_completion() {
        let owner_authority_identifier = 23;
        let source_handle = SETUP_GENERATION_RECIPIENT_PAYLOAD_SOURCE_REGISTRY.with(|registry| {
            let mut registry = registry.borrow_mut();
            let handle = registry.next_available_handle().unwrap();
            registry.retain_at(
                handle,
                recipient_payload_source(owner_authority_identifier, 6, &[7, 8, 9, 10]),
            )
        });
        let mut completed_payload_count_by_authority =
            BTreeMap::from([(owner_authority_identifier, 0_usize)]);

        assert_eq!(
            setup_generation_recipient_vss_payload_source_byte_length(&source_handle).unwrap(),
            4
        );
        assert_eq!(
            setup_generation_recipient_vss_payload_source_recipient_roster_position(&source_handle)
                .unwrap(),
            6
        );
        assert_eq!(
            read_setup_generation_recipient_vss_payload_chunk(&source_handle, 2, 1).unwrap_err(),
            RefusalReason::WrongContext
        );
        assert_eq!(
            read_setup_generation_recipient_vss_payload_chunk(&source_handle, 0, 1)
                .unwrap()
                .as_slice(),
            &[7]
        );
        let final_chunk = SETUP_GENERATION_RECIPIENT_PAYLOAD_SOURCE_REGISTRY.with(|registry| {
            registry.borrow_mut().read_chunk_and_record_completion(
                &source_handle,
                1,
                3,
                |completed_owner_authority_identifier| {
                    let completed_payload_count = completed_payload_count_by_authority
                        .get_mut(&completed_owner_authority_identifier)
                        .ok_or(RefusalReason::ConsumedState)?;
                    *completed_payload_count = completed_payload_count
                        .checked_add(1)
                        .ok_or(RefusalReason::OutsideSupportedProfile)?;
                    Ok(())
                },
            )
        });
        assert_eq!(final_chunk.unwrap().as_slice(), &[8, 9, 10]);
        assert_eq!(
            completed_payload_count_by_authority[&owner_authority_identifier],
            1
        );
        assert!(matches!(
            setup_generation_recipient_vss_payload_source_byte_length(&source_handle),
            Err(RefusalReason::ConsumedState)
        ));
        assert!(matches!(
            cancel_setup_generation_recipient_vss_payload(source_handle),
            Err(RefusalReason::ConsumedState)
        ));
    }
}
