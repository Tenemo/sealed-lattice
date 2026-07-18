use std::{cell::RefCell, collections::BTreeMap, rc::Rc, sync::Arc};

use zeroize::{Zeroize, Zeroizing};

use crate::{
    bgv::proof_suite::{
        AuthenticatedCompactCommittedMaterialSource, CommittedMaterialContext,
        CommittedMaterialRole, CommittedMaterialSourcePolynomialAdapter, CommittedMaterialTree,
        ComponentMaterialOwnershipBinding, ComponentPublicPolynomialRuntimeError,
        CommonProofGenerationAuthorization, CommonProofGenerationPreparationError,
        CommonProofGenerationSources, CommonProofPrivateCoinCoordinateCapacity,
        CommonProofProverError, CommonProofRelationPlanCapability, CommonProofRuntimeError,
        CommonProofRuntimeLimits, CompactCommittedMaterialSource,
        GaloisKeyShareSourcePolynomialAdapter, KeySwitchComponentPublicPolynomialStream,
        KeySwitchComponentMaterialTopology, PreparedCommonProofGeneration,
        PrivateRandomnessCommonProofCoinSource, ProofBaseFieldElement, ProofEvaluationDomain,
        RelationPlanVariant, SelectedEvaluatorEntryKind, SelectedEvaluatorEntryPosition,
        SelectedVssShareLinkageStatement, SetupPublicPolynomialContext, SetupPublicPolynomialTree,
        SetupPublicPolynomialTreeInput, canonical_selected_galois_key_share_statement,
        canonical_selected_vss_share_linkage_statement,
        compile_galois_key_share_relation_with_source_layout,
        compile_vss_share_linkage_relation_plan,
        decode_recipient_private_vss_payload, selected_committed_material_profile,
        selected_committed_material_relation_plan_input, selected_evaluator_galois_entry_positions,
        selected_galois_key_share_batch_schedule, selected_galois_key_share_relation_plan_input,
        selected_relation_plan_check_context, selected_relation_plans,
        verified_application_statement_hash, galois_relation_tree_inputs,
        VerifiedEvaluatorAuxiliaryRoot, VerifiedKeySwitchComponentMaterial,
    },
    bgv::setup::{
        SETUP_COMMITMENT_HIDING_ERROR_WIDTH, SETUP_COMMITMENT_HIDING_SECRET_WIDTH,
        SETUP_COMMITMENT_MODULE_RANK, SETUP_COMMITMENT_MODULUS_LIMB_INDICES,
        sample_galois_common_reference_limb,
        sampling::{
            DATA_MODULUS_CATALOG_IDENTIFIER, SPECIAL_MODULUS_CATALOG_IDENTIFIER,
        },
    },
    foundation::{
        ActionPrivateRandomness, CanonicalStreamDomain, CanonicalStreamReadbackVerifier,
        FOUNDATION_PROFILE, Hash512,
        PersistentProofCoinInput, PreparedActionProofAttemptSource, ProofApplicationSlotCeilings,
        RefusalReason, StreamDescriptor, WitnessBoundPreparedActionProofAttemptSource,
        bind_prepared_action_proof_attempt_to_canonical_witness,
        derive_canonical_stream_descriptor,
    },
};

const MAXIMUM_RETAINED_SETUP_GENERATION_AUTHORITY_COUNT: usize = 16;
const MAXIMUM_RETAINED_SETUP_GENERATION_RECIPIENT_PAYLOAD_SOURCE_COUNT: usize =
    MAXIMUM_RETAINED_SETUP_GENERATION_AUTHORITY_COUNT
        * FOUNDATION_PROFILE.participant_count as usize;
const GALOIS_KEY_SHARE_CANONICAL_SEMANTIC_WITNESS_DOMAIN: &[u8] =
    b"sealed-lattice/galois-key-share/canonical-semantic-witness/v1";

const fn generated_galois_stream_refusal(
    error: ComponentPublicPolynomialRuntimeError,
) -> RefusalReason {
    match error {
        ComponentPublicPolynomialRuntimeError::Refusal(refusal_reason) => refusal_reason,
        ComponentPublicPolynomialRuntimeError::PublicPolynomial(_) => {
            RefusalReason::WrongHashOrRoot
        }
    }
}

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

pub(crate) struct SetupGenerationRecipientPayloadSourceHandle(u32);

impl SetupGenerationRecipientPayloadSourceHandle {
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

    fn recompute_public_polynomial_tree(
        &self,
        context: &SetupPublicPolynomialContext,
        evaluation_domain_size: usize,
    ) -> Result<SetupPublicPolynomialTree, RefusalReason> {
        let trace_column_count = self.topology.trace_column_count()?;
        let mut ordered_columns = Vec::with_capacity(trace_column_count);
        for column_ordinal in 0..trace_column_count {
            let trace_column = self.topology.trace_column(column_ordinal)?;
            let byte_start = usize::try_from(trace_column.byte_offset())
                .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
            let byte_end = usize::try_from(
                trace_column
                    .byte_offset()
                    .checked_add(trace_column.byte_length())
                    .ok_or(RefusalReason::OutsideSupportedProfile)?,
            )
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
            let bytes = self
                .canonical_bytes
                .get(byte_start..byte_end)
                .ok_or(RefusalReason::WrongTypeOrLength)?;
            ordered_columns.push(trace_column.decode_authenticated_bytes(bytes)?);
        }
        SetupPublicPolynomialTree::construct(SetupPublicPolynomialTreeInput {
            context,
            evaluation_domain_size,
            source_polynomial_degree_bound_exclusive: self.topology.polynomial_degree(),
            ordered_coefficient_columns: &ordered_columns,
        })
        .map_err(|_| RefusalReason::WrongHashOrRoot)
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

    pub(crate) const fn public_polynomial_context_hash(
        &self,
    ) -> [u8; Hash512::BYTE_LENGTH] {
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
        source_polynomial_degree_bound_exclusive: usize,
        ordered_data_modulus_indices: Vec<u16>,
        ordered_limb_coefficients: Vec<Zeroizing<Vec<u64>>>,
        centered_error_coefficients: Zeroizing<Vec<i8>>,
    ) -> Result<Self, RefusalReason> {
        if source_polynomial_degree_bound_exclusive == 0
            || !source_polynomial_degree_bound_exclusive.is_power_of_two()
            || ordered_data_modulus_indices.is_empty()
            || ordered_data_modulus_indices.len() != ordered_limb_coefficients.len()
            || centered_error_coefficients.len() != source_polynomial_degree_bound_exclusive
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
        let half_degree = source_polynomial_degree_bound_exclusive / 2;
        let mut ordered_coefficient_columns = Vec::with_capacity(
            ordered_limb_coefficients
                .len()
                .checked_mul(2)
                .ok_or(RefusalReason::OutsideSupportedProfile)?,
        );
        for (data_modulus_index, coefficients) in ordered_data_modulus_indices
            .iter()
            .copied()
            .zip(&ordered_limb_coefficients)
        {
            let modulus = *crate::bgv::parameters::DATA_PRIMES
                .get(usize::from(data_modulus_index))
                .ok_or(RefusalReason::UnsupportedVersionOrSuite)?;
            if coefficients.len() != source_polynomial_degree_bound_exclusive
                || coefficients.iter().any(|coefficient| *coefficient >= modulus)
            {
                return Err(RefusalReason::WrongTypeOrLength);
            }
            for half_ordinal in 0..2 {
                let start = half_ordinal
                    .checked_mul(half_degree)
                    .ok_or(RefusalReason::OutsideSupportedProfile)?;
                ordered_coefficient_columns.push(
                    coefficients[start..start + half_degree]
                        .iter()
                        .copied()
                        .map(ProofBaseFieldElement::from_canonical)
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|_| RefusalReason::InvalidArithmeticRelation)?,
                );
            }
        }
        let tree = SetupPublicPolynomialTree::construct(SetupPublicPolynomialTreeInput {
            context: &context,
            evaluation_domain_size,
            source_polynomial_degree_bound_exclusive,
            ordered_coefficient_columns: &ordered_coefficient_columns,
        })
        .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
        Ok(Self {
            public_polynomial_context_hash: tree.public_polynomial_context_hash(),
            root: tree.root(),
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
}

/// One exact lattice-anchor tree and its browser-owned reset-safe opening.
/// Canonical commitment bytes are retained beside the recomputed tree; neither
/// a transported root nor detached opening polynomials can construct this
/// source.
pub(crate) struct SetupGenerationAnchorOpening {
    commitment_data_prime_index: u16,
    canonical_commitment_bytes: Box<[u8]>,
    public_polynomial_context_hash: [u8; Hash512::BYTE_LENGTH],
    root: [u8; Hash512::BYTE_LENGTH],
    source_polynomial_degree_bound_exclusive: usize,
    ordered_coefficient_columns: Box<[Vec<ProofBaseFieldElement>]>,
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
        let tree = SetupPublicPolynomialTree::from_lattice_anchor_canonical_bytes(
            &context,
            evaluation_domain_size,
            &canonical_commitment_bytes,
        )
        .map_err(|_| RefusalReason::MalformedEncoding)?;
        let ring_degree = tree.source_polynomial_degree_bound_exclusive();
        if hiding_secret_polynomials.len() != SETUP_COMMITMENT_HIDING_SECRET_WIDTH
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
        let public_polynomial_context_hash = tree.public_polynomial_context_hash();
        let root = tree.root();
        let source_polynomial_degree_bound_exclusive =
            tree.source_polynomial_degree_bound_exclusive();
        let ordered_coefficient_columns =
            tree.into_ordered_coefficient_columns().into_boxed_slice();
        Ok(Self {
            commitment_data_prime_index,
            canonical_commitment_bytes: canonical_commitment_bytes.into_boxed_slice(),
            public_polynomial_context_hash,
            root,
            source_polynomial_degree_bound_exclusive,
            ordered_coefficient_columns,
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

    pub(crate) fn ordered_coefficient_columns(&self) -> &[Vec<ProofBaseFieldElement>] {
        &self.ordered_coefficient_columns
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

    pub(crate) fn owned_compact_source(&self) -> Arc<CompactCommittedMaterialSource> {
        self.authenticated_source.owned_compact_source()
    }

    pub(crate) fn into_owned_compact_source(self) -> Arc<CompactCommittedMaterialSource> {
        self.authenticated_source.into_owned_compact_source()
    }

    pub(crate) fn owned_authenticated_source(&self) -> AuthenticatedCompactCommittedMaterialSource {
        self.authenticated_source.clone()
    }

    pub(crate) fn authenticates_canonical_message(
        &self,
        canonical_message: &[u64],
        canonical_modulus: u64,
    ) -> Result<bool, RefusalReason> {
        Ok(self
            .authenticated_source
            .authenticates_canonical_message(canonical_message, canonical_modulus))
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
    pub(crate) galois_batch_schedule_position: u32,
    pub(crate) ordered_galois_entries: Vec<SetupGeneratedGaloisEntry>,
}

struct PinnedProofAttempt {
    attempt_identifier: [u8; 32],
    application_slot_hash: [u8; Hash512::BYTE_LENGTH],
    application_statement_hash: [u8; Hash512::BYTE_LENGTH],
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
    vss_material: SetupGeneratedVssMaterial,
    galois_batch_schedule_position: u32,
    ordered_galois_entries: Box<[SetupGeneratedGaloisEntry]>,
    pinned_vss_proof_attempt: Option<PinnedProofAttempt>,
    pinned_galois_proof_attempt: Option<PinnedProofAttempt>,
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
                != selected_committed_material_relation_plan_input()
                    .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)?
                    .sharing_data_modulus_indices
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
                || anchor.source_polynomial_degree_bound_exclusive() != ring_degree
                || anchor.ordered_coefficient_columns().len()
                    != (SETUP_COMMITMENT_MODULE_RANK + 1) * 2
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
        if input.galois_batch_schedule_position != expected_batch_schedule_position
            || input
                .ordered_galois_entries
                .iter()
                .map(|entry| entry.component().evaluator_position())
                .ne(expected_galois_positions)
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
            vss_material: input.vss_material,
            galois_batch_schedule_position: input.galois_batch_schedule_position,
            ordered_galois_entries: input.ordered_galois_entries.into_boxed_slice(),
            pinned_vss_proof_attempt: None,
            pinned_galois_proof_attempt: None,
        })
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
            let tree = entry
                .component()
                .recompute_public_polynomial_tree(&context, evaluation_domain_size)?;
            ordered_contribution_roots.push(tree.root());
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
            || application_slot.schedule_position()
                != Some(self.galois_batch_schedule_position)
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

/// Exact decoded `0x2110` statement joined to the reset-safe proof attempt.
/// The root arrays remain borrowed from the canonical decoder and are matched
/// in order against the recomputed browser-owned committed-material trees.
pub(crate) struct SetupGenerationVssApplication<'statement> {
    prepared_attempt: PreparedActionProofAttemptSource,
    canonical_application_statement_bytes: &'statement [u8],
    statement: &'statement SelectedVssShareLinkageStatement,
}

#[derive(Debug)]
pub(crate) enum SetupGaloisGenerationPreparationError {
    Refusal(RefusalReason),
    Prover(CommonProofProverError),
    Runtime(CommonProofRuntimeError),
    Preparation(CommonProofGenerationPreparationError),
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
    authority: &'authority SetupGenerationAuthority,
    application: &'authority SetupGenerationVssApplication<'statement>,
}

impl SetupGenerationVssSource<'_, '_> {
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

    pub(crate) fn ordered_roster(&self) -> &[[u8; Hash512::BYTE_LENGTH]] {
        &self.authority.ordered_roster
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

    pub(crate) const fn action_randomness_authorization_hash(&self) -> [u8; 64] {
        self.authority.action_randomness_authorization_hash
    }

    pub(crate) const fn public_setup_seed(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.authority.public_setup_seed
    }

    pub(crate) fn common_secret_coefficients(&self) -> &[i8] {
        self.authority.common_secret_coefficients.as_slice()
    }

    pub(crate) fn ordered_coefficient_materials(&self) -> &[SetupGeneratedCommittedMaterial] {
        self.authority.vss_material.ordered_coefficient_materials()
    }

    pub(crate) fn ordered_recipient_share_materials(&self) -> &[SetupGeneratedCommittedMaterial] {
        self.authority
            .vss_material
            .ordered_recipient_share_materials()
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
                limits,
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

    pub(crate) fn ordered_roster(&self) -> &[[u8; Hash512::BYTE_LENGTH]] {
        &self.authority.ordered_roster
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
        let physical_column_coefficient_count = polynomial_degree / 2;
        if active_data_limb_count > extended_limb_count
            || physical_column_coefficient_count == 0
            || physical_column_coefficient_count.checked_mul(2) != Some(polynomial_degree)
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }

        let expected_column_count = topology.trace_column_count()?;
        let public_setup_seed = self.public_setup_seed();
        let mut ordered_coefficient_columns = Vec::with_capacity(expected_column_count);
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
                let (low_coefficients, high_coefficients) = common_reference_coefficients
                    .split_at(physical_column_coefficient_count);
                for physical_column in [low_coefficients, high_coefficients] {
                    ordered_coefficient_columns.push(
                        physical_column
                            .iter()
                            .copied()
                            .map(ProofBaseFieldElement::from_canonical)
                            .collect::<Result<Vec<_>, _>>()
                            .map_err(|_| RefusalReason::InvalidArithmeticRelation)?,
                    );
                }
            }
        }
        if ordered_coefficient_columns.len() != expected_column_count {
            return Err(RefusalReason::WrongTypeOrLength);
        }

        let public_polynomial_context = SetupPublicPolynomialContext::galois_common(
            self.setup_proof_context_hash(),
            position.schedule_position(),
        )
        .map_err(|_| RefusalReason::WrongContext)?;
        let tree = SetupPublicPolynomialTree::construct(SetupPublicPolynomialTreeInput {
            context: &public_polynomial_context,
            evaluation_domain_size,
            source_polynomial_degree_bound_exclusive: polynomial_degree,
            ordered_coefficient_columns: &ordered_coefficient_columns,
        })
        .map_err(|_| RefusalReason::WrongHashOrRoot)?;
        VerifiedEvaluatorAuxiliaryRoot::from_galois_common_public_polynomial_tree(
            position.schedule_position(),
            galois_element,
            catalog_level,
            &tree,
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
        let evaluation_domain_size = usize::try_from(relation_plan_variant.evaluation_domain_size())
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        let mut ordered_public_polynomial_contexts =
            Vec::with_capacity(self.ordered_entries().len());
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
            let tree = component.recompute_public_polynomial_tree(
                &public_polynomial_context,
                evaluation_domain_size,
            )?;
            let contribution_root = tree.root();
            ordered_contribution_roots.push(contribution_root);
            ordered_public_polynomial_contexts.push(public_polynomial_context);
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
        for ((entry, public_polynomial_context), contribution_root) in self
            .ordered_entries()
            .iter()
            .zip(ordered_public_polynomial_contexts)
            .zip(ordered_contribution_roots.iter().copied())
        {
            let component = entry.component();
            let mut component_stream = KeySwitchComponentPublicPolynomialStream::begin(
                component.topology.clone(),
                material_ownership,
                component.stream_descriptor.clone(),
            )
            .map_err(generated_galois_stream_refusal)?;
            for (chunk_index, chunk_bytes) in component
                .canonical_bytes
                .chunks(FOUNDATION_PROFILE.stream_chunk_byte_length)
                .enumerate()
            {
                component_stream
                    .absorb_chunk(chunk_index, chunk_bytes)
                    .map_err(generated_galois_stream_refusal)?;
            }
            let recomputed = component_stream
                .finish(public_polynomial_context)
                .map_err(generated_galois_stream_refusal)?;
            let (material, tree) = recomputed.into_parts();
            if tree.root() != contribution_root {
                return Err(RefusalReason::WrongHashOrRoot);
            }
            ordered_components.push(SetupGeneratedGaloisSourceComponent {
                evaluator_position: component.evaluator_position,
                material,
                contribution_root,
                public_polynomial_context_hash: tree.public_polynomial_context_hash(),
            });
        }
        let ordered_auxiliary_roots = self
            .ordered_entries()
            .iter()
            .map(|entry| {
                self.recompute_galois_common_auxiliary_root(entry, evaluation_domain_size)
            })
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
                limits,
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

thread_local! {
    static SETUP_GENERATION_AUTHORITY_REGISTRY: RefCell<SetupGenerationAuthorityRegistry> =
        RefCell::new(SetupGenerationAuthorityRegistry::default());
    static SETUP_GENERATION_RECIPIENT_PAYLOAD_SOURCE_REGISTRY:
        RefCell<SetupGenerationRecipientPayloadSourceRegistry> =
            RefCell::new(SetupGenerationRecipientPayloadSourceRegistry::default());
}

pub(super) fn retain_browser_owned_setup_generation_authority(
    input: SetupGenerationAuthorityInput,
) -> Result<SetupGenerationAuthorityHandle, RefusalReason> {
    let authority = SetupGenerationAuthority::from_browser_owned_input(input)?;
    SETUP_GENERATION_AUTHORITY_REGISTRY.with(|registry| {
        registry
            .try_borrow_mut()
            .map_err(|_| RefusalReason::ConsumedState)?
            .retain(authority)
    })
}

pub(crate) fn resolve_setup_generation_vss_preparation_source(
    handle: &SetupGenerationAuthorityHandle,
) -> Result<SetupGenerationVssPreparationSource, RefusalReason> {
    SETUP_GENERATION_AUTHORITY_REGISTRY.with(|registry| {
        registry
            .try_borrow()
            .map_err(|_| RefusalReason::ConsumedState)?
            .authorities
            .get(&handle.0)
            .ok_or(RefusalReason::ConsumedState)?
            .vss_preparation_source()
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

pub(crate) fn with_setup_generation_vss_material<Value, Error>(
    handle: &SetupGenerationAuthorityHandle,
    application: &SetupGenerationVssApplication<'_>,
    operation: impl FnOnce(SetupGenerationVssSource<'_, '_>) -> Result<Value, Error>,
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
    SETUP_GENERATION_RECIPIENT_PAYLOAD_SOURCE_REGISTRY.with(|source_registry| {
        let mut source_registry = source_registry
            .try_borrow_mut()
            .map_err(|_| RefusalReason::ConsumedState)?;
        SETUP_GENERATION_AUTHORITY_REGISTRY.with(|authority_registry| {
            let mut authority_registry = authority_registry
                .try_borrow_mut()
                .map_err(|_| RefusalReason::ConsumedState)?;
            if !authority_registry.authorities.contains_key(&handle.0) {
                return Err(RefusalReason::ConsumedState);
            }
            source_registry.release_for_authority(handle.0);
            let removed_authority = authority_registry.authorities.remove(&handle.0);
            debug_assert!(removed_authority.is_some());
            Ok(())
        })
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
        let (chunk, finished) = registry
            .sources
            .get_mut(&source_handle.0)
            .ok_or(RefusalReason::ConsumedState)?
            .read_chunk(expected_offset, requested_byte_length)?;
        if finished {
            let removed_source = registry.sources.remove(&source_handle.0);
            debug_assert!(removed_source.is_some());
        }
        Ok(chunk)
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
        let source_handle = SETUP_GENERATION_RECIPIENT_PAYLOAD_SOURCE_REGISTRY.with(|registry| {
            let mut registry = registry.borrow_mut();
            let handle = registry.next_available_handle().unwrap();
            registry.retain_at(handle, recipient_payload_source(23, 6, &[7, 8, 9, 10]))
        });

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
        assert_eq!(
            read_setup_generation_recipient_vss_payload_chunk(&source_handle, 1, 3)
                .unwrap()
                .as_slice(),
            &[8, 9, 10]
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
