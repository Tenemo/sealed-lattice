use super::{
    BTreeMap, BTreeSet, COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH, CommonProofChallenge,
    CommonProofPrivateCoinCoordinate, CommonProofPrivateCoinSource, CommonProofProverError,
    ProofBaseFieldElement, ProofChallengeExtensionElement, ProofEvaluationDomain, ProofPrivacyMode,
    ProofTreeRole, RelationApplicationChallengeAssignment, RelationColumnDescriptor,
    RelationColumnOrigin, RelationColumnValueType, RelationIntegerLiftCoefficient,
    RelationIntegerLiftComponentDescriptor, RelationIntegerLiftConvolutionKind,
    RelationIntegerLiftConvolutionProductDescriptor, RelationIntegerLiftFullRingHalf,
    RelationIntegerLiftFullRingNegacyclicProductDescriptor,
    RelationIntegerLiftLinearTermDescriptor,
    RelationIntegerLiftNegacyclicAutomorphismPermutationDescriptor, RelationMaskDescriptor,
    RelationMaskKind, RelationMaskTargetClass, RelationPlanCheckContext, RelationPlanVariant,
    RelationTreeDescriptor, StreamingHash512, SuiteModulusReference, Zeroizing,
    evaluate_extension_at, trim_base_polynomial, trim_extension_polynomial,
};

const SOURCE_REPLAY_IDENTITY_AGGREGATE_DOMAIN: &str =
    "sealed-lattice/common-proof/source-replay-identity-aggregate/v1";
const SOURCE_GENERATION_BINDING_DOMAIN: &str =
    "sealed-lattice/common-proof/source-generation-binding/v1";
const AUTHENTICATED_SOURCE_READ_REQUEST_DOMAIN: &str =
    "sealed-lattice/common-proof/authenticated-source-read-request/v1";

type ProtectedBaseTraceRows = Zeroizing<Vec<ProofBaseFieldElement>>;
type ProtectedAuxiliaryColumnRows = (u32, ProtectedBaseTraceRows);

/// Statement- and plan-bound coordinates for one application-owned source
/// polynomial request. The common prover creates requests only for genuine
/// pre-challenge columns; reversed and auxiliary columns never cross this
/// boundary.
#[derive(Clone, Copy)]
pub(crate) struct CommonProofSourcePolynomialRequest<'descriptor> {
    protocol_version: u16,
    suite_identifier: [u8; 64],
    application_statement_schema_identifier: u16,
    application_statement_hash: [u8; 64],
    relation_plan_hash: [u8; 64],
    relation_plan_variant_hash: [u8; 64],
    schedule_position: Option<u32>,
    top_count: Option<u16>,
    column_ordinal: u32,
    descriptor: &'descriptor RelationColumnDescriptor,
}

impl CommonProofSourcePolynomialRequest<'_> {
    pub(crate) const fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    pub(crate) const fn suite_identifier(&self) -> [u8; 64] {
        self.suite_identifier
    }

    pub(crate) const fn application_statement_schema_identifier(&self) -> u16 {
        self.application_statement_schema_identifier
    }

    pub(crate) const fn application_statement_hash(&self) -> [u8; 64] {
        self.application_statement_hash
    }

    pub(crate) const fn relation_plan_hash(&self) -> [u8; 64] {
        self.relation_plan_hash
    }

    pub(crate) const fn relation_plan_variant_hash(&self) -> [u8; 64] {
        self.relation_plan_variant_hash
    }

    pub(crate) const fn schedule_position(&self) -> Option<u32> {
        self.schedule_position
    }

    pub(crate) const fn top_count(&self) -> Option<u16> {
        self.top_count
    }

    pub(crate) const fn column_ordinal(&self) -> u32 {
        self.column_ordinal
    }

    pub(crate) const fn descriptor(&self) -> &RelationColumnDescriptor {
        self.descriptor
    }

    pub(crate) const fn request_context(&self) -> CommonProofSourcePolynomialRequestContext {
        CommonProofSourcePolynomialRequestContext::new(
            self.protocol_version(),
            self.suite_identifier(),
            self.application_statement_schema_identifier(),
            self.application_statement_hash(),
            self.relation_plan_hash,
            self.relation_plan_variant_hash,
            self.schedule_position,
            self.top_count,
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofSourcePolynomialRequestContext {
    protocol_version: u16,
    suite_identifier: [u8; 64],
    application_statement_schema_identifier: u16,
    application_statement_hash: [u8; 64],
    relation_plan_hash: [u8; 64],
    relation_plan_variant_hash: [u8; 64],
    schedule_position: Option<u32>,
    top_count: Option<u16>,
}

impl CommonProofSourcePolynomialRequestContext {
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new(
        protocol_version: u16,
        suite_identifier: [u8; 64],
        application_statement_schema_identifier: u16,
        application_statement_hash: [u8; 64],
        relation_plan_hash: [u8; 64],
        relation_plan_variant_hash: [u8; 64],
        schedule_position: Option<u32>,
        top_count: Option<u16>,
    ) -> Self {
        Self {
            protocol_version,
            suite_identifier,
            application_statement_schema_identifier,
            application_statement_hash,
            relation_plan_hash,
            relation_plan_variant_hash,
            schedule_position,
            top_count,
        }
    }

    pub(crate) const fn relation_plan_hash(self) -> [u8; 64] {
        self.relation_plan_hash
    }

    pub(crate) const fn protocol_version(self) -> u16 {
        self.protocol_version
    }

    pub(crate) const fn suite_identifier(self) -> [u8; 64] {
        self.suite_identifier
    }

    pub(crate) const fn application_statement_schema_identifier(self) -> u16 {
        self.application_statement_schema_identifier
    }

    pub(crate) const fn application_statement_hash(self) -> [u8; 64] {
        self.application_statement_hash
    }

    pub(crate) const fn relation_plan_variant_hash(self) -> [u8; 64] {
        self.relation_plan_variant_hash
    }

    pub(crate) const fn schedule_position(self) -> Option<u32> {
        self.schedule_position
    }

    pub(crate) const fn top_count(self) -> Option<u16> {
        self.top_count
    }

    pub(crate) fn stable_generation_binding_hash(self) -> [u8; 64] {
        let schedule_position_presence = [u8::from(self.schedule_position.is_some())];
        let schedule_position = self.schedule_position.unwrap_or_default().to_le_bytes();
        let top_count_presence = [u8::from(self.top_count.is_some())];
        let top_count = self.top_count.unwrap_or_default().to_le_bytes();
        crate::hashing::hash_framed_parts_512(
            SOURCE_GENERATION_BINDING_DOMAIN,
            &[
                &self.protocol_version().to_le_bytes(),
                &self.suite_identifier(),
                &self.application_statement_schema_identifier().to_le_bytes(),
                &self.application_statement_hash(),
                &self.relation_plan_hash,
                &self.relation_plan_variant_hash,
                &schedule_position_presence,
                &schedule_position,
                &top_count_presence,
                &top_count,
            ],
        )
    }

    pub(crate) const fn request<'descriptor>(
        self,
        column_ordinal: u32,
        descriptor: &'descriptor RelationColumnDescriptor,
    ) -> CommonProofSourcePolynomialRequest<'descriptor> {
        CommonProofSourcePolynomialRequest {
            protocol_version: self.protocol_version,
            suite_identifier: self.suite_identifier,
            application_statement_schema_identifier: self.application_statement_schema_identifier,
            application_statement_hash: self.application_statement_hash,
            relation_plan_hash: self.relation_plan_hash,
            relation_plan_variant_hash: self.relation_plan_variant_hash,
            schedule_position: self.schedule_position,
            top_count: self.top_count,
            column_ordinal,
            descriptor,
        }
    }
}

/// Exact authenticated byte range requested by a source provider. The range
/// identity binds the proof-generation coordinates and the provider's closed
/// source catalog, material, stream, and authentication-chunk coordinates.
/// Supplying bytes for a different request cannot advance the source cursor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofAuthenticatedSourceReadRequest {
    request_identity: [u8; 64],
    stable_generation_binding_hash: [u8; 64],
    source_catalog_binding: [u8; 64],
    source_descriptor_binding: [u8; 64],
    source_material_root: [u8; 64],
    source_stream_digest: [u8; 64],
    source_stream_total_byte_length: u64,
    source_stream_byte_offset: u64,
    storage_byte_offset: u64,
    source_byte_length: u32,
    authentication_chunk_index: u32,
}

impl CommonProofAuthenticatedSourceReadRequest {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_authenticated_source(
        engine_request: CommonProofSourcePolynomialRequest<'_>,
        source_catalog_binding: [u8; 64],
        source_descriptor_binding: [u8; 64],
        source_material_root: [u8; 64],
        source_stream_digest: [u8; 64],
        source_stream_total_byte_length: u64,
        source_stream_byte_offset: u64,
        storage_byte_offset: u64,
        source_byte_length: u32,
        authentication_chunk_index: u32,
    ) -> Result<Self, CommonProofProverError> {
        if source_catalog_binding == [0_u8; 64]
            || source_descriptor_binding == [0_u8; 64]
            || source_material_root == [0_u8; 64]
            || source_stream_digest == [0_u8; 64]
            || source_stream_total_byte_length == 0
            || source_byte_length == 0
            || usize::try_from(source_byte_length).map_or(true, |source_byte_length| {
                source_byte_length > crate::foundation::FOUNDATION_PROFILE.stream_chunk_byte_length
            })
            || source_stream_byte_offset
                .checked_add(u64::from(source_byte_length))
                .is_none_or(|range_end| range_end > source_stream_total_byte_length)
            || storage_byte_offset
                .checked_add(u64::from(source_byte_length))
                .is_none()
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let request_context = engine_request.request_context();
        let stable_generation_binding_hash = request_context.stable_generation_binding_hash();
        let request_identity = crate::hashing::hash_framed_parts_512(
            AUTHENTICATED_SOURCE_READ_REQUEST_DOMAIN,
            &[
                &stable_generation_binding_hash,
                &engine_request.column_ordinal().to_le_bytes(),
                &source_catalog_binding,
                &source_descriptor_binding,
                &source_material_root,
                &source_stream_digest,
                &source_stream_total_byte_length.to_le_bytes(),
                &source_stream_byte_offset.to_le_bytes(),
                &storage_byte_offset.to_le_bytes(),
                &source_byte_length.to_le_bytes(),
                &authentication_chunk_index.to_le_bytes(),
            ],
        );
        Ok(Self {
            request_identity,
            stable_generation_binding_hash,
            source_catalog_binding,
            source_descriptor_binding,
            source_material_root,
            source_stream_digest,
            source_stream_total_byte_length,
            source_stream_byte_offset,
            storage_byte_offset,
            source_byte_length,
            authentication_chunk_index,
        })
    }

    #[cfg(test)]
    pub(crate) const fn request_identity(self) -> [u8; 64] {
        self.request_identity
    }

    #[cfg(test)]
    pub(crate) const fn source_catalog_binding(self) -> [u8; 64] {
        self.source_catalog_binding
    }

    #[cfg(test)]
    pub(crate) const fn source_descriptor_binding(self) -> [u8; 64] {
        self.source_descriptor_binding
    }

    pub(crate) const fn source_material_root(self) -> [u8; 64] {
        self.source_material_root
    }

    pub(crate) const fn source_stream_digest(self) -> [u8; 64] {
        self.source_stream_digest
    }

    pub(crate) const fn source_stream_total_byte_length(self) -> u64 {
        self.source_stream_total_byte_length
    }

    pub(crate) const fn source_stream_byte_offset(self) -> u64 {
        self.source_stream_byte_offset
    }

    pub(crate) const fn storage_byte_offset(self) -> u64 {
        self.storage_byte_offset
    }

    pub(crate) const fn source_byte_length(self) -> u32 {
        self.source_byte_length
    }

    pub(crate) const fn authentication_chunk_index(self) -> u32 {
        self.authentication_chunk_index
    }
}

/// Stable family-owned identity for replaying the exact authenticated source
/// bytes behind one requested polynomial after a reset. The proof engine also
/// binds the ordered aggregate of these identities into every checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofSourcePolynomialReplayIdentity([u8; 64]);

impl CommonProofSourcePolynomialReplayIdentity {
    pub(crate) fn from_authenticated_source(
        identity: [u8; 64],
    ) -> Result<Self, CommonProofProverError> {
        if identity == [0_u8; 64] {
            return Err(CommonProofProverError::InvalidColumn);
        }
        Ok(Self(identity))
    }

    pub(crate) const fn bytes(self) -> [u8; 64] {
        self.0
    }
}

pub(crate) struct ProvidedCommonProofSourcePolynomial {
    polynomial: CommonProofSourcePolynomial,
    replay_identity: CommonProofSourcePolynomialReplayIdentity,
}

/// Exact engine-derived coordinate for the persistent salt of one
/// statement-owned committed-material leaf. The provider never chooses tree
/// coordinates: it may only recover the salt already bound by the expected
/// root from its compact authenticated source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofBoundTreeLeafSaltRequest {
    request_context: CommonProofSourcePolynomialRequestContext,
    tree_catalog_index: u16,
    leaf_index: u64,
    expected_root: [u8; 64],
}

impl CommonProofBoundTreeLeafSaltRequest {
    pub(crate) const fn new(
        request_context: CommonProofSourcePolynomialRequestContext,
        tree_catalog_index: u16,
        leaf_index: u64,
        expected_root: [u8; 64],
    ) -> Self {
        Self {
            request_context,
            tree_catalog_index,
            leaf_index,
            expected_root,
        }
    }

    pub(crate) const fn request_context(self) -> CommonProofSourcePolynomialRequestContext {
        self.request_context
    }

    pub(crate) const fn tree_catalog_index(self) -> u16 {
        self.tree_catalog_index
    }

    pub(crate) const fn leaf_index(self) -> u64 {
        self.leaf_index
    }

    pub(crate) const fn expected_root(self) -> [u8; 64] {
        self.expected_root
    }
}

impl ProvidedCommonProofSourcePolynomial {
    pub(crate) const fn new(
        polynomial: CommonProofSourcePolynomial,
        replay_identity: CommonProofSourcePolynomialReplayIdentity,
    ) -> Self {
        Self {
            polynomial,
            replay_identity,
        }
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        CommonProofSourcePolynomial,
        CommonProofSourcePolynomialReplayIdentity,
    ) {
        (self.polynomial, self.replay_identity)
    }
}

pub(crate) enum CommonProofSourcePolynomialProviderPoll {
    AuthenticatedSourceReadRequired,
    Ready(ProvidedCommonProofSourcePolynomial),
}

/// Exact provider-owned memory that can overlap the common prover.
///
/// Returned polynomial bytes belong to the common prover's relation working
/// set. They are retained here only as a cross-check that the loading phase is
/// large enough, never added to the provider-owned total a second time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofSourceProviderMemoryAccounting {
    loading_persistent_resident_byte_length: u64,
    post_source_polynomial_finish_persistent_resident_byte_length: u64,
    additional_loading_transient_byte_length: u64,
    maximum_returned_source_polynomial_byte_length: u64,
}

impl CommonProofSourceProviderMemoryAccounting {
    pub(crate) const fn new(
        loading_persistent_resident_byte_length: u64,
        post_source_polynomial_finish_persistent_resident_byte_length: u64,
        additional_loading_transient_byte_length: u64,
        maximum_returned_source_polynomial_byte_length: u64,
    ) -> Self {
        Self {
            loading_persistent_resident_byte_length,
            post_source_polynomial_finish_persistent_resident_byte_length,
            additional_loading_transient_byte_length,
            maximum_returned_source_polynomial_byte_length,
        }
    }

    pub(crate) const fn loading_persistent_resident_byte_length(self) -> u64 {
        self.loading_persistent_resident_byte_length
    }

    pub(crate) const fn post_source_polynomial_finish_persistent_resident_byte_length(self) -> u64 {
        self.post_source_polynomial_finish_persistent_resident_byte_length
    }

    pub(crate) const fn additional_loading_transient_byte_length(self) -> u64 {
        self.additional_loading_transient_byte_length
    }

    pub(crate) const fn maximum_returned_source_polynomial_byte_length(self) -> u64 {
        self.maximum_returned_source_polynomial_byte_length
    }
}

/// Exact, ordered application source boundary for the common prover. A
/// provider must consume each request deterministically and refuse leftovers
/// in `finish`; the engine never accepts an ordinal-keyed host map.
pub(crate) trait CommonProofSourcePolynomialProvider {
    /// Every provider must account explicitly. There is deliberately no zero
    /// default because an omitted implementation would bypass the production
    /// resident-memory bound.
    fn memory_accounting(
        &self,
    ) -> Result<CommonProofSourceProviderMemoryAccounting, CommonProofProverError>;

    fn poll_source_polynomial(
        &mut self,
        request: CommonProofSourcePolynomialRequest<'_>,
    ) -> Result<CommonProofSourcePolynomialProviderPoll, CommonProofProverError>;

    /// Reconstructs one already-consumed source from the same retained,
    /// authenticated family authority. The engine supplies the complete
    /// checked request and compares the returned replay identity with the
    /// identity bound during the canonical initial pass. Implementations must
    /// not sample proof coins or accept caller-supplied polynomial material.
    fn poll_replayed_source_polynomial(
        &mut self,
        request: CommonProofSourcePolynomialRequest<'_>,
    ) -> Result<CommonProofSourcePolynomialProviderPoll, CommonProofProverError>;

    /// Returns the exact request represented by the most recent
    /// `AuthenticatedSourceReadRequired` poll. Keeping the request in provider
    /// state avoids copying the large request through each nested poll enum or
    /// introducing a separately allocated request that would need additional
    /// resident-memory accounting.
    fn pending_authenticated_source_read_request(
        &self,
    ) -> Result<Option<CommonProofAuthenticatedSourceReadRequest>, CommonProofProverError> {
        Ok(None)
    }

    fn supply_authenticated_source_range(
        &mut self,
        _request: CommonProofAuthenticatedSourceReadRequest,
        _authenticated_bytes: Zeroizing<Box<[u8]>>,
    ) -> Result<(), CommonProofProverError> {
        Err(CommonProofProverError::InvalidColumn)
    }

    fn cancel_pending_authenticated_source_read(&mut self) {}

    fn finish(&mut self) -> Result<(), CommonProofProverError>;

    fn provide_bound_tree_leaf_salt(
        &mut self,
        _request: CommonProofBoundTreeLeafSaltRequest,
    ) -> Result<Option<[u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]>, CommonProofProverError>
    {
        Ok(None)
    }

    fn finish_bound_tree_leaf_salts(&mut self) -> Result<(), CommonProofProverError> {
        Ok(())
    }

    fn finish_source_replay(&mut self) -> Result<(), CommonProofProverError> {
        Ok(())
    }
}

/// One plan-addressed source polynomial.  Coefficients are constant-first.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CommonProofSourcePolynomial {
    Base(Zeroizing<Vec<ProofBaseFieldElement>>),
    Extension(Zeroizing<Vec<ProofChallengeExtensionElement>>),
}

impl CommonProofSourcePolynomial {
    pub(crate) fn from_base_coefficients(coefficients: Vec<ProofBaseFieldElement>) -> Self {
        Self::Base(Zeroizing::new(coefficients))
    }

    pub(crate) fn from_protected_base_coefficients(
        coefficients: Zeroizing<Vec<ProofBaseFieldElement>>,
    ) -> Self {
        Self::Base(coefficients)
    }

    #[cfg(test)]
    pub(crate) fn from_extension_coefficients(
        coefficients: Vec<ProofChallengeExtensionElement>,
    ) -> Self {
        Self::Extension(Zeroizing::new(coefficients))
    }

    pub(crate) fn from_protected_extension_coefficients(
        coefficients: Zeroizing<Vec<ProofChallengeExtensionElement>>,
    ) -> Self {
        Self::Extension(coefficients)
    }

    pub(crate) fn value_type(&self) -> RelationColumnValueType {
        match self {
            Self::Base(_) => RelationColumnValueType::BaseField,
            Self::Extension(_) => RelationColumnValueType::ChallengeExtension,
        }
    }

    pub(crate) fn coefficient_count(&self) -> usize {
        match self {
            Self::Base(coefficients) => coefficients.len(),
            Self::Extension(coefficients) => coefficients.len(),
        }
    }

    pub(crate) fn resident_payload_byte_length(&self) -> Result<u64, CommonProofProverError> {
        let (coefficient_count, coefficient_byte_length) = match self {
            Self::Base(coefficients) => (
                coefficients.len(),
                core::mem::size_of::<ProofBaseFieldElement>(),
            ),
            Self::Extension(coefficients) => (
                coefficients.len(),
                core::mem::size_of::<ProofChallengeExtensionElement>(),
            ),
        };
        u64::try_from(coefficient_count)
            .ok()
            .and_then(|count| {
                u64::try_from(coefficient_byte_length)
                    .ok()
                    .and_then(|width| count.checked_mul(width))
            })
            .ok_or(CommonProofProverError::CountOverflow)
    }

    pub(crate) fn evaluate_at(
        &self,
        point: ProofChallengeExtensionElement,
    ) -> ProofChallengeExtensionElement {
        match self {
            Self::Base(coefficients) => coefficients.iter().rev().fold(
                ProofChallengeExtensionElement::ZERO,
                |accumulated, coefficient| {
                    accumulated
                        .multiply(point)
                        .add(ProofChallengeExtensionElement::from_base(*coefficient))
                },
            ),
            Self::Extension(coefficients) => evaluate_extension_at(coefficients, point),
        }
    }
}

#[cfg(test)]
impl Clone for CommonProofSourcePolynomial {
    fn clone(&self) -> Self {
        match self {
            Self::Base(coefficients) => Self::from_base_coefficients(coefficients.to_vec()),
            Self::Extension(coefficients) => {
                Self::from_extension_coefficients(coefficients.to_vec())
            }
        }
    }
}

/// Ordered pre-challenge source cursor. The cursor requests and returns one
/// application-owned polynomial at a time, so the prover never needs a
/// resident source catalog. Reversed columns are deliberately excluded: they
/// are reconstructed later from the persisted, trace-equivalent source.
pub(crate) struct CommonProofPreChallengeSourceCursor {
    requested_column_ordinals: Vec<u32>,
    reversed_column_bindings: Vec<(u32, u32)>,
    tree_roles: BTreeMap<u32, ProofTreeRole>,
    trace_masks: BTreeMap<u32, RelationMaskDescriptor>,
    next_source_index: usize,
    source_identity_hasher: Option<StreamingHash512>,
    ordered_replay_identities: Vec<CommonProofSourcePolynomialReplayIdentity>,
}

pub(crate) struct CommonProofSourceReplayIdentityCatalog {
    aggregate_digest: [u8; 64],
    ordered_replay_identities: Box<[CommonProofSourcePolynomialReplayIdentity]>,
}

impl CommonProofSourceReplayIdentityCatalog {
    pub(crate) const fn aggregate_digest(&self) -> [u8; 64] {
        self.aggregate_digest
    }

    pub(crate) fn identity_at(
        &self,
        source_index: usize,
    ) -> Option<CommonProofSourcePolynomialReplayIdentity> {
        self.ordered_replay_identities.get(source_index).copied()
    }

    pub(crate) fn len(&self) -> usize {
        self.ordered_replay_identities.len()
    }
}

pub(crate) enum CommonProofPreChallengeSourcePoll {
    AuthenticatedSourceReadRequired,
    Ready {
        column_ordinal: u32,
        polynomial: CommonProofSourcePolynomial,
    },
    Complete,
}

impl CommonProofPreChallengeSourceCursor {
    pub(crate) fn resident_owned_payload_byte_length(&self) -> Result<u64, CommonProofProverError> {
        fn vector_byte_length<T>(capacity: usize) -> Result<u64, CommonProofProverError> {
            u64::try_from(capacity)
                .ok()
                .and_then(|count| {
                    u64::try_from(core::mem::size_of::<T>())
                        .ok()
                        .and_then(|element_byte_length| count.checked_mul(element_byte_length))
                })
                .ok_or(CommonProofProverError::CountOverflow)
        }

        const BTREE_ENTRY_LINK_WORD_COUNT: u64 = 6;
        let btree_entry_overhead_byte_length = BTREE_ENTRY_LINK_WORD_COUNT
            .checked_mul(
                u64::try_from(core::mem::size_of::<usize>())
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .ok_or(CommonProofProverError::CountOverflow)?;
        let tree_role_entry_byte_length =
            u64::try_from(core::mem::size_of::<(u32, ProofTreeRole)>())
                .map_err(|_| CommonProofProverError::CountOverflow)?
                .checked_add(btree_entry_overhead_byte_length)
                .ok_or(CommonProofProverError::CountOverflow)?;
        let mask_entry_byte_length =
            u64::try_from(core::mem::size_of::<(u32, RelationMaskDescriptor)>())
                .map_err(|_| CommonProofProverError::CountOverflow)?
                .checked_add(btree_entry_overhead_byte_length)
                .ok_or(CommonProofProverError::CountOverflow)?;
        vector_byte_length::<u32>(self.requested_column_ordinals.capacity())?
            .checked_add(vector_byte_length::<(u32, u32)>(
                self.reversed_column_bindings.capacity(),
            )?)
            .and_then(|total| {
                u64::try_from(self.tree_roles.len())
                    .ok()
                    .and_then(|count| count.checked_mul(tree_role_entry_byte_length))
                    .and_then(|byte_length| total.checked_add(byte_length))
            })
            .and_then(|total| {
                u64::try_from(self.trace_masks.len())
                    .ok()
                    .and_then(|count| count.checked_mul(mask_entry_byte_length))
                    .and_then(|byte_length| total.checked_add(byte_length))
            })
            .and_then(|total| {
                vector_byte_length::<CommonProofSourcePolynomialReplayIdentity>(
                    self.ordered_replay_identities.capacity(),
                )
                .ok()
                .and_then(|byte_length| total.checked_add(byte_length))
            })
            .ok_or(CommonProofProverError::CountOverflow)
    }

    pub(crate) fn completed_replay_identity_catalog_resident_owned_payload_byte_length(
        &self,
    ) -> Result<u64, CommonProofProverError> {
        u64::try_from(self.requested_column_ordinals.len())
            .ok()
            .and_then(|count| {
                u64::try_from(core::mem::size_of::<
                    CommonProofSourcePolynomialReplayIdentity,
                >())
                .ok()
                .and_then(|element_byte_length| count.checked_mul(element_byte_length))
            })
            .ok_or(CommonProofProverError::CountOverflow)
    }

    pub(crate) fn new(
        variant: &RelationPlanVariant,
        request_context: CommonProofSourcePolynomialRequestContext,
    ) -> Result<Self, CommonProofProverError> {
        let tree_roles = proof_created_tree_roles_by_column(variant)?;
        let trace_masks = trace_masks_by_column(variant)?;
        let (reversed_columns_by_source, integer_lift_auxiliary_columns) =
            integer_lift_derived_columns(variant)?;
        let reversed_columns = reversed_columns_by_source
            .values()
            .copied()
            .collect::<BTreeSet<_>>();
        let requested_column_ordinals =
            requested_pre_challenge_source_column_ordinals_from_derived_catalogs(
                variant,
                &tree_roles,
                &reversed_columns,
                &integer_lift_auxiliary_columns,
            )?;
        let source_identity_part_count = u64::try_from(requested_column_ordinals.len())
            .ok()
            .and_then(|count| count.checked_add(2))
            .ok_or(CommonProofProverError::CountOverflow)?;
        let mut source_identity_hasher = StreamingHash512::new(
            SOURCE_REPLAY_IDENTITY_AGGREGATE_DOMAIN,
            source_identity_part_count,
        );
        source_identity_hasher.absorb_part(&request_context.relation_plan_variant_hash);
        source_identity_hasher.absorb_part(
            &u64::try_from(requested_column_ordinals.len())
                .map_err(|_| CommonProofProverError::CountOverflow)?
                .to_le_bytes(),
        );
        let mut ordered_replay_identities = Vec::new();
        ordered_replay_identities
            .try_reserve_exact(requested_column_ordinals.len())
            .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
        Ok(Self {
            requested_column_ordinals,
            reversed_column_bindings: reversed_columns_by_source.into_iter().collect(),
            tree_roles,
            trace_masks,
            next_source_index: 0,
            source_identity_hasher: Some(source_identity_hasher),
            ordered_replay_identities,
        })
    }

    pub(crate) fn next_source<Coins>(
        &mut self,
        variant: &RelationPlanVariant,
        request_context: CommonProofSourcePolynomialRequestContext,
        source_provider: &mut dyn CommonProofSourcePolynomialProvider,
        coins: &mut Coins,
        maximum_candidate_draws_per_output: u32,
    ) -> Result<CommonProofPreChallengeSourcePoll, CommonProofPrivateCoinError<Coins::Error>>
    where
        Coins: CommonProofPrivateCoinSource,
    {
        let Some(column_ordinal) = self
            .requested_column_ordinals
            .get(self.next_source_index)
            .copied()
        else {
            return Ok(CommonProofPreChallengeSourcePoll::Complete);
        };
        let column_index = usize::try_from(column_ordinal).map_err(|_| {
            CommonProofPrivateCoinError::Prover(CommonProofProverError::CountOverflow)
        })?;
        let descriptor = variant.ordered_columns().get(column_index).ok_or(
            CommonProofPrivateCoinError::Prover(CommonProofProverError::InvalidColumn),
        )?;
        let ProvidedCommonProofSourcePolynomial {
            polynomial: source,
            replay_identity,
        } = match source_provider
            .poll_source_polynomial(request_context.request(column_ordinal, descriptor))
            .map_err(CommonProofPrivateCoinError::Prover)?
        {
            CommonProofSourcePolynomialProviderPoll::Ready(provided) => provided,
            CommonProofSourcePolynomialProviderPoll::AuthenticatedSourceReadRequired => {
                return Ok(CommonProofPreChallengeSourcePoll::AuthenticatedSourceReadRequired);
            }
        };
        validate_source_column(descriptor, &source, variant.trace_domain_size())
            .map_err(CommonProofPrivateCoinError::Prover)?;
        let mut coordinate_identity = [0_u8; 68];
        coordinate_identity[..4].copy_from_slice(&column_ordinal.to_le_bytes());
        coordinate_identity[4..].copy_from_slice(&replay_identity.bytes());
        self.source_identity_hasher
            .as_mut()
            .ok_or(CommonProofPrivateCoinError::Prover(
                CommonProofProverError::InvalidInput,
            ))?
            .absorb_part(&coordinate_identity);
        self.ordered_replay_identities.push(replay_identity);
        let source = match self.tree_roles.get(&column_ordinal) {
            Some(ProofTreeRole::BaseOracle) => mask_relation_column(
                variant,
                descriptor,
                self.trace_masks.get(&column_ordinal).copied(),
                source,
                coins,
                maximum_candidate_draws_per_output,
            )?,
            Some(_) => {
                return Err(CommonProofPrivateCoinError::Prover(
                    CommonProofProverError::InvalidColumn,
                ));
            }
            None => source,
        };
        self.next_source_index =
            self.next_source_index
                .checked_add(1)
                .ok_or(CommonProofPrivateCoinError::Prover(
                    CommonProofProverError::CountOverflow,
                ))?;
        Ok(CommonProofPreChallengeSourcePoll::Ready {
            column_ordinal,
            polynomial: source,
        })
    }

    pub(crate) fn finish(
        &mut self,
        source_provider: &mut dyn CommonProofSourcePolynomialProvider,
    ) -> Result<CommonProofSourceReplayIdentityCatalog, CommonProofProverError> {
        if self.next_source_index != self.requested_column_ordinals.len()
            || self.ordered_replay_identities.len() != self.requested_column_ordinals.len()
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        source_provider.finish()?;
        let aggregate_digest = self
            .source_identity_hasher
            .take()
            .map(StreamingHash512::finalize)
            .ok_or(CommonProofProverError::InvalidInput)?;
        Ok(CommonProofSourceReplayIdentityCatalog {
            aggregate_digest,
            ordered_replay_identities: core::mem::take(&mut self.ordered_replay_identities)
                .into_boxed_slice(),
        })
    }

    pub(crate) fn reversed_column_bindings(&self) -> &[(u32, u32)] {
        &self.reversed_column_bindings
    }

    #[cfg(test)]
    pub(crate) fn next_source_column_ordinal(&self) -> Option<u32> {
        self.requested_column_ordinals
            .get(self.next_source_index)
            .copied()
    }
}

pub(crate) fn relation_reversed_column_bindings(
    variant: &RelationPlanVariant,
) -> Result<Vec<(u32, u32)>, CommonProofProverError> {
    let (reversed_columns_by_source, _) = integer_lift_derived_columns(variant)?;
    Ok(reversed_columns_by_source.into_iter().collect())
}

pub(crate) fn construct_reversed_relation_column<Coins>(
    variant: &RelationPlanVariant,
    source_column_ordinal: u32,
    reversed_column_ordinal: u32,
    source: CommonProofSourcePolynomial,
    coins: &mut Coins,
    maximum_candidate_draws_per_output: u32,
) -> Result<CommonProofSourcePolynomial, CommonProofPrivateCoinError<Coins::Error>>
where
    Coins: CommonProofPrivateCoinSource,
{
    let reversed = construct_unmasked_reversed_relation_column(
        variant,
        source_column_ordinal,
        reversed_column_ordinal,
        source,
    )
    .map_err(CommonProofPrivateCoinError::Prover)?;
    let descriptor = variant
        .ordered_columns()
        .get(usize::try_from(reversed_column_ordinal).map_err(|_| {
            CommonProofPrivateCoinError::Prover(CommonProofProverError::CountOverflow)
        })?)
        .ok_or(CommonProofPrivateCoinError::Prover(
            CommonProofProverError::InvalidColumn,
        ))?;
    let tree_roles =
        proof_created_tree_roles_by_column(variant).map_err(CommonProofPrivateCoinError::Prover)?;
    let trace_masks =
        trace_masks_by_column(variant).map_err(CommonProofPrivateCoinError::Prover)?;
    if tree_roles.get(&reversed_column_ordinal) != Some(&ProofTreeRole::BaseOracle) {
        return Err(CommonProofPrivateCoinError::Prover(
            CommonProofProverError::InvalidColumn,
        ));
    }
    mask_relation_column(
        variant,
        descriptor,
        trace_masks.get(&reversed_column_ordinal).copied(),
        reversed,
        coins,
        maximum_candidate_draws_per_output,
    )
}

fn construct_unmasked_reversed_relation_column(
    variant: &RelationPlanVariant,
    source_column_ordinal: u32,
    reversed_column_ordinal: u32,
    source: CommonProofSourcePolynomial,
) -> Result<CommonProofSourcePolynomial, CommonProofProverError> {
    let (reversed_columns_by_source, _) = integer_lift_derived_columns(variant)?;
    if reversed_columns_by_source.get(&source_column_ordinal) != Some(&reversed_column_ordinal) {
        return Err(CommonProofProverError::InvalidColumn);
    }
    let trace_domain = ProofEvaluationDomain::new_subgroup(
        usize::try_from(variant.trace_domain_size())
            .map_err(|_| CommonProofProverError::CountOverflow)?,
    )?;
    let mut reversed_rows = base_trace_rows(&source, trace_domain)?;
    drop(source);
    reversed_rows.reverse();
    trace_domain
        .interpolate_base_polynomial_in_place(&mut reversed_rows)
        .map_err(CommonProofProverError::from)?;
    Ok(CommonProofSourcePolynomial::from_protected_base_coefficients(reversed_rows))
}

#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CommonProofColumnEvaluations {
    Base(Zeroizing<Vec<ProofBaseFieldElement>>),
    Extension(Zeroizing<Vec<ProofChallengeExtensionElement>>),
}

#[cfg(test)]
impl CommonProofColumnEvaluations {
    pub(super) fn extension_value(
        &self,
        position: usize,
    ) -> Result<ProofChallengeExtensionElement, CommonProofProverError> {
        match self {
            Self::Base(values) => values
                .get(position)
                .copied()
                .map(ProofChallengeExtensionElement::from_base),
            Self::Extension(values) => values.get(position).copied(),
        }
        .ok_or(CommonProofProverError::InvalidColumn)
    }
}

/// Samples one uniform base-field polynomial of degree below the exclusive
/// bound from its plan-assigned private stream.
pub(crate) fn sample_private_base_polynomial<Coins>(
    coins: &mut Coins,
    coordinate: CommonProofPrivateCoinCoordinate,
    degree_bound_exclusive: u64,
    maximum_candidate_draws_per_output: u32,
) -> Result<Zeroizing<Vec<ProofBaseFieldElement>>, CommonProofPrivateCoinError<Coins::Error>>
where
    Coins: CommonProofPrivateCoinSource,
{
    let coefficient_count = usize::try_from(degree_bound_exclusive)
        .map_err(|_| CommonProofPrivateCoinError::Prover(CommonProofProverError::CountOverflow))?;
    if coefficient_count == 0 {
        return Err(CommonProofPrivateCoinError::Prover(
            CommonProofProverError::InvalidMask,
        ));
    }
    let mut coefficients = Zeroizing::new(Vec::new());
    coefficients
        .try_reserve_exact(coefficient_count)
        .map_err(|_| {
            CommonProofPrivateCoinError::Prover(CommonProofProverError::AllocationLimitExceeded)
        })?;
    for _ in 0..coefficient_count {
        let coordinate = coins
            .sample_modulo(
                coordinate,
                super::super::PROOF_BASE_FIELD_MODULUS,
                maximum_candidate_draws_per_output,
            )
            .map_err(CommonProofPrivateCoinError::CoinSource)?;
        coefficients.push(
            ProofBaseFieldElement::from_canonical(coordinate)
                .map_err(CommonProofProverError::from)
                .map_err(CommonProofPrivateCoinError::Prover)?,
        );
    }
    Ok(coefficients)
}

/// Samples one uniform challenge-extension polynomial.  Coordinates are read
/// in constant-first extension basis order for each increasing coefficient.
pub(crate) fn sample_private_extension_polynomial<Coins>(
    coins: &mut Coins,
    private_coin_coordinate: CommonProofPrivateCoinCoordinate,
    degree_bound_exclusive: u64,
    maximum_candidate_draws_per_output: u32,
) -> Result<Zeroizing<Vec<ProofChallengeExtensionElement>>, CommonProofPrivateCoinError<Coins::Error>>
where
    Coins: CommonProofPrivateCoinSource,
{
    let coefficient_count = usize::try_from(degree_bound_exclusive)
        .map_err(|_| CommonProofPrivateCoinError::Prover(CommonProofProverError::CountOverflow))?;
    if coefficient_count == 0 {
        return Err(CommonProofPrivateCoinError::Prover(
            CommonProofProverError::InvalidMask,
        ));
    }
    let mut coefficients = Zeroizing::new(Vec::new());
    coefficients
        .try_reserve_exact(coefficient_count)
        .map_err(|_| {
            CommonProofPrivateCoinError::Prover(CommonProofProverError::AllocationLimitExceeded)
        })?;
    for _ in 0..coefficient_count {
        let mut coordinates =
            Zeroizing::new([0_u64; super::super::PROOF_CHALLENGE_EXTENSION_DEGREE]);
        for coordinate in coordinates.iter_mut() {
            *coordinate = coins
                .sample_modulo(
                    private_coin_coordinate,
                    super::super::PROOF_BASE_FIELD_MODULUS,
                    maximum_candidate_draws_per_output,
                )
                .map_err(CommonProofPrivateCoinError::CoinSource)?;
        }
        coefficients.push(
            ProofChallengeExtensionElement::from_canonical_coordinates(*coordinates)
                .map_err(CommonProofProverError::from)
                .map_err(CommonProofPrivateCoinError::Prover)?,
        );
    }
    Ok(coefficients)
}

/// Reconstructs one checked trace-mask polynomial from its private coordinate
/// stream. The coin source authenticates that the replay consumes the exact
/// stream prefix used by the original commitment; no transcript or public
/// value can supply these samples.
pub(crate) fn replay_relation_private_mask_polynomial<Coins>(
    variant: &RelationPlanVariant,
    column_ordinal: u32,
    coins: &mut Coins,
    maximum_candidate_draws_per_output: u32,
) -> Result<Option<CommonProofSourcePolynomial>, CommonProofPrivateCoinError<Coins::Error>>
where
    Coins: CommonProofPrivateCoinSource,
{
    let Some(coefficient_count) =
        relation_private_mask_tail_coefficient_count(variant, column_ordinal)
            .map_err(CommonProofPrivateCoinError::Prover)?
    else {
        return Ok(None);
    };
    let descriptor = variant
        .ordered_columns()
        .get(usize::try_from(column_ordinal).map_err(|_| {
            CommonProofPrivateCoinError::Prover(CommonProofProverError::CountOverflow)
        })?)
        .ok_or(CommonProofPrivateCoinError::Prover(
            CommonProofProverError::InvalidColumn,
        ))?;
    let mask = trace_masks_by_column(variant)
        .map_err(CommonProofPrivateCoinError::Prover)?
        .get(&column_ordinal)
        .copied()
        .ok_or(CommonProofPrivateCoinError::Prover(
            CommonProofProverError::InvalidMask,
        ))?;
    let coordinate = CommonProofPrivateCoinCoordinate::from_mask(mask.mask_coordinate());
    let coordinate_count_per_coefficient = match descriptor.value_type() {
        RelationColumnValueType::BaseField => 1,
        RelationColumnValueType::ChallengeExtension => {
            super::super::PROOF_CHALLENGE_EXTENSION_DEGREE
        }
    };
    let sample_count = coefficient_count
        .checked_mul(coordinate_count_per_coefficient)
        .ok_or(CommonProofPrivateCoinError::Prover(
            CommonProofProverError::CountOverflow,
        ))?;
    let mut samples = Zeroizing::new(Vec::new());
    samples.try_reserve_exact(sample_count).map_err(|_| {
        CommonProofPrivateCoinError::Prover(CommonProofProverError::AllocationLimitExceeded)
    })?;
    samples.resize(sample_count, 0);
    coins
        .replay_modulo_samples(
            coordinate,
            super::super::PROOF_BASE_FIELD_MODULUS,
            maximum_candidate_draws_per_output,
            &mut samples,
        )
        .map_err(CommonProofPrivateCoinError::CoinSource)?;

    match descriptor.value_type() {
        RelationColumnValueType::BaseField => {
            let coefficients = samples
                .iter()
                .copied()
                .map(ProofBaseFieldElement::from_canonical)
                .collect::<Result<Vec<_>, _>>()
                .map_err(CommonProofProverError::from)
                .map_err(CommonProofPrivateCoinError::Prover)?;
            Ok(Some(
                CommonProofSourcePolynomial::from_protected_base_coefficients(Zeroizing::new(
                    coefficients,
                )),
            ))
        }
        RelationColumnValueType::ChallengeExtension => {
            let mut coefficients = Zeroizing::new(Vec::new());
            coefficients
                .try_reserve_exact(coefficient_count)
                .map_err(|_| {
                    CommonProofPrivateCoinError::Prover(
                        CommonProofProverError::AllocationLimitExceeded,
                    )
                })?;
            for coordinates in samples.chunks_exact(super::super::PROOF_CHALLENGE_EXTENSION_DEGREE)
            {
                let canonical_coordinates: [u64; super::super::PROOF_CHALLENGE_EXTENSION_DEGREE] =
                    coordinates.try_into().map_err(|_| {
                        CommonProofPrivateCoinError::Prover(CommonProofProverError::InvalidMask)
                    })?;
                coefficients.push(
                    ProofChallengeExtensionElement::from_canonical_coordinates(
                        canonical_coordinates,
                    )
                    .map_err(CommonProofProverError::from)
                    .map_err(CommonProofPrivateCoinError::Prover)?,
                );
            }
            Ok(Some(
                CommonProofSourcePolynomial::from_protected_extension_coefficients(coefficients),
            ))
        }
    }
}

/// Samples the separately committed opening-batch polynomial in secret mode.
pub(crate) fn construct_opening_batch_mask<Coins>(
    variant: &RelationPlanVariant,
    coins: &mut Coins,
    maximum_candidate_draws_per_output: u32,
) -> Result<
    Option<Zeroizing<Vec<ProofChallengeExtensionElement>>>,
    CommonProofPrivateCoinError<Coins::Error>,
>
where
    Coins: CommonProofPrivateCoinSource,
{
    if variant.proof_privacy_mode() == ProofPrivacyMode::PublicOnly {
        return Ok(None);
    }
    let mut descriptors = variant.ordered_masks().iter().copied().filter(|mask| {
        mask.mask_kind() == RelationMaskKind::OpeningBatch
            && mask.target_class() == RelationMaskTargetClass::Batch
            && mask.target_ordinal() == 0
    });
    let descriptor = descriptors
        .next()
        .ok_or(CommonProofPrivateCoinError::Prover(
            CommonProofProverError::InvalidMask,
        ))?;
    if descriptors.next().is_some() {
        return Err(CommonProofPrivateCoinError::Prover(
            CommonProofProverError::InvalidMask,
        ));
    }
    Ok(Some(sample_private_extension_polynomial(
        coins,
        CommonProofPrivateCoinCoordinate::from_mask(descriptor.mask_coordinate()),
        descriptor.mask_degree_bound_exclusive(),
        maximum_candidate_draws_per_output,
    )?))
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CommonProofPrivateCoinError<CoinError> {
    Prover(CommonProofProverError),
    CoinSource(CoinError),
}

impl<CoinError> From<CommonProofProverError> for CommonProofPrivateCoinError<CoinError> {
    fn from(error: CommonProofProverError) -> Self {
        Self::Prover(error)
    }
}

/// Applies `witness + (X^H - 1) mask` without changing coefficient order.
pub(crate) fn apply_trace_mask(
    witness: CommonProofSourcePolynomial,
    trace_domain_size: u64,
    mask: CommonProofSourcePolynomial,
) -> Result<CommonProofSourcePolynomial, CommonProofProverError> {
    let trace_domain_size =
        usize::try_from(trace_domain_size).map_err(|_| CommonProofProverError::CountOverflow)?;
    if trace_domain_size == 0 || mask.coefficient_count() == 0 {
        return Err(CommonProofProverError::InvalidMask);
    }
    match (witness, mask) {
        (
            CommonProofSourcePolynomial::Base(mut witness),
            CommonProofSourcePolynomial::Base(mask),
        ) => {
            let output_length = trace_domain_size
                .checked_add(mask.len())
                .ok_or(CommonProofProverError::CountOverflow)?;
            let target_length = output_length.max(witness.len());
            witness.resize(target_length, ProofBaseFieldElement::ZERO);
            for (mask_ordinal, coefficient) in mask.iter().copied().enumerate() {
                witness[mask_ordinal] = witness[mask_ordinal].subtract(coefficient);
                let shifted_ordinal = trace_domain_size
                    .checked_add(mask_ordinal)
                    .ok_or(CommonProofProverError::CountOverflow)?;
                witness[shifted_ordinal] = witness[shifted_ordinal].add(coefficient);
            }
            trim_base_polynomial(&mut witness);
            Ok(CommonProofSourcePolynomial::Base(witness))
        }
        (
            CommonProofSourcePolynomial::Extension(mut witness),
            CommonProofSourcePolynomial::Extension(mask),
        ) => {
            let output_length = trace_domain_size
                .checked_add(mask.len())
                .ok_or(CommonProofProverError::CountOverflow)?;
            let target_length = output_length.max(witness.len());
            witness.resize(target_length, ProofChallengeExtensionElement::ZERO);
            for (mask_ordinal, coefficient) in mask.iter().copied().enumerate() {
                witness[mask_ordinal] = witness[mask_ordinal].subtract(coefficient);
                let shifted_ordinal = trace_domain_size
                    .checked_add(mask_ordinal)
                    .ok_or(CommonProofProverError::CountOverflow)?;
                witness[shifted_ordinal] = witness[shifted_ordinal].add(coefficient);
            }
            trim_extension_polynomial(&mut witness);
            Ok(CommonProofSourcePolynomial::Extension(witness))
        }
        _ => Err(CommonProofProverError::InvalidMask),
    }
}

/// Columns constructed before the common transcript releases the complete
/// non-native challenge vector.  Auxiliary-tree entries remain absent, so a
/// caller cannot accidentally commit a challenge-dependent column early.
#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct CommonProofPreChallengeRelationColumns {
    columns: Vec<Option<CommonProofSourcePolynomial>>,
    source_replay_identity_digest: [u8; 64],
}

#[cfg(test)]
impl CommonProofPreChallengeRelationColumns {
    pub(crate) fn column(&self, column_ordinal: u32) -> Option<&CommonProofSourcePolynomial> {
        self.columns
            .get(usize::try_from(column_ordinal).ok()?)
            .and_then(Option::as_ref)
    }

    pub(crate) const fn source_replay_identity_digest(&self) -> [u8; 64] {
        self.source_replay_identity_digest
    }
}

/// Constructs and masks every column committed before the application
/// challenges.  Callers provide only the plan's genuine pre-challenge input
/// columns.  Reversed multiplier columns are derived here from their checked
/// source descriptors; supplying either a reversed or an auxiliary column is
/// rejected.
#[cfg(test)]
pub(crate) fn construct_pre_challenge_relation_columns<Coins>(
    variant: &RelationPlanVariant,
    request_context: CommonProofSourcePolynomialRequestContext,
    source_provider: &mut dyn CommonProofSourcePolynomialProvider,
    coins: &mut Coins,
    maximum_candidate_draws_per_output: u32,
) -> Result<CommonProofPreChallengeRelationColumns, CommonProofPrivateCoinError<Coins::Error>>
where
    Coins: CommonProofPrivateCoinSource,
{
    let tree_roles =
        proof_created_tree_roles_by_column(variant).map_err(CommonProofPrivateCoinError::Prover)?;
    let (reversed_columns_by_source, integer_lift_auxiliary_columns) =
        integer_lift_derived_columns(variant).map_err(CommonProofPrivateCoinError::Prover)?;
    let reversed_columns = reversed_columns_by_source
        .values()
        .copied()
        .collect::<BTreeSet<_>>();
    let mut columns = Vec::new();
    columns
        .try_reserve_exact(variant.ordered_columns().len())
        .map_err(|_| {
            CommonProofPrivateCoinError::Prover(CommonProofProverError::AllocationLimitExceeded)
        })?;
    columns.resize_with(variant.ordered_columns().len(), || None);

    let requested_column_ordinals =
        requested_pre_challenge_source_column_ordinals_from_derived_catalogs(
            variant,
            &tree_roles,
            &reversed_columns,
            &integer_lift_auxiliary_columns,
        )
        .map_err(CommonProofPrivateCoinError::Prover)?;
    let requested_source_count = requested_column_ordinals.len();
    let source_identity_part_count = u64::try_from(requested_source_count)
        .ok()
        .and_then(|count| count.checked_add(2))
        .ok_or(CommonProofPrivateCoinError::Prover(
            CommonProofProverError::CountOverflow,
        ))?;
    let mut source_identity_hasher = StreamingHash512::new(
        SOURCE_REPLAY_IDENTITY_AGGREGATE_DOMAIN,
        source_identity_part_count,
    );
    source_identity_hasher.absorb_part(&request_context.relation_plan_variant_hash);
    source_identity_hasher.absorb_part(
        &u64::try_from(requested_source_count)
            .map_err(|_| {
                CommonProofPrivateCoinError::Prover(CommonProofProverError::CountOverflow)
            })?
            .to_le_bytes(),
    );

    for column_ordinal in requested_column_ordinals {
        let column_index = usize::try_from(column_ordinal).map_err(|_| {
            CommonProofPrivateCoinError::Prover(CommonProofProverError::CountOverflow)
        })?;
        let descriptor = variant.ordered_columns().get(column_index).ok_or(
            CommonProofPrivateCoinError::Prover(CommonProofProverError::InvalidColumn),
        )?;
        let ProvidedCommonProofSourcePolynomial {
            polynomial: source,
            replay_identity,
        } = match source_provider
            .poll_source_polynomial(request_context.request(column_ordinal, descriptor))
            .map_err(CommonProofPrivateCoinError::Prover)?
        {
            CommonProofSourcePolynomialProviderPoll::Ready(provided) => provided,
            CommonProofSourcePolynomialProviderPoll::AuthenticatedSourceReadRequired => {
                return Err(CommonProofPrivateCoinError::Prover(
                    CommonProofProverError::InvalidInput,
                ));
            }
        };
        validate_source_column(descriptor, &source, variant.trace_domain_size())
            .map_err(CommonProofPrivateCoinError::Prover)?;
        let mut coordinate_identity = [0_u8; 68];
        coordinate_identity[..4].copy_from_slice(&column_ordinal.to_le_bytes());
        coordinate_identity[4..].copy_from_slice(&replay_identity.bytes());
        source_identity_hasher.absorb_part(&coordinate_identity);
        let column_slot =
            columns
                .get_mut(column_index)
                .ok_or(CommonProofPrivateCoinError::Prover(
                    CommonProofProverError::InvalidColumn,
                ))?;
        if column_slot.replace(source).is_some() {
            return Err(CommonProofPrivateCoinError::Prover(
                CommonProofProverError::InvalidColumn,
            ));
        }
    }
    source_provider
        .finish()
        .map_err(CommonProofPrivateCoinError::Prover)?;
    let source_replay_identity_digest = source_identity_hasher.finalize();

    let trace_domain =
        ProofEvaluationDomain::new_subgroup(usize::try_from(variant.trace_domain_size()).map_err(
            |_| CommonProofPrivateCoinError::Prover(CommonProofProverError::CountOverflow),
        )?)
        .map_err(CommonProofProverError::from)
        .map_err(CommonProofPrivateCoinError::Prover)?;
    for (source_ordinal, reversed_ordinal) in reversed_columns_by_source {
        let source = columns
            .get(usize::try_from(source_ordinal).map_err(|_| {
                CommonProofPrivateCoinError::Prover(CommonProofProverError::CountOverflow)
            })?)
            .and_then(Option::as_ref)
            .ok_or_else(|| {
                CommonProofPrivateCoinError::Prover(CommonProofProverError::InvalidColumn)
            })?;
        let mut reversed_rows =
            base_trace_rows(source, trace_domain).map_err(CommonProofPrivateCoinError::Prover)?;
        reversed_rows.reverse();
        let reversed_polynomial = CommonProofSourcePolynomial::from_base_coefficients(
            trace_domain
                .interpolate_base_polynomial(&reversed_rows)
                .map_err(CommonProofProverError::from)
                .map_err(CommonProofPrivateCoinError::Prover)?,
        );
        let destination = columns
            .get_mut(usize::try_from(reversed_ordinal).map_err(|_| {
                CommonProofPrivateCoinError::Prover(CommonProofProverError::CountOverflow)
            })?)
            .ok_or_else(|| {
                CommonProofPrivateCoinError::Prover(CommonProofProverError::InvalidColumn)
            })?;
        if destination.replace(reversed_polynomial).is_some() {
            return Err(CommonProofPrivateCoinError::Prover(
                CommonProofProverError::InvalidColumn,
            ));
        }
    }

    let trace_masks =
        trace_masks_by_column(variant).map_err(CommonProofPrivateCoinError::Prover)?;
    for (column_index, descriptor) in variant.ordered_columns().iter().enumerate() {
        let column_ordinal = u32::try_from(column_index).map_err(|_| {
            CommonProofPrivateCoinError::Prover(CommonProofProverError::CountOverflow)
        })?;
        match tree_roles.get(&column_ordinal) {
            Some(ProofTreeRole::BaseOracle) => {
                let source = columns[column_index].take().ok_or_else(|| {
                    CommonProofPrivateCoinError::Prover(CommonProofProverError::InvalidColumn)
                })?;
                columns[column_index] = Some(mask_relation_column(
                    variant,
                    descriptor,
                    trace_masks.get(&column_ordinal).copied(),
                    source,
                    coins,
                    maximum_candidate_draws_per_output,
                )?);
            }
            Some(ProofTreeRole::AuxiliaryOracle) => {
                if columns[column_index].is_some() {
                    return Err(CommonProofPrivateCoinError::Prover(
                        CommonProofProverError::InvalidColumn,
                    ));
                }
            }
            None => {
                if columns[column_index].is_none() {
                    return Err(CommonProofPrivateCoinError::Prover(
                        CommonProofProverError::InvalidColumn,
                    ));
                }
            }
        }
    }
    Ok(CommonProofPreChallengeRelationColumns {
        columns,
        source_replay_identity_digest,
    })
}

pub(crate) fn proof_created_tree_roles_by_column(
    variant: &RelationPlanVariant,
) -> Result<BTreeMap<u32, ProofTreeRole>, CommonProofProverError> {
    let mut roles = BTreeMap::new();
    for tree in variant.ordered_trees() {
        let RelationTreeDescriptor::ProofCreated {
            proof_tree_role,
            ordered_column_ordinals,
        } = tree
        else {
            continue;
        };
        let role = match *proof_tree_role {
            value if value == ProofTreeRole::BaseOracle as u16 => ProofTreeRole::BaseOracle,
            value if value == ProofTreeRole::AuxiliaryOracle as u16 => {
                ProofTreeRole::AuxiliaryOracle
            }
            _ => return Err(CommonProofProverError::InvalidTree),
        };
        for column_ordinal in ordered_column_ordinals {
            if roles.insert(*column_ordinal, role).is_some() {
                return Err(CommonProofProverError::InvalidTree);
            }
        }
    }
    Ok(roles)
}

fn requested_pre_challenge_source_column_ordinals_from_derived_catalogs(
    variant: &RelationPlanVariant,
    proof_tree_roles: &BTreeMap<u32, ProofTreeRole>,
    derived_reversed_columns: &BTreeSet<u32>,
    integer_lift_auxiliary_columns: &BTreeSet<u32>,
) -> Result<Vec<u32>, CommonProofProverError> {
    let mut requested_column_ordinals = Vec::new();
    requested_column_ordinals
        .try_reserve_exact(variant.ordered_columns().len())
        .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
    for column_index in 0..variant.ordered_columns().len() {
        let column_ordinal =
            u32::try_from(column_index).map_err(|_| CommonProofProverError::CountOverflow)?;
        if proof_tree_roles.get(&column_ordinal) != Some(&ProofTreeRole::AuxiliaryOracle)
            && !integer_lift_auxiliary_columns.contains(&column_ordinal)
            && !derived_reversed_columns.contains(&column_ordinal)
        {
            requested_column_ordinals.push(column_ordinal);
        }
    }
    Ok(requested_column_ordinals)
}

pub(crate) fn requested_pre_challenge_source_column_ordinals(
    variant: &RelationPlanVariant,
) -> Result<Vec<u32>, CommonProofProverError> {
    let proof_tree_roles = proof_created_tree_roles_by_column(variant)?;
    let (reversed_columns_by_source, integer_lift_auxiliary_columns) =
        integer_lift_derived_columns(variant)?;
    let derived_reversed_columns = reversed_columns_by_source
        .into_values()
        .collect::<BTreeSet<_>>();
    requested_pre_challenge_source_column_ordinals_from_derived_catalogs(
        variant,
        &proof_tree_roles,
        &derived_reversed_columns,
        &integer_lift_auxiliary_columns,
    )
}

pub(crate) fn integer_lift_derived_columns(
    variant: &RelationPlanVariant,
) -> Result<(BTreeMap<u32, u32>, BTreeSet<u32>), CommonProofProverError> {
    let mut reversed_columns_by_source = BTreeMap::new();
    let mut source_by_reversed_column = BTreeMap::new();
    let mut auxiliary_columns = BTreeSet::new();
    for batch in variant.ordered_integer_lift_batches() {
        for permutation in &batch.ordered_negacyclic_automorphism_permutations {
            auxiliary_columns.extend([
                permutation.source_product_before_column_ordinal,
                permutation.source_low_product_column_ordinal,
                permutation.target_product_before_column_ordinal,
                permutation.target_low_product_column_ordinal,
            ]);
        }
        for binding in &batch.ordered_reversed_column_bindings {
            match reversed_columns_by_source.insert(
                binding.source_column_ordinal,
                binding.reversed_column_ordinal,
            ) {
                Some(existing) if existing != binding.reversed_column_ordinal => {
                    return Err(CommonProofProverError::InvalidColumn);
                }
                _ => {}
            }
            match source_by_reversed_column.insert(
                binding.reversed_column_ordinal,
                binding.source_column_ordinal,
            ) {
                Some(existing) if existing != binding.source_column_ordinal => {
                    return Err(CommonProofProverError::InvalidColumn);
                }
                _ => {}
            }
            auxiliary_columns.extend([
                binding.source_prefix_evaluation_column_ordinal,
                binding.reversed_suffix_evaluation_column_ordinal,
            ]);
        }
        for component in &batch.ordered_components {
            auxiliary_columns.extend([
                component.linear_evaluation_column_ordinal,
                component.product_accumulator_column_ordinal,
            ]);
            for product in &component.ordered_convolution_products {
                auxiliary_columns.extend([
                    product.suffix_evaluation_column_ordinal,
                    product.reversed_transpose_column_ordinal,
                ]);
            }
            for product in &component.ordered_full_ring_negacyclic_products {
                auxiliary_columns.extend([
                    product.multiplicand_low_suffix_evaluation_column_ordinal,
                    product.multiplicand_high_suffix_evaluation_column_ordinal,
                    product.reversed_multiplier_low_transpose_column_ordinal,
                    product.reversed_multiplier_high_transpose_column_ordinal,
                ]);
            }
        }
    }
    if source_by_reversed_column
        .keys()
        .any(|column| auxiliary_columns.contains(column))
    {
        return Err(CommonProofProverError::InvalidColumn);
    }
    Ok((reversed_columns_by_source, auxiliary_columns))
}

pub(crate) fn ordered_integer_lift_auxiliary_column_ordinals(
    variant: &RelationPlanVariant,
) -> Result<Vec<u32>, CommonProofProverError> {
    let mut ordered_columns = Vec::new();
    let mut unique_columns = BTreeSet::new();
    let mut append = |column_ordinal| {
        if unique_columns.insert(column_ordinal) {
            ordered_columns.push(column_ordinal);
        }
        Ok::<(), CommonProofProverError>(())
    };
    for batch in variant.ordered_integer_lift_batches() {
        for descriptor in &batch.ordered_negacyclic_automorphism_permutations {
            for column_ordinal in [
                descriptor.source_product_before_column_ordinal,
                descriptor.source_low_product_column_ordinal,
                descriptor.target_product_before_column_ordinal,
                descriptor.target_low_product_column_ordinal,
            ] {
                append(column_ordinal)?;
            }
        }
        for binding in &batch.ordered_reversed_column_bindings {
            append(binding.source_prefix_evaluation_column_ordinal)?;
            append(binding.reversed_suffix_evaluation_column_ordinal)?;
        }
        for component in &batch.ordered_components {
            for descriptor in &component.ordered_convolution_products {
                append(descriptor.suffix_evaluation_column_ordinal)?;
                append(descriptor.reversed_transpose_column_ordinal)?;
            }
            for descriptor in &component.ordered_full_ring_negacyclic_products {
                for column_ordinal in [
                    descriptor.multiplicand_low_suffix_evaluation_column_ordinal,
                    descriptor.multiplicand_high_suffix_evaluation_column_ordinal,
                    descriptor.reversed_multiplier_low_transpose_column_ordinal,
                    descriptor.reversed_multiplier_high_transpose_column_ordinal,
                ] {
                    append(column_ordinal)?;
                }
            }
            append(component.linear_evaluation_column_ordinal)?;
            append(component.product_accumulator_column_ordinal)?;
        }
    }
    let expected_columns = integer_lift_derived_columns(variant)?.1;
    if unique_columns != expected_columns {
        return Err(CommonProofProverError::InvalidColumn);
    }
    Ok(ordered_columns)
}

fn trace_masks_by_column(
    variant: &RelationPlanVariant,
) -> Result<BTreeMap<u32, RelationMaskDescriptor>, CommonProofProverError> {
    let mut masks = BTreeMap::new();
    for mask in variant.ordered_masks().iter().copied().filter(|mask| {
        mask.mask_kind() == RelationMaskKind::Trace
            && mask.target_class() == RelationMaskTargetClass::Column
    }) {
        if masks.insert(mask.target_ordinal(), mask).is_some() {
            return Err(CommonProofProverError::InvalidMask);
        }
    }
    Ok(masks)
}

/// Returns the maximum authenticated coefficient-position count supplied for
/// every genuine pre-challenge source column.
///
/// A relation descriptor owns an admissible degree ceiling, not necessarily
/// the number of coefficients produced by its authenticated source. Verifier
/// sequences and unmasked prover rows are interpolated over the trace domain;
/// committed-material sources already carry their persistent trace mask.
/// Keeping this derivation beside the production source cursor prevents source
/// manifests and accounting from silently treating every degree ceiling as
/// authenticated source data.
pub(crate) fn authenticated_pre_challenge_source_coefficient_position_counts(
    variant: &RelationPlanVariant,
) -> Result<BTreeMap<u32, u64>, CommonProofProverError> {
    let requested_column_ordinals = requested_pre_challenge_source_column_ordinals(variant)?;
    let mut counts = BTreeMap::new();

    for column_ordinal in requested_column_ordinals {
        let descriptor = variant
            .ordered_columns()
            .get(
                usize::try_from(column_ordinal)
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .ok_or(CommonProofProverError::InvalidColumn)?;
        let coefficient_position_count = match descriptor.origin() {
            RelationColumnOrigin::BoundTree { .. } => descriptor.source_degree_bound_exclusive(),
            RelationColumnOrigin::VerifierSequence { .. } | RelationColumnOrigin::Prover => {
                descriptor
                    .source_degree_bound_exclusive()
                    .min(variant.trace_domain_size())
            }
        };
        if coefficient_position_count == 0
            || coefficient_position_count > descriptor.source_degree_bound_exclusive()
            || counts
                .insert(column_ordinal, coefficient_position_count)
                .is_some()
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
    }
    Ok(counts)
}

/// Returns the maximum coefficient-position count persisted after applying
/// every proof-owned pre-challenge trace mask.
pub(crate) fn persisted_pre_challenge_column_coefficient_position_counts(
    variant: &RelationPlanVariant,
) -> Result<BTreeMap<u32, u64>, CommonProofProverError> {
    let proof_tree_roles = proof_created_tree_roles_by_column(variant)?;
    let trace_masks = trace_masks_by_column(variant)?;
    let source_counts = authenticated_pre_challenge_source_coefficient_position_counts(variant)?;
    let mut counts = BTreeMap::new();

    for (column_ordinal, source_count) in source_counts {
        let descriptor = variant
            .ordered_columns()
            .get(
                usize::try_from(column_ordinal)
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .ok_or(CommonProofProverError::InvalidColumn)?;
        let persisted_position_count = match proof_tree_roles.get(&column_ordinal) {
            Some(ProofTreeRole::BaseOracle) => match (
                descriptor.origin(),
                trace_masks.get(&column_ordinal).copied(),
            ) {
                (RelationColumnOrigin::Prover, Some(mask))
                    if variant.proof_privacy_mode() == ProofPrivacyMode::SecretBearing =>
                {
                    variant
                        .trace_domain_size()
                        .checked_add(mask.mask_degree_bound_exclusive())
                        .ok_or(CommonProofProverError::CountOverflow)?
                }
                (RelationColumnOrigin::Prover, _) => {
                    return Err(CommonProofProverError::InvalidMask);
                }
                (_, None) => source_count,
                (_, Some(_)) => return Err(CommonProofProverError::InvalidMask),
            },
            Some(_) => return Err(CommonProofProverError::InvalidColumn),
            None => source_count,
        };
        if persisted_position_count == 0
            || persisted_position_count > descriptor.source_degree_bound_exclusive()
            || counts
                .insert(column_ordinal, persisted_position_count)
                .is_some()
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
    }
    Ok(counts)
}

pub(crate) fn validate_source_column(
    descriptor: &RelationColumnDescriptor,
    source: &CommonProofSourcePolynomial,
    trace_domain_size: u64,
) -> Result<(), CommonProofProverError> {
    // Prover and verifier-sequence inputs are trace polynomials before any
    // proof-owned mask is applied, so their canonical interpolation contains
    // at most one coefficient per trace row. Bound-tree columns are different:
    // their authenticated source already includes the persistent trace mask.
    // Preserve that mask by accepting the complete descriptor-owned degree
    // bound instead of truncating it to the trace domain.
    let maximum_coefficient_count = match descriptor.origin() {
        RelationColumnOrigin::BoundTree { .. } => descriptor.source_degree_bound_exclusive(),
        RelationColumnOrigin::VerifierSequence { .. } | RelationColumnOrigin::Prover => descriptor
            .source_degree_bound_exclusive()
            .min(trace_domain_size),
    };
    if descriptor.value_type() != source.value_type()
        || source.coefficient_count() == 0
        || source.coefficient_count()
            > usize::try_from(maximum_coefficient_count)
                .map_err(|_| CommonProofProverError::CountOverflow)?
    {
        return Err(CommonProofProverError::InvalidColumn);
    }
    Ok(())
}

fn mask_relation_column<Coins>(
    variant: &RelationPlanVariant,
    descriptor: &RelationColumnDescriptor,
    mask: Option<RelationMaskDescriptor>,
    source: CommonProofSourcePolynomial,
    coins: &mut Coins,
    maximum_candidate_draws_per_output: u32,
) -> Result<CommonProofSourcePolynomial, CommonProofPrivateCoinError<Coins::Error>>
where
    Coins: CommonProofPrivateCoinSource,
{
    let constructed = match (descriptor.origin(), mask) {
        (RelationColumnOrigin::Prover, Some(mask))
            if variant.proof_privacy_mode() == ProofPrivacyMode::SecretBearing =>
        {
            let sampled = match source.value_type() {
                RelationColumnValueType::BaseField => {
                    CommonProofSourcePolynomial::from_protected_base_coefficients(
                        sample_private_base_polynomial(
                            coins,
                            CommonProofPrivateCoinCoordinate::from_mask(mask.mask_coordinate()),
                            mask.mask_degree_bound_exclusive(),
                            maximum_candidate_draws_per_output,
                        )?,
                    )
                }
                RelationColumnValueType::ChallengeExtension => {
                    CommonProofSourcePolynomial::from_protected_extension_coefficients(
                        sample_private_extension_polynomial(
                            coins,
                            CommonProofPrivateCoinCoordinate::from_mask(mask.mask_coordinate()),
                            mask.mask_degree_bound_exclusive(),
                            maximum_candidate_draws_per_output,
                        )?,
                    )
                }
            };
            apply_trace_mask(source, variant.trace_domain_size(), sampled)
                .map_err(CommonProofPrivateCoinError::Prover)?
        }
        (RelationColumnOrigin::Prover, _) => {
            return Err(CommonProofPrivateCoinError::Prover(
                CommonProofProverError::InvalidMask,
            ));
        }
        (_, None) => source,
        (_, Some(_)) => {
            return Err(CommonProofPrivateCoinError::Prover(
                CommonProofProverError::InvalidMask,
            ));
        }
    };
    if constructed.coefficient_count()
        > usize::try_from(descriptor.source_degree_bound_exclusive()).map_err(|_| {
            CommonProofPrivateCoinError::Prover(CommonProofProverError::CountOverflow)
        })?
    {
        return Err(CommonProofPrivateCoinError::Prover(
            CommonProofProverError::InvalidColumn,
        ));
    }
    Ok(constructed)
}

pub(crate) fn base_trace_rows(
    source: &CommonProofSourcePolynomial,
    trace_domain: ProofEvaluationDomain,
) -> Result<Zeroizing<Vec<ProofBaseFieldElement>>, CommonProofProverError> {
    let CommonProofSourcePolynomial::Base(coefficients) = source else {
        return Err(CommonProofProverError::InvalidColumn);
    };
    let mut reduced_coefficients =
        Zeroizing::new(vec![ProofBaseFieldElement::ZERO; trace_domain.size()]);
    for (coefficient_ordinal, coefficient) in coefficients.iter().copied().enumerate() {
        let reduced_ordinal = coefficient_ordinal % trace_domain.size();
        reduced_coefficients[reduced_ordinal] =
            reduced_coefficients[reduced_ordinal].add(coefficient);
    }
    trace_domain
        .evaluate_base_polynomial(&reduced_coefficients)
        .map(Zeroizing::new)
        .map_err(CommonProofProverError::from)
}

fn integer_lift_theta(
    variant: &RelationPlanVariant,
    context: &RelationPlanCheckContext,
    modulus_reference: SuiteModulusReference,
    challenge_ordinal: u16,
    assignments: &[RelationApplicationChallengeAssignment],
) -> Result<ProofBaseFieldElement, CommonProofProverError> {
    let modulus_ordinal = variant
        .non_native_modulus_ordinal(modulus_reference)
        .map_err(CommonProofProverError::from)?;
    let expected_challenge = CommonProofChallenge::Theta { modulus_ordinal };
    let mut matching = assignments.iter().copied().filter(|assignment| {
        assignment.challenge() == expected_challenge
            && assignment.repetition_ordinal() == challenge_ordinal
    });
    let value = matching
        .next()
        .map(RelationApplicationChallengeAssignment::value)
        .ok_or(CommonProofProverError::InvalidColumn)?;
    if matching.next().is_some() || value >= context.base_field_modulus {
        return Err(CommonProofProverError::InvalidColumn);
    }
    ProofBaseFieldElement::from_canonical(value).map_err(CommonProofProverError::from)
}

pub(super) fn prefix_evaluation_rows(
    source_rows: &[ProofBaseFieldElement],
    theta: ProofBaseFieldElement,
) -> ProtectedBaseTraceRows {
    let mut output = Zeroizing::new(Vec::with_capacity(source_rows.len()));
    let mut prefix = ProofBaseFieldElement::ZERO;
    for source in source_rows {
        prefix = prefix.multiply(theta).add(*source);
        output.push(prefix);
    }
    output
}

pub(super) fn suffix_evaluation_rows(
    source_rows: &[ProofBaseFieldElement],
    theta: ProofBaseFieldElement,
) -> ProtectedBaseTraceRows {
    let mut output = Zeroizing::new(vec![ProofBaseFieldElement::ZERO; source_rows.len()]);
    let mut suffix = ProofBaseFieldElement::ZERO;
    for row_ordinal in (0..source_rows.len()).rev() {
        suffix = source_rows[row_ordinal].add(theta.multiply(suffix));
        output[row_ordinal] = suffix;
    }
    output
}

#[derive(Clone, Copy)]
struct AuxiliaryTraceRowInsertionContext<'relation> {
    variant: &'relation RelationPlanVariant,
    tree_roles: &'relation BTreeMap<u32, ProofTreeRole>,
    trace_masks: &'relation BTreeMap<u32, RelationMaskDescriptor>,
    trace_domain: ProofEvaluationDomain,
    maximum_candidate_draws_per_output: u32,
}

impl<'relation> AuxiliaryTraceRowInsertionContext<'relation> {
    fn new(
        variant: &'relation RelationPlanVariant,
        tree_roles: &'relation BTreeMap<u32, ProofTreeRole>,
        trace_masks: &'relation BTreeMap<u32, RelationMaskDescriptor>,
        trace_domain: ProofEvaluationDomain,
        maximum_candidate_draws_per_output: u32,
    ) -> Self {
        Self {
            variant,
            tree_roles,
            trace_masks,
            trace_domain,
            maximum_candidate_draws_per_output,
        }
    }
}

fn construct_auxiliary_relation_column<Coins>(
    context: AuxiliaryTraceRowInsertionContext<'_>,
    column_ordinal: u32,
    mut rows: ProtectedBaseTraceRows,
    coins: &mut Coins,
) -> Result<CommonProofSourcePolynomial, CommonProofPrivateCoinError<Coins::Error>>
where
    Coins: CommonProofPrivateCoinSource,
{
    if rows.len() != context.trace_domain.size()
        || context.tree_roles.get(&column_ordinal) != Some(&ProofTreeRole::AuxiliaryOracle)
    {
        return Err(CommonProofPrivateCoinError::Prover(
            CommonProofProverError::InvalidColumn,
        ));
    }
    let descriptor = context
        .variant
        .ordered_columns()
        .get(usize::try_from(column_ordinal).map_err(|_| {
            CommonProofPrivateCoinError::Prover(CommonProofProverError::CountOverflow)
        })?)
        .ok_or(CommonProofPrivateCoinError::Prover(
            CommonProofProverError::InvalidColumn,
        ))?;
    if descriptor.value_type() != RelationColumnValueType::BaseField {
        return Err(CommonProofPrivateCoinError::Prover(
            CommonProofProverError::InvalidColumn,
        ));
    }
    context
        .trace_domain
        .interpolate_base_polynomial_in_place(&mut rows)
        .map_err(CommonProofProverError::from)
        .map_err(CommonProofPrivateCoinError::Prover)?;
    let source = CommonProofSourcePolynomial::from_protected_base_coefficients(rows);
    mask_relation_column(
        context.variant,
        descriptor,
        context.trace_masks.get(&column_ordinal).copied(),
        source,
        coins,
        context.maximum_candidate_draws_per_output,
    )
}

fn base_field_constant(value: u64) -> Result<ProofBaseFieldElement, CommonProofProverError> {
    ProofBaseFieldElement::from_canonical(value).map_err(CommonProofProverError::from)
}

fn integer_lift_coefficient_value(
    context: &RelationPlanCheckContext,
    coefficient: RelationIntegerLiftCoefficient,
) -> Result<ProofBaseFieldElement, CommonProofProverError> {
    let value = match coefficient {
        RelationIntegerLiftCoefficient::Constant(value) => value,
        RelationIntegerLiftCoefficient::Modulus {
            modulus_reference,
            multiplier,
        } => context
            .resolved_modulus(modulus_reference)?
            .checked_mul(u64::from(multiplier))
            .ok_or(CommonProofProverError::CountOverflow)?,
        RelationIntegerLiftCoefficient::ModulusRadixDigit {
            modulus_reference,
            multiplier,
            radix,
            digit_ordinal,
        } => super::super::relation_plan::resolved_modulus_radix_digit(
            modulus_reference,
            multiplier,
            radix,
            digit_ordinal,
            context,
        )
        .map_err(CommonProofProverError::from)?,
    };
    base_field_constant(value)
}

fn signed_linear_term_row(
    term: &RelationIntegerLiftLinearTermDescriptor,
    row_ordinal: usize,
    context: &RelationPlanCheckContext,
    trace_rows_by_column: &BTreeMap<u32, ProtectedBaseTraceRows>,
) -> Result<ProofBaseFieldElement, CommonProofProverError> {
    let column_value = trace_rows_by_column
        .get(&term.column_ordinal)
        .and_then(|rows| rows.get(row_ordinal))
        .copied()
        .ok_or(CommonProofProverError::InvalidColumn)?;
    let shifted = column_value.subtract(base_field_constant(term.column_offset)?);
    let value = shifted.multiply(integer_lift_coefficient_value(context, term.coefficient)?);
    Ok(if term.negative { value.negate() } else { value })
}

pub(super) fn product_accumulator_rows(
    product_rows: &[ProofBaseFieldElement],
) -> ProtectedBaseTraceRows {
    let mut accumulator_rows =
        Zeroizing::new(vec![ProofBaseFieldElement::ZERO; product_rows.len()]);
    for row_ordinal in 0..product_rows.len().saturating_sub(1) {
        accumulator_rows[row_ordinal + 1] =
            accumulator_rows[row_ordinal].add(product_rows[row_ordinal]);
    }
    accumulator_rows
}

pub(super) fn convolution_transpose_rows(
    kind: RelationIntegerLiftConvolutionKind,
    multiplicand_rows: &[ProofBaseFieldElement],
    suffix_rows: &[ProofBaseFieldElement],
    theta: ProofBaseFieldElement,
) -> Result<ProtectedBaseTraceRows, CommonProofProverError> {
    if multiplicand_rows.is_empty() || multiplicand_rows.len() != suffix_rows.len() {
        return Err(CommonProofProverError::InvalidColumn);
    }
    let row_count = multiplicand_rows.len();
    let theta_to_row_count =
        theta.power(u64::try_from(row_count).map_err(|_| CommonProofProverError::CountOverflow)?);
    let last = row_count - 1;
    let mut transpose_rows = Zeroizing::new(vec![ProofBaseFieldElement::ZERO; row_count]);
    match kind {
        RelationIntegerLiftConvolutionKind::Negacyclic => {
            transpose_rows[last] = suffix_rows[0];
            let wrap_factor = theta_to_row_count.add(ProofBaseFieldElement::ONE);
            for row_ordinal in (1..row_count).rev() {
                transpose_rows[row_ordinal - 1] = theta
                    .multiply(transpose_rows[row_ordinal])
                    .subtract(wrap_factor.multiply(multiplicand_rows[row_ordinal]));
            }
        }
    }
    Ok(transpose_rows)
}

pub(super) fn full_ring_transpose_rows(
    selected_half: RelationIntegerLiftFullRingHalf,
    low_multiplier: bool,
    multiplicand_low_rows: &[ProofBaseFieldElement],
    multiplicand_high_rows: &[ProofBaseFieldElement],
    low_suffix_rows: &[ProofBaseFieldElement],
    high_suffix_rows: &[ProofBaseFieldElement],
    theta: ProofBaseFieldElement,
) -> Result<ProtectedBaseTraceRows, CommonProofProverError> {
    let row_count = multiplicand_low_rows.len();
    if row_count == 0
        || multiplicand_high_rows.len() != row_count
        || low_suffix_rows.len() != row_count
        || high_suffix_rows.len() != row_count
    {
        return Err(CommonProofProverError::InvalidColumn);
    }
    let theta_to_half_ring_degree =
        theta.power(u64::try_from(row_count).map_err(|_| CommonProofProverError::CountOverflow)?);
    let last = row_count - 1;
    let mut transpose_rows = Zeroizing::new(vec![ProofBaseFieldElement::ZERO; row_count]);
    transpose_rows[last] = match (selected_half, low_multiplier) {
        (RelationIntegerLiftFullRingHalf::Low, true)
        | (RelationIntegerLiftFullRingHalf::High, false) => low_suffix_rows[0],
        (RelationIntegerLiftFullRingHalf::Low, false) => high_suffix_rows[0].negate(),
        (RelationIntegerLiftFullRingHalf::High, true) => high_suffix_rows[0],
    };
    for row_ordinal in (0..last).rev() {
        let low_next = multiplicand_low_rows[row_ordinal + 1];
        let high_next = multiplicand_high_rows[row_ordinal + 1];
        let theta_times_next = theta.multiply(transpose_rows[row_ordinal + 1]);
        transpose_rows[row_ordinal] = match (selected_half, low_multiplier) {
            (RelationIntegerLiftFullRingHalf::Low, true)
            | (RelationIntegerLiftFullRingHalf::High, false) => theta_times_next
                .subtract(theta_to_half_ring_degree.multiply(low_next))
                .subtract(high_next),
            (RelationIntegerLiftFullRingHalf::Low, false) => theta_times_next
                .subtract(low_next)
                .add(theta_to_half_ring_degree.multiply(high_next)),
            (RelationIntegerLiftFullRingHalf::High, true) => theta_times_next
                .add(low_next)
                .subtract(theta_to_half_ring_degree.multiply(high_next)),
        };
    }
    Ok(transpose_rows)
}

#[derive(Clone)]
enum AuxiliaryColumnSynthesisTask {
    BeginComponent,
    NegacyclicAutomorphismPermutation {
        descriptor: RelationIntegerLiftNegacyclicAutomorphismPermutationDescriptor,
        theta: ProofBaseFieldElement,
    },
    PrefixEvaluation {
        source_column_ordinal: u32,
        output_column_ordinal: u32,
        theta: ProofBaseFieldElement,
    },
    SuffixEvaluation {
        source_column_ordinal: u32,
        output_column_ordinal: u32,
        theta: ProofBaseFieldElement,
    },
    ConvolutionProduct {
        descriptor: RelationIntegerLiftConvolutionProductDescriptor,
        theta: ProofBaseFieldElement,
    },
    FullRingProduct {
        descriptor: RelationIntegerLiftFullRingNegacyclicProductDescriptor,
        theta: ProofBaseFieldElement,
    },
    LinearEvaluation {
        descriptor: RelationIntegerLiftComponentDescriptor,
        theta: ProofBaseFieldElement,
    },
    ProductAccumulator {
        output_column_ordinal: u32,
    },
}

impl AuxiliaryColumnSynthesisTask {
    fn input_column_ordinals(&self) -> Vec<u32> {
        let input = match self {
            Self::BeginComponent | Self::ProductAccumulator { .. } => Vec::new(),
            Self::NegacyclicAutomorphismPermutation { descriptor, .. } => vec![
                descriptor.source_low_column_ordinal,
                descriptor.source_high_column_ordinal,
                descriptor.target_low_column_ordinal,
                descriptor.target_high_column_ordinal,
                descriptor.mapped_low_position_column_ordinal,
                descriptor.low_negation_bit_column_ordinal,
                descriptor.mapped_high_position_column_ordinal,
                descriptor.high_negation_bit_column_ordinal,
                descriptor.target_low_position_column_ordinal,
                descriptor.target_high_position_column_ordinal,
            ],
            Self::PrefixEvaluation {
                source_column_ordinal,
                ..
            }
            | Self::SuffixEvaluation {
                source_column_ordinal,
                ..
            } => vec![*source_column_ordinal],
            Self::ConvolutionProduct { descriptor, .. } => vec![
                descriptor.multiplicand_column_ordinal,
                descriptor.reversed_multiplier_column_ordinal,
            ],
            Self::FullRingProduct { descriptor, .. } => vec![
                descriptor.multiplicand_low_column_ordinal,
                descriptor.multiplicand_high_column_ordinal,
                descriptor.reversed_multiplier_low_column_ordinal,
                descriptor.reversed_multiplier_high_column_ordinal,
            ],
            Self::LinearEvaluation { descriptor, .. } => descriptor
                .ordered_linear_terms
                .iter()
                .map(|term| term.column_ordinal)
                .collect(),
        };
        let mut seen = BTreeSet::new();
        input
            .into_iter()
            .filter(|column_ordinal| seen.insert(*column_ordinal))
            .collect()
    }

    fn output_column_ordinals(&self) -> Vec<u32> {
        match self {
            Self::BeginComponent => Vec::new(),
            Self::NegacyclicAutomorphismPermutation { descriptor, .. } => vec![
                descriptor.source_product_before_column_ordinal,
                descriptor.source_low_product_column_ordinal,
                descriptor.target_product_before_column_ordinal,
                descriptor.target_low_product_column_ordinal,
            ],
            Self::PrefixEvaluation {
                output_column_ordinal,
                ..
            }
            | Self::SuffixEvaluation {
                output_column_ordinal,
                ..
            }
            | Self::ProductAccumulator {
                output_column_ordinal,
            } => vec![*output_column_ordinal],
            Self::ConvolutionProduct { descriptor, .. } => vec![
                descriptor.suffix_evaluation_column_ordinal,
                descriptor.reversed_transpose_column_ordinal,
            ],
            Self::FullRingProduct { descriptor, .. } => vec![
                descriptor.multiplicand_low_suffix_evaluation_column_ordinal,
                descriptor.multiplicand_high_suffix_evaluation_column_ordinal,
                descriptor.reversed_multiplier_low_transpose_column_ordinal,
                descriptor.reversed_multiplier_high_transpose_column_ordinal,
            ],
            Self::LinearEvaluation { descriptor, .. } => {
                vec![descriptor.linear_evaluation_column_ordinal]
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofAuxiliaryMaterializationLiveness {
    maximum_synthesis_live_trace_row_count: usize,
    maximum_recomputation_live_trace_row_count: usize,
    maximum_private_mask_coefficient_count: usize,
}

impl CommonProofAuxiliaryMaterializationLiveness {
    pub(crate) const fn maximum_synthesis_live_trace_row_count(self) -> usize {
        self.maximum_synthesis_live_trace_row_count
    }

    pub(crate) const fn maximum_recomputation_live_trace_row_count(self) -> usize {
        self.maximum_recomputation_live_trace_row_count
    }

    pub(crate) const fn maximum_private_mask_coefficient_count(self) -> usize {
        self.maximum_private_mask_coefficient_count
    }
}

/// Derives the exact descriptor-local row multiplicities owned by auxiliary
/// synthesis and later reconstruction. The returned counts include input
/// rows, persistent component accumulators, output rows, and task-local
/// transpose or suffix buffers. They deliberately exclude the independently
/// accounted source-provider and external-memory transfer buffers.
pub(crate) fn common_proof_auxiliary_materialization_liveness(
    variant: &RelationPlanVariant,
) -> Result<CommonProofAuxiliaryMaterializationLiveness, CommonProofProverError> {
    let mut maximum_synthesis_live_trace_row_count = 0_usize;
    for batch in variant.ordered_integer_lift_batches() {
        if !batch
            .ordered_negacyclic_automorphism_permutations
            .is_empty()
        {
            maximum_synthesis_live_trace_row_count = maximum_synthesis_live_trace_row_count.max(14);
        }
        if !batch.ordered_reversed_column_bindings.is_empty() {
            maximum_synthesis_live_trace_row_count = maximum_synthesis_live_trace_row_count.max(2);
        }
        for component in &batch.ordered_components {
            maximum_synthesis_live_trace_row_count = maximum_synthesis_live_trace_row_count.max(1);
            if !component.ordered_convolution_products.is_empty() {
                maximum_synthesis_live_trace_row_count =
                    maximum_synthesis_live_trace_row_count.max(5);
            }
            if !component.ordered_full_ring_negacyclic_products.is_empty() {
                maximum_synthesis_live_trace_row_count =
                    maximum_synthesis_live_trace_row_count.max(9);
            }
            let linear_input_count = unique_column_ordinals(
                component
                    .ordered_linear_terms
                    .iter()
                    .map(|term| term.column_ordinal),
            )
            .len();
            maximum_synthesis_live_trace_row_count = maximum_synthesis_live_trace_row_count.max(
                linear_input_count
                    .checked_add(3)
                    .ok_or(CommonProofProverError::CountOverflow)?,
            );
            maximum_synthesis_live_trace_row_count = maximum_synthesis_live_trace_row_count.max(2);
        }
    }

    let catalog = CommonProofAuxiliaryColumnReconstructionCatalog::new(variant)?;
    let mut maximum_recomputation_live_trace_row_count = 0_usize;
    let mut maximum_private_mask_coefficient_count = 0_usize;
    for target_column_ordinal in catalog.ordered_column_ordinals() {
        let locator = catalog.locator(target_column_ordinal)?;
        let input_count = auxiliary_reconstruction_input_column_ordinals(variant, locator)?.len();
        let task_local_row_count = match locator.kind {
            AuxiliaryColumnReconstructionKind::NegacyclicAutomorphismPermutation { .. } => 4,
            AuxiliaryColumnReconstructionKind::ReversedBindingPrefix { .. }
            | AuxiliaryColumnReconstructionKind::ReversedBindingSuffix { .. }
            | AuxiliaryColumnReconstructionKind::ConvolutionSuffix { .. }
            | AuxiliaryColumnReconstructionKind::FullRingSuffix { .. } => 1,
            AuxiliaryColumnReconstructionKind::ConvolutionTranspose { .. } => 2,
            AuxiliaryColumnReconstructionKind::FullRingTranspose { .. } => 3,
            AuxiliaryColumnReconstructionKind::LinearEvaluation { .. } => 2,
            AuxiliaryColumnReconstructionKind::ProductAccumulator { .. } => 5,
        };
        let reconstruction_row_count = input_count
            .checked_add(task_local_row_count)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let resize_row_count = input_count
            .checked_add(2)
            .ok_or(CommonProofProverError::CountOverflow)?;
        maximum_recomputation_live_trace_row_count = maximum_recomputation_live_trace_row_count
            .max(reconstruction_row_count)
            .max(resize_row_count);
        maximum_private_mask_coefficient_count = maximum_private_mask_coefficient_count.max(
            relation_private_mask_tail_coefficient_count(variant, target_column_ordinal)?
                .unwrap_or_default(),
        );
    }

    Ok(CommonProofAuxiliaryMaterializationLiveness {
        maximum_synthesis_live_trace_row_count,
        maximum_recomputation_live_trace_row_count,
        maximum_private_mask_coefficient_count,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuxiliaryColumnReconstructionKind {
    NegacyclicAutomorphismPermutation {
        permutation_index: usize,
        output_index: u8,
    },
    ReversedBindingPrefix {
        binding_index: usize,
    },
    ReversedBindingSuffix {
        binding_index: usize,
    },
    ConvolutionSuffix {
        component_index: usize,
        product_index: usize,
    },
    ConvolutionTranspose {
        component_index: usize,
        product_index: usize,
    },
    FullRingSuffix {
        component_index: usize,
        product_index: usize,
        high_half: bool,
    },
    FullRingTranspose {
        component_index: usize,
        product_index: usize,
        high_coordinate: bool,
    },
    LinearEvaluation {
        component_index: usize,
    },
    ProductAccumulator {
        component_index: usize,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AuxiliaryColumnReconstructionLocator {
    batch_index: usize,
    kind: AuxiliaryColumnReconstructionKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum AuxiliaryColumnReconstructionDependency {
    Unique,
    FullRingSuffix {
        batch_key: (SuiteModulusReference, u16),
        source_column_ordinal: u32,
    },
    FullRingTranspose {
        batch_key: (SuiteModulusReference, u16),
        selected_half: RelationIntegerLiftFullRingHalf,
        multiplicand_columns: [u32; 2],
        low_coordinate: bool,
    },
    LinearEvaluation {
        batch_key: (SuiteModulusReference, u16),
        ordered_terms: Vec<RelationIntegerLiftLinearTermDescriptor>,
    },
    ProductAccumulator {
        batch_key: (SuiteModulusReference, u16),
        ordered_convolution_products: Vec<RelationIntegerLiftConvolutionProductDescriptor>,
        ordered_full_ring_products: Vec<RelationIntegerLiftFullRingNegacyclicProductDescriptor>,
    },
}

impl AuxiliaryColumnReconstructionDependency {
    const fn is_shareable(&self) -> bool {
        !matches!(self, Self::Unique)
    }
}

/// Compact, checked locators for reconstructing challenge-derived auxiliary
/// columns from their persisted pre-challenge dependencies. The catalog owns
/// no witness rows and does not contain private mask material.
#[derive(Clone)]
pub(crate) struct CommonProofAuxiliaryColumnReconstructionCatalog {
    locators: BTreeMap<u32, AuxiliaryColumnReconstructionLocator>,
}

impl CommonProofAuxiliaryColumnReconstructionCatalog {
    pub(crate) fn new(variant: &RelationPlanVariant) -> Result<Self, CommonProofProverError> {
        let (_, expected_auxiliary_columns) = integer_lift_derived_columns(variant)?;
        let mut locators = BTreeMap::new();
        let mut dependencies = BTreeMap::new();
        let mut register = |column_ordinal,
                            locator,
                            dependency: AuxiliaryColumnReconstructionDependency|
         -> Result<(), CommonProofProverError> {
            match dependencies.get(&column_ordinal) {
                None => {
                    dependencies.insert(column_ordinal, dependency);
                    if locators.insert(column_ordinal, locator).is_some() {
                        return Err(CommonProofProverError::InvalidColumn);
                    }
                }
                Some(observed) if dependency.is_shareable() && observed == &dependency => {}
                Some(_) => return Err(CommonProofProverError::InvalidColumn),
            }
            Ok(())
        };

        for (batch_index, batch) in variant.ordered_integer_lift_batches().iter().enumerate() {
            let batch_key = (batch.modulus_reference(), batch.challenge_ordinal());
            for (permutation_index, descriptor) in batch
                .ordered_negacyclic_automorphism_permutations
                .iter()
                .enumerate()
            {
                for (output_index, column_ordinal) in [
                    descriptor.source_product_before_column_ordinal,
                    descriptor.source_low_product_column_ordinal,
                    descriptor.target_product_before_column_ordinal,
                    descriptor.target_low_product_column_ordinal,
                ]
                .into_iter()
                .enumerate()
                {
                    register(
                        column_ordinal,
                        AuxiliaryColumnReconstructionLocator {
                            batch_index,
                            kind: AuxiliaryColumnReconstructionKind::NegacyclicAutomorphismPermutation {
                                permutation_index,
                                output_index: u8::try_from(output_index)
                                    .map_err(|_| CommonProofProverError::CountOverflow)?,
                            },
                        },
                        AuxiliaryColumnReconstructionDependency::Unique,
                    )?;
                }
            }
            for (binding_index, binding) in
                batch.ordered_reversed_column_bindings.iter().enumerate()
            {
                register(
                    binding.source_prefix_evaluation_column_ordinal,
                    AuxiliaryColumnReconstructionLocator {
                        batch_index,
                        kind: AuxiliaryColumnReconstructionKind::ReversedBindingPrefix {
                            binding_index,
                        },
                    },
                    AuxiliaryColumnReconstructionDependency::Unique,
                )?;
                register(
                    binding.reversed_suffix_evaluation_column_ordinal,
                    AuxiliaryColumnReconstructionLocator {
                        batch_index,
                        kind: AuxiliaryColumnReconstructionKind::ReversedBindingSuffix {
                            binding_index,
                        },
                    },
                    AuxiliaryColumnReconstructionDependency::Unique,
                )?;
            }
            for (component_index, component) in batch.ordered_components.iter().enumerate() {
                for (product_index, descriptor) in
                    component.ordered_convolution_products.iter().enumerate()
                {
                    for (column_ordinal, kind) in [
                        (
                            descriptor.suffix_evaluation_column_ordinal,
                            AuxiliaryColumnReconstructionKind::ConvolutionSuffix {
                                component_index,
                                product_index,
                            },
                        ),
                        (
                            descriptor.reversed_transpose_column_ordinal,
                            AuxiliaryColumnReconstructionKind::ConvolutionTranspose {
                                component_index,
                                product_index,
                            },
                        ),
                    ] {
                        register(
                            column_ordinal,
                            AuxiliaryColumnReconstructionLocator { batch_index, kind },
                            AuxiliaryColumnReconstructionDependency::Unique,
                        )?;
                    }
                }
                for (product_index, descriptor) in component
                    .ordered_full_ring_negacyclic_products
                    .iter()
                    .enumerate()
                {
                    for (column_ordinal, high_half, source_column_ordinal) in [
                        (
                            descriptor.multiplicand_low_suffix_evaluation_column_ordinal,
                            false,
                            descriptor.multiplicand_low_column_ordinal,
                        ),
                        (
                            descriptor.multiplicand_high_suffix_evaluation_column_ordinal,
                            true,
                            descriptor.multiplicand_high_column_ordinal,
                        ),
                    ] {
                        register(
                            column_ordinal,
                            AuxiliaryColumnReconstructionLocator {
                                batch_index,
                                kind: AuxiliaryColumnReconstructionKind::FullRingSuffix {
                                    component_index,
                                    product_index,
                                    high_half,
                                },
                            },
                            AuxiliaryColumnReconstructionDependency::FullRingSuffix {
                                batch_key,
                                source_column_ordinal,
                            },
                        )?;
                    }
                    for (column_ordinal, high_coordinate) in [
                        (
                            descriptor.reversed_multiplier_low_transpose_column_ordinal,
                            false,
                        ),
                        (
                            descriptor.reversed_multiplier_high_transpose_column_ordinal,
                            true,
                        ),
                    ] {
                        register(
                            column_ordinal,
                            AuxiliaryColumnReconstructionLocator {
                                batch_index,
                                kind: AuxiliaryColumnReconstructionKind::FullRingTranspose {
                                    component_index,
                                    product_index,
                                    high_coordinate,
                                },
                            },
                            AuxiliaryColumnReconstructionDependency::FullRingTranspose {
                                batch_key,
                                selected_half: descriptor.selected_half,
                                multiplicand_columns: [
                                    descriptor.multiplicand_low_column_ordinal,
                                    descriptor.multiplicand_high_column_ordinal,
                                ],
                                low_coordinate: !high_coordinate,
                            },
                        )?;
                    }
                }
                register(
                    component.linear_evaluation_column_ordinal,
                    AuxiliaryColumnReconstructionLocator {
                        batch_index,
                        kind: AuxiliaryColumnReconstructionKind::LinearEvaluation {
                            component_index,
                        },
                    },
                    AuxiliaryColumnReconstructionDependency::LinearEvaluation {
                        batch_key,
                        ordered_terms: component.ordered_linear_terms.clone(),
                    },
                )?;
                register(
                    component.product_accumulator_column_ordinal,
                    AuxiliaryColumnReconstructionLocator {
                        batch_index,
                        kind: AuxiliaryColumnReconstructionKind::ProductAccumulator {
                            component_index,
                        },
                    },
                    AuxiliaryColumnReconstructionDependency::ProductAccumulator {
                        batch_key,
                        ordered_convolution_products: component
                            .ordered_convolution_products
                            .clone(),
                        ordered_full_ring_products: component
                            .ordered_full_ring_negacyclic_products
                            .clone(),
                    },
                )?;
            }
        }
        if locators.keys().copied().collect::<BTreeSet<_>>() != expected_auxiliary_columns
            || dependencies.keys().copied().collect::<BTreeSet<_>>() != expected_auxiliary_columns
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        Ok(Self { locators })
    }

    pub(crate) fn contains(&self, column_ordinal: u32) -> bool {
        self.locators.contains_key(&column_ordinal)
    }

    pub(crate) fn ordered_column_ordinals(&self) -> impl Iterator<Item = u32> + '_ {
        self.locators.keys().copied()
    }

    pub(crate) fn resident_owned_payload_byte_length(&self) -> Result<u64, CommonProofProverError> {
        const BTREE_ENTRY_LINK_WORD_COUNT: u64 = 6;
        let entry_byte_length = u64::try_from(core::mem::size_of::<(
            u32,
            AuxiliaryColumnReconstructionLocator,
        )>())
        .map_err(|_| CommonProofProverError::CountOverflow)?
        .checked_add(
            BTREE_ENTRY_LINK_WORD_COUNT
                .checked_mul(
                    u64::try_from(core::mem::size_of::<usize>())
                        .map_err(|_| CommonProofProverError::CountOverflow)?,
                )
                .ok_or(CommonProofProverError::CountOverflow)?,
        )
        .ok_or(CommonProofProverError::CountOverflow)?;
        u64::try_from(self.locators.len())
            .ok()
            .and_then(|count| count.checked_mul(entry_byte_length))
            .ok_or(CommonProofProverError::CountOverflow)
    }

    fn locator(
        &self,
        column_ordinal: u32,
    ) -> Result<AuxiliaryColumnReconstructionLocator, CommonProofProverError> {
        self.locators
            .get(&column_ordinal)
            .copied()
            .ok_or(CommonProofProverError::InvalidColumn)
    }
}

fn reconstruction_component(
    variant: &RelationPlanVariant,
    locator: AuxiliaryColumnReconstructionLocator,
    component_index: usize,
) -> Result<&RelationIntegerLiftComponentDescriptor, CommonProofProverError> {
    variant
        .ordered_integer_lift_batches()
        .get(locator.batch_index)
        .and_then(|batch| batch.ordered_components.get(component_index))
        .ok_or(CommonProofProverError::InvalidColumn)
}

fn unique_column_ordinals(columns: impl IntoIterator<Item = u32>) -> Vec<u32> {
    let mut observed = BTreeSet::new();
    columns
        .into_iter()
        .filter(|column_ordinal| observed.insert(*column_ordinal))
        .collect()
}

fn auxiliary_reconstruction_input_column_ordinals(
    variant: &RelationPlanVariant,
    locator: AuxiliaryColumnReconstructionLocator,
) -> Result<Vec<u32>, CommonProofProverError> {
    let batch = variant
        .ordered_integer_lift_batches()
        .get(locator.batch_index)
        .ok_or(CommonProofProverError::InvalidColumn)?;
    let columns = match locator.kind {
        AuxiliaryColumnReconstructionKind::NegacyclicAutomorphismPermutation {
            permutation_index,
            ..
        } => {
            let descriptor = batch
                .ordered_negacyclic_automorphism_permutations
                .get(permutation_index)
                .ok_or(CommonProofProverError::InvalidColumn)?;
            vec![
                descriptor.source_low_column_ordinal,
                descriptor.source_high_column_ordinal,
                descriptor.target_low_column_ordinal,
                descriptor.target_high_column_ordinal,
                descriptor.mapped_low_position_column_ordinal,
                descriptor.low_negation_bit_column_ordinal,
                descriptor.mapped_high_position_column_ordinal,
                descriptor.high_negation_bit_column_ordinal,
                descriptor.target_low_position_column_ordinal,
                descriptor.target_high_position_column_ordinal,
            ]
        }
        AuxiliaryColumnReconstructionKind::ReversedBindingPrefix { binding_index } => {
            vec![
                batch
                    .ordered_reversed_column_bindings
                    .get(binding_index)
                    .ok_or(CommonProofProverError::InvalidColumn)?
                    .source_column_ordinal,
            ]
        }
        AuxiliaryColumnReconstructionKind::ReversedBindingSuffix { binding_index } => {
            vec![
                batch
                    .ordered_reversed_column_bindings
                    .get(binding_index)
                    .ok_or(CommonProofProverError::InvalidColumn)?
                    .reversed_column_ordinal,
            ]
        }
        AuxiliaryColumnReconstructionKind::ConvolutionSuffix {
            component_index,
            product_index,
        }
        | AuxiliaryColumnReconstructionKind::ConvolutionTranspose {
            component_index,
            product_index,
        } => vec![
            reconstruction_component(variant, locator, component_index)?
                .ordered_convolution_products
                .get(product_index)
                .ok_or(CommonProofProverError::InvalidColumn)?
                .multiplicand_column_ordinal,
        ],
        AuxiliaryColumnReconstructionKind::FullRingSuffix {
            component_index,
            product_index,
            high_half,
        } => {
            let descriptor = reconstruction_component(variant, locator, component_index)?
                .ordered_full_ring_negacyclic_products
                .get(product_index)
                .ok_or(CommonProofProverError::InvalidColumn)?;
            vec![if high_half {
                descriptor.multiplicand_high_column_ordinal
            } else {
                descriptor.multiplicand_low_column_ordinal
            }]
        }
        AuxiliaryColumnReconstructionKind::FullRingTranspose {
            component_index,
            product_index,
            ..
        } => {
            let descriptor = reconstruction_component(variant, locator, component_index)?
                .ordered_full_ring_negacyclic_products
                .get(product_index)
                .ok_or(CommonProofProverError::InvalidColumn)?;
            vec![
                descriptor.multiplicand_low_column_ordinal,
                descriptor.multiplicand_high_column_ordinal,
            ]
        }
        AuxiliaryColumnReconstructionKind::LinearEvaluation { component_index } => {
            reconstruction_component(variant, locator, component_index)?
                .ordered_linear_terms
                .iter()
                .map(|term| term.column_ordinal)
                .collect()
        }
        AuxiliaryColumnReconstructionKind::ProductAccumulator { component_index } => {
            let component = reconstruction_component(variant, locator, component_index)?;
            component
                .ordered_convolution_products
                .iter()
                .flat_map(|product| {
                    [
                        product.multiplicand_column_ordinal,
                        product.reversed_multiplier_column_ordinal,
                    ]
                })
                .chain(
                    component
                        .ordered_full_ring_negacyclic_products
                        .iter()
                        .flat_map(|product| {
                            [
                                product.multiplicand_low_column_ordinal,
                                product.multiplicand_high_column_ordinal,
                                product.reversed_multiplier_low_column_ordinal,
                                product.reversed_multiplier_high_column_ordinal,
                            ]
                        }),
                )
                .collect()
        }
    };
    Ok(unique_column_ordinals(columns))
}

#[derive(Clone)]
enum AuxiliaryColumnReconstructionProgram {
    NegacyclicAutomorphismPermutation {
        descriptor: RelationIntegerLiftNegacyclicAutomorphismPermutationDescriptor,
        output_index: u8,
        theta: ProofBaseFieldElement,
    },
    PrefixEvaluation {
        source_column_ordinal: u32,
        theta: ProofBaseFieldElement,
    },
    SuffixEvaluation {
        source_column_ordinal: u32,
        theta: ProofBaseFieldElement,
    },
    ConvolutionTranspose {
        descriptor: RelationIntegerLiftConvolutionProductDescriptor,
        theta: ProofBaseFieldElement,
    },
    FullRingTranspose {
        descriptor: RelationIntegerLiftFullRingNegacyclicProductDescriptor,
        high_coordinate: bool,
        theta: ProofBaseFieldElement,
    },
    LinearEvaluation {
        descriptor: RelationIntegerLiftComponentDescriptor,
        theta: ProofBaseFieldElement,
    },
    ProductAccumulator {
        descriptor: RelationIntegerLiftComponentDescriptor,
        theta: ProofBaseFieldElement,
    },
}

fn auxiliary_reconstruction_program(
    variant: &RelationPlanVariant,
    context: &RelationPlanCheckContext,
    assignments: &[RelationApplicationChallengeAssignment],
    locator: AuxiliaryColumnReconstructionLocator,
) -> Result<AuxiliaryColumnReconstructionProgram, CommonProofProverError> {
    let batch = variant
        .ordered_integer_lift_batches()
        .get(locator.batch_index)
        .ok_or(CommonProofProverError::InvalidColumn)?;
    let theta = integer_lift_theta(
        variant,
        context,
        batch.modulus_reference(),
        batch.challenge_ordinal(),
        assignments,
    )?;
    match locator.kind {
        AuxiliaryColumnReconstructionKind::NegacyclicAutomorphismPermutation {
            permutation_index,
            output_index,
        } => Ok(
            AuxiliaryColumnReconstructionProgram::NegacyclicAutomorphismPermutation {
                descriptor: batch
                    .ordered_negacyclic_automorphism_permutations
                    .get(permutation_index)
                    .cloned()
                    .ok_or(CommonProofProverError::InvalidColumn)?,
                output_index,
                theta,
            },
        ),
        AuxiliaryColumnReconstructionKind::ReversedBindingPrefix { binding_index } => {
            Ok(AuxiliaryColumnReconstructionProgram::PrefixEvaluation {
                source_column_ordinal: batch
                    .ordered_reversed_column_bindings
                    .get(binding_index)
                    .ok_or(CommonProofProverError::InvalidColumn)?
                    .source_column_ordinal,
                theta,
            })
        }
        AuxiliaryColumnReconstructionKind::ReversedBindingSuffix { binding_index } => {
            Ok(AuxiliaryColumnReconstructionProgram::SuffixEvaluation {
                source_column_ordinal: batch
                    .ordered_reversed_column_bindings
                    .get(binding_index)
                    .ok_or(CommonProofProverError::InvalidColumn)?
                    .reversed_column_ordinal,
                theta,
            })
        }
        AuxiliaryColumnReconstructionKind::ConvolutionSuffix {
            component_index,
            product_index,
        } => Ok(AuxiliaryColumnReconstructionProgram::SuffixEvaluation {
            source_column_ordinal: reconstruction_component(variant, locator, component_index)?
                .ordered_convolution_products
                .get(product_index)
                .ok_or(CommonProofProverError::InvalidColumn)?
                .multiplicand_column_ordinal,
            theta,
        }),
        AuxiliaryColumnReconstructionKind::ConvolutionTranspose {
            component_index,
            product_index,
        } => Ok(AuxiliaryColumnReconstructionProgram::ConvolutionTranspose {
            descriptor: reconstruction_component(variant, locator, component_index)?
                .ordered_convolution_products
                .get(product_index)
                .cloned()
                .ok_or(CommonProofProverError::InvalidColumn)?,
            theta,
        }),
        AuxiliaryColumnReconstructionKind::FullRingSuffix {
            component_index,
            product_index,
            high_half,
        } => {
            let descriptor = reconstruction_component(variant, locator, component_index)?
                .ordered_full_ring_negacyclic_products
                .get(product_index)
                .ok_or(CommonProofProverError::InvalidColumn)?;
            Ok(AuxiliaryColumnReconstructionProgram::SuffixEvaluation {
                source_column_ordinal: if high_half {
                    descriptor.multiplicand_high_column_ordinal
                } else {
                    descriptor.multiplicand_low_column_ordinal
                },
                theta,
            })
        }
        AuxiliaryColumnReconstructionKind::FullRingTranspose {
            component_index,
            product_index,
            high_coordinate,
        } => Ok(AuxiliaryColumnReconstructionProgram::FullRingTranspose {
            descriptor: reconstruction_component(variant, locator, component_index)?
                .ordered_full_ring_negacyclic_products
                .get(product_index)
                .cloned()
                .ok_or(CommonProofProverError::InvalidColumn)?,
            high_coordinate,
            theta,
        }),
        AuxiliaryColumnReconstructionKind::LinearEvaluation { component_index } => {
            Ok(AuxiliaryColumnReconstructionProgram::LinearEvaluation {
                descriptor: reconstruction_component(variant, locator, component_index)?.clone(),
                theta,
            })
        }
        AuxiliaryColumnReconstructionKind::ProductAccumulator { component_index } => {
            Ok(AuxiliaryColumnReconstructionProgram::ProductAccumulator {
                descriptor: reconstruction_component(variant, locator, component_index)?.clone(),
                theta,
            })
        }
    }
}

pub(crate) fn relation_private_mask_tail_coefficient_count(
    variant: &RelationPlanVariant,
    column_ordinal: u32,
) -> Result<Option<usize>, CommonProofProverError> {
    let descriptor = variant
        .ordered_columns()
        .get(usize::try_from(column_ordinal).map_err(|_| CommonProofProverError::CountOverflow)?)
        .ok_or(CommonProofProverError::InvalidColumn)?;
    let masks = trace_masks_by_column(variant)?;
    let mask = masks.get(&column_ordinal).copied();
    match (variant.proof_privacy_mode(), descriptor.origin(), mask) {
        (ProofPrivacyMode::SecretBearing, RelationColumnOrigin::Prover, Some(mask)) => {
            usize::try_from(mask.mask_degree_bound_exclusive())
                .map(Some)
                .map_err(|_| CommonProofProverError::CountOverflow)
        }
        (ProofPrivacyMode::SecretBearing, RelationColumnOrigin::Prover, None) => {
            Err(CommonProofProverError::InvalidMask)
        }
        (ProofPrivacyMode::SecretBearing, _, None) | (ProofPrivacyMode::PublicOnly, _, None) => {
            Ok(None)
        }
        _ => Err(CommonProofProverError::InvalidMask),
    }
}

/// Reconstructs one auxiliary column from checked pre-challenge inputs and the
/// exact mask coefficients replayed by private randomness custody. The trace
/// rows determine the unmasked witness; the private coefficients restore
/// `witness + (X^H - 1) mask` without deriving mask material from public data.
pub(crate) struct CommonProofAuxiliaryColumnReconstructionCursor {
    program: AuxiliaryColumnReconstructionProgram,
    ordered_input_column_ordinals: Vec<u32>,
    next_input_index: usize,
    input_trace_rows: BTreeMap<u32, ProtectedBaseTraceRows>,
    trace_domain: ProofEvaluationDomain,
    relation_context: RelationPlanCheckContext,
    mask_coefficient_count: usize,
}

impl CommonProofAuxiliaryColumnReconstructionCursor {
    pub(crate) fn new(
        variant: &RelationPlanVariant,
        relation_context: &RelationPlanCheckContext,
        application_challenges: &[RelationApplicationChallengeAssignment],
        catalog: &CommonProofAuxiliaryColumnReconstructionCatalog,
        target_column_ordinal: u32,
    ) -> Result<Self, CommonProofProverError> {
        let locator = catalog.locator(target_column_ordinal)?;
        let ordered_input_column_ordinals =
            auxiliary_reconstruction_input_column_ordinals(variant, locator)?;
        let program = auxiliary_reconstruction_program(
            variant,
            relation_context,
            application_challenges,
            locator,
        )?;
        let trace_domain = ProofEvaluationDomain::new_subgroup(
            usize::try_from(variant.trace_domain_size())
                .map_err(|_| CommonProofProverError::CountOverflow)?,
        )?;
        let mask_coefficient_count =
            relation_private_mask_tail_coefficient_count(variant, target_column_ordinal)?
                .unwrap_or_default();
        Ok(Self {
            program,
            ordered_input_column_ordinals,
            next_input_index: 0,
            input_trace_rows: BTreeMap::new(),
            trace_domain,
            relation_context: relation_context.clone(),
            mask_coefficient_count,
        })
    }

    pub(crate) fn ordered_input_column_ordinals(&self) -> &[u32] {
        &self.ordered_input_column_ordinals
    }

    pub(crate) const fn mask_coefficient_count(&self) -> usize {
        self.mask_coefficient_count
    }

    pub(crate) fn next_input_column_ordinal(&self) -> Option<u32> {
        self.ordered_input_column_ordinals
            .get(self.next_input_index)
            .copied()
    }

    pub(crate) fn accept_input_column(
        &mut self,
        column_ordinal: u32,
        polynomial: CommonProofSourcePolynomial,
    ) -> Result<(), CommonProofProverError> {
        if self.next_input_column_ordinal() != Some(column_ordinal) {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let rows = base_trace_rows(&polynomial, self.trace_domain)?;
        if self.input_trace_rows.insert(column_ordinal, rows).is_some() {
            return Err(CommonProofProverError::InvalidColumn);
        }
        self.next_input_index = self
            .next_input_index
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
        Ok(())
    }

    fn rows(
        &self,
        column_ordinal: u32,
    ) -> Result<&[ProofBaseFieldElement], CommonProofProverError> {
        self.input_trace_rows
            .get(&column_ordinal)
            .filter(|rows| rows.len() == self.trace_domain.size())
            .map(|rows| rows.as_slice())
            .ok_or(CommonProofProverError::InvalidColumn)
    }

    fn reconstruct_rows(&self) -> Result<ProtectedBaseTraceRows, CommonProofProverError> {
        if self.next_input_index != self.ordered_input_column_ordinals.len()
            || self.input_trace_rows.len() != self.ordered_input_column_ordinals.len()
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        match &self.program {
            AuxiliaryColumnReconstructionProgram::PrefixEvaluation {
                source_column_ordinal,
                theta,
            } => Ok(prefix_evaluation_rows(
                self.rows(*source_column_ordinal)?,
                *theta,
            )),
            AuxiliaryColumnReconstructionProgram::SuffixEvaluation {
                source_column_ordinal,
                theta,
            } => Ok(suffix_evaluation_rows(
                self.rows(*source_column_ordinal)?,
                *theta,
            )),
            AuxiliaryColumnReconstructionProgram::ConvolutionTranspose { descriptor, theta } => {
                let multiplicand_rows = self.rows(descriptor.multiplicand_column_ordinal)?;
                let suffix_rows = suffix_evaluation_rows(multiplicand_rows, *theta);
                convolution_transpose_rows(
                    descriptor.convolution_kind,
                    multiplicand_rows,
                    &suffix_rows,
                    *theta,
                )
            }
            AuxiliaryColumnReconstructionProgram::FullRingTranspose {
                descriptor,
                high_coordinate,
                theta,
            } => {
                let low_rows = self.rows(descriptor.multiplicand_low_column_ordinal)?;
                let high_rows = self.rows(descriptor.multiplicand_high_column_ordinal)?;
                let low_suffix_rows = suffix_evaluation_rows(low_rows, *theta);
                let high_suffix_rows = suffix_evaluation_rows(high_rows, *theta);
                full_ring_transpose_rows(
                    descriptor.selected_half,
                    !*high_coordinate,
                    low_rows,
                    high_rows,
                    &low_suffix_rows,
                    &high_suffix_rows,
                    *theta,
                )
            }
            AuxiliaryColumnReconstructionProgram::LinearEvaluation { descriptor, theta } => {
                let mut coefficient_rows =
                    Zeroizing::new(vec![ProofBaseFieldElement::ZERO; self.trace_domain.size()]);
                for (row_ordinal, coefficient) in coefficient_rows.iter_mut().enumerate() {
                    for term in &descriptor.ordered_linear_terms {
                        *coefficient = coefficient.add(signed_linear_term_row(
                            term,
                            row_ordinal,
                            &self.relation_context,
                            &self.input_trace_rows,
                        )?);
                    }
                }
                Ok(suffix_evaluation_rows(&coefficient_rows, *theta))
            }
            AuxiliaryColumnReconstructionProgram::ProductAccumulator { descriptor, theta } => {
                let mut product_sum_rows =
                    Zeroizing::new(vec![ProofBaseFieldElement::ZERO; self.trace_domain.size()]);
                for product in &descriptor.ordered_convolution_products {
                    let multiplicand_rows = self.rows(product.multiplicand_column_ordinal)?;
                    let reversed_rows = self.rows(product.reversed_multiplier_column_ordinal)?;
                    let suffix_rows = suffix_evaluation_rows(multiplicand_rows, *theta);
                    let transpose_rows = convolution_transpose_rows(
                        product.convolution_kind,
                        multiplicand_rows,
                        &suffix_rows,
                        *theta,
                    )?;
                    let offset = base_field_constant(product.multiplier_offset)?;
                    for row_ordinal in 0..self.trace_domain.size() {
                        let value = transpose_rows[row_ordinal]
                            .multiply(reversed_rows[row_ordinal].subtract(offset));
                        product_sum_rows[row_ordinal] =
                            product_sum_rows[row_ordinal].add(if product.negative {
                                value.negate()
                            } else {
                                value
                            });
                    }
                }
                for product in &descriptor.ordered_full_ring_negacyclic_products {
                    let low_rows = self.rows(product.multiplicand_low_column_ordinal)?;
                    let high_rows = self.rows(product.multiplicand_high_column_ordinal)?;
                    let reversed_low_rows =
                        self.rows(product.reversed_multiplier_low_column_ordinal)?;
                    let reversed_high_rows =
                        self.rows(product.reversed_multiplier_high_column_ordinal)?;
                    let low_suffix_rows = suffix_evaluation_rows(low_rows, *theta);
                    let high_suffix_rows = suffix_evaluation_rows(high_rows, *theta);
                    let low_transpose_rows = full_ring_transpose_rows(
                        product.selected_half,
                        true,
                        low_rows,
                        high_rows,
                        &low_suffix_rows,
                        &high_suffix_rows,
                        *theta,
                    )?;
                    let high_transpose_rows = full_ring_transpose_rows(
                        product.selected_half,
                        false,
                        low_rows,
                        high_rows,
                        &low_suffix_rows,
                        &high_suffix_rows,
                        *theta,
                    )?;
                    let low_offset = base_field_constant(product.multiplier_low_offset)?;
                    let high_offset = base_field_constant(product.multiplier_high_offset)?;
                    for row_ordinal in 0..self.trace_domain.size() {
                        let value =
                            low_transpose_rows[row_ordinal]
                                .multiply(reversed_low_rows[row_ordinal].subtract(low_offset))
                                .add(high_transpose_rows[row_ordinal].multiply(
                                    reversed_high_rows[row_ordinal].subtract(high_offset),
                                ));
                        product_sum_rows[row_ordinal] =
                            product_sum_rows[row_ordinal].add(if product.negative {
                                value.negate()
                            } else {
                                value
                            });
                    }
                }
                Ok(product_accumulator_rows(&product_sum_rows))
            }
            AuxiliaryColumnReconstructionProgram::NegacyclicAutomorphismPermutation {
                descriptor,
                output_index,
                theta,
            } => {
                let source_low_rows = self.rows(descriptor.source_low_column_ordinal)?;
                let source_high_rows = self.rows(descriptor.source_high_column_ordinal)?;
                let target_low_rows = self.rows(descriptor.target_low_column_ordinal)?;
                let target_high_rows = self.rows(descriptor.target_high_column_ordinal)?;
                let mapped_low_position_rows =
                    self.rows(descriptor.mapped_low_position_column_ordinal)?;
                let low_negation_bit_rows =
                    self.rows(descriptor.low_negation_bit_column_ordinal)?;
                let mapped_high_position_rows =
                    self.rows(descriptor.mapped_high_position_column_ordinal)?;
                let high_negation_bit_rows =
                    self.rows(descriptor.high_negation_bit_column_ordinal)?;
                let target_low_position_rows =
                    self.rows(descriptor.target_low_position_column_ordinal)?;
                let target_high_position_rows =
                    self.rows(descriptor.target_high_position_column_ordinal)?;
                let one = ProofBaseFieldElement::ONE;
                let two = one.add(one);
                let three = two.add(one);
                let encoded_source =
                    |position: ProofBaseFieldElement,
                     negation_bit: ProofBaseFieldElement,
                     value: ProofBaseFieldElement| {
                        position
                            .multiply(three)
                            .add(one)
                            .add(value.subtract(negation_bit.multiply(two).multiply(value)))
                    };
                let encoded_target =
                    |position: ProofBaseFieldElement, value: ProofBaseFieldElement| {
                        position.multiply(three).add(one).add(value)
                    };
                let mut outputs = [
                    Zeroizing::new(Vec::with_capacity(self.trace_domain.size())),
                    Zeroizing::new(Vec::with_capacity(self.trace_domain.size())),
                    Zeroizing::new(Vec::with_capacity(self.trace_domain.size())),
                    Zeroizing::new(Vec::with_capacity(self.trace_domain.size())),
                ];
                let mut source_before = one;
                let mut target_before = one;
                for row_ordinal in 0..self.trace_domain.size() {
                    outputs[0].push(source_before);
                    outputs[2].push(target_before);
                    let source_low_product =
                        source_before.multiply(theta.subtract(encoded_source(
                            mapped_low_position_rows[row_ordinal],
                            low_negation_bit_rows[row_ordinal],
                            source_low_rows[row_ordinal],
                        )));
                    outputs[1].push(source_low_product);
                    let target_low_product =
                        target_before.multiply(theta.subtract(encoded_target(
                            target_low_position_rows[row_ordinal],
                            target_low_rows[row_ordinal],
                        )));
                    outputs[3].push(target_low_product);
                    source_before = source_low_product.multiply(theta.subtract(encoded_source(
                        mapped_high_position_rows[row_ordinal],
                        high_negation_bit_rows[row_ordinal],
                        source_high_rows[row_ordinal],
                    )));
                    target_before = target_low_product.multiply(theta.subtract(encoded_target(
                        target_high_position_rows[row_ordinal],
                        target_high_rows[row_ordinal],
                    )));
                }
                let output_index = usize::from(*output_index);
                if output_index >= outputs.len() {
                    return Err(CommonProofProverError::InvalidColumn);
                }
                Ok(core::mem::take(&mut outputs[output_index]))
            }
        }
    }

    pub(crate) fn finish(
        self,
        mut private_mask_coefficients: Zeroizing<Vec<ProofBaseFieldElement>>,
    ) -> Result<CommonProofSourcePolynomial, CommonProofProverError> {
        if private_mask_coefficients.len() != self.mask_coefficient_count {
            return Err(CommonProofProverError::InvalidMask);
        }
        let mut coefficients = self.reconstruct_rows()?;
        self.trace_domain
            .interpolate_base_polynomial_in_place(&mut coefficients)?;
        if self.mask_coefficient_count == 0 {
            return if private_mask_coefficients.is_empty() {
                Ok(CommonProofSourcePolynomial::from_protected_base_coefficients(coefficients))
            } else {
                Err(CommonProofProverError::InvalidMask)
            };
        }
        let trace_value_count = coefficients.len();
        coefficients
            .try_reserve_exact(self.mask_coefficient_count)
            .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
        coefficients.resize(
            trace_value_count
                .checked_add(self.mask_coefficient_count)
                .ok_or(CommonProofProverError::CountOverflow)?,
            ProofBaseFieldElement::ZERO,
        );
        for (mask_index, mask_coefficient) in private_mask_coefficients.drain(..).enumerate() {
            coefficients[mask_index] = coefficients[mask_index].subtract(mask_coefficient);
            coefficients[trace_value_count + mask_index] = mask_coefficient;
        }
        Ok(CommonProofSourcePolynomial::from_protected_base_coefficients(coefficients))
    }
}

/// Descriptor-local auxiliary synthesis. Persisted relation polynomials are
/// replayed one at a time and immediately reduced to trace rows. The cursor
/// never owns a pre- or post-challenge polynomial catalog; its maximum live
/// row workspace is determined by one checked integer-lift descriptor.
pub(crate) struct CommonProofAuxiliaryColumnSynthesisCursor {
    tasks: Vec<AuxiliaryColumnSynthesisTask>,
    next_task_index: usize,
    next_input_index: usize,
    input_trace_rows: BTreeMap<u32, ProtectedBaseTraceRows>,
    pending_output_rows: Vec<ProtectedAuxiliaryColumnRows>,
    materialized_output_columns: BTreeSet<u32>,
    component_product_sum_rows: Option<ProtectedBaseTraceRows>,
    trace_domain: ProofEvaluationDomain,
    relation_context: RelationPlanCheckContext,
    tree_roles: BTreeMap<u32, ProofTreeRole>,
    trace_masks: BTreeMap<u32, RelationMaskDescriptor>,
}

impl CommonProofAuxiliaryColumnSynthesisCursor {
    pub(crate) fn new(
        variant: &RelationPlanVariant,
        relation_context: &RelationPlanCheckContext,
        application_challenges: &[RelationApplicationChallengeAssignment],
    ) -> Result<Self, CommonProofProverError> {
        let trace_domain = ProofEvaluationDomain::new_subgroup(
            usize::try_from(variant.trace_domain_size())
                .map_err(|_| CommonProofProverError::CountOverflow)?,
        )
        .map_err(CommonProofProverError::from)?;
        let tree_roles = proof_created_tree_roles_by_column(variant)?;
        let trace_masks = trace_masks_by_column(variant)?;
        let (_, expected_auxiliary_columns) = integer_lift_derived_columns(variant)?;
        let mut tasks = Vec::new();
        for batch in variant.ordered_integer_lift_batches() {
            let theta = integer_lift_theta(
                variant,
                relation_context,
                batch.modulus_reference(),
                batch.challenge_ordinal(),
                application_challenges,
            )?;
            for descriptor in &batch.ordered_negacyclic_automorphism_permutations {
                tasks.push(
                    AuxiliaryColumnSynthesisTask::NegacyclicAutomorphismPermutation {
                        descriptor: descriptor.clone(),
                        theta,
                    },
                );
            }
            for binding in &batch.ordered_reversed_column_bindings {
                tasks.push(AuxiliaryColumnSynthesisTask::PrefixEvaluation {
                    source_column_ordinal: binding.source_column_ordinal,
                    output_column_ordinal: binding.source_prefix_evaluation_column_ordinal,
                    theta,
                });
                tasks.push(AuxiliaryColumnSynthesisTask::SuffixEvaluation {
                    source_column_ordinal: binding.reversed_column_ordinal,
                    output_column_ordinal: binding.reversed_suffix_evaluation_column_ordinal,
                    theta,
                });
            }
            for component in &batch.ordered_components {
                tasks.push(AuxiliaryColumnSynthesisTask::BeginComponent);
                for descriptor in &component.ordered_convolution_products {
                    tasks.push(AuxiliaryColumnSynthesisTask::ConvolutionProduct {
                        descriptor: descriptor.clone(),
                        theta,
                    });
                }
                for descriptor in &component.ordered_full_ring_negacyclic_products {
                    tasks.push(AuxiliaryColumnSynthesisTask::FullRingProduct {
                        descriptor: descriptor.clone(),
                        theta,
                    });
                }
                tasks.push(AuxiliaryColumnSynthesisTask::LinearEvaluation {
                    descriptor: component.clone(),
                    theta,
                });
                tasks.push(AuxiliaryColumnSynthesisTask::ProductAccumulator {
                    output_column_ordinal: component.product_accumulator_column_ordinal,
                });
            }
        }
        let mut produced_auxiliary_columns = BTreeSet::new();
        for task in &tasks {
            for output_column_ordinal in task.output_column_ordinals() {
                produced_auxiliary_columns.insert(output_column_ordinal);
            }
            for input_column_ordinal in task.input_column_ordinals() {
                if expected_auxiliary_columns.contains(&input_column_ordinal) {
                    return Err(CommonProofProverError::InvalidColumn);
                }
            }
        }
        if produced_auxiliary_columns != expected_auxiliary_columns {
            return Err(CommonProofProverError::InvalidColumn);
        }
        Ok(Self {
            tasks,
            next_task_index: 0,
            next_input_index: 0,
            input_trace_rows: BTreeMap::new(),
            pending_output_rows: Vec::new(),
            materialized_output_columns: BTreeSet::new(),
            component_product_sum_rows: None,
            trace_domain,
            relation_context: relation_context.clone(),
            tree_roles,
            trace_masks,
        })
    }

    pub(crate) fn next_input_column_ordinal(&self) -> Option<u32> {
        if !self.pending_output_rows.is_empty() {
            return None;
        }
        self.tasks.get(self.next_task_index).and_then(|task| {
            task.input_column_ordinals()
                .get(self.next_input_index)
                .copied()
        })
    }

    pub(crate) fn accept_input_column(
        &mut self,
        column_ordinal: u32,
        polynomial: CommonProofSourcePolynomial,
    ) -> Result<(), CommonProofProverError> {
        if self.next_input_column_ordinal() != Some(column_ordinal) {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let rows = base_trace_rows(&polynomial, self.trace_domain)?;
        drop(polynomial);
        if self.input_trace_rows.insert(column_ordinal, rows).is_some() {
            return Err(CommonProofProverError::InvalidColumn);
        }
        self.next_input_index = self
            .next_input_index
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
        Ok(())
    }

    pub(crate) fn has_pending_output(&self) -> bool {
        !self.pending_output_rows.is_empty()
    }

    pub(crate) fn advance_ready_task(&mut self) -> Result<bool, CommonProofProverError> {
        if !self.pending_output_rows.is_empty() {
            return Ok(false);
        }
        let Some(task) = self.tasks.get(self.next_task_index).cloned() else {
            return Ok(false);
        };
        let input_column_ordinals = task.input_column_ordinals();
        if self.next_input_index != input_column_ordinals.len()
            || self.input_trace_rows.len() != input_column_ordinals.len()
        {
            return Ok(false);
        }
        self.pending_output_rows = self.evaluate_task(task)?;
        self.pending_output_rows
            .retain(|(column_ordinal, _)| self.materialized_output_columns.insert(*column_ordinal));
        self.input_trace_rows.clear();
        self.next_input_index = 0;
        self.next_task_index = self
            .next_task_index
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
        Ok(true)
    }

    fn evaluate_task(
        &mut self,
        task: AuxiliaryColumnSynthesisTask,
    ) -> Result<Vec<ProtectedAuxiliaryColumnRows>, CommonProofProverError> {
        let row_count = self.trace_domain.size();
        let rows = |column_ordinal: u32| {
            self.input_trace_rows
                .get(&column_ordinal)
                .filter(|values| values.len() == row_count)
                .ok_or(CommonProofProverError::InvalidColumn)
        };
        match task {
            AuxiliaryColumnSynthesisTask::BeginComponent => {
                if self.component_product_sum_rows.is_some() {
                    return Err(CommonProofProverError::InvalidColumn);
                }
                self.component_product_sum_rows =
                    Some(Zeroizing::new(vec![ProofBaseFieldElement::ZERO; row_count]));
                Ok(Vec::new())
            }
            AuxiliaryColumnSynthesisTask::NegacyclicAutomorphismPermutation {
                descriptor,
                theta,
            } => {
                let source_low_rows = rows(descriptor.source_low_column_ordinal)?;
                let source_high_rows = rows(descriptor.source_high_column_ordinal)?;
                let target_low_rows = rows(descriptor.target_low_column_ordinal)?;
                let target_high_rows = rows(descriptor.target_high_column_ordinal)?;
                let mapped_low_position_rows = rows(descriptor.mapped_low_position_column_ordinal)?;
                let low_negation_bit_rows = rows(descriptor.low_negation_bit_column_ordinal)?;
                let mapped_high_position_rows =
                    rows(descriptor.mapped_high_position_column_ordinal)?;
                let high_negation_bit_rows = rows(descriptor.high_negation_bit_column_ordinal)?;
                let target_low_position_rows = rows(descriptor.target_low_position_column_ordinal)?;
                let target_high_position_rows =
                    rows(descriptor.target_high_position_column_ordinal)?;
                let one = ProofBaseFieldElement::ONE;
                let two = one.add(one);
                let three = two.add(one);
                let encoded_source =
                    |position: ProofBaseFieldElement,
                     negation_bit: ProofBaseFieldElement,
                     value: ProofBaseFieldElement| {
                        position
                            .multiply(three)
                            .add(one)
                            .add(value.subtract(negation_bit.multiply(two).multiply(value)))
                    };
                let encoded_target =
                    |position: ProofBaseFieldElement, value: ProofBaseFieldElement| {
                        position.multiply(three).add(one).add(value)
                    };
                let mut source_before_rows = Zeroizing::new(Vec::with_capacity(row_count));
                let mut source_low_product_rows = Zeroizing::new(Vec::with_capacity(row_count));
                let mut target_before_rows = Zeroizing::new(Vec::with_capacity(row_count));
                let mut target_low_product_rows = Zeroizing::new(Vec::with_capacity(row_count));
                let mut source_before = one;
                let mut target_before = one;
                for row_ordinal in 0..row_count {
                    source_before_rows.push(source_before);
                    target_before_rows.push(target_before);
                    let source_low_factor = theta.subtract(encoded_source(
                        mapped_low_position_rows[row_ordinal],
                        low_negation_bit_rows[row_ordinal],
                        source_low_rows[row_ordinal],
                    ));
                    let source_low_product = source_before.multiply(source_low_factor);
                    source_low_product_rows.push(source_low_product);
                    let target_low_factor = theta.subtract(encoded_target(
                        target_low_position_rows[row_ordinal],
                        target_low_rows[row_ordinal],
                    ));
                    let target_low_product = target_before.multiply(target_low_factor);
                    target_low_product_rows.push(target_low_product);
                    source_before = source_low_product.multiply(theta.subtract(encoded_source(
                        mapped_high_position_rows[row_ordinal],
                        high_negation_bit_rows[row_ordinal],
                        source_high_rows[row_ordinal],
                    )));
                    target_before = target_low_product.multiply(theta.subtract(encoded_target(
                        target_high_position_rows[row_ordinal],
                        target_high_rows[row_ordinal],
                    )));
                }
                Ok(vec![
                    (
                        descriptor.source_product_before_column_ordinal,
                        source_before_rows,
                    ),
                    (
                        descriptor.source_low_product_column_ordinal,
                        source_low_product_rows,
                    ),
                    (
                        descriptor.target_product_before_column_ordinal,
                        target_before_rows,
                    ),
                    (
                        descriptor.target_low_product_column_ordinal,
                        target_low_product_rows,
                    ),
                ])
            }
            AuxiliaryColumnSynthesisTask::PrefixEvaluation {
                source_column_ordinal,
                output_column_ordinal,
                theta,
            } => Ok(vec![(
                output_column_ordinal,
                prefix_evaluation_rows(rows(source_column_ordinal)?, theta),
            )]),
            AuxiliaryColumnSynthesisTask::SuffixEvaluation {
                source_column_ordinal,
                output_column_ordinal,
                theta,
            } => Ok(vec![(
                output_column_ordinal,
                suffix_evaluation_rows(rows(source_column_ordinal)?, theta),
            )]),
            AuxiliaryColumnSynthesisTask::ConvolutionProduct { descriptor, theta } => {
                let multiplicand_rows = rows(descriptor.multiplicand_column_ordinal)?;
                let reversed_multiplier_rows = rows(descriptor.reversed_multiplier_column_ordinal)?;
                let suffix_rows = suffix_evaluation_rows(multiplicand_rows, theta);
                let transpose_rows = convolution_transpose_rows(
                    descriptor.convolution_kind,
                    multiplicand_rows,
                    &suffix_rows,
                    theta,
                )?;
                let offset = base_field_constant(descriptor.multiplier_offset)?;
                let product_sum_rows = self
                    .component_product_sum_rows
                    .as_mut()
                    .ok_or(CommonProofProverError::InvalidColumn)?;
                for row_ordinal in 0..row_count {
                    let value = transpose_rows[row_ordinal]
                        .multiply(reversed_multiplier_rows[row_ordinal].subtract(offset));
                    product_sum_rows[row_ordinal] =
                        product_sum_rows[row_ordinal].add(if descriptor.negative {
                            value.negate()
                        } else {
                            value
                        });
                }
                Ok(vec![
                    (descriptor.suffix_evaluation_column_ordinal, suffix_rows),
                    (descriptor.reversed_transpose_column_ordinal, transpose_rows),
                ])
            }
            AuxiliaryColumnSynthesisTask::FullRingProduct { descriptor, theta } => {
                let multiplicand_low_rows = rows(descriptor.multiplicand_low_column_ordinal)?;
                let multiplicand_high_rows = rows(descriptor.multiplicand_high_column_ordinal)?;
                let reversed_multiplier_low_rows =
                    rows(descriptor.reversed_multiplier_low_column_ordinal)?;
                let reversed_multiplier_high_rows =
                    rows(descriptor.reversed_multiplier_high_column_ordinal)?;
                let low_suffix_rows = suffix_evaluation_rows(multiplicand_low_rows, theta);
                let high_suffix_rows = suffix_evaluation_rows(multiplicand_high_rows, theta);
                let low_transpose_rows = full_ring_transpose_rows(
                    descriptor.selected_half,
                    true,
                    multiplicand_low_rows,
                    multiplicand_high_rows,
                    &low_suffix_rows,
                    &high_suffix_rows,
                    theta,
                )?;
                let high_transpose_rows = full_ring_transpose_rows(
                    descriptor.selected_half,
                    false,
                    multiplicand_low_rows,
                    multiplicand_high_rows,
                    &low_suffix_rows,
                    &high_suffix_rows,
                    theta,
                )?;
                let low_offset = base_field_constant(descriptor.multiplier_low_offset)?;
                let high_offset = base_field_constant(descriptor.multiplier_high_offset)?;
                let product_sum_rows = self
                    .component_product_sum_rows
                    .as_mut()
                    .ok_or(CommonProofProverError::InvalidColumn)?;
                for row_ordinal in 0..row_count {
                    let low_product = low_transpose_rows[row_ordinal]
                        .multiply(reversed_multiplier_low_rows[row_ordinal].subtract(low_offset));
                    let high_product = high_transpose_rows[row_ordinal]
                        .multiply(reversed_multiplier_high_rows[row_ordinal].subtract(high_offset));
                    let value = low_product.add(high_product);
                    product_sum_rows[row_ordinal] =
                        product_sum_rows[row_ordinal].add(if descriptor.negative {
                            value.negate()
                        } else {
                            value
                        });
                }
                Ok(vec![
                    (
                        descriptor.multiplicand_low_suffix_evaluation_column_ordinal,
                        low_suffix_rows,
                    ),
                    (
                        descriptor.multiplicand_high_suffix_evaluation_column_ordinal,
                        high_suffix_rows,
                    ),
                    (
                        descriptor.reversed_multiplier_low_transpose_column_ordinal,
                        low_transpose_rows,
                    ),
                    (
                        descriptor.reversed_multiplier_high_transpose_column_ordinal,
                        high_transpose_rows,
                    ),
                ])
            }
            AuxiliaryColumnSynthesisTask::LinearEvaluation { descriptor, theta } => {
                let mut coefficient_rows =
                    vec![ProofBaseFieldElement::ZERO; self.trace_domain.size()];
                for (row_ordinal, coefficient) in coefficient_rows.iter_mut().enumerate() {
                    for term in &descriptor.ordered_linear_terms {
                        *coefficient = coefficient.add(signed_linear_term_row(
                            term,
                            row_ordinal,
                            &self.relation_context,
                            &self.input_trace_rows,
                        )?);
                    }
                }
                Ok(vec![(
                    descriptor.linear_evaluation_column_ordinal,
                    suffix_evaluation_rows(&coefficient_rows, theta),
                )])
            }
            AuxiliaryColumnSynthesisTask::ProductAccumulator {
                output_column_ordinal,
            } => Ok(vec![(
                output_column_ordinal,
                product_accumulator_rows(
                    &self
                        .component_product_sum_rows
                        .take()
                        .ok_or(CommonProofProverError::InvalidColumn)?,
                ),
            )]),
        }
    }

    pub(crate) fn take_next_output<Coins>(
        &mut self,
        variant: &RelationPlanVariant,
        coins: &mut Coins,
        maximum_candidate_draws_per_output: u32,
    ) -> Result<Option<(u32, CommonProofSourcePolynomial)>, CommonProofPrivateCoinError<Coins::Error>>
    where
        Coins: CommonProofPrivateCoinSource,
    {
        if self.pending_output_rows.is_empty() {
            return Ok(None);
        }
        let (column_ordinal, rows) = self.pending_output_rows.remove(0);
        let context = AuxiliaryTraceRowInsertionContext::new(
            variant,
            &self.tree_roles,
            &self.trace_masks,
            self.trace_domain,
            maximum_candidate_draws_per_output,
        );
        construct_auxiliary_relation_column(context, column_ordinal, rows, coins)
            .map(|polynomial| Some((column_ordinal, polynomial)))
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.next_task_index == self.tasks.len()
            && self.next_input_index == 0
            && self.input_trace_rows.is_empty()
            && self.pending_output_rows.is_empty()
            && self.component_product_sum_rows.is_none()
    }
}

#[cfg(test)]
mod requested_pre_challenge_source_column_tests {
    use std::collections::BTreeSet;

    use crate::{
        bgv::proof_suite::{ProofTreeRole, selected_relation_plans},
        foundation::ProofApplicationSlotCeilings,
    };

    use super::{
        authenticated_pre_challenge_source_coefficient_position_counts,
        integer_lift_derived_columns, ordered_integer_lift_auxiliary_column_ordinals,
        persisted_pre_challenge_column_coefficient_position_counts,
        proof_created_tree_roles_by_column, requested_pre_challenge_source_column_ordinals,
    };

    fn expected_requested_source_column_count(schema_identifier: u16) -> usize {
        match schema_identifier {
            ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER => 2_018,
            ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER => 3_302,
            ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER => 506,
            ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER => 61_140,
            ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER => 9_152,
            ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER => 157_508,
            ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER => 123_450,
            ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER => 20_680,
            ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER => 1_728,
            ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER => 25_670,
            ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER => 3_451,
            ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER => 2_528,
            _ => panic!("unexpected selected proof family {schema_identifier}"),
        }
    }

    #[test]
    fn selected_pre_challenge_source_column_catalog_matches_exact_family_geometry() {
        let selected_plans = selected_relation_plans().expect("selected relation plans compile");
        let mut variant_count = 0_usize;
        let mut evaluator_top_counts = BTreeSet::new();
        let mut observed_repeated_reversed_column_binding = false;
        let mut observed_integer_lift_auxiliary_column = false;

        for artifact in selected_plans {
            let schema_identifier = artifact.application_statement_schema_identifier();
            let expected_requested_count =
                expected_requested_source_column_count(schema_identifier);
            for variant in artifact.compiled_plan().variants() {
                variant_count += 1;
                if schema_identifier
                    == ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
                {
                    assert!(
                        evaluator_top_counts.insert(
                            variant
                                .top_count()
                                .expect("each evaluator aggregate variant has a top count"),
                        ),
                        "evaluator aggregate top counts are unique",
                    );
                }

                let requested_column_ordinals =
                    requested_pre_challenge_source_column_ordinals(variant)
                        .expect("selected requested source columns derive");
                assert_eq!(
                    requested_column_ordinals.len(),
                    expected_requested_count,
                    "family {schema_identifier} has the exact requested source count",
                );
                assert!(
                    requested_column_ordinals
                        .windows(2)
                        .all(|pair| pair[0] < pair[1]),
                    "requested source columns remain in strict physical-column order",
                );
                let source_coefficient_position_counts =
                    authenticated_pre_challenge_source_coefficient_position_counts(variant)
                        .expect("selected source coefficient-position counts derive");
                assert!(
                    source_coefficient_position_counts
                        .keys()
                        .copied()
                        .eq(requested_column_ordinals.iter().copied()),
                    "source position counts own exactly the requested source catalog",
                );
                if schema_identifier
                    == ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER
                {
                    assert_eq!(
                        source_coefficient_position_counts.values().sum::<u64>(),
                        33_128_448,
                        "the raw authenticated same-secret source position census is exact",
                    );
                    assert_eq!(
                        persisted_pre_challenge_column_coefficient_position_counts(variant)
                            .expect("selected persisted source position counts derive")
                            .values()
                            .sum::<u64>(),
                        34_462_440,
                        "proof-owned masks restore the normative persisted census",
                    );
                }

                let proof_tree_roles = proof_created_tree_roles_by_column(variant)
                    .expect("selected proof tree roles derive");
                let auxiliary_oracle_columns = proof_tree_roles
                    .iter()
                    .filter_map(|(column_ordinal, role)| {
                        (*role == ProofTreeRole::AuxiliaryOracle).then_some(*column_ordinal)
                    })
                    .collect::<BTreeSet<_>>();
                let (reversed_columns_by_source, integer_lift_auxiliary_columns) =
                    integer_lift_derived_columns(variant)
                        .expect("selected integer-lift columns derive");
                let ordered_integer_lift_auxiliary_columns =
                    ordered_integer_lift_auxiliary_column_ordinals(variant)
                        .expect("selected integer-lift auxiliary order derives");
                assert_eq!(
                    ordered_integer_lift_auxiliary_columns
                        .iter()
                        .copied()
                        .collect::<BTreeSet<_>>(),
                    integer_lift_auxiliary_columns,
                    "family {schema_identifier} has one complete auxiliary-column order",
                );
                let derived_reversed_columns = reversed_columns_by_source
                    .into_values()
                    .collect::<BTreeSet<_>>();
                assert!(
                    integer_lift_auxiliary_columns.is_subset(&auxiliary_oracle_columns),
                    "integer-lift auxiliary columns are owned by the auxiliary oracle",
                );
                assert!(
                    auxiliary_oracle_columns.is_disjoint(&derived_reversed_columns),
                    "derived reversed columns remain base-oracle columns",
                );
                observed_integer_lift_auxiliary_column |=
                    !integer_lift_auxiliary_columns.is_empty();

                let excluded_columns = auxiliary_oracle_columns
                    .union(&derived_reversed_columns)
                    .copied()
                    .collect::<BTreeSet<_>>();
                assert!(requested_column_ordinals.iter().all(|column_ordinal| {
                    usize::try_from(*column_ordinal)
                        .ok()
                        .is_some_and(|column_index| {
                            column_index < variant.ordered_columns().len()
                                && !excluded_columns.contains(column_ordinal)
                        })
                }));
                assert_eq!(
                    requested_column_ordinals.len(),
                    variant
                        .ordered_columns()
                        .len()
                        .checked_sub(excluded_columns.len())
                        .expect("excluded columns fit the relation column catalog"),
                    "auxiliary and derived reversed columns are excluded as one set union",
                );

                let raw_reversed_binding_count = variant
                    .ordered_integer_lift_batches()
                    .iter()
                    .map(|batch| batch.ordered_reversed_column_bindings.len())
                    .sum::<usize>();
                observed_repeated_reversed_column_binding |=
                    raw_reversed_binding_count > derived_reversed_columns.len();
            }
        }

        assert_eq!(variant_count, 31);
        assert_eq!(evaluator_top_counts, (1_u16..=20).collect::<BTreeSet<_>>());
        assert!(observed_integer_lift_auxiliary_column);
        assert!(
            observed_repeated_reversed_column_binding,
            "theta-repeated reversal descriptors exclude each physical column only once",
        );
    }
}
