use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use super::state::StateExactOutputHasher;
use super::{
    CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalDecodeLimits,
    CanonicalItem, CanonicalItemType, CanonicalTuple, FOUNDATION_PROFILE, FoundationObjectType,
    FoundationSchemaError, Hash512, ML_DSA_65_SIGNATURE_BYTE_LENGTH, RefusalReason,
    SIGNED_CARRIER_SCHEMA_IDENTIFIER, SignedCarrier, StateCapabilityKind, StreamDescriptor,
    VerificationResult,
};

#[cfg(test)]
use super::{ObjectEnvelope, ParticipantIdentity, hash_foundation_tuple_512 as hash512};

const CHUNK_DIGEST_DOMAIN: &str = "sealed-lattice/transport/chunk/v1";
const FULL_OBJECT_DIGEST_DOMAIN: &str = "sealed-lattice/transport/full-object/v1";
const CANONICAL_RAW_BYTES_LENGTH_PREFIX_BYTE_LENGTH: u32 = 4;
/// Largest payload whose four-byte length prefix and bytes fit a canonical u32 item length.
/// Phone feasibility is measured separately from this absolute transport safety bound.
pub const MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH: u64 =
    u32::MAX as u64 - CANONICAL_RAW_BYTES_LENGTH_PREFIX_BYTE_LENGTH as u64;

/// The verifier-owned stream domains accepted by the foundation profile.
///
/// A transport producer supplies a descriptor and bytes, never a free-form
/// domain string. The consuming protocol position selects one of these values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CanonicalStreamDomain {
    PrivateMailboxCiphertext,
    DealerVssShareLinkageProof,
    RecipientAggregateThresholdShareProof,
    SameSecretProof,
    PublicKeyShareProof,
    CollectivePublicKeyAggregateProof,
    RkgRoundOneProof,
    RkgRoundOneAggregateProof,
    RkgRoundTwoProof,
    GaloisShareProof,
    EvaluatorKeyAggregateProof,
    CollectivePublicKey,
    EvaluatorKeyStore,
    BallotCiphertext,
    BallotValidityProof,
    AggregateCiphertext,
    ReplayTargetIdentifierCiphertext,
    ReplayTargetOrderCiphertext,
    TargetIdentifierPartialDecryption,
    TargetOrderPartialDecryption,
    MaliciousTargetShareProof,
    CheckpointState,
    StateFinalitySignatureExactOutput,
    StateTargetReleaseExactOutput,
    PublicKeyShareMaterial,
}

impl CanonicalStreamDomain {
    pub const fn canonical_domain(self) -> &'static str {
        match self {
            Self::PrivateMailboxCiphertext => "sealed-lattice/stream/mailbox/ciphertext/v1",
            Self::DealerVssShareLinkageProof => {
                "sealed-lattice/stream/setup/vss-share-linkage-proof/v1"
            }
            Self::RecipientAggregateThresholdShareProof => {
                "sealed-lattice/stream/setup/aggregate-threshold-share-proof/v1"
            }
            Self::SameSecretProof => "sealed-lattice/stream/setup/same-secret-proof/v1",
            Self::PublicKeyShareProof => "sealed-lattice/stream/setup/public-key-share-proof/v1",
            Self::CollectivePublicKeyAggregateProof => {
                "sealed-lattice/stream/setup/collective-public-key-aggregate-proof/v1"
            }
            Self::RkgRoundOneProof => "sealed-lattice/stream/setup/rkg-round-one-proof/v1",
            Self::RkgRoundOneAggregateProof => {
                "sealed-lattice/stream/setup/rkg-round-one-aggregate-proof/v1"
            }
            Self::RkgRoundTwoProof => "sealed-lattice/stream/setup/rkg-round-two-proof/v1",
            Self::GaloisShareProof => "sealed-lattice/stream/setup/galois-share-proof/v1",
            Self::EvaluatorKeyAggregateProof => {
                "sealed-lattice/stream/setup/evaluator-key-aggregate-proof/v1"
            }
            Self::CollectivePublicKey => "sealed-lattice/stream/setup/collective-public-key/v1",
            Self::EvaluatorKeyStore => "sealed-lattice/stream/setup/evaluator-key-store/v1",
            Self::BallotCiphertext => "sealed-lattice/stream/ballot/ciphertext/v1",
            Self::BallotValidityProof => "sealed-lattice/stream/ballot/validity-proof/v1",
            Self::AggregateCiphertext => "sealed-lattice/stream/aggregation/ciphertext/v1",
            Self::ReplayTargetIdentifierCiphertext => {
                "sealed-lattice/stream/evaluator/target-id-ciphertext/v1"
            }
            Self::ReplayTargetOrderCiphertext => {
                "sealed-lattice/stream/evaluator/target-order-ciphertext/v1"
            }
            Self::TargetIdentifierPartialDecryption => {
                "sealed-lattice/stream/target-release/target-id-partial-decryption/v1"
            }
            Self::TargetOrderPartialDecryption => {
                "sealed-lattice/stream/target-release/target-order-partial-decryption/v1"
            }
            Self::MaliciousTargetShareProof => {
                "sealed-lattice/stream/target-release/malicious-share-proof/v1"
            }
            Self::CheckpointState => "sealed-lattice/stream/checkpoint/state/v1",
            Self::StateFinalitySignatureExactOutput => {
                "sealed-lattice/stream/state/finality-signature-exact-output/v1"
            }
            Self::StateTargetReleaseExactOutput => {
                "sealed-lattice/stream/state/target-release-exact-output/v1"
            }
            Self::PublicKeyShareMaterial => {
                "sealed-lattice/stream/setup/public-key-share-material/v1"
            }
        }
    }

    pub const fn canonical_code(self) -> u32 {
        match self {
            Self::PrivateMailboxCiphertext => 1,
            Self::DealerVssShareLinkageProof => 2,
            Self::RecipientAggregateThresholdShareProof => 3,
            Self::SameSecretProof => 4,
            Self::PublicKeyShareProof => 5,
            Self::CollectivePublicKeyAggregateProof => 6,
            Self::RkgRoundOneProof => 7,
            Self::RkgRoundOneAggregateProof => 8,
            Self::RkgRoundTwoProof => 9,
            Self::GaloisShareProof => 10,
            Self::EvaluatorKeyAggregateProof => 11,
            Self::CollectivePublicKey => 12,
            Self::EvaluatorKeyStore => 13,
            Self::BallotCiphertext => 14,
            Self::BallotValidityProof => 15,
            Self::AggregateCiphertext => 16,
            Self::ReplayTargetIdentifierCiphertext => 17,
            Self::ReplayTargetOrderCiphertext => 18,
            Self::TargetIdentifierPartialDecryption => 19,
            Self::TargetOrderPartialDecryption => 20,
            Self::MaliciousTargetShareProof => 21,
            Self::CheckpointState => 22,
            Self::StateFinalitySignatureExactOutput => 24,
            Self::StateTargetReleaseExactOutput => 25,
            Self::PublicKeyShareMaterial => 26,
        }
    }

    pub const fn from_canonical_code(code: u32) -> Option<Self> {
        match code {
            1 => Some(Self::PrivateMailboxCiphertext),
            2 => Some(Self::DealerVssShareLinkageProof),
            3 => Some(Self::RecipientAggregateThresholdShareProof),
            4 => Some(Self::SameSecretProof),
            5 => Some(Self::PublicKeyShareProof),
            6 => Some(Self::CollectivePublicKeyAggregateProof),
            7 => Some(Self::RkgRoundOneProof),
            8 => Some(Self::RkgRoundOneAggregateProof),
            9 => Some(Self::RkgRoundTwoProof),
            10 => Some(Self::GaloisShareProof),
            11 => Some(Self::EvaluatorKeyAggregateProof),
            12 => Some(Self::CollectivePublicKey),
            13 => Some(Self::EvaluatorKeyStore),
            14 => Some(Self::BallotCiphertext),
            15 => Some(Self::BallotValidityProof),
            16 => Some(Self::AggregateCiphertext),
            17 => Some(Self::ReplayTargetIdentifierCiphertext),
            18 => Some(Self::ReplayTargetOrderCiphertext),
            19 => Some(Self::TargetIdentifierPartialDecryption),
            20 => Some(Self::TargetOrderPartialDecryption),
            21 => Some(Self::MaliciousTargetShareProof),
            22 => Some(Self::CheckpointState),
            24 => Some(Self::StateFinalitySignatureExactOutput),
            25 => Some(Self::StateTargetReleaseExactOutput),
            26 => Some(Self::PublicKeyShareMaterial),
            _ => None,
        }
    }

    pub(crate) const fn state_exact_output_capability_kind(self) -> Option<StateCapabilityKind> {
        match self {
            Self::StateFinalitySignatureExactOutput => Some(StateCapabilityKind::FinalitySignature),
            Self::StateTargetReleaseExactOutput => Some(StateCapabilityKind::TargetRelease),
            _ => None,
        }
    }
}

/// Verifier-owned terminal binding for one complete canonical stream.
///
/// Its fields and constructor stay private to the stream engine. Downstream
/// verifiers may consume the summary, but cannot create one from a caller-supplied
/// digest or descriptor alone.
#[derive(Debug, Clone)]
pub(crate) struct VerifiedCanonicalStreamSummary {
    stream_domain: CanonicalStreamDomain,
    stream_descriptor: StreamDescriptor,
    state_exact_output_hash: Option<Hash512>,
    target_release_output_bundle: Option<Box<VerifiedTargetReleaseOutputBundle>>,
}

impl VerifiedCanonicalStreamSummary {
    pub(crate) const fn stream_domain(&self) -> CanonicalStreamDomain {
        self.stream_domain
    }

    pub(crate) const fn stream_descriptor(&self) -> &StreamDescriptor {
        &self.stream_descriptor
    }

    fn authenticate_readback_chunk(
        &self,
        chunk_index: usize,
        chunk_bytes: &[u8],
    ) -> Result<(), RefusalReason> {
        let expected_digest = self
            .stream_descriptor
            .ordered_chunk_digests
            .get(chunk_index)
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        let expected_byte_length = expected_chunk_byte_length(
            self.total_byte_length(),
            self.stream_descriptor.ordered_chunk_digests.len(),
            chunk_index,
        )?;
        if chunk_bytes.len() != expected_byte_length
            || chunk_digest(self.stream_domain, chunk_index, chunk_bytes)? != *expected_digest
        {
            return Err(RefusalReason::WrongHashOrRoot);
        }
        Ok(())
    }

    pub(crate) const fn total_byte_length(&self) -> u64 {
        self.stream_descriptor.total_byte_length
    }

    pub(crate) const fn full_object_digest(&self) -> Hash512 {
        self.stream_descriptor.full_object_digest
    }

    pub(crate) const fn state_exact_output_hash(&self) -> Option<Hash512> {
        self.state_exact_output_hash
    }

    pub(crate) fn into_target_release_output_bundle(
        self,
    ) -> Option<VerifiedTargetReleaseOutputBundle> {
        self.target_release_output_bundle.map(|bundle| *bundle)
    }
}

/// Verifier-owned decomposition of one exact target-release output. The large
/// proof body is never retained here; only the bounded signed carrier and the
/// three terminal child-stream authorities survive verification.
#[derive(Debug, Clone)]
pub(crate) struct VerifiedTargetReleaseOutputBundle {
    canonical_signed_carrier: Vec<u8>,
    finality_hash: Hash512,
    reservation_intent_object_hash: Hash512,
    target_identifier_stream: VerifiedCanonicalStreamSummary,
    target_order_stream: VerifiedCanonicalStreamSummary,
    malicious_share_proof_stream: VerifiedCanonicalStreamSummary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(test)]
pub(crate) struct TargetReleaseOutputBundleByteLengths {
    header: u64,
    signed_carrier: u64,
    target_identifier: u64,
    target_order: u64,
    malicious_share_proof: u64,
    total: u64,
}

pub(crate) fn canonical_target_release_output_payload(
    finality_hash: Hash512,
    reservation_intent_object_hash: Hash512,
    target_identifier_descriptor: &StreamDescriptor,
    target_order_descriptor: &StreamDescriptor,
    malicious_share_proof_descriptor: &StreamDescriptor,
) -> Result<Vec<u8>, FoundationSchemaError> {
    fn descriptor_item(
        descriptor: &StreamDescriptor,
    ) -> Result<CanonicalItem, FoundationSchemaError> {
        let canonical_descriptor = descriptor.encode()?;
        let descriptor_tuple =
            CanonicalTuple::decode(&canonical_descriptor, &CanonicalDecodeLimits::default())?;
        Ok(CanonicalItem::nested_tuple(&descriptor_tuple)?)
    }

    Ok(CanonicalTuple::new(
        TARGET_DECRYPTION_SHARE_PAYLOAD_SCHEMA_IDENTIFIER,
        TARGET_RELEASE_OUTPUT_BUNDLE_VERSION,
        vec![
            CanonicalItem::hash512(finality_hash.into_bytes()),
            CanonicalItem::hash512(reservation_intent_object_hash.into_bytes()),
            descriptor_item(target_identifier_descriptor)?,
            descriptor_item(target_order_descriptor)?,
            descriptor_item(malicious_share_proof_descriptor)?,
        ],
    )
    .encode()?)
}

/// Derives the exact target-share carrier and bundle lengths without
/// materializing the three potentially large child streams. The placeholder
/// hashes, participant identity, and signature all occupy fixed-width
/// canonical fields; production verification fixes the prerequisite list to
/// empty and the producer sequence to zero, so their values cannot change the
/// encoded length.
#[cfg(test)]
pub(crate) fn canonical_target_release_output_bundle_byte_lengths_for_accounting(
    target_identifier_descriptor: &StreamDescriptor,
    target_order_descriptor: &StreamDescriptor,
    malicious_share_proof_descriptor: &StreamDescriptor,
) -> Result<TargetReleaseOutputBundleByteLengths, FoundationSchemaError> {
    let payload = canonical_target_release_output_payload(
        Hash512::from_bytes([0x31; Hash512::BYTE_LENGTH]),
        Hash512::from_bytes([0x32; Hash512::BYTE_LENGTH]),
        target_identifier_descriptor,
        target_order_descriptor,
        malicious_share_proof_descriptor,
    )?;
    let signed_carrier = SignedCarrier {
        envelope: ObjectEnvelope {
            suite_id: Hash512::from_bytes([0x11; Hash512::BYTE_LENGTH]),
            object_type: FoundationObjectType::TargetDecryptionShare,
            ceremony_context_hash: Hash512::from_bytes([0x12; Hash512::BYTE_LENGTH]),
            action_context_hash: Hash512::from_bytes([0x13; Hash512::BYTE_LENGTH]),
            producer_participant_id: Some(ParticipantIdentity::from_bytes(
                [0x14; ParticipantIdentity::BYTE_LENGTH],
            )),
            producer_sequence: 0,
            ordered_prerequisite_hashes: Vec::new(),
            payload_bytes: payload,
        },
        signature: [0x15; ML_DSA_65_SIGNATURE_BYTE_LENGTH],
    }
    .encode()?;

    let header = u64::try_from(TARGET_RELEASE_OUTPUT_BUNDLE_HEADER_BYTE_LENGTH).map_err(|_| {
        FoundationSchemaError::new(
            RefusalReason::OutsideSupportedProfile,
            "target-release bundle header length does not fit u64",
        )
    })?;
    let signed_carrier = u64::try_from(signed_carrier.len()).map_err(|_| {
        FoundationSchemaError::new(
            RefusalReason::OutsideSupportedProfile,
            "target-release signed carrier length does not fit u64",
        )
    })?;
    let target_identifier = target_identifier_descriptor.total_byte_length;
    let target_order = target_order_descriptor.total_byte_length;
    let malicious_share_proof = malicious_share_proof_descriptor.total_byte_length;
    let total = [
        signed_carrier,
        target_identifier,
        target_order,
        malicious_share_proof,
    ]
    .into_iter()
    .try_fold(header, |total, byte_length| {
        total.checked_add(byte_length).ok_or_else(|| {
            FoundationSchemaError::new(
                RefusalReason::OutsideSupportedProfile,
                "target-release output bundle length overflows",
            )
        })
    })?;
    Ok(TargetReleaseOutputBundleByteLengths {
        header,
        signed_carrier,
        target_identifier,
        target_order,
        malicious_share_proof,
        total,
    })
}

#[cfg(test)]
impl TargetReleaseOutputBundleByteLengths {
    pub(crate) const fn header(self) -> u64 {
        self.header
    }

    pub(crate) const fn signed_carrier(self) -> u64 {
        self.signed_carrier
    }

    pub(crate) const fn target_identifier(self) -> u64 {
        self.target_identifier
    }

    pub(crate) const fn target_order(self) -> u64 {
        self.target_order
    }

    pub(crate) const fn malicious_share_proof(self) -> u64 {
        self.malicious_share_proof
    }

    pub(crate) const fn total(self) -> u64 {
        self.total
    }
}

impl VerifiedTargetReleaseOutputBundle {
    pub(crate) fn canonical_signed_carrier(&self) -> &[u8] {
        &self.canonical_signed_carrier
    }

    pub(crate) const fn finality_hash(&self) -> Hash512 {
        self.finality_hash
    }

    pub(crate) const fn reservation_intent_object_hash(&self) -> Hash512 {
        self.reservation_intent_object_hash
    }

    pub(crate) const fn target_identifier_descriptor(&self) -> &StreamDescriptor {
        self.target_identifier_stream.stream_descriptor()
    }

    pub(crate) const fn target_order_descriptor(&self) -> &StreamDescriptor {
        self.target_order_stream.stream_descriptor()
    }

    pub(crate) const fn malicious_share_proof_descriptor(&self) -> &StreamDescriptor {
        self.malicious_share_proof_stream.stream_descriptor()
    }

    #[cfg(test)]
    pub(crate) fn byte_lengths(
        &self,
    ) -> Result<TargetReleaseOutputBundleByteLengths, RefusalReason> {
        let header = u64::try_from(TARGET_RELEASE_OUTPUT_BUNDLE_HEADER_BYTE_LENGTH)
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        let signed_carrier = u64::try_from(self.canonical_signed_carrier.len())
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        let target_identifier = self.target_identifier_stream.total_byte_length();
        let target_order = self.target_order_stream.total_byte_length();
        let malicious_share_proof = self.malicious_share_proof_stream.total_byte_length();
        let total = [
            signed_carrier,
            target_identifier,
            target_order,
            malicious_share_proof,
        ]
        .into_iter()
        .try_fold(header, |total, byte_length| {
            total
                .checked_add(byte_length)
                .ok_or(RefusalReason::OutsideSupportedProfile)
        })?;
        Ok(TargetReleaseOutputBundleByteLengths {
            header,
            signed_carrier,
            target_identifier,
            target_order,
            malicious_share_proof,
            total,
        })
    }

    pub(crate) fn open_target_identifier_readback(
        &self,
    ) -> Result<CanonicalStreamReadbackVerifier, RefusalReason> {
        CanonicalStreamReadbackVerifier::new(
            CanonicalStreamDomain::TargetIdentifierPartialDecryption,
            self.target_identifier_stream.clone(),
        )
    }

    pub(crate) fn open_target_order_readback(
        &self,
    ) -> Result<CanonicalStreamReadbackVerifier, RefusalReason> {
        CanonicalStreamReadbackVerifier::new(
            CanonicalStreamDomain::TargetOrderPartialDecryption,
            self.target_order_stream.clone(),
        )
    }

    #[cfg(test)]
    pub(crate) fn open_malicious_share_proof_readback(
        &self,
    ) -> Result<CanonicalStreamReadbackVerifier, RefusalReason> {
        CanonicalStreamReadbackVerifier::new(
            CanonicalStreamDomain::MaliciousTargetShareProof,
            self.malicious_share_proof_stream.clone(),
        )
    }
}

/// Authenticates browser-stored canonical chunks before a random-access
/// verifier consumes them. Construction requires the terminal summary from a
/// complete sequential canonical-stream verification of the same descriptor,
/// so a descriptor or a set of independently matching chunk digests cannot
/// mint stream authority by themselves.
pub(crate) struct CanonicalStreamReadbackVerifier {
    stream_domain: CanonicalStreamDomain,
    verified_summary: VerifiedCanonicalStreamSummary,
    authenticated_chunks: Box<[bool]>,
    authenticated_chunk_count: usize,
    initial_pass_finished: bool,
    refusal_reason: Option<RefusalReason>,
}

impl CanonicalStreamReadbackVerifier {
    pub(crate) fn new(
        stream_domain: CanonicalStreamDomain,
        verified_summary: VerifiedCanonicalStreamSummary,
    ) -> Result<Self, RefusalReason> {
        validate_descriptor(verified_summary.stream_descriptor())?;
        if verified_summary.stream_domain() != stream_domain {
            return Err(RefusalReason::WrongHashOrRoot);
        }
        let chunk_count = verified_summary
            .stream_descriptor()
            .ordered_chunk_digests
            .len();
        Ok(Self {
            stream_domain,
            verified_summary,
            authenticated_chunks: vec![false; chunk_count].into_boxed_slice(),
            authenticated_chunk_count: 0,
            initial_pass_finished: false,
            refusal_reason: None,
        })
    }

    #[cfg(test)]
    pub(crate) const fn total_byte_length(&self) -> u64 {
        self.verified_summary.total_byte_length()
    }

    pub(crate) fn chunk_count(&self) -> usize {
        self.verified_summary
            .stream_descriptor()
            .ordered_chunk_digests
            .len()
    }

    pub(crate) fn authenticate_chunk(
        &mut self,
        chunk_index: usize,
        chunk_bytes: &[u8],
    ) -> Result<(), RefusalReason> {
        if let Some(refusal_reason) = self.refusal_reason {
            return Err(refusal_reason);
        }
        let result = self.authenticate_chunk_inner(chunk_index, chunk_bytes);
        if let Err(refusal_reason) = result {
            self.refusal_reason = Some(refusal_reason);
        }
        result
    }

    pub(crate) fn finish(self) -> VerificationResult<VerifiedCanonicalStreamSummary> {
        if let Some(refusal_reason) = self.refusal_reason {
            return VerificationResult::refused(refusal_reason);
        }
        if !self.initial_pass_finished
            && self.authenticated_chunk_count != self.authenticated_chunks.len()
        {
            return VerificationResult::refused(RefusalReason::WrongTypeOrLength);
        }
        VerificationResult::valid(self.verified_summary)
    }

    /// Completes the required full authenticated pass while retaining only the
    /// verified chunk-digest authority. Later random-access reads are checked
    /// against those bound digests without retaining the source body or the
    /// initial per-chunk visitation flags.
    pub(crate) fn finish_initial_pass(&mut self) -> VerificationResult<()> {
        if let Some(refusal_reason) = self.refusal_reason {
            return VerificationResult::refused(refusal_reason);
        }
        if self.initial_pass_finished
            || self.authenticated_chunk_count != self.authenticated_chunks.len()
        {
            return VerificationResult::refused(RefusalReason::WrongTypeOrLength);
        }
        self.authenticated_chunks = Box::new([]);
        self.authenticated_chunk_count = 0;
        self.initial_pass_finished = true;
        VerificationResult::valid(())
    }

    fn authenticate_chunk_inner(
        &mut self,
        chunk_index: usize,
        chunk_bytes: &[u8],
    ) -> Result<(), RefusalReason> {
        if self.stream_domain != self.verified_summary.stream_domain() {
            return Err(RefusalReason::WrongHashOrRoot);
        }
        self.verified_summary
            .authenticate_readback_chunk(chunk_index, chunk_bytes)?;
        if self.initial_pass_finished {
            return Ok(());
        }
        let authenticated = self
            .authenticated_chunks
            .get_mut(chunk_index)
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        if !*authenticated {
            *authenticated = true;
            self.authenticated_chunk_count = self
                .authenticated_chunk_count
                .checked_add(1)
                .ok_or(RefusalReason::OutsideSupportedProfile)?;
        }
        Ok(())
    }
}

/// Incrementally authenticates one canonical stream without retaining its body.
///
/// A refusal poisons the verifier so ignoring an intermediate result can never
/// produce a valid terminal result.
pub struct CanonicalStreamVerifier {
    stream_domain: CanonicalStreamDomain,
    descriptor: StreamDescriptor,
    next_chunk_index: usize,
    observed_byte_length: u64,
    full_object_hasher: Shake256,
    state_exact_output_hasher: Option<StateExactOutputHasher>,
    target_release_output_verifier: Option<Box<TargetReleaseOutputBundleVerifier>>,
    refusal_reason: Option<RefusalReason>,
}

/// Incrementally constructs a canonical stream descriptor without retaining
/// the streamed object. Generation failures poison the writer so a caller
/// cannot ignore an intermediate error and publish a partial descriptor.
pub struct CanonicalStreamWriter {
    stream_domain: CanonicalStreamDomain,
    total_byte_length: u64,
    expected_chunk_count: usize,
    next_chunk_index: usize,
    observed_byte_length: u64,
    ordered_chunk_digests: Vec<Hash512>,
    full_object_hasher: Shake256,
    error: Option<RefusalReason>,
}

impl CanonicalStreamWriter {
    pub fn new(
        stream_domain: CanonicalStreamDomain,
        total_byte_length: u64,
    ) -> Result<Self, RefusalReason> {
        let expected_chunk_count = expected_chunk_count(total_byte_length)?;
        let full_object_hasher = full_object_hasher(stream_domain, total_byte_length)?;
        Ok(Self {
            stream_domain,
            total_byte_length,
            expected_chunk_count,
            next_chunk_index: 0,
            observed_byte_length: 0,
            ordered_chunk_digests: Vec::with_capacity(expected_chunk_count),
            full_object_hasher,
            error: None,
        })
    }

    pub fn absorb_chunk(
        &mut self,
        chunk_index: usize,
        chunk_bytes: &[u8],
    ) -> Result<(), RefusalReason> {
        if let Some(error) = self.error {
            return Err(error);
        }
        let result = self.absorb_chunk_inner(chunk_index, chunk_bytes);
        if let Err(error) = result {
            self.error = Some(error);
        }
        result
    }

    pub fn finish(self) -> Result<StreamDescriptor, RefusalReason> {
        if let Some(error) = self.error {
            return Err(error);
        }
        if self.next_chunk_index != self.expected_chunk_count
            || self.observed_byte_length != self.total_byte_length
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }

        let full_object_digest = finish_full_object_hasher(self.full_object_hasher);
        StreamDescriptor::new(
            self.total_byte_length,
            self.ordered_chunk_digests,
            full_object_digest,
        )
        .map_err(|error| error.refusal_reason)
    }

    /// Mints verifier-owned authority for generator-produced replay
    /// ciphertexts from the same digest state that constructs their canonical
    /// descriptor. Domains whose validity requires parsing or state semantics
    /// must still pass through `CanonicalStreamVerifier`.
    pub(crate) fn finish_generated_summary(
        self,
    ) -> Result<VerifiedCanonicalStreamSummary, RefusalReason> {
        let stream_domain = self.stream_domain;
        if !matches!(
            stream_domain,
            CanonicalStreamDomain::ReplayTargetIdentifierCiphertext
                | CanonicalStreamDomain::ReplayTargetOrderCiphertext
        ) {
            return Err(RefusalReason::WrongContext);
        }
        let stream_descriptor = self.finish()?;
        Ok(VerifiedCanonicalStreamSummary {
            stream_domain,
            stream_descriptor,
            state_exact_output_hash: None,
            target_release_output_bundle: None,
        })
    }

    fn absorb_chunk_inner(
        &mut self,
        chunk_index: usize,
        chunk_bytes: &[u8],
    ) -> Result<(), RefusalReason> {
        if chunk_index != self.next_chunk_index || chunk_index >= self.expected_chunk_count {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        let expected_byte_length = expected_chunk_byte_length(
            self.total_byte_length,
            self.expected_chunk_count,
            chunk_index,
        )?;
        if chunk_bytes.len() != expected_byte_length {
            return Err(RefusalReason::WrongTypeOrLength);
        }

        self.ordered_chunk_digests.push(chunk_digest(
            self.stream_domain,
            chunk_index,
            chunk_bytes,
        )?);
        self.full_object_hasher.update(chunk_bytes);
        self.observed_byte_length = self
            .observed_byte_length
            .checked_add(
                u64::try_from(chunk_bytes.len())
                    .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
            )
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        self.next_chunk_index += 1;
        Ok(())
    }
}

impl CanonicalStreamVerifier {
    pub fn new(
        stream_domain: CanonicalStreamDomain,
        descriptor: StreamDescriptor,
    ) -> Result<Self, RefusalReason> {
        validate_descriptor(&descriptor)?;
        let full_object_hasher = full_object_hasher(stream_domain, descriptor.total_byte_length)?;
        let state_exact_output_hasher = stream_domain
            .state_exact_output_capability_kind()
            .map(|capability_kind| {
                StateExactOutputHasher::new(capability_kind, descriptor.total_byte_length)
                    .map_err(|error| error.refusal_reason)
            })
            .transpose()?;
        let target_release_output_verifier = (stream_domain
            == CanonicalStreamDomain::StateTargetReleaseExactOutput)
            .then(|| {
                TargetReleaseOutputBundleVerifier::new(descriptor.total_byte_length).map(Box::new)
            })
            .transpose()?;
        Ok(Self {
            stream_domain,
            descriptor,
            next_chunk_index: 0,
            observed_byte_length: 0,
            full_object_hasher,
            state_exact_output_hasher,
            target_release_output_verifier,
            refusal_reason: None,
        })
    }

    pub(crate) const fn stream_descriptor(&self) -> &StreamDescriptor {
        &self.descriptor
    }

    pub fn absorb_chunk(
        &mut self,
        chunk_index: usize,
        chunk_bytes: &[u8],
    ) -> VerificationResult<()> {
        if let Some(refusal_reason) = self.refusal_reason {
            return VerificationResult::refused(refusal_reason);
        }
        let verification = self.verify_and_absorb_chunk(chunk_index, chunk_bytes);
        match verification {
            Ok(()) => VerificationResult::valid(()),
            Err(refusal_reason) => {
                self.refusal_reason = Some(refusal_reason);
                VerificationResult::refused(refusal_reason)
            }
        }
    }

    pub fn finish(self) -> VerificationResult<()> {
        match self.finish_with_summary() {
            VerificationResult::Valid { .. } => VerificationResult::valid(()),
            VerificationResult::Refused { refusal_reason } => {
                VerificationResult::refused(refusal_reason)
            }
        }
    }

    pub(crate) fn finish_with_summary(self) -> VerificationResult<VerifiedCanonicalStreamSummary> {
        if let Some(refusal_reason) = self.refusal_reason {
            return VerificationResult::refused(refusal_reason);
        }
        if self.next_chunk_index != self.descriptor.ordered_chunk_digests.len()
            || self.observed_byte_length != self.descriptor.total_byte_length
        {
            return VerificationResult::refused(RefusalReason::WrongTypeOrLength);
        }

        let full_object_digest = finish_full_object_hasher(self.full_object_hasher);
        if full_object_digest != self.descriptor.full_object_digest {
            return VerificationResult::refused(RefusalReason::WrongHashOrRoot);
        }

        let state_exact_output_hash = match self.state_exact_output_hasher {
            Some(hasher) => match hasher.finish() {
                Ok(digest) => Some(digest),
                Err(error) => return VerificationResult::refused(error.refusal_reason),
            },
            None => None,
        };
        let target_release_output_bundle = match self.target_release_output_verifier {
            Some(verifier) => match verifier.finish() {
                Ok(bundle) => Some(Box::new(bundle)),
                Err(refusal_reason) => return VerificationResult::refused(refusal_reason),
            },
            None => None,
        };
        VerificationResult::valid(VerifiedCanonicalStreamSummary {
            stream_domain: self.stream_domain,
            stream_descriptor: self.descriptor,
            state_exact_output_hash,
            target_release_output_bundle,
        })
    }

    fn verify_and_absorb_chunk(
        &mut self,
        chunk_index: usize,
        chunk_bytes: &[u8],
    ) -> Result<(), RefusalReason> {
        if chunk_index != self.next_chunk_index
            || chunk_index >= self.descriptor.ordered_chunk_digests.len()
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }

        let expected_chunk_byte_length = expected_chunk_byte_length(
            self.descriptor.total_byte_length,
            self.descriptor.ordered_chunk_digests.len(),
            chunk_index,
        )?;
        if chunk_bytes.len() != expected_chunk_byte_length {
            return Err(RefusalReason::WrongTypeOrLength);
        }

        let observed_chunk_digest = chunk_digest(self.stream_domain, chunk_index, chunk_bytes)?;
        if observed_chunk_digest != self.descriptor.ordered_chunk_digests[chunk_index] {
            return Err(RefusalReason::WrongHashOrRoot);
        }

        self.full_object_hasher.update(chunk_bytes);
        if let Some(hasher) = self.state_exact_output_hasher.as_mut() {
            hasher
                .absorb(chunk_bytes)
                .map_err(|error| error.refusal_reason)?;
        }
        if let Some(verifier) = self.target_release_output_verifier.as_mut() {
            verifier.absorb(chunk_bytes)?;
        }
        self.observed_byte_length = self
            .observed_byte_length
            .checked_add(
                u64::try_from(chunk_bytes.len())
                    .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
            )
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        self.next_chunk_index += 1;
        Ok(())
    }
}

const TARGET_RELEASE_OUTPUT_BUNDLE_SCHEMA_IDENTIFIER: u16 = 0x1622;
const TARGET_DECRYPTION_SHARE_PAYLOAD_SCHEMA_IDENTIFIER: u16 = 0x1620;
const TARGET_RELEASE_OUTPUT_BUNDLE_VERSION: u16 = 1;
const TARGET_RELEASE_OUTPUT_BUNDLE_HEADER_BYTE_LENGTH: usize = 4;
const CANONICAL_TUPLE_HEADER_BYTE_LENGTH: usize = 8;
const CANONICAL_ITEM_HEADER_BYTE_LENGTH: usize = 6;

struct TargetReleaseCarrierPayload {
    finality_hash: Hash512,
    reservation_intent_object_hash: Hash512,
    target_identifier_descriptor: Option<StreamDescriptor>,
    target_order_descriptor: Option<StreamDescriptor>,
    malicious_share_proof_descriptor: Option<StreamDescriptor>,
}

/// Verifies the self-delimiting target-release bundle while the outer exact
/// output is streamed. It buffers only the bounded signed carrier and one
/// canonical child chunk; proof-sized bytes are never assembled in memory.
struct TargetReleaseOutputBundleVerifier {
    expected_total_byte_length: u64,
    observed_total_byte_length: u64,
    header_bytes: Vec<u8>,
    canonical_signed_carrier: Vec<u8>,
    carrier_payload: Option<TargetReleaseCarrierPayload>,
    child_stream_position: usize,
    active_child_stream: Option<EmbeddedCanonicalStreamVerifier>,
    target_identifier_stream: Option<VerifiedCanonicalStreamSummary>,
    target_order_stream: Option<VerifiedCanonicalStreamSummary>,
    malicious_share_proof_stream: Option<VerifiedCanonicalStreamSummary>,
}

impl TargetReleaseOutputBundleVerifier {
    fn new(expected_total_byte_length: u64) -> Result<Self, RefusalReason> {
        if expected_total_byte_length
            <= u64::try_from(TARGET_RELEASE_OUTPUT_BUNDLE_HEADER_BYTE_LENGTH)
                .map_err(|_| RefusalReason::OutsideSupportedProfile)?
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        Ok(Self {
            expected_total_byte_length,
            observed_total_byte_length: 0,
            header_bytes: Vec::with_capacity(TARGET_RELEASE_OUTPUT_BUNDLE_HEADER_BYTE_LENGTH),
            canonical_signed_carrier: Vec::new(),
            carrier_payload: None,
            child_stream_position: 0,
            active_child_stream: None,
            target_identifier_stream: None,
            target_order_stream: None,
            malicious_share_proof_stream: None,
        })
    }

    fn absorb(&mut self, bytes: &[u8]) -> Result<(), RefusalReason> {
        let incoming_byte_length =
            u64::try_from(bytes.len()).map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        let next_observed_byte_length = self
            .observed_total_byte_length
            .checked_add(incoming_byte_length)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        if next_observed_byte_length > self.expected_total_byte_length {
            return Err(RefusalReason::WrongTypeOrLength);
        }

        let mut byte_offset = 0;
        while byte_offset < bytes.len() {
            if self.header_bytes.len() < TARGET_RELEASE_OUTPUT_BUNDLE_HEADER_BYTE_LENGTH {
                let needed = TARGET_RELEASE_OUTPUT_BUNDLE_HEADER_BYTE_LENGTH
                    .checked_sub(self.header_bytes.len())
                    .ok_or(RefusalReason::OutsideSupportedProfile)?;
                let consumed = needed.min(bytes.len() - byte_offset);
                self.header_bytes
                    .extend_from_slice(&bytes[byte_offset..byte_offset + consumed]);
                byte_offset += consumed;
                if self.header_bytes.len() == TARGET_RELEASE_OUTPUT_BUNDLE_HEADER_BYTE_LENGTH {
                    self.validate_header()?;
                }
                continue;
            }

            if self.carrier_payload.is_none() {
                let boundary = next_signed_carrier_boundary(&self.canonical_signed_carrier)?;
                let needed = boundary
                    .checked_sub(self.canonical_signed_carrier.len())
                    .ok_or(RefusalReason::MalformedEncoding)?;
                let consumed = needed.min(bytes.len() - byte_offset);
                self.canonical_signed_carrier
                    .extend_from_slice(&bytes[byte_offset..byte_offset + consumed]);
                byte_offset += consumed;
                if self.canonical_signed_carrier.len() == boundary
                    && signed_carrier_total_byte_length(&self.canonical_signed_carrier)?
                        == Some(boundary)
                {
                    self.initialize_child_streams()?;
                }
                continue;
            }

            let active_stream = self
                .active_child_stream
                .as_mut()
                .ok_or(RefusalReason::WrongTypeOrLength)?;
            let consumed = active_stream.absorb(&bytes[byte_offset..])?;
            if consumed == 0 {
                return Err(RefusalReason::WrongTypeOrLength);
            }
            byte_offset += consumed;
            if active_stream.is_complete() {
                self.finish_active_child_stream()?;
            }
        }

        self.observed_total_byte_length = next_observed_byte_length;
        Ok(())
    }

    fn finish(self) -> Result<VerifiedTargetReleaseOutputBundle, RefusalReason> {
        if self.observed_total_byte_length != self.expected_total_byte_length
            || self.child_stream_position != 3
            || self.active_child_stream.is_some()
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        let payload = self
            .carrier_payload
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        Ok(VerifiedTargetReleaseOutputBundle {
            canonical_signed_carrier: self.canonical_signed_carrier,
            finality_hash: payload.finality_hash,
            reservation_intent_object_hash: payload.reservation_intent_object_hash,
            target_identifier_stream: self
                .target_identifier_stream
                .ok_or(RefusalReason::WrongTypeOrLength)?,
            target_order_stream: self
                .target_order_stream
                .ok_or(RefusalReason::WrongTypeOrLength)?,
            malicious_share_proof_stream: self
                .malicious_share_proof_stream
                .ok_or(RefusalReason::WrongTypeOrLength)?,
        })
    }

    fn validate_header(&self) -> Result<(), RefusalReason> {
        let schema_identifier = u16::from_le_bytes(
            self.header_bytes[..2]
                .try_into()
                .map_err(|_| RefusalReason::MalformedEncoding)?,
        );
        let schema_version = u16::from_le_bytes(
            self.header_bytes[2..]
                .try_into()
                .map_err(|_| RefusalReason::MalformedEncoding)?,
        );
        if schema_identifier != TARGET_RELEASE_OUTPUT_BUNDLE_SCHEMA_IDENTIFIER {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        if schema_version != TARGET_RELEASE_OUTPUT_BUNDLE_VERSION {
            return Err(RefusalReason::UnsupportedVersionOrSuite);
        }
        Ok(())
    }

    fn initialize_child_streams(&mut self) -> Result<(), RefusalReason> {
        let mut payload = decode_target_release_carrier_payload(&self.canonical_signed_carrier)?;
        let expected_bundle_byte_length = [
            payload
                .target_identifier_descriptor
                .as_ref()
                .ok_or(RefusalReason::WrongTypeOrLength)?
                .total_byte_length,
            payload
                .target_order_descriptor
                .as_ref()
                .ok_or(RefusalReason::WrongTypeOrLength)?
                .total_byte_length,
            payload
                .malicious_share_proof_descriptor
                .as_ref()
                .ok_or(RefusalReason::WrongTypeOrLength)?
                .total_byte_length,
        ]
        .into_iter()
        .try_fold(
            u64::try_from(TARGET_RELEASE_OUTPUT_BUNDLE_HEADER_BYTE_LENGTH)
                .map_err(|_| RefusalReason::OutsideSupportedProfile)?
                .checked_add(
                    u64::try_from(self.canonical_signed_carrier.len())
                        .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
                )
                .ok_or(RefusalReason::OutsideSupportedProfile)?,
            |total, child_length| {
                total
                    .checked_add(child_length)
                    .ok_or(RefusalReason::OutsideSupportedProfile)
            },
        )?;
        if expected_bundle_byte_length != self.expected_total_byte_length {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        self.active_child_stream = Some(EmbeddedCanonicalStreamVerifier::new(
            CanonicalStreamDomain::TargetIdentifierPartialDecryption,
            payload
                .target_identifier_descriptor
                .take()
                .ok_or(RefusalReason::WrongTypeOrLength)?,
        )?);
        self.carrier_payload = Some(payload);
        Ok(())
    }

    fn finish_active_child_stream(&mut self) -> Result<(), RefusalReason> {
        let active_stream = self
            .active_child_stream
            .take()
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        let summary = active_stream.finish()?;
        let payload = self
            .carrier_payload
            .as_mut()
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        match self.child_stream_position {
            0 => {
                self.target_identifier_stream = Some(summary);
                self.active_child_stream = Some(EmbeddedCanonicalStreamVerifier::new(
                    CanonicalStreamDomain::TargetOrderPartialDecryption,
                    payload
                        .target_order_descriptor
                        .take()
                        .ok_or(RefusalReason::WrongTypeOrLength)?,
                )?);
            }
            1 => {
                self.target_order_stream = Some(summary);
                self.active_child_stream = Some(EmbeddedCanonicalStreamVerifier::new(
                    CanonicalStreamDomain::MaliciousTargetShareProof,
                    payload
                        .malicious_share_proof_descriptor
                        .take()
                        .ok_or(RefusalReason::WrongTypeOrLength)?,
                )?);
            }
            2 => {
                self.malicious_share_proof_stream = Some(summary);
            }
            _ => return Err(RefusalReason::WrongTypeOrLength),
        }
        self.child_stream_position += 1;
        Ok(())
    }
}

struct EmbeddedCanonicalStreamVerifier {
    verifier: CanonicalStreamVerifier,
    total_byte_length: u64,
    expected_chunk_count: usize,
    next_chunk_index: usize,
    observed_byte_length: u64,
    pending_chunk: Vec<u8>,
}

impl EmbeddedCanonicalStreamVerifier {
    fn new(
        stream_domain: CanonicalStreamDomain,
        descriptor: StreamDescriptor,
    ) -> Result<Self, RefusalReason> {
        let total_byte_length = descriptor.total_byte_length;
        let expected_chunk_count = descriptor.ordered_chunk_digests.len();
        let verifier = CanonicalStreamVerifier::new(stream_domain, descriptor)?;
        Ok(Self {
            verifier,
            total_byte_length,
            expected_chunk_count,
            next_chunk_index: 0,
            observed_byte_length: 0,
            pending_chunk: Vec::new(),
        })
    }

    fn absorb(&mut self, bytes: &[u8]) -> Result<usize, RefusalReason> {
        let remaining_byte_length = self
            .total_byte_length
            .checked_sub(self.observed_byte_length)
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        let consumed =
            usize::try_from(remaining_byte_length.min(
                u64::try_from(bytes.len()).map_err(|_| RefusalReason::OutsideSupportedProfile)?,
            ))
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        let mut byte_offset = 0;
        while byte_offset < consumed {
            let expected_chunk_length = expected_chunk_byte_length(
                self.total_byte_length,
                self.expected_chunk_count,
                self.next_chunk_index,
            )?;
            let needed = expected_chunk_length
                .checked_sub(self.pending_chunk.len())
                .ok_or(RefusalReason::WrongTypeOrLength)?;
            let copied = needed.min(consumed - byte_offset);
            self.pending_chunk
                .extend_from_slice(&bytes[byte_offset..byte_offset + copied]);
            byte_offset += copied;
            self.observed_byte_length = self
                .observed_byte_length
                .checked_add(
                    u64::try_from(copied).map_err(|_| RefusalReason::OutsideSupportedProfile)?,
                )
                .ok_or(RefusalReason::OutsideSupportedProfile)?;
            if self.pending_chunk.len() == expected_chunk_length {
                self.verifier
                    .absorb_chunk(self.next_chunk_index, &self.pending_chunk)
                    .into_result()?;
                self.pending_chunk.clear();
                self.next_chunk_index += 1;
            }
        }
        Ok(consumed)
    }

    const fn is_complete(&self) -> bool {
        self.observed_byte_length == self.total_byte_length
    }

    fn finish(self) -> Result<VerifiedCanonicalStreamSummary, RefusalReason> {
        if !self.pending_chunk.is_empty()
            || self.next_chunk_index != self.expected_chunk_count
            || self.observed_byte_length != self.total_byte_length
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        self.verifier.finish_with_summary().into_result()
    }
}

fn next_signed_carrier_boundary(carrier_bytes: &[u8]) -> Result<usize, RefusalReason> {
    if carrier_bytes.len() < CANONICAL_TUPLE_HEADER_BYTE_LENGTH + CANONICAL_ITEM_HEADER_BYTE_LENGTH
    {
        return Ok(CANONICAL_TUPLE_HEADER_BYTE_LENGTH + CANONICAL_ITEM_HEADER_BYTE_LENGTH);
    }
    validate_signed_carrier_tuple_header(carrier_bytes)?;
    let first_item_byte_length = read_u32_at(carrier_bytes, 10)? as usize;
    let second_item_header_end = CANONICAL_TUPLE_HEADER_BYTE_LENGTH
        .checked_add(CANONICAL_ITEM_HEADER_BYTE_LENGTH)
        .and_then(|length| length.checked_add(first_item_byte_length))
        .and_then(|length| length.checked_add(CANONICAL_ITEM_HEADER_BYTE_LENGTH))
        .ok_or(RefusalReason::OutsideSupportedProfile)?;
    if second_item_header_end > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length {
        return Err(RefusalReason::OutsideSupportedProfile);
    }
    if carrier_bytes.len() < second_item_header_end {
        return Ok(second_item_header_end);
    }
    if read_u16_at(
        carrier_bytes,
        second_item_header_end - CANONICAL_ITEM_HEADER_BYTE_LENGTH,
    )? != CanonicalItemType::RawBytes.canonical_code()
        || read_u32_at(carrier_bytes, second_item_header_end - 4)? as usize
            != ML_DSA_65_SIGNATURE_BYTE_LENGTH
    {
        return Err(RefusalReason::MalformedEncoding);
    }
    let total_byte_length = second_item_header_end
        .checked_add(ML_DSA_65_SIGNATURE_BYTE_LENGTH)
        .ok_or(RefusalReason::OutsideSupportedProfile)?;
    if total_byte_length > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length {
        return Err(RefusalReason::OutsideSupportedProfile);
    }
    Ok(total_byte_length)
}

fn signed_carrier_total_byte_length(carrier_bytes: &[u8]) -> Result<Option<usize>, RefusalReason> {
    let boundary = next_signed_carrier_boundary(carrier_bytes)?;
    Ok((carrier_bytes.len() == boundary).then_some(boundary))
}

fn validate_signed_carrier_tuple_header(carrier_bytes: &[u8]) -> Result<(), RefusalReason> {
    if read_u16_at(carrier_bytes, 0)? != SIGNED_CARRIER_SCHEMA_IDENTIFIER {
        return Err(RefusalReason::WrongTypeOrLength);
    }
    if read_u16_at(carrier_bytes, 2)? != CANONICAL_TUPLE_VERSION {
        return Err(RefusalReason::UnsupportedVersionOrSuite);
    }
    if read_u32_at(carrier_bytes, 4)? != 2
        || read_u16_at(carrier_bytes, 8)? != CanonicalItemType::RawBytes.canonical_code()
    {
        return Err(RefusalReason::MalformedEncoding);
    }
    Ok(())
}

fn decode_target_release_carrier_payload(
    canonical_signed_carrier: &[u8],
) -> Result<TargetReleaseCarrierPayload, RefusalReason> {
    let limits = CanonicalDecodeLimits::default();
    let carrier = SignedCarrier::decode(canonical_signed_carrier, &limits)
        .map_err(|error| error.refusal_reason)?;
    if carrier.envelope.object_type != FoundationObjectType::TargetDecryptionShare {
        return Err(RefusalReason::WrongTypeOrLength);
    }
    let payload = CanonicalTuple::decode(&carrier.envelope.payload_bytes, &limits)
        .map_err(|_| RefusalReason::MalformedEncoding)?;
    if payload.schema_identifier != TARGET_DECRYPTION_SHARE_PAYLOAD_SCHEMA_IDENTIFIER
        || payload.schema_version != TARGET_RELEASE_OUTPUT_BUNDLE_VERSION
        || payload.items.len() != 5
    {
        return Err(RefusalReason::WrongTypeOrLength);
    }
    Ok(TargetReleaseCarrierPayload {
        finality_hash: read_hash_item(&payload.items[0])?,
        reservation_intent_object_hash: read_hash_item(&payload.items[1])?,
        target_identifier_descriptor: Some(read_stream_descriptor_item(
            &payload.items[2],
            &limits,
        )?),
        target_order_descriptor: Some(read_stream_descriptor_item(&payload.items[3], &limits)?),
        malicious_share_proof_descriptor: Some(read_stream_descriptor_item(
            &payload.items[4],
            &limits,
        )?),
    })
}

fn read_hash_item(item: &super::CanonicalItem) -> Result<Hash512, RefusalReason> {
    if item.item_type() != CanonicalItemType::Hash512
        || item.canonical_bytes().len() != Hash512::BYTE_LENGTH
    {
        return Err(RefusalReason::MalformedEncoding);
    }
    Ok(Hash512::from_bytes(
        item.canonical_bytes()
            .try_into()
            .map_err(|_| RefusalReason::MalformedEncoding)?,
    ))
}

fn read_stream_descriptor_item(
    item: &super::CanonicalItem,
    limits: &CanonicalDecodeLimits,
) -> Result<StreamDescriptor, RefusalReason> {
    if item.item_type() != CanonicalItemType::NestedTuple {
        return Err(RefusalReason::MalformedEncoding);
    }
    StreamDescriptor::decode(item.canonical_bytes(), limits).map_err(|error| error.refusal_reason)
}

fn read_u16_at(bytes: &[u8], byte_offset: usize) -> Result<u16, RefusalReason> {
    let byte_end = byte_offset
        .checked_add(2)
        .ok_or(RefusalReason::OutsideSupportedProfile)?;
    Ok(u16::from_le_bytes(
        bytes
            .get(byte_offset..byte_end)
            .ok_or(RefusalReason::MalformedEncoding)?
            .try_into()
            .map_err(|_| RefusalReason::MalformedEncoding)?,
    ))
}

fn read_u32_at(bytes: &[u8], byte_offset: usize) -> Result<u32, RefusalReason> {
    let byte_end = byte_offset
        .checked_add(4)
        .ok_or(RefusalReason::OutsideSupportedProfile)?;
    Ok(u32::from_le_bytes(
        bytes
            .get(byte_offset..byte_end)
            .ok_or(RefusalReason::MalformedEncoding)?
            .try_into()
            .map_err(|_| RefusalReason::MalformedEncoding)?,
    ))
}

/// Derives the canonical descriptor for an in-memory stream body.
///
/// Stream producers use the same verifier-owned domain registry and framing as
/// incremental consumers. This in-memory convenience function delegates to
/// the incremental writer so both producer paths have one implementation.
pub fn derive_canonical_stream_descriptor(
    stream_domain: CanonicalStreamDomain,
    stream_bytes: &[u8],
) -> Result<StreamDescriptor, RefusalReason> {
    let total_byte_length =
        u64::try_from(stream_bytes.len()).map_err(|_| RefusalReason::OutsideSupportedProfile)?;
    let mut writer = CanonicalStreamWriter::new(stream_domain, total_byte_length)?;
    for (chunk_index, chunk_bytes) in stream_bytes
        .chunks(FOUNDATION_PROFILE.stream_chunk_byte_length)
        .enumerate()
    {
        writer.absorb_chunk(chunk_index, chunk_bytes)?;
    }
    writer.finish()
}

fn validate_descriptor(descriptor: &StreamDescriptor) -> Result<(), RefusalReason> {
    let expected_chunk_count = expected_chunk_count(descriptor.total_byte_length)?;
    if descriptor.ordered_chunk_digests.len() != expected_chunk_count {
        return Err(RefusalReason::WrongTypeOrLength);
    }

    Ok(())
}

fn expected_chunk_count(total_byte_length: u64) -> Result<usize, RefusalReason> {
    if total_byte_length == 0 {
        return Err(RefusalReason::WrongTypeOrLength);
    }
    if total_byte_length > MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH {
        return Err(RefusalReason::OutsideSupportedProfile);
    }
    let chunk_byte_length = u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length)
        .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
    usize::try_from(1 + (total_byte_length - 1) / chunk_byte_length)
        .map_err(|_| RefusalReason::OutsideSupportedProfile)
}

fn expected_chunk_byte_length(
    total_byte_length: u64,
    chunk_count: usize,
    chunk_index: usize,
) -> Result<usize, RefusalReason> {
    if chunk_index >= chunk_count {
        return Err(RefusalReason::WrongTypeOrLength);
    }
    if chunk_index + 1 < chunk_count {
        return Ok(FOUNDATION_PROFILE.stream_chunk_byte_length);
    }

    let preceding_chunk_count =
        u64::try_from(chunk_count - 1).map_err(|_| RefusalReason::OutsideSupportedProfile)?;
    let chunk_byte_length = u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length)
        .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
    let preceding_byte_length = preceding_chunk_count
        .checked_mul(chunk_byte_length)
        .ok_or(RefusalReason::OutsideSupportedProfile)?;
    usize::try_from(
        total_byte_length
            .checked_sub(preceding_byte_length)
            .ok_or(RefusalReason::WrongTypeOrLength)?,
    )
    .map_err(|_| RefusalReason::OutsideSupportedProfile)
}

fn chunk_digest(
    stream_domain: CanonicalStreamDomain,
    chunk_index: usize,
    chunk_bytes: &[u8],
) -> Result<Hash512, RefusalReason> {
    let chunk_index =
        u32::try_from(chunk_index).map_err(|_| RefusalReason::OutsideSupportedProfile)?;
    let chunk_byte_length =
        u32::try_from(chunk_bytes.len()).map_err(|_| RefusalReason::OutsideSupportedProfile)?;
    let raw_item_byte_length = chunk_byte_length
        .checked_add(4)
        .ok_or(RefusalReason::OutsideSupportedProfile)?;
    let mut hasher = Shake256::default();
    hasher.update(&CANONICAL_TUPLE_SCHEMA_IDENTIFIER.to_le_bytes());
    hasher.update(&CANONICAL_TUPLE_VERSION.to_le_bytes());
    hasher.update(&5_u32.to_le_bytes());
    absorb_ascii_item(&mut hasher, CHUNK_DIGEST_DOMAIN)?;
    absorb_ascii_item(&mut hasher, stream_domain.canonical_domain())?;
    absorb_fixed_item(
        &mut hasher,
        CanonicalItemType::Unsigned32,
        &chunk_index.to_le_bytes(),
    )?;
    absorb_fixed_item(
        &mut hasher,
        CanonicalItemType::Unsigned32,
        &chunk_byte_length.to_le_bytes(),
    )?;
    hasher.update(&CanonicalItemType::RawBytes.canonical_code().to_le_bytes());
    hasher.update(&raw_item_byte_length.to_le_bytes());
    hasher.update(&chunk_byte_length.to_le_bytes());
    hasher.update(chunk_bytes);

    let mut reader = hasher.finalize_xof();
    let mut digest = [0_u8; Hash512::BYTE_LENGTH];
    reader.read(&mut digest);
    Ok(Hash512::from_bytes(digest))
}

fn full_object_hasher(
    stream_domain: CanonicalStreamDomain,
    total_byte_length: u64,
) -> Result<Shake256, RefusalReason> {
    let object_byte_length =
        u32::try_from(total_byte_length).map_err(|_| RefusalReason::OutsideSupportedProfile)?;
    let raw_item_byte_length = object_byte_length
        .checked_add(CANONICAL_RAW_BYTES_LENGTH_PREFIX_BYTE_LENGTH)
        .ok_or(RefusalReason::OutsideSupportedProfile)?;
    let mut hasher = Shake256::default();
    hasher.update(&CANONICAL_TUPLE_SCHEMA_IDENTIFIER.to_le_bytes());
    hasher.update(&CANONICAL_TUPLE_VERSION.to_le_bytes());
    hasher.update(&4_u32.to_le_bytes());
    absorb_ascii_item(&mut hasher, FULL_OBJECT_DIGEST_DOMAIN)?;
    absorb_ascii_item(&mut hasher, stream_domain.canonical_domain())?;
    absorb_fixed_item(
        &mut hasher,
        CanonicalItemType::Unsigned64,
        &total_byte_length.to_le_bytes(),
    )?;
    hasher.update(&CanonicalItemType::RawBytes.canonical_code().to_le_bytes());
    hasher.update(&raw_item_byte_length.to_le_bytes());
    hasher.update(&object_byte_length.to_le_bytes());
    Ok(hasher)
}

fn finish_full_object_hasher(hasher: Shake256) -> Hash512 {
    let mut reader = hasher.finalize_xof();
    let mut digest = [0_u8; Hash512::BYTE_LENGTH];
    reader.read(&mut digest);
    Hash512::from_bytes(digest)
}

fn absorb_ascii_item(hasher: &mut Shake256, value: &str) -> Result<(), RefusalReason> {
    if value.is_empty()
        || !value
            .as_bytes()
            .iter()
            .all(|byte| matches!(byte, 0x20..=0x7e))
    {
        return Err(RefusalReason::MalformedEncoding);
    }
    let value_byte_length =
        u32::try_from(value.len()).map_err(|_| RefusalReason::OutsideSupportedProfile)?;
    let item_byte_length = value_byte_length
        .checked_add(4)
        .ok_or(RefusalReason::OutsideSupportedProfile)?;
    hasher.update(&CanonicalItemType::Ascii.canonical_code().to_le_bytes());
    hasher.update(&item_byte_length.to_le_bytes());
    hasher.update(&value_byte_length.to_le_bytes());
    hasher.update(value.as_bytes());
    Ok(())
}

fn absorb_fixed_item(
    hasher: &mut Shake256,
    item_type: CanonicalItemType,
    canonical_bytes: &[u8],
) -> Result<(), RefusalReason> {
    let item_byte_length =
        u32::try_from(canonical_bytes.len()).map_err(|_| RefusalReason::OutsideSupportedProfile)?;
    hasher.update(&item_type.canonical_code().to_le_bytes());
    hasher.update(&item_byte_length.to_le_bytes());
    hasher.update(canonical_bytes);
    Ok(())
}

#[cfg(test)]
pub(super) fn canonical_target_release_exact_output_fixture(
    target_identifier_bytes: &[u8],
    target_order_bytes: &[u8],
    malicious_share_proof_bytes: &[u8],
) -> Vec<u8> {
    let target_identifier_descriptor = derive_canonical_stream_descriptor(
        CanonicalStreamDomain::TargetIdentifierPartialDecryption,
        target_identifier_bytes,
    )
    .expect("test target-identifier descriptor derives");
    let target_order_descriptor = derive_canonical_stream_descriptor(
        CanonicalStreamDomain::TargetOrderPartialDecryption,
        target_order_bytes,
    )
    .expect("test target-order descriptor derives");
    let malicious_share_proof_descriptor = derive_canonical_stream_descriptor(
        CanonicalStreamDomain::MaliciousTargetShareProof,
        malicious_share_proof_bytes,
    )
    .expect("test target-share proof descriptor derives");
    let payload = canonical_target_release_output_payload(
        Hash512::from_bytes([0x31; Hash512::BYTE_LENGTH]),
        Hash512::from_bytes([0x32; Hash512::BYTE_LENGTH]),
        &target_identifier_descriptor,
        &target_order_descriptor,
        &malicious_share_proof_descriptor,
    )
    .expect("test target-release payload encodes");
    let carrier = SignedCarrier {
        envelope: ObjectEnvelope {
            suite_id: Hash512::from_bytes([0x11; Hash512::BYTE_LENGTH]),
            object_type: FoundationObjectType::TargetDecryptionShare,
            ceremony_context_hash: Hash512::from_bytes([0x12; Hash512::BYTE_LENGTH]),
            action_context_hash: Hash512::from_bytes([0x13; Hash512::BYTE_LENGTH]),
            producer_participant_id: Some(ParticipantIdentity::from_bytes(
                [0x14; ParticipantIdentity::BYTE_LENGTH],
            )),
            producer_sequence: 0,
            ordered_prerequisite_hashes: Vec::new(),
            payload_bytes: payload,
        },
        signature: [0x15; ML_DSA_65_SIGNATURE_BYTE_LENGTH],
    }
    .encode()
    .expect("test target-release carrier encodes");
    let mut bundle = Vec::new();
    bundle.extend_from_slice(&TARGET_RELEASE_OUTPUT_BUNDLE_SCHEMA_IDENTIFIER.to_le_bytes());
    bundle.extend_from_slice(&TARGET_RELEASE_OUTPUT_BUNDLE_VERSION.to_le_bytes());
    bundle.extend_from_slice(&carrier);
    bundle.extend_from_slice(target_identifier_bytes);
    bundle.extend_from_slice(target_order_bytes);
    bundle.extend_from_slice(malicious_share_proof_bytes);
    bundle
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    fn descriptor_for(stream_domain: CanonicalStreamDomain, bytes: &[u8]) -> StreamDescriptor {
        derive_canonical_stream_descriptor(stream_domain, bytes).expect("test descriptor is valid")
    }

    fn verify_stream_with_summary(
        stream_domain: CanonicalStreamDomain,
        bytes: &[u8],
    ) -> VerifiedCanonicalStreamSummary {
        let descriptor = descriptor_for(stream_domain, bytes);
        let mut verifier =
            CanonicalStreamVerifier::new(stream_domain, descriptor).expect("stream begins");
        for (chunk_index, chunk) in bytes
            .chunks(FOUNDATION_PROFILE.stream_chunk_byte_length)
            .enumerate()
        {
            verifier
                .absorb_chunk(chunk_index, chunk)
                .into_result()
                .expect("chunk verifies");
        }
        verifier
            .finish_with_summary()
            .into_result()
            .expect("stream finishes")
    }

    #[test]
    fn target_release_exact_output_authenticates_misaligned_nested_streams_incrementally() {
        let target_identifier_bytes = vec![0x41; 37];
        let target_order_bytes = vec![0x42; 53];
        let proof_bytes = vec![0x43; FOUNDATION_PROFILE.stream_chunk_byte_length + 29];
        let bundle_bytes = canonical_target_release_exact_output_fixture(
            &target_identifier_bytes,
            &target_order_bytes,
            &proof_bytes,
        );

        let summary = verify_stream_with_summary(
            CanonicalStreamDomain::StateTargetReleaseExactOutput,
            &bundle_bytes,
        );
        let bundle = summary
            .into_target_release_output_bundle()
            .expect("typed target bundle");
        assert_eq!(bundle.finality_hash(), Hash512::from_bytes([0x31; 64]));
        assert_eq!(
            bundle.reservation_intent_object_hash(),
            Hash512::from_bytes([0x32; 64])
        );
        let byte_lengths = bundle.byte_lengths().expect("bundle byte lengths derive");
        assert_eq!(
            byte_lengths.header(),
            u64::try_from(TARGET_RELEASE_OUTPUT_BUNDLE_HEADER_BYTE_LENGTH)
                .expect("test header byte length fits u64")
        );
        assert_eq!(
            byte_lengths.signed_carrier(),
            u64::try_from(bundle.canonical_signed_carrier().len())
                .expect("test carrier byte length fits u64")
        );
        assert_eq!(
            byte_lengths.target_identifier(),
            u64::try_from(target_identifier_bytes.len())
                .expect("test target-identifier byte length fits u64")
        );
        assert_eq!(
            byte_lengths.target_order(),
            u64::try_from(target_order_bytes.len())
                .expect("test target-order byte length fits u64")
        );
        assert_eq!(
            byte_lengths.malicious_share_proof(),
            u64::try_from(proof_bytes.len()).expect("test proof byte length fits u64")
        );
        assert_eq!(
            byte_lengths.total(),
            u64::try_from(bundle_bytes.len()).expect("test bundle byte length fits u64")
        );

        let mut proof_readback = bundle
            .open_malicious_share_proof_readback()
            .expect("proof readback begins");
        for (chunk_index, chunk) in proof_bytes
            .chunks(FOUNDATION_PROFILE.stream_chunk_byte_length)
            .enumerate()
        {
            proof_readback
                .authenticate_chunk(chunk_index, chunk)
                .expect("proof readback chunk");
        }
        proof_readback
            .finish()
            .into_result()
            .expect("proof readback finishes");
    }

    #[test]
    fn target_release_exact_output_rejects_extension_and_nested_stream_substitution() {
        let target_identifier_bytes = vec![0x51; 17];
        let target_order_bytes = vec![0x52; 19];
        let proof_bytes = vec![0x53; 23];
        let bundle_bytes = canonical_target_release_exact_output_fixture(
            &target_identifier_bytes,
            &target_order_bytes,
            &proof_bytes,
        );
        let mut extended = bundle_bytes.clone();
        extended.push(0);
        let extended_descriptor = descriptor_for(
            CanonicalStreamDomain::StateTargetReleaseExactOutput,
            &extended,
        );
        let mut extended_verifier = CanonicalStreamVerifier::new(
            CanonicalStreamDomain::StateTargetReleaseExactOutput,
            extended_descriptor,
        )
        .expect("extended stream begins");
        assert!(
            extended_verifier
                .absorb_chunk(0, &extended)
                .into_result()
                .is_err()
        );

        let mut substituted = bundle_bytes;
        let target_byte_offset = substituted.len()
            - target_identifier_bytes.len()
            - target_order_bytes.len()
            - proof_bytes.len();
        substituted[target_byte_offset] ^= 1;
        let substituted_descriptor = descriptor_for(
            CanonicalStreamDomain::StateTargetReleaseExactOutput,
            &substituted,
        );
        let mut substituted_verifier = CanonicalStreamVerifier::new(
            CanonicalStreamDomain::StateTargetReleaseExactOutput,
            substituted_descriptor,
        )
        .expect("substituted stream begins");
        assert!(
            substituted_verifier
                .absorb_chunk(0, &substituted)
                .into_result()
                .is_err()
        );
    }

    #[test]
    fn stream_domains_have_unique_labels_and_codes() {
        let assigned_domains = [
            CanonicalStreamDomain::PrivateMailboxCiphertext,
            CanonicalStreamDomain::DealerVssShareLinkageProof,
            CanonicalStreamDomain::RecipientAggregateThresholdShareProof,
            CanonicalStreamDomain::SameSecretProof,
            CanonicalStreamDomain::PublicKeyShareProof,
            CanonicalStreamDomain::CollectivePublicKeyAggregateProof,
            CanonicalStreamDomain::RkgRoundOneProof,
            CanonicalStreamDomain::RkgRoundOneAggregateProof,
            CanonicalStreamDomain::RkgRoundTwoProof,
            CanonicalStreamDomain::GaloisShareProof,
            CanonicalStreamDomain::EvaluatorKeyAggregateProof,
            CanonicalStreamDomain::CollectivePublicKey,
            CanonicalStreamDomain::EvaluatorKeyStore,
            CanonicalStreamDomain::BallotCiphertext,
            CanonicalStreamDomain::BallotValidityProof,
            CanonicalStreamDomain::AggregateCiphertext,
            CanonicalStreamDomain::ReplayTargetIdentifierCiphertext,
            CanonicalStreamDomain::ReplayTargetOrderCiphertext,
            CanonicalStreamDomain::TargetIdentifierPartialDecryption,
            CanonicalStreamDomain::TargetOrderPartialDecryption,
            CanonicalStreamDomain::MaliciousTargetShareProof,
            CanonicalStreamDomain::CheckpointState,
            CanonicalStreamDomain::StateFinalitySignatureExactOutput,
            CanonicalStreamDomain::StateTargetReleaseExactOutput,
            CanonicalStreamDomain::PublicKeyShareMaterial,
        ];
        for stream_domain in assigned_domains {
            let canonical_code = stream_domain.canonical_code();
            assert_eq!(
                CanonicalStreamDomain::from_canonical_code(canonical_code),
                Some(stream_domain)
            );
        }

        let domains = assigned_domains
            .into_iter()
            .map(CanonicalStreamDomain::canonical_domain)
            .collect::<BTreeSet<_>>();
        assert_eq!(domains.len(), assigned_domains.len());
        assert!(
            domains
                .iter()
                .all(|domain| domain.starts_with("sealed-lattice/stream/"))
        );
        let codes = assigned_domains
            .into_iter()
            .map(CanonicalStreamDomain::canonical_code)
            .collect::<BTreeSet<_>>();
        assert_eq!(codes.len(), assigned_domains.len());
        assert_eq!(CanonicalStreamDomain::from_canonical_code(0), None);
        assert_eq!(CanonicalStreamDomain::from_canonical_code(27), None);
        assert_eq!(CanonicalStreamDomain::from_canonical_code(28), None);
        assert_eq!(CanonicalStreamDomain::from_canonical_code(u32::MAX), None);
    }

    #[test]
    fn state_exact_output_streams_preserve_the_raw_byte_hash_relation() {
        let finality_signature_bytes = (0..FOUNDATION_PROFILE.stream_chunk_byte_length + 19)
            .map(|index| (index.wrapping_mul(211) & 0xff) as u8)
            .collect::<Vec<_>>();
        let target_release_bytes = canonical_target_release_exact_output_fixture(
            b"target identifier partial decryption",
            b"target order partial decryption",
            &finality_signature_bytes,
        );
        for (stream_domain, capability_kind, bytes) in [
            (
                CanonicalStreamDomain::StateFinalitySignatureExactOutput,
                StateCapabilityKind::FinalitySignature,
                finality_signature_bytes,
            ),
            (
                CanonicalStreamDomain::StateTargetReleaseExactOutput,
                StateCapabilityKind::TargetRelease,
                target_release_bytes,
            ),
        ] {
            let descriptor = descriptor_for(stream_domain, bytes.as_slice());
            let mut verifier = CanonicalStreamVerifier::new(stream_domain, descriptor)
                .expect("state exact-output verifier begins");
            for (chunk_index, chunk) in bytes
                .chunks(FOUNDATION_PROFILE.stream_chunk_byte_length)
                .enumerate()
            {
                assert_eq!(
                    verifier.absorb_chunk(chunk_index, chunk),
                    VerificationResult::valid(())
                );
            }
            let summary = verifier
                .finish_with_summary()
                .into_result()
                .expect("complete exact-output stream verifies");
            assert_eq!(summary.stream_domain(), stream_domain);
            assert_eq!(summary.total_byte_length(), bytes.len() as u64);
            assert_eq!(
                summary.full_object_digest(),
                descriptor_for(stream_domain, bytes.as_slice()).full_object_digest
            );
            assert_eq!(
                summary.state_exact_output_hash(),
                Some(
                    crate::foundation::derive_state_exact_output_hash(capability_kind, &bytes)
                        .expect("in-memory relation derives")
                )
            );
        }
    }

    #[test]
    fn allocation_free_chunk_hash_framing_matches_the_canonical_hash() {
        for byte_length in [
            1_usize,
            31,
            65_535,
            FOUNDATION_PROFILE.stream_chunk_byte_length,
        ] {
            let bytes = (0..byte_length)
                .map(|index| (index.wrapping_mul(149) & 0xff) as u8)
                .collect::<Vec<_>>();
            let chunk_index = 7_usize;
            let expected = hash512(
                CHUNK_DIGEST_DOMAIN,
                &[
                    CanonicalItem::nonempty_ascii(
                        CanonicalStreamDomain::PublicKeyShareProof.canonical_domain(),
                    )
                    .expect("stream domain"),
                    CanonicalItem::unsigned32(u32::try_from(chunk_index).expect("chunk index")),
                    CanonicalItem::unsigned32(
                        u32::try_from(bytes.len()).expect("chunk byte length"),
                    ),
                    CanonicalItem::variable_bytes(&bytes).expect("chunk bytes"),
                ],
            )
            .expect("canonical chunk digest");
            assert_eq!(
                chunk_digest(
                    CanonicalStreamDomain::PublicKeyShareProof,
                    chunk_index,
                    &bytes,
                )
                .expect("incremental chunk digest"),
                expected
            );
        }
    }

    #[test]
    fn allocation_free_full_object_hash_framing_matches_the_canonical_hash() {
        for byte_length in [1_usize, 31, 65_535, 1_048_593] {
            let bytes = (0..byte_length)
                .map(|index| (index.wrapping_mul(173) & 0xff) as u8)
                .collect::<Vec<_>>();
            let expected = hash512(
                FULL_OBJECT_DIGEST_DOMAIN,
                &[
                    CanonicalItem::nonempty_ascii(
                        CanonicalStreamDomain::BallotValidityProof.canonical_domain(),
                    )
                    .expect("stream domain"),
                    CanonicalItem::unsigned64(
                        u64::try_from(bytes.len()).expect("object byte length"),
                    ),
                    CanonicalItem::variable_bytes(&bytes).expect("object bytes"),
                ],
            )
            .expect("canonical full-object digest");
            let descriptor = descriptor_for(CanonicalStreamDomain::BallotValidityProof, &bytes);
            assert_eq!(descriptor.full_object_digest, expected);
        }
    }

    #[test]
    fn incremental_stream_verification_accepts_exact_boundary_lengths() {
        for byte_length in [1_usize, 31, 65_535, 1_048_576, 1_048_593] {
            let bytes = (0..byte_length)
                .map(|index| (index.wrapping_mul(131) & 0xff) as u8)
                .collect::<Vec<_>>();
            let descriptor = descriptor_for(CanonicalStreamDomain::PublicKeyShareMaterial, &bytes);
            let mut verifier = CanonicalStreamVerifier::new(
                CanonicalStreamDomain::PublicKeyShareMaterial,
                descriptor,
            )
            .expect("descriptor begins a verifier");
            for (chunk_index, chunk) in bytes
                .chunks(FOUNDATION_PROFILE.stream_chunk_byte_length)
                .enumerate()
            {
                assert_eq!(
                    verifier.absorb_chunk(chunk_index, chunk),
                    VerificationResult::valid(())
                );
            }
            assert_eq!(verifier.finish(), VerificationResult::valid(()));
        }
    }

    #[test]
    fn authenticated_readback_accepts_every_descriptor_chunk_in_arbitrary_order() {
        let stream_domain = CanonicalStreamDomain::BallotValidityProof;
        let bytes = (0..FOUNDATION_PROFILE.stream_chunk_byte_length + 37)
            .map(|index| (index.wrapping_mul(157) & 0xff) as u8)
            .collect::<Vec<_>>();
        let descriptor = descriptor_for(stream_domain, &bytes);
        let chunks = bytes
            .chunks(FOUNDATION_PROFILE.stream_chunk_byte_length)
            .collect::<Vec<_>>();
        let mut sequential_verifier =
            CanonicalStreamVerifier::new(stream_domain, descriptor.clone())
                .expect("descriptor begins sequential verification");
        for (chunk_index, chunk) in chunks.iter().copied().enumerate() {
            assert_eq!(
                sequential_verifier.absorb_chunk(chunk_index, chunk),
                VerificationResult::valid(())
            );
        }
        let verified_summary = sequential_verifier
            .finish_with_summary()
            .into_result()
            .expect("the sequential stream verifies");

        let mut readback = CanonicalStreamReadbackVerifier::new(stream_domain, verified_summary)
            .expect("the verified descriptor begins authenticated readback");
        assert_eq!(readback.chunk_count(), 2);
        assert_eq!(readback.total_byte_length(), bytes.len() as u64);
        assert_eq!(readback.authenticate_chunk(1, chunks[1]), Ok(()));
        assert_eq!(readback.authenticate_chunk(1, chunks[1]), Ok(()));
        assert_eq!(readback.authenticate_chunk(0, chunks[0]), Ok(()));
        let summary = readback
            .finish()
            .into_result()
            .expect("every descriptor chunk was authenticated");
        assert_eq!(summary.stream_domain(), stream_domain);
        assert_eq!(summary.total_byte_length(), bytes.len() as u64);
    }

    #[test]
    fn authenticated_readback_releases_visit_flags_and_reauthenticates_replayed_chunks() {
        let stream_domain = CanonicalStreamDomain::EvaluatorKeyStore;
        let bytes = (0..FOUNDATION_PROFILE.stream_chunk_byte_length + 29)
            .map(|index| (index.wrapping_mul(211) & 0xff) as u8)
            .collect::<Vec<_>>();
        let descriptor = descriptor_for(stream_domain, &bytes);
        let chunks = bytes
            .chunks(FOUNDATION_PROFILE.stream_chunk_byte_length)
            .collect::<Vec<_>>();
        let verified_summary = {
            let mut verifier = CanonicalStreamVerifier::new(stream_domain, descriptor)
                .expect("descriptor begins sequential verification");
            for (chunk_index, chunk) in chunks.iter().copied().enumerate() {
                assert_eq!(
                    verifier.absorb_chunk(chunk_index, chunk),
                    VerificationResult::valid(())
                );
            }
            verifier
                .finish_with_summary()
                .into_result()
                .expect("the sequential stream verifies")
        };
        let mut readback = CanonicalStreamReadbackVerifier::new(stream_domain, verified_summary)
            .expect("verified descriptor begins readback");
        for (chunk_index, chunk) in chunks.iter().copied().enumerate() {
            readback
                .authenticate_chunk(chunk_index, chunk)
                .expect("the complete initial readback authenticates");
        }
        assert_eq!(
            readback.finish_initial_pass(),
            VerificationResult::valid(())
        );
        assert_eq!(readback.authenticated_chunks.len(), 0);
        assert_eq!(readback.authenticated_chunk_count, 0);
        readback
            .authenticate_chunk(1, chunks[1])
            .expect("a replayed chunk authenticates from the retained verified digest");

        let mut substituted = chunks[0].to_vec();
        substituted[9] ^= 1;
        assert_eq!(
            readback.authenticate_chunk(0, &substituted),
            Err(RefusalReason::WrongHashOrRoot)
        );
        assert!(matches!(
            readback.finish().into_result(),
            Err(RefusalReason::WrongHashOrRoot)
        ));
    }

    #[test]
    fn authenticated_readback_refuses_missing_substituted_and_wrong_domain_streams() {
        let stream_domain = CanonicalStreamDomain::PublicKeyShareProof;
        let bytes = vec![0x4d; FOUNDATION_PROFILE.stream_chunk_byte_length + 11];
        let descriptor = descriptor_for(stream_domain, &bytes);
        let chunks = bytes
            .chunks(FOUNDATION_PROFILE.stream_chunk_byte_length)
            .collect::<Vec<_>>();
        let verified_summary = {
            let mut verifier = CanonicalStreamVerifier::new(stream_domain, descriptor.clone())
                .expect("descriptor begins sequential verification");
            for (chunk_index, chunk) in chunks.iter().copied().enumerate() {
                assert_eq!(
                    verifier.absorb_chunk(chunk_index, chunk),
                    VerificationResult::valid(())
                );
            }
            verifier
                .finish_with_summary()
                .into_result()
                .expect("the sequential stream verifies")
        };

        let mut missing =
            CanonicalStreamReadbackVerifier::new(stream_domain, verified_summary.clone())
                .expect("verified descriptor begins readback");
        assert_eq!(missing.authenticate_chunk(0, chunks[0]), Ok(()));
        assert!(matches!(
            missing.finish().into_result(),
            Err(RefusalReason::WrongTypeOrLength)
        ));

        let mut substituted_chunk = chunks[0].to_vec();
        substituted_chunk[17] ^= 1;
        let mut substituted =
            CanonicalStreamReadbackVerifier::new(stream_domain, verified_summary.clone())
                .expect("verified descriptor begins readback");
        assert_eq!(
            substituted.authenticate_chunk(0, &substituted_chunk),
            Err(RefusalReason::WrongHashOrRoot)
        );
        assert_eq!(
            substituted.authenticate_chunk(0, chunks[0]),
            Err(RefusalReason::WrongHashOrRoot)
        );
        assert!(matches!(
            substituted.finish().into_result(),
            Err(RefusalReason::WrongHashOrRoot)
        ));

        assert!(matches!(
            CanonicalStreamReadbackVerifier::new(
                CanonicalStreamDomain::PublicKeyShareMaterial,
                verified_summary,
            ),
            Err(RefusalReason::WrongHashOrRoot)
        ));
    }

    #[test]
    fn incremental_writer_matches_the_canonical_descriptor_and_poisoning_is_terminal() {
        let bytes = (0..FOUNDATION_PROFILE.stream_chunk_byte_length + 17)
            .map(|index| (index.wrapping_mul(193) & 0xff) as u8)
            .collect::<Vec<_>>();
        let expected_descriptor =
            descriptor_for(CanonicalStreamDomain::DealerVssShareLinkageProof, &bytes);
        let mut writer = CanonicalStreamWriter::new(
            CanonicalStreamDomain::DealerVssShareLinkageProof,
            u64::try_from(bytes.len()).expect("test length fits"),
        )
        .expect("declared stream length is supported");
        for (chunk_index, chunk) in bytes
            .chunks(FOUNDATION_PROFILE.stream_chunk_byte_length)
            .enumerate()
        {
            writer
                .absorb_chunk(chunk_index, chunk)
                .expect("canonical chunk is accepted");
        }
        assert_eq!(
            writer.finish().expect("complete stream"),
            expected_descriptor
        );

        let chunks = bytes
            .chunks(FOUNDATION_PROFILE.stream_chunk_byte_length)
            .collect::<Vec<_>>();
        let mut reordered = CanonicalStreamWriter::new(
            CanonicalStreamDomain::DealerVssShareLinkageProof,
            u64::try_from(bytes.len()).expect("test length fits"),
        )
        .expect("declared stream length is supported");
        assert_eq!(
            reordered.absorb_chunk(1, chunks[1]),
            Err(RefusalReason::WrongTypeOrLength)
        );
        assert_eq!(
            reordered.absorb_chunk(0, chunks[0]),
            Err(RefusalReason::WrongTypeOrLength)
        );
        assert_eq!(reordered.finish(), Err(RefusalReason::WrongTypeOrLength));

        let mut truncated = CanonicalStreamWriter::new(
            CanonicalStreamDomain::DealerVssShareLinkageProof,
            u64::try_from(bytes.len()).expect("test length fits"),
        )
        .expect("declared stream length is supported");
        truncated
            .absorb_chunk(0, chunks[0])
            .expect("first chunk is complete");
        assert_eq!(truncated.finish(), Err(RefusalReason::WrongTypeOrLength));

        assert!(CanonicalStreamWriter::new(CanonicalStreamDomain::EvaluatorKeyStore, 0).is_err());
        assert!(
            CanonicalStreamWriter::new(
                CanonicalStreamDomain::EvaluatorKeyStore,
                MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH,
            )
            .is_ok()
        );
        assert!(
            CanonicalStreamWriter::new(
                CanonicalStreamDomain::EvaluatorKeyStore,
                MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH + 1,
            )
            .is_err()
        );
    }

    #[test]
    fn ordering_lengths_hashes_and_terminal_state_are_enforced() {
        let bytes = vec![0x5a; FOUNDATION_PROFILE.stream_chunk_byte_length + 17];
        let descriptor = descriptor_for(CanonicalStreamDomain::EvaluatorKeyStore, &bytes);
        let chunks = bytes
            .chunks(FOUNDATION_PROFILE.stream_chunk_byte_length)
            .collect::<Vec<_>>();

        let mut reordered = CanonicalStreamVerifier::new(
            CanonicalStreamDomain::EvaluatorKeyStore,
            descriptor.clone(),
        )
        .expect("descriptor");
        assert_eq!(
            reordered.absorb_chunk(1, chunks[1]),
            VerificationResult::refused(RefusalReason::WrongTypeOrLength)
        );
        assert_eq!(
            reordered.absorb_chunk(0, chunks[0]),
            VerificationResult::refused(RefusalReason::WrongTypeOrLength)
        );
        assert_eq!(
            reordered.finish(),
            VerificationResult::refused(RefusalReason::WrongTypeOrLength)
        );

        let mut short = CanonicalStreamVerifier::new(
            CanonicalStreamDomain::EvaluatorKeyStore,
            descriptor.clone(),
        )
        .expect("descriptor");
        assert_eq!(
            short.absorb_chunk(0, &chunks[0][..chunks[0].len() - 1]),
            VerificationResult::refused(RefusalReason::WrongTypeOrLength)
        );

        let mut substituted = chunks[0].to_vec();
        substituted[0] ^= 1;
        let mut wrong_hash = CanonicalStreamVerifier::new(
            CanonicalStreamDomain::EvaluatorKeyStore,
            descriptor.clone(),
        )
        .expect("descriptor");
        assert_eq!(
            wrong_hash.absorb_chunk(0, &substituted),
            VerificationResult::refused(RefusalReason::WrongHashOrRoot)
        );

        let mut truncated = CanonicalStreamVerifier::new(
            CanonicalStreamDomain::EvaluatorKeyStore,
            descriptor.clone(),
        )
        .expect("descriptor");
        assert_eq!(
            truncated.absorb_chunk(0, chunks[0]),
            VerificationResult::valid(())
        );
        assert_eq!(
            truncated.finish(),
            VerificationResult::refused(RefusalReason::WrongTypeOrLength)
        );

        let mut wrong_domain = CanonicalStreamVerifier::new(
            CanonicalStreamDomain::PublicKeyShareProof,
            descriptor_for(CanonicalStreamDomain::EvaluatorKeyStore, &bytes),
        )
        .expect("descriptor is structurally valid across domains");
        assert_eq!(
            wrong_domain.absorb_chunk(0, chunks[0]),
            VerificationResult::refused(RefusalReason::WrongHashOrRoot)
        );

        let mut wrong_full_object_digest_descriptor =
            descriptor_for(CanonicalStreamDomain::EvaluatorKeyStore, &bytes);
        wrong_full_object_digest_descriptor.full_object_digest =
            Hash512::from_bytes([0x91; Hash512::BYTE_LENGTH]);
        let mut wrong_full_object_digest = CanonicalStreamVerifier::new(
            CanonicalStreamDomain::EvaluatorKeyStore,
            wrong_full_object_digest_descriptor,
        )
        .expect("descriptor is structurally valid");
        for (chunk_index, chunk) in chunks.iter().copied().enumerate() {
            assert_eq!(
                wrong_full_object_digest.absorb_chunk(chunk_index, chunk),
                VerificationResult::valid(())
            );
        }
        assert_eq!(
            wrong_full_object_digest.finish(),
            VerificationResult::refused(RefusalReason::WrongHashOrRoot)
        );

        let one_chunk_bytes = [0x77; 32];
        let mut overlong = CanonicalStreamVerifier::new(
            CanonicalStreamDomain::EvaluatorKeyStore,
            descriptor_for(CanonicalStreamDomain::EvaluatorKeyStore, &one_chunk_bytes),
        )
        .expect("one-chunk descriptor");
        assert_eq!(
            overlong.absorb_chunk(0, &one_chunk_bytes),
            VerificationResult::valid(())
        );
        assert_eq!(
            overlong.absorb_chunk(1, &[1]),
            VerificationResult::refused(RefusalReason::WrongTypeOrLength)
        );
        assert_eq!(
            overlong.finish(),
            VerificationResult::refused(RefusalReason::WrongTypeOrLength)
        );
    }

    #[test]
    fn hostile_descriptor_sizes_refuse_before_stream_work() {
        for descriptor in [
            StreamDescriptor {
                total_byte_length: 0,
                ordered_chunk_digests: std::sync::Arc::from([]),
                full_object_digest: Hash512::from_bytes([0; 64]),
            },
            StreamDescriptor {
                total_byte_length: 1,
                ordered_chunk_digests: std::sync::Arc::from([]),
                full_object_digest: Hash512::from_bytes([0; 64]),
            },
            StreamDescriptor {
                total_byte_length: u64::from(u32::MAX),
                ordered_chunk_digests: vec![Hash512::from_bytes([0; 64]); 4096].into(),
                full_object_digest: Hash512::from_bytes([0; 64]),
            },
        ] {
            assert!(
                CanonicalStreamVerifier::new(CanonicalStreamDomain::EvaluatorKeyStore, descriptor)
                    .is_err()
            );
        }
    }
}
