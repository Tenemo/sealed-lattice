use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use super::state::StateExactOutputHasher;
use super::{
    CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalItemType,
    FOUNDATION_PROFILE, Hash512, RefusalReason, StateCapabilityKind, StreamDescriptor,
    VerificationResult,
};

#[cfg(test)]
use super::{CanonicalItem, hash_foundation_tuple_512 as hash512};

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
    total_byte_length: u64,
    full_object_digest: Hash512,
    state_exact_output_hash: Option<Hash512>,
}

impl VerifiedCanonicalStreamSummary {
    pub(crate) const fn stream_domain(&self) -> CanonicalStreamDomain {
        self.stream_domain
    }

    pub(crate) const fn total_byte_length(&self) -> u64 {
        self.total_byte_length
    }

    pub(crate) const fn full_object_digest(&self) -> Hash512 {
        self.full_object_digest
    }

    pub(crate) const fn state_exact_output_hash(&self) -> Option<Hash512> {
        self.state_exact_output_hash
    }
}

/// Authenticates browser-stored canonical chunks before a random-access
/// verifier consumes them. Construction requires the terminal summary from a
/// complete sequential canonical-stream verification of the same descriptor,
/// so a descriptor or a set of independently matching chunk digests cannot
/// mint stream authority by themselves.
pub(crate) struct CanonicalStreamReadbackVerifier {
    stream_domain: CanonicalStreamDomain,
    descriptor: StreamDescriptor,
    verified_summary: VerifiedCanonicalStreamSummary,
    authenticated_chunks: Vec<bool>,
    authenticated_chunk_count: usize,
    refusal_reason: Option<RefusalReason>,
}

impl CanonicalStreamReadbackVerifier {
    pub(crate) fn new(
        stream_domain: CanonicalStreamDomain,
        descriptor: StreamDescriptor,
        verified_summary: VerifiedCanonicalStreamSummary,
    ) -> Result<Self, RefusalReason> {
        validate_descriptor(&descriptor)?;
        if verified_summary.stream_domain() != stream_domain
            || verified_summary.total_byte_length() != descriptor.total_byte_length
            || verified_summary.full_object_digest() != descriptor.full_object_digest
        {
            return Err(RefusalReason::WrongHashOrRoot);
        }
        let chunk_count = descriptor.ordered_chunk_digests.len();
        Ok(Self {
            stream_domain,
            descriptor,
            verified_summary,
            authenticated_chunks: vec![false; chunk_count],
            authenticated_chunk_count: 0,
            refusal_reason: None,
        })
    }

    #[cfg(test)]
    pub(crate) const fn total_byte_length(&self) -> u64 {
        self.descriptor.total_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn chunk_count(&self) -> usize {
        self.descriptor.ordered_chunk_digests.len()
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
        if self.authenticated_chunk_count != self.authenticated_chunks.len() {
            return VerificationResult::refused(RefusalReason::WrongTypeOrLength);
        }
        VerificationResult::valid(self.verified_summary)
    }

    fn authenticate_chunk_inner(
        &mut self,
        chunk_index: usize,
        chunk_bytes: &[u8],
    ) -> Result<(), RefusalReason> {
        let expected_digest = self
            .descriptor
            .ordered_chunk_digests
            .get(chunk_index)
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        let expected_byte_length = expected_chunk_byte_length(
            self.descriptor.total_byte_length,
            self.descriptor.ordered_chunk_digests.len(),
            chunk_index,
        )?;
        if chunk_bytes.len() != expected_byte_length
            || chunk_digest(self.stream_domain, chunk_index, chunk_bytes)? != *expected_digest
        {
            return Err(RefusalReason::WrongHashOrRoot);
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
        Ok(Self {
            stream_domain,
            descriptor,
            next_chunk_index: 0,
            observed_byte_length: 0,
            full_object_hasher,
            state_exact_output_hasher,
            refusal_reason: None,
        })
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
        VerificationResult::valid(VerifiedCanonicalStreamSummary {
            stream_domain: self.stream_domain,
            total_byte_length: self.descriptor.total_byte_length,
            full_object_digest,
            state_exact_output_hash,
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
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    fn descriptor_for(stream_domain: CanonicalStreamDomain, bytes: &[u8]) -> StreamDescriptor {
        derive_canonical_stream_descriptor(stream_domain, bytes).expect("test descriptor is valid")
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
        let bytes = (0..FOUNDATION_PROFILE.stream_chunk_byte_length + 19)
            .map(|index| (index.wrapping_mul(211) & 0xff) as u8)
            .collect::<Vec<_>>();
        for (stream_domain, capability_kind) in [
            (
                CanonicalStreamDomain::StateFinalitySignatureExactOutput,
                StateCapabilityKind::FinalitySignature,
            ),
            (
                CanonicalStreamDomain::StateTargetReleaseExactOutput,
                StateCapabilityKind::TargetRelease,
            ),
        ] {
            let descriptor = descriptor_for(stream_domain, &bytes);
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
                descriptor_for(stream_domain, &bytes).full_object_digest
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

        let mut readback =
            CanonicalStreamReadbackVerifier::new(stream_domain, descriptor, verified_summary)
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
    fn authenticated_readback_refuses_missing_substituted_and_mismatched_streams() {
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

        let mut missing = CanonicalStreamReadbackVerifier::new(
            stream_domain,
            descriptor.clone(),
            verified_summary.clone(),
        )
        .expect("verified descriptor begins readback");
        assert_eq!(missing.authenticate_chunk(0, chunks[0]), Ok(()));
        assert!(matches!(
            missing.finish().into_result(),
            Err(RefusalReason::WrongTypeOrLength)
        ));

        let mut substituted_chunk = chunks[0].to_vec();
        substituted_chunk[17] ^= 1;
        let mut substituted = CanonicalStreamReadbackVerifier::new(
            stream_domain,
            descriptor.clone(),
            verified_summary.clone(),
        )
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

        let other_bytes = vec![0x93; bytes.len()];
        let other_descriptor = descriptor_for(stream_domain, &other_bytes);
        assert!(matches!(
            CanonicalStreamReadbackVerifier::new(
                stream_domain,
                other_descriptor,
                verified_summary.clone(),
            ),
            Err(RefusalReason::WrongHashOrRoot)
        ));
        assert!(matches!(
            CanonicalStreamReadbackVerifier::new(
                CanonicalStreamDomain::PublicKeyShareMaterial,
                descriptor,
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
                ordered_chunk_digests: Vec::new(),
                full_object_digest: Hash512::from_bytes([0; 64]),
            },
            StreamDescriptor {
                total_byte_length: 1,
                ordered_chunk_digests: Vec::new(),
                full_object_digest: Hash512::from_bytes([0; 64]),
            },
            StreamDescriptor {
                total_byte_length: u64::from(u32::MAX),
                ordered_chunk_digests: vec![Hash512::from_bytes([0; 64]); 4096],
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
