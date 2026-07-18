use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
};

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::board_ingestion::{
    BALLOT_PACKAGE_PAYLOAD_SCHEMA_IDENTIFIER, CanonicalBoardLimits, CanonicalBoardVerifier,
    DEALER_PUBLIC_RECORD_PAYLOAD_SCHEMA_IDENTIFIER, FOUNDATION_SCHEMA_VERSION,
    MAXIMUM_CANONICAL_BOARD_BATCH_CARRIER_COUNT,
    PRIVATE_SHARE_ACCEPTANCE_PAYLOAD_SCHEMA_IDENTIFIER,
    PUBLIC_RANDOMNESS_COMMITMENT_PAYLOAD_SCHEMA_IDENTIFIER,
    PUBLIC_RANDOMNESS_REVEAL_PAYLOAD_SCHEMA_IDENTIFIER, SETUP_INTENT_PAYLOAD_SCHEMA_IDENTIFIER,
    VerifiedTranscriptObject,
};
use super::runtime_input::{RuntimeInputReader as InputReader, refusal_status};
use super::{
    ActionContext, ActionDefinition, BoardPolicy, CanonicalDecodeLimits, CeremonyContext,
    FOUNDATION_PROFILE, FoundationObjectType, Hash512, Manifest, ParticipantIdentity,
    RefusalReason, Roster, SignedCarrier, StreamDescriptor, SuiteRecord,
};

pub(crate) const BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH: usize = 32;
pub(crate) const VERIFIED_TRANSCRIPT_OBJECT_DESCRIPTION_BYTE_LENGTH: usize =
    2 + 2 + Hash512::BYTE_LENGTH;

type RuntimeResult<Value> = Result<Value, u32>;

pub(crate) struct BoardVerifierCanonicalContextInput<'input> {
    pub(crate) canonical_suite_record_bytes: &'input [u8],
    pub(crate) canonical_manifest_bytes: &'input [u8],
    pub(crate) canonical_roster_bytes: &'input [u8],
    pub(crate) canonical_action_definition_bytes: &'input [u8],
    pub(crate) canonical_board_policy_bytes: &'input [u8],
    pub(crate) ceremony_identifier_bytes: &'input [u8],
    pub(crate) action_identifier_bytes: &'input [u8],
    pub(crate) expected_suite_identifier_bytes: &'input [u8],
    pub(crate) expected_ceremony_context_hash_bytes: &'input [u8],
    pub(crate) expected_action_context_hash_bytes: &'input [u8],
}

/// Process-local board authority for one proof application source. The value
/// owns the verified transcript object and its verifier-derived context; it has
/// no constructor from copied descriptions or canonical carrier bytes.
#[derive(Clone, Debug)]
pub(crate) struct VerifiedBoardApplicationSource {
    verified_object: VerifiedTranscriptObject,
    suite_identifier: Hash512,
    manifest_hash: Hash512,
    ceremony_context_hash: Hash512,
    action_context_hash: Hash512,
    roster_hash: Hash512,
    producer_roster_position: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VerifiedSetupIntentApplicationPayload {
    action_randomness_commitment: Hash512,
}

impl VerifiedSetupIntentApplicationPayload {
    pub(crate) const fn action_randomness_commitment(self) -> Hash512 {
        self.action_randomness_commitment
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedPublicRandomnessCommitmentApplicationPayload {
    contribution_commitment: Hash512,
    ordered_setup_intent_object_hashes: Box<[Hash512]>,
}

impl VerifiedPublicRandomnessCommitmentApplicationPayload {
    pub(crate) const fn contribution_commitment(&self) -> Hash512 {
        self.contribution_commitment
    }

    pub(crate) fn ordered_setup_intent_object_hashes(&self) -> &[Hash512] {
        &self.ordered_setup_intent_object_hashes
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VerifiedPublicRandomnessRevealApplicationPayload {
    contribution_commitment_object_hash: Hash512,
    contribution_and_salt: [u8; Hash512::BYTE_LENGTH],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedBallotPackageApplicationPayload {
    ciphertext_descriptor: StreamDescriptor,
    proof_descriptor: StreamDescriptor,
}

/// Exact authenticated fields from one dealer's canonical `0x2100` payload.
/// The sole public-setup-seed prerequisite remains attached to this value so a
/// proof-family terminal never needs a detached prerequisite hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedDealerPublicRecordApplicationPayload {
    dealer_roster_position: u16,
    coefficient_material_roots: Box<[Hash512]>,
    recipient_share_material_roots: Box<[Hash512]>,
    ordered_recipient_envelope_hashes: Box<[Hash512]>,
    share_linkage_proof: StreamDescriptor,
    public_setup_seed_prerequisite: Hash512,
}

impl VerifiedDealerPublicRecordApplicationPayload {
    pub(crate) const fn dealer_roster_position(&self) -> u16 {
        self.dealer_roster_position
    }

    pub(crate) fn coefficient_material_roots(&self) -> &[Hash512] {
        &self.coefficient_material_roots
    }

    pub(crate) fn recipient_share_material_roots(&self) -> &[Hash512] {
        &self.recipient_share_material_roots
    }

    pub(crate) fn ordered_recipient_envelope_hashes(&self) -> &[Hash512] {
        &self.ordered_recipient_envelope_hashes
    }

    pub(crate) const fn share_linkage_proof(&self) -> &StreamDescriptor {
        &self.share_linkage_proof
    }

    pub(crate) const fn public_setup_seed_prerequisite(&self) -> Hash512 {
        self.public_setup_seed_prerequisite
    }
}

/// Exact authenticated fields from one recipient's canonical `0x1203`
/// acceptance. Its empty prerequisite list is rechecked while decoding so the
/// typed value is the sole public catalog of the aggregate relation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedPrivateShareAcceptanceApplicationPayload {
    recipient_input_root: Hash512,
    aggregate_threshold_share_material_roots: Box<[Hash512]>,
    aggregate_threshold_share_proof: StreamDescriptor,
}

impl VerifiedPrivateShareAcceptanceApplicationPayload {
    pub(crate) const fn recipient_input_root(&self) -> Hash512 {
        self.recipient_input_root
    }

    pub(crate) fn aggregate_threshold_share_material_roots(&self) -> &[Hash512] {
        &self.aggregate_threshold_share_material_roots
    }

    pub(crate) const fn aggregate_threshold_share_proof(&self) -> &StreamDescriptor {
        &self.aggregate_threshold_share_proof
    }
}

impl VerifiedBallotPackageApplicationPayload {
    pub(crate) const fn ciphertext_descriptor(&self) -> &StreamDescriptor {
        &self.ciphertext_descriptor
    }

    pub(crate) const fn proof_descriptor(&self) -> &StreamDescriptor {
        &self.proof_descriptor
    }
}

impl VerifiedPublicRandomnessRevealApplicationPayload {
    pub(crate) const fn contribution_commitment_object_hash(self) -> Hash512 {
        self.contribution_commitment_object_hash
    }

    pub(crate) const fn contribution_and_salt(self) -> [u8; Hash512::BYTE_LENGTH] {
        self.contribution_and_salt
    }
}

impl VerifiedBoardApplicationSource {
    pub(crate) fn from_verifier(
        verifier: &CanonicalBoardVerifier,
        manifest_hash: Hash512,
        verified_object: VerifiedTranscriptObject,
    ) -> Self {
        let producer_roster_position = verified_object
            .producer_participant_id()
            .and_then(|participant_identity| verifier.roster_position(participant_identity).ok());
        Self {
            verified_object,
            suite_identifier: verifier.suite_id(),
            manifest_hash,
            ceremony_context_hash: verifier.ceremony_context_hash(),
            action_context_hash: verifier.action_context_hash(),
            roster_hash: verifier.roster_hash(),
            producer_roster_position,
        }
    }

    pub(crate) const fn suite_identifier(&self) -> Hash512 {
        self.suite_identifier
    }

    pub(crate) const fn manifest_hash(&self) -> Hash512 {
        self.manifest_hash
    }

    pub(crate) const fn ceremony_context_hash(&self) -> Hash512 {
        self.ceremony_context_hash
    }

    pub(crate) const fn action_context_hash(&self) -> Hash512 {
        self.action_context_hash
    }

    pub(crate) const fn roster_hash(&self) -> Hash512 {
        self.roster_hash
    }

    pub(crate) fn object_hash(&self) -> Hash512 {
        self.verified_object.object_hash()
    }

    pub(crate) fn object_type(&self) -> FoundationObjectType {
        self.verified_object.object_type()
    }

    pub(crate) fn producer_participant_identity(&self) -> Option<ParticipantIdentity> {
        self.verified_object.producer_participant_id()
    }

    pub(crate) const fn producer_roster_position(&self) -> Option<u16> {
        self.producer_roster_position
    }

    pub(crate) fn producer_sequence(&self) -> u64 {
        self.verified_object.producer_sequence()
    }

    pub(crate) fn canonical_carrier_bytes(&self) -> &[u8] {
        self.verified_object.canonical_carrier_bytes()
    }

    /// Decodes the already authenticated setup-intent payload while retaining
    /// the board verifier as the only source of application authority.
    pub(crate) fn setup_intent_payload(
        &self,
    ) -> Result<VerifiedSetupIntentApplicationPayload, RefusalReason> {
        let carrier = self.decode_exact_signed_carrier(FoundationObjectType::SetupIntent)?;
        let tuple = decode_exact_payload_tuple(&carrier.envelope.payload_bytes)?;
        require_payload_shape(&tuple, SETUP_INTENT_PAYLOAD_SCHEMA_IDENTIFIER, 1)?;
        Ok(VerifiedSetupIntentApplicationPayload {
            action_randomness_commitment: read_payload_hash(&tuple.items[0])?,
        })
    }

    /// Decodes the authenticated commitment and its exact roster-ordered
    /// setup-intent prerequisites. The prerequisite bytes never become an
    /// independent capability.
    pub(crate) fn public_randomness_commitment_payload(
        &self,
    ) -> Result<VerifiedPublicRandomnessCommitmentApplicationPayload, RefusalReason> {
        let carrier =
            self.decode_exact_signed_carrier(FoundationObjectType::PublicRandomnessCommitment)?;
        let tuple = decode_exact_payload_tuple(&carrier.envelope.payload_bytes)?;
        require_payload_shape(
            &tuple,
            PUBLIC_RANDOMNESS_COMMITMENT_PAYLOAD_SCHEMA_IDENTIFIER,
            1,
        )?;
        Ok(VerifiedPublicRandomnessCommitmentApplicationPayload {
            contribution_commitment: read_payload_hash(&tuple.items[0])?,
            ordered_setup_intent_object_hashes: carrier
                .envelope
                .ordered_prerequisite_hashes
                .into_boxed_slice(),
        })
    }

    /// Decodes the authenticated reveal into the exact commitment reference
    /// and fixed contribution-and-salt bytes consumed by setup verification.
    pub(crate) fn public_randomness_reveal_payload(
        &self,
    ) -> Result<VerifiedPublicRandomnessRevealApplicationPayload, RefusalReason> {
        let carrier =
            self.decode_exact_signed_carrier(FoundationObjectType::PublicRandomnessReveal)?;
        let tuple = decode_exact_payload_tuple(&carrier.envelope.payload_bytes)?;
        require_payload_shape(
            &tuple,
            PUBLIC_RANDOMNESS_REVEAL_PAYLOAD_SCHEMA_IDENTIFIER,
            2,
        )?;
        Ok(VerifiedPublicRandomnessRevealApplicationPayload {
            contribution_commitment_object_hash: read_payload_hash(&tuple.items[0])?,
            contribution_and_salt: read_fixed_payload_bytes(&tuple.items[1])?,
        })
    }

    /// Decodes a board-verified dealer record without promoting copied payload
    /// fields into independent authority. Exact suite-owned root counts are
    /// enforced when the payload is joined to canonical `0x2110` statement
    /// roots by the VSS terminal.
    pub(crate) fn dealer_public_record_payload(
        &self,
    ) -> Result<VerifiedDealerPublicRecordApplicationPayload, RefusalReason> {
        let carrier = self.decode_exact_signed_carrier(FoundationObjectType::PublicSetupRecord)?;
        let tuple = decode_exact_payload_tuple(&carrier.envelope.payload_bytes)?;
        require_payload_shape(&tuple, DEALER_PUBLIC_RECORD_PAYLOAD_SCHEMA_IDENTIFIER, 5)?;
        let [public_setup_seed_prerequisite] =
            <[Hash512; 1]>::try_from(carrier.envelope.ordered_prerequisite_hashes)
                .map_err(|_| RefusalReason::WrongTypeOrLength)?;
        Ok(VerifiedDealerPublicRecordApplicationPayload {
            dealer_roster_position: read_payload_unsigned16(&tuple.items[0])?,
            coefficient_material_roots: read_payload_hash_list(&tuple.items[1])?.into_boxed_slice(),
            recipient_share_material_roots: read_payload_hash_list(&tuple.items[2])?
                .into_boxed_slice(),
            ordered_recipient_envelope_hashes: read_payload_hash_list(&tuple.items[3])?
                .into_boxed_slice(),
            share_linkage_proof: read_payload_stream_descriptor(&tuple.items[4])?,
            public_setup_seed_prerequisite,
        })
    }

    /// Decodes a board-verified private-share acceptance. The canonical
    /// acceptance has no prerequisites; the aggregate terminal later joins
    /// these exact roots and descriptor to canonical `0x2111` proof authority.
    pub(crate) fn private_share_acceptance_payload(
        &self,
    ) -> Result<VerifiedPrivateShareAcceptanceApplicationPayload, RefusalReason> {
        let carrier =
            self.decode_exact_signed_carrier(FoundationObjectType::PrivateShareAcceptance)?;
        if !carrier.envelope.ordered_prerequisite_hashes.is_empty() {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        let tuple = decode_exact_payload_tuple(&carrier.envelope.payload_bytes)?;
        require_payload_shape(
            &tuple,
            PRIVATE_SHARE_ACCEPTANCE_PAYLOAD_SCHEMA_IDENTIFIER,
            3,
        )?;
        Ok(VerifiedPrivateShareAcceptanceApplicationPayload {
            recipient_input_root: read_payload_hash(&tuple.items[0])?,
            aggregate_threshold_share_material_roots: read_payload_hash_list(&tuple.items[1])?
                .into_boxed_slice(),
            aggregate_threshold_share_proof: read_payload_stream_descriptor(&tuple.items[2])?,
        })
    }

    /// Decodes the two exact stream descriptors from an authenticated ballot
    /// package. Their positions fix the ciphertext and ballot-validity proof
    /// domains; detached descriptors cannot construct this payload.
    pub(crate) fn ballot_package_payload(
        &self,
    ) -> Result<VerifiedBallotPackageApplicationPayload, RefusalReason> {
        let carrier = self.decode_exact_signed_carrier(FoundationObjectType::BallotPackage)?;
        let tuple = decode_exact_payload_tuple(&carrier.envelope.payload_bytes)?;
        require_payload_shape(&tuple, BALLOT_PACKAGE_PAYLOAD_SCHEMA_IDENTIFIER, 2)?;
        Ok(VerifiedBallotPackageApplicationPayload {
            ciphertext_descriptor: read_payload_stream_descriptor(&tuple.items[0])?,
            proof_descriptor: read_payload_stream_descriptor(&tuple.items[1])?,
        })
    }

    fn decode_exact_signed_carrier(
        &self,
        expected_object_type: FoundationObjectType,
    ) -> Result<SignedCarrier, RefusalReason> {
        let carrier = SignedCarrier::decode(
            self.verified_object.canonical_carrier_bytes(),
            &CanonicalDecodeLimits::default(),
        )
        .map_err(|error| error.refusal_reason)?;
        let exact_reencoding = carrier.encode().map_err(|error| error.refusal_reason)?;
        if exact_reencoding != self.verified_object.canonical_carrier_bytes() {
            return Err(RefusalReason::MalformedEncoding);
        }
        let envelope = &carrier.envelope;
        if envelope.object_type != expected_object_type
            || self.verified_object.object_type() != expected_object_type
            || envelope.suite_id != self.suite_identifier
            || envelope.ceremony_context_hash != self.ceremony_context_hash
            || envelope.action_context_hash != self.action_context_hash
            || envelope.producer_participant_id != self.verified_object.producer_participant_id()
            || envelope.producer_sequence != self.verified_object.producer_sequence()
            || envelope
                .object_hash()
                .map_err(|error| error.refusal_reason)?
                != self.verified_object.object_hash()
        {
            return Err(RefusalReason::WrongContext);
        }
        Ok(carrier)
    }
}

fn decode_exact_payload_tuple(bytes: &[u8]) -> Result<super::CanonicalTuple, RefusalReason> {
    let tuple = super::CanonicalTuple::decode(bytes, &CanonicalDecodeLimits::default()).map_err(
        |error| {
            if error.kind == super::CanonicalCodecErrorKind::LimitExceeded {
                RefusalReason::OutsideSupportedProfile
            } else {
                RefusalReason::MalformedEncoding
            }
        },
    )?;
    if tuple.encode().map_err(|error| {
        if error.kind == super::CanonicalCodecErrorKind::LimitExceeded {
            RefusalReason::OutsideSupportedProfile
        } else {
            RefusalReason::MalformedEncoding
        }
    })? != bytes
    {
        return Err(RefusalReason::MalformedEncoding);
    }
    Ok(tuple)
}

fn require_payload_shape(
    tuple: &super::CanonicalTuple,
    expected_schema_identifier: u16,
    expected_item_count: usize,
) -> Result<(), RefusalReason> {
    if tuple.schema_version != FOUNDATION_SCHEMA_VERSION {
        return Err(RefusalReason::UnsupportedVersionOrSuite);
    }
    if tuple.schema_identifier != expected_schema_identifier
        || tuple.items.len() != expected_item_count
    {
        return Err(RefusalReason::WrongTypeOrLength);
    }
    Ok(())
}

fn read_payload_hash(item: &super::CanonicalItem) -> Result<Hash512, RefusalReason> {
    if item.item_type() != super::CanonicalItemType::Hash512 {
        return Err(RefusalReason::WrongTypeOrLength);
    }
    let bytes = <[u8; Hash512::BYTE_LENGTH]>::try_from(item.canonical_bytes())
        .map_err(|_| RefusalReason::WrongTypeOrLength)?;
    Ok(Hash512::from_bytes(bytes))
}

fn read_payload_unsigned16(item: &super::CanonicalItem) -> Result<u16, RefusalReason> {
    if item.item_type() != super::CanonicalItemType::Unsigned16 {
        return Err(RefusalReason::WrongTypeOrLength);
    }
    let bytes = <[u8; 2]>::try_from(item.canonical_bytes())
        .map_err(|_| RefusalReason::WrongTypeOrLength)?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_payload_hash_list(item: &super::CanonicalItem) -> Result<Vec<Hash512>, RefusalReason> {
    super::schemas::read_hash_list(item).map_err(|error| error.refusal_reason)
}

fn read_fixed_payload_bytes(
    item: &super::CanonicalItem,
) -> Result<[u8; Hash512::BYTE_LENGTH], RefusalReason> {
    if item.item_type() != super::CanonicalItemType::RawBytes {
        return Err(RefusalReason::WrongTypeOrLength);
    }
    <[u8; Hash512::BYTE_LENGTH]>::try_from(item.canonical_bytes())
        .map_err(|_| RefusalReason::WrongTypeOrLength)
}

fn read_payload_stream_descriptor(
    item: &super::CanonicalItem,
) -> Result<StreamDescriptor, RefusalReason> {
    if item.item_type() != super::CanonicalItemType::NestedTuple {
        return Err(RefusalReason::WrongTypeOrLength);
    }
    StreamDescriptor::decode(item.canonical_bytes(), &CanonicalDecodeLimits::default())
        .map_err(|error| error.refusal_reason)
}

struct BoardVerifierRuntimeSession {
    capability: Zeroizing<[u8; BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH]>,
    handle: u32,
    action_top_count: u16,
    manifest_hash: Hash512,
    verifier: CanonicalBoardVerifier,
    verified_objects: HashMap<u32, VerifiedTranscriptObject>,
    object_handles_by_hash: HashMap<Hash512, u32>,
}

struct BoardVerifierRuntimeRegistry {
    active_session: Option<BoardVerifierRuntimeSession>,
    next_session_handle: u32,
    next_verified_object_handle: u32,
}

impl Default for BoardVerifierRuntimeRegistry {
    fn default() -> Self {
        Self {
            active_session: None,
            next_session_handle: 1,
            next_verified_object_handle: 1,
        }
    }
}

impl BoardVerifierRuntimeRegistry {
    fn begin(
        &mut self,
        context_input: BoardVerifierCanonicalContextInput<'_>,
        capability: [u8; BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH],
    ) -> RuntimeResult<u32> {
        let capability = Zeroizing::new(capability);
        if self.active_session.is_some() {
            return Err(refusal_status(RefusalReason::OutsideSupportedProfile));
        }
        if capability.iter().all(|byte| *byte == 0) {
            return Err(refusal_status(RefusalReason::WrongContext));
        }
        let configuration = derive_configuration(context_input)?;
        let verifier = CanonicalBoardVerifier::new(
            configuration.suite_id,
            configuration.ceremony_context_hash,
            configuration.action_context_hash,
            &configuration.roster,
            configuration.limits,
            CanonicalDecodeLimits::default(),
        )
        .map_err(|error| refusal_status(error.refusal_reason))?;
        let handle = take_nonrepeating_handle(&mut self.next_session_handle)?;
        self.active_session = Some(BoardVerifierRuntimeSession {
            capability,
            handle,
            action_top_count: configuration.action_top_count,
            manifest_hash: configuration.manifest_hash,
            verifier,
            verified_objects: HashMap::new(),
            object_handles_by_hash: HashMap::new(),
        });
        Ok(handle)
    }

    fn verify_unordered(
        &mut self,
        session_handle: u32,
        capability: &[u8],
        canonical_carriers: &[Vec<u8>],
    ) -> RuntimeResult<Vec<u8>> {
        preflight_handle_range(self.next_verified_object_handle, canonical_carriers.len())?;
        let session =
            require_active_session_mut(&mut self.active_session, session_handle, capability)?;
        let batch = session
            .verifier
            .verify_unordered_carriers(canonical_carriers)
            .into_result()
            .map_err(refusal_status)?;
        let mut handles = Vec::with_capacity(batch.objects().len());
        for object in batch.objects() {
            if let Some(handle) = session.object_handles_by_hash.get(&object.object_hash()) {
                handles.push(*handle);
                continue;
            }
            let handle = take_nonrepeating_handle(&mut self.next_verified_object_handle)?;
            session
                .object_handles_by_hash
                .insert(object.object_hash(), handle);
            session.verified_objects.insert(handle, object.clone());
            handles.push(handle);
        }
        encode_verified_object_handles(&handles)
    }

    fn describe(
        &self,
        session_handle: u32,
        capability: &[u8],
        verified_object_handle: u32,
    ) -> RuntimeResult<Vec<u8>> {
        let session = require_active_session(&self.active_session, session_handle, capability)?;
        let object = session
            .verified_objects
            .get(&verified_object_handle)
            .ok_or_else(|| refusal_status(RefusalReason::ConsumedState))?;
        let mut output = Vec::with_capacity(VERIFIED_TRANSCRIPT_OBJECT_DESCRIPTION_BYTE_LENGTH);
        output.extend_from_slice(&1_u16.to_le_bytes());
        output.extend_from_slice(&object.object_type().canonical_code().to_le_bytes());
        output.extend_from_slice(object.object_hash().as_bytes());
        Ok(output)
    }

    fn copy_cached_carrier(
        &self,
        session_handle: u32,
        capability: &[u8],
        verified_object_handle: u32,
    ) -> RuntimeResult<Vec<u8>> {
        let session = require_active_session(&self.active_session, session_handle, capability)?;
        let object = session
            .verified_objects
            .get(&verified_object_handle)
            .ok_or_else(|| refusal_status(RefusalReason::ConsumedState))?;
        Ok(object.canonical_carrier_bytes().to_vec())
    }

    fn cached_carrier_byte_length(
        &self,
        session_handle: u32,
        capability: &[u8],
        verified_object_handle: u32,
    ) -> RuntimeResult<usize> {
        let session = require_active_session(&self.active_session, session_handle, capability)?;
        let object = session
            .verified_objects
            .get(&verified_object_handle)
            .ok_or_else(|| refusal_status(RefusalReason::ConsumedState))?;
        Ok(object.canonical_carrier_bytes().len())
    }

    fn release(
        &mut self,
        session_handle: u32,
        capability: &[u8],
        verified_object_handle: u32,
    ) -> RuntimeResult<()> {
        let session =
            require_active_session_mut(&mut self.active_session, session_handle, capability)?;
        let object = session
            .verified_objects
            .remove(&verified_object_handle)
            .ok_or_else(|| refusal_status(RefusalReason::ConsumedState))?;
        session.object_handles_by_hash.remove(&object.object_hash());
        Ok(())
    }

    fn cancel(&mut self, session_handle: u32, capability: &[u8]) -> RuntimeResult<()> {
        require_active_session(&self.active_session, session_handle, capability)?;
        self.active_session = None;
        Ok(())
    }
}

struct BoardVerifierRuntimeConfiguration {
    suite_id: Hash512,
    manifest_hash: Hash512,
    ceremony_context_hash: Hash512,
    action_context_hash: Hash512,
    action_top_count: u16,
    limits: CanonicalBoardLimits,
    roster: Roster,
}

pub(crate) fn begin_board_verifier_session(
    context_input: BoardVerifierCanonicalContextInput<'_>,
    capability: [u8; BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH],
) -> RuntimeResult<u32> {
    with_runtime_registry(|registry| registry.begin(context_input, capability))
}

pub(crate) fn verify_unordered_board_carriers(
    session_handle: u32,
    capability: &[u8],
    framed_canonical_carriers: &[u8],
) -> RuntimeResult<Vec<u8>> {
    let canonical_carriers = decode_framed_carriers(framed_canonical_carriers)?;
    with_runtime_registry(|registry| {
        registry.verify_unordered(session_handle, capability, &canonical_carriers)
    })
}

pub(crate) fn describe_verified_transcript_object(
    session_handle: u32,
    capability: &[u8],
    verified_object_handle: u32,
) -> RuntimeResult<Vec<u8>> {
    with_runtime_registry(|registry| {
        registry.describe(session_handle, capability, verified_object_handle)
    })
}

pub(crate) fn copy_cached_board_carrier(
    session_handle: u32,
    capability: &[u8],
    verified_object_handle: u32,
) -> RuntimeResult<Vec<u8>> {
    with_runtime_registry(|registry| {
        registry.copy_cached_carrier(session_handle, capability, verified_object_handle)
    })
}

pub(crate) fn cached_board_carrier_byte_length(
    session_handle: u32,
    capability: &[u8],
    verified_object_handle: u32,
) -> RuntimeResult<usize> {
    with_runtime_registry(|registry| {
        registry.cached_carrier_byte_length(session_handle, capability, verified_object_handle)
    })
}

pub(crate) fn release_verified_transcript_object(
    session_handle: u32,
    capability: &[u8],
    verified_object_handle: u32,
) -> RuntimeResult<()> {
    with_runtime_registry(|registry| {
        registry.release(session_handle, capability, verified_object_handle)
    })
}

pub(crate) fn cancel_board_verifier_session(
    session_handle: u32,
    capability: &[u8],
) -> RuntimeResult<()> {
    with_runtime_registry(|registry| registry.cancel(session_handle, capability))
}

/// Resolves live board capabilities for another verifier inside this WASM
/// instance. Callers receive verifier-owned values, never caller-provided
/// carrier bytes promoted into capabilities.
pub(crate) fn resolve_verified_transcript_objects(
    session_handle: u32,
    capability: &[u8],
    verified_object_handles: &[u32],
) -> RuntimeResult<Vec<VerifiedTranscriptObject>> {
    with_runtime_registry(|registry| {
        let session = require_active_session(&registry.active_session, session_handle, capability)?;
        verified_object_handles
            .iter()
            .map(|verified_object_handle| {
                session
                    .verified_objects
                    .get(verified_object_handle)
                    .cloned()
                    .ok_or_else(|| refusal_status(RefusalReason::ConsumedState))
            })
            .collect()
    })
}

/// Resolves the top count from the exact canonical action definition accepted
/// when the board session opened. The process-local session capability is the
/// authority; a detached integer cannot enter evaluator selection.
pub(crate) fn resolve_verified_action_top_count(
    session_handle: u32,
    capability: &[u8],
) -> RuntimeResult<u16> {
    with_runtime_registry(|registry| {
        require_active_session(&registry.active_session, session_handle, capability)
            .map(|session| session.action_top_count)
    })
}

/// Resolves verifier-owned application sources for a consumer in this WASM
/// instance. Descriptions and copied carrier bytes cannot enter this path.
pub(crate) fn resolve_verified_board_application_sources(
    session_handle: u32,
    capability: &[u8],
    verified_object_handles: &[u32],
) -> RuntimeResult<Vec<VerifiedBoardApplicationSource>> {
    with_runtime_registry(|registry| {
        let session = require_active_session(&registry.active_session, session_handle, capability)?;
        verified_object_handles
            .iter()
            .map(|verified_object_handle| {
                let verified_object = session
                    .verified_objects
                    .get(verified_object_handle)
                    .cloned()
                    .ok_or_else(|| refusal_status(RefusalReason::ConsumedState))?;
                Ok(VerifiedBoardApplicationSource::from_verifier(
                    &session.verifier,
                    session.manifest_hash,
                    verified_object,
                ))
            })
            .collect()
    })
}

fn derive_configuration(
    input: BoardVerifierCanonicalContextInput<'_>,
) -> RuntimeResult<BoardVerifierRuntimeConfiguration> {
    let decode_limits = CanonicalDecodeLimits::default();
    require_individually_bounded_input(input.canonical_suite_record_bytes)?;
    require_individually_bounded_input(input.canonical_manifest_bytes)?;
    require_individually_bounded_input(input.canonical_roster_bytes)?;
    require_individually_bounded_input(input.canonical_action_definition_bytes)?;
    require_individually_bounded_input(input.canonical_board_policy_bytes)?;

    let suite = SuiteRecord::decode(input.canonical_suite_record_bytes, &decode_limits)
        .map_err(|error| refusal_status(error.refusal_reason))?;
    require_exact_reencoding(
        input.canonical_suite_record_bytes,
        suite
            .encode()
            .map_err(|error| refusal_status(error.refusal_reason))?,
    )?;
    let manifest = Manifest::decode(input.canonical_manifest_bytes, &decode_limits)
        .map_err(|error| refusal_status(error.refusal_reason))?;
    require_exact_reencoding(
        input.canonical_manifest_bytes,
        manifest
            .encode()
            .map_err(|error| refusal_status(error.refusal_reason))?,
    )?;
    let roster = Roster::decode(input.canonical_roster_bytes, &decode_limits)
        .map_err(|error| refusal_status(error.refusal_reason))?;
    require_exact_reencoding(
        input.canonical_roster_bytes,
        roster
            .encode()
            .map_err(|error| refusal_status(error.refusal_reason))?,
    )?;
    let action_definition =
        ActionDefinition::decode(input.canonical_action_definition_bytes, &decode_limits)
            .map_err(|error| refusal_status(error.refusal_reason))?;
    require_exact_reencoding(
        input.canonical_action_definition_bytes,
        action_definition
            .encode()
            .map_err(|error| refusal_status(error.refusal_reason))?,
    )?;
    let board_policy = BoardPolicy::decode(input.canonical_board_policy_bytes, &decode_limits)
        .map_err(|error| refusal_status(error.refusal_reason))?;
    require_exact_reencoding(
        input.canonical_board_policy_bytes,
        board_policy
            .encode()
            .map_err(|error| refusal_status(error.refusal_reason))?,
    )?;

    let ceremony_identifier = decode_external_identifier(input.ceremony_identifier_bytes)?;
    let action_identifier = decode_external_identifier(input.action_identifier_bytes)?;
    let ceremony_context = CeremonyContext::new(&suite, &manifest, &roster, ceremony_identifier)
        .map_err(|error| refusal_status(error.refusal_reason))?;
    let action_context = ActionContext::new(
        &ceremony_context,
        action_identifier,
        action_definition,
        &board_policy,
    )
    .map_err(|error| refusal_status(error.refusal_reason))?;

    let expected_suite_identifier = decode_expected_hash(input.expected_suite_identifier_bytes)?;
    let expected_ceremony_context_hash =
        decode_expected_hash(input.expected_ceremony_context_hash_bytes)?;
    let expected_action_context_hash =
        decode_expected_hash(input.expected_action_context_hash_bytes)?;
    if action_context.suite_id() != expected_suite_identifier
        || action_context.ceremony_context_hash() != expected_ceremony_context_hash
        || action_context.context_hash() != expected_action_context_hash
    {
        return Err(refusal_status(RefusalReason::WrongContext));
    }

    let count_limits = suite.count_limits();
    let limits = CanonicalBoardLimits {
        maximum_ballot_attempts_per_participant: u64::from(
            count_limits.maximum_ballot_attempts_per_participant(),
        ),
        maximum_retained_canonical_carrier_byte_length: super::MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH,
        maximum_unordered_carriers_per_batch: MAXIMUM_CANONICAL_BOARD_BATCH_CARRIER_COUNT,
        maximum_retained_transcript_objects: MAXIMUM_CANONICAL_BOARD_BATCH_CARRIER_COUNT,
    };
    Ok(BoardVerifierRuntimeConfiguration {
        suite_id: action_context.suite_id(),
        manifest_hash: ceremony_context.manifest_hash(),
        ceremony_context_hash: action_context.ceremony_context_hash(),
        action_context_hash: action_context.context_hash(),
        action_top_count: action_definition.top_count(),
        limits,
        roster,
    })
}

fn require_individually_bounded_input(bytes: &[u8]) -> RuntimeResult<()> {
    if bytes.is_empty() {
        return Err(refusal_status(RefusalReason::WrongTypeOrLength));
    }
    if bytes.len() > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length {
        return Err(refusal_status(RefusalReason::OutsideSupportedProfile));
    }
    Ok(())
}

fn require_exact_reencoding(input: &[u8], canonical_bytes: Vec<u8>) -> RuntimeResult<()> {
    if input != canonical_bytes {
        return Err(refusal_status(RefusalReason::MalformedEncoding));
    }
    Ok(())
}

fn decode_external_identifier(bytes: &[u8]) -> RuntimeResult<String> {
    require_individually_bounded_input(bytes)?;
    core::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| refusal_status(RefusalReason::MalformedEncoding))
}

fn decode_expected_hash(bytes: &[u8]) -> RuntimeResult<Hash512> {
    let hash_bytes = <[u8; Hash512::BYTE_LENGTH]>::try_from(bytes)
        .map_err(|_| refusal_status(RefusalReason::WrongTypeOrLength))?;
    Ok(Hash512::from_bytes(hash_bytes))
}

fn decode_framed_carriers(bytes: &[u8]) -> RuntimeResult<Vec<Vec<u8>>> {
    if bytes.is_empty() || bytes.len() > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length {
        return Err(refusal_status(if bytes.is_empty() {
            RefusalReason::WrongTypeOrLength
        } else {
            RefusalReason::OutsideSupportedProfile
        }));
    }
    let mut reader = InputReader::new(bytes);
    let count = usize::try_from(reader.read_u32()?)
        .map_err(|_| refusal_status(RefusalReason::OutsideSupportedProfile))?;
    if count == 0
        || count
            > usize::try_from(MAXIMUM_CANONICAL_BOARD_BATCH_CARRIER_COUNT)
                .map_err(|_| refusal_status(RefusalReason::OutsideSupportedProfile))?
    {
        return Err(refusal_status(RefusalReason::OutsideSupportedProfile));
    }
    let mut carriers = Vec::with_capacity(count);
    for _ in 0..count {
        let byte_length = usize::try_from(reader.read_u32()?)
            .map_err(|_| refusal_status(RefusalReason::OutsideSupportedProfile))?;
        if byte_length == 0 {
            return Err(refusal_status(RefusalReason::WrongTypeOrLength));
        }
        carriers.push(reader.read_bytes(byte_length)?.to_vec());
    }
    reader.finish()?;
    Ok(carriers)
}

fn encode_verified_object_handles(handles: &[u32]) -> RuntimeResult<Vec<u8>> {
    let count = u32::try_from(handles.len())
        .map_err(|_| refusal_status(RefusalReason::OutsideSupportedProfile))?;
    let capacity = handles
        .len()
        .checked_mul(4)
        .and_then(|value| value.checked_add(4))
        .ok_or_else(|| refusal_status(RefusalReason::OutsideSupportedProfile))?;
    let mut output = Vec::with_capacity(capacity);
    output.extend_from_slice(&count.to_le_bytes());
    for handle in handles {
        output.extend_from_slice(&handle.to_le_bytes());
    }
    Ok(output)
}

fn require_active_session<'a>(
    active_session: &'a Option<BoardVerifierRuntimeSession>,
    session_handle: u32,
    capability: &[u8],
) -> RuntimeResult<&'a BoardVerifierRuntimeSession> {
    let session = active_session
        .as_ref()
        .ok_or_else(|| refusal_status(RefusalReason::ConsumedState))?;
    require_session_binding(session, session_handle, capability)?;
    Ok(session)
}

fn require_active_session_mut<'a>(
    active_session: &'a mut Option<BoardVerifierRuntimeSession>,
    session_handle: u32,
    capability: &[u8],
) -> RuntimeResult<&'a mut BoardVerifierRuntimeSession> {
    let session = active_session
        .as_mut()
        .ok_or_else(|| refusal_status(RefusalReason::ConsumedState))?;
    require_session_binding(session, session_handle, capability)?;
    Ok(session)
}

fn require_session_binding(
    session: &BoardVerifierRuntimeSession,
    session_handle: u32,
    capability: &[u8],
) -> RuntimeResult<()> {
    if session.handle != session_handle {
        return Err(refusal_status(RefusalReason::ConsumedState));
    }
    if capability.len() != BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH
        || !bool::from(session.capability.as_ref().ct_eq(capability))
    {
        return Err(refusal_status(RefusalReason::WrongContext));
    }
    Ok(())
}

fn preflight_handle_range(next_handle: u32, additional_count: usize) -> RuntimeResult<()> {
    if next_handle == 0 {
        return Err(refusal_status(RefusalReason::OutsideSupportedProfile));
    }
    let additional_count = u32::try_from(additional_count)
        .map_err(|_| refusal_status(RefusalReason::OutsideSupportedProfile))?;
    next_handle
        .checked_add(additional_count)
        .ok_or_else(|| refusal_status(RefusalReason::OutsideSupportedProfile))?;
    Ok(())
}

fn take_nonrepeating_handle(next_handle: &mut u32) -> RuntimeResult<u32> {
    if *next_handle == 0 {
        return Err(refusal_status(RefusalReason::OutsideSupportedProfile));
    }
    let handle = *next_handle;
    *next_handle = next_handle.checked_add(1).unwrap_or(0);
    Ok(handle)
}

fn with_runtime_registry<Value>(
    operation: impl FnOnce(&mut BoardVerifierRuntimeRegistry) -> RuntimeResult<Value>,
) -> RuntimeResult<Value> {
    static REGISTRY: OnceLock<Mutex<BoardVerifierRuntimeRegistry>> = OnceLock::new();
    let registry = REGISTRY.get_or_init(|| Mutex::new(BoardVerifierRuntimeRegistry::default()));
    let mut registry = match registry.lock() {
        Ok(registry) => registry,
        Err(poisoned) => {
            poisoned.into_inner().active_session = None;
            return Err(refusal_status(RefusalReason::ConsumedState));
        }
    };
    operation(&mut registry)
}
