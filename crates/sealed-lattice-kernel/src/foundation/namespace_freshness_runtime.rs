use std::{cell::RefCell, collections::HashMap};

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::{
    CanonicalDecodeLimits, FOUNDATION_PROFILE, Hash512, NamespaceFreshnessVerifier,
    ParticipantIdentity, RefusalReason, Roster, VerifiedNamespaceFreshnessCertificate,
    VerifiedNamespaceFreshnessCheckpoint,
};

const COMMAND_BEGIN: u32 = 1;
const COMMAND_PREPARE_CHECKPOINT: u32 = 2;
const COMMAND_VERIFY_CHECKPOINT: u32 = 3;
const COMMAND_DESCRIBE_CHECKPOINT: u32 = 4;
const COMMAND_VERIFY_VOTE_CARRIER: u32 = 5;
const COMMAND_VERIFY_CERTIFICATE: u32 = 6;
const COMMAND_DESCRIBE_CERTIFICATE: u32 = 7;
const COMMAND_RELEASE_CHECKPOINT: u32 = 8;
const COMMAND_RELEASE_CERTIFICATE: u32 = 9;
const COMMAND_CANCEL: u32 = 10;

const CONFIGURATION_VERSION: u16 = 1;
const DESCRIPTION_VERSION: u16 = 1;
const HASH_BYTE_LENGTH: usize = Hash512::BYTE_LENGTH;
const HANDLE_BYTE_LENGTH: usize = size_of::<u32>();
const MAXIMUM_RETAINED_CHECKPOINT_COUNT: usize = 64;
const MAXIMUM_RETAINED_CERTIFICATE_COUNT: usize = 64;

pub(crate) const NAMESPACE_FRESHNESS_SESSION_CAPABILITY_BYTE_LENGTH: usize = 32;
pub(crate) const VERIFIED_NAMESPACE_FRESHNESS_CHECKPOINT_DESCRIPTION_BYTE_LENGTH: usize =
    size_of::<u16>()
        + 5 * HASH_BYTE_LENGTH
        + size_of::<u64>()
        + HASH_BYTE_LENGTH
        + size_of::<u8>()
        + HASH_BYTE_LENGTH
        + HASH_BYTE_LENGTH;

type RuntimeResult<Value> = Result<Value, u32>;

struct NamespaceFreshnessRuntimeSession {
    capability: Zeroizing<[u8; NAMESPACE_FRESHNESS_SESSION_CAPABILITY_BYTE_LENGTH]>,
    handle: u32,
    verifier: NamespaceFreshnessVerifier,
    verified_certificates: HashMap<u32, VerifiedNamespaceFreshnessCertificate>,
    verified_checkpoints: HashMap<u32, VerifiedNamespaceFreshnessCheckpoint>,
}

struct NamespaceFreshnessRuntimeRegistry {
    active_session: Option<NamespaceFreshnessRuntimeSession>,
    next_certificate_handle: u32,
    next_checkpoint_handle: u32,
    next_session_handle: u32,
}

impl Default for NamespaceFreshnessRuntimeRegistry {
    fn default() -> Self {
        Self {
            active_session: None,
            next_certificate_handle: 1,
            next_checkpoint_handle: 1,
            next_session_handle: 1,
        }
    }
}

impl NamespaceFreshnessRuntimeRegistry {
    fn begin(
        &mut self,
        capability: [u8; NAMESPACE_FRESHNESS_SESSION_CAPABILITY_BYTE_LENGTH],
        configuration_bytes: &[u8],
    ) -> RuntimeResult<Vec<u8>> {
        if self.active_session.is_some() {
            return Err(refusal_status(RefusalReason::OutsideSupportedProfile));
        }
        if capability.iter().all(|byte| *byte == 0) {
            return Err(refusal_status(RefusalReason::WrongContext));
        }
        let configuration = decode_configuration(configuration_bytes)?;
        let verifier = NamespaceFreshnessVerifier::new(
            configuration.suite_identifier,
            configuration.ceremony_context_hash,
            configuration.action_context_hash,
            configuration.subject_participant_identity,
            configuration.storage_instance_identity,
            &configuration.roster,
        )
        .map_err(|error| refusal_status(error.refusal_reason))?;
        let handle = take_nonrepeating_handle(&mut self.next_session_handle)?;
        self.active_session = Some(NamespaceFreshnessRuntimeSession {
            capability: Zeroizing::new(capability),
            handle,
            verifier,
            verified_certificates: HashMap::new(),
            verified_checkpoints: HashMap::new(),
        });
        Ok(handle.to_le_bytes().to_vec())
    }

    fn prepare_checkpoint(
        &mut self,
        session_handle: u32,
        capability: &[u8],
        namespace_sequence: u64,
        authenticated_head_digest: Hash512,
        previous_checkpoint_hash: Option<Hash512>,
    ) -> RuntimeResult<Vec<u8>> {
        let verified_checkpoint = {
            let session = require_active_session(&self.active_session, session_handle, capability)?;
            if session.verified_checkpoints.len() >= MAXIMUM_RETAINED_CHECKPOINT_COUNT {
                return Err(refusal_status(RefusalReason::OutsideSupportedProfile));
            }
            session
                .verifier
                .prepare_checkpoint(
                    namespace_sequence,
                    authenticated_head_digest,
                    previous_checkpoint_hash,
                )
                .into_result()
                .map_err(refusal_status)?
        };
        self.retain_checkpoint(session_handle, capability, verified_checkpoint)
    }

    fn verify_checkpoint(
        &mut self,
        session_handle: u32,
        capability: &[u8],
        canonical_checkpoint: &[u8],
    ) -> RuntimeResult<Vec<u8>> {
        let verified_checkpoint = {
            let session = require_active_session(&self.active_session, session_handle, capability)?;
            if session.verified_checkpoints.len() >= MAXIMUM_RETAINED_CHECKPOINT_COUNT {
                return Err(refusal_status(RefusalReason::OutsideSupportedProfile));
            }
            session
                .verifier
                .verify_checkpoint(canonical_checkpoint, &CanonicalDecodeLimits::default())
                .into_result()
                .map_err(refusal_status)?
        };
        self.retain_checkpoint(session_handle, capability, verified_checkpoint)
    }

    fn retain_checkpoint(
        &mut self,
        session_handle: u32,
        capability: &[u8],
        verified_checkpoint: VerifiedNamespaceFreshnessCheckpoint,
    ) -> RuntimeResult<Vec<u8>> {
        let canonical_checkpoint = verified_checkpoint.canonical_checkpoint();
        let canonical_byte_length = u32::try_from(canonical_checkpoint.len())
            .map_err(|_| refusal_status(RefusalReason::OutsideSupportedProfile))?;
        let checkpoint_handle = take_nonrepeating_handle(&mut self.next_checkpoint_handle)?;
        let mut output =
            Vec::with_capacity(HANDLE_BYTE_LENGTH + size_of::<u32>() + canonical_checkpoint.len());
        output.extend_from_slice(&checkpoint_handle.to_le_bytes());
        output.extend_from_slice(&canonical_byte_length.to_le_bytes());
        output.extend_from_slice(canonical_checkpoint);
        require_active_session_mut(&mut self.active_session, session_handle, capability)?
            .verified_checkpoints
            .insert(checkpoint_handle, verified_checkpoint);
        Ok(output)
    }

    fn describe_checkpoint(
        &self,
        session_handle: u32,
        capability: &[u8],
        checkpoint_handle: u32,
    ) -> RuntimeResult<Vec<u8>> {
        let session = require_active_session(&self.active_session, session_handle, capability)?;
        let verified_checkpoint = session
            .verified_checkpoints
            .get(&checkpoint_handle)
            .ok_or_else(|| refusal_status(RefusalReason::ConsumedState))?;
        Ok(encode_checkpoint_description(verified_checkpoint))
    }

    fn verify_vote_carrier(
        &self,
        session_handle: u32,
        capability: &[u8],
        checkpoint_handle: u32,
        expected_witness_participant_identity: ParticipantIdentity,
        canonical_vote_carrier: &[u8],
    ) -> RuntimeResult<Vec<u8>> {
        let session = require_active_session(&self.active_session, session_handle, capability)?;
        let verified_checkpoint = session
            .verified_checkpoints
            .get(&checkpoint_handle)
            .ok_or_else(|| refusal_status(RefusalReason::ConsumedState))?;
        session
            .verifier
            .verify_vote_carrier(
                verified_checkpoint,
                expected_witness_participant_identity,
                canonical_vote_carrier,
                &CanonicalDecodeLimits::default(),
            )
            .into_result()
            .map_err(refusal_status)?;
        Ok(Vec::new())
    }

    fn verify_certificate(
        &mut self,
        session_handle: u32,
        capability: &[u8],
        checkpoint_handle: u32,
        canonical_vote_carriers: &[Vec<u8>],
    ) -> RuntimeResult<Vec<u8>> {
        let verified_certificate = {
            let session = require_active_session(&self.active_session, session_handle, capability)?;
            if session.verified_certificates.len() >= MAXIMUM_RETAINED_CERTIFICATE_COUNT {
                return Err(refusal_status(RefusalReason::OutsideSupportedProfile));
            }
            let verified_checkpoint = session
                .verified_checkpoints
                .get(&checkpoint_handle)
                .ok_or_else(|| refusal_status(RefusalReason::ConsumedState))?;
            session
                .verifier
                .verify_certificate(
                    verified_checkpoint,
                    canonical_vote_carriers,
                    &CanonicalDecodeLimits::default(),
                )
                .into_result()
                .map_err(refusal_status)?
        };
        let certificate_handle = take_nonrepeating_handle(&mut self.next_certificate_handle)?;
        require_active_session_mut(&mut self.active_session, session_handle, capability)?
            .verified_certificates
            .insert(certificate_handle, verified_certificate);
        Ok(certificate_handle.to_le_bytes().to_vec())
    }

    fn describe_certificate(
        &self,
        session_handle: u32,
        capability: &[u8],
        certificate_handle: u32,
    ) -> RuntimeResult<Vec<u8>> {
        let session = require_active_session(&self.active_session, session_handle, capability)?;
        let certificate = session
            .verified_certificates
            .get(&certificate_handle)
            .ok_or_else(|| refusal_status(RefusalReason::ConsumedState))?;
        let witness_count = u16::try_from(certificate.witness_participant_identities().len())
            .map_err(|_| refusal_status(RefusalReason::OutsideSupportedProfile))?;
        let mut output = Vec::with_capacity(
            size_of::<u16>()
                + size_of::<u16>()
                + usize::from(witness_count) * ParticipantIdentity::BYTE_LENGTH,
        );
        output.extend_from_slice(&DESCRIPTION_VERSION.to_le_bytes());
        output.extend_from_slice(&witness_count.to_le_bytes());
        for identity in certificate.witness_participant_identities() {
            output.extend_from_slice(identity.as_bytes());
        }
        Ok(output)
    }

    fn release_checkpoint(
        &mut self,
        session_handle: u32,
        capability: &[u8],
        checkpoint_handle: u32,
    ) -> RuntimeResult<Vec<u8>> {
        require_active_session_mut(&mut self.active_session, session_handle, capability)?
            .verified_checkpoints
            .remove(&checkpoint_handle)
            .map(|_| Vec::new())
            .ok_or_else(|| refusal_status(RefusalReason::ConsumedState))
    }

    fn release_certificate(
        &mut self,
        session_handle: u32,
        capability: &[u8],
        certificate_handle: u32,
    ) -> RuntimeResult<Vec<u8>> {
        require_active_session_mut(&mut self.active_session, session_handle, capability)?
            .verified_certificates
            .remove(&certificate_handle)
            .map(|_| Vec::new())
            .ok_or_else(|| refusal_status(RefusalReason::ConsumedState))
    }

    fn cancel(&mut self, session_handle: u32, capability: &[u8]) -> RuntimeResult<Vec<u8>> {
        require_active_session(&self.active_session, session_handle, capability)?;
        self.active_session = None;
        Ok(Vec::new())
    }
}

struct NamespaceFreshnessRuntimeConfiguration {
    suite_identifier: Hash512,
    ceremony_context_hash: Hash512,
    action_context_hash: Hash512,
    subject_participant_identity: ParticipantIdentity,
    storage_instance_identity: Hash512,
    roster: Roster,
}

thread_local! {
    static REGISTRY: RefCell<NamespaceFreshnessRuntimeRegistry> =
        RefCell::new(NamespaceFreshnessRuntimeRegistry::default());
}

pub(crate) fn run_namespace_freshness_command(
    command: u32,
    input: &[u8],
) -> RuntimeResult<Vec<u8>> {
    if input.len() > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length {
        return Err(refusal_status(RefusalReason::OutsideSupportedProfile));
    }
    REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        let mut reader = InputReader::new(input);
        let output = match command {
            COMMAND_BEGIN => {
                let capability = reader.read_array()?;
                let configuration_bytes = reader.read_remaining();
                registry.begin(capability, configuration_bytes)
            }
            COMMAND_PREPARE_CHECKPOINT => {
                let (session_handle, capability) = read_session_binding(&mut reader)?;
                let namespace_sequence = reader.read_u64()?;
                let authenticated_head_digest = Hash512::from_bytes(reader.read_array()?);
                let previous_checkpoint_hash = read_optional_hash(&mut reader)?;
                reader.finish()?;
                registry.prepare_checkpoint(
                    session_handle,
                    &capability,
                    namespace_sequence,
                    authenticated_head_digest,
                    previous_checkpoint_hash,
                )
            }
            COMMAND_VERIFY_CHECKPOINT => {
                let (session_handle, capability) = read_session_binding(&mut reader)?;
                let canonical_checkpoint = reader.read_length_prefixed_bytes()?;
                reader.finish()?;
                registry.verify_checkpoint(session_handle, &capability, canonical_checkpoint)
            }
            COMMAND_DESCRIBE_CHECKPOINT => {
                let (session_handle, capability) = read_session_binding(&mut reader)?;
                let checkpoint_handle = reader.read_u32()?;
                reader.finish()?;
                registry.describe_checkpoint(session_handle, &capability, checkpoint_handle)
            }
            COMMAND_VERIFY_VOTE_CARRIER => {
                let (session_handle, capability) = read_session_binding(&mut reader)?;
                let checkpoint_handle = reader.read_u32()?;
                let expected_witness_participant_identity =
                    ParticipantIdentity::from_bytes(reader.read_array()?);
                let canonical_vote_carrier = reader.read_length_prefixed_bytes()?;
                reader.finish()?;
                registry.verify_vote_carrier(
                    session_handle,
                    &capability,
                    checkpoint_handle,
                    expected_witness_participant_identity,
                    canonical_vote_carrier,
                )
            }
            COMMAND_VERIFY_CERTIFICATE => {
                let (session_handle, capability) = read_session_binding(&mut reader)?;
                let checkpoint_handle = reader.read_u32()?;
                let carrier_count = usize::from(reader.read_u16()?);
                if carrier_count < usize::from(FOUNDATION_PROFILE.state_witness_quorum)
                    || carrier_count
                        > usize::from(FOUNDATION_PROFILE.participant_count.saturating_sub(1))
                {
                    return Err(refusal_status(RefusalReason::MissingPrerequisite));
                }
                let mut carriers = Vec::with_capacity(carrier_count);
                for _ in 0..carrier_count {
                    carriers.push(reader.read_length_prefixed_bytes()?.to_vec());
                }
                reader.finish()?;
                registry.verify_certificate(
                    session_handle,
                    &capability,
                    checkpoint_handle,
                    &carriers,
                )
            }
            COMMAND_DESCRIBE_CERTIFICATE => {
                let (session_handle, capability) = read_session_binding(&mut reader)?;
                let certificate_handle = reader.read_u32()?;
                reader.finish()?;
                registry.describe_certificate(session_handle, &capability, certificate_handle)
            }
            COMMAND_RELEASE_CHECKPOINT => {
                let (session_handle, capability) = read_session_binding(&mut reader)?;
                let checkpoint_handle = reader.read_u32()?;
                reader.finish()?;
                registry.release_checkpoint(session_handle, &capability, checkpoint_handle)
            }
            COMMAND_RELEASE_CERTIFICATE => {
                let (session_handle, capability) = read_session_binding(&mut reader)?;
                let certificate_handle = reader.read_u32()?;
                reader.finish()?;
                registry.release_certificate(session_handle, &capability, certificate_handle)
            }
            COMMAND_CANCEL => {
                let (session_handle, capability) = read_session_binding(&mut reader)?;
                reader.finish()?;
                registry.cancel(session_handle, &capability)
            }
            _ => Err(refusal_status(RefusalReason::UnsupportedVersionOrSuite)),
        }?;
        if output.len() > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length {
            return Err(refusal_status(RefusalReason::OutsideSupportedProfile));
        }
        Ok(output)
    })
}

fn encode_checkpoint_description(
    verified_checkpoint: &VerifiedNamespaceFreshnessCheckpoint,
) -> Vec<u8> {
    let checkpoint = verified_checkpoint.checkpoint();
    let mut output =
        Vec::with_capacity(VERIFIED_NAMESPACE_FRESHNESS_CHECKPOINT_DESCRIPTION_BYTE_LENGTH);
    output.extend_from_slice(&DESCRIPTION_VERSION.to_le_bytes());
    output.extend_from_slice(checkpoint.suite_identifier().as_bytes());
    output.extend_from_slice(checkpoint.ceremony_context_hash().as_bytes());
    output.extend_from_slice(checkpoint.action_context_hash().as_bytes());
    output.extend_from_slice(checkpoint.subject_participant_identity().as_bytes());
    output.extend_from_slice(checkpoint.storage_instance_identity().as_bytes());
    output.extend_from_slice(&checkpoint.namespace_sequence().to_le_bytes());
    output.extend_from_slice(checkpoint.authenticated_head_digest().as_bytes());
    if let Some(previous_checkpoint_hash) = checkpoint.previous_checkpoint_hash() {
        output.push(1);
        output.extend_from_slice(previous_checkpoint_hash.as_bytes());
    } else {
        output.push(0);
        output.extend_from_slice(&[0; HASH_BYTE_LENGTH]);
    }
    output.extend_from_slice(verified_checkpoint.checkpoint_hash().as_bytes());
    debug_assert_eq!(
        output.len(),
        VERIFIED_NAMESPACE_FRESHNESS_CHECKPOINT_DESCRIPTION_BYTE_LENGTH
    );
    output
}

fn decode_configuration(bytes: &[u8]) -> RuntimeResult<NamespaceFreshnessRuntimeConfiguration> {
    let fixed_byte_length = size_of::<u16>() + 5 * HASH_BYTE_LENGTH + size_of::<u32>();
    if bytes.len() < fixed_byte_length
        || bytes.len() > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length
    {
        return Err(refusal_status(RefusalReason::MalformedEncoding));
    }
    let mut reader = InputReader::new(bytes);
    if reader.read_u16()? != CONFIGURATION_VERSION {
        return Err(refusal_status(RefusalReason::UnsupportedVersionOrSuite));
    }
    let suite_identifier = Hash512::from_bytes(reader.read_array()?);
    let ceremony_context_hash = Hash512::from_bytes(reader.read_array()?);
    let action_context_hash = Hash512::from_bytes(reader.read_array()?);
    let subject_participant_identity = ParticipantIdentity::from_bytes(reader.read_array()?);
    let storage_instance_identity = Hash512::from_bytes(reader.read_array()?);
    let roster_byte_length = usize::try_from(reader.read_u32()?)
        .map_err(|_| refusal_status(RefusalReason::OutsideSupportedProfile))?;
    if roster_byte_length == 0 {
        return Err(refusal_status(RefusalReason::WrongTypeOrLength));
    }
    let roster = Roster::decode(
        reader.read_bytes(roster_byte_length)?,
        &CanonicalDecodeLimits::default(),
    )
    .map_err(|error| refusal_status(error.refusal_reason))?;
    reader.finish()?;
    Ok(NamespaceFreshnessRuntimeConfiguration {
        suite_identifier,
        ceremony_context_hash,
        action_context_hash,
        subject_participant_identity,
        storage_instance_identity,
        roster,
    })
}

fn read_session_binding(
    reader: &mut InputReader<'_>,
) -> RuntimeResult<(
    u32,
    [u8; NAMESPACE_FRESHNESS_SESSION_CAPABILITY_BYTE_LENGTH],
)> {
    Ok((reader.read_u32()?, reader.read_array()?))
}

fn read_optional_hash(reader: &mut InputReader<'_>) -> RuntimeResult<Option<Hash512>> {
    match reader.read_u8()? {
        0 => Ok(None),
        1 => Ok(Some(Hash512::from_bytes(reader.read_array()?))),
        _ => Err(refusal_status(RefusalReason::MalformedEncoding)),
    }
}

fn require_active_session<'session>(
    active_session: &'session Option<NamespaceFreshnessRuntimeSession>,
    session_handle: u32,
    capability: &[u8],
) -> RuntimeResult<&'session NamespaceFreshnessRuntimeSession> {
    let session = active_session
        .as_ref()
        .ok_or_else(|| refusal_status(RefusalReason::ConsumedState))?;
    require_session_binding(session, session_handle, capability)?;
    Ok(session)
}

fn require_active_session_mut<'session>(
    active_session: &'session mut Option<NamespaceFreshnessRuntimeSession>,
    session_handle: u32,
    capability: &[u8],
) -> RuntimeResult<&'session mut NamespaceFreshnessRuntimeSession> {
    let session = active_session
        .as_mut()
        .ok_or_else(|| refusal_status(RefusalReason::ConsumedState))?;
    require_session_binding(session, session_handle, capability)?;
    Ok(session)
}

fn require_session_binding(
    session: &NamespaceFreshnessRuntimeSession,
    session_handle: u32,
    capability: &[u8],
) -> RuntimeResult<()> {
    if session.handle != session_handle {
        return Err(refusal_status(RefusalReason::ConsumedState));
    }
    if capability.len() != NAMESPACE_FRESHNESS_SESSION_CAPABILITY_BYTE_LENGTH
        || !bool::from(session.capability.as_ref().ct_eq(capability))
    {
        return Err(refusal_status(RefusalReason::WrongContext));
    }
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

struct InputReader<'input> {
    bytes: &'input [u8],
    offset: usize,
}

impl<'input> InputReader<'input> {
    const fn new(bytes: &'input [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_u8(&mut self) -> RuntimeResult<u8> {
        Ok(self.read_array::<1>()?[0])
    }

    fn read_u16(&mut self) -> RuntimeResult<u16> {
        Ok(u16::from_le_bytes(self.read_array()?))
    }

    fn read_u32(&mut self) -> RuntimeResult<u32> {
        Ok(u32::from_le_bytes(self.read_array()?))
    }

    fn read_u64(&mut self) -> RuntimeResult<u64> {
        Ok(u64::from_le_bytes(self.read_array()?))
    }

    fn read_array<const LENGTH: usize>(&mut self) -> RuntimeResult<[u8; LENGTH]> {
        self.read_bytes(LENGTH)?
            .try_into()
            .map_err(|_| refusal_status(RefusalReason::MalformedEncoding))
    }

    fn read_bytes(&mut self, byte_length: usize) -> RuntimeResult<&'input [u8]> {
        let end = self
            .offset
            .checked_add(byte_length)
            .ok_or_else(|| refusal_status(RefusalReason::MalformedEncoding))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| refusal_status(RefusalReason::MalformedEncoding))?;
        self.offset = end;
        Ok(value)
    }

    fn read_length_prefixed_bytes(&mut self) -> RuntimeResult<&'input [u8]> {
        let byte_length = usize::try_from(self.read_u32()?)
            .map_err(|_| refusal_status(RefusalReason::OutsideSupportedProfile))?;
        if byte_length == 0 || byte_length > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length {
            return Err(refusal_status(RefusalReason::WrongTypeOrLength));
        }
        self.read_bytes(byte_length)
    }

    fn read_remaining(&mut self) -> &'input [u8] {
        let value = &self.bytes[self.offset..];
        self.offset = self.bytes.len();
        value
    }

    fn finish(self) -> RuntimeResult<()> {
        if self.offset != self.bytes.len() {
            return Err(refusal_status(RefusalReason::MalformedEncoding));
        }
        Ok(())
    }
}

const fn refusal_status(refusal_reason: RefusalReason) -> u32 {
    refusal_reason.canonical_code() as u32
}
