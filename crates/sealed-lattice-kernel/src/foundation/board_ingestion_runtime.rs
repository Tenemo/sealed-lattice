use std::sync::{Mutex, OnceLock};

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::{
    CanonicalDecodeLimits, FoundationBoardIngestionContext, FoundationBoardIngestionLimits,
    FoundationBoardIngestor, FoundationExternalPrerequisite, FoundationExternalPrerequisiteKind,
    Hash512, RefusalReason, Roster,
};

pub(crate) const FOUNDATION_BOARD_SESSION_CAPABILITY_BYTE_LENGTH: usize = 32;
pub(crate) const FOUNDATION_BOARD_CANDIDATE_HASH_BYTE_LENGTH: usize = Hash512::BYTE_LENGTH;

const FOUNDATION_BOARD_SESSION_CONFIGURATION_VERSION: u16 = 1;
const PUBLIC_SETUP_SEED_ANCHOR_MASK: u16 = 1 << 0;
const SETUP_SOURCE_ANCHOR_MASK: u16 = 1 << 1;
const ASSIGNED_ANCHOR_MASK: u16 = PUBLIC_SETUP_SEED_ANCHOR_MASK | SETUP_SOURCE_ANCHOR_MASK;
const FIXED_CONFIGURATION_BYTE_LENGTH: usize = 2 + 3 * Hash512::BYTE_LENGTH + 4 * 4 + 2 + 4;

struct FoundationBoardRuntimeSession {
    capability: Zeroizing<[u8; FOUNDATION_BOARD_SESSION_CAPABILITY_BYTE_LENGTH]>,
    handle: u32,
    ingestor: FoundationBoardIngestor,
}

struct FoundationBoardRuntimeRegistry {
    active_session: Option<FoundationBoardRuntimeSession>,
    next_handle: u32,
}

impl Default for FoundationBoardRuntimeRegistry {
    fn default() -> Self {
        Self {
            active_session: None,
            next_handle: 1,
        }
    }
}

impl FoundationBoardRuntimeRegistry {
    fn begin(
        &mut self,
        configuration_bytes: &[u8],
        capability: [u8; FOUNDATION_BOARD_SESSION_CAPABILITY_BYTE_LENGTH],
    ) -> RuntimeResult<u32> {
        if self.active_session.is_some() {
            return Err(refusal_status(RefusalReason::OutsideSupportedProfile));
        }
        if capability.iter().all(|byte| *byte == 0) {
            return Err(refusal_status(RefusalReason::WrongContext));
        }

        let configuration = decode_configuration(configuration_bytes)?;
        let ingestor = FoundationBoardIngestor::new(FoundationBoardIngestionContext {
            suite_id: configuration.suite_id,
            ceremony_context_hash: configuration.ceremony_context_hash,
            action_context_hash: configuration.action_context_hash,
            roster: &configuration.roster,
            external_prerequisites: &configuration.external_prerequisites,
            limits: configuration.limits,
        })
        .into_result()
        .map_err(refusal_status)?;
        let handle = self.take_handle()?;
        self.active_session = Some(FoundationBoardRuntimeSession {
            capability: Zeroizing::new(capability),
            handle,
            ingestor,
        });
        Ok(handle)
    }

    fn ingest(
        &mut self,
        handle: u32,
        capability: &[u8],
        canonical_carrier_bytes: &[u8],
    ) -> RuntimeResult<[u8; FOUNDATION_BOARD_CANDIDATE_HASH_BYTE_LENGTH]> {
        let session = self.require_active_session_mut(handle, capability)?;
        session
            .ingestor
            .ingest_canonical_carrier(canonical_carrier_bytes)
            .into_result()
            .map(|candidate| candidate.object_hash().into_bytes())
            .map_err(refusal_status)
    }

    fn require_complete_carrier_graph(&self, handle: u32, capability: &[u8]) -> RuntimeResult<()> {
        self.require_active_session(handle, capability)?
            .ingestor
            .require_complete_carrier_dependency_graph()
            .into_result()
            .map_err(refusal_status)
    }

    fn cancel(&mut self, handle: u32, capability: &[u8]) -> RuntimeResult<()> {
        let Some(session) = self.active_session.as_ref() else {
            return Ok(());
        };
        require_session_binding(session, handle, capability)?;
        self.active_session = None;
        Ok(())
    }

    fn require_active_session(
        &self,
        handle: u32,
        capability: &[u8],
    ) -> RuntimeResult<&FoundationBoardRuntimeSession> {
        let session = self
            .active_session
            .as_ref()
            .ok_or_else(|| refusal_status(RefusalReason::ConsumedState))?;
        require_session_binding(session, handle, capability)?;
        Ok(session)
    }

    fn require_active_session_mut(
        &mut self,
        handle: u32,
        capability: &[u8],
    ) -> RuntimeResult<&mut FoundationBoardRuntimeSession> {
        let session = self
            .active_session
            .as_mut()
            .ok_or_else(|| refusal_status(RefusalReason::ConsumedState))?;
        require_session_binding(session, handle, capability)?;
        Ok(session)
    }

    fn take_handle(&mut self) -> RuntimeResult<u32> {
        if self.next_handle == 0 {
            return Err(refusal_status(RefusalReason::OutsideSupportedProfile));
        }
        let handle = self.next_handle;
        self.next_handle = self.next_handle.checked_add(1).unwrap_or(0);
        Ok(handle)
    }
}

struct FoundationBoardRuntimeConfiguration {
    suite_id: Hash512,
    ceremony_context_hash: Hash512,
    action_context_hash: Hash512,
    roster: Roster,
    external_prerequisites: Vec<FoundationExternalPrerequisite>,
    limits: FoundationBoardIngestionLimits,
}

struct InputReader<'input> {
    bytes: &'input [u8],
    offset: usize,
}

impl<'input> InputReader<'input> {
    const fn new(bytes: &'input [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_array<const BYTE_LENGTH: usize>(&mut self) -> RuntimeResult<[u8; BYTE_LENGTH]> {
        let bytes = self.read_bytes(BYTE_LENGTH)?;
        bytes
            .try_into()
            .map_err(|_| refusal_status(RefusalReason::MalformedEncoding))
    }

    fn read_u16(&mut self) -> RuntimeResult<u16> {
        Ok(u16::from_le_bytes(self.read_array()?))
    }

    fn read_u32(&mut self) -> RuntimeResult<u32> {
        Ok(u32::from_le_bytes(self.read_array()?))
    }

    fn read_bytes(&mut self, byte_length: usize) -> RuntimeResult<&'input [u8]> {
        let end = self
            .offset
            .checked_add(byte_length)
            .ok_or_else(|| refusal_status(RefusalReason::MalformedEncoding))?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| refusal_status(RefusalReason::MalformedEncoding))?;
        self.offset = end;
        Ok(bytes)
    }

    fn finish(self) -> RuntimeResult<()> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(refusal_status(RefusalReason::MalformedEncoding))
        }
    }
}

type RuntimeResult<Value> = Result<Value, u32>;

static FOUNDATION_BOARD_RUNTIME_REGISTRY: OnceLock<Mutex<FoundationBoardRuntimeRegistry>> =
    OnceLock::new();

fn runtime_registry() -> &'static Mutex<FoundationBoardRuntimeRegistry> {
    FOUNDATION_BOARD_RUNTIME_REGISTRY
        .get_or_init(|| Mutex::new(FoundationBoardRuntimeRegistry::default()))
}

fn with_runtime_registry<ResultValue>(
    operation: impl FnOnce(&mut FoundationBoardRuntimeRegistry) -> RuntimeResult<ResultValue>,
) -> RuntimeResult<ResultValue> {
    let mut registry = match runtime_registry().lock() {
        Ok(registry) => registry,
        Err(poisoned) => {
            poisoned.into_inner().active_session = None;
            return Err(refusal_status(RefusalReason::ConsumedState));
        }
    };
    operation(&mut registry)
}

pub(crate) fn begin_foundation_board_session(
    configuration_bytes: &[u8],
    capability: [u8; FOUNDATION_BOARD_SESSION_CAPABILITY_BYTE_LENGTH],
) -> RuntimeResult<u32> {
    with_runtime_registry(|registry| registry.begin(configuration_bytes, capability))
}

pub(crate) fn ingest_foundation_board_carrier(
    handle: u32,
    capability: &[u8],
    canonical_carrier_bytes: &[u8],
) -> RuntimeResult<[u8; FOUNDATION_BOARD_CANDIDATE_HASH_BYTE_LENGTH]> {
    with_runtime_registry(|registry| registry.ingest(handle, capability, canonical_carrier_bytes))
}

pub(crate) fn require_complete_foundation_board_carrier_graph(
    handle: u32,
    capability: &[u8],
) -> RuntimeResult<()> {
    with_runtime_registry(|registry| registry.require_complete_carrier_graph(handle, capability))
}

pub(crate) fn cancel_foundation_board_session(handle: u32, capability: &[u8]) -> RuntimeResult<()> {
    with_runtime_registry(|registry| registry.cancel(handle, capability))
}

fn decode_configuration(
    configuration_bytes: &[u8],
) -> RuntimeResult<FoundationBoardRuntimeConfiguration> {
    if configuration_bytes.len() < FIXED_CONFIGURATION_BYTE_LENGTH {
        return Err(refusal_status(RefusalReason::MalformedEncoding));
    }
    let mut reader = InputReader::new(configuration_bytes);
    if reader.read_u16()? != FOUNDATION_BOARD_SESSION_CONFIGURATION_VERSION {
        return Err(refusal_status(RefusalReason::UnsupportedVersionOrSuite));
    }
    let suite_id = Hash512::from_bytes(reader.read_array()?);
    let ceremony_context_hash = Hash512::from_bytes(reader.read_array()?);
    let action_context_hash = Hash512::from_bytes(reader.read_array()?);
    let limits = FoundationBoardIngestionLimits::try_new(
        usize::try_from(reader.read_u32()?)
            .map_err(|_| refusal_status(RefusalReason::OutsideSupportedProfile))?,
        usize::try_from(reader.read_u32()?)
            .map_err(|_| refusal_status(RefusalReason::OutsideSupportedProfile))?,
        usize::try_from(reader.read_u32()?)
            .map_err(|_| refusal_status(RefusalReason::OutsideSupportedProfile))?,
        usize::try_from(reader.read_u32()?)
            .map_err(|_| refusal_status(RefusalReason::OutsideSupportedProfile))?,
    )
    .map_err(refusal_status)?;
    let anchor_mask = reader.read_u16()?;
    if anchor_mask & !ASSIGNED_ANCHOR_MASK != 0 {
        return Err(refusal_status(RefusalReason::MalformedEncoding));
    }
    let mut external_prerequisites = Vec::with_capacity(anchor_mask.count_ones() as usize);
    if anchor_mask & PUBLIC_SETUP_SEED_ANCHOR_MASK != 0 {
        external_prerequisites.push(FoundationExternalPrerequisite {
            prerequisite_kind: FoundationExternalPrerequisiteKind::PublicSetupSeed,
            object_hash: Hash512::from_bytes(reader.read_array()?),
        });
    }
    if anchor_mask & SETUP_SOURCE_ANCHOR_MASK != 0 {
        external_prerequisites.push(FoundationExternalPrerequisite {
            prerequisite_kind: FoundationExternalPrerequisiteKind::SetupSourceAnchor,
            object_hash: Hash512::from_bytes(reader.read_array()?),
        });
    }
    let roster_byte_length = usize::try_from(reader.read_u32()?)
        .map_err(|_| refusal_status(RefusalReason::OutsideSupportedProfile))?;
    if roster_byte_length == 0 {
        return Err(refusal_status(RefusalReason::WrongTypeOrLength));
    }
    let roster_bytes = reader.read_bytes(roster_byte_length)?;
    reader.finish()?;
    let roster = Roster::decode(roster_bytes, &CanonicalDecodeLimits::default())
        .map_err(|error| refusal_status(error.refusal_reason))?;

    Ok(FoundationBoardRuntimeConfiguration {
        suite_id,
        ceremony_context_hash,
        action_context_hash,
        roster,
        external_prerequisites,
        limits,
    })
}

fn require_session_binding(
    session: &FoundationBoardRuntimeSession,
    handle: u32,
    capability: &[u8],
) -> RuntimeResult<()> {
    if session.handle != handle {
        return Err(refusal_status(RefusalReason::ConsumedState));
    }
    if capability.len() != FOUNDATION_BOARD_SESSION_CAPABILITY_BYTE_LENGTH
        || !bool::from(session.capability.as_ref().ct_eq(capability))
    {
        return Err(refusal_status(RefusalReason::WrongContext));
    }
    Ok(())
}

const fn refusal_status(refusal_reason: RefusalReason) -> u32 {
    refusal_reason.canonical_code() as u32
}

#[cfg(test)]
mod tests {
    use fips204::{
        ml_dsa_65,
        traits::{KeyGen, SerDes},
    };

    use super::*;
    use crate::foundation::{FOUNDATION_PROFILE, RosterEntry};

    fn configuration_bytes() -> Vec<u8> {
        let roster_entries = (0..FOUNDATION_PROFILE.participant_count)
            .map(|roster_position| {
                let mut signing_seed = [0_u8; 32];
                signing_seed[0] =
                    u8::try_from(roster_position + 1).expect("test roster position fits u8");
                signing_seed[31] =
                    u8::try_from(FOUNDATION_PROFILE.participant_count - roster_position)
                        .expect("test reverse roster position fits u8");
                let (verification_key, _) = ml_dsa_65::KG::keygen_from_seed(&signing_seed);
                let mut mailbox_encapsulation_key = [0_u8; 1_184];
                mailbox_encapsulation_key[1_152] =
                    u8::try_from(roster_position + 1).expect("test roster position fits u8");
                RosterEntry {
                    roster_position,
                    signing_verification_key: verification_key.into_bytes(),
                    mailbox_encapsulation_key,
                }
            })
            .collect();
        let roster_bytes = Roster::new(roster_entries)
            .expect("test roster is valid")
            .encode()
            .expect("test roster encodes");
        let mut configuration = Vec::new();
        configuration
            .extend_from_slice(&FOUNDATION_BOARD_SESSION_CONFIGURATION_VERSION.to_le_bytes());
        configuration.extend_from_slice(&[0x11; Hash512::BYTE_LENGTH]);
        configuration.extend_from_slice(&[0x22; Hash512::BYTE_LENGTH]);
        configuration.extend_from_slice(&[0x33; Hash512::BYTE_LENGTH]);
        configuration.extend_from_slice(&131_072_u32.to_le_bytes());
        configuration.extend_from_slice(&32_u32.to_le_bytes());
        configuration.extend_from_slice(&1_048_576_u32.to_le_bytes());
        configuration.extend_from_slice(&128_u32.to_le_bytes());
        configuration.extend_from_slice(&0_u16.to_le_bytes());
        configuration.extend_from_slice(
            &u32::try_from(roster_bytes.len())
                .expect("test roster length fits u32")
                .to_le_bytes(),
        );
        configuration.extend_from_slice(&roster_bytes);
        configuration
    }

    #[test]
    fn handles_never_wrap_or_reuse_after_exhaustion() {
        let mut registry = FoundationBoardRuntimeRegistry {
            active_session: None,
            next_handle: u32::MAX,
        };
        assert_eq!(registry.take_handle(), Ok(u32::MAX));
        assert_eq!(registry.next_handle, 0);
        assert_eq!(
            registry.take_handle(),
            Err(refusal_status(RefusalReason::OutsideSupportedProfile))
        );
        assert_eq!(registry.next_handle, 0);
    }

    #[test]
    fn forged_and_overlapping_requests_do_not_destroy_the_active_session() {
        let configuration = configuration_bytes();
        let owner = [0x41; FOUNDATION_BOARD_SESSION_CAPABILITY_BYTE_LENGTH];
        let mut registry = FoundationBoardRuntimeRegistry::default();
        let handle = registry
            .begin(&configuration, owner)
            .expect("board session begins");

        assert_eq!(
            registry.cancel(handle.wrapping_add(1), &owner),
            Err(refusal_status(RefusalReason::ConsumedState))
        );
        assert!(registry.active_session.is_some());
        assert_eq!(
            registry.cancel(
                handle,
                &[0x42; FOUNDATION_BOARD_SESSION_CAPABILITY_BYTE_LENGTH],
            ),
            Err(refusal_status(RefusalReason::WrongContext))
        );
        assert!(registry.active_session.is_some());
        assert_eq!(
            registry.begin(
                &configuration,
                [0x43; FOUNDATION_BOARD_SESSION_CAPABILITY_BYTE_LENGTH],
            ),
            Err(refusal_status(RefusalReason::OutsideSupportedProfile))
        );
        assert!(registry.active_session.is_some());
        assert_eq!(
            registry.require_complete_carrier_graph(handle, &owner),
            Ok(())
        );
        assert_eq!(registry.cancel(handle, &owner), Ok(()));
        assert!(registry.active_session.is_none());
    }
}
