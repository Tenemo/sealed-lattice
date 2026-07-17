use core::fmt;

use super::super::schemas::{SchemaResult, read_fixed_bytes, read_hash, read_u16, require_header};
use super::super::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple, FOUNDATION_PROFILE,
    Hash512, ProofApplicationSlotCeilings as ProofFamilyIdentifiers, RefusalReason,
    hash_foundation_tuple_512 as hash512,
};
use super::domain::AttemptClass;
use super::validation::{
    read_nested_tuple, read_optional_u16, read_optional_u32, read_optional_u64,
    require_protocol_version,
};
use super::{
    APPLICATION_SLOT_HASH_DOMAIN, FOUNDATION_SCHEMA_VERSION, ORDINARY_BALLOT_PROOF_FAMILY,
    ORDINARY_PROOF_COIN_INPUT_SCHEMA_IDENTIFIER, PERSISTENT_PROOF_COIN_INPUT_SCHEMA_IDENTIFIER,
    PRIVATE_RANDOMNESS_ATTEMPT_IDENTIFIER_BYTE_LENGTH, PROOF_APPLICATION_SLOT_SCHEMA_IDENTIFIER,
    RESET_SAFE_PROOF_FAMILIES, TARGET_DECRYPTION_SHARE_PROOF_FAMILY, schema_error,
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateRandomnessAttemptIdentifier {
    pub(super) bytes: [u8; PRIVATE_RANDOMNESS_ATTEMPT_IDENTIFIER_BYTE_LENGTH],
    pub(super) attempt_class: AttemptClass,
}

impl PrivateRandomnessAttemptIdentifier {
    pub const fn as_bytes(&self) -> &[u8; PRIVATE_RANDOMNESS_ATTEMPT_IDENTIFIER_BYTE_LENGTH] {
        &self.bytes
    }
}

impl fmt::Debug for PrivateRandomnessAttemptIdentifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateRandomnessAttemptIdentifier")
            .field("attempt_class", &self.attempt_class)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofApplicationSlot {
    pub(super) suite_identifier: Hash512,
    pub(super) ceremony_context_hash: Hash512,
    pub(super) action_context_hash: Hash512,
    pub(super) application_statement_schema_identifier: u16,
    roster_position: Option<u16>,
    schedule_position: Option<u32>,
    producer_sequence: Option<u64>,
}

impl ProofApplicationSlot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        suite_identifier: Hash512,
        ceremony_context_hash: Hash512,
        action_context_hash: Hash512,
        application_statement_schema_identifier: u16,
        roster_position: Option<u16>,
        schedule_position: Option<u32>,
        producer_sequence: Option<u64>,
    ) -> SchemaResult<Self> {
        let slot = Self {
            suite_identifier,
            ceremony_context_hash,
            action_context_hash,
            application_statement_schema_identifier,
            roster_position,
            schedule_position,
            producer_sequence,
        };
        slot.validate()?;
        Ok(slot)
    }

    pub const fn suite_identifier(self) -> Hash512 {
        self.suite_identifier
    }

    pub const fn ceremony_context_hash(self) -> Hash512 {
        self.ceremony_context_hash
    }

    pub const fn action_context_hash(self) -> Hash512 {
        self.action_context_hash
    }

    pub const fn application_statement_schema_identifier(self) -> u16 {
        self.application_statement_schema_identifier
    }

    pub const fn roster_position(self) -> Option<u16> {
        self.roster_position
    }

    pub const fn schedule_position(self) -> Option<u32> {
        self.schedule_position
    }

    pub const fn producer_sequence(self) -> Option<u64> {
        self.producer_sequence
    }

    fn validate(self) -> SchemaResult<()> {
        if self
            .roster_position
            .is_some_and(|position| position >= FOUNDATION_PROFILE.participant_count)
        {
            return Err(schema_error(
                RefusalReason::OutsideSupportedProfile,
                "proof application slot roster position is outside the fixed profile",
            ));
        }

        let expected_presence = match self.application_statement_schema_identifier {
            ProofFamilyIdentifiers::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER
            | ProofFamilyIdentifiers::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER
            | ProofFamilyIdentifiers::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER
            | ProofFamilyIdentifiers::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER
            | TARGET_DECRYPTION_SHARE_PROOF_FAMILY => (true, false, false),
            ProofFamilyIdentifiers::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER
            | ProofFamilyIdentifiers::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER
            | ProofFamilyIdentifiers::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER => {
                (true, true, false)
            }
            ProofFamilyIdentifiers::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
            | ProofFamilyIdentifiers::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER => {
                (false, false, false)
            }
            ProofFamilyIdentifiers::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER => {
                (false, true, false)
            }
            ORDINARY_BALLOT_PROOF_FAMILY => (true, false, true),
            _ => {
                return Err(schema_error(
                    RefusalReason::WrongTypeOrLength,
                    "proof application slot uses an unassigned statement schema",
                ));
            }
        };
        let actual_presence = (
            self.roster_position.is_some(),
            self.schedule_position.is_some(),
            self.producer_sequence.is_some(),
        );
        if actual_presence != expected_presence {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "proof application slot optional coordinates do not match its statement schema",
            ));
        }
        Ok(())
    }

    pub(super) fn attempt_class(self) -> SchemaResult<AttemptClass> {
        self.validate()?;
        match self.application_statement_schema_identifier {
            ORDINARY_BALLOT_PROOF_FAMILY => Ok(AttemptClass::OrdinaryProof),
            family if RESET_SAFE_PROOF_FAMILIES.contains(&family) => {
                Ok(AttemptClass::ResetSafeProof)
            }
            _ => Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "public-only proof application slots cannot derive private proof coins",
            )),
        }
    }

    fn canonical_tuple(self) -> SchemaResult<CanonicalTuple> {
        self.validate()?;
        let roster_position = self.roster_position.map(CanonicalItem::unsigned16);
        let schedule_position = self.schedule_position.map(CanonicalItem::unsigned32);
        let producer_sequence = self.producer_sequence.map(CanonicalItem::unsigned64);
        Ok(CanonicalTuple::new(
            PROOF_APPLICATION_SLOT_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(FOUNDATION_PROFILE.protocol_version),
                CanonicalItem::hash512(self.suite_identifier.into_bytes()),
                CanonicalItem::hash512(self.ceremony_context_hash.into_bytes()),
                CanonicalItem::hash512(self.action_context_hash.into_bytes()),
                CanonicalItem::unsigned16(self.application_statement_schema_identifier),
                CanonicalItem::optional(CanonicalItemType::Unsigned16, roster_position.as_ref())?,
                CanonicalItem::optional(CanonicalItemType::Unsigned32, schedule_position.as_ref())?,
                CanonicalItem::optional(CanonicalItemType::Unsigned64, producer_sequence.as_ref())?,
            ],
        ))
    }

    pub fn encode(self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple()?.encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        Self::decode_tuple(&tuple)
    }

    fn decode_tuple(tuple: &CanonicalTuple) -> SchemaResult<Self> {
        require_header(tuple, PROOF_APPLICATION_SLOT_SCHEMA_IDENTIFIER, 8)?;
        require_protocol_version(read_u16(&tuple.items[0])?)?;
        Self::new(
            read_hash(&tuple.items[1])?,
            read_hash(&tuple.items[2])?,
            read_hash(&tuple.items[3])?,
            read_u16(&tuple.items[4])?,
            read_optional_u16(&tuple.items[5])?,
            read_optional_u32(&tuple.items[6])?,
            read_optional_u64(&tuple.items[7])?,
        )
    }

    pub fn hash(self) -> SchemaResult<Hash512> {
        Ok(hash512(
            APPLICATION_SLOT_HASH_DOMAIN,
            &[CanonicalItem::variable_bytes(self.encode()?)?],
        )?)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PersistentProofCoinInput {
    pub(super) application_slot: ProofApplicationSlot,
    application_statement_hash: Hash512,
}

impl PersistentProofCoinInput {
    pub fn new(
        application_slot: ProofApplicationSlot,
        application_statement_hash: Hash512,
    ) -> SchemaResult<Self> {
        if application_slot.attempt_class()? != AttemptClass::ResetSafeProof {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "persistent proof coin input requires a reset-safe proof slot",
            ));
        }
        Ok(Self {
            application_slot,
            application_statement_hash,
        })
    }

    pub const fn application_slot(self) -> ProofApplicationSlot {
        self.application_slot
    }

    pub const fn application_statement_hash(self) -> Hash512 {
        self.application_statement_hash
    }

    fn canonical_tuple(self) -> SchemaResult<CanonicalTuple> {
        Ok(CanonicalTuple::new(
            PERSISTENT_PROOF_COIN_INPUT_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::nested_tuple(&self.application_slot.canonical_tuple()?)?,
                CanonicalItem::hash512(self.application_statement_hash.into_bytes()),
            ],
        ))
    }

    pub fn encode(self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple()?.encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        require_header(&tuple, PERSISTENT_PROOF_COIN_INPUT_SCHEMA_IDENTIFIER, 2)?;
        let slot_tuple = read_nested_tuple(&tuple.items[0], limits)?;
        Self::new(
            ProofApplicationSlot::decode_tuple(&slot_tuple)?,
            read_hash(&tuple.items[1])?,
        )
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct OrdinaryProofCoinInput {
    pub(super) application_slot: ProofApplicationSlot,
    application_statement_hash: Hash512,
    ordinary_proof_attempt_nonce: [u8; PRIVATE_RANDOMNESS_ATTEMPT_IDENTIFIER_BYTE_LENGTH],
}

impl fmt::Debug for OrdinaryProofCoinInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OrdinaryProofCoinInput")
            .field("application_slot", &self.application_slot)
            .field(
                "application_statement_hash",
                &self.application_statement_hash,
            )
            .field("ordinary_proof_attempt_nonce", &"[REDACTED]")
            .finish()
    }
}

impl OrdinaryProofCoinInput {
    pub fn new(
        application_slot: ProofApplicationSlot,
        application_statement_hash: Hash512,
        ordinary_proof_attempt_nonce: [u8; PRIVATE_RANDOMNESS_ATTEMPT_IDENTIFIER_BYTE_LENGTH],
    ) -> SchemaResult<Self> {
        if application_slot.attempt_class()? != AttemptClass::OrdinaryProof {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "ordinary proof coin input requires the ordinary ballot proof slot",
            ));
        }
        Ok(Self {
            application_slot,
            application_statement_hash,
            ordinary_proof_attempt_nonce,
        })
    }

    pub const fn application_slot(self) -> ProofApplicationSlot {
        self.application_slot
    }

    pub const fn application_statement_hash(self) -> Hash512 {
        self.application_statement_hash
    }

    pub const fn ordinary_proof_attempt_nonce(
        self,
    ) -> [u8; PRIVATE_RANDOMNESS_ATTEMPT_IDENTIFIER_BYTE_LENGTH] {
        self.ordinary_proof_attempt_nonce
    }

    fn canonical_tuple(self) -> SchemaResult<CanonicalTuple> {
        Ok(CanonicalTuple::new(
            ORDINARY_PROOF_COIN_INPUT_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::nested_tuple(&self.application_slot.canonical_tuple()?)?,
                CanonicalItem::hash512(self.application_statement_hash.into_bytes()),
                CanonicalItem::fixed_bytes(self.ordinary_proof_attempt_nonce)?,
            ],
        ))
    }

    pub fn encode(self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple()?.encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        require_header(&tuple, ORDINARY_PROOF_COIN_INPUT_SCHEMA_IDENTIFIER, 3)?;
        let slot_tuple = read_nested_tuple(&tuple.items[0], limits)?;
        Self::new(
            ProofApplicationSlot::decode_tuple(&slot_tuple)?,
            read_hash(&tuple.items[1])?,
            read_fixed_bytes(&tuple.items[2])?,
        )
    }
}
