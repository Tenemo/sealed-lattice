use core::{cmp, fmt};

use tiny_keccak::{Hasher, Kmac};
use zeroize::Zeroizing;

use crate::bgv::proof_suite::common_proof_randomness_purpose_is_assigned;

use super::schemas::{
    SchemaResult, read_fixed_bytes, read_hash, read_item, read_u16, read_u64, require_header,
};
use super::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple, FOUNDATION_PROFILE,
    FoundationSchemaError, Hash512, ParticipantIdentity, RefusalReason,
    hash_foundation_tuple_512 as hash512,
};

pub const PROOF_APPLICATION_SLOT_SCHEMA_IDENTIFIER: u16 = 0x0109;
pub const PRIVATE_RANDOM_BLOCK_INPUT_SCHEMA_IDENTIFIER: u16 = 0x0400;
pub const PERSISTENT_PROOF_COIN_INPUT_SCHEMA_IDENTIFIER: u16 = 0x0401;
pub const ACTION_RANDOMNESS_DERIVATION_INPUT_SCHEMA_IDENTIFIER: u16 = 0x0402;
pub const ORDINARY_PROOF_COIN_INPUT_SCHEMA_IDENTIFIER: u16 = 0x0403;
pub const RANDOM_CURSOR_SCHEMA_IDENTIFIER: u16 = 0x1804;

pub const ACTION_RANDOMNESS_ROOT_BYTE_LENGTH: usize = 64;
pub const PRIVATE_RANDOMNESS_ATTEMPT_IDENTIFIER_BYTE_LENGTH: usize = 32;
pub const PRIVATE_RANDOMNESS_BLOCK_BYTE_LENGTH: usize = 64;
pub const PRIVATE_PROOF_SALT_PURPOSE: u16 = 0xfffe;

const FOUNDATION_SCHEMA_VERSION: u16 = 1;
const ACTION_RANDOMNESS_KEY_MATERIAL_BYTE_LENGTH: usize = 192;
const ACTION_RANDOMNESS_COMMITMENT_PREIMAGE_BYTE_LENGTH: usize = 64;
const PRIVATE_RANDOMNESS_STREAM_KEY_BYTE_LENGTH: usize = 64;
const PROOF_COIN_KEY_BYTE_LENGTH: usize = 64;
const PRIVATE_RANDOMNESS_BLOCK_BIT_LENGTH: u16 = 512;

const SUITE_DISTRIBUTION_FAMILY: u16 = 0x0116;
const SETUP_SOURCE_FAMILY: u16 = 0x1201;
const SETUP_MAILBOX_FAMILY: u16 = 0x0200;
const VSS_EXPANSION_FAMILY: u16 = 0x2120;
const TARGET_FLOODING_FAMILY: u16 = 0x1630;
const ORDINARY_BALLOT_PROOF_FAMILY: u16 = 0x1302;
const TARGET_DECRYPTION_SHARE_PROOF_FAMILY: u16 = 0x1621;

const ACTION_RANDOMNESS_KEY_HIERARCHY_CUSTOMIZATION: &[u8] =
    b"sealed-lattice/private-randomness/action-key-hierarchy/v1";
const ACTION_RANDOMNESS_COMMITMENT_DOMAIN: &str =
    "sealed-lattice/private-randomness/action-root-commitment/v1";
const SETUP_ACTION_RANDOMNESS_AUTHORIZATION_DOMAIN: &str =
    "sealed-lattice/setup/state/action-randomness/v1";
const PRIVATE_RANDOMNESS_BLOCK_CUSTOMIZATION: &[u8] = b"sealed-lattice/private-randomness/v1";
const SETUP_ATTEMPT_CUSTOMIZATION: &[u8] = b"sealed-lattice/setup/reset-safe-attempt/v1";
const PERSISTENT_PROOF_ATTEMPT_CUSTOMIZATION: &[u8] = b"sealed-lattice/proof/persistent-attempt/v1";
const ORDINARY_PROOF_ATTEMPT_CUSTOMIZATION: &[u8] = b"sealed-lattice/proof/ordinary-attempt/v1";
const TARGET_RELEASE_ATTEMPT_CUSTOMIZATION: &[u8] = b"sealed-lattice/target-release/attempt/v1";
const APPLICATION_SLOT_HASH_DOMAIN: &str = "sealed-lattice/proof/application-slot/v1";
const APPLICATION_STATEMENT_HASH_DOMAIN: &str = "sealed-lattice/proof/application-statement/v1";
const RELATION_PLAN_VARIANT_HASH_DOMAIN: &str = "sealed-lattice/proof/relation-plan-variant/v1";
const PRIVATE_PROOF_COIN_CONTEXT_HASH_DOMAIN: &str = "sealed-lattice/proof/private-coin-context/v1";

const RESET_SAFE_PROOF_FAMILIES: [u16; 8] = [
    0x2110,
    0x2111,
    0x1211,
    0x1212,
    0x1214,
    0x1216,
    0x1217,
    TARGET_DECRYPTION_SHARE_PROOF_FAMILY,
];
const PUBLIC_ONLY_PROOF_FAMILIES: [u16; 3] = [0x1213, 0x1215, 0x1218];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttemptClass {
    ResetSafeSetup,
    BallotEncryption,
    ResetSafeProof,
    OrdinaryProof,
    TargetRelease,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivateRandomnessDomain {
    family: u16,
    purpose: u16,
}

impl PrivateRandomnessDomain {
    pub fn setup_suite_distribution(purpose: u16) -> SchemaResult<Self> {
        if !matches!(purpose, 1..=7 | 11 | 12) {
            return Err(unassigned_randomness_domain());
        }
        Ok(Self {
            family: SUITE_DISTRIBUTION_FAMILY,
            purpose,
        })
    }

    pub fn ballot_encryption_distribution(purpose: u16) -> SchemaResult<Self> {
        if !matches!(purpose, 8..=10) {
            return Err(unassigned_randomness_domain());
        }
        Ok(Self {
            family: SUITE_DISTRIBUTION_FAMILY,
            purpose,
        })
    }

    pub fn setup_source(purpose: u16) -> SchemaResult<Self> {
        assigned_fixed_purpose_domain(SETUP_SOURCE_FAMILY, purpose, 4)
    }

    pub fn setup_mailbox(purpose: u16) -> SchemaResult<Self> {
        assigned_fixed_purpose_domain(SETUP_MAILBOX_FAMILY, purpose, 3)
    }

    pub fn vss_expansion(purpose: u16) -> SchemaResult<Self> {
        assigned_fixed_purpose_domain(VSS_EXPANSION_FAMILY, purpose, 4)
    }

    pub fn target_flooding(purpose: u16) -> SchemaResult<Self> {
        if !(1..=2).contains(&purpose) {
            return Err(unassigned_randomness_domain());
        }
        Ok(Self {
            family: TARGET_FLOODING_FAMILY,
            purpose,
        })
    }

    pub fn reset_safe_proof(statement_schema_identifier: u16, purpose: u16) -> SchemaResult<Self> {
        proof_domain(
            statement_schema_identifier,
            purpose,
            AttemptClass::ResetSafeProof,
        )
    }

    pub fn ordinary_proof(purpose: u16) -> SchemaResult<Self> {
        proof_domain(
            ORDINARY_BALLOT_PROOF_FAMILY,
            purpose,
            AttemptClass::OrdinaryProof,
        )
    }

    pub(crate) fn from_assigned_pair(family: u16, purpose: u16) -> SchemaResult<Self> {
        match family {
            SUITE_DISTRIBUTION_FAMILY if matches!(purpose, 1..=7 | 11 | 12) => {
                Self::setup_suite_distribution(purpose)
            }
            SUITE_DISTRIBUTION_FAMILY if matches!(purpose, 8..=10) => {
                Self::ballot_encryption_distribution(purpose)
            }
            SETUP_SOURCE_FAMILY => Self::setup_source(purpose),
            SETUP_MAILBOX_FAMILY => Self::setup_mailbox(purpose),
            VSS_EXPANSION_FAMILY => Self::vss_expansion(purpose),
            TARGET_FLOODING_FAMILY => Self::target_flooding(purpose),
            ORDINARY_BALLOT_PROOF_FAMILY => Self::ordinary_proof(purpose),
            family if RESET_SAFE_PROOF_FAMILIES.contains(&family) => {
                Self::reset_safe_proof(family, purpose)
            }
            _ => Err(unassigned_randomness_domain()),
        }
    }

    pub const fn family(self) -> u16 {
        self.family
    }

    pub const fn purpose(self) -> u16 {
        self.purpose
    }

    fn attempt_class(self) -> AttemptClass {
        match self.family {
            SUITE_DISTRIBUTION_FAMILY if matches!(self.purpose, 8..=10) => {
                AttemptClass::BallotEncryption
            }
            SUITE_DISTRIBUTION_FAMILY
            | SETUP_SOURCE_FAMILY
            | SETUP_MAILBOX_FAMILY
            | VSS_EXPANSION_FAMILY => AttemptClass::ResetSafeSetup,
            TARGET_FLOODING_FAMILY => AttemptClass::TargetRelease,
            ORDINARY_BALLOT_PROOF_FAMILY => AttemptClass::OrdinaryProof,
            _ => AttemptClass::ResetSafeProof,
        }
    }
}

fn assigned_fixed_purpose_domain(
    family: u16,
    purpose: u16,
    maximum_purpose: u16,
) -> SchemaResult<PrivateRandomnessDomain> {
    if purpose == 0 || purpose > maximum_purpose {
        return Err(unassigned_randomness_domain());
    }
    Ok(PrivateRandomnessDomain { family, purpose })
}

fn proof_domain(
    statement_schema_identifier: u16,
    purpose: u16,
    attempt_class: AttemptClass,
) -> SchemaResult<PrivateRandomnessDomain> {
    if purpose == 0 || purpose == u16::MAX {
        return Err(unassigned_randomness_domain());
    }
    if PUBLIC_ONLY_PROOF_FAMILIES.contains(&statement_schema_identifier) {
        return Err(schema_error(
            RefusalReason::WrongTypeOrLength,
            "public-only proof families cannot allocate private randomness",
        ));
    }
    let family_matches_attempt = match attempt_class {
        AttemptClass::ResetSafeProof => {
            RESET_SAFE_PROOF_FAMILIES.contains(&statement_schema_identifier)
        }
        AttemptClass::OrdinaryProof => statement_schema_identifier == ORDINARY_BALLOT_PROOF_FAMILY,
        AttemptClass::ResetSafeSetup
        | AttemptClass::BallotEncryption
        | AttemptClass::TargetRelease => false,
    };
    if !family_matches_attempt
        || !common_proof_randomness_purpose_is_assigned(statement_schema_identifier, purpose)
    {
        return Err(unassigned_randomness_domain());
    }
    Ok(PrivateRandomnessDomain {
        family: statement_schema_identifier,
        purpose,
    })
}

fn unassigned_randomness_domain() -> FoundationSchemaError {
    schema_error(
        RefusalReason::WrongTypeOrLength,
        "private-randomness family and purpose pair is not assigned",
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActionRandomnessDerivationInput {
    suite_identifier: Hash512,
    ceremony_context_hash: Hash512,
    action_context_hash: Hash512,
    participant_identity: ParticipantIdentity,
}

impl ActionRandomnessDerivationInput {
    pub const fn new(
        suite_identifier: Hash512,
        ceremony_context_hash: Hash512,
        action_context_hash: Hash512,
        participant_identity: ParticipantIdentity,
    ) -> Self {
        Self {
            suite_identifier,
            ceremony_context_hash,
            action_context_hash,
            participant_identity,
        }
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

    pub const fn participant_identity(self) -> ParticipantIdentity {
        self.participant_identity
    }

    fn canonical_tuple(self) -> CanonicalTuple {
        CanonicalTuple::new(
            ACTION_RANDOMNESS_DERIVATION_INPUT_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(FOUNDATION_PROFILE.protocol_version),
                CanonicalItem::hash512(self.suite_identifier.into_bytes()),
                CanonicalItem::hash512(self.ceremony_context_hash.into_bytes()),
                CanonicalItem::hash512(self.action_context_hash.into_bytes()),
                CanonicalItem::participant_identity(self.participant_identity.into_bytes()),
            ],
        )
    }

    pub fn encode(self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple().encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        require_header(
            &tuple,
            ACTION_RANDOMNESS_DERIVATION_INPUT_SCHEMA_IDENTIFIER,
            5,
        )?;
        require_protocol_version(read_u16(&tuple.items[0])?)?;
        Ok(Self::new(
            read_hash(&tuple.items[1])?,
            read_hash(&tuple.items[2])?,
            read_hash(&tuple.items[3])?,
            read_participant_identity(&tuple.items[4])?,
        ))
    }
}

pub struct ActionRandomnessRoot {
    root: Zeroizing<[u8; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH]>,
}

impl ActionRandomnessRoot {
    /// Takes ownership of a fresh action root supplied by the platform random generator.
    pub fn from_injected_bytes(root: Zeroizing<[u8; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH]>) -> Self {
        Self { root }
    }

    pub fn derive(
        self,
        derivation_input: ActionRandomnessDerivationInput,
    ) -> SchemaResult<ActionPrivateRandomness> {
        let canonical_derivation_input = derivation_input.encode()?;
        let key_material = kmac256_zeroizing::<ACTION_RANDOMNESS_KEY_MATERIAL_BYTE_LENGTH>(
            self.root.as_ref(),
            &canonical_derivation_input,
            ACTION_RANDOMNESS_KEY_HIERARCHY_CUSTOMIZATION,
        );

        let mut commitment_preimage =
            Zeroizing::new([0u8; ACTION_RANDOMNESS_COMMITMENT_PREIMAGE_BYTE_LENGTH]);
        commitment_preimage
            .copy_from_slice(&key_material[..ACTION_RANDOMNESS_COMMITMENT_PREIMAGE_BYTE_LENGTH]);
        let mut private_randomness_stream_key =
            Zeroizing::new([0u8; PRIVATE_RANDOMNESS_STREAM_KEY_BYTE_LENGTH]);
        private_randomness_stream_key.copy_from_slice(
            &key_material[ACTION_RANDOMNESS_COMMITMENT_PREIMAGE_BYTE_LENGTH
                ..ACTION_RANDOMNESS_COMMITMENT_PREIMAGE_BYTE_LENGTH
                    + PRIVATE_RANDOMNESS_STREAM_KEY_BYTE_LENGTH],
        );
        let mut proof_coin_key = Zeroizing::new([0u8; PROOF_COIN_KEY_BYTE_LENGTH]);
        proof_coin_key.copy_from_slice(
            &key_material[ACTION_RANDOMNESS_COMMITMENT_PREIMAGE_BYTE_LENGTH
                + PRIVATE_RANDOMNESS_STREAM_KEY_BYTE_LENGTH..],
        );

        let action_randomness_commitment = hash512(
            ACTION_RANDOMNESS_COMMITMENT_DOMAIN,
            &[
                CanonicalItem::variable_bytes(canonical_derivation_input)?,
                CanonicalItem::fixed_bytes(commitment_preimage.as_ref())?,
            ],
        )?;

        Ok(ActionPrivateRandomness {
            root: self.root,
            derivation_input,
            action_randomness_commitment,
            private_randomness_stream_key,
            proof_coin_key,
        })
    }
}

impl fmt::Debug for ActionRandomnessRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActionRandomnessRoot")
            .field("root", &"[REDACTED]")
            .finish()
    }
}

pub struct ActionPrivateRandomness {
    root: Zeroizing<[u8; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH]>,
    derivation_input: ActionRandomnessDerivationInput,
    action_randomness_commitment: Hash512,
    private_randomness_stream_key: Zeroizing<[u8; PRIVATE_RANDOMNESS_STREAM_KEY_BYTE_LENGTH]>,
    proof_coin_key: Zeroizing<[u8; PROOF_COIN_KEY_BYTE_LENGTH]>,
}

impl ActionPrivateRandomness {
    pub(crate) fn root(&self) -> &[u8; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH] {
        self.root.as_ref()
    }

    pub const fn derivation_input(&self) -> ActionRandomnessDerivationInput {
        self.derivation_input
    }

    pub const fn action_randomness_commitment(&self) -> Hash512 {
        self.action_randomness_commitment
    }

    pub(crate) fn setup_action_randomness_authorization(
        &self,
        roster_hash: Hash512,
    ) -> SchemaResult<Hash512> {
        Ok(hash512(
            SETUP_ACTION_RANDOMNESS_AUTHORIZATION_DOMAIN,
            &[
                CanonicalItem::hash512(self.derivation_input.suite_identifier.into_bytes()),
                CanonicalItem::hash512(
                    self.derivation_input.ceremony_context_hash.into_bytes(),
                ),
                CanonicalItem::hash512(self.derivation_input.action_context_hash.into_bytes()),
                CanonicalItem::hash512(roster_hash.into_bytes()),
                CanonicalItem::participant_identity(
                    self.derivation_input.participant_identity.into_bytes(),
                ),
                CanonicalItem::hash512(self.action_randomness_commitment.into_bytes()),
            ],
        )?)
    }

    pub fn setup_attempt_identifier(&self) -> PrivateRandomnessAttemptIdentifier {
        PrivateRandomnessAttemptIdentifier {
            bytes: kmac256::<PRIVATE_RANDOMNESS_ATTEMPT_IDENTIFIER_BYTE_LENGTH>(
                self.private_randomness_stream_key.as_ref(),
                self.action_randomness_commitment.as_bytes(),
                SETUP_ATTEMPT_CUSTOMIZATION,
            ),
            attempt_class: AttemptClass::ResetSafeSetup,
        }
    }

    /// Takes ownership of the one fresh identifier injected before ballot encryption starts.
    pub fn ballot_encryption_attempt_identifier(
        &self,
        injected_attempt_identifier: Zeroizing<
            [u8; PRIVATE_RANDOMNESS_ATTEMPT_IDENTIFIER_BYTE_LENGTH],
        >,
    ) -> PrivateRandomnessAttemptIdentifier {
        PrivateRandomnessAttemptIdentifier {
            bytes: *injected_attempt_identifier,
            attempt_class: AttemptClass::BallotEncryption,
        }
    }

    pub fn persistent_proof_attempt_identifier(
        &self,
        input: &PersistentProofCoinInput,
    ) -> SchemaResult<PrivateRandomnessAttemptIdentifier> {
        self.require_matching_slot(input.application_slot)?;
        if input.application_slot.attempt_class()? != AttemptClass::ResetSafeProof {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "persistent proof coins require a reset-safe private proof family",
            ));
        }
        Ok(PrivateRandomnessAttemptIdentifier {
            bytes: kmac256::<PRIVATE_RANDOMNESS_ATTEMPT_IDENTIFIER_BYTE_LENGTH>(
                self.proof_coin_key.as_ref(),
                &input.encode()?,
                PERSISTENT_PROOF_ATTEMPT_CUSTOMIZATION,
            ),
            attempt_class: AttemptClass::ResetSafeProof,
        })
    }

    pub fn ordinary_proof_attempt_identifier(
        &self,
        input: &OrdinaryProofCoinInput,
    ) -> SchemaResult<PrivateRandomnessAttemptIdentifier> {
        self.require_matching_slot(input.application_slot)?;
        if input.application_slot.attempt_class()? != AttemptClass::OrdinaryProof {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "ordinary proof coins require the ordinary ballot proof family",
            ));
        }
        Ok(PrivateRandomnessAttemptIdentifier {
            bytes: kmac256::<PRIVATE_RANDOMNESS_ATTEMPT_IDENTIFIER_BYTE_LENGTH>(
                self.proof_coin_key.as_ref(),
                &input.encode()?,
                ORDINARY_PROOF_ATTEMPT_CUSTOMIZATION,
            ),
            attempt_class: AttemptClass::OrdinaryProof,
        })
    }

    pub fn target_release_attempt_identifier(
        &self,
        application_slot: ProofApplicationSlot,
    ) -> SchemaResult<PrivateRandomnessAttemptIdentifier> {
        self.require_matching_slot(application_slot)?;
        if application_slot.application_statement_schema_identifier
            != TARGET_DECRYPTION_SHARE_PROOF_FAMILY
        {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "target release requires the target-decryption-share application slot",
            ));
        }
        Ok(PrivateRandomnessAttemptIdentifier {
            bytes: kmac256::<PRIVATE_RANDOMNESS_ATTEMPT_IDENTIFIER_BYTE_LENGTH>(
                self.private_randomness_stream_key.as_ref(),
                application_slot.hash()?.as_bytes(),
                TARGET_RELEASE_ATTEMPT_CUSTOMIZATION,
            ),
            attempt_class: AttemptClass::TargetRelease,
        })
    }

    pub fn begin_stream(
        &self,
        domain: PrivateRandomnessDomain,
        derivation_context_hash: Hash512,
        attempt_identifier: PrivateRandomnessAttemptIdentifier,
    ) -> SchemaResult<PrivateRandomnessStream<'_>> {
        require_attempt_class(domain, attempt_identifier)?;
        Ok(PrivateRandomnessStream {
            action_private_randomness: self,
            domain,
            derivation_context_hash,
            attempt_identifier,
            next_counter: 0,
            buffered_block: Zeroizing::new([0u8; PRIVATE_RANDOMNESS_BLOCK_BYTE_LENGTH]),
            next_unread_bit_offset_in_buffered_block: None,
        })
    }

    /// Restores an exact cursor after the containing private attempt record was authenticated.
    pub fn resume_stream(
        &self,
        domain: PrivateRandomnessDomain,
        derivation_context_hash: Hash512,
        attempt_identifier: PrivateRandomnessAttemptIdentifier,
        cursor: PrivateRandomCursor,
    ) -> SchemaResult<PrivateRandomnessStream<'_>> {
        require_attempt_class(domain, attempt_identifier)?;
        if cursor.domain != domain
            || cursor.derivation_context_hash != derivation_context_hash
            || cursor.stream_attempt_identifier != attempt_identifier.bytes
        {
            return Err(schema_error(
                RefusalReason::WrongContext,
                "private-randomness cursor does not match the requested stream",
            ));
        }

        let mut stream = PrivateRandomnessStream {
            action_private_randomness: self,
            domain,
            derivation_context_hash,
            attempt_identifier,
            next_counter: cursor.next_counter,
            buffered_block: Zeroizing::new([0u8; PRIVATE_RANDOMNESS_BLOCK_BYTE_LENGTH]),
            next_unread_bit_offset_in_buffered_block: cursor
                .next_unread_bit_offset_in_buffered_block,
        };
        if cursor.next_unread_bit_offset_in_buffered_block.is_some() {
            let buffered_counter = cursor.next_counter.checked_sub(1).ok_or_else(|| {
                schema_error(
                    RefusalReason::MalformedEncoding,
                    "private-randomness cursor cannot reference a block before counter zero",
                )
            })?;
            stream.buffered_block = stream.derive_block(buffered_counter)?;
        }
        Ok(stream)
    }

    fn require_matching_slot(&self, application_slot: ProofApplicationSlot) -> SchemaResult<()> {
        if application_slot.suite_identifier != self.derivation_input.suite_identifier
            || application_slot.ceremony_context_hash != self.derivation_input.ceremony_context_hash
            || application_slot.action_context_hash != self.derivation_input.action_context_hash
        {
            return Err(schema_error(
                RefusalReason::WrongContext,
                "proof application slot does not match the action randomness binding",
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for ActionPrivateRandomness {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActionPrivateRandomness")
            .field("root", &"[REDACTED]")
            .field("derivation_input", &self.derivation_input)
            .field(
                "action_randomness_commitment",
                &self.action_randomness_commitment,
            )
            .field("private_randomness_stream_key", &"[REDACTED]")
            .field("proof_coin_key", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateRandomnessAttemptIdentifier {
    bytes: [u8; PRIVATE_RANDOMNESS_ATTEMPT_IDENTIFIER_BYTE_LENGTH],
    attempt_class: AttemptClass,
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
    suite_identifier: Hash512,
    ceremony_context_hash: Hash512,
    action_context_hash: Hash512,
    application_statement_schema_identifier: u16,
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
            0x2110 | 0x2111 | 0x1211 | 0x1212 | TARGET_DECRYPTION_SHARE_PROOF_FAMILY => {
                (true, false, false)
            }
            0x1214 | 0x1216 | 0x1217 => (true, true, false),
            0x1213 | 0x1218 => (false, false, false),
            0x1215 => (false, true, false),
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

    fn attempt_class(self) -> SchemaResult<AttemptClass> {
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
    application_slot: ProofApplicationSlot,
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
    application_slot: ProofApplicationSlot,
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

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateRandomBlockInput {
    derivation_input: ActionRandomnessDerivationInput,
    domain: PrivateRandomnessDomain,
    derivation_context_hash: Hash512,
    attempt_identifier: [u8; PRIVATE_RANDOMNESS_ATTEMPT_IDENTIFIER_BYTE_LENGTH],
    counter: u64,
}

impl fmt::Debug for PrivateRandomBlockInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateRandomBlockInput")
            .field("derivation_input", &self.derivation_input)
            .field("domain", &self.domain)
            .field("derivation_context_hash", &self.derivation_context_hash)
            .field("attempt_identifier", &"[REDACTED]")
            .field("counter", &self.counter)
            .finish()
    }
}

impl PrivateRandomBlockInput {
    fn new(
        derivation_input: ActionRandomnessDerivationInput,
        domain: PrivateRandomnessDomain,
        derivation_context_hash: Hash512,
        attempt_identifier: PrivateRandomnessAttemptIdentifier,
        counter: u64,
    ) -> SchemaResult<Self> {
        require_attempt_class(domain, attempt_identifier)?;
        Ok(Self {
            derivation_input,
            domain,
            derivation_context_hash,
            attempt_identifier: attempt_identifier.bytes,
            counter,
        })
    }

    pub const fn derivation_input(self) -> ActionRandomnessDerivationInput {
        self.derivation_input
    }

    pub const fn domain(self) -> PrivateRandomnessDomain {
        self.domain
    }

    pub const fn derivation_context_hash(self) -> Hash512 {
        self.derivation_context_hash
    }

    pub const fn attempt_identifier(
        self,
    ) -> [u8; PRIVATE_RANDOMNESS_ATTEMPT_IDENTIFIER_BYTE_LENGTH] {
        self.attempt_identifier
    }

    pub const fn counter(self) -> u64 {
        self.counter
    }

    fn canonical_tuple(self) -> SchemaResult<CanonicalTuple> {
        Ok(CanonicalTuple::new(
            PRIVATE_RANDOM_BLOCK_INPUT_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(FOUNDATION_PROFILE.protocol_version),
                CanonicalItem::hash512(self.derivation_input.suite_identifier.into_bytes()),
                CanonicalItem::hash512(self.derivation_input.ceremony_context_hash.into_bytes()),
                CanonicalItem::hash512(self.derivation_input.action_context_hash.into_bytes()),
                CanonicalItem::participant_identity(
                    self.derivation_input.participant_identity.into_bytes(),
                ),
                CanonicalItem::unsigned16(self.domain.family),
                CanonicalItem::unsigned16(self.domain.purpose),
                CanonicalItem::hash512(self.derivation_context_hash.into_bytes()),
                CanonicalItem::fixed_bytes(self.attempt_identifier)?,
                CanonicalItem::unsigned64(self.counter),
            ],
        ))
    }

    pub fn encode(self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple()?.encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        require_header(&tuple, PRIVATE_RANDOM_BLOCK_INPUT_SCHEMA_IDENTIFIER, 10)?;
        require_protocol_version(read_u16(&tuple.items[0])?)?;
        let domain = PrivateRandomnessDomain::from_assigned_pair(
            read_u16(&tuple.items[5])?,
            read_u16(&tuple.items[6])?,
        )?;
        let derivation_input = ActionRandomnessDerivationInput::new(
            read_hash(&tuple.items[1])?,
            read_hash(&tuple.items[2])?,
            read_hash(&tuple.items[3])?,
            read_participant_identity(&tuple.items[4])?,
        );
        let attempt_identifier = PrivateRandomnessAttemptIdentifier {
            bytes: read_fixed_bytes(&tuple.items[8])?,
            attempt_class: domain.attempt_class(),
        };
        Self::new(
            derivation_input,
            domain,
            read_hash(&tuple.items[7])?,
            attempt_identifier,
            read_u64(&tuple.items[9])?,
        )
    }
}

pub struct PrivateRandomnessStream<'action> {
    action_private_randomness: &'action ActionPrivateRandomness,
    domain: PrivateRandomnessDomain,
    derivation_context_hash: Hash512,
    attempt_identifier: PrivateRandomnessAttemptIdentifier,
    next_counter: u64,
    buffered_block: Zeroizing<[u8; PRIVATE_RANDOMNESS_BLOCK_BYTE_LENGTH]>,
    next_unread_bit_offset_in_buffered_block: Option<u16>,
}

impl PrivateRandomnessStream<'_> {
    pub fn cursor(&self) -> PrivateRandomCursor {
        PrivateRandomCursor {
            domain: self.domain,
            derivation_context_hash: self.derivation_context_hash,
            stream_attempt_identifier: self.attempt_identifier.bytes,
            next_counter: self.next_counter,
            next_unread_bit_offset_in_buffered_block: self.next_unread_bit_offset_in_buffered_block,
        }
    }

    pub fn fill_bytes(&mut self, output: &mut [u8]) -> SchemaResult<()> {
        if self
            .next_unread_bit_offset_in_buffered_block
            .is_some_and(|offset| offset % 8 != 0)
        {
            return Err(schema_error(
                RefusalReason::ConsumedState,
                "byte-oriented private randomness cannot resume from a partial byte",
            ));
        }

        let mut output_offset = 0usize;
        while output_offset < output.len() {
            self.ensure_buffered_block()?;
            let bit_offset = usize::from(self.buffered_bit_offset()?);
            let block_byte_offset = bit_offset / 8;
            let copy_length = cmp::min(
                output.len() - output_offset,
                PRIVATE_RANDOMNESS_BLOCK_BYTE_LENGTH - block_byte_offset,
            );
            output[output_offset..output_offset + copy_length].copy_from_slice(
                &self.buffered_block[block_byte_offset..block_byte_offset + copy_length],
            );
            output_offset += copy_length;
            let consumed_bit_length = u16::try_from(copy_length * 8).map_err(|_| {
                schema_error(
                    RefusalReason::OutsideSupportedProfile,
                    "private-randomness byte consumption does not fit the cursor offset",
                )
            })?;
            self.advance_buffered_bit_offset(consumed_bit_length)?;
        }
        Ok(())
    }

    pub fn sample_modulo(
        &mut self,
        modulus: u64,
        maximum_candidate_draws_per_output: u32,
    ) -> SchemaResult<u64> {
        sample_modulo_from_byte_source(
            modulus,
            maximum_candidate_draws_per_output,
            |candidate_bytes| self.fill_bytes(candidate_bytes),
        )
    }

    pub fn sample_centered_ternary(
        &mut self,
        maximum_candidate_draws_per_output: u32,
    ) -> SchemaResult<i8> {
        match self.sample_modulo(3, maximum_candidate_draws_per_output)? {
            0 => Ok(-1),
            1 => Ok(0),
            2 => Ok(1),
            _ => Err(schema_error(
                RefusalReason::InvalidArithmeticRelation,
                "private ternary sampling produced a residue outside modulo three",
            )),
        }
    }

    pub fn sample_bit(&mut self) -> SchemaResult<bool> {
        self.ensure_buffered_block()?;
        let bit_offset = self.buffered_bit_offset()?;
        let byte = self.buffered_block[usize::from(bit_offset / 8)];
        let bit = ((byte >> (bit_offset % 8)) & 1) == 1;
        self.advance_buffered_bit_offset(1)?;
        Ok(bit)
    }

    pub fn sample_centered_binomial(&mut self, eta: u16) -> SchemaResult<i32> {
        if eta == 0 {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "centered-binomial sampling requires a positive eta",
            ));
        }
        let mut positive_sum = 0i32;
        for _ in 0..eta {
            positive_sum += i32::from(self.sample_bit()?);
        }
        let mut negative_sum = 0i32;
        for _ in 0..eta {
            negative_sum += i32::from(self.sample_bit()?);
        }
        Ok(positive_sum - negative_sum)
    }

    fn ensure_buffered_block(&mut self) -> SchemaResult<()> {
        if self.next_unread_bit_offset_in_buffered_block.is_some() {
            return Ok(());
        }
        let counter = self.next_counter;
        let next_counter = self.next_counter.checked_add(1).ok_or_else(|| {
            schema_error(
                RefusalReason::ConsumedState,
                "private-randomness block counter is exhausted",
            )
        })?;
        let block = self.derive_block(counter)?;
        self.next_counter = next_counter;
        self.buffered_block = block;
        self.next_unread_bit_offset_in_buffered_block = Some(0);
        Ok(())
    }

    fn derive_block(
        &self,
        counter: u64,
    ) -> SchemaResult<Zeroizing<[u8; PRIVATE_RANDOMNESS_BLOCK_BYTE_LENGTH]>> {
        let input = PrivateRandomBlockInput::new(
            self.action_private_randomness.derivation_input,
            self.domain,
            self.derivation_context_hash,
            self.attempt_identifier,
            counter,
        )?;
        Ok(kmac256_zeroizing::<PRIVATE_RANDOMNESS_BLOCK_BYTE_LENGTH>(
            self.action_private_randomness
                .private_randomness_stream_key
                .as_ref(),
            &input.encode()?,
            PRIVATE_RANDOMNESS_BLOCK_CUSTOMIZATION,
        ))
    }

    fn buffered_bit_offset(&self) -> SchemaResult<u16> {
        self.next_unread_bit_offset_in_buffered_block
            .ok_or_else(|| {
                schema_error(
                    RefusalReason::ConsumedState,
                    "private-randomness stream has no buffered block",
                )
            })
    }

    fn advance_buffered_bit_offset(&mut self, consumed_bit_length: u16) -> SchemaResult<()> {
        let next_offset = self
            .buffered_bit_offset()?
            .checked_add(consumed_bit_length)
            .ok_or_else(|| {
                schema_error(
                    RefusalReason::ConsumedState,
                    "private-randomness buffered bit offset overflows",
                )
            })?;
        if next_offset == PRIVATE_RANDOMNESS_BLOCK_BIT_LENGTH {
            self.buffered_block = Zeroizing::new([0u8; PRIVATE_RANDOMNESS_BLOCK_BYTE_LENGTH]);
            self.next_unread_bit_offset_in_buffered_block = None;
        } else if next_offset < PRIVATE_RANDOMNESS_BLOCK_BIT_LENGTH {
            self.next_unread_bit_offset_in_buffered_block = Some(next_offset);
        } else {
            return Err(schema_error(
                RefusalReason::ConsumedState,
                "private-randomness consumption exceeds the buffered block",
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for PrivateRandomnessStream<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateRandomnessStream")
            .field("domain", &self.domain)
            .field("derivation_context_hash", &self.derivation_context_hash)
            .field("attempt_identifier", &self.attempt_identifier)
            .field("next_counter", &self.next_counter)
            .field(
                "next_unread_bit_offset_in_buffered_block",
                &self.next_unread_bit_offset_in_buffered_block,
            )
            .field("buffered_block", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateRandomCursor {
    domain: PrivateRandomnessDomain,
    derivation_context_hash: Hash512,
    stream_attempt_identifier: [u8; PRIVATE_RANDOMNESS_ATTEMPT_IDENTIFIER_BYTE_LENGTH],
    next_counter: u64,
    next_unread_bit_offset_in_buffered_block: Option<u16>,
}

impl fmt::Debug for PrivateRandomCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateRandomCursor")
            .field("domain", &self.domain)
            .field("derivation_context_hash", &self.derivation_context_hash)
            .field("stream_attempt_identifier", &"[REDACTED]")
            .field("next_counter", &self.next_counter)
            .field(
                "next_unread_bit_offset_in_buffered_block",
                &self.next_unread_bit_offset_in_buffered_block,
            )
            .finish()
    }
}

impl PrivateRandomCursor {
    pub fn new(
        family: u16,
        purpose: u16,
        derivation_context_hash: Hash512,
        stream_attempt_identifier: [u8; PRIVATE_RANDOMNESS_ATTEMPT_IDENTIFIER_BYTE_LENGTH],
        next_counter: u64,
        next_unread_bit_offset_in_buffered_block: Option<u16>,
    ) -> SchemaResult<Self> {
        let cursor = Self {
            domain: PrivateRandomnessDomain::from_assigned_pair(family, purpose)?,
            derivation_context_hash,
            stream_attempt_identifier,
            next_counter,
            next_unread_bit_offset_in_buffered_block,
        };
        validate_cursor_offset(
            cursor.next_counter,
            cursor.next_unread_bit_offset_in_buffered_block,
        )?;
        Ok(cursor)
    }

    pub const fn family(self) -> u16 {
        self.domain.family
    }

    pub const fn purpose(self) -> u16 {
        self.domain.purpose
    }

    pub const fn derivation_context_hash(self) -> Hash512 {
        self.derivation_context_hash
    }

    pub const fn stream_attempt_identifier(
        self,
    ) -> [u8; PRIVATE_RANDOMNESS_ATTEMPT_IDENTIFIER_BYTE_LENGTH] {
        self.stream_attempt_identifier
    }

    pub const fn next_counter(self) -> u64 {
        self.next_counter
    }

    pub const fn next_unread_bit_offset_in_buffered_block(self) -> Option<u16> {
        self.next_unread_bit_offset_in_buffered_block
    }

    fn canonical_tuple(self) -> SchemaResult<CanonicalTuple> {
        validate_cursor_offset(
            self.next_counter,
            self.next_unread_bit_offset_in_buffered_block,
        )?;
        let offset_item = self
            .next_unread_bit_offset_in_buffered_block
            .map(CanonicalItem::unsigned16);
        Ok(CanonicalTuple::new(
            RANDOM_CURSOR_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.domain.family),
                CanonicalItem::unsigned16(self.domain.purpose),
                CanonicalItem::hash512(self.derivation_context_hash.into_bytes()),
                CanonicalItem::fixed_bytes(self.stream_attempt_identifier)?,
                CanonicalItem::unsigned64(self.next_counter),
                CanonicalItem::optional(CanonicalItemType::Unsigned16, offset_item.as_ref())?,
            ],
        ))
    }

    pub fn encode(self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple()?.encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        require_header(&tuple, RANDOM_CURSOR_SCHEMA_IDENTIFIER, 6)?;
        let family = read_u16(&tuple.items[0])?;
        let purpose = read_u16(&tuple.items[1])?;
        let next_counter = read_u64(&tuple.items[4])?;
        let next_unread_bit_offset_in_buffered_block = read_optional_u16(&tuple.items[5])?;
        validate_cursor_offset(next_counter, next_unread_bit_offset_in_buffered_block)?;
        Self::new(
            family,
            purpose,
            read_hash(&tuple.items[2])?,
            read_fixed_bytes(&tuple.items[3])?,
            next_counter,
            next_unread_bit_offset_in_buffered_block,
        )
    }
}

pub fn derive_application_statement_hash(
    canonical_application_statement_bytes: &[u8],
) -> SchemaResult<Hash512> {
    Ok(hash512(
        APPLICATION_STATEMENT_HASH_DOMAIN,
        &[CanonicalItem::variable_bytes(
            canonical_application_statement_bytes,
        )?],
    )?)
}

pub fn derive_relation_plan_variant_hash(
    canonical_relation_plan_variant_bytes: &[u8],
) -> SchemaResult<Hash512> {
    Ok(hash512(
        RELATION_PLAN_VARIANT_HASH_DOMAIN,
        &[CanonicalItem::variable_bytes(
            canonical_relation_plan_variant_bytes,
        )?],
    )?)
}

pub fn derive_proof_coin_context_hash(
    application_slot_hash: Hash512,
    application_statement_hash: Hash512,
    relation_plan_variant_hash: Hash512,
) -> SchemaResult<Hash512> {
    Ok(hash512(
        PRIVATE_PROOF_COIN_CONTEXT_HASH_DOMAIN,
        &[
            CanonicalItem::hash512(application_slot_hash.into_bytes()),
            CanonicalItem::hash512(application_statement_hash.into_bytes()),
            CanonicalItem::hash512(relation_plan_variant_hash.into_bytes()),
        ],
    )?)
}

fn require_attempt_class(
    domain: PrivateRandomnessDomain,
    attempt_identifier: PrivateRandomnessAttemptIdentifier,
) -> SchemaResult<()> {
    if domain.attempt_class() != attempt_identifier.attempt_class {
        return Err(schema_error(
            RefusalReason::WrongContext,
            "private-randomness attempt identifier is not valid for the requested domain",
        ));
    }
    Ok(())
}

fn require_protocol_version(protocol_version: u16) -> SchemaResult<()> {
    if protocol_version != FOUNDATION_PROFILE.protocol_version {
        return Err(schema_error(
            RefusalReason::UnsupportedVersionOrSuite,
            "private-randomness input uses an unsupported protocol version",
        ));
    }
    Ok(())
}

fn validate_cursor_offset(next_counter: u64, offset: Option<u16>) -> SchemaResult<()> {
    if let Some(offset) = offset
        && (next_counter == 0 || offset >= PRIVATE_RANDOMNESS_BLOCK_BIT_LENGTH)
    {
        return Err(schema_error(
            RefusalReason::MalformedEncoding,
            "private-randomness cursor buffered offset is inconsistent",
        ));
    }
    Ok(())
}

fn read_participant_identity(item: &CanonicalItem) -> SchemaResult<ParticipantIdentity> {
    let bytes: [u8; ParticipantIdentity::BYTE_LENGTH] =
        read_item(item, CanonicalItemType::ParticipantIdentity)?
            .try_into()
            .map_err(|_| {
                schema_error(
                    RefusalReason::WrongTypeOrLength,
                    "participant identity has the wrong length",
                )
            })?;
    Ok(ParticipantIdentity::from_bytes(bytes))
}

fn read_nested_tuple(
    item: &CanonicalItem,
    limits: &CanonicalDecodeLimits,
) -> SchemaResult<CanonicalTuple> {
    Ok(CanonicalTuple::decode(
        read_item(item, CanonicalItemType::NestedTuple)?,
        limits,
    )?)
}

fn read_optional_u16(item: &CanonicalItem) -> SchemaResult<Option<u16>> {
    Ok(
        read_optional_unsigned(item, CanonicalItemType::Unsigned16, 2)?
            .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]])),
    )
}

fn read_optional_u32(item: &CanonicalItem) -> SchemaResult<Option<u32>> {
    Ok(
        read_optional_unsigned(item, CanonicalItemType::Unsigned32, 4)?
            .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])),
    )
}

fn read_optional_u64(item: &CanonicalItem) -> SchemaResult<Option<u64>> {
    Ok(
        read_optional_unsigned(item, CanonicalItemType::Unsigned64, 8)?.map(|bytes| {
            u64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ])
        }),
    )
}

fn read_optional_unsigned<'item>(
    item: &'item CanonicalItem,
    expected_type: CanonicalItemType,
    expected_byte_length: usize,
) -> SchemaResult<Option<&'item [u8]>> {
    let bytes = read_item(item, CanonicalItemType::Optional)?;
    if bytes.len() < 3 || u16::from_le_bytes([bytes[0], bytes[1]]) != expected_type.canonical_code()
    {
        return Err(schema_error(
            RefusalReason::WrongTypeOrLength,
            "optional private-randomness coordinate has the wrong contained type",
        ));
    }
    match bytes[2] {
        0 if bytes.len() == 3 => Ok(None),
        1 if bytes.len() == 3 + expected_byte_length => Ok(Some(&bytes[3..])),
        _ => Err(schema_error(
            RefusalReason::MalformedEncoding,
            "optional private-randomness coordinate is malformed",
        )),
    }
}

fn candidate_draw_ceiling_exhausted() -> FoundationSchemaError {
    schema_error(
        RefusalReason::OutsideSupportedProfile,
        "private rejection sampler exhausted its per-output candidate-draw ceiling",
    )
}

fn sample_modulo_from_byte_source<FillBytes>(
    modulus: u64,
    maximum_candidate_draws_per_output: u32,
    mut fill_bytes: FillBytes,
) -> SchemaResult<u64>
where
    FillBytes: FnMut(&mut [u8]) -> SchemaResult<()>,
{
    if modulus <= 1 {
        return Err(schema_error(
            RefusalReason::WrongTypeOrLength,
            "private rejection sampling requires a modulus greater than one",
        ));
    }
    if maximum_candidate_draws_per_output == 0 {
        return Err(candidate_draw_ceiling_exhausted());
    }

    let significant_bit_length = u64::BITS - modulus.leading_zeros();
    let sample_byte_length =
        usize::try_from(significant_bit_length.div_ceil(8)).expect("a u64 sample width fits usize");
    let sample_space = 1u128 << (sample_byte_length * 8);
    let modulus_u128 = u128::from(modulus);
    let acceptance_limit = sample_space - (sample_space % modulus_u128);

    for _ in 0..maximum_candidate_draws_per_output {
        let mut candidate_bytes = [0u8; size_of::<u64>()];
        fill_bytes(&mut candidate_bytes[..sample_byte_length])?;
        let candidate = u64::from_le_bytes(candidate_bytes);
        if u128::from(candidate) < acceptance_limit {
            return Ok(candidate % modulus);
        }
    }
    Err(candidate_draw_ceiling_exhausted())
}

fn schema_error(refusal_reason: RefusalReason, message: &'static str) -> FoundationSchemaError {
    FoundationSchemaError::new(refusal_reason, message)
}

fn kmac256<const OUTPUT_BYTE_LENGTH: usize>(
    key: &[u8],
    message: &[u8],
    customization: &[u8],
) -> [u8; OUTPUT_BYTE_LENGTH] {
    *kmac256_zeroizing(key, message, customization)
}

fn kmac256_zeroizing<const OUTPUT_BYTE_LENGTH: usize>(
    key: &[u8],
    message: &[u8],
    customization: &[u8],
) -> Zeroizing<[u8; OUTPUT_BYTE_LENGTH]> {
    let mut output = Zeroizing::new([0u8; OUTPUT_BYTE_LENGTH]);
    let mut kmac = Kmac::v256(key, customization);
    kmac.update(message);
    kmac.finalize(output.as_mut());
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(fill: u8) -> Hash512 {
        Hash512::from_bytes([fill; Hash512::BYTE_LENGTH])
    }

    fn fixed_lowercase_hex<const BYTE_LENGTH: usize>(value: &str) -> [u8; BYTE_LENGTH] {
        assert_eq!(value.len(), BYTE_LENGTH * 2);
        let mut output = [0u8; BYTE_LENGTH];
        for (byte_index, hexadecimal_pair) in value.as_bytes().chunks_exact(2).enumerate() {
            let decode_digit = |digit: u8| match digit {
                b'0'..=b'9' => digit - b'0',
                b'a'..=b'f' => digit - b'a' + 10,
                _ => panic!("test vector must use lowercase hexadecimal"),
            };
            output[byte_index] =
                (decode_digit(hexadecimal_pair[0]) << 4) | decode_digit(hexadecimal_pair[1]);
        }
        output
    }

    fn participant_identity() -> ParticipantIdentity {
        ParticipantIdentity::from_bytes([0x44; ParticipantIdentity::BYTE_LENGTH])
    }

    fn derivation_input() -> ActionRandomnessDerivationInput {
        ActionRandomnessDerivationInput::new(
            hash(0x11),
            hash(0x22),
            hash(0x33),
            participant_identity(),
        )
    }

    fn action_randomness() -> ActionPrivateRandomness {
        ActionRandomnessRoot::from_injected_bytes(Zeroizing::new(
            [0x5a; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH],
        ))
        .derive(derivation_input())
        .expect("fixed action randomness derives")
    }

    fn persistent_slot() -> ProofApplicationSlot {
        ProofApplicationSlot::new(
            hash(0x11),
            hash(0x22),
            hash(0x33),
            0x1211,
            Some(2),
            None,
            None,
        )
        .expect("persistent application slot")
    }

    fn ordinary_slot() -> ProofApplicationSlot {
        ProofApplicationSlot::new(
            hash(0x11),
            hash(0x22),
            hash(0x33),
            ORDINARY_BALLOT_PROOF_FAMILY,
            Some(2),
            None,
            Some(19),
        )
        .expect("ordinary application slot")
    }

    #[test]
    fn canonical_private_randomness_inputs_round_trip() {
        let limits = CanonicalDecodeLimits::default();
        let derivation = derivation_input();
        assert_eq!(
            ActionRandomnessDerivationInput::decode(
                &derivation.encode().expect("derivation input encodes"),
                &limits,
            )
            .expect("derivation input decodes"),
            derivation,
        );

        let persistent = PersistentProofCoinInput::new(persistent_slot(), hash(0x66))
            .expect("persistent proof coin input");
        assert_eq!(
            PersistentProofCoinInput::decode(
                &persistent.encode().expect("persistent input encodes"),
                &limits,
            )
            .expect("persistent input decodes"),
            persistent,
        );

        let ordinary = OrdinaryProofCoinInput::new(ordinary_slot(), hash(0x77), [0x88; 32])
            .expect("ordinary proof coin input");
        assert_eq!(
            OrdinaryProofCoinInput::decode(
                &ordinary.encode().expect("ordinary input encodes"),
                &limits,
            )
            .expect("ordinary input decodes"),
            ordinary,
        );

        let action_randomness = action_randomness();
        let domain = PrivateRandomnessDomain::setup_source(4).expect("block domain");
        let block_input = PrivateRandomBlockInput::new(
            derivation,
            domain,
            hash(0x99),
            action_randomness.setup_attempt_identifier(),
            u64::MAX,
        )
        .expect("block input");
        assert_eq!(
            PrivateRandomBlockInput::decode(
                &block_input.encode().expect("block input encodes"),
                &limits,
            )
            .expect("block input decodes"),
            block_input,
        );

        let mut unsupported_version_tuple = CanonicalTuple::decode(
            &derivation.encode().expect("derivation input encodes"),
            &limits,
        )
        .expect("derivation tuple decodes");
        unsupported_version_tuple.items[0] = CanonicalItem::unsigned16(2);
        let error = ActionRandomnessDerivationInput::decode(
            &unsupported_version_tuple
                .encode()
                .expect("mutated tuple encodes"),
            &limits,
        )
        .expect_err("unsupported protocol version refuses");
        assert_eq!(
            error.refusal_reason,
            RefusalReason::UnsupportedVersionOrSuite
        );
    }

    #[test]
    fn key_hierarchy_is_deterministic_and_bound_to_every_action_input() {
        let first = action_randomness();
        let second = action_randomness();
        assert_eq!(
            first.action_randomness_commitment(),
            second.action_randomness_commitment()
        );
        assert_eq!(
            first.setup_attempt_identifier(),
            second.setup_attempt_identifier()
        );

        for changed_input in [
            ActionRandomnessDerivationInput::new(
                hash(0x10),
                hash(0x22),
                hash(0x33),
                participant_identity(),
            ),
            ActionRandomnessDerivationInput::new(
                hash(0x11),
                hash(0x20),
                hash(0x33),
                participant_identity(),
            ),
            ActionRandomnessDerivationInput::new(
                hash(0x11),
                hash(0x22),
                hash(0x30),
                participant_identity(),
            ),
            ActionRandomnessDerivationInput::new(
                hash(0x11),
                hash(0x22),
                hash(0x33),
                ParticipantIdentity::from_bytes([0x45; ParticipantIdentity::BYTE_LENGTH]),
            ),
        ] {
            let changed = ActionRandomnessRoot::from_injected_bytes(Zeroizing::new(
                [0x5a; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH],
            ))
            .derive(changed_input)
            .expect("changed input derives");
            assert_ne!(
                first.action_randomness_commitment(),
                changed.action_randomness_commitment()
            );
            assert_ne!(
                first.setup_attempt_identifier(),
                changed.setup_attempt_identifier()
            );
        }

        let changed_root = ActionRandomnessRoot::from_injected_bytes(Zeroizing::new(
            [0x5b; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH],
        ))
        .derive(derivation_input())
        .expect("changed root derives");
        assert_ne!(
            first.action_randomness_commitment(),
            changed_root.action_randomness_commitment()
        );
    }

    #[test]
    fn setup_action_randomness_authorization_binds_commitment_roster_and_action_scope() {
        let randomness = action_randomness();
        let roster_hash = hash(0x55);
        let expected = hash512(
            SETUP_ACTION_RANDOMNESS_AUTHORIZATION_DOMAIN,
            &[
                CanonicalItem::hash512(hash(0x11).into_bytes()),
                CanonicalItem::hash512(hash(0x22).into_bytes()),
                CanonicalItem::hash512(hash(0x33).into_bytes()),
                CanonicalItem::hash512(roster_hash.into_bytes()),
                CanonicalItem::participant_identity(participant_identity().into_bytes()),
                CanonicalItem::hash512(
                    randomness.action_randomness_commitment().into_bytes(),
                ),
            ],
        )
        .expect("authorization tuple hashes");
        assert_eq!(
            randomness
                .setup_action_randomness_authorization(roster_hash)
                .expect("authorization derives"),
            expected,
        );
        assert_ne!(
            randomness
                .setup_action_randomness_authorization(hash(0x56))
                .expect("changed roster authorization derives"),
            expected,
        );

        let changed_root = ActionRandomnessRoot::from_injected_bytes(Zeroizing::new(
            [0x5b; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH],
        ))
        .derive(derivation_input())
        .expect("changed root derives");
        assert_ne!(
            changed_root
                .setup_action_randomness_authorization(roster_hash)
                .expect("changed commitment authorization derives"),
            expected,
        );
    }

    #[test]
    fn key_hierarchy_and_first_stream_block_match_independent_kmac_vector() {
        let action_randomness = action_randomness();
        assert_eq!(
            action_randomness
                .action_randomness_commitment()
                .into_bytes(),
            fixed_lowercase_hex(concat!(
                "358a1f0d923ca0ee03d6a5ddd4dd1bcd49c1c0d71e66e3e82e575097aba76d5f",
                "ce106820325f0459528e341511ebacfb872a42d6ae7e2e1ed5ab12b3b079d12e",
            ))
        );
        let setup_attempt = action_randomness.setup_attempt_identifier();
        assert_eq!(
            *setup_attempt.as_bytes(),
            fixed_lowercase_hex("d04f89c8ec54e88bd6d9dddfe1cff886dc8f51bc6d486f719915c2f0e686d85f")
        );

        let mut stream = action_randomness
            .begin_stream(
                PrivateRandomnessDomain::setup_source(3).expect("assigned setup-source domain"),
                hash(0xa1),
                setup_attempt,
            )
            .expect("stream starts");
        let mut first_block = [0u8; PRIVATE_RANDOMNESS_BLOCK_BYTE_LENGTH];
        stream
            .fill_bytes(&mut first_block)
            .expect("first block derives");
        assert_eq!(
            first_block,
            fixed_lowercase_hex(concat!(
                "7ac7eae0a4b6fd1aacc599e5bd68c04c178e374809afb4d072c0e61f6a130b59",
                "1b010e50d8ba98fb973c159511b6daf5e36683bdd23307d7f7ce6a355124cab5",
            ))
        );
        assert_eq!(stream.cursor().next_counter(), 1);
        assert_eq!(
            stream.cursor().next_unread_bit_offset_in_buffered_block(),
            None
        );
    }

    #[test]
    fn attempt_identifiers_bind_attempt_kind_statement_and_nonce() {
        let action_randomness = action_randomness();
        let persistent =
            PersistentProofCoinInput::new(persistent_slot(), hash(0x66)).expect("persistent input");
        let changed_statement = PersistentProofCoinInput::new(persistent_slot(), hash(0x67))
            .expect("changed persistent input");
        assert_ne!(
            action_randomness
                .persistent_proof_attempt_identifier(&persistent)
                .expect("persistent attempt"),
            action_randomness
                .persistent_proof_attempt_identifier(&changed_statement)
                .expect("changed persistent attempt"),
        );

        let ordinary = OrdinaryProofCoinInput::new(ordinary_slot(), hash(0x66), [0x70; 32])
            .expect("ordinary input");
        let retried = OrdinaryProofCoinInput::new(ordinary_slot(), hash(0x66), [0x71; 32])
            .expect("ordinary retry input");
        assert_ne!(
            action_randomness
                .ordinary_proof_attempt_identifier(&ordinary)
                .expect("ordinary attempt"),
            action_randomness
                .ordinary_proof_attempt_identifier(&retried)
                .expect("ordinary retry attempt"),
        );

        let target_slot = ProofApplicationSlot::new(
            hash(0x11),
            hash(0x22),
            hash(0x33),
            TARGET_DECRYPTION_SHARE_PROOF_FAMILY,
            Some(2),
            None,
            None,
        )
        .expect("target application slot");
        let target_attempt = action_randomness
            .target_release_attempt_identifier(target_slot)
            .expect("target attempt");
        let changed_target_slot = ProofApplicationSlot::new(
            hash(0x11),
            hash(0x22),
            hash(0x33),
            TARGET_DECRYPTION_SHARE_PROOF_FAMILY,
            Some(3),
            None,
            None,
        )
        .expect("changed target application slot");
        assert_ne!(
            target_attempt,
            action_randomness
                .target_release_attempt_identifier(changed_target_slot)
                .expect("changed target attempt")
        );
        assert!(
            action_randomness
                .begin_stream(
                    PrivateRandomnessDomain::target_flooding(1).expect("target domain"),
                    hash(0x81),
                    target_attempt,
                )
                .is_ok()
        );

        let persistent_attempt = action_randomness
            .persistent_proof_attempt_identifier(&persistent)
            .expect("persistent attempt");
        let mismatch = action_randomness
            .begin_stream(
                PrivateRandomnessDomain::setup_source(1).expect("setup domain"),
                hash(0x82),
                persistent_attempt,
            )
            .expect_err("proof attempt cannot select a setup stream");
        assert_eq!(mismatch.refusal_reason, RefusalReason::WrongContext);

        let ballot_attempt = action_randomness.ballot_encryption_attempt_identifier(
            Zeroizing::new([0x91; PRIVATE_RANDOMNESS_ATTEMPT_IDENTIFIER_BYTE_LENGTH]),
        );
        assert!(
            action_randomness
                .begin_stream(
                    PrivateRandomnessDomain::ballot_encryption_distribution(8)
                        .expect("ballot domain"),
                    hash(0x83),
                    ballot_attempt,
                )
                .is_ok()
        );
        assert_eq!(
            action_randomness
                .begin_stream(
                    PrivateRandomnessDomain::setup_suite_distribution(1)
                        .expect("setup distribution domain"),
                    hash(0x83),
                    ballot_attempt,
                )
                .expect_err("ballot attempt cannot select a setup distribution stream")
                .refusal_reason,
            RefusalReason::WrongContext,
        );
    }

    #[test]
    fn stream_resume_preserves_exact_byte_and_bit_suffixes() {
        let action_randomness = action_randomness();
        let domain = PrivateRandomnessDomain::setup_source(3).expect("assigned domain");
        let context = hash(0xa1);
        let attempt = action_randomness.setup_attempt_identifier();

        let mut uninterrupted = action_randomness
            .begin_stream(domain, context, attempt)
            .expect("stream starts");
        let mut prefix = [0u8; 61];
        uninterrupted
            .fill_bytes(&mut prefix)
            .expect("prefix samples");
        let byte_cursor = uninterrupted.cursor();
        let mut expected_suffix = [0u8; 79];
        uninterrupted
            .fill_bytes(&mut expected_suffix)
            .expect("suffix samples");

        let mut resumed = action_randomness
            .resume_stream(domain, context, attempt, byte_cursor)
            .expect("byte cursor resumes");
        let mut resumed_suffix = [0u8; 79];
        resumed
            .fill_bytes(&mut resumed_suffix)
            .expect("resumed suffix samples");
        assert_eq!(resumed_suffix, expected_suffix);
        assert_eq!(resumed.cursor(), uninterrupted.cursor());

        let mut bit_stream = action_randomness
            .begin_stream(domain, context, attempt)
            .expect("bit stream starts");
        for _ in 0..509 {
            bit_stream.sample_bit().expect("prefix bit samples");
        }
        let bit_cursor = bit_stream.cursor();
        let expected_bits = (0..70)
            .map(|_| bit_stream.sample_bit().expect("suffix bit samples"))
            .collect::<Vec<_>>();
        let mut resumed_bits = action_randomness
            .resume_stream(domain, context, attempt, bit_cursor)
            .expect("bit cursor resumes");
        let actual_bits = (0..70)
            .map(|_| resumed_bits.sample_bit().expect("resumed bit samples"))
            .collect::<Vec<_>>();
        assert_eq!(actual_bits, expected_bits);
        assert_eq!(resumed_bits.cursor(), bit_stream.cursor());
    }

    #[test]
    fn cursor_binding_misalignment_and_counter_exhaustion_refuse_without_consuming() {
        let action_randomness = action_randomness();
        let domain = PrivateRandomnessDomain::setup_source(1).expect("assigned domain");
        let context = hash(0xa2);
        let attempt = action_randomness.setup_attempt_identifier();
        let mut stream = action_randomness
            .begin_stream(domain, context, attempt)
            .expect("stream starts");
        stream.sample_bit().expect("one bit samples");
        let misaligned_cursor = stream.cursor();
        let mut output = [0u8; 1];
        let error = stream
            .fill_bytes(&mut output)
            .expect_err("byte sampling from a partial byte refuses");
        assert_eq!(error.refusal_reason, RefusalReason::ConsumedState);
        assert_eq!(stream.cursor(), misaligned_cursor);

        let wrong_context_error = action_randomness
            .resume_stream(domain, hash(0xa3), attempt, misaligned_cursor)
            .expect_err("wrong context refuses");
        assert_eq!(
            wrong_context_error.refusal_reason,
            RefusalReason::WrongContext
        );

        let exhausted_cursor = PrivateRandomCursor::new(
            domain.family(),
            domain.purpose(),
            context,
            *attempt.as_bytes(),
            u64::MAX,
            None,
        )
        .expect("boundary cursor is structurally valid");
        let mut exhausted_stream = action_randomness
            .resume_stream(domain, context, attempt, exhausted_cursor)
            .expect("boundary cursor resumes before another block is requested");
        let error = exhausted_stream
            .sample_bit()
            .expect_err("counter overflow refuses");
        assert_eq!(error.refusal_reason, RefusalReason::ConsumedState);
        assert_eq!(exhausted_stream.cursor(), exhausted_cursor);
    }

    #[test]
    fn sampling_is_bounded_and_stays_in_exact_output_domains() {
        let action_randomness = action_randomness();
        let domain = PrivateRandomnessDomain::setup_source(3).expect("assigned domain");
        let attempt = action_randomness.setup_attempt_identifier();
        let mut stream = action_randomness
            .begin_stream(domain, hash(0xb1), attempt)
            .expect("stream starts");

        for modulus in [2, 3, 5, 251, 256, 257, 65_537, u32::MAX as u64, u64::MAX] {
            for _ in 0..257 {
                let sample = stream
                    .sample_modulo(modulus, 64)
                    .expect("fixed ceiling is ample for deterministic test stream");
                assert!(sample < modulus);
            }
        }
        for _ in 0..257 {
            assert!(matches!(
                stream
                    .sample_centered_ternary(64)
                    .expect("ternary sample succeeds"),
                -1..=1
            ));
            let centered_binomial = stream
                .sample_centered_binomial(7)
                .expect("centered-binomial sample succeeds");
            assert!((-7..=7).contains(&centered_binomial));
        }
        assert_eq!(
            stream
                .sample_modulo(1, 64)
                .expect_err("unit modulus refuses")
                .refusal_reason,
            RefusalReason::WrongTypeOrLength,
        );
        assert_eq!(
            stream
                .sample_modulo(3, 0)
                .expect_err("zero draw ceiling refuses")
                .refusal_reason,
            RefusalReason::OutsideSupportedProfile,
        );
    }

    #[test]
    fn rejection_sampling_uses_exact_little_endian_candidates_and_hard_ceiling() {
        fn sample_from_bytes(
            source: &[u8],
            modulus: u64,
            maximum_draws: u32,
        ) -> (SchemaResult<u64>, usize) {
            let mut source_offset = 0usize;
            let result =
                sample_modulo_from_byte_source(modulus, maximum_draws, |candidate_bytes| {
                    let source_end = source_offset + candidate_bytes.len();
                    if source_end > source.len() {
                        return Err(schema_error(
                            RefusalReason::MissingPrerequisite,
                            "test byte source is exhausted",
                        ));
                    }
                    candidate_bytes.copy_from_slice(&source[source_offset..source_end]);
                    source_offset = source_end;
                    Ok(())
                });
            (result, source_offset)
        }

        let (sample, consumed) = sample_from_bytes(&[255, 254], 5, 2);
        assert_eq!(sample.expect("second one-byte candidate is accepted"), 4);
        assert_eq!(consumed, 2);

        let (exhausted, consumed) = sample_from_bytes(&[255, 0], 5, 1);
        assert_eq!(
            exhausted
                .expect_err("one rejected candidate exhausts a one-draw ceiling")
                .refusal_reason,
            RefusalReason::OutsideSupportedProfile,
        );
        assert_eq!(consumed, 1);

        let (sample, consumed) = sample_from_bytes(&[0xff, 0xff, 0x02, 0x01], 257, 2);
        assert_eq!(
            sample.expect("little-endian 65535 rejects and 258 accepts"),
            1
        );
        assert_eq!(consumed, 4);

        let mut maximum_width_candidates = [0xff; 16];
        maximum_width_candidates[8] = 0xfe;
        let (sample, consumed) = sample_from_bytes(&maximum_width_candidates, u64::MAX, 2);
        assert_eq!(
            sample.expect("maximum-width second candidate accepts"),
            u64::MAX - 1
        );
        assert_eq!(consumed, 16);
    }

    #[test]
    fn proof_application_slots_enforce_closed_coordinate_shapes() {
        for (family, roster, schedule, producer) in [
            (0x1211, Some(0), None, None),
            (0x1214, Some(9), Some(0), None),
            (0x1213, None, None, None),
            (0x1215, None, Some(u32::MAX), None),
            (ORDINARY_BALLOT_PROOF_FAMILY, Some(1), None, Some(0)),
        ] {
            assert!(
                ProofApplicationSlot::new(
                    hash(1),
                    hash(2),
                    hash(3),
                    family,
                    roster,
                    schedule,
                    producer,
                )
                .is_ok()
            );
        }

        for (family, roster, schedule, producer) in [
            (0x1211, None, None, None),
            (0x1214, Some(0), None, None),
            (0x1213, Some(0), None, None),
            (0x1215, None, None, None),
            (ORDINARY_BALLOT_PROOF_FAMILY, Some(0), None, None),
            (0xffff, None, None, None),
        ] {
            assert!(
                ProofApplicationSlot::new(
                    hash(1),
                    hash(2),
                    hash(3),
                    family,
                    roster,
                    schedule,
                    producer,
                )
                .is_err()
            );
        }
        assert!(
            ProofApplicationSlot::new(
                hash(1),
                hash(2),
                hash(3),
                0x1211,
                Some(FOUNDATION_PROFILE.participant_count),
                None,
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn proof_hashes_bind_each_canonical_layer_and_keep_domains_separate() {
        let slot_hash = persistent_slot().hash().expect("slot hash");
        let same_canonical_bytes = b"same canonical bytes";
        let application_statement_hash =
            derive_application_statement_hash(same_canonical_bytes).expect("statement hash");
        let relation_plan_variant_hash =
            derive_relation_plan_variant_hash(same_canonical_bytes).expect("plan hash");
        assert_ne!(application_statement_hash, relation_plan_variant_hash);

        let context_hash = derive_proof_coin_context_hash(
            slot_hash,
            application_statement_hash,
            relation_plan_variant_hash,
        )
        .expect("proof coin context hash");
        for changed_context_hash in [
            derive_proof_coin_context_hash(
                hash(0x90),
                application_statement_hash,
                relation_plan_variant_hash,
            )
            .expect("changed slot context"),
            derive_proof_coin_context_hash(slot_hash, hash(0x91), relation_plan_variant_hash)
                .expect("changed statement context"),
            derive_proof_coin_context_hash(slot_hash, application_statement_hash, hash(0x92))
                .expect("changed plan context"),
        ] {
            assert_ne!(context_hash, changed_context_hash);
        }
    }

    #[test]
    fn public_only_and_unassigned_randomness_domains_refuse() {
        for public_family in PUBLIC_ONLY_PROOF_FAMILIES {
            assert!(PrivateRandomnessDomain::reset_safe_proof(public_family, 1).is_err());
        }
        for invalid_purpose in [0, 8, 9, 10, 13, u16::MAX] {
            assert!(PrivateRandomnessDomain::setup_suite_distribution(invalid_purpose).is_err());
        }
        for invalid_purpose in [0, 1, 7, 11, u16::MAX] {
            assert!(
                PrivateRandomnessDomain::ballot_encryption_distribution(invalid_purpose).is_err()
            );
        }
        assert!(PrivateRandomnessDomain::setup_mailbox(4).is_err());
        assert!(PrivateRandomnessDomain::target_flooding(0).is_err());
        assert!(PrivateRandomnessDomain::target_flooding(3).is_err());
        assert!(PrivateRandomnessDomain::reset_safe_proof(0x1211, 0x4000).is_err());
        assert!(PrivateRandomnessDomain::ordinary_proof(0x4000).is_err());
    }
}
