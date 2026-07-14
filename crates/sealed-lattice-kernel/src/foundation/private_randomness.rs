use tiny_keccak::{Hasher, Kmac};
use zeroize::Zeroizing;

use crate::bgv::proof_suite::common_proof_randomness_purpose_is_assigned;

use super::proof_application::ProofApplicationSlot;
use super::schemas::{
    SchemaResult, read_fixed_bytes, read_hash, read_item, read_u16, read_u64, require_header,
};
use super::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple, FoundationSchemaError,
    Hash512, ParticipantIdentity, RefusalReason, hash_foundation_tuple_512 as hash512,
};

pub const PRIVATE_RANDOM_BLOCK_INPUT_SCHEMA_IDENTIFIER: u16 = 0x0400;
pub const PERSISTENT_PROOF_COIN_INPUT_SCHEMA_IDENTIFIER: u16 = 0x0401;
pub const ACTION_RANDOMNESS_DERIVATION_INPUT_SCHEMA_IDENTIFIER: u16 = 0x0402;
pub const ORDINARY_PROOF_COIN_INPUT_SCHEMA_IDENTIFIER: u16 = 0x0403;
pub const RANDOM_CURSOR_SCHEMA_IDENTIFIER: u16 = 0x1804;

pub const ACTION_RANDOMNESS_ROOT_BYTE_LENGTH: usize = 64;
pub const PRIVATE_RANDOM_BLOCK_BYTE_LENGTH: usize = 64;
pub const PRIVATE_RANDOMNESS_ATTEMPT_IDENTIFIER_BYTE_LENGTH: usize = 32;
pub const MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT: usize = 64;

const FOUNDATION_SCHEMA_VERSION: u16 = 1;
const ACTION_KEY_MATERIAL_BYTE_LENGTH: usize = 192;
const ACTION_RANDOMNESS_COMMITMENT_PREIMAGE_BYTE_LENGTH: usize = 64;

const ACTION_KEY_HIERARCHY_CUSTOMIZATION: &[u8] =
    b"sealed-lattice/private-randomness/action-key-hierarchy/v1";

const SUITE_DISTRIBUTION_FAMILY: u16 = 0x0116;
const SETUP_SOURCE_FAMILY: u16 = 0x1201;
const SETUP_MAILBOX_FAMILY: u16 = 0x0200;
const VSS_EXPANSION_FAMILY: u16 = 0x2120;
const TARGET_FLOODING_FAMILY: u16 = 0x1630;
const ORDINARY_BALLOT_PROOF_FAMILY: u16 = 0x1302;
const TARGET_DECRYPTION_SHARE_PROOF_FAMILY: u16 = 0x1621;
pub const PRIVATE_PROOF_SALT_PURPOSE: u16 = 0xfffe;

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
pub struct ActionRandomnessDerivationInput {
    suite_id: Hash512,
    ceremony_context_hash: Hash512,
    action_context_hash: Hash512,
    participant_id: ParticipantIdentity,
}

impl ActionRandomnessDerivationInput {
    pub const fn new(
        suite_id: Hash512,
        ceremony_context_hash: Hash512,
        action_context_hash: Hash512,
        participant_id: ParticipantIdentity,
    ) -> Self {
        Self {
            suite_id,
            ceremony_context_hash,
            action_context_hash,
            participant_id,
        }
    }

    pub const fn suite_id(self) -> Hash512 {
        self.suite_id
    }

    pub const fn ceremony_context_hash(self) -> Hash512 {
        self.ceremony_context_hash
    }

    pub const fn action_context_hash(self) -> Hash512 {
        self.action_context_hash
    }

    pub const fn participant_id(self) -> ParticipantIdentity {
        self.participant_id
    }

    fn canonical_tuple(self) -> CanonicalTuple {
        CanonicalTuple::new(
            ACTION_RANDOMNESS_DERIVATION_INPUT_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::hash512(self.suite_id.into_bytes()),
                CanonicalItem::hash512(self.ceremony_context_hash.into_bytes()),
                CanonicalItem::hash512(self.action_context_hash.into_bytes()),
                CanonicalItem::participant_identity(self.participant_id.into_bytes()),
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
            4,
        )?;
        Ok(Self::new(
            read_hash(&tuple.items[0])?,
            read_hash(&tuple.items[1])?,
            read_hash(&tuple.items[2])?,
            ParticipantIdentity::from_bytes(read_fixed_participant_identity(&tuple.items[3])?),
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttemptClass {
    ResetSafeProof,
    OrdinaryProof,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PrivateRandomnessDomain {
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

    fn reset_safe_proof(statement_schema_identifier: u16, purpose: u16) -> SchemaResult<Self> {
        proof_domain(
            statement_schema_identifier,
            purpose,
            AttemptClass::ResetSafeProof,
        )
    }

    fn ordinary_proof(purpose: u16) -> SchemaResult<Self> {
        proof_domain(
            ORDINARY_BALLOT_PROOF_FAMILY,
            purpose,
            AttemptClass::OrdinaryProof,
        )
    }

    pub fn from_assigned_pair(family: u16, purpose: u16) -> SchemaResult<Self> {
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
        return Err(FoundationSchemaError::new(
            RefusalReason::WrongTypeOrLength,
            "public-only proof families cannot allocate private randomness",
        ));
    }
    let family_matches_attempt = match attempt_class {
        AttemptClass::ResetSafeProof => {
            RESET_SAFE_PROOF_FAMILIES.contains(&statement_schema_identifier)
        }
        AttemptClass::OrdinaryProof => statement_schema_identifier == ORDINARY_BALLOT_PROOF_FAMILY,
    };
    if !family_matches_attempt {
        return Err(unassigned_randomness_domain());
    }
    if !common_proof_randomness_purpose_is_assigned(statement_schema_identifier, purpose) {
        return Err(unassigned_randomness_domain());
    }
    Ok(PrivateRandomnessDomain {
        family: statement_schema_identifier,
        purpose,
    })
}

fn unassigned_randomness_domain() -> FoundationSchemaError {
    FoundationSchemaError::new(
        RefusalReason::WrongTypeOrLength,
        "private-randomness family and purpose pair is not assigned",
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivateRandomBlockInput {
    derivation_input: ActionRandomnessDerivationInput,
    domain: PrivateRandomnessDomain,
    derivation_context_hash: Hash512,
    attempt_identifier: [u8; PRIVATE_RANDOMNESS_ATTEMPT_IDENTIFIER_BYTE_LENGTH],
    counter: u64,
}

impl PrivateRandomBlockInput {
    pub(crate) const fn new(
        derivation_input: ActionRandomnessDerivationInput,
        domain: PrivateRandomnessDomain,
        derivation_context_hash: Hash512,
        attempt_identifier: [u8; PRIVATE_RANDOMNESS_ATTEMPT_IDENTIFIER_BYTE_LENGTH],
        counter: u64,
    ) -> Self {
        Self {
            derivation_input,
            domain,
            derivation_context_hash,
            attempt_identifier,
            counter,
        }
    }

    pub fn from_assigned_pair(
        derivation_input: ActionRandomnessDerivationInput,
        family: u16,
        purpose: u16,
        derivation_context_hash: Hash512,
        attempt_identifier: [u8; PRIVATE_RANDOMNESS_ATTEMPT_IDENTIFIER_BYTE_LENGTH],
        counter: u64,
    ) -> SchemaResult<Self> {
        Ok(Self::new(
            derivation_input,
            PrivateRandomnessDomain::from_assigned_pair(family, purpose)?,
            derivation_context_hash,
            attempt_identifier,
            counter,
        ))
    }

    pub const fn derivation_input(self) -> ActionRandomnessDerivationInput {
        self.derivation_input
    }

    pub const fn family(self) -> u16 {
        self.domain.family()
    }

    pub const fn purpose(self) -> u16 {
        self.domain.purpose()
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
                CanonicalItem::hash512(self.derivation_input.suite_id.into_bytes()),
                CanonicalItem::hash512(self.derivation_input.ceremony_context_hash.into_bytes()),
                CanonicalItem::hash512(self.derivation_input.action_context_hash.into_bytes()),
                CanonicalItem::participant_identity(
                    self.derivation_input.participant_id.into_bytes(),
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
        require_header(&tuple, PRIVATE_RANDOM_BLOCK_INPUT_SCHEMA_IDENTIFIER, 9)?;
        let domain = PrivateRandomnessDomain::from_assigned_pair(
            read_u16(&tuple.items[4])?,
            read_u16(&tuple.items[5])?,
        )?;
        Ok(Self::new(
            ActionRandomnessDerivationInput::new(
                read_hash(&tuple.items[0])?,
                read_hash(&tuple.items[1])?,
                read_hash(&tuple.items[2])?,
                ParticipantIdentity::from_bytes(read_fixed_participant_identity(&tuple.items[3])?),
            ),
            domain,
            read_hash(&tuple.items[6])?,
            read_fixed_bytes(&tuple.items[7])?,
            read_u64(&tuple.items[8])?,
        ))
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
        if !RESET_SAFE_PROOF_FAMILIES
            .contains(&application_slot.application_statement_schema_identifier())
        {
            return Err(FoundationSchemaError::new(
                RefusalReason::WrongTypeOrLength,
                "persistent proof coins require a reset-safe secret-bearing family",
            ));
        }
        Ok(Self {
            application_slot,
            application_statement_hash,
        })
    }

    fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
        Ok(CanonicalTuple::new(
            PERSISTENT_PROOF_COIN_INPUT_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::nested_tuple(&self.application_slot.canonical_tuple()?)?,
                CanonicalItem::hash512(self.application_statement_hash.into_bytes()),
            ],
        ))
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple()?.encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        require_header(&tuple, PERSISTENT_PROOF_COIN_INPUT_SCHEMA_IDENTIFIER, 2)?;
        Self::new(
            read_nested_proof_application_slot(&tuple.items[0], limits)?,
            read_hash(&tuple.items[1])?,
        )
    }

    pub const fn application_slot(&self) -> ProofApplicationSlot {
        self.application_slot
    }

    pub const fn application_statement_hash(&self) -> Hash512 {
        self.application_statement_hash
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrdinaryProofCoinInput {
    application_slot: ProofApplicationSlot,
    application_statement_hash: Hash512,
    ordinary_proof_attempt_nonce: [u8; PRIVATE_RANDOMNESS_ATTEMPT_IDENTIFIER_BYTE_LENGTH],
}

impl OrdinaryProofCoinInput {
    pub fn new(
        application_slot: ProofApplicationSlot,
        application_statement_hash: Hash512,
        ordinary_proof_attempt_nonce: [u8; PRIVATE_RANDOMNESS_ATTEMPT_IDENTIFIER_BYTE_LENGTH],
    ) -> SchemaResult<Self> {
        if application_slot.application_statement_schema_identifier()
            != ORDINARY_BALLOT_PROOF_FAMILY
        {
            return Err(FoundationSchemaError::new(
                RefusalReason::WrongTypeOrLength,
                "ordinary proof coins require the ballot-validity family",
            ));
        }
        Ok(Self {
            application_slot,
            application_statement_hash,
            ordinary_proof_attempt_nonce,
        })
    }

    fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
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

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple()?.encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        require_header(&tuple, ORDINARY_PROOF_COIN_INPUT_SCHEMA_IDENTIFIER, 3)?;
        Self::new(
            read_nested_proof_application_slot(&tuple.items[0], limits)?,
            read_hash(&tuple.items[1])?,
            read_fixed_bytes(&tuple.items[2])?,
        )
    }

    pub const fn application_slot(&self) -> ProofApplicationSlot {
        self.application_slot
    }

    pub const fn application_statement_hash(&self) -> Hash512 {
        self.application_statement_hash
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivateRandomCursor {
    domain: PrivateRandomnessDomain,
    derivation_context_hash: Hash512,
    stream_attempt_identifier: [u8; PRIVATE_RANDOMNESS_ATTEMPT_IDENTIFIER_BYTE_LENGTH],
    next_counter: u64,
    next_unread_bit_offset_in_buffered_block: Option<u16>,
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

fn validate_cursor_offset(next_counter: u64, offset: Option<u16>) -> SchemaResult<()> {
    if let Some(offset) = offset
        && (next_counter == 0 || offset >= 512)
    {
        return Err(FoundationSchemaError::new(
            RefusalReason::MalformedEncoding,
            "private-randomness cursor buffered offset is inconsistent",
        ));
    }
    Ok(())
}

pub(crate) struct ActionRandomness {
    action_randomness_commitment: Hash512,
}

impl ActionRandomness {
    pub fn derive(
        action_randomness_root: [u8; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH],
        derivation_input: ActionRandomnessDerivationInput,
    ) -> SchemaResult<Self> {
        let action_randomness_root = Zeroizing::new(action_randomness_root);
        let canonical_derivation_input_bytes = derivation_input.encode()?;
        let action_key_material = Zeroizing::new(kmac256::<ACTION_KEY_MATERIAL_BYTE_LENGTH>(
            &action_randomness_root[..],
            &canonical_derivation_input_bytes,
            ACTION_KEY_HIERARCHY_CUSTOMIZATION,
        ));
        let mut action_randomness_commitment_preimage =
            Zeroizing::new([0u8; ACTION_RANDOMNESS_COMMITMENT_PREIMAGE_BYTE_LENGTH]);
        action_randomness_commitment_preimage.copy_from_slice(
            &action_key_material[..ACTION_RANDOMNESS_COMMITMENT_PREIMAGE_BYTE_LENGTH],
        );
        let action_randomness_commitment = hash512(
            "sealed-lattice/private-randomness/action-root-commitment/v1",
            &[
                CanonicalItem::variable_bytes(canonical_derivation_input_bytes)?,
                CanonicalItem::fixed_bytes(&action_randomness_commitment_preimage[..])?,
            ],
        )?;
        Ok(Self {
            action_randomness_commitment,
        })
    }

    pub const fn action_randomness_commitment(&self) -> Hash512 {
        self.action_randomness_commitment
    }
}

pub fn derive_application_statement_hash(
    canonical_application_statement_bytes: &[u8],
) -> SchemaResult<Hash512> {
    Ok(hash512(
        "sealed-lattice/proof/application-statement/v1",
        &[CanonicalItem::variable_bytes(
            canonical_application_statement_bytes,
        )?],
    )?)
}

pub fn derive_relation_plan_variant_hash(
    canonical_relation_plan_variant_bytes: &[u8],
) -> SchemaResult<Hash512> {
    Ok(hash512(
        "sealed-lattice/proof/relation-plan-variant/v1",
        &[CanonicalItem::variable_bytes(
            canonical_relation_plan_variant_bytes,
        )?],
    )?)
}

fn kmac256<const OUTPUT_BYTE_LENGTH: usize>(
    key: &[u8],
    message: &[u8],
    customization: &[u8],
) -> [u8; OUTPUT_BYTE_LENGTH] {
    let mut output = [0u8; OUTPUT_BYTE_LENGTH];
    let mut kmac = Kmac::v256(key, customization);
    kmac.update(message);
    kmac.finalize(&mut output);
    output
}

fn read_fixed_participant_identity(item: &CanonicalItem) -> SchemaResult<[u8; 64]> {
    let bytes = read_item(item, CanonicalItemType::ParticipantIdentity)?;
    bytes.try_into().map_err(|_| {
        FoundationSchemaError::new(
            RefusalReason::WrongTypeOrLength,
            "participant identity has the wrong byte length",
        )
    })
}

fn read_nested_proof_application_slot(
    item: &CanonicalItem,
    limits: &CanonicalDecodeLimits,
) -> SchemaResult<ProofApplicationSlot> {
    ProofApplicationSlot::decode(read_item(item, CanonicalItemType::NestedTuple)?, limits)
}

fn read_optional_u16(item: &CanonicalItem) -> SchemaResult<Option<u16>> {
    let bytes = read_item(item, CanonicalItemType::Optional)?;
    if bytes.len() < 3
        || u16::from_le_bytes([bytes[0], bytes[1]])
            != CanonicalItemType::Unsigned16.canonical_code()
    {
        return Err(FoundationSchemaError::new(
            RefusalReason::WrongTypeOrLength,
            "optional cursor offset has the wrong contained type",
        ));
    }
    match bytes {
        [_, _, 0] => Ok(None),
        [_, _, 1, low, high] => Ok(Some(u16::from_le_bytes([*low, *high]))),
        _ => Err(FoundationSchemaError::new(
            RefusalReason::MalformedEncoding,
            "optional cursor offset is malformed",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(fill: u8) -> Hash512 {
        Hash512::from_bytes([fill; Hash512::BYTE_LENGTH])
    }

    fn participant(fill: u8) -> ParticipantIdentity {
        ParticipantIdentity::from_bytes([fill; ParticipantIdentity::BYTE_LENGTH])
    }

    fn derivation_input() -> ActionRandomnessDerivationInput {
        ActionRandomnessDerivationInput::new(hash(0x11), hash(0x22), hash(0x33), participant(0x44))
    }

    fn action_randomness() -> ActionRandomness {
        ActionRandomness::derive(
            [0x5a; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH],
            derivation_input(),
        )
        .expect("test action randomness derives")
    }

    #[test]
    fn kmac256_matches_the_nist_sp_800_185_sample() {
        let key: Vec<u8> = (0x40..=0x5f).collect();
        let expected = [
            0x20, 0xc5, 0x70, 0xc3, 0x13, 0x46, 0xf7, 0x03, 0xc9, 0xac, 0x36, 0xc6, 0x1c, 0x03,
            0xcb, 0x64, 0xc3, 0x97, 0x0d, 0x0c, 0xfc, 0x78, 0x7e, 0x9b, 0x79, 0x59, 0x9d, 0x27,
            0x3a, 0x68, 0xd2, 0xf7, 0xf6, 0x9d, 0x4c, 0xc3, 0xde, 0x9d, 0x10, 0x4a, 0x35, 0x16,
            0x89, 0xf2, 0x7c, 0xf6, 0xf5, 0x95, 0x1f, 0x01, 0x03, 0xf3, 0x3f, 0x4f, 0x24, 0x87,
            0x10, 0x24, 0xd9, 0xc2, 0x77, 0x73, 0xa8, 0xdd,
        ];
        assert_eq!(
            kmac256::<64>(&key, &[0, 1, 2, 3], b"My Tagged Application"),
            expected
        );
    }

    #[test]
    fn canonical_randomness_inputs_round_trip_and_reject_trailing_bytes() {
        let action_input = derivation_input();
        let action_bytes = action_input.encode().expect("action input encodes");
        assert_eq!(
            ActionRandomnessDerivationInput::decode(
                &action_bytes,
                &CanonicalDecodeLimits::default()
            )
            .expect("action input decodes"),
            action_input
        );

        let block_input = PrivateRandomBlockInput::new(
            action_input,
            PrivateRandomnessDomain::setup_mailbox(2).expect("assigned domain"),
            hash(0x55),
            [0x66; 32],
            u64::MAX,
        );
        let block_bytes = block_input.encode().expect("block input encodes");
        assert_eq!(
            PrivateRandomBlockInput::decode(&block_bytes, &CanonicalDecodeLimits::default())
                .expect("block input decodes"),
            block_input
        );
        let mut trailing = block_bytes;
        trailing.push(0);
        assert!(
            PrivateRandomBlockInput::decode(&trailing, &CanonicalDecodeLimits::default()).is_err()
        );
    }

    #[test]
    fn action_commitment_is_stable_and_context_separated() {
        let baseline = action_randomness();
        let repeated = action_randomness();
        let changed_context = ActionRandomness::derive(
            [0x5a; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH],
            ActionRandomnessDerivationInput::new(
                hash(0x11),
                hash(0x22),
                hash(0x34),
                participant(0x44),
            ),
        )
        .expect("changed context derives");
        assert_eq!(
            baseline.action_randomness_commitment(),
            repeated.action_randomness_commitment()
        );
        assert_ne!(
            baseline.action_randomness_commitment(),
            changed_context.action_randomness_commitment()
        );
        assert_ne!(
            baseline.action_randomness_commitment().into_bytes(),
            [0x5a; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH]
        );
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
