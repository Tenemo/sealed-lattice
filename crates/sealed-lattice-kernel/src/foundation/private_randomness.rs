use crate::bgv::proof_suite::common_proof_randomness_purpose_is_assigned;

use super::schemas::{
    SchemaResult, read_fixed_bytes, read_hash, read_item, read_u16, read_u64, require_header,
};
use super::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple, FoundationSchemaError,
    Hash512, RefusalReason,
};

pub const RANDOM_CURSOR_SCHEMA_IDENTIFIER: u16 = 0x1804;

pub const PRIVATE_RANDOMNESS_ATTEMPT_IDENTIFIER_BYTE_LENGTH: usize = 32;

const FOUNDATION_SCHEMA_VERSION: u16 = 1;

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
