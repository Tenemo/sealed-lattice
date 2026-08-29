use core::{fmt, str};
use std::collections::BTreeSet;

use fips203::{ml_kem_768, traits::SerDes as KemSerDes};

use super::canonical_tuple::CanonicalDecodeBudget;
use super::{
    CanonicalCodecError, CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple,
    Hash512, ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH, ParticipantIdentity, RefusalReason,
    derive_participant_identity, hash_foundation_tuple_512,
};

pub const ROSTER_ENTRY_SCHEMA_IDENTIFIER: u16 = 0x0114;
pub const ROSTER_SCHEMA_IDENTIFIER: u16 = 0x0115;
pub const ML_KEM_768_ENCAPSULATION_KEY_BYTE_LENGTH: usize = ml_kem_768::EK_LEN;

const FOUNDATION_SCHEMA_VERSION: u16 = 1;

pub const MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT: u16 = 3;
pub const MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT: u16 = 20;
pub(crate) const PROTOTYPE_PARTICIPANT_COUNT: u16 = 10;
pub const MINIMUM_CONFIGURABLE_OPTION_COUNT: u16 = 2;
pub const MAXIMUM_CONFIGURABLE_OPTION_COUNT: u16 = 20;
pub(crate) const PROTOTYPE_OPTION_COUNT: u16 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FoundationRosterParameters {
    pub participant_count: u16,
    pub active_fault_bound: u16,
    pub reconstruction_threshold: u16,
    pub selected_set_quorum: u16,
    pub finality_quorum: u16,
    pub state_witness_quorum: u16,
}

/// Derives structural roster parameters without selecting or qualifying the
/// resulting profile. The reconstruction threshold is independent of the
/// strict asynchronous active-fault bound when the roster size is divisible
/// by three.
pub const fn derive_foundation_roster_parameters(
    participant_count: u16,
) -> Option<FoundationRosterParameters> {
    if participant_count < MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT
        || participant_count > MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT
    {
        return None;
    }

    let active_fault_bound = (participant_count - 1) / 3;
    let reconstruction_threshold = participant_count / 3 + 1;
    let quorum = (participant_count + active_fault_bound) / 2 + 1;

    Some(FoundationRosterParameters {
        participant_count,
        active_fault_bound,
        reconstruction_threshold,
        selected_set_quorum: quorum,
        finality_quorum: quorum,
        state_witness_quorum: quorum,
    })
}

const PROTOTYPE_ROSTER_PARAMETERS: FoundationRosterParameters =
    match derive_foundation_roster_parameters(PROTOTYPE_PARTICIPANT_COUNT) {
        Some(parameters) => parameters,
        None => panic!("the prototype participant count must be configurable"),
    };

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FoundationProfile {
    pub protocol_name: &'static str,
    pub protocol_version: u16,
    pub participant_count: u16,
    pub active_fault_bound: u16,
    pub reconstruction_threshold: u16,
    pub selected_set_quorum: u16,
    pub finality_quorum: u16,
    pub state_witness_quorum: u16,
    pub option_count: u16,
    pub minimum_score: u16,
    pub maximum_score: u16,
    pub maximum_identifier_byte_length: usize,
    pub maximum_copied_buffer_byte_length: usize,
}

pub const FOUNDATION_PROFILE: FoundationProfile = FoundationProfile {
    protocol_name: "sealed-lattice",
    protocol_version: 1,
    participant_count: PROTOTYPE_ROSTER_PARAMETERS.participant_count,
    active_fault_bound: PROTOTYPE_ROSTER_PARAMETERS.active_fault_bound,
    reconstruction_threshold: PROTOTYPE_ROSTER_PARAMETERS.reconstruction_threshold,
    selected_set_quorum: PROTOTYPE_ROSTER_PARAMETERS.selected_set_quorum,
    finality_quorum: PROTOTYPE_ROSTER_PARAMETERS.finality_quorum,
    state_witness_quorum: PROTOTYPE_ROSTER_PARAMETERS.state_witness_quorum,
    option_count: PROTOTYPE_OPTION_COUNT,
    minimum_score: 1,
    maximum_score: 10,
    maximum_identifier_byte_length: 128,
    maximum_copied_buffer_byte_length: 8_388_608,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundationSchemaError {
    pub refusal_reason: RefusalReason,
    pub message: &'static str,
}

impl FoundationSchemaError {
    pub(super) const fn new(refusal_reason: RefusalReason, message: &'static str) -> Self {
        Self {
            refusal_reason,
            message,
        }
    }
}

impl fmt::Display for FoundationSchemaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for FoundationSchemaError {}

impl From<CanonicalCodecError> for FoundationSchemaError {
    fn from(error: CanonicalCodecError) -> Self {
        let refusal_reason = if error.kind == super::CanonicalCodecErrorKind::LimitExceeded {
            RefusalReason::OutsideSupportedProfile
        } else {
            RefusalReason::MalformedEncoding
        };
        Self::new(refusal_reason, "foundation value is not canonical")
    }
}

pub(super) type SchemaResult<Value> = Result<Value, FoundationSchemaError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterEntry {
    pub roster_position: u16,
    pub signing_verification_key: [u8; ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH],
    pub mailbox_encapsulation_key: [u8; ML_KEM_768_ENCAPSULATION_KEY_BYTE_LENGTH],
}

impl RosterEntry {
    pub fn new(
        roster_position: u16,
        signing_verification_key: [u8; ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH],
        mailbox_encapsulation_key: [u8; ML_KEM_768_ENCAPSULATION_KEY_BYTE_LENGTH],
    ) -> SchemaResult<Self> {
        let entry = Self {
            roster_position,
            signing_verification_key,
            mailbox_encapsulation_key,
        };
        entry.validate()?;
        Ok(entry)
    }

    fn validate(&self) -> SchemaResult<()> {
        if self.roster_position >= MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT {
            return Err(FoundationSchemaError::new(
                RefusalReason::OutsideSupportedProfile,
                "roster position is outside the configurable range",
            ));
        }
        validate_ml_kem_768_encapsulation_key(&self.mailbox_encapsulation_key)
    }

    pub fn participant_identity(&self) -> SchemaResult<ParticipantIdentity> {
        Ok(derive_participant_identity(&self.signing_verification_key)?)
    }

    fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
        self.validate()?;
        Ok(CanonicalTuple::new(
            ROSTER_ENTRY_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.roster_position),
                CanonicalItem::fixed_bytes(self.signing_verification_key)?,
                CanonicalItem::fixed_bytes(self.mailbox_encapsulation_key)?,
            ],
        ))
    }

    fn from_tuple(tuple: &CanonicalTuple) -> SchemaResult<Self> {
        require_header(tuple, ROSTER_ENTRY_SCHEMA_IDENTIFIER, 3)?;
        Self::new(
            read_u16(&tuple.items[0])?,
            read_fixed_bytes(&tuple.items[1])?,
            read_fixed_bytes(&tuple.items[2])?,
        )
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple()?.encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        Self::from_tuple(&CanonicalTuple::decode(bytes, limits)?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Roster {
    pub entries: Vec<RosterEntry>,
}

impl Roster {
    pub fn new(entries: Vec<RosterEntry>) -> SchemaResult<Self> {
        validate_roster_entries(&entries)?;
        Ok(Self { entries })
    }

    pub(crate) fn validate(&self) -> SchemaResult<()> {
        validate_roster_entries(&self.entries)
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        self.validate()?;
        let entries = self
            .entries
            .iter()
            .map(|entry| {
                entry
                    .canonical_tuple()
                    .and_then(|tuple| CanonicalItem::nested_tuple(&tuple).map_err(Into::into))
            })
            .collect::<SchemaResult<Vec<_>>>()?;
        Ok(CanonicalTuple::new(
            ROSTER_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![CanonicalItem::homogeneous_list(
                CanonicalItemType::NestedTuple,
                &entries,
            )?],
        )
        .encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let mut budget = CanonicalDecodeBudget::new(limits);
        Self::decode_with_budget(bytes, limits, &mut budget)
    }

    fn decode_with_budget(
        bytes: &[u8],
        limits: &CanonicalDecodeLimits,
        budget: &mut CanonicalDecodeBudget,
    ) -> SchemaResult<Self> {
        preflight_roster_entry_count(bytes, limits)?;
        let tuple = CanonicalTuple::decode_with_budget(bytes, limits, budget)?;
        require_header(&tuple, ROSTER_SCHEMA_IDENTIFIER, 1)?;
        let entries = read_nested_tuple_list_with_budget(&tuple.items[0], limits, budget)?
            .iter()
            .map(RosterEntry::from_tuple)
            .collect::<SchemaResult<Vec<_>>>()?;
        Self::new(entries)
    }

    pub fn roster_hash(&self) -> SchemaResult<Hash512> {
        Ok(hash_foundation_tuple_512(
            "sealed-lattice/foundation/roster/v1",
            &[CanonicalItem::variable_bytes(self.encode()?)?],
        )?)
    }
}

fn validate_roster_entries(entries: &[RosterEntry]) -> SchemaResult<()> {
    let participant_count = u16::try_from(entries.len()).ok();
    if participant_count
        .and_then(derive_foundation_roster_parameters)
        .is_none()
    {
        return Err(FoundationSchemaError::new(
            RefusalReason::OutsideSupportedProfile,
            "roster size is outside the configurable range",
        ));
    }

    let mut signing_keys = BTreeSet::new();
    let mut mailbox_keys = BTreeSet::new();
    let mut participant_identities = BTreeSet::new();
    for (entry_index, entry) in entries.iter().enumerate() {
        entry.validate()?;
        if usize::from(entry.roster_position) != entry_index {
            return Err(FoundationSchemaError::new(
                RefusalReason::WrongTypeOrLength,
                "roster positions must be consecutive and canonically ordered",
            ));
        }
        let participant_identity = derive_participant_identity(&entry.signing_verification_key)?;
        if !signing_keys.insert(entry.signing_verification_key.as_slice())
            || !mailbox_keys.insert(entry.mailbox_encapsulation_key.as_slice())
            || !participant_identities.insert(participant_identity)
        {
            return Err(FoundationSchemaError::new(
                RefusalReason::DuplicateIdentity,
                "roster contains a duplicate identity, signing key, or mailbox key",
            ));
        }
    }
    Ok(())
}

fn validate_ml_kem_768_encapsulation_key(
    key: &[u8; ML_KEM_768_ENCAPSULATION_KEY_BYTE_LENGTH],
) -> SchemaResult<()> {
    let encapsulation_key = ml_kem_768::EncapsKey::try_from_bytes(*key).map_err(|_| {
        FoundationSchemaError::new(
            RefusalReason::MalformedEncoding,
            "mailbox encapsulation key is not a canonical ML-KEM-768 public key",
        )
    })?;
    if encapsulation_key.into_bytes() != *key {
        return Err(FoundationSchemaError::new(
            RefusalReason::MalformedEncoding,
            "mailbox encapsulation key is not a canonical ML-KEM-768 public key",
        ));
    }
    Ok(())
}

pub(super) fn require_header(
    tuple: &CanonicalTuple,
    schema_identifier: u16,
    item_count: usize,
) -> SchemaResult<()> {
    if tuple.schema_identifier != schema_identifier {
        return Err(FoundationSchemaError::new(
            RefusalReason::WrongTypeOrLength,
            "foundation tuple has the wrong schema",
        ));
    }
    if tuple.schema_version != FOUNDATION_SCHEMA_VERSION {
        return Err(FoundationSchemaError::new(
            RefusalReason::UnsupportedVersionOrSuite,
            "foundation tuple schema version is unsupported",
        ));
    }
    if tuple.items.len() != item_count {
        return Err(FoundationSchemaError::new(
            RefusalReason::WrongTypeOrLength,
            "foundation tuple has the wrong item count",
        ));
    }
    Ok(())
}

fn preflight_roster_entry_count(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<()> {
    const ITEM_TYPES: [CanonicalItemType; 1] = [CanonicalItemType::HomogeneousList];
    let Some(entry_list_bytes) =
        raw_schema_item(bytes, limits, ROSTER_SCHEMA_IDENTIFIER, &ITEM_TYPES, 0)
    else {
        return Ok(());
    };
    let Some(declared_entry_count) =
        raw_homogeneous_list_count(entry_list_bytes, CanonicalItemType::NestedTuple, limits)
    else {
        return Ok(());
    };
    if u16::try_from(declared_entry_count)
        .ok()
        .and_then(derive_foundation_roster_parameters)
        .is_none()
    {
        return Err(FoundationSchemaError::new(
            RefusalReason::OutsideSupportedProfile,
            "roster size is outside the configurable range",
        ));
    }
    Ok(())
}

fn raw_schema_item<'a>(
    bytes: &'a [u8],
    limits: &CanonicalDecodeLimits,
    expected_schema_identifier: u16,
    expected_item_types: &[CanonicalItemType],
    requested_item_index: usize,
) -> Option<&'a [u8]> {
    const TUPLE_HEADER_BYTE_LENGTH: usize = 8;
    const ITEM_HEADER_BYTE_LENGTH: usize = 6;

    if requested_item_index >= expected_item_types.len()
        || expected_item_types.len() > limits.maximum_item_count
        || bytes.len() > limits.maximum_tuple_byte_length
        || bytes.len() > limits.maximum_cumulative_work_byte_length
    {
        return None;
    }
    let tuple_header = bytes.get(..TUPLE_HEADER_BYTE_LENGTH)?;
    if read_raw_u16(tuple_header, 0)? != expected_schema_identifier
        || read_raw_u16(tuple_header, 2)? != FOUNDATION_SCHEMA_VERSION
        || usize::try_from(read_raw_u32(tuple_header, 4)?).ok()? != expected_item_types.len()
    {
        return None;
    }

    let mut requested_item = None;
    let mut total_item_byte_length = 0usize;
    let mut item_offset = TUPLE_HEADER_BYTE_LENGTH;
    for (item_index, expected_item_type) in expected_item_types.iter().enumerate() {
        let item_header_end = item_offset.checked_add(ITEM_HEADER_BYTE_LENGTH)?;
        let item_header = bytes.get(item_offset..item_header_end)?;
        if read_raw_u16(item_header, 0)? != expected_item_type.canonical_code() {
            return None;
        }
        let item_byte_length = usize::try_from(read_raw_u32(item_header, 2)?).ok()?;
        if item_byte_length > limits.maximum_item_byte_length {
            return None;
        }
        total_item_byte_length = total_item_byte_length.checked_add(item_byte_length)?;
        let item_end = item_header_end.checked_add(item_byte_length)?;
        let item_bytes = bytes.get(item_header_end..item_end)?;
        if item_index == requested_item_index {
            requested_item = Some(item_bytes);
        }
        item_offset = item_end;
    }
    if item_offset != bytes.len()
        || total_item_byte_length > limits.maximum_cumulative_allocation_byte_length
    {
        return None;
    }
    requested_item
}

fn raw_homogeneous_list_count(
    bytes: &[u8],
    expected_element_type: CanonicalItemType,
    limits: &CanonicalDecodeLimits,
) -> Option<u32> {
    if read_raw_u16(bytes, 0)? != expected_element_type.canonical_code() {
        return None;
    }
    let declared_count = read_raw_u32(bytes, 2)?;
    if usize::try_from(declared_count).ok()? > limits.maximum_item_count {
        return None;
    }
    Some(declared_count)
}

fn read_raw_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let value_end = offset.checked_add(2)?;
    Some(u16::from_le_bytes(
        bytes.get(offset..value_end)?.try_into().ok()?,
    ))
}

fn read_raw_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let value_end = offset.checked_add(4)?;
    Some(u32::from_le_bytes(
        bytes.get(offset..value_end)?.try_into().ok()?,
    ))
}

pub(super) fn read_item(
    item: &CanonicalItem,
    expected_type: CanonicalItemType,
) -> SchemaResult<&[u8]> {
    if item.item_type() != expected_type {
        return Err(FoundationSchemaError::new(
            RefusalReason::WrongTypeOrLength,
            "foundation tuple item has the wrong semantic type",
        ));
    }
    Ok(item.canonical_bytes())
}

pub(super) fn read_variable_item(
    item: &CanonicalItem,
    expected_type: CanonicalItemType,
) -> SchemaResult<&[u8]> {
    if item.item_type() != expected_type {
        return Err(FoundationSchemaError::new(
            RefusalReason::WrongTypeOrLength,
            "foundation tuple item has the wrong semantic type",
        ));
    }
    item.variable_value_bytes().map_err(Into::into)
}

pub(super) fn read_u16(item: &CanonicalItem) -> SchemaResult<u16> {
    let bytes: [u8; 2] = read_item(item, CanonicalItemType::Unsigned16)?
        .try_into()
        .map_err(|_| FoundationSchemaError::new(RefusalReason::MalformedEncoding, "u16 length"))?;
    Ok(u16::from_le_bytes(bytes))
}

pub(super) fn read_u64(item: &CanonicalItem) -> SchemaResult<u64> {
    let bytes: [u8; 8] = read_item(item, CanonicalItemType::Unsigned64)?
        .try_into()
        .map_err(|_| FoundationSchemaError::new(RefusalReason::MalformedEncoding, "u64 length"))?;
    Ok(u64::from_le_bytes(bytes))
}

pub(super) fn read_ascii(item: &CanonicalItem) -> SchemaResult<&str> {
    str::from_utf8(read_variable_item(item, CanonicalItemType::Ascii)?).map_err(|_| {
        FoundationSchemaError::new(RefusalReason::MalformedEncoding, "ASCII item is invalid")
    })
}

fn read_fixed_bytes<const LENGTH: usize>(item: &CanonicalItem) -> SchemaResult<[u8; LENGTH]> {
    read_item(item, CanonicalItemType::RawBytes)?
        .try_into()
        .map_err(|_| {
            FoundationSchemaError::new(
                RefusalReason::WrongTypeOrLength,
                "fixed byte string has the wrong length",
            )
        })
}

fn read_list_header(
    item: &CanonicalItem,
    expected_element_type: CanonicalItemType,
) -> SchemaResult<(usize, &[u8])> {
    let bytes = read_item(item, CanonicalItemType::HomogeneousList)?;
    if bytes.len() < 6
        || u16::from_le_bytes([bytes[0], bytes[1]]) != expected_element_type.canonical_code()
    {
        return Err(FoundationSchemaError::new(
            RefusalReason::WrongTypeOrLength,
            "homogeneous list has the wrong element type",
        ));
    }
    Ok((
        u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]) as usize,
        &bytes[6..],
    ))
}

pub(super) fn read_nested_tuple_list_with_budget(
    item: &CanonicalItem,
    limits: &CanonicalDecodeLimits,
    budget: &mut CanonicalDecodeBudget,
) -> SchemaResult<Vec<CanonicalTuple>> {
    let (count, bytes) = read_list_header(item, CanonicalItemType::NestedTuple)?;
    if count > limits.maximum_item_count {
        return Err(FoundationSchemaError::new(
            RefusalReason::OutsideSupportedProfile,
            "nested tuple list exceeds the configured count limit",
        ));
    }
    let mut tuples = Vec::with_capacity(count);
    let mut offset = 0usize;
    for _ in 0..count {
        let (tuple, consumed) = CanonicalTuple::decode_prefix(&bytes[offset..], limits, budget, 1)?;
        offset = offset.checked_add(consumed).ok_or_else(|| {
            FoundationSchemaError::new(
                RefusalReason::MalformedEncoding,
                "nested tuple list offset overflows",
            )
        })?;
        tuples.push(tuple);
    }
    if offset != bytes.len() {
        return Err(FoundationSchemaError::new(
            RefusalReason::MalformedEncoding,
            "nested tuple list contains trailing bytes",
        ));
    }
    Ok(tuples)
}

#[cfg(test)]
mod tests {
    use fips203::{
        ml_kem_768,
        traits::{KeyGen as KemKeyGen, SerDes as KemSerDes},
    };

    use super::*;

    fn roster_entries(participant_count: u16) -> Vec<RosterEntry> {
        (0..participant_count)
            .map(|roster_position| {
                let mut signing_verification_key =
                    [0x23_u8; ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH];
                signing_verification_key[0..2].copy_from_slice(&roster_position.to_le_bytes());
                let mut mailbox_seed = [0x61_u8; 32];
                mailbox_seed[0] = u8::try_from(roster_position + 1).expect("position fits u8");
                let mut fallback_seed = [0x97_u8; 32];
                fallback_seed[31] = u8::try_from(participant_count - roster_position)
                    .expect("reverse position fits u8");
                let (mailbox_key, _) =
                    ml_kem_768::KG::keygen_from_seed(mailbox_seed, fallback_seed);
                RosterEntry::new(
                    roster_position,
                    signing_verification_key,
                    mailbox_key.into_bytes(),
                )
                .expect("test roster entry is valid")
            })
            .collect()
    }

    #[test]
    fn roster_parameter_formulas_cover_only_the_configurable_range() {
        assert_eq!(derive_foundation_roster_parameters(2), None);
        assert_eq!(derive_foundation_roster_parameters(21), None);
        for participant_count in
            MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT..=MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT
        {
            let parameters = derive_foundation_roster_parameters(participant_count)
                .expect("admitted roster derives");
            assert_eq!(parameters.active_fault_bound, (participant_count - 1) / 3);
            assert_eq!(
                parameters.reconstruction_threshold,
                participant_count / 3 + 1
            );
            assert_eq!(
                parameters.selected_set_quorum,
                (participant_count + parameters.active_fault_bound) / 2 + 1
            );
        }
        assert_eq!(FOUNDATION_PROFILE.active_fault_bound, 3);
        assert_eq!(FOUNDATION_PROFILE.reconstruction_threshold, 4);
        assert_eq!(FOUNDATION_PROFILE.selected_set_quorum, 7);
    }

    #[test]
    fn every_configurable_roster_size_round_trips_canonically() {
        for participant_count in [3, FOUNDATION_PROFILE.participant_count, 20] {
            let roster = Roster::new(roster_entries(participant_count)).expect("roster is valid");
            let encoded = roster.encode().expect("roster encodes");
            let decoded = Roster::decode(&encoded, &CanonicalDecodeLimits::default())
                .expect("roster decodes");
            assert_eq!(decoded, roster);
            assert_eq!(decoded.encode().expect("roster re-encodes"), encoded);
            assert_eq!(
                decoded.roster_hash().expect("decoded roster hashes"),
                roster.roster_hash().expect("source roster hashes")
            );
        }
    }

    #[test]
    fn roster_refuses_duplicates_reordering_and_oversized_declared_counts() {
        let mut entries = roster_entries(3);
        entries.swap(0, 1);
        assert_eq!(
            Roster::new(entries)
                .expect_err("reordered positions refuse")
                .refusal_reason,
            RefusalReason::WrongTypeOrLength
        );

        let mut duplicate = roster_entries(3);
        duplicate[2].signing_verification_key = duplicate[0].signing_verification_key;
        assert_eq!(
            Roster::new(duplicate)
                .expect_err("duplicate identity refuses")
                .refusal_reason,
            RefusalReason::DuplicateIdentity
        );

        let roster = Roster::new(roster_entries(3)).expect("roster is valid");
        let mut encoded = roster.encode().expect("roster encodes");
        encoded[16..20].copy_from_slice(&21_u32.to_le_bytes());
        assert_eq!(
            Roster::decode(&encoded, &CanonicalDecodeLimits::default())
                .expect_err("oversized declared roster refuses before allocation")
                .refusal_reason,
            RefusalReason::OutsideSupportedProfile
        );
    }
}
