//! Canonical ceremony inputs and their immutable context bindings.

use std::collections::BTreeSet;

use super::canonical_tuple::CanonicalDecodeBudget;
use super::schemas::{
    SchemaResult, read_ascii, read_nested_tuple_list_with_budget, read_u16, read_u64,
    read_variable_item, require_header,
};
use super::suite::SuiteRecord;
use super::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple, FOUNDATION_PROFILE,
    FoundationSchemaError, Hash512, RefusalReason, Roster, StabilizedDisplayText,
    StreamingFoundationTupleHash512, hash_foundation_tuple_512,
};

pub const MANIFEST_SCHEMA_IDENTIFIER: u16 = 0x0110;
pub const OPTION_DEFINITION_SCHEMA_IDENTIFIER: u16 = 0x0111;
pub const ACTION_DEFINITION_SCHEMA_IDENTIFIER: u16 = 0x0112;
pub const BOARD_POLICY_SCHEMA_IDENTIFIER: u16 = 0x0113;

const FOUNDATION_SCHEMA_VERSION: u16 = 1;
const MANIFEST_HASH_DOMAIN: &str = "sealed-lattice/foundation/manifest/v1";
const ACTION_DEFINITION_HASH_DOMAIN: &str = "sealed-lattice/foundation/action-definition/v1";
const BOARD_POLICY_HASH_DOMAIN: &str = "sealed-lattice/foundation/board-policy/v1";
const CEREMONY_CONTEXT_HASH_DOMAIN: &str = "sealed-lattice/foundation/ceremony-context/v1";
const ACTION_CONTEXT_HASH_DOMAIN: &str = "sealed-lattice/foundation/action-context/v1";
const SUBMISSION_CUTOFF_HASH_DOMAIN: &str = "sealed-lattice/foundation/submission-cutoff/v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionDefinition {
    option_index: u16,
    option_identifier: String,
    display_label: StabilizedDisplayText,
}

impl OptionDefinition {
    pub fn new(
        option_index: u16,
        option_identifier: String,
        display_label: StabilizedDisplayText,
    ) -> SchemaResult<Self> {
        let definition = Self {
            option_index,
            option_identifier,
            display_label,
        };
        definition.validate()?;
        Ok(definition)
    }

    pub const fn option_index(&self) -> u16 {
        self.option_index
    }

    pub fn option_identifier(&self) -> &str {
        &self.option_identifier
    }

    pub const fn display_label(&self) -> &StabilizedDisplayText {
        &self.display_label
    }

    fn validate(&self) -> SchemaResult<()> {
        if self.option_index >= FOUNDATION_PROFILE.option_count {
            return Err(FoundationSchemaError::new(
                RefusalReason::OutsideSupportedProfile,
                "option index is outside the supported profile",
            ));
        }
        CanonicalItem::nonempty_ascii(&self.option_identifier)?;
        if self.display_label.as_str().is_empty() {
            return Err(FoundationSchemaError::new(
                RefusalReason::WrongTypeOrLength,
                "option display label must be nonempty",
            ));
        }
        CanonicalItem::display_text(&self.display_label)?;
        Ok(())
    }

    fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
        self.validate()?;
        Ok(CanonicalTuple::new(
            OPTION_DEFINITION_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.option_index),
                CanonicalItem::nonempty_ascii(&self.option_identifier)?,
                CanonicalItem::display_text(&self.display_label)?,
            ],
        ))
    }

    fn from_tuple(tuple: &CanonicalTuple) -> SchemaResult<Self> {
        require_header(tuple, OPTION_DEFINITION_SCHEMA_IDENTIFIER, 3)?;
        Self::new(
            read_u16(&tuple.items[0])?,
            read_ascii(&tuple.items[1])?.to_owned(),
            read_display_text(&tuple.items[2])?,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    display_title: StabilizedDisplayText,
    options: Vec<OptionDefinition>,
}

impl Manifest {
    pub fn new(
        display_title: StabilizedDisplayText,
        options: Vec<OptionDefinition>,
    ) -> SchemaResult<Self> {
        let manifest = Self {
            display_title,
            options,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub const fn display_title(&self) -> &StabilizedDisplayText {
        &self.display_title
    }

    pub fn options(&self) -> &[OptionDefinition] {
        &self.options
    }

    fn validate_components(&self) -> SchemaResult<()> {
        if self.options.len() != usize::from(FOUNDATION_PROFILE.option_count) {
            return Err(FoundationSchemaError::new(
                RefusalReason::OutsideSupportedProfile,
                "manifest option count does not match the supported profile",
            ));
        }
        CanonicalItem::display_text(&self.display_title)?;
        let mut option_identifiers = BTreeSet::new();
        for (option_position, option) in self.options.iter().enumerate() {
            option.validate()?;
            if usize::from(option.option_index) != option_position {
                return Err(FoundationSchemaError::new(
                    RefusalReason::WrongTypeOrLength,
                    "manifest option indexes must be consecutive and canonically ordered",
                ));
            }
            if !option_identifiers.insert(option.option_identifier.as_str()) {
                return Err(FoundationSchemaError::new(
                    RefusalReason::DuplicateIdentity,
                    "manifest option identifiers must be unique",
                ));
            }
        }
        Ok(())
    }

    fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
        self.validate_components()?;
        let options = self
            .options
            .iter()
            .map(|option| {
                option
                    .canonical_tuple()
                    .and_then(|tuple| CanonicalItem::nested_tuple(&tuple).map_err(Into::into))
            })
            .collect::<SchemaResult<Vec<_>>>()?;
        let tuple = CanonicalTuple::new(
            MANIFEST_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::display_text(&self.display_title)?,
                CanonicalItem::homogeneous_list(CanonicalItemType::NestedTuple, &options)?,
            ],
        );
        require_copied_buffer_bound(&tuple, "manifest exceeds the supported copied-buffer bound")?;
        Ok(tuple)
    }

    fn validate(&self) -> SchemaResult<()> {
        self.canonical_tuple().map(|_| ())
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple()?.encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let mut budget = CanonicalDecodeBudget::new(limits);
        let tuple = CanonicalTuple::decode_with_budget(bytes, limits, &mut budget)?;
        require_header(&tuple, MANIFEST_SCHEMA_IDENTIFIER, 2)?;
        let display_title = read_display_text(&tuple.items[0])?;
        let options = read_nested_tuple_list_with_budget(&tuple.items[1], limits, &mut budget)?
            .iter()
            .map(OptionDefinition::from_tuple)
            .collect::<SchemaResult<Vec<_>>>()?;
        Self::new(display_title, options)
    }

    pub fn manifest_hash(&self) -> SchemaResult<Hash512> {
        let canonical_manifest_bytes = self.encode()?;
        let mut hasher = StreamingFoundationTupleHash512::new_variable_bytes(
            MANIFEST_HASH_DOMAIN,
            &[],
            canonical_manifest_bytes.len(),
        )
        .map_err(|_| manifest_hash_error())?;
        hasher
            .absorb(&canonical_manifest_bytes)
            .map_err(|_| manifest_hash_error())?;
        hasher.finalize().map_err(|_| manifest_hash_error())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActionDefinition {
    top_count: u16,
    submission_cutoff_unix_milliseconds: u64,
}

impl ActionDefinition {
    pub fn new(top_count: u16, submission_cutoff_unix_milliseconds: u64) -> SchemaResult<Self> {
        if top_count == 0 || top_count > FOUNDATION_PROFILE.option_count {
            return Err(FoundationSchemaError::new(
                RefusalReason::OutsideSupportedProfile,
                "action top count is outside the supported profile",
            ));
        }
        Ok(Self {
            top_count,
            submission_cutoff_unix_milliseconds,
        })
    }

    pub const fn top_count(self) -> u16 {
        self.top_count
    }

    pub const fn submission_cutoff_unix_milliseconds(self) -> u64 {
        self.submission_cutoff_unix_milliseconds
    }

    fn canonical_tuple(self) -> CanonicalTuple {
        CanonicalTuple::new(
            ACTION_DEFINITION_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.top_count),
                CanonicalItem::unsigned64(self.submission_cutoff_unix_milliseconds),
            ],
        )
    }

    pub fn encode(self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple().encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        require_header(&tuple, ACTION_DEFINITION_SCHEMA_IDENTIFIER, 2)?;
        Self::new(read_u16(&tuple.items[0])?, read_u64(&tuple.items[1])?)
    }

    pub fn action_definition_hash(self) -> SchemaResult<Hash512> {
        Ok(hash_foundation_tuple_512(
            ACTION_DEFINITION_HASH_DOMAIN,
            &[CanonicalItem::variable_bytes(self.encode()?)?],
        )?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoardPolicy {
    board_origin_identifier: String,
}

impl BoardPolicy {
    pub fn new(board_origin_identifier: String) -> SchemaResult<Self> {
        CanonicalItem::ascii(&board_origin_identifier)?;
        let policy = Self {
            board_origin_identifier,
        };
        require_copied_buffer_bound(
            &policy.canonical_tuple()?,
            "board policy exceeds the supported copied-buffer bound",
        )?;
        Ok(policy)
    }

    pub fn board_origin_identifier(&self) -> &str {
        &self.board_origin_identifier
    }

    fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
        Ok(CanonicalTuple::new(
            BOARD_POLICY_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![CanonicalItem::ascii(&self.board_origin_identifier)?],
        ))
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple()?.encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        require_header(&tuple, BOARD_POLICY_SCHEMA_IDENTIFIER, 1)?;
        Self::new(read_ascii(&tuple.items[0])?.to_owned())
    }

    pub fn board_policy_hash(&self) -> SchemaResult<Hash512> {
        Ok(hash_foundation_tuple_512(
            BOARD_POLICY_HASH_DOMAIN,
            &[CanonicalItem::variable_bytes(self.encode()?)?],
        )?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CeremonyContext {
    suite_id: Hash512,
    manifest_hash: Hash512,
    roster_hash: Hash512,
    ceremony_identifier: String,
    context_hash: Hash512,
}

impl CeremonyContext {
    pub fn new(
        suite: &SuiteRecord,
        manifest: &Manifest,
        roster: &Roster,
        ceremony_identifier: String,
    ) -> SchemaResult<Self> {
        validate_external_identifier(&ceremony_identifier)?;
        if roster.entries.len() != usize::from(suite.roster_size()) {
            return Err(FoundationSchemaError::new(
                RefusalReason::WrongContext,
                "ceremony roster size does not match the suite record",
            ));
        }
        let suite_id = suite.suite_id()?;
        let manifest_hash = manifest.manifest_hash()?;
        let roster_hash = roster.roster_hash()?;
        let context_hash = hash_foundation_tuple_512(
            CEREMONY_CONTEXT_HASH_DOMAIN,
            &[
                CanonicalItem::nonempty_ascii(FOUNDATION_PROFILE.protocol_name)?,
                CanonicalItem::unsigned16(FOUNDATION_PROFILE.protocol_version),
                CanonicalItem::hash512(suite_id.into_bytes()),
                CanonicalItem::hash512(manifest_hash.into_bytes()),
                CanonicalItem::hash512(roster_hash.into_bytes()),
                CanonicalItem::nonempty_ascii(&ceremony_identifier)?,
            ],
        )?;
        Ok(Self {
            suite_id,
            manifest_hash,
            roster_hash,
            ceremony_identifier,
            context_hash,
        })
    }

    pub const fn suite_id(&self) -> Hash512 {
        self.suite_id
    }

    pub const fn manifest_hash(&self) -> Hash512 {
        self.manifest_hash
    }

    pub const fn roster_hash(&self) -> Hash512 {
        self.roster_hash
    }

    pub fn ceremony_identifier(&self) -> &str {
        &self.ceremony_identifier
    }

    pub const fn context_hash(&self) -> Hash512 {
        self.context_hash
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionContext {
    suite_id: Hash512,
    roster_hash: Hash512,
    ceremony_context_hash: Hash512,
    action_identifier: String,
    action_definition_hash: Hash512,
    board_policy_hash: Hash512,
    context_hash: Hash512,
    submission_cutoff_hash: Hash512,
}

impl ActionContext {
    pub fn new(
        ceremony_context: &CeremonyContext,
        action_identifier: String,
        action_definition: ActionDefinition,
        board_policy: &BoardPolicy,
    ) -> SchemaResult<Self> {
        validate_external_identifier(&action_identifier)?;
        let action_definition_hash = action_definition.action_definition_hash()?;
        let board_policy_hash = board_policy.board_policy_hash()?;
        let context_hash = hash_foundation_tuple_512(
            ACTION_CONTEXT_HASH_DOMAIN,
            &[
                CanonicalItem::hash512(ceremony_context.context_hash.into_bytes()),
                CanonicalItem::nonempty_ascii(&action_identifier)?,
                CanonicalItem::hash512(action_definition_hash.into_bytes()),
                CanonicalItem::hash512(board_policy_hash.into_bytes()),
            ],
        )?;
        let submission_cutoff_hash = hash_foundation_tuple_512(
            SUBMISSION_CUTOFF_HASH_DOMAIN,
            &[
                CanonicalItem::hash512(context_hash.into_bytes()),
                CanonicalItem::unsigned64(action_definition.submission_cutoff_unix_milliseconds),
            ],
        )?;
        Ok(Self {
            suite_id: ceremony_context.suite_id,
            roster_hash: ceremony_context.roster_hash,
            ceremony_context_hash: ceremony_context.context_hash,
            action_identifier,
            action_definition_hash,
            board_policy_hash,
            context_hash,
            submission_cutoff_hash,
        })
    }

    pub const fn suite_id(&self) -> Hash512 {
        self.suite_id
    }

    pub const fn roster_hash(&self) -> Hash512 {
        self.roster_hash
    }

    pub const fn ceremony_context_hash(&self) -> Hash512 {
        self.ceremony_context_hash
    }

    pub fn action_identifier(&self) -> &str {
        &self.action_identifier
    }

    pub const fn action_definition_hash(&self) -> Hash512 {
        self.action_definition_hash
    }

    pub const fn board_policy_hash(&self) -> Hash512 {
        self.board_policy_hash
    }

    pub const fn context_hash(&self) -> Hash512 {
        self.context_hash
    }

    pub const fn submission_cutoff_hash(&self) -> Hash512 {
        self.submission_cutoff_hash
    }
}

fn read_display_text(item: &CanonicalItem) -> SchemaResult<StabilizedDisplayText> {
    let bytes = read_variable_item(item, CanonicalItemType::DisplayText)?;
    StabilizedDisplayText::from_canonical_utf8(bytes).map_err(|error| {
        FoundationSchemaError::new(error.refusal_reason(), "display text is not canonical")
    })
}

fn require_copied_buffer_bound(tuple: &CanonicalTuple, message: &'static str) -> SchemaResult<()> {
    if tuple.encode()?.len() > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length {
        return Err(FoundationSchemaError::new(
            RefusalReason::OutsideSupportedProfile,
            message,
        ));
    }
    Ok(())
}

fn manifest_hash_error() -> FoundationSchemaError {
    FoundationSchemaError::new(
        RefusalReason::OutsideSupportedProfile,
        "manifest cannot be framed within the supported hash profile",
    )
}

fn validate_external_identifier(identifier: &str) -> SchemaResult<()> {
    if identifier.len() > FOUNDATION_PROFILE.maximum_identifier_byte_length {
        return Err(FoundationSchemaError::new(
            RefusalReason::OutsideSupportedProfile,
            "external identifier exceeds the supported byte bound",
        ));
    }
    CanonicalItem::nonempty_ascii(identifier)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use fips203::{
        ml_kem_768,
        traits::{KeyGen as KemKeyGen, SerDes as KemSerDes},
    };
    use fips204::{
        ml_dsa_65,
        traits::{KeyGen as SignatureKeyGen, SerDes as SignatureSerDes},
    };

    use super::*;
    use crate::foundation::{ArtifactKind, ArtifactReference, RosterEntry, SuiteCountLimits};

    fn display_text(value: &str) -> StabilizedDisplayText {
        StabilizedDisplayText::from_ingress_utf8(value.as_bytes())
            .expect("test display text is valid")
    }

    fn sample_manifest() -> Manifest {
        let options = (0..FOUNDATION_PROFILE.option_count)
            .map(|option_index| {
                OptionDefinition::new(
                    option_index,
                    format!("option-{option_index}"),
                    display_text(&format!("Option {option_index}")),
                )
                .expect("test option is valid")
            })
            .collect();
        Manifest::new(display_text("Ceremony title"), options).expect("test manifest is valid")
    }

    fn sample_roster() -> Roster {
        let entries = (0..FOUNDATION_PROFILE.participant_count)
            .map(|roster_position| {
                let mut signing_seed = [0x23_u8; 32];
                signing_seed[0] = u8::try_from(roster_position + 1).expect("test position fits u8");
                let (signing_key, _) = ml_dsa_65::KG::keygen_from_seed(&signing_seed);
                let mut mailbox_seed = [0x61_u8; 32];
                mailbox_seed[0] = u8::try_from(roster_position + 1).expect("test position fits u8");
                let mut mailbox_fallback_seed = [0x97_u8; 32];
                mailbox_fallback_seed[31] =
                    u8::try_from(FOUNDATION_PROFILE.participant_count - roster_position)
                        .expect("reverse test position fits u8");
                let (mailbox_key, _) =
                    ml_kem_768::KG::keygen_from_seed(mailbox_seed, mailbox_fallback_seed);
                RosterEntry {
                    roster_position,
                    signing_verification_key: signing_key.into_bytes(),
                    mailbox_encapsulation_key: mailbox_key.into_bytes(),
                }
            })
            .collect();
        Roster::new(entries).expect("test roster is valid")
    }

    fn sample_suite() -> SuiteRecord {
        let count_limits = SuiteCountLimits::new(3, 10, 64, 128, 20, 100)
            .expect("test suite count limits are valid");
        let artifacts = ArtifactKind::ALL
            .into_iter()
            .map(|artifact_kind| {
                ArtifactReference::new(
                    artifact_kind,
                    1,
                    Hash512::from_bytes(
                        [u8::try_from(artifact_kind.canonical_code())
                            .expect("test artifact kind fits u8");
                            Hash512::BYTE_LENGTH],
                    ),
                )
                .expect("test artifact reference is valid")
            })
            .collect();
        SuiteRecord::new(count_limits, artifacts).expect("test suite is valid")
    }

    #[test]
    fn manifest_round_trip_preserves_normalized_text_and_hash() {
        let manifest = sample_manifest();
        let encoded = manifest.encode().expect("manifest encodes");
        let tuple = CanonicalTuple::decode(&encoded, &CanonicalDecodeLimits::default())
            .expect("manifest tuple decodes");
        assert_eq!(tuple.schema_identifier, MANIFEST_SCHEMA_IDENTIFIER);
        assert_eq!(tuple.items.len(), 2);

        let decoded = Manifest::decode(&encoded, &CanonicalDecodeLimits::default())
            .expect("manifest decodes");
        assert_eq!(decoded, manifest);
        assert_eq!(
            decoded.manifest_hash().expect("decoded hash derives"),
            manifest.manifest_hash().expect("manifest hash derives")
        );
    }

    #[test]
    fn manifest_hash_accepts_the_exact_copied_buffer_boundary() {
        let options = sample_manifest().options;
        let one_byte_title_manifest =
            Manifest::new(display_text("A"), options.clone()).expect("test manifest is valid");
        let title_independent_byte_length = one_byte_title_manifest
            .encode()
            .expect("one-byte-title manifest encodes")
            .len()
            - 1;
        let maximum_title_byte_length = FOUNDATION_PROFILE
            .maximum_copied_buffer_byte_length
            .checked_sub(title_independent_byte_length)
            .expect("manifest framing fits the copied-buffer profile");

        let exact_boundary_manifest = Manifest::new(
            display_text(&"A".repeat(maximum_title_byte_length)),
            options.clone(),
        )
        .expect("exact-boundary manifest is valid");
        assert_eq!(
            exact_boundary_manifest
                .encode()
                .expect("exact-boundary manifest encodes")
                .len(),
            FOUNDATION_PROFILE.maximum_copied_buffer_byte_length,
        );
        exact_boundary_manifest
            .manifest_hash()
            .expect("exact-boundary manifest hash derives");

        assert_eq!(
            Manifest::new(
                display_text(&"A".repeat(maximum_title_byte_length + 1)),
                options,
            )
            .expect_err("one byte beyond the copied-buffer boundary must refuse")
            .refusal_reason,
            RefusalReason::OutsideSupportedProfile,
        );
    }

    #[test]
    fn manifest_rejects_wrong_count_order_duplicate_identifiers_and_empty_labels() {
        let mut too_few = sample_manifest().options;
        too_few.pop();
        assert_eq!(
            Manifest::new(display_text("Title"), too_few)
                .expect_err("nineteen options must refuse")
                .refusal_reason,
            RefusalReason::OutsideSupportedProfile
        );

        let mut wrong_order = sample_manifest().options;
        wrong_order.swap(3, 4);
        assert_eq!(
            Manifest::new(display_text("Title"), wrong_order)
                .expect_err("wrong option order must refuse")
                .refusal_reason,
            RefusalReason::WrongTypeOrLength
        );

        let mut duplicate_identifier = sample_manifest().options;
        duplicate_identifier[7].option_identifier =
            duplicate_identifier[2].option_identifier.clone();
        assert_eq!(
            Manifest::new(display_text("Title"), duplicate_identifier)
                .expect_err("duplicate option identifier must refuse")
                .refusal_reason,
            RefusalReason::DuplicateIdentity
        );

        assert_eq!(
            OptionDefinition::new(0, "option-0".to_owned(), display_text(""))
                .expect_err("empty display label must refuse")
                .refusal_reason,
            RefusalReason::WrongTypeOrLength
        );
        assert_eq!(
            OptionDefinition::new(0, "option\n0".to_owned(), display_text("Option"))
                .expect_err("non-printable identifier must refuse")
                .refusal_reason,
            RefusalReason::MalformedEncoding
        );
    }

    #[test]
    fn action_and_board_values_round_trip_and_reject_genuine_boundary_errors() {
        for top_count in [1, FOUNDATION_PROFILE.option_count] {
            let action =
                ActionDefinition::new(top_count, u64::MAX).expect("boundary top count is valid");
            assert_eq!(
                ActionDefinition::decode(
                    &action.encode().expect("action encodes"),
                    &CanonicalDecodeLimits::default(),
                )
                .expect("action decodes"),
                action
            );
        }
        for top_count in [0, FOUNDATION_PROFILE.option_count + 1] {
            assert_eq!(
                ActionDefinition::new(top_count, 0)
                    .expect_err("out-of-range top count must refuse")
                    .refusal_reason,
                RefusalReason::OutsideSupportedProfile
            );
        }

        let board_policy =
            BoardPolicy::new("https://board.example".to_owned()).expect("board policy is valid");
        assert_eq!(
            BoardPolicy::decode(
                &board_policy.encode().expect("board policy encodes"),
                &CanonicalDecodeLimits::default(),
            )
            .expect("board policy decodes"),
            board_policy
        );
        assert!(BoardPolicy::new("board\norigin".to_owned()).is_err());
    }

    #[test]
    fn context_hashes_bind_every_canonical_input_and_identifier_boundary() {
        let manifest = sample_manifest();
        let roster = sample_roster();
        let suite = sample_suite();
        let suite_id = suite.suite_id().expect("suite identifier derives");
        let ceremony = CeremonyContext::new(&suite, &manifest, &roster, "ceremony-2026".to_owned())
            .expect("schema-level ceremony context derives");
        let action_definition =
            ActionDefinition::new(7, 1_800_000_000_000).expect("action definition is valid");
        let board_policy =
            BoardPolicy::new("board.example".to_owned()).expect("board policy is valid");
        let action = ActionContext::new(
            &ceremony,
            "submission".to_owned(),
            action_definition,
            &board_policy,
        )
        .expect("action context derives");

        let expected_ceremony_hash = hash_foundation_tuple_512(
            CEREMONY_CONTEXT_HASH_DOMAIN,
            &[
                CanonicalItem::nonempty_ascii(FOUNDATION_PROFILE.protocol_name)
                    .expect("protocol name is canonical"),
                CanonicalItem::unsigned16(FOUNDATION_PROFILE.protocol_version),
                CanonicalItem::hash512(suite_id.into_bytes()),
                CanonicalItem::hash512(
                    manifest
                        .manifest_hash()
                        .expect("manifest hash")
                        .into_bytes(),
                ),
                CanonicalItem::hash512(roster.roster_hash().expect("roster hash").into_bytes()),
                CanonicalItem::nonempty_ascii("ceremony-2026").expect("identifier is canonical"),
            ],
        )
        .expect("manual ceremony hash derives");
        assert_eq!(ceremony.context_hash(), expected_ceremony_hash);
        assert_eq!(action.suite_id(), suite_id);
        assert_eq!(action.roster_hash(), ceremony.roster_hash());

        let changed_action = ActionContext::new(
            &ceremony,
            "submission-two".to_owned(),
            action_definition,
            &board_policy,
        )
        .expect("changed action context derives");
        assert_ne!(changed_action.context_hash(), action.context_hash());
        assert_ne!(
            changed_action.submission_cutoff_hash(),
            action.submission_cutoff_hash()
        );

        for invalid_identifier in [
            String::new(),
            "bad\nidentifier".to_owned(),
            "a".repeat(FOUNDATION_PROFILE.maximum_identifier_byte_length + 1),
        ] {
            assert!(CeremonyContext::new(&suite, &manifest, &roster, invalid_identifier,).is_err());
        }
    }

    #[test]
    fn ceremony_context_is_structural_and_does_not_select_a_suite() {
        let suite = sample_suite();
        let ceremony_context = CeremonyContext::new(
            &suite,
            &sample_manifest(),
            &sample_roster(),
            "ceremony-2026".to_owned(),
        )
        .expect("a structurally valid suite can bind a ceremony context");
        assert_eq!(
            ceremony_context.suite_id(),
            suite.suite_id().expect("suite identifier derives")
        );

        let error = super::super::selected_suite::require_selected_suite_record(&suite)
            .expect_err("structural validation must not grant selected-suite authority");
        assert!(matches!(
            error.refusal_reason,
            RefusalReason::UnsupportedVersionOrSuite | RefusalReason::OutsideSupportedProfile
        ));
    }

    #[test]
    fn ceremony_context_requires_the_suite_and_roster_sizes_to_match() {
        let suite = sample_suite();
        let short_roster = Roster::new(sample_roster().entries.into_iter().take(3).collect())
            .expect("three-participant roster is structural");
        assert_eq!(
            CeremonyContext::new(
                &suite,
                &sample_manifest(),
                &short_roster,
                "ceremony-2026".to_owned(),
            )
            .expect_err("a selected-profile suite cannot bind a different roster size")
            .refusal_reason,
            RefusalReason::WrongContext
        );
    }

    #[test]
    fn manifest_decode_respects_caller_limits_and_schema_identity() {
        let manifest = sample_manifest();
        let encoded = manifest.encode().expect("manifest encodes");
        let limits = CanonicalDecodeLimits {
            maximum_tuple_byte_length: encoded.len() - 1,
            ..CanonicalDecodeLimits::default()
        };
        assert_eq!(
            Manifest::decode(&encoded, &limits)
                .expect_err("bounded decoder must reject oversized input")
                .refusal_reason,
            RefusalReason::OutsideSupportedProfile
        );

        let mut tuple = manifest.canonical_tuple().expect("manifest tuple");
        tuple.schema_identifier = BOARD_POLICY_SCHEMA_IDENTIFIER;
        assert_eq!(
            Manifest::decode(
                &tuple.encode().expect("mutated tuple encodes"),
                &CanonicalDecodeLimits::default(),
            )
            .expect_err("wrong schema must refuse")
            .refusal_reason,
            RefusalReason::WrongTypeOrLength
        );
    }
}
