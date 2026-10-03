use std::collections::BTreeSet;

use supported_profile::Profile;

use super::canonical_tuple::CanonicalDecodeBudget;
use super::schemas::{
    SchemaResult, read_ascii, read_nested_tuple_list_with_budget, read_u16, read_variable_item,
    require_header,
};
use super::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple, FoundationSchemaError,
    RefusalReason, StabilizedDisplayText,
};

const MANIFEST_SCHEMA_IDENTIFIER: u16 = 0x0110;
const OPTION_DEFINITION_SCHEMA_IDENTIFIER: u16 = 0x0111;

const FOUNDATION_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionDefinition {
    option_index: u16,
    option_identifier: String,
    display_label: StabilizedDisplayText,
}

impl OptionDefinition {
    pub fn option_identifier(&self) -> &str {
        &self.option_identifier
    }
    pub fn display_label(&self) -> &StabilizedDisplayText {
        &self.display_label
    }
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

    fn validate(&self) -> SchemaResult<()> {
        if usize::from(self.option_index) >= *Profile::option_range().end() {
            return Err(FoundationSchemaError::new(
                RefusalReason::OutsideSupportedProfile,
                "option index is outside the supported profile",
            ));
        }
        CanonicalItem::nonempty_ascii(self.option_identifier())?;
        if self.display_label().as_str().is_empty() {
            return Err(FoundationSchemaError::new(
                RefusalReason::WrongTypeOrLength,
                "option display label must be nonempty",
            ));
        }
        CanonicalItem::display_text(self.display_label())?;
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
    pub fn option_count(&self) -> usize {
        self.options.len()
    }
    pub fn display_title(&self) -> &StabilizedDisplayText {
        &self.display_title
    }
    pub fn options(&self) -> &[OptionDefinition] {
        &self.options
    }

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

    fn validate_components(&self) -> SchemaResult<()> {
        if !Profile::option_range().contains(&self.option_count()) {
            return Err(FoundationSchemaError::new(
                RefusalReason::OutsideSupportedProfile,
                "manifest option count is outside the configurable range",
            ));
        }
        if self.display_title().as_str().is_empty() {
            return Err(FoundationSchemaError::new(
                RefusalReason::WrongTypeOrLength,
                "manifest display title must be nonempty",
            ));
        }
        CanonicalItem::display_text(self.display_title())?;
        let mut option_identifiers = BTreeSet::new();
        let mut display_labels = BTreeSet::new();
        for (option_position, option) in self.options().iter().enumerate() {
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
            // Stabilized labels are NFC, so canonically equivalent input
            // spellings compare equal here.
            if !display_labels.insert(option.display_label.as_str()) {
                return Err(FoundationSchemaError::new(
                    RefusalReason::DuplicateIdentity,
                    "manifest option display labels must be unique",
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
            .map(OptionDefinition::canonical_tuple)
            .collect::<SchemaResult<Vec<_>>>()?;
        Ok(CanonicalTuple::new(
            MANIFEST_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::display_text(&self.display_title)?,
                CanonicalItem::nested_tuple_list(&options)?,
            ],
        ))
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
}

fn read_display_text(item: &CanonicalItem) -> SchemaResult<StabilizedDisplayText> {
    let bytes = read_variable_item(item, CanonicalItemType::DisplayText)?;
    StabilizedDisplayText::from_canonical_utf8(bytes).map_err(|error| {
        FoundationSchemaError::new(error.refusal_reason(), "display text is not canonical")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // A poll has 2 to 20 options. The literals restate that owner
    // independently of the implementation constants the tests check.
    const GOAL_OPTION_COUNTS: std::ops::RangeInclusive<u16> = 2..=20;

    fn display_text(value: &str) -> StabilizedDisplayText {
        StabilizedDisplayText::from_ingress_utf8(value.as_bytes())
            .expect("test display text is valid")
    }

    fn manifest_for_option_count(option_count: u16) -> Manifest {
        let options = (0..option_count)
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

    fn sample_manifest() -> Manifest {
        manifest_for_option_count(10)
    }

    #[test]
    fn manifest_round_trip_preserves_normalized_text() {
        let manifest = sample_manifest();
        let encoded = manifest.encode().expect("manifest encodes");
        let tuple = CanonicalTuple::decode(&encoded, &CanonicalDecodeLimits::default())
            .expect("manifest tuple decodes");
        assert_eq!(tuple.schema_identifier, MANIFEST_SCHEMA_IDENTIFIER);
        assert_eq!(tuple.items.len(), 2);

        let decoded = Manifest::decode(&encoded, &CanonicalDecodeLimits::default())
            .expect("manifest decodes");
        assert_eq!(decoded, manifest);
    }

    #[test]
    fn manifest_schema_round_trips_every_configurable_option_count() {
        for option_count in GOAL_OPTION_COUNTS {
            let manifest = manifest_for_option_count(option_count);
            let encoded = manifest.encode().expect("bounded manifest encodes");
            let decoded = Manifest::decode(&encoded, &CanonicalDecodeLimits::default())
                .expect("bounded manifest decodes");
            assert_eq!(decoded.options.len(), usize::from(option_count));
            assert_eq!(
                decoded.encode().expect("bounded manifest re-encodes"),
                encoded
            );
        }
    }

    #[test]
    fn manifest_rejects_wrong_count_order_duplicates_and_empty_text() {
        let too_few = manifest_for_option_count(*GOAL_OPTION_COUNTS.start())
            .options
            .into_iter()
            .take(1)
            .collect();
        assert_eq!(
            Manifest::new(display_text("Title"), too_few)
                .expect_err("one option must refuse")
                .refusal_reason,
            RefusalReason::OutsideSupportedProfile
        );
        // A twenty-first option cannot be constructed, so encode it unchecked
        // and require the decoder to refuse the oversized manifest.
        let mut too_many: Vec<_> = manifest_for_option_count(*GOAL_OPTION_COUNTS.end())
            .options
            .iter()
            .map(|option| option.canonical_tuple().expect("option encodes"))
            .collect();
        too_many.push(CanonicalTuple::new(
            OPTION_DEFINITION_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(*GOAL_OPTION_COUNTS.end()),
                CanonicalItem::nonempty_ascii("option-20").expect("identifier encodes"),
                CanonicalItem::display_text(&display_text("Option 20")).expect("label encodes"),
            ],
        ));
        let too_many_bytes = CanonicalTuple::new(
            MANIFEST_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::display_text(&display_text("Title")).expect("title encodes"),
                CanonicalItem::nested_tuple_list(&too_many).expect("options encode"),
            ],
        )
        .encode()
        .expect("unchecked manifest encodes");
        assert_eq!(
            Manifest::decode(&too_many_bytes, &CanonicalDecodeLimits::default())
                .expect_err("twenty-one options must refuse")
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

        let mut equivalent_labels = sample_manifest().options;
        equivalent_labels[2].display_label = display_text("\u{e9}");
        equivalent_labels[7].display_label = display_text("e\u{301}");
        assert_eq!(
            Manifest::new(display_text("Title"), equivalent_labels.clone())
                .expect_err("canonically equivalent display labels must refuse")
                .refusal_reason,
            RefusalReason::DuplicateIdentity
        );
        let unchecked_bytes = CanonicalTuple::new(
            MANIFEST_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::display_text(&display_text("Title")).expect("title encodes"),
                CanonicalItem::nested_tuple_list(
                    &equivalent_labels
                        .iter()
                        .map(|option| option.canonical_tuple().expect("option encodes"))
                        .collect::<Vec<_>>(),
                )
                .expect("options encode"),
            ],
        )
        .encode()
        .expect("unchecked manifest encodes");
        assert_eq!(
            Manifest::decode(&unchecked_bytes, &CanonicalDecodeLimits::default())
                .expect_err("decoded duplicate display labels must refuse")
                .refusal_reason,
            RefusalReason::DuplicateIdentity
        );

        assert_eq!(
            Manifest::new(display_text(""), sample_manifest().options)
                .expect_err("empty display title must refuse")
                .refusal_reason,
            RefusalReason::WrongTypeOrLength
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
        tuple.schema_identifier = OPTION_DEFINITION_SCHEMA_IDENTIFIER;
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
