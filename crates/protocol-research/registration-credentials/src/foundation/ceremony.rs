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
#[path = "ceremony-tests.rs"]
mod tests;
