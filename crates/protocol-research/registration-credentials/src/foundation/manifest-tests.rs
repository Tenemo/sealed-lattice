use super::*;

// A poll has 2 to 20 options. The literals restate that owner
// independently of the implementation constants the tests check.
const GOAL_OPTION_COUNTS: std::ops::RangeInclusive<u16> = 2..=20;

fn display_text(value: &str) -> StabilizedDisplayText {
    StabilizedDisplayText::from_ingress_utf8(value.as_bytes()).expect("test display text is valid")
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

    let decoded =
        Manifest::decode(&encoded, &CanonicalDecodeLimits::default()).expect("manifest decodes");
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
    duplicate_identifier[7].option_identifier = duplicate_identifier[2].option_identifier.clone();
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
