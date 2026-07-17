use super::super::StabilizedDisplayText;
use super::*;

struct OversizedByteSource {
    bytes: Vec<u8>,
}

impl OversizedByteSource {
    fn new(byte_length: usize) -> Self {
        Self {
            bytes: vec![0; byte_length],
        }
    }
}

impl AsRef<[u8]> for OversizedByteSource {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

fn unchecked_single_item_tuple(item_type: CanonicalItemType, canonical_bytes: &[u8]) -> Vec<u8> {
    let mut tuple = Vec::new();
    tuple.extend_from_slice(&1_u16.to_le_bytes());
    tuple.extend_from_slice(&1_u16.to_le_bytes());
    tuple.extend_from_slice(&1_u32.to_le_bytes());
    tuple.extend_from_slice(&item_type.canonical_code().to_le_bytes());
    tuple.extend_from_slice(
        &u32::try_from(canonical_bytes.len())
            .expect("test item length fits u32")
            .to_le_bytes(),
    );
    tuple.extend_from_slice(canonical_bytes);
    tuple
}

fn recursively_nested_single_item_tuple(
    nested_tuple_wrapper_count: usize,
    leaf_byte_length: usize,
) -> Vec<u8> {
    let leaf_bytes = vec![0x5a; leaf_byte_length];
    let mut encoded = unchecked_single_item_tuple(CanonicalItemType::RawBytes, &leaf_bytes);
    for _ in 0..nested_tuple_wrapper_count {
        encoded = unchecked_single_item_tuple(CanonicalItemType::NestedTuple, &encoded);
    }
    encoded
}

fn representative_tuple() -> CanonicalTuple {
    let display = StabilizedDisplayText::from_ingress_utf8("Cafe\u{301}".as_bytes())
        .expect("display text normalizes");
    let nested = CanonicalTuple::new(0x0111, 1, vec![CanonicalItem::unsigned16(3)]);
    CanonicalTuple::new(
        0x0110,
        1,
        vec![
            CanonicalItem::unsigned16(1),
            CanonicalItem::ascii("sealed-lattice").expect("printable ASCII"),
            CanonicalItem::display_text(&display).expect("display text fits u32"),
            CanonicalItem::hash512([0x5a; 64]),
            CanonicalItem::nested_tuple(&nested).expect("nested tuple encodes"),
            CanonicalItem::optional(CanonicalItemType::Hash512, None).expect("optional encodes"),
        ],
    )
}

#[test]
fn representative_tuples_and_homogeneous_lists_round_trip_byte_identically() {
    let tuple = representative_tuple();
    let encoded = tuple.encode().expect("tuple encodes");
    let decoded =
        CanonicalTuple::decode(&encoded, &CanonicalDecodeLimits::default()).expect("tuple decodes");
    assert_eq!(decoded, tuple);
    assert_eq!(decoded.encode().expect("decoded tuple re-encodes"), encoded);

    let hash_values = [
        CanonicalItem::hash512([1; 64]),
        CanonicalItem::hash512([2; 64]),
    ];
    let nested_values = [
        CanonicalItem::nested_tuple(&CanonicalTuple::new(
            0x0111,
            1,
            vec![CanonicalItem::unsigned16(0)],
        ))
        .expect("nested tuple"),
        CanonicalItem::nested_tuple(&CanonicalTuple::new(
            0x0111,
            1,
            vec![CanonicalItem::unsigned16(1)],
        ))
        .expect("nested tuple"),
    ];
    let list_tuple = CanonicalTuple::new(
        0x0110,
        1,
        vec![
            CanonicalItem::homogeneous_list(CanonicalItemType::Hash512, &hash_values)
                .expect("hash list"),
            CanonicalItem::homogeneous_list(CanonicalItemType::NestedTuple, &nested_values)
                .expect("tuple list"),
        ],
    );
    let encoded = list_tuple.encode().expect("encode");
    assert_eq!(
        CanonicalTuple::decode(&encoded, &CanonicalDecodeLimits::default()).expect("decode"),
        list_tuple
    );
}

#[test]
fn byte_and_text_constructors_enforce_exact_framed_item_boundaries() {
    let maximum_item_byte_length = CanonicalDecodeLimits::default().maximum_item_byte_length;

    let fixed_item = CanonicalItem::fixed_bytes(vec![0x5a; maximum_item_byte_length])
        .expect("fixed bytes exactly at the item limit must encode");
    assert_eq!(fixed_item.canonical_bytes().len(), maximum_item_byte_length);
    assert_eq!(fixed_item.canonical_bytes().first(), Some(&0x5a));
    assert_eq!(fixed_item.canonical_bytes().last(), Some(&0x5a));
    drop(fixed_item);

    let fixed_error =
        CanonicalItem::fixed_bytes(OversizedByteSource::new(maximum_item_byte_length + 1))
            .expect_err("oversized fixed bytes must refuse before copying");
    assert_eq!(fixed_error.kind, CanonicalCodecErrorKind::LimitExceeded);
    assert_eq!(
        fixed_error.message,
        "fixed byte value exceeds the default item limit"
    );

    let maximum_variable_payload_byte_length = maximum_item_byte_length - 4;
    let variable_item =
        CanonicalItem::variable_bytes(vec![0xa5; maximum_variable_payload_byte_length])
            .expect("variable bytes exactly at the framed item limit must encode");
    assert_eq!(
        variable_item.canonical_bytes().len(),
        maximum_item_byte_length
    );
    assert_eq!(
        &variable_item.canonical_bytes()[..4],
        &u32::try_from(maximum_variable_payload_byte_length)
            .expect("default item limit fits u32")
            .to_le_bytes()
    );
    let variable_payload = variable_item
        .variable_value_bytes()
        .expect("variable payload decodes");
    assert_eq!(variable_payload.first(), Some(&0xa5));
    assert_eq!(variable_payload.last(), Some(&0xa5));
    drop(variable_item);

    let variable_error = CanonicalItem::variable_bytes(OversizedByteSource::new(
        maximum_variable_payload_byte_length + 1,
    ))
    .expect_err("oversized variable bytes must refuse before allocation");
    assert_eq!(variable_error.kind, CanonicalCodecErrorKind::LimitExceeded);
    assert_eq!(
        variable_error.message,
        "variable-width item exceeds the default item limit"
    );

    let maximum_text_byte_length = maximum_item_byte_length - 4;
    let exact_text = "A".repeat(maximum_text_byte_length);

    let ascii_item = CanonicalItem::ascii(&exact_text)
        .expect("ASCII exactly at the framed item limit must encode");
    assert_eq!(ascii_item.canonical_bytes().len(), maximum_item_byte_length);
    assert_eq!(
        ascii_item
            .variable_value_bytes()
            .expect("ASCII payload decodes")
            .len(),
        maximum_text_byte_length
    );
    drop(ascii_item);

    let display_text = StabilizedDisplayText::from_ingress_utf8(exact_text.as_bytes())
        .expect("test text is assigned stabilized NFC");
    drop(exact_text);
    let display_item = CanonicalItem::display_text(&display_text)
        .expect("display text exactly at the framed item limit must encode");
    assert_eq!(
        display_item.canonical_bytes().len(),
        maximum_item_byte_length
    );
    assert_eq!(
        display_item
            .variable_value_bytes()
            .expect("display-text payload decodes")
            .len(),
        maximum_text_byte_length
    );
    drop(display_item);
    drop(display_text);

    let oversized_text = "B".repeat(maximum_text_byte_length + 1);
    let ascii_error = CanonicalItem::ascii(&oversized_text)
        .expect_err("oversized ASCII must refuse before cloning");
    assert_eq!(ascii_error.kind, CanonicalCodecErrorKind::LimitExceeded);

    let oversized_display_text =
        StabilizedDisplayText::from_ingress_utf8(oversized_text.as_bytes())
            .expect("test text is assigned stabilized NFC");
    drop(oversized_text);
    let display_error = CanonicalItem::display_text(&oversized_display_text)
        .expect_err("oversized display text must refuse before cloning");
    assert_eq!(display_error.kind, CanonicalCodecErrorKind::LimitExceeded);
}

#[test]
fn hostile_counts_lengths_types_and_termination_refuse_before_allocation() {
    let limits = CanonicalDecodeLimits {
        maximum_tuple_byte_length: 512,
        maximum_item_count: 4,
        maximum_item_byte_length: 128,
        maximum_nesting_depth: 2,
        ..CanonicalDecodeLimits::default()
    };
    let mut oversized_count = vec![0x10, 0x01, 1, 0];
    oversized_count.extend_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        CanonicalTuple::decode(&oversized_count, &limits)
            .expect_err("oversized count must refuse")
            .kind,
        CanonicalCodecErrorKind::LimitExceeded
    );

    let mut unknown_type = CanonicalTuple::new(1, 1, vec![CanonicalItem::unsigned8(1)])
        .encode()
        .expect("encode");
    unknown_type[8..10].copy_from_slice(&0xffff_u16.to_le_bytes());
    assert_eq!(
        CanonicalTuple::decode(&unknown_type, &limits)
            .expect_err("unknown type must refuse")
            .kind,
        CanonicalCodecErrorKind::UnknownItemType
    );

    let mut hostile_length = unknown_type;
    hostile_length[8..10]
        .copy_from_slice(&CanonicalItemType::RawBytes.canonical_code().to_le_bytes());
    hostile_length[10..14].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        CanonicalTuple::decode(&hostile_length, &limits)
            .expect_err("hostile length must refuse")
            .kind,
        CanonicalCodecErrorKind::LimitExceeded
    );

    let mut trailing = representative_tuple().encode().expect("encode");
    trailing.push(0);
    assert_eq!(
        CanonicalTuple::decode(&trailing, &CanonicalDecodeLimits::default())
            .expect_err("trailing byte must refuse")
            .kind,
        CanonicalCodecErrorKind::TrailingBytes
    );
}

#[test]
fn noncanonical_boolean_optional_and_unicode_items_refuse() {
    let decomposed = "Cafe\u{301}".as_bytes();
    let mut noncanonical_display_text = Vec::new();
    noncanonical_display_text.extend_from_slice(
        &u32::try_from(decomposed.len())
            .expect("test text length fits u32")
            .to_le_bytes(),
    );
    noncanonical_display_text.extend_from_slice(decomposed);
    for (item_type, bytes) in [
        (CanonicalItemType::Boolean, vec![2]),
        (CanonicalItemType::Optional, vec![0x06, 0x00, 0, 1]),
        (CanonicalItemType::DisplayText, noncanonical_display_text),
    ] {
        let encoded = unchecked_single_item_tuple(item_type, &bytes);
        assert!(CanonicalTuple::decode(&encoded, &CanonicalDecodeLimits::default()).is_err());
    }
}

#[test]
fn deeply_nested_optionals_refuse_at_the_configured_depth() {
    let mut contained_type = CanonicalItemType::Unsigned8;
    let mut nested_value = vec![1];
    for _ in 0..40 {
        let mut optional = Vec::with_capacity(nested_value.len() + 3);
        optional.extend_from_slice(&contained_type.canonical_code().to_le_bytes());
        optional.push(1);
        optional.extend_from_slice(&nested_value);
        nested_value = optional;
        contained_type = CanonicalItemType::Optional;
    }
    let error = CanonicalTuple::decode(
        &unchecked_single_item_tuple(CanonicalItemType::Optional, &nested_value),
        &CanonicalDecodeLimits::default(),
    )
    .expect_err("optional nesting must be bounded");
    assert_eq!(error.kind, CanonicalCodecErrorKind::LimitExceeded);

    let mut contained_type = CanonicalItemType::Unsigned8;
    let mut nested_value = vec![1];
    for _ in 0..=ABSOLUTE_MAXIMUM_NESTING_DEPTH {
        let mut optional = Vec::with_capacity(nested_value.len() + 3);
        optional.extend_from_slice(&contained_type.canonical_code().to_le_bytes());
        optional.push(1);
        optional.extend_from_slice(&nested_value);
        nested_value = optional;
        contained_type = CanonicalItemType::Optional;
    }
    let permissive_limits = CanonicalDecodeLimits {
        maximum_nesting_depth: u16::MAX,
        ..CanonicalDecodeLimits::default()
    };
    assert_eq!(
        CanonicalTuple::decode(
            &unchecked_single_item_tuple(CanonicalItemType::Optional, &nested_value),
            &permissive_limits,
        )
        .expect_err("the absolute nesting ceiling cannot be disabled")
        .kind,
        CanonicalCodecErrorKind::LimitExceeded
    );
}

#[test]
fn cumulative_budgets_refuse_recursive_scanning_and_copy_amplification() {
    let encoded = recursively_nested_single_item_tuple(7, 1_024);
    let cumulative_work_byte_length = encoded
        .len()
        .checked_mul(2)
        .expect("test budget multiplication does not overflow");
    let limits = CanonicalDecodeLimits {
        maximum_cumulative_work_byte_length: cumulative_work_byte_length,
        ..CanonicalDecodeLimits::default()
    };

    let error = CanonicalTuple::decode(&encoded, &limits)
        .expect_err("recursive rescanning must consume one shared work budget");
    assert_eq!(error.kind, CanonicalCodecErrorKind::LimitExceeded);
    assert_eq!(
        error.message,
        "canonical decoding exceeds the configured cumulative work limit"
    );

    let allocation_encoded = recursively_nested_single_item_tuple(7, 1_024);
    let cumulative_allocation_byte_length = allocation_encoded
        .len()
        .checked_mul(2)
        .expect("test budget multiplication does not overflow");
    let limits = CanonicalDecodeLimits {
        maximum_cumulative_allocation_byte_length: cumulative_allocation_byte_length,
        ..CanonicalDecodeLimits::default()
    };

    let error = CanonicalTuple::decode(&allocation_encoded, &limits)
        .expect_err("recursive copying must consume one shared allocation budget");
    assert_eq!(error.kind, CanonicalCodecErrorKind::LimitExceeded);
    assert_eq!(
        error.message,
        "canonical decoding exceeds the configured cumulative allocation limit"
    );
}

#[test]
fn cumulative_budgets_enforce_exact_flat_decode_boundaries() {
    let encoded = unchecked_single_item_tuple(CanonicalItemType::Unsigned8, &[7]);
    let before_item_validation_limit = CanonicalDecodeLimits {
        maximum_cumulative_work_byte_length: encoded.len() - 1,
        ..CanonicalDecodeLimits::default()
    };
    let work_error = CanonicalTuple::decode(&encoded, &before_item_validation_limit)
        .expect_err("item validation work must be precharged");
    assert_eq!(work_error.kind, CanonicalCodecErrorKind::LimitExceeded);
    assert_eq!(work_error.byte_offset, 14);

    let exact_work_limit = CanonicalDecodeLimits {
        maximum_cumulative_work_byte_length: encoded.len(),
        ..CanonicalDecodeLimits::default()
    };
    CanonicalTuple::decode(&encoded, &exact_work_limit)
        .expect("the exact cumulative work boundary must decode");

    let before_item_storage_limit = CanonicalDecodeLimits {
        maximum_cumulative_allocation_byte_length: CANONICAL_ITEM_LOGICAL_ALLOCATION_BYTE_LENGTH
            - 1,
        ..CanonicalDecodeLimits::default()
    };
    let storage_error = CanonicalTuple::decode(&encoded, &before_item_storage_limit)
        .expect_err("item storage allocation must be precharged");
    assert_eq!(storage_error.kind, CanonicalCodecErrorKind::LimitExceeded);
    assert_eq!(storage_error.byte_offset, 4);

    let before_item_copy_limit = CanonicalDecodeLimits {
        maximum_cumulative_allocation_byte_length: CANONICAL_ITEM_LOGICAL_ALLOCATION_BYTE_LENGTH,
        ..CanonicalDecodeLimits::default()
    };
    let copy_error = CanonicalTuple::decode(&encoded, &before_item_copy_limit)
        .expect_err("item byte copying must be precharged");
    assert_eq!(copy_error.kind, CanonicalCodecErrorKind::LimitExceeded);
    assert_eq!(copy_error.byte_offset, 14);

    let exact_limit = CanonicalDecodeLimits {
        maximum_cumulative_allocation_byte_length: CANONICAL_ITEM_LOGICAL_ALLOCATION_BYTE_LENGTH
            + 1,
        ..CanonicalDecodeLimits::default()
    };
    CanonicalTuple::decode(&encoded, &exact_limit)
        .expect("the exact logical allocation boundary must decode");
}

#[test]
fn prefix_decodes_share_one_cumulative_budget() {
    let encoded = unchecked_single_item_tuple(CanonicalItemType::Unsigned8, &[7]);
    let limits = CanonicalDecodeLimits {
        maximum_cumulative_work_byte_length: encoded.len(),
        ..CanonicalDecodeLimits::default()
    };
    let mut budget = CanonicalDecodeBudget::new(&limits);

    CanonicalTuple::decode_prefix(&encoded, &limits, &mut budget, 1)
        .expect("the first prefix consumes the exact work budget");
    let error = CanonicalTuple::decode_prefix(&encoded, &limits, &mut budget, 1)
        .expect_err("a second prefix must not receive a fresh work budget");

    assert_eq!(error.kind, CanonicalCodecErrorKind::LimitExceeded);
    assert_eq!(error.byte_offset, 0);
    assert_eq!(
        error.message,
        "canonical decoding exceeds the configured cumulative work limit"
    );
}

#[test]
fn constructors_do_not_emit_values_the_default_decoder_refuses() {
    let too_many_values =
        vec![CanonicalItem::unsigned8(0); CanonicalDecodeLimits::default().maximum_item_count + 1];
    assert_eq!(
        CanonicalItem::homogeneous_list(CanonicalItemType::Unsigned8, &too_many_values)
            .expect_err("oversized list must refuse")
            .kind,
        CanonicalCodecErrorKind::LimitExceeded
    );

    let too_many_items = CanonicalTuple::new(
        1,
        1,
        vec![CanonicalItem::unsigned8(0); CanonicalDecodeLimits::default().maximum_item_count + 1],
    );
    assert_eq!(
        too_many_items
            .encode()
            .expect_err("oversized tuple must refuse")
            .kind,
        CanonicalCodecErrorKind::LimitExceeded
    );

    let maximum_item_byte_length = CanonicalDecodeLimits::default().maximum_item_byte_length;
    assert_eq!(
        CanonicalItem::variable_bytes(vec![0; maximum_item_byte_length])
            .expect_err("inner length framing must be charged before allocation")
            .kind,
        CanonicalCodecErrorKind::LimitExceeded
    );

    let maximum_fixed_item = CanonicalItem::fixed_bytes(vec![0; maximum_item_byte_length])
        .expect("the fixed value itself is exactly at the limit");
    assert_eq!(
        CanonicalItem::optional(CanonicalItemType::RawBytes, Some(&maximum_fixed_item))
            .expect_err("optional framing must be charged before allocation")
            .kind,
        CanonicalCodecErrorKind::LimitExceeded
    );

    let half_limit_item =
        CanonicalItem::fixed_bytes(vec![0; maximum_item_byte_length / 2]).expect("half-limit item");
    assert_eq!(
        CanonicalItem::homogeneous_list(
            CanonicalItemType::RawBytes,
            &[half_limit_item.clone(), half_limit_item],
        )
        .expect_err("list framing must be charged before allocation")
        .kind,
        CanonicalCodecErrorKind::LimitExceeded
    );
}

#[test]
fn typed_local_encoding_uses_exact_caller_derived_bounds_without_weakening_decode() {
    let value_count = CanonicalDecodeLimits::default().maximum_item_count + 1;
    let values = vec![CanonicalItem::unsigned8(7); value_count];
    let list_byte_length = 6_usize
        .checked_add(value_count)
        .expect("test list length fits usize");
    let list_limits = CanonicalDecodeLimits {
        maximum_tuple_byte_length: list_byte_length,
        maximum_item_count: value_count,
        maximum_item_byte_length: list_byte_length,
        ..CanonicalDecodeLimits::default()
    };
    let short_list_count_limit = CanonicalDecodeLimits {
        maximum_item_count: value_count - 1,
        ..list_limits
    };
    assert_eq!(
        CanonicalItem::homogeneous_list_with_limits(
            CanonicalItemType::Unsigned8,
            &values,
            &short_list_count_limit,
        )
        .expect_err("one entry below the derived list-count bound must refuse")
        .kind,
        CanonicalCodecErrorKind::LimitExceeded
    );
    let short_list_byte_limit = CanonicalDecodeLimits {
        maximum_item_byte_length: list_byte_length - 1,
        ..list_limits
    };
    assert_eq!(
        CanonicalItem::homogeneous_list_with_limits(
            CanonicalItemType::Unsigned8,
            &values,
            &short_list_byte_limit,
        )
        .expect_err("one byte below the derived list bound must refuse")
        .kind,
        CanonicalCodecErrorKind::LimitExceeded
    );
    let list = CanonicalItem::homogeneous_list_with_limits(
        CanonicalItemType::Unsigned8,
        &values,
        &list_limits,
    )
    .expect("the exact local list bound accepts the typed value");

    let tuple = CanonicalTuple::new(0x0110, 1, vec![list]);
    let tuple_byte_length = 8_usize
        .checked_add(6)
        .and_then(|length| length.checked_add(list_byte_length))
        .expect("test tuple length fits usize");
    let tuple_limits = CanonicalDecodeLimits {
        maximum_tuple_byte_length: tuple_byte_length,
        maximum_item_count: 1,
        maximum_item_byte_length: list_byte_length,
        ..CanonicalDecodeLimits::default()
    };
    let encoded = tuple
        .encode_with_limits(&tuple_limits)
        .expect("the exact local tuple bound accepts the typed value");

    let short_tuple_limit = CanonicalDecodeLimits {
        maximum_tuple_byte_length: tuple_byte_length - 1,
        ..tuple_limits
    };
    assert_eq!(
        tuple
            .encode_with_limits(&short_tuple_limit)
            .expect_err("one byte below the derived tuple bound must refuse")
            .kind,
        CanonicalCodecErrorKind::LimitExceeded
    );
    assert_eq!(
        CanonicalTuple::decode(&encoded, &CanonicalDecodeLimits::default())
            .expect_err("default external decoding must retain its item-count ceiling")
            .kind,
        CanonicalCodecErrorKind::LimitExceeded
    );
}

#[test]
fn incremental_decoder_round_trips_across_every_two_fragment_boundary() {
    let tuple = CanonicalTuple::new(
        0x0110,
        1,
        vec![
            CanonicalItem::nested_tuple(&representative_tuple())
                .expect("nested representative tuple"),
            CanonicalItem::homogeneous_list(
                CanonicalItemType::Ascii,
                &[
                    CanonicalItem::ascii("first").expect("first ASCII item"),
                    CanonicalItem::ascii("second").expect("second ASCII item"),
                    CanonicalItem::ascii("third").expect("third ASCII item"),
                ],
            )
            .expect("ASCII list"),
            CanonicalItem::boolean(true),
        ],
    );
    let encoded = tuple.encode().expect("tuple encodes");
    let limits = CanonicalDecodeLimits::default();

    for split_offset in 0..=encoded.len() {
        let decoded = CanonicalTuple::decode_fragments(
            encoded.len(),
            [&encoded[..split_offset], &encoded[split_offset..]],
            &limits,
        )
        .unwrap_or_else(|error| panic!("fragment split {split_offset} must decode: {error}"));
        assert_eq!(decoded, tuple, "fragment split {split_offset}");
    }

    let decoded_one_byte_at_a_time =
        CanonicalTuple::decode_fragments(encoded.len(), encoded.chunks(1), &limits)
            .expect("one-byte fragments decode");
    assert_eq!(decoded_one_byte_at_a_time, tuple);
}

#[test]
fn incremental_decoder_refuses_the_same_structural_mutations_as_flat_decode() {
    let limits = CanonicalDecodeLimits::default();
    let canonical = unchecked_single_item_tuple(CanonicalItemType::Boolean, &[1]);
    let mut mutations = Vec::new();

    let mut unknown_item_type = canonical.clone();
    unknown_item_type[8..10].copy_from_slice(&0xffff_u16.to_le_bytes());
    mutations.push(unknown_item_type);

    let mut invalid_boolean = canonical.clone();
    *invalid_boolean.last_mut().expect("boolean byte") = 2;
    mutations.push(invalid_boolean);

    let mut oversized_item = canonical.clone();
    oversized_item[10..14].copy_from_slice(
        &u32::try_from(limits.maximum_item_byte_length + 1)
            .expect("test item bound fits u32")
            .to_le_bytes(),
    );
    mutations.push(oversized_item);

    let mut trailing = canonical;
    trailing.push(0);
    mutations.push(trailing);

    for mutation in mutations {
        let flat_error = CanonicalTuple::decode(&mutation, &limits)
            .expect_err("structural mutation must be refused");
        let mut incremental_decoder =
            IncrementalCanonicalTupleDecoder::new(mutation.len(), &limits)
                .expect("mutation length is within the tuple limit");
        let incremental_error = mutation
            .chunks(1)
            .find_map(|fragment| incremental_decoder.absorb(fragment).err())
            .unwrap_or_else(|| {
                incremental_decoder
                    .finish()
                    .expect_err("structural mutation must be refused at finish")
            });
        assert_eq!(incremental_error.kind, flat_error.kind);
        assert_eq!(incremental_error.byte_offset, flat_error.byte_offset);
    }
}

#[test]
fn incremental_decoder_refuses_every_truncated_prefix_without_panicking() {
    let encoded = representative_tuple()
        .encode()
        .expect("representative tuple encodes");
    let limits = CanonicalDecodeLimits::default();

    for prefix_byte_length in 8..encoded.len() {
        let mut decoder = IncrementalCanonicalTupleDecoder::new(encoded.len(), &limits)
            .expect("declared tuple length is valid");
        let absorb_result = decoder.absorb(&encoded[..prefix_byte_length]);
        if absorb_result.is_ok() {
            let error = decoder
                .finish()
                .expect_err("a truncated prefix must not finish");
            assert_eq!(error.kind, CanonicalCodecErrorKind::Truncated);
            assert!(error.byte_offset <= prefix_byte_length);
        } else {
            assert_eq!(
                absorb_result.expect_err("prefix is refused").kind,
                CanonicalCodecErrorKind::Truncated
            );
        }
    }
}

#[test]
fn incremental_decoder_enforces_declared_length_and_allocation_before_copying() {
    let encoded = unchecked_single_item_tuple(CanonicalItemType::RawBytes, &[0x5a; 32]);
    let limits = CanonicalDecodeLimits {
        maximum_cumulative_allocation_byte_length: CANONICAL_ITEM_LOGICAL_ALLOCATION_BYTE_LENGTH
            + 31,
        ..CanonicalDecodeLimits::default()
    };
    let mut decoder = IncrementalCanonicalTupleDecoder::new(encoded.len(), &limits)
        .expect("tuple length is valid");
    let error = decoder
        .absorb(&encoded[..14])
        .expect_err("declared item allocation exceeds the remaining budget");
    assert_eq!(error.kind, CanonicalCodecErrorKind::LimitExceeded);
    assert_eq!(error.byte_offset, 14);

    let canonical = representative_tuple()
        .encode()
        .expect("representative tuple encodes");
    let mut exact_length_decoder =
        IncrementalCanonicalTupleDecoder::new(canonical.len(), &CanonicalDecodeLimits::default())
            .expect("tuple length is valid");
    let error = exact_length_decoder
        .absorb(&[canonical.as_slice(), &[0]].concat())
        .expect_err("bytes beyond the declared length must be refused");
    assert_eq!(error.kind, CanonicalCodecErrorKind::TrailingBytes);
    assert_eq!(error.byte_offset, canonical.len());
}

#[test]
fn deterministic_hostile_byte_corpus_never_panics_and_successes_are_canonical() {
    fn next_pseudorandom(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    let canonical_seed = representative_tuple()
        .encode()
        .expect("representative tuple encodes");
    let limits = CanonicalDecodeLimits {
        maximum_tuple_byte_length: 4_096,
        maximum_item_count: 256,
        maximum_item_byte_length: 2_048,
        maximum_cumulative_work_byte_length: 8_192,
        maximum_cumulative_allocation_byte_length: 8_192,
        maximum_nesting_depth: 16,
    };
    let mut pseudorandom_state = 0x7365_616c_6564_4c31_u64;

    for case_index in 0..4_096_usize {
        let mut candidate = if case_index % 2 == 0 {
            canonical_seed.clone()
        } else {
            let byte_length = usize::try_from(next_pseudorandom(&mut pseudorandom_state) % 2_049)
                .expect("bounded corpus length fits usize");
            (0..byte_length)
                .map(|_| next_pseudorandom(&mut pseudorandom_state).to_le_bytes()[0])
                .collect::<Vec<_>>()
        };

        if !candidate.is_empty() {
            let mutation_count =
                1 + usize::try_from(next_pseudorandom(&mut pseudorandom_state) % 4)
                    .expect("bounded mutation count fits usize");
            for _ in 0..mutation_count {
                let mutation_index = usize::try_from(
                    next_pseudorandom(&mut pseudorandom_state)
                        % u64::try_from(candidate.len()).expect("candidate length fits u64"),
                )
                .expect("bounded mutation index fits usize");
                candidate[mutation_index] ^=
                    next_pseudorandom(&mut pseudorandom_state).to_le_bytes()[0];
            }
        }

        let decode_outcome =
            std::panic::catch_unwind(|| CanonicalTuple::decode(&candidate, &limits));
        let decoded = decode_outcome.expect("hostile canonical input must never panic");
        if let Ok(tuple) = decoded {
            assert_eq!(
                tuple.encode().expect("accepted tuple re-encodes"),
                candidate,
                "every accepted byte string must already be canonical"
            );
        }
    }
}
