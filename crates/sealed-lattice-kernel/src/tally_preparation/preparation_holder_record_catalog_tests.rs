use crate::{
    foundation::{
        FOUNDATION_PROFILE, Hash512, MAXIMUM_CONFIGURABLE_OPTION_COUNT,
        MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT, MINIMUM_CONFIGURABLE_OPTION_COUNT,
        MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT,
    },
    hashing::{hash_framed_parts_512, to_hex},
    tally_circuit::{BooleanOperation, CompiledTallyCircuit, TallyCircuitProfile, WireIndex},
};

use super::{
    TallyPreparationContext, TallyPreparationError,
    garbled_resource_model::GarbledTallyResourceLowerBound,
    preparation_holder_record_catalog::{
        PreparationHolderOutputKind, PreparationHolderRecord, PreparationHolderRecordCatalog,
        PreparationHolderRecordClass, PreparationHolderRecordCoordinate,
        PreparationHolderRecordInventory, PreparationHolderRecordIter,
        compiler_identity_from_source_for_test,
    },
};

const CATALOG_IDENTITY_DOMAIN: &str =
    "sealed-lattice/preparation-holder-record-catalog-identity/v1";

#[test]
fn completion_catalog_streams_every_holder_record_in_source_order() {
    let circuit = completion_profile_circuit();
    let catalog = PreparationHolderRecordCatalog::derive(context(0x51, &circuit), &circuit)
        .expect("completion holder-record catalog should derive");

    assert_eq!(catalog.record_count(), 475_590);
    assert_eq!(catalog.records().len(), 475_590);
    assert_eq!(catalog.value_field_element_count(), 967_590);
    assert_eq!(catalog.verification_key_field_element_count(), 1_443_180);
    assert_eq!(catalog.record(0).unwrap().global_ordinal, 0);
    assert_eq!(catalog.record_stream_byte_length(), 6_659_588);
    assert_eq!(catalog.artifact_byte_length(), 6_659_930);

    let mut records = catalog.records();
    let mut expected_ordinal = 0_u64;
    let participant_count = circuit.profile().participant_count();
    let input_wire_count = u32::try_from(circuit.geometry().input_bit_count).unwrap();

    for input_wire in 0..input_wire_count {
        for holder_position in 0..participant_count {
            assert_next_record(
                &mut records,
                &mut expected_ordinal,
                PreparationHolderRecordCoordinate::InputMask {
                    input_wire,
                    holder_position,
                },
            );
        }
    }
    for input_wire in 0..input_wire_count {
        for label_alternative in 0_u8..2 {
            for label_component_position in 0..participant_count {
                for holder_position in 0..participant_count {
                    assert_next_record(
                        &mut records,
                        &mut expected_ordinal,
                        PreparationHolderRecordCoordinate::InputLabelBody {
                            input_wire,
                            label_alternative,
                            label_component_position,
                            holder_position,
                        },
                    );
                }
            }
        }
    }
    let mut conjunction_ordinal = 0_u64;
    for (operation_position, operation) in circuit.operations().iter().enumerate() {
        let BooleanOperation::Conjunction {
            left_wire,
            right_wire,
        } = operation
        else {
            continue;
        };
        let circuit_operation_position = u64::try_from(operation_position).unwrap();
        let output_wire =
            WireIndex::try_from(u64::from(input_wire_count) + circuit_operation_position).unwrap();
        for input_value_code in 0_u8..4 {
            for holder_position in 0..participant_count {
                assert_next_record(
                    &mut records,
                    &mut expected_ordinal,
                    PreparationHolderRecordCoordinate::ConjunctionRowBit {
                        conjunction_ordinal,
                        circuit_operation_position,
                        output_wire,
                        left_wire: *left_wire,
                        right_wire: *right_wire,
                        input_value_code,
                        holder_position,
                    },
                );
            }
        }
        conjunction_ordinal += 1;
    }
    for holder_position in 0..participant_count {
        assert_next_record(
            &mut records,
            &mut expected_ordinal,
            PreparationHolderRecordCoordinate::OutputMask {
                output_position: 0,
                output_kind: PreparationHolderOutputKind::PublicNonempty,
                output_wire: circuit.nonempty_output_wire(),
                holder_position,
            },
        );
    }
    for (result_bit_position, output_wire) in circuit
        .ordered_option_position_wires()
        .iter()
        .flatten()
        .copied()
        .enumerate()
    {
        for holder_position in 0..participant_count {
            assert_next_record(
                &mut records,
                &mut expected_ordinal,
                PreparationHolderRecordCoordinate::OutputMask {
                    output_position: u64::try_from(result_bit_position).unwrap() + 1,
                    output_kind: PreparationHolderOutputKind::PrivateResult {
                        result_bit_position: u64::try_from(result_bit_position).unwrap(),
                    },
                    output_wire,
                    holder_position,
                },
            );
        }
    }
    assert_eq!(expected_ordinal, catalog.record_count());
    assert!(records.next().is_none());

    let mut class_counts = [0_u64; 5];
    let mut materialized_artifact = catalog.canonical_header_bytes();
    for record in catalog.records() {
        let record = record.unwrap();
        class_counts[class_position(record.class())] += 1;
        materialized_artifact.extend(record.canonical_bytes());
    }
    assert_eq!(class_counts, [12_300, 246_000, 216_880, 10, 400]);
    assert_eq!(
        u64::try_from(materialized_artifact.len()).unwrap(),
        catalog.artifact_byte_length()
    );
    assert_eq!(
        u64::try_from(materialized_artifact.len() - catalog.canonical_header_bytes().len())
            .unwrap(),
        catalog.record_stream_byte_length()
    );
    assert_eq!(
        catalog.identity().as_bytes(),
        &hash_framed_parts_512(CATALOG_IDENTITY_DOMAIN, &[&materialized_artifact])
    );
    assert_eq!(
        to_hex(catalog.identity().as_bytes()),
        "5bdc5844512d6319e964a13108ad87f4867a161c9d41ee043aaf4c9a66ec7b42853bec57773bbccb2923cf5d738f0202ad1fe241100fd000f8be137164394ed3"
    );
}

#[test]
fn completion_catalog_boundaries_bind_exact_sources_and_value_widths() {
    let circuit = completion_profile_circuit();
    let inventory = PreparationHolderRecordInventory::derive(context(0x51, &circuit), &circuit)
        .expect("completion holder-record inventory should derive");
    let conjunctions = completion_conjunctions(&circuit);
    let first_conjunction = conjunctions.first().unwrap();
    let final_conjunction = conjunctions.last().unwrap();

    assert_eq!(
        inventory.record_class_counts(),
        [12_300, 246_000, 216_880, 10, 400]
    );
    assert_eq!(
        inventory.record(0).unwrap(),
        PreparationHolderRecord {
            global_ordinal: 0,
            coordinate: PreparationHolderRecordCoordinate::InputMask {
                input_wire: 0,
                holder_position: 0,
            },
        }
    );
    assert_eq!(
        inventory.record(12_300).unwrap(),
        PreparationHolderRecord {
            global_ordinal: 12_300,
            coordinate: PreparationHolderRecordCoordinate::InputLabelBody {
                input_wire: 0,
                label_alternative: 0,
                label_component_position: 0,
                holder_position: 0,
            },
        }
    );
    assert_eq!(
        inventory
            .record(12_300)
            .unwrap()
            .value_field_element_count(),
        3
    );
    assert_eq!(
        inventory
            .record(12_300)
            .unwrap()
            .verification_key_field_element_count(),
        4
    );
    assert_eq!(
        inventory.record(258_300).unwrap(),
        PreparationHolderRecord {
            global_ordinal: 258_300,
            coordinate: PreparationHolderRecordCoordinate::ConjunctionRowBit {
                conjunction_ordinal: 0,
                circuit_operation_position: first_conjunction.0,
                output_wire: first_conjunction.1,
                left_wire: first_conjunction.2,
                right_wire: first_conjunction.3,
                input_value_code: 0,
                holder_position: 0,
            },
        }
    );
    assert_eq!(
        inventory.record(475_179).unwrap(),
        PreparationHolderRecord {
            global_ordinal: 475_179,
            coordinate: PreparationHolderRecordCoordinate::ConjunctionRowBit {
                conjunction_ordinal: 5_421,
                circuit_operation_position: final_conjunction.0,
                output_wire: final_conjunction.1,
                left_wire: final_conjunction.2,
                right_wire: final_conjunction.3,
                input_value_code: 3,
                holder_position: 9,
            },
        }
    );
    assert_eq!(
        inventory.record(475_180).unwrap().coordinate,
        PreparationHolderRecordCoordinate::OutputMask {
            output_position: 0,
            output_kind: PreparationHolderOutputKind::PublicNonempty,
            output_wire: circuit.nonempty_output_wire(),
            holder_position: 0,
        }
    );
    assert_eq!(
        inventory.record(475_590),
        Err(
            TallyPreparationError::PreparationHolderRecordIndexOutOfRange {
                record_index: 475_590,
                record_count: 475_590,
            }
        )
    );
}

#[test]
fn every_admitted_shape_has_exact_record_family_boundaries_without_materialization() {
    for participant_count in
        MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT..=MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT
    {
        for option_count in MINIMUM_CONFIGURABLE_OPTION_COUNT..=MAXIMUM_CONFIGURABLE_OPTION_COUNT {
            for top_count in 1..=option_count {
                let circuit = CompiledTallyCircuit::compile(
                    TallyCircuitProfile::new(participant_count, option_count, top_count).unwrap(),
                )
                .unwrap();
                let resources = GarbledTallyResourceLowerBound::derive(&circuit).unwrap();
                let inventory = PreparationHolderRecordInventory::derive(
                    context(u8::try_from(top_count).unwrap(), &circuit),
                    &circuit,
                )
                .unwrap();
                let class_counts = inventory.record_class_counts();
                assert_eq!(
                    class_counts.iter().copied().sum::<u64>(),
                    resources.total_share_record_count
                );
                assert_eq!(inventory.record_count(), resources.total_share_record_count);
                assert_eq!(
                    inventory.value_field_element_count(),
                    resources.total_share_value_field_element_count
                );
                assert_eq!(
                    inventory.verification_key_field_element_count(),
                    resources.dkac_verification_key_field_element_count
                );
                assert_eq!(
                    inventory.records().len(),
                    usize::try_from(resources.total_share_record_count).unwrap()
                );

                let expected_classes = [
                    PreparationHolderRecordClass::InputMask,
                    PreparationHolderRecordClass::InputLabelBody,
                    PreparationHolderRecordClass::ConjunctionRowBit,
                    PreparationHolderRecordClass::PublicOutputMask,
                    PreparationHolderRecordClass::PrivateOutputMask,
                ];
                let mut class_start = 0_u64;
                for (class_count, expected_class) in class_counts.into_iter().zip(expected_classes)
                {
                    assert!(class_count > 0);
                    assert_eq!(
                        inventory.record(class_start).unwrap().class(),
                        expected_class
                    );
                    assert_eq!(
                        inventory
                            .record(class_start + class_count - 1)
                            .unwrap()
                            .class(),
                        expected_class
                    );
                    class_start += class_count;
                }
                assert_eq!(class_start, inventory.record_count());
            }
        }
    }
}

#[test]
fn identities_bind_context_profile_and_canonical_catalog_source() {
    let completion_circuit = completion_profile_circuit();
    let first = PreparationHolderRecordCatalog::derive(
        context(0x51, &completion_circuit),
        &completion_circuit,
    )
    .unwrap();
    let changed_context = PreparationHolderRecordCatalog::derive(
        context(0x52, &completion_circuit),
        &completion_circuit,
    )
    .unwrap();
    let alternate_circuit = CompiledTallyCircuit::compile(
        TallyCircuitProfile::new(
            MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT,
            MINIMUM_CONFIGURABLE_OPTION_COUNT,
            1,
        )
        .unwrap(),
    )
    .unwrap();
    let changed_profile = PreparationHolderRecordCatalog::derive(
        context(0x51, &alternate_circuit),
        &alternate_circuit,
    )
    .unwrap();

    assert_ne!(first.identity(), changed_context.identity());
    assert_ne!(first.identity(), changed_profile.identity());
    let source_identity = compiler_identity_from_source_for_test(b"canonical source\n").unwrap();
    let changed_source_identity =
        compiler_identity_from_source_for_test(b"changed canonical source\n").unwrap();
    assert_ne!(source_identity, changed_source_identity);
    for malformed_source in [
        b"carriage return\r\n".as_slice(),
        b"missing final line feed".as_slice(),
        &[
            0xef, 0xbb, 0xbf, b'c', b'a', b'n', b'o', b'n', b'i', b'c', b'a', b'l', b'\n',
        ],
        &[0xff, b'\n'],
    ] {
        assert_eq!(
            compiler_identity_from_source_for_test(malformed_source),
            Err(TallyPreparationError::NonCanonicalPreparationSourceEncoding)
        );
    }
}

fn assert_next_record(
    records: &mut PreparationHolderRecordIter<'_>,
    expected_ordinal: &mut u64,
    expected_coordinate: PreparationHolderRecordCoordinate,
) {
    let record = records
        .next()
        .expect("expected holder record")
        .expect("holder record should derive");
    assert_eq!(record.global_ordinal, *expected_ordinal);
    assert_eq!(record.coordinate, expected_coordinate);
    let expected_value_field_element_count = if matches!(
        expected_coordinate,
        PreparationHolderRecordCoordinate::InputLabelBody { .. }
    ) {
        3
    } else {
        1
    };
    assert_eq!(
        record.value_field_element_count(),
        expected_value_field_element_count
    );
    assert_eq!(
        record.verification_key_field_element_count(),
        expected_value_field_element_count + 1
    );
    *expected_ordinal += 1;
}

fn completion_conjunctions(
    circuit: &CompiledTallyCircuit,
) -> Vec<(u64, WireIndex, WireIndex, WireIndex)> {
    let input_wire_count = u64::try_from(circuit.geometry().input_bit_count).unwrap();
    circuit
        .operations()
        .iter()
        .enumerate()
        .filter_map(|(operation_position, operation)| {
            let BooleanOperation::Conjunction {
                left_wire,
                right_wire,
            } = operation
            else {
                return None;
            };
            let operation_position = u64::try_from(operation_position).unwrap();
            Some((
                operation_position,
                WireIndex::try_from(input_wire_count + operation_position).unwrap(),
                *left_wire,
                *right_wire,
            ))
        })
        .collect()
}

fn class_position(record_class: PreparationHolderRecordClass) -> usize {
    match record_class {
        PreparationHolderRecordClass::InputMask => 0,
        PreparationHolderRecordClass::InputLabelBody => 1,
        PreparationHolderRecordClass::ConjunctionRowBit => 2,
        PreparationHolderRecordClass::PublicOutputMask => 3,
        PreparationHolderRecordClass::PrivateOutputMask => 4,
    }
}

fn context(marker: u8, circuit: &CompiledTallyCircuit) -> TallyPreparationContext {
    TallyPreparationContext::new(
        Hash512::from_bytes([0x31; Hash512::BYTE_LENGTH]),
        Hash512::from_bytes([0x42; Hash512::BYTE_LENGTH]),
        [marker; 32],
        circuit,
    )
    .unwrap()
}

fn completion_profile_circuit() -> CompiledTallyCircuit {
    CompiledTallyCircuit::compile(
        TallyCircuitProfile::new(
            FOUNDATION_PROFILE.participant_count,
            FOUNDATION_PROFILE.option_count,
            FOUNDATION_PROFILE.option_count,
        )
        .unwrap(),
    )
    .unwrap()
}
