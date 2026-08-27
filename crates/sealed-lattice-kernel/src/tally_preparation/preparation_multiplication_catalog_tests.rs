use crate::{
    foundation::{
        FOUNDATION_PROFILE, Hash512, MAXIMUM_CONFIGURABLE_OPTION_COUNT,
        MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT, MINIMUM_CONFIGURABLE_OPTION_COUNT,
        MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT,
    },
    hashing::{hash_framed_parts_512, to_hex},
    tally_circuit::{CompiledTallyCircuit, TallyCircuitProfile},
};

use super::{
    TallyPreparationContext, TallyPreparationError,
    preparation_arithmetic_graph::PreparationMultiplicationFamily,
    preparation_multiplication_catalog::{
        PreparationMultiplicationCatalog, PreparationMultiplicationCoordinate,
        PreparationMultiplicationInventory, PreparationOutputKind,
        compiler_identity_from_source_for_test,
    },
};

const CATALOG_IDENTITY_DOMAIN: &str =
    "sealed-lattice/preparation-multiplication-catalog-identity/v1";

#[test]
fn completion_catalog_streams_every_multiplication_in_dependency_order() {
    let circuit = completion_profile_circuit();
    let catalog = PreparationMultiplicationCatalog::derive(context(0x33, &circuit), &circuit)
        .expect("completion catalog should derive");

    assert_eq!(catalog.operation_count(), 730_764);
    assert_eq!(catalog.operations().len(), 730_764);
    assert_eq!(catalog.operation_stream_byte_length(), 10_423_410);
    assert_eq!(catalog.artifact_byte_length(), 10_423_746);

    let mut family_counts = [0_u64; 7];
    let mut next_layer_positions = [0_u64; 2];
    let mut materialized_artifact = catalog.canonical_header_bytes();
    for (expected_ordinal, operation) in catalog.operations().enumerate() {
        let operation = operation.expect("canonical operation should derive");
        assert_eq!(operation.global_ordinal, expected_ordinal as u64);
        let layer_position = usize::from(operation.multiplicative_layer - 1);
        assert_eq!(
            operation.position_within_layer,
            next_layer_positions[layer_position]
        );
        next_layer_positions[layer_position] += 1;
        family_counts[family_position(operation.family())] += 1;
        match operation.coordinate {
            PreparationMultiplicationCoordinate::RowOffsetLimbProduct {
                conjunction_ordinal,
                conjunction_mask_product_ordinal,
                ..
            }
            | PreparationMultiplicationCoordinate::RowBitShareTagProduct {
                conjunction_ordinal,
                conjunction_mask_product_ordinal,
                ..
            } => {
                assert!(conjunction_mask_product_ordinal < operation.global_ordinal);
                assert_eq!(
                    catalog
                        .operation(conjunction_mask_product_ordinal)
                        .expect("dependency should exist")
                        .coordinate,
                    conjunction_coordinate(&catalog, conjunction_ordinal)
                );
            }
            _ => {}
        }
        materialized_artifact.extend(operation.canonical_bytes());
    }

    assert_eq!(next_layer_positions, [256_844, 473_920]);
    assert_eq!(
        family_counts,
        [3_372, 2_962, 246_000, 4_100, 410, 355_440, 118_480]
    );
    assert_eq!(
        materialized_artifact.len() as u64,
        catalog.artifact_byte_length()
    );
    assert_eq!(
        materialized_artifact.len() as u64 - catalog.canonical_header_bytes().len() as u64,
        catalog.operation_stream_byte_length()
    );
    assert_eq!(
        catalog.identity().as_bytes(),
        &hash_framed_parts_512(CATALOG_IDENTITY_DOMAIN, &[&materialized_artifact])
    );
    assert_eq!(
        to_hex(catalog.identity().as_bytes()),
        "e72a01560a991330664840b927b5e8597f10fd21e7c10fde8458e4a08600c845b38433bf287cbae6bbf29edaf5c3e8056c51e78be75bf7beabf7e63b8cc840da"
    );
}

#[test]
fn completion_catalog_boundaries_bind_exact_wires_rows_holders_and_outputs() {
    let circuit = completion_profile_circuit();
    let inventory = PreparationMultiplicationInventory::derive(context(0x33, &circuit), &circuit)
        .expect("completion inventory should derive");

    assert_eq!(
        inventory.operation(0).unwrap().coordinate,
        PreparationMultiplicationCoordinate::SemanticMaskBitness { wire_index: 0 }
    );
    assert!(matches!(
        inventory.operation(3_371).unwrap().coordinate,
        PreparationMultiplicationCoordinate::SemanticMaskBitness { .. }
    ));
    assert!(matches!(
        inventory.operation(3_372).unwrap().coordinate,
        PreparationMultiplicationCoordinate::ConjunctionMaskProduct {
            conjunction_ordinal: 0,
            ..
        }
    ));
    assert_eq!(
        inventory.operation(6_334).unwrap().coordinate,
        PreparationMultiplicationCoordinate::LabelShareTagLimbProduct {
            input_wire: 0,
            label_alternative: 0,
            label_component_position: 0,
            holder_position: 0,
            limb_position: 0,
        }
    );
    assert_eq!(
        inventory.operation(252_334).unwrap().coordinate,
        PreparationMultiplicationCoordinate::InputMaskShareTagProduct {
            input_wire: 0,
            holder_position: 0,
        }
    );
    assert_eq!(
        inventory.operation(256_434).unwrap().coordinate,
        PreparationMultiplicationCoordinate::OutputMaskShareTagProduct {
            output_position: 0,
            output_kind: PreparationOutputKind::PublicNonempty,
            output_wire: circuit.nonempty_output_wire(),
            holder_position: 0,
        }
    );
    assert_eq!(
        inventory.operation(256_843).unwrap().coordinate,
        PreparationMultiplicationCoordinate::OutputMaskShareTagProduct {
            output_position: 40,
            output_kind: PreparationOutputKind::PrivateResult {
                result_bit_position: 39,
            },
            output_wire: *circuit
                .ordered_option_position_wires()
                .iter()
                .flatten()
                .last()
                .unwrap(),
            holder_position: 9,
        }
    );
    assert_eq!(
        inventory.operation(256_844).unwrap(),
        super::preparation_multiplication_catalog::PreparationMultiplicationOperation {
            global_ordinal: 256_844,
            multiplicative_layer: 2,
            position_within_layer: 0,
            coordinate: PreparationMultiplicationCoordinate::RowOffsetLimbProduct {
                conjunction_ordinal: 0,
                input_value_code: 0,
                garbling_contributor_position: 0,
                limb_position: 0,
                conjunction_mask_product_ordinal: 3_372,
            },
        }
    );
    assert_eq!(
        inventory.operation(730_763).unwrap(),
        super::preparation_multiplication_catalog::PreparationMultiplicationOperation {
            global_ordinal: 730_763,
            multiplicative_layer: 2,
            position_within_layer: 473_919,
            coordinate: PreparationMultiplicationCoordinate::RowBitShareTagProduct {
                conjunction_ordinal: 2_961,
                input_value_code: 3,
                holder_position: 9,
                conjunction_mask_product_ordinal: 6_333,
            },
        }
    );
    assert_eq!(
        inventory.operation(730_764),
        Err(
            TallyPreparationError::PreparationMultiplicationIndexOutOfRange {
                operation_index: 730_764,
                operation_count: 730_764,
            }
        )
    );
}

#[test]
fn every_admitted_shape_has_exact_family_boundaries_without_materializing_the_catalog() {
    for participant_count in
        MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT..=MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT
    {
        for option_count in MINIMUM_CONFIGURABLE_OPTION_COUNT..=MAXIMUM_CONFIGURABLE_OPTION_COUNT {
            for top_count in 1..=option_count {
                let circuit = CompiledTallyCircuit::compile(
                    TallyCircuitProfile::new(participant_count, option_count, top_count).unwrap(),
                )
                .unwrap();
                let inventory = PreparationMultiplicationInventory::derive(
                    context(top_count as u8, &circuit),
                    &circuit,
                )
                .unwrap();
                let graph = inventory.graph();
                assert_eq!(
                    inventory.operation_count(),
                    graph.total_multiplication_count
                );
                assert_eq!(
                    inventory.operations().len(),
                    usize::try_from(graph.total_multiplication_count).unwrap()
                );

                let family_counts = [
                    graph.mask_bitness_multiplication_count,
                    graph.mask_product_multiplication_count,
                    graph.label_share_tag_multiplication_count,
                    graph.input_mask_share_tag_multiplication_count,
                    graph.output_mask_share_tag_multiplication_count,
                    graph.row_offset_limb_multiplication_count,
                    graph.row_bit_share_tag_multiplication_count,
                ];
                let expected_families = [
                    PreparationMultiplicationFamily::SemanticMaskBitness,
                    PreparationMultiplicationFamily::ConjunctionMaskProduct,
                    PreparationMultiplicationFamily::LabelShareTagLimbProduct,
                    PreparationMultiplicationFamily::InputMaskShareTagProduct,
                    PreparationMultiplicationFamily::OutputMaskShareTagProduct,
                    PreparationMultiplicationFamily::RowOffsetLimbProduct,
                    PreparationMultiplicationFamily::RowBitShareTagProduct,
                ];
                let mut family_start = 0_u64;
                for (family_count, expected_family) in
                    family_counts.into_iter().zip(expected_families)
                {
                    assert!(family_count > 0);
                    assert_eq!(
                        inventory.operation(family_start).unwrap().family(),
                        expected_family
                    );
                    assert_eq!(
                        inventory
                            .operation(family_start + family_count - 1)
                            .unwrap()
                            .family(),
                        expected_family
                    );
                    family_start += family_count;
                }
                assert_eq!(family_start, inventory.operation_count());
            }
        }
    }
}

#[test]
fn identities_bind_context_profile_and_canonical_catalog_source() {
    let completion_circuit = completion_profile_circuit();
    let first = PreparationMultiplicationCatalog::derive(
        context(0x33, &completion_circuit),
        &completion_circuit,
    )
    .unwrap();
    let changed_context = PreparationMultiplicationCatalog::derive(
        context(0x34, &completion_circuit),
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
    let changed_profile = PreparationMultiplicationCatalog::derive(
        context(0x33, &alternate_circuit),
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

fn conjunction_coordinate(
    catalog: &PreparationMultiplicationCatalog,
    conjunction_ordinal: u64,
) -> PreparationMultiplicationCoordinate {
    match catalog
        .operation(3_372 + conjunction_ordinal)
        .expect("conjunction operation should exist")
        .coordinate
    {
        coordinate @ PreparationMultiplicationCoordinate::ConjunctionMaskProduct { .. } => {
            coordinate
        }
        other => panic!("expected conjunction dependency, received {other:?}"),
    }
}

fn family_position(family: PreparationMultiplicationFamily) -> usize {
    match family {
        PreparationMultiplicationFamily::SemanticMaskBitness => 0,
        PreparationMultiplicationFamily::ConjunctionMaskProduct => 1,
        PreparationMultiplicationFamily::LabelShareTagLimbProduct => 2,
        PreparationMultiplicationFamily::InputMaskShareTagProduct => 3,
        PreparationMultiplicationFamily::OutputMaskShareTagProduct => 4,
        PreparationMultiplicationFamily::RowOffsetLimbProduct => 5,
        PreparationMultiplicationFamily::RowBitShareTagProduct => 6,
    }
}

fn context(marker: u8, circuit: &CompiledTallyCircuit) -> TallyPreparationContext {
    TallyPreparationContext::new(
        Hash512::from_bytes([0x11; Hash512::BYTE_LENGTH]),
        Hash512::from_bytes([0x22; Hash512::BYTE_LENGTH]),
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
