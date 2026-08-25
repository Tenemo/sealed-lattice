use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use crate::{
    foundation::{
        CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalItem, CanonicalTuple,
        FOUNDATION_PROFILE, Hash512,
    },
    tally_circuit::{CompiledTallyCircuit, TallyCircuitProfile},
};

use super::{
    BinaryFieldElement256, TallyPreparationContext, TallyPreparationError,
    output_sharing::canonical_evaluation_point,
    replicated_key_ceremony::{
        ReplicatedRandomSharingKey, ReplicatedRandomSharingKeyCoordinate,
        ReplicatedRandomSharingKeyPurpose, combine_replicated_random_sharing_key,
        create_replicated_key_component,
    },
    replicated_random_bit_catalog::{ReplicatedRandomBitCatalog, ReplicatedRandomBitCoordinate},
    replicated_random_bit_sharing::ReplicatedRandomBitShareDeriver,
    replicated_random_bit_stream::{
        REPLICATED_RANDOM_BIT_STREAM_DOMAIN, generate_replicated_random_bit_chunk,
        replicated_random_bit_chunk_count, replicated_random_bit_chunk_preimage_byte_length,
    },
    replicated_random_sharing::{BinaryFieldPolynomial, ReplicatedRandomSharingSubset},
};

#[test]
fn completion_catalog_and_stream_match_the_independent_shake_query() {
    let circuit = completion_circuit();
    let context = context_for_circuit(&circuit, 19);
    let catalog = ReplicatedRandomBitCatalog::derive(context, &circuit).unwrap();
    assert_eq!(catalog.participant_count(), 10);
    assert_eq!(catalog.semantic_mask_bit_count(), 6_652);
    assert_eq!(
        catalog.additive_correlation_free_point_bit_count(),
        1_951_920
    );
    assert_eq!(catalog.total_bit_count(), 1_958_572);
    assert_eq!(catalog.output_byte_length_per_key(), 244_822);
    assert_eq!(catalog.unused_high_bit_count(), 4);
    assert_eq!(replicated_random_bit_chunk_count(&catalog).unwrap(), 1);

    let coordinate = random_coordinate(context);
    let key = combined_key(coordinate, 23);
    let chunk = generate_replicated_random_bit_chunk(&key, &catalog, 0).unwrap();
    assert_eq!(chunk.first_bit_index(), 0);
    assert_eq!(chunk.bit_count(), catalog.total_bit_count());
    assert_eq!(chunk.byte_length(), 244_822);

    let items = vec![
        CanonicalItem::fixed_bytes(key.as_bytes()).unwrap(),
        CanonicalItem::variable_bytes(coordinate.canonical_bytes()).unwrap(),
        CanonicalItem::fixed_bytes(catalog.identity().as_bytes()).unwrap(),
        CanonicalItem::unsigned16(catalog.participant_count()),
        CanonicalItem::unsigned64(catalog.semantic_mask_bit_count()),
        CanonicalItem::unsigned64(catalog.additive_correlation_free_point_bit_count()),
        CanonicalItem::unsigned64(catalog.total_bit_count()),
        CanonicalItem::unsigned64(0),
        CanonicalItem::unsigned64(0),
        CanonicalItem::unsigned64(catalog.total_bit_count()),
        CanonicalItem::unsigned64(catalog.output_byte_length_per_key()),
        CanonicalItem::unsigned16(u16::from(catalog.unused_high_bit_count())),
    ];
    let mut framed_items = Vec::with_capacity(items.len() + 1);
    framed_items.push(CanonicalItem::nonempty_ascii(REPLICATED_RANDOM_BIT_STREAM_DOMAIN).unwrap());
    framed_items.extend_from_slice(&items);
    let preimage = CanonicalTuple::new(
        CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
        CANONICAL_TUPLE_VERSION,
        framed_items,
    )
    .encode()
    .unwrap();
    let mut hasher = Shake256::default();
    hasher.update(&preimage);
    let mut expected_bytes = vec![0_u8; 244_822];
    hasher.finalize_xof().read(&mut expected_bytes);
    *expected_bytes.last_mut().unwrap() &= 0x0f;
    assert_eq!(chunk.bytes(), expected_bytes);
    assert_eq!(chunk.bytes().last().unwrap() & 0xf0, 0);
    assert_eq!(
        replicated_random_bit_chunk_preimage_byte_length(coordinate, &catalog, 0).unwrap(),
        preimage.len() as u64
    );
    assert!(matches!(
        chunk.bit(catalog.total_bit_count()),
        Err(TallyPreparationError::ReplicatedRandomBitPositionOutOfRange { .. })
    ));
}

#[test]
fn completion_catalog_assigns_every_logical_bit_one_round_trip_coordinate() {
    let circuit = completion_circuit();
    let context = context_for_circuit(&circuit, 29);
    let catalog = ReplicatedRandomBitCatalog::derive(context, &circuit).unwrap();

    assert_eq!(
        catalog.coordinate(0).unwrap(),
        ReplicatedRandomBitCoordinate::SemanticMask { wire_index: 0 }
    );
    assert_eq!(
        catalog.coordinate(1_229).unwrap(),
        ReplicatedRandomBitCoordinate::SemanticMask { wire_index: 1_229 }
    );
    assert_eq!(
        catalog.coordinate(6_652).unwrap(),
        ReplicatedRandomBitCoordinate::AdditiveCorrelationFreePoint {
            conjunction_ordinal: 0,
            input_value_code: 0,
            output_component_position: 0,
            free_garbling_contributor_position: 1,
        }
    );
    assert_eq!(
        catalog.coordinate(1_958_571).unwrap(),
        ReplicatedRandomBitCoordinate::AdditiveCorrelationFreePoint {
            conjunction_ordinal: 5_421,
            input_value_code: 3,
            output_component_position: 9,
            free_garbling_contributor_position: 8,
        }
    );

    for bit_index in 0..catalog.total_bit_count() {
        let coordinate = catalog.coordinate(bit_index).unwrap();
        assert_eq!(catalog.bit_index(coordinate).unwrap(), bit_index);
    }

    assert_eq!(
        catalog.coordinate(catalog.total_bit_count()),
        Err(TallyPreparationError::ReplicatedRandomBitIndexOutOfRange {
            bit_index: 1_958_572,
            total_bit_count: 1_958_572,
        })
    );
    for malformed_coordinate in [
        ReplicatedRandomBitCoordinate::SemanticMask { wire_index: 1_230 },
        ReplicatedRandomBitCoordinate::AdditiveCorrelationFreePoint {
            conjunction_ordinal: 5_422,
            input_value_code: 0,
            output_component_position: 0,
            free_garbling_contributor_position: 1,
        },
        ReplicatedRandomBitCoordinate::AdditiveCorrelationFreePoint {
            conjunction_ordinal: 0,
            input_value_code: 4,
            output_component_position: 0,
            free_garbling_contributor_position: 1,
        },
        ReplicatedRandomBitCoordinate::AdditiveCorrelationFreePoint {
            conjunction_ordinal: 0,
            input_value_code: 0,
            output_component_position: 4,
            free_garbling_contributor_position: 4,
        },
    ] {
        assert_eq!(
            catalog.bit_index(malformed_coordinate),
            Err(TallyPreparationError::ReplicatedRandomBitCoordinateMismatch)
        );
    }

    let other_context = context_for_circuit(&circuit, 30);
    let other_catalog = ReplicatedRandomBitCatalog::derive(other_context, &circuit).unwrap();
    assert_ne!(catalog.identity(), other_catalog.identity());
    assert_ne!(catalog.canonical_bytes(), other_catalog.canonical_bytes());
}

#[test]
fn maximum_shape_stream_uses_exact_full_and_partial_chunk_boundaries() {
    let circuit =
        CompiledTallyCircuit::compile(TallyCircuitProfile::new(20, 20, 20).unwrap()).unwrap();
    let context = context_for_circuit(&circuit, 31);
    let catalog = ReplicatedRandomBitCatalog::derive(context, &circuit).unwrap();
    let chunk_count = replicated_random_bit_chunk_count(&catalog).unwrap();
    assert!(chunk_count > 1);
    let key = combined_key(random_coordinate(context), 37);
    let first_chunk = generate_replicated_random_bit_chunk(&key, &catalog, 0).unwrap();
    assert_eq!(
        first_chunk.byte_length(),
        FOUNDATION_PROFILE.stream_chunk_byte_length
    );
    assert_eq!(
        first_chunk.bit_count(),
        u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length).unwrap() * 8
    );
    let final_chunk =
        generate_replicated_random_bit_chunk(&key, &catalog, chunk_count - 1).unwrap();
    assert!(final_chunk.byte_length() <= FOUNDATION_PROFILE.stream_chunk_byte_length);
    assert_eq!(
        final_chunk.first_bit_index() + final_chunk.bit_count(),
        catalog.total_bit_count()
    );
    assert!(matches!(
        generate_replicated_random_bit_chunk(&key, &catalog, chunk_count),
        Err(TallyPreparationError::ReplicatedRandomBitChunkOutOfRange { .. })
    ));
}

#[test]
fn stream_refuses_zero_sharing_keys_and_mixed_context_catalogs() {
    let circuit = completion_circuit();
    let context = context_for_circuit(&circuit, 41);
    let catalog = ReplicatedRandomBitCatalog::derive(context, &circuit).unwrap();
    let zero_coordinate = ReplicatedRandomSharingKeyCoordinate::all(context)
        .unwrap()
        .into_iter()
        .find(|coordinate| {
            matches!(
                coordinate.purpose(),
                ReplicatedRandomSharingKeyPurpose::DegreeDoubleZeroSharing { .. }
            )
        })
        .unwrap();
    let zero_key = combined_key(zero_coordinate, 43);
    assert!(matches!(
        generate_replicated_random_bit_chunk(&zero_key, &catalog, 0),
        Err(TallyPreparationError::ReplicatedRandomBitKeyPurposeMismatch)
    ));

    let other_context = context_for_circuit(&circuit, 47);
    let other_key = combined_key(random_coordinate(other_context), 53);
    assert!(matches!(
        generate_replicated_random_bit_chunk(&other_key, &catalog, 0),
        Err(TallyPreparationError::ReplicatedKeyCoordinateMismatch)
    ));
    assert!(matches!(
        ReplicatedRandomBitCatalog::derive(
            other_context,
            &CompiledTallyCircuit::compile(TallyCircuitProfile::new(10, 9, 9).unwrap()).unwrap()
        ),
        Err(TallyPreparationError::ReplicatedKeyCoordinateMismatch)
    ));
}

#[test]
fn every_participant_derivation_matches_the_independent_global_polynomial() {
    let participant_count = FOUNDATION_PROFILE.participant_count;
    let subset_bases = subset_bases(participant_count);
    for pattern_seed in [0_u16, 1, 0x35, 0xa7, 0xffff] {
        let component_bits = (0..subset_bases.len())
            .map(|subset_position| {
                ((u16::try_from(subset_position).unwrap().wrapping_mul(0x6d) ^ pattern_seed)
                    .count_ones()
                    & 1) as u8
            })
            .collect::<Vec<_>>();
        let global_polynomial = global_polynomial(&subset_bases, &component_bits);
        let expected_secret = component_bits
            .iter()
            .copied()
            .fold(0_u8, |parity, bit| parity ^ bit);
        assert!(global_polynomial.degree() <= usize::from(FOUNDATION_PROFILE.active_fault_bound));
        assert_eq!(
            global_polynomial.evaluate(BinaryFieldElement256::ZERO),
            BinaryFieldElement256::from_low_polynomial_u16(u16::from(expected_secret))
        );

        for roster_position in 0..participant_count {
            let deriver =
                ReplicatedRandomBitShareDeriver::new(participant_count, roster_position).unwrap();
            let member_bits = subset_bases
                .iter()
                .zip(&component_bits)
                .filter_map(|((subset, _basis), bit)| {
                    subset.contains(roster_position).unwrap().then_some(*bit)
                })
                .collect::<Vec<_>>();
            assert_eq!(member_bits.len(), deriver.component_count());
            assert_eq!(deriver.participant_count(), participant_count);
            assert_eq!(deriver.roster_position(), roster_position);
            assert_eq!(
                deriver.derive_share(&member_bits).unwrap(),
                global_polynomial.evaluate(
                    canonical_evaluation_point(participant_count, roster_position).unwrap()
                )
            );
        }
    }
}

#[test]
fn every_completion_corruption_complement_toggles_only_the_hidden_secret() {
    let participant_count = FOUNDATION_PROFILE.participant_count;
    let subset_bases = subset_bases(participant_count);
    let baseline_bits = (0..subset_bases.len())
        .map(|position| u8::from(position % 3 == 1 || position % 7 == 0))
        .collect::<Vec<_>>();
    let baseline_polynomial = global_polynomial(&subset_bases, &baseline_bits);

    for (hidden_subset_position, (hidden_subset, hidden_basis)) in subset_bases.iter().enumerate() {
        let mut changed_bits = baseline_bits.clone();
        changed_bits[hidden_subset_position] ^= 1;
        let changed_polynomial = global_polynomial(&subset_bases, &changed_bits);
        assert_eq!(changed_polynomial, baseline_polynomial.add(hidden_basis));
        assert_eq!(
            changed_polynomial
                .evaluate(BinaryFieldElement256::ZERO)
                .add(baseline_polynomial.evaluate(BinaryFieldElement256::ZERO)),
            BinaryFieldElement256::ONE
        );
        for corrupt_position in hidden_subset.excluded_positions() {
            let evaluation_point =
                canonical_evaluation_point(participant_count, corrupt_position).unwrap();
            assert_eq!(
                changed_polynomial.evaluate(evaluation_point),
                baseline_polynomial.evaluate(evaluation_point)
            );
        }
    }
}

#[test]
fn share_deriver_refuses_wrong_component_count_and_non_bit_values() {
    let deriver = ReplicatedRandomBitShareDeriver::new(10, 4).unwrap();
    assert_eq!(deriver.component_count(), 84);
    assert!(matches!(
        deriver.derive_share(&[0; 83]),
        Err(
            TallyPreparationError::ReplicatedRandomBitComponentCountMismatch {
                expected: 84,
                actual: 83,
            }
        )
    ));
    let mut components = vec![0_u8; 84];
    components[37] = 2;
    assert_eq!(
        deriver.derive_share(&components),
        Err(
            TallyPreparationError::ReplicatedRandomBitComponentNonCanonical {
                component_position: 37,
                value: 2,
            }
        )
    );
    assert!(matches!(
        ReplicatedRandomBitShareDeriver::new(10, 10),
        Err(TallyPreparationError::RosterPositionOutOfRange { .. })
    ));
}

fn subset_bases(
    participant_count: u16,
) -> Vec<(ReplicatedRandomSharingSubset, BinaryFieldPolynomial)> {
    ReplicatedRandomSharingSubset::all(participant_count)
        .unwrap()
        .into_iter()
        .map(|subset| {
            let basis = subset
                .random_sharing_polynomial(BinaryFieldElement256::ONE)
                .unwrap();
            (subset, basis)
        })
        .collect()
}

fn global_polynomial(
    subset_bases: &[(ReplicatedRandomSharingSubset, BinaryFieldPolynomial)],
    component_bits: &[u8],
) -> BinaryFieldPolynomial {
    assert_eq!(subset_bases.len(), component_bits.len());
    subset_bases.iter().zip(component_bits).fold(
        BinaryFieldPolynomial::zero(),
        |polynomial, ((_subset, basis), bit)| match bit {
            0 => polynomial,
            1 => polynomial.add(basis),
            _ => panic!("test component must be a bit"),
        },
    )
}

fn random_coordinate(context: TallyPreparationContext) -> ReplicatedRandomSharingKeyCoordinate {
    ReplicatedRandomSharingKeyCoordinate::all(context)
        .unwrap()
        .into_iter()
        .find(|coordinate| {
            matches!(
                coordinate.purpose(),
                ReplicatedRandomSharingKeyPurpose::RandomSharing
            )
        })
        .unwrap()
}

fn combined_key(
    coordinate: ReplicatedRandomSharingKeyCoordinate,
    seed: u8,
) -> ReplicatedRandomSharingKey {
    let mut commitments = Vec::new();
    let mut openings = Vec::new();
    for contributor_position in coordinate.member_positions().unwrap() {
        let component = core::array::from_fn(|byte_position| {
            seed.wrapping_add((contributor_position as u8).wrapping_mul(29))
                .wrapping_add((byte_position as u8).wrapping_mul(13))
        });
        let (commitment, opening) =
            create_replicated_key_component(coordinate, contributor_position, component).unwrap();
        commitments.push(commitment);
        openings.push(opening);
    }
    combine_replicated_random_sharing_key(coordinate, &commitments, &openings).unwrap()
}

fn completion_circuit() -> CompiledTallyCircuit {
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

fn context_for_circuit(
    circuit: &CompiledTallyCircuit,
    attempt_byte: u8,
) -> TallyPreparationContext {
    TallyPreparationContext::new(
        Hash512::from_bytes([61_u8; 64]),
        Hash512::from_bytes([73_u8; 64]),
        [attempt_byte; 32],
        circuit,
    )
    .unwrap()
}
