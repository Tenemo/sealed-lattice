use crate::{
    foundation::{
        FOUNDATION_PROFILE, MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT,
        MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT, derive_foundation_roster_parameters,
    },
    tally_preparation::output_sharing::canonical_evaluation_point,
};

use super::{
    BinaryFieldElement256,
    replicated_random_sharing::{
        BinaryFieldPolynomial, CanonicalPolynomialConsistencyVerifier,
        ReplicatedRandomSharingGeometry, ReplicatedRandomSharingSubset,
    },
};

#[test]
fn completion_profile_reproduces_the_replicated_key_geometry() {
    let geometry =
        ReplicatedRandomSharingGeometry::derive(FOUNDATION_PROFILE.participant_count).unwrap();

    assert_eq!(
        geometry,
        ReplicatedRandomSharingGeometry {
            participant_count: 10,
            active_fault_bound: 3,
            authorized_subset_size: 7,
            authorized_subset_count: 120,
            authorized_subset_count_per_participant: 84,
            random_sharing_key_count_per_subset: 1,
            zero_sharing_key_count_per_subset: 3,
            total_key_count: 480,
            key_count_per_participant: 336,
            key_byte_length: 64,
            all_member_contribution_count: 3_360,
            remote_key_component_delivery_count: 20_160,
            remote_key_component_byte_length: 1_290_240,
        }
    );
    assert_eq!(
        geometry
            .field_outputs_per_participant_for_one_triple()
            .unwrap(),
        504
    );
}

#[test]
fn every_admitted_roster_uses_the_normative_fault_formula_and_exact_subset_counts() {
    for participant_count in
        MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT..=MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT
    {
        let roster_parameters = derive_foundation_roster_parameters(participant_count).unwrap();
        let geometry = ReplicatedRandomSharingGeometry::derive(participant_count).unwrap();

        assert_eq!(
            geometry.active_fault_bound,
            u64::from(roster_parameters.active_fault_bound)
        );
        assert_eq!(
            geometry.authorized_subset_size,
            u64::from(participant_count - roster_parameters.active_fault_bound)
        );
        assert!(geometry.participant_count > 3 * geometry.active_fault_bound);
        assert_eq!(
            geometry.total_key_count,
            geometry.authorized_subset_count * (geometry.active_fault_bound + 1)
        );
        assert_eq!(
            geometry.key_count_per_participant,
            geometry.authorized_subset_count_per_participant * (geometry.active_fault_bound + 1)
        );
        assert_eq!(
            geometry.remote_key_component_byte_length,
            geometry.remote_key_component_delivery_count * geometry.key_byte_length
        );
    }
}

#[test]
fn every_completion_corruption_set_has_one_unknown_random_basis_and_a_full_zero_basis() {
    let participant_count = FOUNDATION_PROFILE.participant_count;
    let active_fault_bound = FOUNDATION_PROFILE.active_fault_bound;
    let subsets = ReplicatedRandomSharingSubset::all(participant_count).unwrap();
    assert_eq!(subsets.len(), 120);

    for subset in subsets {
        let excluded_positions = subset.excluded_positions();
        assert_eq!(excluded_positions.len(), usize::from(active_fault_bound));
        let random_polynomial = subset
            .random_sharing_polynomial(field_element(0x9d))
            .unwrap();
        assert_eq!(random_polynomial.degree(), usize::from(active_fault_bound));
        assert_eq!(
            random_polynomial.evaluate(BinaryFieldElement256::ZERO),
            field_element(0x9d)
        );

        for excluded_position in &excluded_positions {
            let evaluation_point =
                canonical_evaluation_point(participant_count, *excluded_position).unwrap();
            assert_eq!(
                random_polynomial.evaluate(evaluation_point),
                BinaryFieldElement256::ZERO
            );
            assert!(!subset.contains(*excluded_position).unwrap());
        }

        for basis_position in 0..active_fault_bound {
            let mut zero_components =
                vec![BinaryFieldElement256::ZERO; usize::from(active_fault_bound)];
            zero_components[usize::from(basis_position)] = BinaryFieldElement256::ONE;
            let zero_polynomial = subset.zero_sharing_polynomial(&zero_components).unwrap();
            assert_eq!(
                zero_polynomial.degree(),
                usize::from(active_fault_bound + basis_position + 1)
            );
            assert_eq!(
                zero_polynomial.evaluate(BinaryFieldElement256::ZERO),
                BinaryFieldElement256::ZERO
            );
            assert_eq!(
                zero_polynomial.coefficient(usize::from(active_fault_bound + basis_position + 1)),
                BinaryFieldElement256::ONE
            );
            for excluded_position in &excluded_positions {
                assert_eq!(
                    zero_polynomial.evaluate(
                        canonical_evaluation_point(participant_count, *excluded_position).unwrap()
                    ),
                    BinaryFieldElement256::ZERO
                );
            }
        }
    }
}

#[test]
fn local_subset_evaluation_matches_the_global_polynomial_for_every_participant() {
    let participant_count = FOUNDATION_PROFILE.participant_count;
    for (subset_position, subset) in ReplicatedRandomSharingSubset::all(participant_count)
        .unwrap()
        .into_iter()
        .enumerate()
    {
        let random_polynomial = subset
            .random_sharing_polynomial(field_element(u16::try_from(subset_position + 1).unwrap()))
            .unwrap();
        let zero_polynomial = subset
            .zero_sharing_polynomial(&[
                field_element(u16::try_from(subset_position + 2).unwrap()),
                field_element(u16::try_from(subset_position + 3).unwrap()),
                field_element(u16::try_from(subset_position + 4).unwrap()),
            ])
            .unwrap();

        for roster_position in 0..participant_count {
            let evaluation_point =
                canonical_evaluation_point(participant_count, roster_position).unwrap();
            if subset.contains(roster_position).unwrap() {
                assert_ne!(
                    random_polynomial.evaluate(evaluation_point),
                    BinaryFieldElement256::ZERO
                );
            } else {
                assert_eq!(
                    random_polynomial.evaluate(evaluation_point),
                    BinaryFieldElement256::ZERO
                );
                assert_eq!(
                    zero_polynomial.evaluate(evaluation_point),
                    BinaryFieldElement256::ZERO
                );
            }
        }
    }
}

#[test]
fn masked_degree_reduction_produces_correct_triples_for_every_static_corruption_set() {
    let participant_count = FOUNDATION_PROFILE.participant_count;
    for (subset_position, honest_subset) in ReplicatedRandomSharingSubset::all(participant_count)
        .unwrap()
        .into_iter()
        .enumerate()
    {
        let position = u16::try_from(subset_position).unwrap();
        let left = honest_subset
            .random_sharing_polynomial(field_element(position.wrapping_add(0x101)))
            .unwrap()
            .add(&polynomial_with_position_offset(position, 0x31));
        let right = honest_subset
            .random_sharing_polynomial(field_element(position.wrapping_add(0x202)))
            .unwrap()
            .add(&polynomial_with_position_offset(position, 0x53));
        let degree_reduction_mask = honest_subset
            .random_sharing_polynomial(field_element(position.wrapping_add(0x303)))
            .unwrap()
            .add(&polynomial_with_position_offset(position, 0x79));
        let zero_mask = honest_subset
            .zero_sharing_polynomial(&[
                field_element(position.wrapping_add(0x401)),
                field_element(position.wrapping_add(0x502)),
                field_element(position.wrapping_add(0x603)),
            ])
            .unwrap();

        let opened_polynomial = left
            .multiply(&right)
            .add(&degree_reduction_mask)
            .add(&zero_mask);
        assert!(opened_polynomial.degree() <= 6);
        let opened_constant = opened_polynomial.evaluate(BinaryFieldElement256::ZERO);
        assert_eq!(
            opened_constant,
            left.evaluate(BinaryFieldElement256::ZERO)
                .multiply(right.evaluate(BinaryFieldElement256::ZERO))
                .add(degree_reduction_mask.evaluate(BinaryFieldElement256::ZERO))
        );

        let product_sharing =
            degree_reduction_mask.add(&BinaryFieldPolynomial::constant(opened_constant));
        assert!(product_sharing.degree() <= 3);
        assert_eq!(
            product_sharing.evaluate(BinaryFieldElement256::ZERO),
            left.evaluate(BinaryFieldElement256::ZERO)
                .multiply(right.evaluate(BinaryFieldElement256::ZERO))
        );
    }
}

#[test]
fn all_ten_consistency_rejects_each_corrupt_degree_reduction_share_mutation() {
    let participant_count = FOUNDATION_PROFILE.participant_count;
    let verifier = CanonicalPolynomialConsistencyVerifier::new(participant_count, 6).unwrap();
    let honest_subset =
        ReplicatedRandomSharingSubset::from_excluded_positions(participant_count, &[0, 4, 9])
            .unwrap();
    let opened_polynomial = honest_subset
        .random_sharing_polynomial(field_element(0x17))
        .unwrap()
        .multiply(
            &honest_subset
                .random_sharing_polynomial(field_element(0x29))
                .unwrap(),
        )
        .add(
            &honest_subset
                .random_sharing_polynomial(field_element(0x3b))
                .unwrap(),
        )
        .add(
            &honest_subset
                .zero_sharing_polynomial(&[
                    field_element(0x4d),
                    field_element(0x5f),
                    field_element(0x71),
                ])
                .unwrap(),
        );
    let values = canonical_values(participant_count, &opened_polynomial);
    assert_eq!(
        verifier.interpolate_and_verify(&values).unwrap().unwrap(),
        opened_polynomial
    );

    for corrupt_position in [0_usize, 4, 9] {
        let mut changed_values = values.clone();
        changed_values[corrupt_position] =
            changed_values[corrupt_position].add(BinaryFieldElement256::ONE);
        assert!(
            verifier
                .interpolate_and_verify(&changed_values)
                .unwrap()
                .is_none()
        );
    }
}

fn polynomial_with_position_offset(position: u16, offset: u16) -> BinaryFieldPolynomial {
    BinaryFieldPolynomial::new(vec![
        field_element(position.wrapping_add(offset)),
        field_element(position.wrapping_add(offset + 1)),
        field_element(position.wrapping_add(offset + 2)),
        field_element(position.wrapping_add(offset + 3)),
    ])
}

fn canonical_values(
    participant_count: u16,
    polynomial: &BinaryFieldPolynomial,
) -> Vec<BinaryFieldElement256> {
    (0..participant_count)
        .map(|roster_position| {
            polynomial
                .evaluate(canonical_evaluation_point(participant_count, roster_position).unwrap())
        })
        .collect()
}

fn field_element(value: u16) -> BinaryFieldElement256 {
    BinaryFieldElement256::from_low_polynomial_u16(value)
}
