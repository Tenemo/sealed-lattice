use super::*;

use std::collections::{BTreeMap, BTreeSet};

use num_traits::ToPrimitive;
use sha3::{Digest, Sha3_512};

use crate::bgv::{
    direct_ballots::PAIR_CHARACTER_LANE_COUNT,
    encoding::encode_scalar_lanes_to_plaintext_coefficients,
};

#[test]
fn selected_kllps_constants_match_the_spaced_monomial_construction() {
    assert_eq!(KLLPS_PARTICIPANT_COUNT, 10);
    assert_eq!(KLLPS_RECONSTRUCTION_THRESHOLD, 4);
    assert_eq!(KLLPS_DENOMINATOR_CLEARING_FACTOR, 4);
    assert_eq!(KLLPS_PAIRED_TARGET_ROLE_COUNT, 2);
    assert_eq!(KLLPS_POINT_STRIDE, POLYNOMIAL_DEGREE / 8);
    assert_eq!(KLLPS_SUBRING_DEGREE, 8);
}

#[test]
fn positive_bgv_conversion_scale_matches_the_selected_full_target_basis() {
    let selected_target_primes = &DATA_PRIMES[..=CANONICAL_TARGET_CIPHERTEXT_LEVEL];
    assert_eq!(selected_target_primes.len(), 8);
    for modulus in selected_target_primes.iter().copied() {
        assert_eq!(modulus % PLAINTEXT_MODULUS, 1);
        let conversion_scale = positive_bfv_message_conversion_scale(modulus)
            .expect("selected positive-message BGV conversion scale");
        assert_eq!(
            conversion_scale,
            (modulus - 1) / PLAINTEXT_MODULUS,
            "the BGV-to-BFV conversion must retain the positive plaintext sign",
        );
        assert_eq!(
            mul_mod_fast(conversion_scale, PLAINTEXT_MODULUS, modulus),
            modulus - 1,
            "the positive-message conversion scale must equal -p^-1 modulo q",
        );
    }
}

#[test]
fn canonical_target_decoding_returns_only_identifiers_in_rank_order() {
    let mut target_identifier_slots = vec![0_u64; 24];
    let mut target_order_slots = vec![0_u64; 24];
    for (option_index, order) in [(1_usize, 3_u64), (4, 1), (9, 4), (19, 2)] {
        target_identifier_slots[option_index] =
            u64::try_from(option_index + 1).expect("small test option identifier");
        target_order_slots[option_index] = order;
    }

    assert_eq!(
        canonical_ordered_option_identifiers(&target_identifier_slots, &target_order_slots, 4, 20,)
            .expect("canonical target roles decode"),
        vec![5, 20, 2, 10],
    );
}

#[test]
fn canonical_target_decoding_rejects_every_malformed_semantic_class() {
    let valid_slots = || {
        let mut target_identifier_slots = vec![0_u64; 24];
        let mut target_order_slots = vec![0_u64; 24];
        for (option_index, order) in [(1_usize, 3_u64), (4, 1), (9, 4), (19, 2)] {
            target_identifier_slots[option_index] =
                u64::try_from(option_index + 1).expect("small test option identifier");
            target_order_slots[option_index] = order;
        }
        (target_identifier_slots, target_order_slots)
    };

    let (identifiers, mut orders) = valid_slots();
    orders[1] = 0;
    assert!(canonical_ordered_option_identifiers(&identifiers, &orders, 4, 20).is_err());

    let (mut identifiers, orders) = valid_slots();
    identifiers[0] = 1;
    assert!(canonical_ordered_option_identifiers(&identifiers, &orders, 4, 20).is_err());

    let (mut identifiers, orders) = valid_slots();
    identifiers[1] = 3;
    assert!(canonical_ordered_option_identifiers(&identifiers, &orders, 4, 20).is_err());

    let (mut identifiers, orders) = valid_slots();
    identifiers[1] = PLAINTEXT_MODULUS - 1;
    assert!(canonical_ordered_option_identifiers(&identifiers, &orders, 4, 20).is_err());

    let (identifiers, mut orders) = valid_slots();
    orders[19] = 3;
    assert!(canonical_ordered_option_identifiers(&identifiers, &orders, 4, 20).is_err());

    let (identifiers, mut orders) = valid_slots();
    orders[19] = 5;
    assert!(canonical_ordered_option_identifiers(&identifiers, &orders, 4, 20).is_err());

    let (mut identifiers, mut orders) = valid_slots();
    identifiers[19] = 0;
    orders[19] = 0;
    assert!(canonical_ordered_option_identifiers(&identifiers, &orders, 4, 20).is_err());

    let (mut identifiers, orders) = valid_slots();
    identifiers[20] = 1;
    assert!(canonical_ordered_option_identifiers(&identifiers, &orders, 4, 20).is_err());

    let (identifiers, mut orders) = valid_slots();
    orders[23] = 1;
    assert!(canonical_ordered_option_identifiers(&identifiers, &orders, 4, 20).is_err());

    let (identifiers, orders) = valid_slots();
    assert!(canonical_ordered_option_identifiers(&identifiers, &orders, 0, 20).is_err());
    assert!(canonical_ordered_option_identifiers(&identifiers, &orders, 21, 20).is_err());
    assert!(
        canonical_ordered_option_identifiers(&identifiers[..19], &orders[..19], 4, 20).is_err()
    );
    assert!(canonical_ordered_option_identifiers(&identifiers, &orders[..23], 4, 20).is_err());
}

#[test]
fn selected_eight_prime_target_basis_satisfies_the_exact_factor_four_theorem_bounds() {
    use crate::bgv::evaluator::{
        noise_recurrence::direct_ballot_target_noise_bounds,
        top_k::CANONICAL_TARGET_CIPHERTEXT_LEVEL,
    };

    let expected_target_primes = [
        1_953_759_233,
        2_256_928_769,
        2_408_513_537,
        2_610_626_561,
        2_661_154_817,
        3_014_852_609,
        3_031_695_361,
        3_368_550_401,
    ];
    assert_eq!(CANONICAL_TARGET_CIPHERTEXT_LEVEL, 7);
    assert_eq!(
        &DATA_PRIMES[..=CANONICAL_TARGET_CIPHERTEXT_LEVEL],
        &expected_target_primes,
    );

    let target_bounds = direct_ballot_target_noise_bounds(10, 10, 20, 1, 10)
        .expect("the selected evaluator has an exact symbolic target bound");
    let evaluation_error_bound = target_bounds
        .iter()
        .map(|bound| bound.maximum_error_coefficient_bound())
        .max()
        .cloned()
        .expect("the selected evaluator has at least one target");
    assert_eq!(
        evaluation_error_bound.to_str_radix(10),
        "16870171037775988578755335442628",
    );

    let flooding_bound = factor_four_required_flooding_bound(&evaluation_error_bound)
        .expect("the exact factor-four flooding bound is representable");
    assert_eq!(
        flooding_bound.to_str_radix(10),
        "350379744329557993497411231781118201360220160600365913688770609152",
    );
    ensure_factor_four_parameter_conditions(
        CANONICAL_TARGET_CIPHERTEXT_LEVEL,
        &evaluation_error_bound,
        &flooding_bound,
    )
    .expect("the selected eight-prime target basis satisfies C2 and C4");

    let target_modulus = expected_target_primes
        .into_iter()
        .map(BigUint::from)
        .product::<BigUint>();
    assert_eq!(
        target_modulus.to_str_radix(10),
        "2271682199083132530942007860211960213597483954489024377020137669658856718337",
    );

    let plaintext_modulus = BigUint::from(PLAINTEXT_MODULUS);
    let clearing_coefficient_norm = BigUint::from(KLLPS_DENOMINATOR_CLEARING_FACTOR);
    let independently_scaled_evaluation_term = &plaintext_modulus
        * BigUint::from(4_u8)
        * &clearing_coefficient_norm
        * &evaluation_error_bound;
    let independently_scaled_rounding_term = &plaintext_modulus
        * &plaintext_modulus
        * (&clearing_coefficient_norm + BigUint::from(1_u8));
    let independently_scaled_flooding_term = &plaintext_modulus
        * BigUint::from(4_u64 * KLLPS_RECONSTRUCTION_THRESHOLD as u64)
        * &flooding_bound
        * BigUint::from(MAXIMUM_AUTHORIZED_COEFFICIENT_NORM);
    let independently_scaled_c2_left = independently_scaled_evaluation_term
        + independently_scaled_rounding_term
        + independently_scaled_flooding_term;
    let scaled_c2_left = factor_four_scaled_c2_left(&evaluation_error_bound, &flooding_bound);
    assert_eq!(
        scaled_c2_left, independently_scaled_c2_left,
        "C2 must scale the converted ciphertext's unscaled evaluator error by ||Cdec||_1 = 4",
    );
    assert_eq!(
        scaled_c2_left.to_str_radix(10),
        "63393506382058268647499619343694154005072056524437869067723828113069637",
    );
    assert_eq!(
        ((&target_modulus << 1_usize) - scaled_c2_left).to_str_radix(10),
        "4543301004659883003615368220804576733040962836921524316171207615489600367037",
        "the exact C2 margin must remain positive",
    );
}

#[test]
fn factor_four_release_reconstructs_full_eight_prime_targets_from_lowest_distinct_participants() {
    let binding = test_release_binding(11);
    let participant_binding = test_participant_release_binding(11, 0);
    let sharing_polynomials = test_sharing_polynomials();
    let target_identifier_lanes = sparse_scalar_lanes(&[(0, 17), (19, 1), (97, 31)]);
    let target_order_lanes = sparse_scalar_lanes(&[(1, 9), (63, 44), (127, 7)]);
    let target_identifier_plaintext =
        encode_scalar_lanes_to_plaintext_coefficients(&target_identifier_lanes)
            .expect("encode target identifier lanes");
    let target_order_plaintext = encode_scalar_lanes_to_plaintext_coefficients(&target_order_lanes)
        .expect("encode target order lanes");
    let target_identifier = test_target_ciphertext(
        &target_identifier_plaintext,
        7,
        &sharing_polynomials[0],
        CANONICAL_TARGET_CIPHERTEXT_LEVEL,
        3,
    );
    let target_order = test_target_ciphertext(
        &target_order_plaintext,
        7,
        &sharing_polynomials[0],
        CANONICAL_TARGET_CIPHERTEXT_LEVEL,
        5,
    );
    let target_pair = KllpsTargetPair::from_verified_finality(
        binding.clone(),
        participant_binding,
        target_identifier,
        target_order,
    )
    .expect("valid finalized target pair");
    assert_eq!(target_pair.binding(), &binding);

    let flooding_bound = BigUint::from(16_u8);
    let mut shares_by_position = BTreeMap::new();
    for roster_position in [0, 1, 2, 3, 4, 5, 6, 9] {
        let producer_target_pair = KllpsTargetPair::from_verified_finality(
            binding.clone(),
            test_participant_release_binding(11, roster_position as u8),
            target_pair.target_identifier.clone(),
            target_pair.target_order.clone(),
        )
        .expect("participant-specific finalized target pair");
        let threshold_share =
            test_threshold_share(&sharing_polynomials, roster_position, target_pair.level());
        let target_identifier_error = test_flooding_error(roster_position, 1);
        let target_order_error = test_flooding_error(roster_position, 2);
        let partial = generate_factor_four_paired_partial_decryption(
            &producer_target_pair,
            roster_position,
            &threshold_share,
            &target_identifier_error,
            &target_order_error,
            &flooding_bound,
        )
        .expect("factor-four paired partial decryption");
        let verified =
            VerifiedKllpsPairedShare::from_common_proof_verifier(&producer_target_pair, partial)
                .expect("common-proof verified paired share");
        shares_by_position.insert(roster_position, verified);
    }

    let shuffled_positions = [9, 6, 5, 4, 3, 2, 1, 0];
    let shuffled = shuffled_positions
        .iter()
        .map(|position| &shares_by_position[position])
        .collect::<Vec<_>>();
    let reconstructed = reconstruct_factor_four_target_pair(&target_pair, &shuffled)
        .expect("lowest-position reconstruction");
    assert_eq!(
        reconstructed.target_identifier_coefficients,
        target_identifier_plaintext
    );
    assert_eq!(
        reconstructed.target_order_coefficients,
        target_order_plaintext
    );
    let (identifier_slots, order_slots) = reconstructed
        .decode_scalar_lanes()
        .expect("scalar target lanes");
    assert_eq!(identifier_slots, target_identifier_lanes);
    assert_eq!(order_slots, target_order_lanes);

    let ordered_positions = [0, 1, 2, 3, 4, 5, 6, 9];
    let ordered = ordered_positions
        .iter()
        .map(|position| &shares_by_position[position])
        .collect::<Vec<_>>();
    let ordered_reconstruction = reconstruct_factor_four_target_pair(&target_pair, &ordered)
        .expect("relay-order-independent reconstruction");
    assert_eq!(
        ordered_reconstruction, reconstructed,
        "all supplied verified shares must select the same four lowest roster positions regardless of relay order",
    );

    let alternate_quartet = [2, 3, 4, 5]
        .iter()
        .map(|position| &shares_by_position[position])
        .collect::<Vec<_>>();
    let alternate = reconstruct_factor_four_target_pair(&target_pair, &alternate_quartet)
        .expect("alternate authorized quartet reconstruction");
    assert_eq!(
        alternate.target_identifier_coefficients,
        target_identifier_plaintext
    );
    assert_eq!(alternate.target_order_coefficients, target_order_plaintext);

    let only_three = [0, 1, 2]
        .iter()
        .map(|position| &shares_by_position[position])
        .collect::<Vec<_>>();
    assert!(reconstruct_factor_four_target_pair(&target_pair, &only_three).is_err());
    let repeated = vec![
        &shares_by_position[&0],
        &shares_by_position[&1],
        &shares_by_position[&2],
        &shares_by_position[&2],
    ];
    assert!(reconstruct_factor_four_target_pair(&target_pair, &repeated).is_err());

    let threshold_share = test_threshold_share(&sharing_polynomials, 0, target_pair.level());
    let mut wrong_binding_partial = generate_factor_four_paired_partial_decryption(
        &target_pair,
        0,
        &threshold_share,
        &test_flooding_error(0, 1),
        &test_flooding_error(0, 2),
        &flooding_bound,
    )
    .expect("paired partial for binding rejection");
    wrong_binding_partial.binding.action_context_hash[0] ^= 1;
    assert!(
        VerifiedKllpsPairedShare::from_common_proof_verifier(&target_pair, wrong_binding_partial)
            .is_err()
    );
}

#[test]
fn factor_four_generation_and_reconstruction_reject_malformed_ring_inputs() {
    let binding = test_release_binding(23);
    let participant_binding = test_participant_release_binding(23, 0);
    let valid_component = vec![vec![0_u64; POLYNOMIAL_DEGREE]];
    let malformed_target = Ciphertext {
        components: vec![valid_component.clone()],
        level: 0,
        decrypt_scaling: 1,
    };
    let valid_target = Ciphertext {
        components: vec![valid_component.clone(), valid_component],
        level: 0,
        decrypt_scaling: 1,
    };
    for invalid_top_count in [0, FOUNDATION_PROFILE.option_count + 1] {
        assert!(
            KllpsReconstructionTargetPair::from_verified_finality(
                binding.clone(),
                invalid_top_count,
                valid_target.clone(),
                valid_target.clone(),
            )
            .is_err(),
            "reconstruction must retain only a verified action top count",
        );
    }
    assert!(
        KllpsTargetPair::from_verified_finality(
            binding.clone(),
            participant_binding.clone(),
            malformed_target,
            valid_target.clone(),
        )
        .is_err()
    );
    let mut differently_scaled_target = valid_target.clone();
    differently_scaled_target.decrypt_scaling = 2;
    assert!(
        KllpsTargetPair::from_verified_finality(
            binding.clone(),
            participant_binding.clone(),
            differently_scaled_target,
            valid_target.clone(),
        )
        .is_err(),
        "paired targets with different replay-derived scaling must refuse",
    );

    let target_pair = KllpsTargetPair::from_verified_finality(
        binding,
        participant_binding,
        valid_target.clone(),
        valid_target,
    )
    .expect("zero target is structurally valid");
    let flooding_bound = BigUint::from(5_u8);
    let valid_error = vec![BigInt::zero(); POLYNOMIAL_DEGREE];
    assert!(
        generate_factor_four_paired_partial_decryption(
            &target_pair,
            KLLPS_PARTICIPANT_COUNT,
            &[vec![0; POLYNOMIAL_DEGREE]],
            &valid_error,
            &valid_error,
            &flooding_bound,
        )
        .is_err()
    );
    assert!(
        generate_factor_four_paired_partial_decryption(
            &target_pair,
            0,
            &[vec![0; POLYNOMIAL_DEGREE - 1]],
            &valid_error,
            &valid_error,
            &flooding_bound,
        )
        .is_err()
    );
    let mut excessive_error = valid_error.clone();
    excessive_error[0] = BigInt::from(6_u8);
    assert!(
        generate_factor_four_paired_partial_decryption(
            &target_pair,
            0,
            &[vec![0; POLYNOMIAL_DEGREE]],
            &excessive_error,
            &valid_error,
            &flooding_bound,
        )
        .is_err()
    );
}

#[test]
fn paired_partial_streams_move_as_independent_fixed_role_buffers() {
    let selected_limb_count = CANONICAL_TARGET_CIPHERTEXT_LEVEL + 1;
    let target_identifier_by_limb = DATA_PRIMES
        .iter()
        .take(selected_limb_count)
        .map(|_| {
            (0..POLYNOMIAL_DEGREE)
                .map(|coefficient_ordinal| coefficient_ordinal as u64)
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let target_order_by_limb = DATA_PRIMES
        .iter()
        .take(selected_limb_count)
        .map(|_| {
            (0..POLYNOMIAL_DEGREE)
                .map(|coefficient_ordinal| (POLYNOMIAL_DEGREE - coefficient_ordinal - 1) as u64)
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let streams = KllpsPairedPartialDecryption {
        binding: test_release_binding(41),
        roster_position: 3,
        target_identifier_by_limb: target_identifier_by_limb.clone(),
        target_order_by_limb: target_order_by_limb.clone(),
    }
    .encode_streams()
    .expect("independent canonical role streams");
    let identifier_descriptor = streams
        .target_identifier_descriptor()
        .expect("identifier descriptor");
    let order_descriptor = streams.target_order_descriptor().expect("order descriptor");
    let (identifier_stream, order_stream) = streams.into_role_streams();

    assert_eq!(
        identifier_stream.role(),
        TargetPartialDecryptionRole::TargetIdentifier
    );
    assert_eq!(
        order_stream.role(),
        TargetPartialDecryptionRole::TargetOrder
    );
    assert_ne!(
        identifier_stream.canonical_bytes().as_ptr(),
        order_stream.canonical_bytes().as_ptr(),
        "the two role payloads must have independent custody",
    );
    assert!(
        identifier_stream.canonical_bytes().len()
            <= FOUNDATION_PROFILE.maximum_copied_buffer_byte_length
    );
    assert!(
        order_stream.canonical_bytes().len()
            <= FOUNDATION_PROFILE.maximum_copied_buffer_byte_length
    );
    let exact_role_stream_byte_length = size_of::<u16>()
        + selected_limb_count * (size_of::<u64>() + POLYNOMIAL_DEGREE * size_of::<u64>());
    assert_eq!(
        identifier_stream.canonical_bytes().len(),
        exact_role_stream_byte_length
    );
    assert_eq!(
        order_stream.canonical_bytes().len(),
        exact_role_stream_byte_length
    );
    assert_ne!(
        identifier_descriptor.full_object_digest, order_descriptor.full_object_digest,
        "role-specific stream domains and payloads must remain distinct",
    );

    let decoded_identifier =
        CanonicalTargetPartialDecryptionStream::decode(identifier_stream.canonical_bytes())
            .expect("decode identifier stream");
    let decoded_order =
        CanonicalTargetPartialDecryptionStream::decode(order_stream.canonical_bytes())
            .expect("decode order stream");
    assert_eq!(
        decoded_identifier
            .ordered_limbs()
            .expect("identifier limbs"),
        target_identifier_by_limb
    );
    assert_eq!(
        decoded_order.ordered_limbs().expect("order limbs"),
        target_order_by_limb
    );
}

#[test]
fn retained_flooding_polynomial_uses_exact_zeroizable_signed_limbs() {
    let center = BigUint::from(5_u8);
    let mut polynomial =
        ZeroizingSignedLimbPolynomial::new(5, &center).expect("fixed signed-limb flooding storage");
    for sample in [0_u8, 4, 5, 6, 10] {
        polynomial
            .push_centered_sample(BigUint::from(sample), &center)
            .expect("centered flooding sample");
    }
    let mut polynomial = polynomial.finish().expect("complete flooding polynomial");
    polynomial
        .with_bigints(|coefficients| {
            assert_eq!(
                coefficients,
                [
                    BigInt::from(-5_i8),
                    BigInt::from(-1_i8),
                    BigInt::zero(),
                    BigInt::from(1_i8),
                    BigInt::from(5_i8),
                ]
            );
            Ok(())
        })
        .expect("exact signed-limb reconstruction scratch");
    assert!(
        polynomial.zeroize_and_is_empty(),
        "explicit lifetime completion must clear every retained sign and magnitude limb",
    );
}

#[test]
fn factor_four_bounds_use_exact_arbitrary_width_inequalities() {
    let evaluation_error_bound = BigUint::from(1_u8);
    let minimum_flooding_bound = factor_four_required_flooding_bound(&evaluation_error_bound)
        .expect("the selected KLLPS flooding bound is representable");
    assert_eq!(
        minimum_flooding_bound,
        (BigUint::from(1_u8) << KLLPS_THRESHOLD_SIMULATION_BIT_LENGTH as usize)
            * BigUint::from(POLYNOMIAL_DEGREE)
            * BigUint::from(MAXIMUM_UNAUTHORIZED_COEFFICIENT_NORM),
        "C4 must retain the exact 2^lambda, ring-degree, and unauthorized-coefficient factors",
    );
    assert!(minimum_flooding_bound.bits() > 64);
    ensure_factor_four_parameter_conditions(
        crate::bgv::evaluator::top_k::CANONICAL_TARGET_CIPHERTEXT_LEVEL,
        &evaluation_error_bound,
        &minimum_flooding_bound,
    )
    .expect("the selected target basis satisfies exact factor-four bounds for the test recurrence");

    assert!(
        ensure_factor_four_parameter_conditions(
            crate::bgv::evaluator::top_k::CANONICAL_TARGET_CIPHERTEXT_LEVEL,
            &evaluation_error_bound,
            &(&minimum_flooding_bound - BigUint::from(1_u8)),
        )
        .is_err(),
        "one below the exact C4 minimum must refuse",
    );
    assert!(
        ensure_factor_four_parameter_conditions(
            1,
            &evaluation_error_bound,
            &minimum_flooding_bound,
        )
        .is_err(),
        "a target modulus smaller than the flooding support must refuse",
    );
    assert!(
        ensure_factor_four_parameter_conditions(
            crate::bgv::evaluator::top_k::CANONICAL_TARGET_CIPHERTEXT_LEVEL,
            &(BigUint::from(1_u8) << 230_usize),
            &minimum_flooding_bound,
        )
        .is_err(),
        "an evaluator bound that violates C2 or C4 must refuse",
    );
}

fn test_release_binding(seed: u8) -> KllpsReleaseBinding {
    let hash = |offset: u8| [seed.wrapping_add(offset); 64];
    KllpsReleaseBinding {
        suite_id: hash(0),
        ceremony_context_hash: hash(1),
        action_context_hash: hash(2),
        roster_hash: hash(3),
        verified_setup_source_hash: hash(4),
        finality_hash: hash(5),
        authorization_hash: hash(9),
        target_identifier_full_digest: hash(10),
        target_order_full_digest: hash(11),
    }
}

fn test_participant_release_binding(
    seed: u8,
    roster_position: u8,
) -> KllpsParticipantReleaseBinding {
    let hash = |offset: u8| [seed.wrapping_add(offset).wrapping_add(roster_position); 64];
    KllpsParticipantReleaseBinding {
        reservation_intent_object_hash: hash(6),
        subject_participant_id: hash(7),
        state_key: hash(8),
    }
}

fn test_sharing_polynomials() -> Vec<Vec<i64>> {
    vec![
        sparse_signed_polynomial(&[(0, 1), (7, -1), (4_097, 1)]),
        sparse_signed_polynomial(&[(1, 2), (71, -2), (8_193, 1)]),
        sparse_signed_polynomial(&[(2, -1), (1_023, 3), (12_289, -2)]),
        sparse_signed_polynomial(&[(3, 1), (2_049, -1), (16_385, 2)]),
    ]
}

fn sparse_signed_polynomial(entries: &[(usize, i64)]) -> Vec<i64> {
    let mut polynomial = vec![0_i64; POLYNOMIAL_DEGREE];
    for (coefficient_index, coefficient) in entries {
        polynomial[*coefficient_index] = *coefficient;
    }
    polynomial
}

fn sparse_scalar_lanes(entries: &[(usize, u64)]) -> Vec<u64> {
    let mut lanes = vec![0_u64; PAIR_CHARACTER_LANE_COUNT];
    for (lane_ordinal, lane_value) in entries {
        lanes[*lane_ordinal] = *lane_value;
    }
    lanes
}

fn test_threshold_share(
    sharing_polynomials: &[Vec<i64>],
    roster_position: usize,
    level: usize,
) -> Vec<Vec<u64>> {
    DATA_PRIMES[..=level]
        .iter()
        .copied()
        .map(|modulus| {
            let mut share = vec![0_u64; POLYNOMIAL_DEGREE];
            for (sharing_degree, polynomial) in sharing_polynomials.iter().enumerate() {
                let shifted = shift_signed_polynomial_by_monomial(
                    polynomial,
                    roster_position * sharing_degree * KLLPS_POINT_STRIDE,
                    modulus,
                );
                for (share_coefficient, shifted_coefficient) in share.iter_mut().zip(shifted) {
                    *share_coefficient =
                        add_mod_fast(*share_coefficient, shifted_coefficient, modulus);
                }
            }
            share
        })
        .collect()
}

fn shift_signed_polynomial_by_monomial(
    polynomial: &[i64],
    exponent: usize,
    modulus: u64,
) -> Vec<u64> {
    let reduced_exponent = exponent % (2 * POLYNOMIAL_DEGREE);
    let (shift, initial_negative) = if reduced_exponent >= POLYNOMIAL_DEGREE {
        (reduced_exponent - POLYNOMIAL_DEGREE, true)
    } else {
        (reduced_exponent, false)
    };
    let mut output = vec![0_u64; POLYNOMIAL_DEGREE];
    for (source_index, coefficient) in polynomial.iter().copied().enumerate() {
        let destination_sum = source_index + shift;
        let (destination, wrap_negative) = if destination_sum >= POLYNOMIAL_DEGREE {
            (destination_sum - POLYNOMIAL_DEGREE, true)
        } else {
            (destination_sum, false)
        };
        let mut residue = signed_test_residue(coefficient, modulus);
        if initial_negative ^ wrap_negative {
            residue = sub_mod_fast(0, residue, modulus);
        }
        output[destination] = residue;
    }
    output
}

fn test_target_ciphertext(
    plaintext: &[u64],
    plaintext_multiplier: u64,
    collective_secret: &[i64],
    level: usize,
    seed: u64,
) -> Ciphertext {
    let inverse_multiplier =
        inverse_mod(plaintext_multiplier, PLAINTEXT_MODULUS).expect("plaintext inverse");
    let mut component_zero = Vec::with_capacity(level + 1);
    let mut component_one = Vec::with_capacity(level + 1);
    for (limb_index, modulus) in DATA_PRIMES[..=level].iter().copied().enumerate() {
        let mut component_one_limb = vec![0_u64; POLYNOMIAL_DEGREE];
        for (coefficient_index, coefficient) in [
            (0, seed + limb_index as u64 + 1),
            (31, seed * 3 + 7),
            (4_095, seed * 5 + 11),
        ] {
            component_one_limb[coefficient_index] = coefficient % modulus;
        }
        let secret_residues = collective_secret
            .iter()
            .map(|coefficient| signed_test_residue(*coefficient, modulus))
            .collect::<Vec<_>>();
        let product = crate::bgv::evaluator::engine::negacyclic_mul(
            &component_one_limb,
            &secret_residues,
            modulus,
        )
        .expect("test target product");
        let component_zero_limb = plaintext
            .iter()
            .copied()
            .enumerate()
            .map(|(coefficient_index, desired_coefficient)| {
                let raw_residue =
                    mul_mod_fast(desired_coefficient, inverse_multiplier, PLAINTEXT_MODULUS);
                let raw_centered = if raw_residue > PLAINTEXT_MODULUS / 2 {
                    i64::try_from(raw_residue).expect("plaintext fits i64")
                        - i64::try_from(PLAINTEXT_MODULUS).expect("plaintext fits i64")
                } else {
                    i64::try_from(raw_residue).expect("plaintext fits i64")
                };
                let error = match coefficient_index % 17 {
                    0 => -2_i64,
                    1 => 1_i64,
                    _ => 0_i64,
                };
                let raw_with_error = raw_centered
                    + i64::try_from(PLAINTEXT_MODULUS).expect("plaintext fits i64") * error;
                sub_mod_fast(
                    signed_test_residue(raw_with_error, modulus),
                    product[coefficient_index],
                    modulus,
                )
            })
            .collect::<Vec<_>>();
        component_zero.push(component_zero_limb);
        component_one.push(component_one_limb);
    }

    Ciphertext {
        components: vec![component_zero, component_one],
        level,
        decrypt_scaling: plaintext_multiplier,
    }
}

fn test_flooding_error(roster_position: usize, role: usize) -> Vec<BigInt> {
    let mut error = vec![BigInt::zero(); POLYNOMIAL_DEGREE];
    error[(roster_position * 97 + role * 13) % POLYNOMIAL_DEGREE] =
        BigInt::from((roster_position as i64 % 5) - 2);
    error[(roster_position * 193 + role * 29 + 1) % POLYNOMIAL_DEGREE] =
        BigInt::from((role as i64 * 3) - 4);
    error
}

fn signed_test_residue(value: i64, modulus: u64) -> u64 {
    let modulus_wide = i128::from(modulus);
    u64::try_from(i128::from(value).rem_euclid(modulus_wide))
        .expect("test residue fits target prime")
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ExactCoefficientRecord {
    subset: Vec<usize>,
    participant_position: usize,
    coefficients: [i64; KLLPS_SUBRING_DEGREE],
    norm: u64,
}

#[test]
fn all_selected_kllps_coefficients_match_an_independent_exact_checker() {
    let production_authorized = production_authorized_records();
    let independent_authorized = independent_authorized_records();
    assert_eq!(production_authorized.len(), 840);
    assert_eq!(production_authorized, independent_authorized);

    let production_unauthorized = production_unauthorized_records();
    let independent_unauthorized = independent_unauthorized_records();
    assert_eq!(production_unauthorized.len(), 840);
    assert_eq!(production_unauthorized, independent_unauthorized);

    assert_eq!(
        norm_counts(&production_authorized),
        BTreeMap::from([
            (2, 24),
            (4, 200),
            (6, 32),
            (8, 262),
            (12, 132),
            (16, 108),
            (24, 50),
            (32, 14),
            (44, 18),
        ])
    );
    assert_eq!(
        norm_counts(&production_unauthorized),
        BTreeMap::from([(2, 48), (4, 218), (6, 176), (8, 398)])
    );
    assert_eq!(
        norm_set(&production_authorized),
        BTreeSet::from([2, 4, 6, 8, 12, 16, 24, 32, 44])
    );
    assert_eq!(
        norm_set(&production_unauthorized),
        BTreeSet::from([2, 4, 6, 8])
    );
    assert_eq!(
        maximum_infinity_norm(&production_authorized),
        8,
        "authorized scaled coefficients must reproduce the exact full-ring maximum",
    );
    assert_eq!(maximum_infinity_norm(&production_unauthorized), 4);

    let authorized_known_answer = production_authorized
        .iter()
        .find(|record| record.subset == [0, 1, 2, 3] && record.participant_position == 1)
        .expect("authorized known-answer coefficient");
    assert_eq!(
        authorized_known_answer.coefficients,
        [4, 0, -4, -6, -8, -8, -8, -6]
    );
    let unauthorized_known_answer = production_unauthorized
        .iter()
        .find(|record| record.subset == [0, 1, 2] && record.participant_position == 4)
        .expect("unauthorized known-answer coefficient");
    assert_eq!(
        unauthorized_known_answer.coefficients,
        [1, 1, -1, -1, -1, 1, 1, 1]
    );

    assert_eq!(
        coefficient_records_hash(&production_authorized, b"authorized"),
        coefficient_records_hash(&independent_authorized, b"authorized")
    );
    assert_eq!(
        hash_hex(coefficient_records_hash(
            &production_authorized,
            b"authorized"
        )),
        "17fc2d42a5e88cf746702d6208f9870ff1d6591f6af9ecdf1436209ae519150a1b0b90bc47cbeda3f00e1edce0512a5413a6f550460f47a8b42f33771aca82c7"
    );
    assert_eq!(
        coefficient_records_hash(&production_unauthorized, b"unauthorized"),
        coefficient_records_hash(&independent_unauthorized, b"unauthorized")
    );
    assert_eq!(
        hash_hex(coefficient_records_hash(
            &production_unauthorized,
            b"unauthorized"
        )),
        "32c01816177e7bbf92cf2b206f49784477c6ad6f8921b128a82a652c78c89667ebe1ab4b57ca8c0aa6cc6bd8fb0546023de8b26674f0ea638780293af0d44609"
    );
}

fn production_authorized_records() -> Vec<ExactCoefficientRecord> {
    let mut records = Vec::with_capacity(840);
    for selected_positions in combinations(KLLPS_PARTICIPANT_COUNT, KLLPS_RECONSTRUCTION_THRESHOLD)
    {
        for selected_index in 0..KLLPS_RECONSTRUCTION_THRESHOLD {
            let coefficients = centered_authorized_coefficient_for_every_prime(
                &selected_positions,
                selected_index,
            );
            records.push(exact_record(
                selected_positions.clone(),
                selected_positions[selected_index],
                coefficients,
            ));
        }
    }
    records
}

fn centered_authorized_coefficient_for_every_prime(
    selected_positions: &[usize],
    selected_index: usize,
) -> [i64; KLLPS_SUBRING_DEGREE] {
    let mut expected = None;
    for modulus in DATA_PRIMES {
        let coefficient = authorized_scaled_lagrange_coefficient_at_zero(
            selected_positions,
            selected_index,
            modulus,
        )
        .expect("authorized KLLPS coefficient");
        let centered = coefficient.map(|value| centered_residue(value, modulus));
        if let Some(previous) = expected {
            assert_eq!(centered, previous, "target-prime coefficient mismatch");
        } else {
            expected = Some(centered);
        }
    }
    expected.expect("selected data basis is nonempty")
}

fn production_unauthorized_records() -> Vec<ExactCoefficientRecord> {
    let mut records = Vec::with_capacity(840);
    for corrupted_positions in
        combinations(KLLPS_PARTICIPANT_COUNT, KLLPS_RECONSTRUCTION_THRESHOLD - 1)
    {
        for absent_position in 0..KLLPS_PARTICIPANT_COUNT {
            if corrupted_positions.contains(&absent_position) {
                continue;
            }
            let mut expected = None;
            for modulus in DATA_PRIMES {
                let coefficient = unauthorized_zero_lagrange_coefficient(
                    &corrupted_positions,
                    absent_position,
                    modulus,
                )
                .expect("unauthorized KLLPS coefficient");
                let centered = coefficient.map(|value| centered_residue(value, modulus));
                if let Some(previous) = expected {
                    assert_eq!(centered, previous, "target-prime coefficient mismatch");
                } else {
                    expected = Some(centered);
                }
            }
            records.push(exact_record(
                corrupted_positions.clone(),
                absent_position,
                expected.expect("selected data basis is nonempty"),
            ));
        }
    }
    records
}

fn exact_record(
    subset: Vec<usize>,
    participant_position: usize,
    coefficients: [i64; KLLPS_SUBRING_DEGREE],
) -> ExactCoefficientRecord {
    let norm = coefficients
        .iter()
        .map(|coefficient| coefficient.unsigned_abs())
        .sum();
    ExactCoefficientRecord {
        subset,
        participant_position,
        coefficients,
        norm,
    }
}

fn centered_residue(value: u64, modulus: u64) -> i64 {
    if value > modulus / 2 {
        i64::try_from(value).expect("selected prime fits i64")
            - i64::try_from(modulus).expect("selected prime fits i64")
    } else {
        i64::try_from(value).expect("selected prime fits i64")
    }
}

fn combinations(universe_size: usize, subset_size: usize) -> Vec<Vec<usize>> {
    fn extend(
        universe_size: usize,
        subset_size: usize,
        next_position: usize,
        current: &mut Vec<usize>,
        output: &mut Vec<Vec<usize>>,
    ) {
        if current.len() == subset_size {
            output.push(current.clone());
            return;
        }
        let remaining = subset_size - current.len();
        for position in next_position..=universe_size - remaining {
            current.push(position);
            extend(universe_size, subset_size, position + 1, current, output);
            current.pop();
        }
    }

    let mut output = Vec::new();
    extend(
        universe_size,
        subset_size,
        0,
        &mut Vec::with_capacity(subset_size),
        &mut output,
    );
    output
}

fn norm_counts(records: &[ExactCoefficientRecord]) -> BTreeMap<u64, usize> {
    let mut counts = BTreeMap::new();
    for record in records {
        *counts.entry(record.norm).or_insert(0) += 1;
    }
    counts
}

fn norm_set(records: &[ExactCoefficientRecord]) -> BTreeSet<u64> {
    records.iter().map(|record| record.norm).collect()
}

fn maximum_infinity_norm(records: &[ExactCoefficientRecord]) -> u64 {
    records
        .iter()
        .flat_map(|record| record.coefficients)
        .map(i64::unsigned_abs)
        .max()
        .expect("coefficient records are nonempty")
}

fn coefficient_records_hash(records: &[ExactCoefficientRecord], role: &[u8]) -> [u8; 64] {
    let mut hasher = Sha3_512::new();
    hasher.update(b"sealed-lattice/kllps26/exact-coefficients/v1");
    hasher.update((role.len() as u64).to_le_bytes());
    hasher.update(role);
    hasher.update((records.len() as u64).to_le_bytes());
    for record in records {
        hasher.update((record.subset.len() as u64).to_le_bytes());
        for position in &record.subset {
            hasher.update((*position as u64).to_le_bytes());
        }
        hasher.update((record.participant_position as u64).to_le_bytes());
        for coefficient in record.coefficients {
            hasher.update(coefficient.to_le_bytes());
        }
        hasher.update(record.norm.to_le_bytes());
    }
    hasher.finalize().into()
}

fn hash_hex(hash: [u8; 64]) -> String {
    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ExactFraction {
    numerator: BigInt,
    denominator: BigInt,
}

impl ExactFraction {
    fn from_integer(value: BigInt) -> Self {
        Self {
            numerator: value,
            denominator: BigInt::from(1_u8),
        }
    }

    fn is_zero(&self) -> bool {
        self.numerator.is_zero()
    }

    fn subtract(&self, other: &Self) -> Self {
        Self::new(
            &self.numerator * &other.denominator - &other.numerator * &self.denominator,
            &self.denominator * &other.denominator,
        )
    }

    fn multiply(&self, other: &Self) -> Self {
        Self::new(
            &self.numerator * &other.numerator,
            &self.denominator * &other.denominator,
        )
    }

    fn divide(&self, other: &Self) -> Self {
        assert!(!other.is_zero(), "exact division by zero");
        Self::new(
            &self.numerator * &other.denominator,
            &self.denominator * &other.numerator,
        )
    }

    fn new(mut numerator: BigInt, mut denominator: BigInt) -> Self {
        assert!(!denominator.is_zero(), "exact fraction denominator is zero");
        if denominator.sign() == Sign::Minus {
            numerator = -numerator;
            denominator = -denominator;
        }
        let divisor = exact_greatest_common_divisor(numerator.abs(), denominator.clone());
        Self {
            numerator: numerator / &divisor,
            denominator: denominator / divisor,
        }
    }
}

fn exact_greatest_common_divisor(mut left: BigInt, mut right: BigInt) -> BigInt {
    while !right.is_zero() {
        let remainder = &left % &right;
        left = right;
        right = remainder;
    }
    if left.is_zero() {
        BigInt::from(1_u8)
    } else {
        left
    }
}

fn independent_authorized_records() -> Vec<ExactCoefficientRecord> {
    let mut records = Vec::with_capacity(840);
    for selected_positions in combinations(KLLPS_PARTICIPANT_COUNT, KLLPS_RECONSTRUCTION_THRESHOLD)
    {
        for selected_index in 0..selected_positions.len() {
            let selected_point = exact_monomial(selected_positions[selected_index]);
            let mut numerator = exact_one();
            let mut denominator = exact_one();
            for (other_index, other_position) in selected_positions.iter().copied().enumerate() {
                if other_index == selected_index {
                    continue;
                }
                let other_point = exact_monomial(other_position);
                numerator = exact_multiply(&numerator, &exact_negate(&other_point));
                denominator =
                    exact_multiply(&denominator, &exact_subtract(&selected_point, &other_point));
            }
            let scaled_numerator = numerator
                .into_iter()
                .map(|coefficient| coefficient * BigInt::from(4_u8))
                .collect::<Vec<_>>();
            let coefficients = exact_quotient(&denominator, &scaled_numerator);
            records.push(exact_record(
                selected_positions.clone(),
                selected_positions[selected_index],
                exact_coefficients_to_i64(&coefficients),
            ));
        }
    }
    records
}

fn independent_unauthorized_records() -> Vec<ExactCoefficientRecord> {
    let mut records = Vec::with_capacity(840);
    for corrupted_positions in
        combinations(KLLPS_PARTICIPANT_COUNT, KLLPS_RECONSTRUCTION_THRESHOLD - 1)
    {
        for absent_position in 0..KLLPS_PARTICIPANT_COUNT {
            if corrupted_positions.contains(&absent_position) {
                continue;
            }
            let destination = exact_monomial(absent_position);
            let mut numerator = exact_one();
            let mut denominator = exact_one();
            for corrupted_position in corrupted_positions.iter().copied() {
                let corrupted_point = exact_monomial(corrupted_position);
                numerator =
                    exact_multiply(&numerator, &exact_subtract(&destination, &corrupted_point));
                denominator = exact_multiply(&denominator, &exact_negate(&corrupted_point));
            }
            let coefficients = exact_quotient(&denominator, &numerator);
            records.push(exact_record(
                corrupted_positions.clone(),
                absent_position,
                exact_coefficients_to_i64(&coefficients),
            ));
        }
    }
    records
}

fn exact_coefficients_to_i64(coefficients: &[BigInt]) -> [i64; KLLPS_SUBRING_DEGREE] {
    std::array::from_fn(|index| {
        coefficients[index]
            .to_i64()
            .expect("exact KLLPS coefficient fits i64")
    })
}

fn exact_quotient(denominator: &[BigInt], numerator: &[BigInt]) -> Vec<BigInt> {
    let mut augmented =
        vec![
            vec![ExactFraction::from_integer(BigInt::zero()); KLLPS_SUBRING_DEGREE + 1];
            KLLPS_SUBRING_DEGREE
        ];
    for column_index in 0..KLLPS_SUBRING_DEGREE {
        let product = exact_multiply(denominator, &exact_monomial(column_index));
        for row_index in 0..KLLPS_SUBRING_DEGREE {
            augmented[row_index][column_index] =
                ExactFraction::from_integer(product[row_index].clone());
        }
    }
    for row_index in 0..KLLPS_SUBRING_DEGREE {
        augmented[row_index][KLLPS_SUBRING_DEGREE] =
            ExactFraction::from_integer(numerator[row_index].clone());
    }

    for pivot_column in 0..KLLPS_SUBRING_DEGREE {
        let pivot_row = (pivot_column..KLLPS_SUBRING_DEGREE)
            .find(|row_index| !augmented[*row_index][pivot_column].is_zero())
            .expect("spaced-monomial denominator is a unit over the rationals");
        augmented.swap(pivot_column, pivot_row);
        let pivot = augmented[pivot_column][pivot_column].clone();
        for column_index in pivot_column..=KLLPS_SUBRING_DEGREE {
            augmented[pivot_column][column_index] =
                augmented[pivot_column][column_index].divide(&pivot);
        }
        for row_index in 0..KLLPS_SUBRING_DEGREE {
            if row_index == pivot_column {
                continue;
            }
            let elimination_factor = augmented[row_index][pivot_column].clone();
            if elimination_factor.is_zero() {
                continue;
            }
            for column_index in pivot_column..=KLLPS_SUBRING_DEGREE {
                let subtracted =
                    elimination_factor.multiply(&augmented[pivot_column][column_index]);
                augmented[row_index][column_index] =
                    augmented[row_index][column_index].subtract(&subtracted);
            }
        }
    }

    (0..KLLPS_SUBRING_DEGREE)
        .map(|index| {
            let solution = &augmented[index][KLLPS_SUBRING_DEGREE];
            assert_eq!(
                solution.denominator,
                BigInt::from(1_u8),
                "required KLLPS coefficient is not integral",
            );
            solution.numerator.clone()
        })
        .collect()
}

fn exact_one() -> Vec<BigInt> {
    let mut one = vec![BigInt::zero(); KLLPS_SUBRING_DEGREE];
    one[0] = BigInt::from(1_u8);
    one
}

fn exact_monomial(exponent: usize) -> Vec<BigInt> {
    let reduced_exponent = exponent % KLLPS_SPACED_POINT_COUNT;
    let mut polynomial = vec![BigInt::zero(); KLLPS_SUBRING_DEGREE];
    if reduced_exponent < KLLPS_SUBRING_DEGREE {
        polynomial[reduced_exponent] = BigInt::from(1_u8);
    } else {
        polynomial[reduced_exponent - KLLPS_SUBRING_DEGREE] = BigInt::from(-1_i8);
    }
    polynomial
}

fn exact_negate(polynomial: &[BigInt]) -> Vec<BigInt> {
    polynomial.iter().map(|coefficient| -coefficient).collect()
}

fn exact_subtract(left: &[BigInt], right: &[BigInt]) -> Vec<BigInt> {
    left.iter()
        .zip(right)
        .map(|(left, right)| left - right)
        .collect()
}

fn exact_multiply(left: &[BigInt], right: &[BigInt]) -> Vec<BigInt> {
    let mut product = vec![BigInt::zero(); KLLPS_SUBRING_DEGREE];
    for (left_index, left_coefficient) in left.iter().enumerate() {
        for (right_index, right_coefficient) in right.iter().enumerate() {
            let term = left_coefficient * right_coefficient;
            let output_index = left_index + right_index;
            if output_index < KLLPS_SUBRING_DEGREE {
                product[output_index] += term;
            } else {
                product[output_index - KLLPS_SUBRING_DEGREE] -= term;
            }
        }
    }
    product
}
