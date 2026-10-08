use super::*;
use num_bigint::BigUint;

fn integer(bytes: &[u8]) -> BigUint {
    BigUint::from_bytes_le(bytes)
}

#[test]
fn every_modulus_is_a_certified_prime_of_its_form() {
    let plaintext = 65_537u32;
    for profile in Profile::all() {
        for (prime, bits) in [
            (
                profile.ciphertext_modulus(),
                profile.ciphertext_modulus().bits(),
            ),
            (profile.release_modulus(), profile.release_modulus().bits()),
        ] {
            let modulus = integer(&prime.to_bytes());
            let odd = BigUint::from(prime.odd_factor());
            assert_eq!(prime.odd_factor() % 2, 1);
            assert_eq!(prime.odd_factor() % plaintext, 0);
            assert!(odd < BigUint::from(1u8) << prime.exponent());
            assert_eq!(modulus, (odd << prime.exponent()) + 1u8);
            assert_eq!(modulus.bits() as usize, bits);
            // Proth: w^((q - 1) / 2) = -1 proves q prime.
            let minus_one = &modulus - 1u8;
            assert_eq!(
                BigUint::from(prime.witness()).modpow(&(&minus_one >> 1), &modulus),
                minus_one
            );
        }
        assert_eq!(profile.ciphertext_modulus().bits() % 32, 0);
        assert!(profile.release_modulus().bits() < profile.ciphertext_modulus().bits());
    }
}

#[test]
fn completion_parameters_rebuild_the_independent_moduli() {
    let profile = Profile::new(10, 10).unwrap();
    let fhe: BigUint = ((BigUint::from(65_537u32) * 65_319u32) << 832usize) + 1u8;
    let proof_field: BigUint =
        (BigUint::from(1u8) << 128usize) - (BigUint::from(133u8) << 64usize) + 1u8;
    let share: BigUint = proof_field * (119u32 * (1 << 23) + 1);
    let auxiliary: BigUint = (BigUint::from(257u32 * 101) << 20usize) + 1u8;
    let mut expected = b"SCP1".to_vec();
    for (value, length) in [(&fhe, 108), (&share, 20), (&auxiliary, 5)] {
        let mut bytes = value.to_bytes_le();
        assert!(bytes.len() <= length);
        bytes.resize(length, 0);
        expected.extend(bytes);
    }
    assert_eq!(profile.parameters(), expected);
    assert_eq!(profile.parameters().len(), 137);
    assert_eq!(integer(share_modulus()), share);
    assert_eq!(integer(auxiliary_modulus()), auxiliary);
}

#[test]
fn thresholds_and_interpolation_match_the_census() {
    // Participants, corrupt bound, inventory and release thresholds,
    // minimum turnout, interpolation degree and clearing factor.
    for (participants, corrupt, inventory, release, turnout, degree, clearing) in [
        (3, 0, 3, 2, 2, 2, 2),
        (4, 1, 3, 2, 3, 2, 2),
        (5, 1, 4, 2, 3, 4, 2),
        (7, 2, 5, 3, 4, 4, 4),
        (9, 2, 7, 3, 4, 8, 4),
        (10, 3, 7, 4, 5, 8, 4),
        (13, 4, 9, 5, 6, 8, 8),
        (16, 5, 11, 6, 7, 8, 8),
        (17, 5, 12, 6, 7, 16, 8),
        (20, 6, 14, 7, 8, 16, 8),
    ] {
        let profile = Profile::new(participants, 2).unwrap();
        assert_eq!(
            (
                profile.maximum_corrupt_participants(),
                profile.inventory_threshold(),
                profile.release_threshold(),
                profile.minimum_turnout(),
                profile.interpolation_degree(),
                profile.clearing_factor()
            ),
            (corrupt, inventory, release, turnout, degree, clearing)
        );
        assert_eq!(profile.sharing_degree(), release - 1);
        assert_eq!(profile.setup_eligible_contributors(), release + corrupt);
        assert!(profile.setup_eligible_contributors() <= participants);
        assert_eq!(profile.point_stride() * degree, DEGREE);
    }
}

#[test]
fn searched_sizes_match_the_census() {
    // Participants, options, ciphertext bits, gadget coordinates, FHE
    // limbs, sharing coefficient, share limb and carry bits, release
    // share and quotient bits, and common-matrix sample bits.
    for (participants, options, bits, gadgets, limbs, sharing, limb, carry, share, quotient) in [
        (3, 2, 576, 4, 6, 108, 96, 32, 112, 144),
        (10, 10, 864, 6, 9, 112, 96, 32, 120, 144),
        (13, 2, 704, 5, 8, 114, 96, 32, 120, 144),
        (16, 2, 736, 6, 8, 115, 95, 33, 120, 144),
        (20, 20, 960, 7, 10, 116, 95, 33, 127, 192),
    ] {
        let profile = Profile::new(participants, options).unwrap();
        assert_eq!(profile.ciphertext_modulus().bits(), bits);
        assert_eq!(profile.gadget_length(), gadgets);
        assert_eq!(profile.fhe_limbs(), limbs);
        assert_eq!(profile.sharing_coefficient_bits(), sharing);
        assert_eq!(profile.share_limb_bits(), limb);
        assert_eq!(profile.share_carry_bits(), carry);
        assert_eq!(profile.release_share_bits(), share);
        assert_eq!(profile.release_quotient_bits(), quotient);
        assert_eq!(profile.release_modulus().bits(), 192);
    }
    for (participants, options, sample) in [(3, 2, 768), (10, 10, 1024), (20, 20, 1152)] {
        assert_eq!(
            Profile::new(participants, options)
                .unwrap()
                .fhe_common_sample_bits(),
            sample
        );
    }
    assert_eq!(fixed_common_sample_bits(), 320);
    let completion = Profile::new(10, 10).unwrap();
    assert_eq!(completion.release_noise_bits(), 144);
    assert_eq!(completion.comparison_degree(), 181);
    assert_eq!(completion.rank_window(), 16);
    assert_eq!(Profile::new(3, 2).unwrap().rank_window(), 2);
    assert_eq!(Profile::new(20, 17).unwrap().rank_window(), 32);
}

#[test]
fn setup_polynomials_are_numbered_once_by_family() {
    for (participants, options) in [(3, 2), (10, 10), (20, 20)] {
        let profile = Profile::new(participants, options).unwrap();
        let mut seen = vec![false; profile.setup_polynomials()];
        let mut mark = |index: usize, family: Family| {
            assert!(!seen[index]);
            seen[index] = true;
            assert_eq!(profile.setup_family(index), Some(family));
        };
        for gadget in 0..profile.gadget_length() {
            for component in 0..7 {
                let index = profile.fhe_polynomial(gadget, component);
                mark(index, Family::Fhe);
                assert_eq!(
                    profile.fhe_polynomial_position(index),
                    Some((gadget, component))
                );
            }
        }
        assert_eq!(
            profile.fhe_polynomial_position(profile.share_common_polynomial()),
            None
        );
        mark(profile.share_common_polynomial(), Family::Sharing);
        for recipient in 0..participants {
            mark(profile.recipient_key_polynomial(recipient), Family::Sharing);
            mark(
                profile.share_constant_polynomial(recipient),
                Family::Sharing,
            );
            mark(profile.share_linear_polynomial(recipient), Family::Sharing);
        }
        assert!(seen.iter().all(|value| *value));
        assert_eq!(profile.setup_family(profile.setup_polynomials()), None);
    }
    let completion = Profile::new(10, 10).unwrap();
    assert_eq!(completion.setup_statement_header().len(), 136);
    assert_eq!(
        completion.setup_statement_length(),
        136 + 42 * DEGREE * 109 + 31 * DEGREE * 21
    );
    assert_eq!(completion.setup_polynomials(), 73);
    assert_eq!(completion.share_common_polynomial(), 42);
    assert_eq!(completion.recipient_key_polynomial(0), 43);
    assert_eq!(completion.share_linear_polynomial(9), 72);
}

#[test]
fn contribution_bodies_carry_every_key_once_and_no_common_polynomial() {
    for profile in Profile::all() {
        let polynomials = profile.contribution_body_polynomials();
        assert_eq!(
            polynomials.len(),
            4 * profile.gadget_length() + 2 * profile.participants()
        );
        assert!(polynomials.windows(2).all(|pair| pair[0] < pair[1]));
        let mut commons = vec![profile.share_common_polynomial()];
        for gadget in 0..profile.gadget_length() {
            commons.extend([0, 3, 5].map(|component| profile.fhe_polynomial(gadget, component)));
        }
        commons.extend(
            (0..profile.participants())
                .map(|recipient| profile.recipient_key_polynomial(recipient)),
        );
        assert!(polynomials.iter().all(|index| !commons.contains(index)));
        assert_eq!(
            polynomials.len() + commons.len(),
            profile.setup_polynomials()
        );
    }
    // The contribution body model's layout: four FHE keys per gadget
    // coordinate and two share encryptions per recipient, each a sign
    // byte and a magnitude per coefficient.
    let completion = Profile::new(10, 10).unwrap();
    let polynomials = completion.contribution_body_polynomials();
    assert_eq!(polynomials[..4], [1, 2, 4, 6]);
    assert_eq!(polynomials[20..26], [36, 37, 39, 41, 44, 45]);
    assert_eq!(polynomials[43], 72);
    assert_eq!(
        polynomials
            .iter()
            .map(|index| completion.setup_polynomial_bytes(*index).unwrap())
            .sum::<usize>(),
        24 * DEGREE * 109 + 20 * DEGREE * 21
    );
    assert_eq!(
        completion.setup_polynomial_bytes(completion.setup_polynomials()),
        None
    );
}

#[test]
fn setup_shapes_match_the_census() {
    let completion = Profile::new(10, 10).unwrap().setup_shape();
    assert_eq!(
        (completion.word_columns, completion.boolean_columns),
        (331, 24)
    );
    // Twenty-four FHE errors, one per key, then two share errors per
    // recipient.
    let mut narrow: Vec<_> = (0..24).map(|key| (30 + 10 * key, 7)).collect();
    for recipient in 0..10 {
        narrow.extend([(264 + 7 * recipient, 7), (267 + 7 * recipient, 7)]);
    }
    assert_eq!(completion.narrow_words, narrow);
    assert_eq!(completion.sparse_supports.len(), 12);
    assert_eq!(completion.sparse_supports[0], (1, 512));
    assert_eq!(completion.sparse_supports[2], (1, 128));
    // Census ranges of word columns by participant count.
    for (participants, low, high) in [(3, 140, 268), (16, 358, 450), (20, 392, 484)] {
        let words: Vec<_> = Profile::option_range()
            .map(|options| {
                Profile::new(participants, options)
                    .unwrap()
                    .setup_shape()
                    .word_columns
            })
            .collect();
        assert_eq!(*words.iter().min().unwrap(), low);
        assert_eq!(*words.iter().max().unwrap(), high);
    }
    // Twelve-bit high parts are narrow words for three participants.
    let small = Profile::new(3, 2).unwrap().setup_shape();
    assert_eq!(small.narrow_words[0], (6, 12));
}

#[test]
fn counts_outside_the_supported_ranges_are_refused() {
    for (participants, options) in [(0, 0), (2, 10), (21, 10), (10, 1), (10, 21)] {
        assert_eq!(Profile::new(participants, options), Err(Unsupported));
    }
    assert_eq!(Profile::participant_range(), 3..=20);
    assert_eq!(Profile::option_range(), 2..=20);
    assert_eq!(Profile::all().count(), 342);
}
