use super::*;
use crate::hashing::hash512_hex;

#[test]
fn setup_proof_challenge_sampler_derives_autostable_bounded_coefficients() {
    let statement_hash = hash512_hex("test-statement", &[b"same-secret"]);
    let relation_commitment_hash = hash512_hex("test-relation", &[b"same-secret"]);

    let coefficients = derive_setup_proof_challenge_coefficients(
        "same-secret-consistency",
        &statement_hash,
        &relation_commitment_hash,
        16,
    )
    .expect("challenge coefficients");

    assert_eq!(coefficients.len(), 16);
    assert!(
        coefficients[..8]
            .iter()
            .any(|coefficient| *coefficient != 0)
    );
    assert_eq!(coefficients[8], 0);
    for coefficient in &coefficients {
        assert!((-2..=2).contains(coefficient));
    }
    for coefficient_position in 9..16 {
        assert_eq!(
            coefficients[coefficient_position],
            -coefficients[16 - coefficient_position]
        );
    }
}

#[test]
fn setup_proof_challenge_sampler_binds_statement_and_relation() {
    let statement_hash = hash512_hex("test-statement", &[b"same-secret"]);
    let other_statement_hash = hash512_hex("test-statement", &[b"same-secret-drift"]);
    let relation_commitment_hash = hash512_hex("test-relation", &[b"same-secret"]);

    let first = derive_setup_proof_challenge_coefficients(
        "same-secret-consistency",
        &statement_hash,
        &relation_commitment_hash,
        32,
    )
    .expect("challenge coefficients");
    let second = derive_setup_proof_challenge_coefficients(
        "same-secret-consistency",
        &other_statement_hash,
        &relation_commitment_hash,
        32,
    )
    .expect("challenge coefficients");

    assert_ne!(first, second);
}

#[test]
fn setup_proof_challenge_sampler_rejects_wrong_profile_shape() {
    let statement_hash = hash512_hex("test-statement", &[b"same-secret"]);
    let relation_commitment_hash = hash512_hex("test-relation", &[b"same-secret"]);

    let odd_ring_error = derive_setup_proof_challenge_coefficients(
        "same-secret-consistency",
        &statement_hash,
        &relation_commitment_hash,
        15,
    )
    .expect_err("odd ring degree should fail");
    let wrong_family_error = derive_setup_proof_challenge_coefficients(
        "unknown-proof-family",
        &statement_hash,
        &relation_commitment_hash,
        16,
    )
    .expect_err("unknown proof family should fail");

    assert_eq!(
        odd_ring_error.code,
        CanonicalErrorCode::ProfileComponentMismatch
    );
    assert_eq!(
        wrong_family_error.code,
        CanonicalErrorCode::ProfileComponentMismatch
    );
}

#[test]
fn setup_proof_lnp_tbox_uniform_sampler_uses_full_declared_width() {
    let bit_count = 130;
    let modulus = (BigUint::one() << bit_count) - BigUint::from(159_u64);
    let mut observed_high_bits = false;

    for coefficient_index in 0..64 {
        let residue_bytes = sample_setup_proof_lnp_tbox_uniform_residue_bytes(
            "sealed-lattice/setup/test/lnp-tbox-uniform-v1",
            "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
            2,
            coefficient_index,
            bit_count,
            Some(&modulus),
        )
        .expect("uniform residue");
        assert_eq!(residue_bytes.len(), bit_count.div_ceil(8));
        assert_eq!(residue_bytes[16] & !0b0000_0011, 0);

        let residue = BigUint::from_bytes_le(&residue_bytes);
        assert!(residue < modulus);
        if residue.bits() > 64 {
            observed_high_bits = true;
        }
    }

    assert!(
        observed_high_bits,
        "tbox uniform sampler must not truncate residues to the low machine word"
    );
}

#[test]
fn setup_proof_scalar_challenge_sampler_uses_declared_width() {
    let statement_hash = hash512_hex("test-statement", &[b"same-secret"]);
    let mut observed_above_old_word = false;
    let challenge_maximum = (1_u64 << 45) - 1;

    for relation_index in 0..64_u64 {
        let relation_index_bytes = relation_index.to_le_bytes();
        let relation_commitment_hash =
            hash512_hex("test-relation", &[b"same-secret", &relation_index_bytes]);
        let challenge = derive_setup_proof_scalar_challenge(
            "same-secret-consistency",
            "sealed-lattice/setup/test/scalar-challenge-v1",
            &statement_hash,
            &relation_commitment_hash,
            45,
        )
        .expect("scalar challenge");

        assert!((1..=challenge_maximum).contains(&challenge));
        if challenge > u64::from(u32::MAX) {
            observed_above_old_word = true;
        }
    }

    assert!(
        observed_above_old_word,
        "scalar challenge sampler must not truncate to the old 32-bit challenge space"
    );
}

#[test]
fn setup_proof_challenge_space_audit_covers_all_families_and_invertible_differences() {
    let accounting = challenge_difference_invertibility_accounting_value()
        .expect("challenge difference accounting");
    assert_eq!(
        accounting["status"],
        SETUP_PROOF_CHALLENGE_DIFFERENCE_INVERTIBILITY_STATUS
    );
    assert_eq!(accounting["conditionSatisfied"], true);

    let audit = setup_proof_challenge_space_audit_value(SETUP_PROOF_LNP_PROOF_RING_DEGREE)
        .expect("challenge audit");
    let family_samples = audit["familySamples"].as_array().expect("family samples");
    assert_eq!(family_samples.len(), SETUP_PROOF_FAMILIES.len());
    for proof_family in SETUP_PROOF_FAMILIES {
        assert!(
            family_samples.iter().any(|sample| {
                sample["proofFamily"].as_str() == Some(proof_family)
                    && sample["sampledCoefficients"]
                        .as_array()
                        .is_some_and(|coefficients| {
                            coefficients.len()
                                == challenge_sample_positions(SETUP_PROOF_LNP_PROOF_RING_DEGREE)
                                    .expect("sample positions")
                                    .len()
                        })
            }),
            "missing challenge audit family {proof_family}"
        );
    }

    let sampled_difference_checks = audit["sampledDifferenceChecks"]
        .as_array()
        .expect("sampled difference checks");
    // One pairwise difference per unordered LNP family pair.
    assert_eq!(
        sampled_difference_checks.len(),
        SETUP_PROOF_FAMILIES.len() * (SETUP_PROOF_FAMILIES.len() - 1) / 2
    );
    assert!(sampled_difference_checks.iter().all(|check| {
        check["invertibleOverProofRing"].as_bool() == Some(true)
            && check["coefficientInfinityNorm"]
                .as_u64()
                .is_some_and(|norm| norm <= SETUP_PROOF_CHALLENGE_COEFFICIENT_BOUND * 2)
    }));
}

#[test]
fn setup_proof_lnp_tbox_decoder_accepts_generated_canonical_proof_byte_layout() {
    let statement_hash = hash512_hex("test-statement", &[b"same-secret"]);
    let relation_commitment_hash = hash512_hex("test-relation", &[b"same-secret"]);
    let layout = small_lnp_tbox_layout_for_test();
    let proof_bytes = encode_lnp_tbox_proof_for_test(
        &layout,
        &statement_hash,
        &relation_commitment_hash,
        None,
        None,
        TboxSuffixProfileForTest::Generated,
    )
    .expect("proof bytes");

    let decoded = verify_setup_proof_lnp_tbox_proof_bytes(
        &layout,
        &statement_hash,
        &relation_commitment_hash,
        &proof_bytes,
    )
    .expect("proof byte layout");

    assert_eq!(decoded.decoded_size_bytes, proof_bytes.len());
    let derived_challenge = derive_setup_proof_lnp_tbox_challenge_from_prefix(
        &layout,
        &statement_hash,
        &relation_commitment_hash,
        &proof_bytes[..setup_proof_lnp_tbox_commitment_prefix_byte_count(&layout)
            .expect("prefix byte count")],
    )
    .expect("derived tbox challenge");
    assert_eq!(
        decoded.challenge_coefficients,
        derived_challenge.challenge_coefficients
    );
    assert_eq!(
        decoded.t_b_coefficients.len(),
        layout.t_b_polynomial_count * layout.proof_ring_degree
    );
    assert_eq!(
        decoded.h_coefficients.len(),
        layout.h_polynomial_count * layout.proof_ring_degree
    );
    assert_eq!(
        decoded.t_a1_compressed_coefficients.len(),
        layout.t_a1_polynomial_count * layout.proof_ring_degree
    );
    assert_eq!(decoded.t_b_coefficients[1], BigUint::from(1_u64));
    assert_eq!(decoded.h_coefficients[2], BigUint::from(2_u64));
    assert_eq!(
        decoded.t_a1_compressed_coefficients[3],
        BigUint::from(3_u64)
    );
    assert!(
        decoded
            .hint_coefficients
            .iter()
            .any(|coefficient| coefficient.value != 0)
    );
    for coefficients in [
        &decoded.z1_coefficients,
        &decoded.z21_coefficients,
        &decoded.z3_coefficients,
        &decoded.z4_coefficients,
    ] {
        assert!(
            coefficients
                .iter()
                .any(|coefficient| coefficient.value != 0)
        );
    }
    assert!(!decoded.z3_l2_squared.is_zero());
    assert!(!decoded.z4_infinity_norm.is_zero());
    assert_eq!(decoded.z34_seed_material_hash.len(), 128);
    assert_eq!(decoded.z34_challenge_seed_hex.len(), 64);
    assert_eq!(decoded.z34_challenge_seed_hash.len(), 128);
    assert_eq!(decoded.z34_challenge_tail_hash.len(), 128);
    assert_eq!(decoded.z34_challenge_row_domain_hash.len(), 128);
    assert_eq!(decoded.z34_challenge_z3_row_set_hash.len(), 128);
    assert_eq!(decoded.z34_challenge_z4_row_set_hash.len(), 128);
    assert_eq!(decoded.tbox_lower_protocol_challenge_hash.len(), 128);
    assert_eq!(decoded.z34_z3_check_window_hash.len(), 128);
    assert_eq!(decoded.z34_z4_check_window_hash.len(), 128);
    assert_ne!(
        decoded.z34_challenge_z3_row_set_hash,
        decoded.z34_challenge_z4_row_set_hash
    );
    assert_ne!(
        decoded.z34_z3_check_window_hash,
        decoded.z34_z4_check_window_hash
    );
}

#[test]
fn setup_proof_lnp_tbox_decoder_accepts_generated_suffix_for_all_setup_families() {
    for layout in [
        private_vss_share_lnp_tbox_layout(),
        same_secret_lnp_tbox_layout(),
        public_key_share_lnp_tbox_layout(),
    ] {
        let statement_hash = hash512_hex(
            "test-statement",
            &[
                layout.proof_family.as_bytes(),
                layout.tbox_parameter_profile_id.as_bytes(),
            ],
        );
        let relation_commitment_hash = hash512_hex(
            "test-relation",
            &[
                layout.proof_family.as_bytes(),
                layout.tbox_parameter_profile_id.as_bytes(),
            ],
        );
        let proof_bytes = encode_lnp_tbox_proof_for_test(
            &layout,
            &statement_hash,
            &relation_commitment_hash,
            None,
            None,
            TboxSuffixProfileForTest::Generated,
        )
        .expect("proof bytes");
        let prefix_byte_count =
            setup_proof_lnp_tbox_commitment_prefix_byte_count(&layout).expect("prefix byte count");
        assert!(
            proof_bytes[prefix_byte_count..]
                .iter()
                .any(|byte| *byte != 0),
            "generated suffix for {} must not collapse to a zero placeholder",
            layout.proof_family
        );

        let decoded = verify_setup_proof_lnp_tbox_proof_bytes(
            &layout,
            &statement_hash,
            &relation_commitment_hash,
            &proof_bytes,
        )
        .expect("generated suffix verifies");

        assert_eq!(decoded.decoded_size_bytes, proof_bytes.len());
        assert_eq!(decoded.z34_seed_material_hash.len(), 128);
        assert_eq!(decoded.z34_challenge_seed_hash.len(), 128);
        assert_eq!(decoded.z34_challenge_tail_hash.len(), 128);
        assert_eq!(decoded.z34_challenge_row_domain_hash.len(), 128);
        assert_eq!(decoded.z34_challenge_z3_row_set_hash.len(), 128);
        assert_eq!(decoded.z34_challenge_z4_row_set_hash.len(), 128);
        assert_eq!(decoded.tbox_lower_protocol_challenge_hash.len(), 128);
        assert_eq!(decoded.z34_z3_check_window_hash.len(), 128);
        assert_eq!(decoded.z34_z4_check_window_hash.len(), 128);
        assert!(!decoded.z3_l2_squared.is_zero());
        assert!(!decoded.z4_infinity_norm.is_zero());
    }
}

#[test]
fn setup_proof_lnp_tbox_generated_norm_bounds_match_lazer_codegen_formula() {
    let layout = small_lnp_tbox_layout_for_test();

    assert_eq!(
        setup_proof_lnp_tbox_z3_l2_squared_bound(&layout).expect("z3 L2-squared bound"),
        BigUint::from(26_467_u64)
    );
    assert_eq!(
        setup_proof_lnp_tbox_z4_infinity_norm_bound(&layout).expect("z4 infinity bound"),
        BigUint::from(99_u64)
    );
}

#[test]
fn setup_proof_lnp_tbox_z34_challenge_profile_pins_row_domains() {
    let layout = small_lnp_tbox_layout_for_test();
    let profile = setup_proof_lnp_tbox_z34_challenge_profile_value(&layout).expect("z34 profile");
    assert_eq!(
        profile["challengeSeedByteCount"].as_u64(),
        Some(SETUP_PROOF_LNP_TBOX_Z34_CHALLENGE_SEED_BYTE_COUNT as u64)
    );
    assert_eq!(
        profile["rowExpansion"]["brandomK"].as_u64(),
        Some(SETUP_PROOF_LNP_TBOX_Z34_BRANDOM_K)
    );
    assert_eq!(
        profile["rowExpansion"]["z3RowDomainStart"].as_u64(),
        Some(SETUP_PROOF_LNP_TBOX_Z34_R_ROW_DOMAIN_START)
    );
    assert_eq!(
        profile["rowExpansion"]["z4RowDomainStart"].as_u64(),
        Some(SETUP_PROOF_LNP_TBOX_Z34_RPRIME_ROW_DOMAIN_START)
    );
    assert_eq!(
        profile["rowExpansion"]["z3RowDomainCount"].as_u64(),
        Some(SETUP_PROOF_LNP_TBOX_Z34_SEED_TOTAL_COEFFICIENTS as u64)
    );
    assert_eq!(
        profile["rowExpansion"]["z4RowDomainCount"].as_u64(),
        Some(SETUP_PROOF_LNP_TBOX_Z34_SEED_TOTAL_COEFFICIENTS as u64)
    );
    assert_eq!(
        profile["rowExpansion"]["z3RowColumnCount"].as_u64(),
        Some((layout.z3_polynomial_count * layout.proof_ring_degree) as u64)
    );
    assert_eq!(
        profile["rowExpansion"]["z4RowColumnCount"].as_u64(),
        Some((layout.z4_polynomial_count * layout.proof_ring_degree) as u64)
    );
}

#[test]
fn setup_proof_lnp_tbox_z34_brandom_row_matches_lazer_bit_planes() {
    let mut challenge_seed_bytes = [0_u8; SETUP_PROOF_LNP_TBOX_Z34_CHALLENGE_SEED_BYTE_COUNT];
    for (byte_index, byte) in challenge_seed_bytes.iter_mut().enumerate() {
        *byte = u8::try_from(byte_index).expect("test seed byte fits u8");
    }

    let row =
        setup_proof_lnp_tbox_z34_brandom_row(&challenge_seed_bytes, 7, 17).expect("brandom row");

    assert_eq!(
        row,
        vec![1, -1, 0, 1, 0, 0, 0, -1, -1, 0, 0, -1, 0, -1, 0, 0, 1]
    );
    assert!(
        row.iter()
            .all(|coefficient| [-1, 0, 1].contains(coefficient))
    );
    assert_ne!(
        setup_proof_lnp_tbox_z34_brandom_row(&challenge_seed_bytes, 7, 17).expect("same row"),
        setup_proof_lnp_tbox_z34_brandom_row(&challenge_seed_bytes, 263, 17)
            .expect("domain-separated row")
    );
}

#[test]
fn setup_proof_lnp_tbox_z34_check_window_hash_binds_signed_values() {
    let layout = small_lnp_tbox_layout_for_test();
    let mut zero_window = (0..SETUP_PROOF_LNP_TBOX_Z34_SEED_TOTAL_COEFFICIENTS)
        .map(|_| LnpTboxGaussianCoefficient {
            unary_ones: 0,
            low_bits: 0,
            low_bit_count: 3,
            value: 0,
        })
        .collect::<Vec<_>>();
    let zero_hash = setup_proof_lnp_tbox_z34_check_window_hash(&layout, "z3", &zero_window)
        .expect("zero check-window hash");

    zero_window[17].value = -3;
    let changed_hash = setup_proof_lnp_tbox_z34_check_window_hash(&layout, "z3", &zero_window)
        .expect("changed check-window hash");
    let z4_domain_hash = setup_proof_lnp_tbox_z34_check_window_hash(&layout, "z4", &zero_window)
        .expect("z4 check-window hash");

    assert_eq!(zero_hash.len(), 128);
    assert_ne!(zero_hash, changed_hash);
    assert_ne!(changed_hash, z4_domain_hash);
}

#[test]
fn setup_proof_lnp_tbox_decoder_rejects_z34_norm_bound_overflow() {
    let statement_hash = hash512_hex("test-statement", &[b"same-secret"]);
    let relation_commitment_hash = hash512_hex("test-relation", &[b"same-secret"]);
    let layout = small_lnp_tbox_layout_for_test();

    let high_z3_proof_bytes = encode_lnp_tbox_proof_for_test(
        &layout,
        &statement_hash,
        &relation_commitment_hash,
        None,
        None,
        TboxSuffixProfileForTest::NonzeroZ3AboveBound,
    )
    .expect("z3 proof bytes");
    let z3_error = verify_setup_proof_lnp_tbox_proof_bytes(
        &layout,
        &statement_hash,
        &relation_commitment_hash,
        &high_z3_proof_bytes,
    )
    .expect_err("oversized z3 should fail the generated bound");
    assert_eq!(z3_error.code, CanonicalErrorCode::InvalidProtocolObject);
    assert!(z3_error.message.contains("z3 L2-squared"));

    let high_z4_proof_bytes = encode_lnp_tbox_proof_for_test(
        &layout,
        &statement_hash,
        &relation_commitment_hash,
        None,
        None,
        TboxSuffixProfileForTest::NonzeroZ4AboveBound,
    )
    .expect("z4 proof bytes");
    let z4_error = verify_setup_proof_lnp_tbox_proof_bytes(
        &layout,
        &statement_hash,
        &relation_commitment_hash,
        &high_z4_proof_bytes,
    )
    .expect_err("oversized z4 should fail the generated bound");
    assert_eq!(z4_error.code, CanonicalErrorCode::InvalidProtocolObject);
    assert!(z4_error.message.contains("z4 infinity norm"));
}

#[test]
fn setup_proof_lnp_tbox_z34_seed_material_tracks_t_b_seed_components() {
    let statement_hash = hash512_hex("test-statement", &[b"same-secret"]);
    let relation_commitment_hash = hash512_hex("test-relation", &[b"same-secret"]);
    let layout = small_lnp_tbox_layout_for_test();
    let proof_bytes = encode_lnp_tbox_proof_for_test(
        &layout,
        &statement_hash,
        &relation_commitment_hash,
        None,
        None,
        TboxSuffixProfileForTest::Generated,
    )
    .expect("proof bytes");
    let decoded = verify_setup_proof_lnp_tbox_proof_bytes(
        &layout,
        &statement_hash,
        &relation_commitment_hash,
        &proof_bytes,
    )
    .expect("decoded proof");

    let seed_polynomial_count =
        setup_proof_lnp_tbox_z34_seed_polynomial_count(&layout).expect("seed polynomial count");
    let message_polynomial_count =
        setup_proof_lnp_tbox_message_polynomial_count(&layout).expect("message polynomial count");
    assert_eq!(seed_polynomial_count, 2);
    assert_eq!(message_polynomial_count, 1);
    let mut changed_t_b = decoded.t_b_coefficients.clone();
    let ty3_first_coefficient = message_polynomial_count * layout.proof_ring_degree;
    changed_t_b[ty3_first_coefficient] += BigUint::one();
    if changed_t_b[ty3_first_coefficient] >= layout.proof_modulus {
        changed_t_b[ty3_first_coefficient] = BigUint::zero();
    }
    let changed_seed = setup_proof_lnp_tbox_z34_seed_material(
        &layout,
        &statement_hash,
        &relation_commitment_hash,
        &changed_t_b,
    )
    .expect("changed seed material");

    assert_ne!(
        changed_seed.seed_material_hash,
        decoded.z34_seed_material_hash
    );
    assert_ne!(
        changed_seed.challenge_seed_hex,
        decoded.z34_challenge_seed_hex
    );
    assert_ne!(
        changed_seed.challenge_seed_hash,
        decoded.z34_challenge_seed_hash
    );
    assert_ne!(
        changed_seed.challenge_tail_hash,
        decoded.z34_challenge_tail_hash
    );
    assert_ne!(
        changed_seed.challenge_row_domain_hash,
        decoded.z34_challenge_row_domain_hash
    );
    assert_ne!(
        changed_seed.challenge_z3_row_set_hash,
        decoded.z34_challenge_z3_row_set_hash
    );
    assert_ne!(
        changed_seed.challenge_z4_row_set_hash,
        decoded.z34_challenge_z4_row_set_hash
    );
}

#[test]
fn setup_proof_lnp_tbox_z34_tail_hash_tracks_t_b_tail_components() {
    let statement_hash = hash512_hex("test-statement", &[b"same-secret"]);
    let relation_commitment_hash = hash512_hex("test-relation", &[b"same-secret"]);
    let layout = small_lnp_tbox_layout_for_test();
    let proof_bytes = encode_lnp_tbox_proof_for_test(
        &layout,
        &statement_hash,
        &relation_commitment_hash,
        None,
        None,
        TboxSuffixProfileForTest::Generated,
    )
    .expect("proof bytes");
    let decoded = verify_setup_proof_lnp_tbox_proof_bytes(
        &layout,
        &statement_hash,
        &relation_commitment_hash,
        &proof_bytes,
    )
    .expect("decoded proof");

    let seed_polynomial_count =
        setup_proof_lnp_tbox_z34_seed_polynomial_count(&layout).expect("seed polynomial count");
    let message_polynomial_count =
        setup_proof_lnp_tbox_message_polynomial_count(&layout).expect("message polynomial count");
    let challenge_tail_start = message_polynomial_count
        .checked_add(seed_polynomial_count * 2)
        .and_then(|start| start.checked_add(1))
        .expect("challenge-tail start");
    let challenge_tail_first_coefficient = challenge_tail_start * layout.proof_ring_degree;
    let mut changed_t_b = decoded.t_b_coefficients.clone();
    changed_t_b[challenge_tail_first_coefficient] += BigUint::one();
    if changed_t_b[challenge_tail_first_coefficient] >= layout.proof_modulus {
        changed_t_b[challenge_tail_first_coefficient] = BigUint::zero();
    }
    let changed_seed = setup_proof_lnp_tbox_z34_seed_material(
        &layout,
        &statement_hash,
        &relation_commitment_hash,
        &changed_t_b,
    )
    .expect("changed seed material");

    assert_eq!(
        changed_seed.seed_material_hash,
        decoded.z34_seed_material_hash
    );
    assert_ne!(
        changed_seed.challenge_tail_hash,
        decoded.z34_challenge_tail_hash
    );
    let changed_challenge_material = setup_proof_lnp_tbox_challenge_material(
        &layout,
        &statement_hash,
        &relation_commitment_hash,
        &changed_seed,
    )
    .expect("changed lower-protocol challenge");
    assert_ne!(
        changed_challenge_material.lower_protocol_challenge_hash,
        decoded.tbox_lower_protocol_challenge_hash
    );
    assert_ne!(
        changed_challenge_material.challenge_coefficients,
        decoded.challenge_coefficients
    );
}

#[test]
fn setup_proof_lnp_tbox_layout_rejects_missing_z34_seed_material() {
    let mut layout = small_lnp_tbox_layout_for_test();
    layout.t_b_polynomial_count = 6;

    let error = validate_lnp_tbox_layout(&layout)
        .expect_err("layout without ty3, ty4, beta, and tail space must fail");

    assert!(error.message.contains("too small for z3/z4 seed material"));
}

#[test]
fn setup_proof_lnp_hint_decoder_matches_lazer_signed_values() {
    assert_eq!(
        decode_lnp_tbox_hint_value(false, false, 0).expect("zero hint"),
        0
    );
    assert_eq!(
        decode_lnp_tbox_hint_value(false, true, 0).expect("one hint"),
        1
    );
    assert_eq!(
        decode_lnp_tbox_hint_value(true, false, 0).expect("minus one hint"),
        -1
    );
    assert_eq!(
        decode_lnp_tbox_hint_value(true, true, 0).expect("positive extended hint"),
        2
    );
    assert_eq!(
        decode_lnp_tbox_hint_value(true, true, 1).expect("negative extended hint"),
        -2
    );
    assert_eq!(
        decode_lnp_tbox_hint_value(true, true, 4).expect("larger positive extended hint"),
        4
    );
    assert_eq!(
        decode_lnp_tbox_hint_value(true, true, 5).expect("larger negative extended hint"),
        -4
    );
}

#[test]
fn setup_proof_lnp_gaussian_decoder_matches_lazer_signed_values() {
    assert_eq!(
        decode_lnp_tbox_gaussian_value(0, 0, 3).expect("zero Gaussian"),
        0
    );
    assert_eq!(
        decode_lnp_tbox_gaussian_value(0, 7, 3).expect("negative low bits"),
        -1
    );
    assert_eq!(
        decode_lnp_tbox_gaussian_value(1, 0, 3).expect("positive quotient"),
        8
    );
    assert_eq!(
        decode_lnp_tbox_gaussian_value(1, 7, 3).expect("positive quotient negative low bits"),
        7
    );
    assert_eq!(
        decode_lnp_tbox_gaussian_value(2, 0, 3).expect("negative quotient"),
        -8
    );
    assert_eq!(
        decode_lnp_tbox_gaussian_value(3, 3, 3).expect("larger positive quotient"),
        19
    );
}

#[test]
fn setup_proof_lnp_tbox_decoder_rejects_noncanonical_uniform_residue() {
    let statement_hash = hash512_hex("test-statement", &[b"same-secret"]);
    let relation_commitment_hash = hash512_hex("test-relation", &[b"same-secret"]);
    let layout = small_lnp_tbox_layout_for_test();
    let dummy_challenge = vec![0_i64; layout.proof_ring_degree];
    let proof_bytes = encode_lnp_tbox_proof_for_test(
        &layout,
        &statement_hash,
        &relation_commitment_hash,
        Some(&dummy_challenge),
        Some(layout.proof_modulus.clone()),
        TboxSuffixProfileForTest::Generated,
    )
    .expect("proof bytes");

    let error = verify_setup_proof_lnp_tbox_proof_bytes(
        &layout,
        &statement_hash,
        &relation_commitment_hash,
        &proof_bytes,
    )
    .expect_err("noncanonical residue should fail");

    assert_eq!(error.code, CanonicalErrorCode::InvalidProtocolObject);
    assert!(error.message.contains("tB"));
}

#[test]
fn setup_proof_lnp_tbox_decoder_rejects_nonzero_h_forced_zero_position() {
    let statement_hash = hash512_hex("test-statement", &[b"same-secret"]);
    let relation_commitment_hash = hash512_hex("test-relation", &[b"same-secret"]);
    let layout = small_lnp_tbox_layout_for_test();
    let mut proof_bytes = encode_lnp_tbox_proof_for_test(
        &layout,
        &statement_hash,
        &relation_commitment_hash,
        None,
        None,
        TboxSuffixProfileForTest::Generated,
    )
    .expect("proof bytes");
    let h_bit_offset =
        layout.t_b_polynomial_count * layout.proof_ring_degree * layout.proof_modulus_bit_count;
    proof_bytes[h_bit_offset / 8] |= 1 << (h_bit_offset % 8);

    let error = verify_setup_proof_lnp_tbox_proof_bytes(
        &layout,
        &statement_hash,
        &relation_commitment_hash,
        &proof_bytes,
    )
    .expect_err("nonzero forced h coefficient should fail");

    assert_eq!(error.code, CanonicalErrorCode::InvalidProtocolObject);
    assert!(error.message.contains("h coefficients"));
}

#[test]
fn setup_proof_lnp_tbox_decoder_rejects_challenge_drift_and_trailing_bytes() {
    let statement_hash = hash512_hex("test-statement", &[b"same-secret"]);
    let relation_commitment_hash = hash512_hex("test-relation", &[b"same-secret"]);
    let layout = small_lnp_tbox_layout_for_test();
    let valid_proof_bytes = encode_lnp_tbox_proof_for_test(
        &layout,
        &statement_hash,
        &relation_commitment_hash,
        None,
        None,
        TboxSuffixProfileForTest::Generated,
    )
    .expect("valid proof bytes");
    let mut challenge = verify_setup_proof_lnp_tbox_proof_bytes(
        &layout,
        &statement_hash,
        &relation_commitment_hash,
        &valid_proof_bytes,
    )
    .expect("valid proof bytes should decode")
    .challenge_coefficients;
    challenge[0] = if challenge[0] == 2 {
        1
    } else {
        challenge[0] + 1
    };
    let proof_bytes = encode_lnp_tbox_proof_for_test(
        &layout,
        &statement_hash,
        &relation_commitment_hash,
        Some(&challenge),
        None,
        TboxSuffixProfileForTest::Generated,
    )
    .expect("proof bytes");

    let challenge_error = verify_setup_proof_lnp_tbox_proof_bytes(
        &layout,
        &statement_hash,
        &relation_commitment_hash,
        &proof_bytes,
    )
    .expect_err("challenge drift should fail");

    assert_eq!(
        challenge_error.code,
        CanonicalErrorCode::InvalidProtocolObject
    );
    assert!(challenge_error.message.contains("challenge"));

    let mut trailing_bytes = encode_lnp_tbox_proof_for_test(
        &layout,
        &statement_hash,
        &relation_commitment_hash,
        None,
        None,
        TboxSuffixProfileForTest::Generated,
    )
    .expect("proof bytes");
    trailing_bytes.push(0);
    let trailing_error = verify_setup_proof_lnp_tbox_proof_bytes(
        &layout,
        &statement_hash,
        &relation_commitment_hash,
        &trailing_bytes,
    )
    .expect_err("trailing byte should fail");

    assert_eq!(trailing_error.code, CanonicalErrorCode::TrailingBytes);
}

#[test]
fn setup_proof_lnp_tbox_decoder_rejects_noncanonical_generated_suffix() {
    let statement_hash = hash512_hex("test-statement", &[b"same-secret"]);
    let relation_commitment_hash = hash512_hex("test-relation", &[b"same-secret"]);
    let layout = small_lnp_tbox_layout_for_test();

    let nonzero_hint_proof_bytes = encode_lnp_tbox_proof_for_test(
        &layout,
        &statement_hash,
        &relation_commitment_hash,
        None,
        None,
        TboxSuffixProfileForTest::NonzeroHint,
    )
    .expect("proof bytes");
    let hint_error = verify_setup_proof_lnp_tbox_proof_bytes(
        &layout,
        &statement_hash,
        &relation_commitment_hash,
        &nonzero_hint_proof_bytes,
    )
    .expect_err("noncanonical generated hint should fail");
    assert_eq!(hint_error.code, CanonicalErrorCode::InvalidProtocolObject);
    assert!(hint_error.message.contains("generated suffix"));

    let nonzero_gaussian_proof_bytes = encode_lnp_tbox_proof_for_test(
        &layout,
        &statement_hash,
        &relation_commitment_hash,
        None,
        None,
        TboxSuffixProfileForTest::NonzeroGaussian,
    )
    .expect("proof bytes");
    let gaussian_error = verify_setup_proof_lnp_tbox_proof_bytes(
        &layout,
        &statement_hash,
        &relation_commitment_hash,
        &nonzero_gaussian_proof_bytes,
    )
    .expect_err("noncanonical generated Gaussian should fail");
    assert_eq!(
        gaussian_error.code,
        CanonicalErrorCode::InvalidProtocolObject
    );
    assert!(gaussian_error.message.contains("generated suffix"));
}

fn small_lnp_tbox_layout_for_test() -> SetupProofLnpTboxLayout {
    SetupProofLnpTboxLayout {
        proof_family: "same-secret-consistency",
        tbox_parameter_profile_id: SAME_SECRET_LNP_TBOX_PARAMETER_PROFILE_ID,
        tbox_commitment_prefix_hash_domain: "sealed-lattice/setup/same-secret/lnp-tbox-commitment-prefix-v1",
        proof_ring_degree: SETUP_PROOF_LNP_PROOF_RING_DEGREE,
        proof_modulus: BigUint::from(12_289_u64),
        proof_modulus_bit_count: 14,
        compression_dropped_bits: 3,
        t_b_polynomial_count: 11,
        h_polynomial_count: 4,
        t_a1_polynomial_count: 1,
        hint_polynomial_count: 1,
        z1_polynomial_count: 1,
        z21_polynomial_count: 1,
        z3_polynomial_count: 2,
        z4_polynomial_count: 2,
        z1_log2_standard_deviation: 2,
        z21_log2_standard_deviation: 2,
        z3_log2_standard_deviation: 2,
        z4_log2_standard_deviation: 2,
    }
}

fn encode_lnp_tbox_proof_for_test(
    layout: &SetupProofLnpTboxLayout,
    statement_hash_hex: &str,
    relation_commitment_hash_hex: &str,
    challenge_override: Option<&[i64]>,
    first_t_b_residue_override: Option<BigUint>,
    suffix_profile: TboxSuffixProfileForTest,
) -> CanonicalResult<Vec<u8>> {
    let has_first_t_b_residue_override = first_t_b_residue_override.is_some();
    let mut writer = LnpBitWriterForTest::new();
    encode_uniform_polyvec_for_test(
        &mut writer,
        layout.t_b_polynomial_count,
        layout.proof_ring_degree,
        layout.proof_modulus_bit_count,
        first_t_b_residue_override,
        false,
    )?;
    encode_uniform_polyvec_for_test(
        &mut writer,
        layout.h_polynomial_count,
        layout.proof_ring_degree,
        layout.proof_modulus_bit_count,
        None,
        true,
    )?;
    encode_uniform_polyvec_for_test(
        &mut writer,
        layout.t_a1_polynomial_count,
        layout.proof_ring_degree,
        layout.proof_modulus_bit_count - layout.compression_dropped_bits,
        None,
        false,
    )?;
    if suffix_profile == TboxSuffixProfileForTest::Generated
        && challenge_override.is_none()
        && !has_first_t_b_residue_override
    {
        let prefix_bytes = writer.into_bytes();
        let suffix_bytes = setup_proof_lnp_tbox_generated_suffix_bytes(
            layout,
            statement_hash_hex,
            relation_commitment_hash_hex,
            &prefix_bytes,
        )?;
        let mut proof_bytes = prefix_bytes;
        proof_bytes.extend_from_slice(&suffix_bytes);
        return Ok(proof_bytes);
    }
    let derived_challenge;
    let challenge_coefficients = if let Some(challenge_override) = challenge_override {
        challenge_override
    } else {
        derived_challenge = derive_setup_proof_lnp_tbox_challenge_from_prefix(
            layout,
            statement_hash_hex,
            relation_commitment_hash_hex,
            writer.bytes(),
        )?;
        &derived_challenge.challenge_coefficients
    };
    for coefficient in challenge_coefficients {
        let shifted = coefficient
            .checked_add(i64::try_from(SETUP_PROOF_CHALLENGE_COEFFICIENT_BOUND).unwrap())
            .ok_or_else(|| setup_proof_error("test challenge coefficient overflowed"))?;
        writer.write_u64_le_bits(
            u64::try_from(shifted)
                .map_err(|_| setup_proof_error("test challenge coefficient was negative"))?,
            SETUP_PROOF_LNP_CHALLENGE_LOG2_RANGE,
        );
    }
    let hint_count = layout
        .hint_polynomial_count
        .checked_mul(layout.proof_ring_degree)
        .ok_or_else(|| setup_proof_error("test hint count overflowed"))?;
    for coefficient_index in 0..hint_count {
        match (suffix_profile, coefficient_index) {
            (TboxSuffixProfileForTest::NonzeroHint, 0) => {
                writer.write_bit(true);
                writer.write_bit(false);
            }
            _ => {
                writer.write_bit(false);
                writer.write_bit(false);
            }
        }
    }
    for (field, polynomial_count, log2_standard_deviation) in [
        (
            TboxGaussianFieldForTest::Z1,
            layout.z1_polynomial_count,
            layout.z1_log2_standard_deviation,
        ),
        (
            TboxGaussianFieldForTest::Z21,
            layout.z21_polynomial_count,
            layout.z21_log2_standard_deviation,
        ),
        (
            TboxGaussianFieldForTest::Z3,
            layout.z3_polynomial_count,
            layout.z3_log2_standard_deviation,
        ),
        (
            TboxGaussianFieldForTest::Z4,
            layout.z4_polynomial_count,
            layout.z4_log2_standard_deviation,
        ),
    ] {
        let coefficient_count = polynomial_count
            .checked_mul(layout.proof_ring_degree)
            .ok_or_else(|| setup_proof_error("test gaussian count overflowed"))?;
        for coefficient_index in 0..coefficient_count {
            if suffix_profile == TboxSuffixProfileForTest::NonzeroGaussian && coefficient_index == 0
            {
                write_gaussian_coefficient_for_test(&mut writer, log2_standard_deviation, 2, 3);
            } else if suffix_profile == TboxSuffixProfileForTest::NonzeroZ3AboveBound
                && field == TboxGaussianFieldForTest::Z3
                && coefficient_index == 0
            {
                write_gaussian_coefficient_for_test(&mut writer, log2_standard_deviation, 41, 0);
            } else if suffix_profile == TboxSuffixProfileForTest::NonzeroZ4AboveBound
                && field == TboxGaussianFieldForTest::Z4
                && coefficient_index == 0
            {
                write_gaussian_coefficient_for_test(&mut writer, log2_standard_deviation, 25, 0);
            } else {
                write_gaussian_coefficient_for_test(&mut writer, log2_standard_deviation, 0, 0);
            }
        }
    }
    writer.finish_lazer_padding();

    Ok(writer.into_bytes())
}

fn write_gaussian_coefficient_for_test(
    writer: &mut LnpBitWriterForTest,
    log2_standard_deviation: usize,
    unary_ones: usize,
    low_bits: u64,
) {
    for _ in 0..unary_ones {
        writer.write_bit(true);
    }
    writer.write_bit(false);
    writer.write_u64_le_bits(low_bits, log2_standard_deviation + 1);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TboxSuffixProfileForTest {
    Generated,
    NonzeroHint,
    NonzeroGaussian,
    NonzeroZ3AboveBound,
    NonzeroZ4AboveBound,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TboxGaussianFieldForTest {
    Z1,
    Z21,
    Z3,
    Z4,
}

fn encode_uniform_polyvec_for_test(
    writer: &mut LnpBitWriterForTest,
    polynomial_count: usize,
    proof_ring_degree: usize,
    bit_count: usize,
    first_residue_override: Option<BigUint>,
    force_lnp_tbox_h_zero_positions: bool,
) -> CanonicalResult<()> {
    let coefficient_count = polynomial_count
        .checked_mul(proof_ring_degree)
        .ok_or_else(|| setup_proof_error("test uniform count overflowed"))?;
    for coefficient_index in 0..coefficient_count {
        if force_lnp_tbox_h_zero_positions
            && setup_proof_lnp_tbox_h_coefficient_must_be_zero(coefficient_index, proof_ring_degree)
        {
            writer.write_u64_le_bits(0, bit_count);
            continue;
        }
        if coefficient_index == 0
            && let Some(value) = first_residue_override.as_ref()
        {
            writer.write_big_uint_le_bits(value, bit_count);
            continue;
        }
        writer.write_u64_le_bits(
            u64::try_from(coefficient_index)
                .map_err(|_| setup_proof_error("test coefficient index overflowed"))?,
            bit_count,
        );
    }

    Ok(())
}

struct LnpBitWriterForTest {
    bytes: Vec<u8>,
    bit_offset: usize,
}

impl LnpBitWriterForTest {
    fn new() -> Self {
        Self {
            bytes: vec![0],
            bit_offset: 0,
        }
    }

    fn write_bit(&mut self, bit: bool) {
        let byte_index = self.bit_offset / 8;
        let bit_index = self.bit_offset % 8;
        if byte_index == self.bytes.len() {
            self.bytes.push(0);
        }
        if bit {
            self.bytes[byte_index] |= 1 << bit_index;
        }
        self.bit_offset += 1;
    }

    fn write_u64_le_bits(&mut self, value: u64, bit_count: usize) {
        for bit_index in 0..bit_count {
            let bit = if bit_index < u64::BITS as usize {
                ((value >> bit_index) & 1) == 1
            } else {
                false
            };
            self.write_bit(bit);
        }
    }

    fn write_big_uint_le_bits(&mut self, value: &BigUint, bit_count: usize) {
        let digits = value.to_u64_digits();
        for bit_index in 0..bit_count {
            let digit_index = bit_index / 64;
            let digit_bit_index = bit_index % 64;
            let bit = digits
                .get(digit_index)
                .map(|digit| ((digit >> digit_bit_index) & 1) == 1)
                .unwrap_or(false);
            self.write_bit(bit);
        }
    }

    fn finish_lazer_padding(&mut self) {
        self.write_bit(true);
        while !self.bit_offset.is_multiple_of(8) {
            self.write_bit(false);
        }
    }

    fn bytes(&self) -> &[u8] {
        &self.bytes[..self.bit_offset.div_ceil(8)]
    }

    fn into_bytes(mut self) -> Vec<u8> {
        let used_bytes = self.bit_offset.div_ceil(8);
        self.bytes.truncate(used_bytes);
        self.bytes
    }
}
