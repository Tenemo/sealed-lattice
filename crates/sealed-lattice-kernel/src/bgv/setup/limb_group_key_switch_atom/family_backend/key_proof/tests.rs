use super::super::super::proof_field::sixteen_limb_group_field_parameters;
use super::super::test_support::build_synthetic_key_fixture;
use super::*;

#[test]
fn coefficient_space_combination_matches_codeword_space_reference_including_shifted_g() {
    let parameters = sixteen_limb_group_field_parameters();
    for trace_size in [16_usize, 64] {
        let coset_size = FRI_RATE_BLOWUP * 2 * trace_size;
        let coset_domain = CyclicDomain::new(&parameters, coset_size).expect("coset domain");
        let offset = coset_offset(&parameters);
        let coefficient_vectors: Vec<Vec<[u64; 13]>> = [
            trace_size / 2 + 1,
            trace_size,
            2 * trace_size - 3,
            trace_size - 1,
        ]
        .into_iter()
        .enumerate()
        .map(|(vector_index, coefficient_count)| {
            (0..coefficient_count)
                .map(|coefficient_index| {
                    parameters.unsigned_word_to_element(
                        17 + vector_index as u64 * 101 + coefficient_index as u64 * 13,
                    )
                })
                .collect()
        })
        .collect();
        let weights: Vec<[u64; 13]> = (0..=coefficient_vectors.len())
            .map(|index| parameters.unsigned_word_to_element(29 + index as u64 * 31))
            .collect();

        let mut codeword_space_reference = vec![parameters.zero(); coset_size];
        for (coefficients, weight) in coefficient_vectors.iter().zip(weights.iter()) {
            let extended = coset_evaluate_coefficients(&coset_domain, &offset, coefficients);
            for (combined_value, value) in codeword_space_reference.iter_mut().zip(extended) {
                *combined_value =
                    parameters.add(combined_value, &parameters.multiply(weight, &value));
            }
        }
        let g_coefficients = &coefficient_vectors[3];
        let shifted_g_degree = g_degree_adjustment_shift(trace_size);
        let mut shifted_g = vec![parameters.zero(); shifted_g_degree];
        shifted_g.extend_from_slice(g_coefficients);
        let shifted_g_extended = coset_evaluate_coefficients(&coset_domain, &offset, &shifted_g);
        for (combined_value, value) in codeword_space_reference.iter_mut().zip(shifted_g_extended) {
            *combined_value = parameters.add(
                combined_value,
                &parameters.multiply(&weights[coefficient_vectors.len()], &value),
            );
        }

        let mut coefficient_space_combination = vec![parameters.zero(); coset_size];
        for (coefficients, weight) in coefficient_vectors.iter().zip(weights.iter()) {
            super::prove::accumulate_weighted_coefficients(
                &parameters,
                &mut coefficient_space_combination,
                weight,
                coefficients,
                0,
            );
        }
        super::prove::accumulate_weighted_coefficients(
            &parameters,
            &mut coefficient_space_combination,
            &weights[coefficient_vectors.len()],
            g_coefficients,
            shifted_g_degree,
        );
        coset_evaluate_coefficients_in_place(
            &coset_domain,
            &offset,
            &mut coefficient_space_combination,
        );

        assert_eq!(
            coefficient_space_combination, codeword_space_reference,
            "coefficient-space fusion must preserve the exact combined codeword at trace size {trace_size}"
        );
    }
}

// The univariate-sumcheck helper `g` must have degree at most trace_size - 2;
// otherwise its spare top coefficient can absorb a false sum. Shifting `g` by
// `g_degree_adjustment_shift` makes the shared FRI bound enforce that exact
// boundary.
#[test]
fn g_degree_adjustment_rejects_helper_above_the_sumcheck_bound() {
    let parameters = sixteen_limb_group_field_parameters();
    let trace_size = 64;
    // The layout's coset: FRI_RATE_BLOWUP * 2 * trace_size, rate 1/4, so the
    // combined codeword bound is 2 * trace_size.
    let coset_size = FRI_RATE_BLOWUP * 2 * trace_size;
    let coset_domain = CyclicDomain::new(&parameters, coset_size).expect("coset domain");
    let offset = coset_offset(&parameters);
    let shift = g_degree_adjustment_shift(trace_size);
    let fri_parameters = FriParameters {
        blowup: FRI_RATE_BLOWUP,
    };

    // Whether `x^shift * g` (for a `g` with a nonzero top coefficient at
    // `g_degree`) passes the shared FRI degree bound, mirroring the prover's
    // shifted-g codeword and the verifier's FRI structure/query checks.
    let shifted_g_passes_fri = |g_degree: usize| -> bool {
        let g: Vec<[u64; 13]> = (0..=g_degree)
            .map(|index| parameters.unsigned_word_to_element(index as u64 * 7 + 1))
            .collect();
        let mut shifted = vec![parameters.zero(); shift];
        shifted.extend_from_slice(&g);
        let codeword = coset_evaluate_coefficients(&coset_domain, &offset, &shifted);

        let mut private_randomness = PrivateProofRandomness::for_test(0xa7c3);
        let mut prover_transcript = Transcript::new(PROTOCOL_LABEL);
        let commitment = fri_commit(
            &parameters,
            &mut prover_transcript,
            &codeword,
            &offset,
            &mut private_randomness,
        )
        .expect("fri commit");
        let query_positions = prover_transcript.challenge_positions("key-query", coset_size, 40);
        let fri = fri_answer(&commitment, &query_positions);

        let mut verifier_transcript = Transcript::new(PROTOCOL_LABEL);
        let Some(verification) = fri_verify_structure(
            &parameters,
            &mut verifier_transcript,
            &fri,
            coset_size,
            &offset,
            &fri_parameters,
        )
        .expect("fri structure") else {
            return false;
        };
        let verifier_positions =
            verifier_transcript.challenge_positions("key-query", coset_size, 40);
        fri_verify_queries(&parameters, &verification, &fri, &verifier_positions)
    };

    assert!(
        shifted_g_passes_fri(trace_size - 2),
        "an honest sumcheck helper (degree trace_size - 2) must pass the shifted FRI bound"
    );
    assert!(
        !shifted_g_passes_fri(trace_size - 1),
        "a sumcheck helper of degree trace_size - 1 must fail the shifted FRI bound"
    );
}

#[test]
fn honest_multi_digit_key_verifies() {
    let parameters = sixteen_limb_group_field_parameters();
    let ring_degree = 64;
    for digit_count in [1_usize, 3, 8] {
        let (secret, digits, public) =
            build_synthetic_key_fixture(ring_degree, digit_count, &KeySource::RoundOne);
        let proof_parameters = KeyFriProofParameters {
            query_count: 40,
            mask_degree: 0,
        };
        let mut private_randomness = PrivateProofRandomness::for_test(0x1234 + digit_count as u64);
        let proof = prove_round_one_key_fri(
            &parameters,
            ring_degree,
            &public,
            &secret,
            &digits,
            &proof_parameters,
            &mut private_randomness,
        )
        .expect("prove");
        assert!(
            verify_round_one_key_fri(&parameters, ring_degree, &public, &proof, &proof_parameters)
                .expect("verify"),
            "honest {digit_count}-digit key must verify"
        );
    }
}

#[test]
fn prover_and_verifier_transcript_order_matches() {
    use crate::bgv::setup::transcript_order_audit::{
        capture_transcript_order_audit, run_length_encode_transcript_order_audit,
    };

    let parameters = sixteen_limb_group_field_parameters();
    let ring_degree = 64;
    let (secret, digits, public) =
        build_synthetic_key_fixture(ring_degree, 3, &KeySource::RoundOne);
    let proof_parameters = KeyFriProofParameters {
        query_count: 40,
        mask_degree: 16,
    };
    let mut private_randomness = PrivateProofRandomness::for_test(0x5a17);
    let (proof_result, prover_events) = capture_transcript_order_audit(|| {
        prove_round_one_key_fri(
            &parameters,
            ring_degree,
            &public,
            &secret,
            &digits,
            &proof_parameters,
            &mut private_randomness,
        )
    });
    let proof = proof_result.expect("audit proof generation");
    let (verification_result, verifier_events) = capture_transcript_order_audit(|| {
        verify_round_one_key_fri(&parameters, ring_degree, &public, &proof, &proof_parameters)
    });

    assert!(verification_result.expect("audit proof verification"));
    assert_eq!(prover_events, verifier_events);
    let transcripts = run_length_encode_transcript_order_audit(&prover_events);
    let audit_artifact = serde_json::json!({
        "proofFamily": "limb-group-key-switch-atom",
        "fixture": {
            "digitCount": 3,
            "maskDegree": 16,
            "queryCount": 40,
            "ringDegree": ring_degree,
        },
        "transcripts": transcripts,
    });
    let expected_artifact: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/fiat-shamir-limb-group-key-switch-atom-transcript-order.json"
    )))
    .expect("parse transcript-order audit artifact");
    assert_eq!(audit_artifact, expected_artifact);
}

#[test]
fn masked_multi_digit_key_verifies() {
    let parameters = sixteen_limb_group_field_parameters();
    let ring_degree = 64;
    let (secret, digits, public) =
        build_synthetic_key_fixture(ring_degree, 4, &KeySource::RoundOne);
    let proof_parameters = KeyFriProofParameters {
        query_count: 40,
        mask_degree: 16,
    };
    let mut private_randomness = PrivateProofRandomness::for_test(0x5eed);
    let proof = prove_round_one_key_fri(
        &parameters,
        ring_degree,
        &public,
        &secret,
        &digits,
        &proof_parameters,
        &mut private_randomness,
    )
    .expect("prove");
    assert!(
        verify_round_one_key_fri(&parameters, ring_degree, &public, &proof, &proof_parameters)
            .expect("verify")
    );
}

#[test]
fn one_tampered_digit_error_is_caught_by_the_batch() {
    // Flip one digit's error in a way that breaks its congruence (and its
    // eta-2 support). The per-digit batching challenge makes the combined
    // claim miss, and the support constraint fails, so the prover cannot
    // build a valid proof or the verifier rejects.
    let parameters = sixteen_limb_group_field_parameters();
    let ring_degree = 64;
    let (secret, mut digits, public) =
        build_synthetic_key_fixture(ring_degree, 5, &KeySource::RoundOne);
    digits[2].error[7] = 3; // out of eta-2 range and breaks the congruence
    let proof_parameters = KeyFriProofParameters {
        query_count: 40,
        mask_degree: 0,
    };
    let mut private_randomness = PrivateProofRandomness::for_test(0x9);
    let result = prove_round_one_key_fri(
        &parameters,
        ring_degree,
        &public,
        &secret,
        &digits,
        &proof_parameters,
        &mut private_randomness,
    );
    match result {
        Err(_) => {}
        Ok(proof) => assert!(
            !verify_round_one_key_fri(&parameters, ring_degree, &public, &proof, &proof_parameters)
                .expect("verify"),
            "a tampered digit must not yield an accepted key proof"
        ),
    }
}

#[test]
fn honest_committed_component_material_verifies() {
    // The prover commits the public material through its dedicated material
    // columns and sumcheck forms, both unmasked and masked.
    let parameters = sixteen_limb_group_field_parameters();
    let ring_degree = 64;
    let (secret, digits, public) =
        build_synthetic_key_fixture(ring_degree, 4, &KeySource::RoundOne);
    let honest: Vec<Vec<[u64; 13]>> = public
        .digits
        .iter()
        .map(|digit| digit.recombined_component_b.clone())
        .collect();
    for mask_degree in [0_usize, 16] {
        let component_b: Vec<&[[u64; 13]]> =
            honest.iter().map(|values| values.as_slice()).collect();
        let proof_parameters = KeyFriProofParameters {
            query_count: 40,
            mask_degree,
        };
        let mut private_randomness =
            PrivateProofRandomness::for_test(0xc0ff_ee22 + mask_degree as u64);
        let proof = prove_key_fri_with_component_b(
            &parameters,
            ring_degree,
            &public,
            &KeySource::RoundOne,
            &secret,
            &digits,
            component_b,
            None,
            &ZERO_STATEMENT_BINDING,
            0,
            &proof_parameters,
            &mut private_randomness,
        )
        .expect("prove");
        assert!(
            verify_key_fri(
                &parameters,
                ring_degree,
                &public,
                &KeySource::RoundOne,
                &proof,
                None,
                &ZERO_STATEMENT_BINDING,
                0,
                &proof_parameters,
            )
            .expect("verify"),
            "committing the public material must verify (mask_degree {mask_degree})"
        );
    }
}

#[test]
fn tampered_committed_component_material_is_rejected_by_the_relation() {
    // The batched sumcheck folds committed `B_col_j` with `delta_j * gamma` on
    // the left side of `B + A(*)s - t e - G source - Q c = 0`. Changing one
    // coefficient therefore breaks the relation even when every other column
    // and transcript-bound input is unchanged.
    let parameters = sixteen_limb_group_field_parameters();
    let ring_degree = 64;
    let (secret, digits, public) =
        build_synthetic_key_fixture(ring_degree, 4, &KeySource::RoundOne);
    let mut tampered: Vec<Vec<[u64; 13]>> = public
        .digits
        .iter()
        .map(|digit| digit.recombined_component_b.clone())
        .collect();
    tampered[1][9] = parameters.add(&tampered[1][9], &parameters.one());
    // Both unmasked and masked: the material column rides the same masking idiom
    // as the base columns, and neither hides a wrong committed value.
    for mask_degree in [0_usize, 16] {
        let component_b: Vec<&[[u64; 13]]> =
            tampered.iter().map(|values| values.as_slice()).collect();
        let proof_parameters = KeyFriProofParameters {
            query_count: 40,
            mask_degree,
        };
        let mut private_randomness =
            PrivateProofRandomness::for_test(0xc0ff_ee11 + mask_degree as u64);
        let result = prove_key_fri_with_component_b(
            &parameters,
            ring_degree,
            &public,
            &KeySource::RoundOne,
            &secret,
            &digits,
            component_b,
            None,
            &ZERO_STATEMENT_BINDING,
            0,
            &proof_parameters,
            &mut private_randomness,
        );
        match result {
            Err(_) => {}
            Ok(proof) => assert!(
                !verify_key_fri(
                    &parameters,
                    ring_degree,
                    &public,
                    &KeySource::RoundOne,
                    &proof,
                    None,
                    &ZERO_STATEMENT_BINDING,
                    0,
                    &proof_parameters,
                )
                .expect("verify runs"),
                "a committed material that breaks the relation must not verify \
                 (mask_degree {mask_degree})"
            ),
        }
    }
}

#[test]
fn out_of_range_carry_is_rejected() {
    // A carry outside `|c| <= N+1`, with the component rebuilt so the
    // congruence still holds: the shifted carry is not a value in the logUp
    // range table, so its lookup fraction has no matching table term and the
    // multiset balance (the sumcheck-bound terminals plus their cross-check)
    // fails, so the prover or verifier rejects. This guards the carry range
    // against admitting a carry large enough to break the field no-wrap bound.
    use super::super::super::negacyclic_transform::NegacyclicDomain;
    let parameters = sixteen_limb_group_field_parameters();
    let ring_degree = 64;
    let domain = NegacyclicDomain::new(&parameters, ring_degree).expect("domain");
    let secret: Vec<i64> = (0..ring_degree).map(|i| ((i * 7) % 3) as i64 - 1).collect();
    let secret_field: Vec<[u64; 13]> = secret
        .iter()
        .map(|v| parameters.signed_word_to_element(*v))
        .collect();
    let group_modulus = parameters.unsigned_word_to_element(1_000_003);
    let plaintext_modulus = parameters.unsigned_word_to_element(65_537);
    let error: Vec<i64> = (0..ring_degree).map(|i| ((i * 5) % 5) as i64 - 2).collect();
    let mut carry: Vec<i64> = (0..ring_degree).map(|i| (i % 3) as i64 - 1).collect();
    // Well beyond `|c| <= N+1` and the relation's no-wrap bound.
    carry[3] = (ring_degree as i64) * 3;
    let error_field: Vec<[u64; 13]> = error
        .iter()
        .map(|v| parameters.signed_word_to_element(*v))
        .collect();
    let carry_field: Vec<[u64; 13]> = carry
        .iter()
        .map(|v| parameters.signed_word_to_element(*v))
        .collect();
    let mut sample = Vec::with_capacity(ring_degree);
    let mut state = 0xa5_u64;
    for _ in 0..ring_degree {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        sample.push(parameters.unsigned_word_to_element(state));
    }
    let gadget_idempotent = parameters.unsigned_word_to_element(0x9e37);
    let a_times_s = domain.negacyclic_product(&sample, &secret_field);
    let mut component_b = vec![parameters.zero(); ring_degree];
    for index in 0..ring_degree {
        let t_e = parameters.multiply(&plaintext_modulus, &error_field[index]);
        let g_s = parameters.multiply(&gadget_idempotent, &secret_field[index]);
        let q_c = parameters.multiply(&group_modulus, &carry_field[index]);
        let mut value = parameters.add(&t_e, &g_s);
        value = parameters.add(&value, &q_c);
        value = parameters.subtract(&value, &a_times_s[index]);
        component_b[index] = value;
    }
    let public = KeyPublic {
        digits: vec![DigitPublic {
            recombined_sample: sample,
            recombined_component_b: component_b,
            gadget_idempotent,
        }],
        group_modulus,
        plaintext_modulus,
    };
    let digits = vec![DigitWitness { error, carry }];
    let proof_parameters = KeyFriProofParameters {
        query_count: 40,
        mask_degree: 0,
    };
    let mut private_randomness = PrivateProofRandomness::for_test(0x4321);
    let result = prove_key_fri(
        &parameters,
        ring_degree,
        &public,
        &KeySource::RoundOne,
        &secret,
        &digits,
        None,
        &ZERO_STATEMENT_BINDING,
        0,
        &proof_parameters,
        &mut private_randomness,
    );
    match result {
        Err(_) => {}
        Ok(proof) => assert!(
            !verify_key_fri(
                &parameters,
                ring_degree,
                &public,
                &KeySource::RoundOne,
                &proof,
                None,
                &ZERO_STATEMENT_BINDING,
                0,
                &proof_parameters
            )
            .expect("verify"),
            "an out-of-range carry must not yield an accepted key proof"
        ),
    }
}

#[test]
fn wrong_shared_secret_breaks_every_digit() {
    // A secret that is not the one the components were built from: every
    // digit congruence fails, so the batched claim misses.
    let parameters = sixteen_limb_group_field_parameters();
    let ring_degree = 64;
    let (secret, digits, public) =
        build_synthetic_key_fixture(ring_degree, 4, &KeySource::RoundOne);
    let mut wrong_secret = secret.clone();
    wrong_secret[3] = if wrong_secret[3] == 1 { -1 } else { 1 };
    let proof_parameters = KeyFriProofParameters {
        query_count: 40,
        mask_degree: 0,
    };
    let mut private_randomness = PrivateProofRandomness::for_test(0xabc);
    let result = prove_round_one_key_fri(
        &parameters,
        ring_degree,
        &public,
        &wrong_secret,
        &digits,
        &proof_parameters,
        &mut private_randomness,
    );
    match result {
        Err(_) => {}
        Ok(proof) => assert!(
            !verify_round_one_key_fri(&parameters, ring_degree, &public, &proof, &proof_parameters)
                .expect("verify"),
            "a wrong shared secret must not yield an accepted key proof"
        ),
    }
}

#[test]
fn tampered_lookup_terminal_is_rejected() {
    // The lookup terminal is bound to the committed fraction columns by the
    // batched sumcheck and cross-checked against the table terminals. Any
    // change (the verifier also re-absorbs it into the transcript) breaks
    // acceptance.
    let parameters = sixteen_limb_group_field_parameters();
    let ring_degree = 64;
    let (secret, digits, public) =
        build_synthetic_key_fixture(ring_degree, 4, &KeySource::RoundOne);
    let proof_parameters = KeyFriProofParameters {
        query_count: 40,
        mask_degree: 0,
    };
    let mut private_randomness = PrivateProofRandomness::for_test(0xc0ffee);
    let mut proof = prove_round_one_key_fri(
        &parameters,
        ring_degree,
        &public,
        &secret,
        &digits,
        &proof_parameters,
        &mut private_randomness,
    )
    .expect("prove");
    proof.lookup_terminal = parameters.add(&proof.lookup_terminal, &parameters.one());
    assert!(
        !verify_round_one_key_fri(&parameters, ring_degree, &public, &proof, &proof_parameters)
            .expect("verify"),
        "a tampered lookup terminal must not verify"
    );
}

#[test]
fn tampered_table_terminal_is_rejected() {
    // Tampering one table terminal breaks the lookup/table cross-check and
    // the sumcheck binding.
    let parameters = sixteen_limb_group_field_parameters();
    let ring_degree = 64;
    let (secret, digits, public) =
        build_synthetic_key_fixture(ring_degree, 4, &KeySource::RoundOne);
    let proof_parameters = KeyFriProofParameters {
        query_count: 40,
        mask_degree: 0,
    };
    let mut private_randomness = PrivateProofRandomness::for_test(0xbadf00d);
    let mut proof = prove_round_one_key_fri(
        &parameters,
        ring_degree,
        &public,
        &secret,
        &digits,
        &proof_parameters,
        &mut private_randomness,
    )
    .expect("prove");
    proof.table_terminals[0] = parameters.add(&proof.table_terminals[0], &parameters.one());
    assert!(
        !verify_round_one_key_fri(&parameters, ring_degree, &public, &proof, &proof_parameters)
            .expect("verify"),
        "a tampered table terminal must not verify"
    );
}

#[test]
fn honest_galois_key_verifies() {
    let parameters = sixteen_limb_group_field_parameters();
    let ring_degree = 64;
    let source = KeySource::Galois { galois_element: 5 };
    let (secret, digits, public) = build_synthetic_key_fixture(ring_degree, 4, &source);
    let proof_parameters = KeyFriProofParameters {
        query_count: 40,
        mask_degree: 0,
    };
    let mut private_randomness = PrivateProofRandomness::for_test(0x6a10);
    let proof = prove_key_fri(
        &parameters,
        ring_degree,
        &public,
        &source,
        &secret,
        &digits,
        None,
        &ZERO_STATEMENT_BINDING,
        0,
        &proof_parameters,
        &mut private_randomness,
    )
    .expect("prove");
    assert!(
        verify_key_fri(
            &parameters,
            ring_degree,
            &public,
            &source,
            &proof,
            None,
            &ZERO_STATEMENT_BINDING,
            0,
            &proof_parameters
        )
        .expect("verify")
    );
}

#[test]
fn galois_proof_bound_to_its_element() {
    // A Galois proof made with element 5 must not verify as element 7: the
    // element is absorbed into the transcript.
    let parameters = sixteen_limb_group_field_parameters();
    let ring_degree = 64;
    let source = KeySource::Galois { galois_element: 5 };
    let (secret, digits, public) = build_synthetic_key_fixture(ring_degree, 3, &source);
    let proof_parameters = KeyFriProofParameters {
        query_count: 40,
        mask_degree: 0,
    };
    let mut private_randomness = PrivateProofRandomness::for_test(0x6a11);
    let proof = prove_key_fri(
        &parameters,
        ring_degree,
        &public,
        &source,
        &secret,
        &digits,
        None,
        &ZERO_STATEMENT_BINDING,
        0,
        &proof_parameters,
        &mut private_randomness,
    )
    .expect("prove");
    let other_source = KeySource::Galois { galois_element: 7 };
    assert!(
        !verify_key_fri(
            &parameters,
            ring_degree,
            &public,
            &other_source,
            &proof,
            None,
            &ZERO_STATEMENT_BINDING,
            0,
            &proof_parameters
        )
        .expect("verify"),
        "a Galois proof must not verify under a different automorphism element"
    );
}

#[test]
fn honest_round_two_key_verifies() {
    let parameters = sixteen_limb_group_field_parameters();
    let ring_degree = 64;
    let digit_count = 4;
    // One public aggregate per digit.
    let aggregate_by_digit: Vec<Vec<[u64; 13]>> = (0..digit_count)
        .map(|digit_index| {
            let mut state = 0x3300_u64 + digit_index as u64;
            (0..ring_degree)
                .map(|_| {
                    state = state
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(7);
                    parameters.unsigned_word_to_element(state)
                })
                .collect()
        })
        .collect();
    let source = KeySource::RoundTwo { aggregate_by_digit };
    let (secret, digits, public) = build_synthetic_key_fixture(ring_degree, digit_count, &source);
    let proof_parameters = KeyFriProofParameters {
        query_count: 40,
        mask_degree: 0,
    };
    let mut private_randomness = PrivateProofRandomness::for_test(0x7b20);
    let proof = prove_key_fri(
        &parameters,
        ring_degree,
        &public,
        &source,
        &secret,
        &digits,
        None,
        &ZERO_STATEMENT_BINDING,
        0,
        &proof_parameters,
        &mut private_randomness,
    )
    .expect("prove");
    assert!(
        verify_key_fri(
            &parameters,
            ring_degree,
            &public,
            &source,
            &proof,
            None,
            &ZERO_STATEMENT_BINDING,
            0,
            &proof_parameters
        )
        .expect("verify")
    );
}
