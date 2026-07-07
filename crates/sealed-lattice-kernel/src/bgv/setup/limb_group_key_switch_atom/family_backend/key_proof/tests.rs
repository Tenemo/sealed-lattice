use super::super::super::negacyclic_transform::NegacyclicDomain;
use super::super::super::proof_field::sixteen_limb_group_field_parameters;
use super::*;

// Build a synthetic round-one key with `digit_count` digits sharing one
// ternary secret, whose every digit congruence holds exactly.
fn synthetic_key(
    ring_degree: usize,
    digit_count: usize,
) -> (Vec<i64>, Vec<DigitWitness>, KeyPublic<13>) {
    let parameters = sixteen_limb_group_field_parameters();
    let domain = NegacyclicDomain::new(&parameters, ring_degree).expect("domain");
    let secret: Vec<i64> = (0..ring_degree).map(|i| ((i * 7) % 3) as i64 - 1).collect();
    let secret_field: Vec<[u64; 13]> = secret
        .iter()
        .map(|v| parameters.signed_word_to_element(*v))
        .collect();
    let group_modulus = parameters.unsigned_word_to_element(1_000_003);
    let plaintext_modulus = parameters.unsigned_word_to_element(65_537);
    let mut digits = Vec::with_capacity(digit_count);
    let mut public_digits = Vec::with_capacity(digit_count);
    for digit_index in 0..digit_count {
        let error: Vec<i64> = (0..ring_degree)
            .map(|i| (((i + digit_index) * 5) % 5) as i64 - 2)
            .collect();
        let carry: Vec<i64> = (0..ring_degree)
            .map(|i| ((i + digit_index) % 3) as i64 - 1)
            .collect();
        let error_field: Vec<[u64; 13]> = error
            .iter()
            .map(|v| parameters.signed_word_to_element(*v))
            .collect();
        let carry_field: Vec<[u64; 13]> = carry
            .iter()
            .map(|v| parameters.signed_word_to_element(*v))
            .collect();
        let mut sample = Vec::with_capacity(ring_degree);
        let mut state = 0xa5_u64.wrapping_add(digit_index as u64 * 0x1000);
        for _ in 0..ring_degree {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            sample.push(parameters.unsigned_word_to_element(state));
        }
        let gadget_idempotent = parameters.unsigned_word_to_element(0x9e37 + digit_index as u64);
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
        digits.push(DigitWitness { error, carry });
        public_digits.push(DigitPublic {
            recombined_sample: sample,
            recombined_component_b: component_b,
            gadget_idempotent,
        });
    }
    let public = KeyPublic {
        digits: public_digits,
        group_modulus,
        plaintext_modulus,
    };
    (secret, digits, public)
}

// The univariate-sumcheck helper `g` must have degree <= trace_size - 2, or a
// prover can absorb a false sum in the spare coefficient `g_{trace_size-1}`.
// The fix re-enters `g` into the combined FRI shifted by
// `g_degree_adjustment_shift` (= trace_size + 1), so the shared coset bound
// (2 * trace_size) rejects any `g` above that degree. This pins the exact
// boundary: an honest-degree `g` (trace_size - 2) lands at the bound and
// passes; a degree-(trace_size - 1) `g` reaches 2 * trace_size and FRI rejects.
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

        let mut salt_seed = 0xa7c3_u64;
        let mut prover_transcript = Transcript::new(PROTOCOL_LABEL);
        let commitment = fri_commit(
            &parameters,
            &mut prover_transcript,
            &codeword,
            &offset,
            &mut salt_seed,
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
        let (secret, digits, public) = synthetic_key(ring_degree, digit_count);
        let proof_parameters = KeyFriProofParameters {
            query_count: 40,
            mask_degree: 0,
        };
        let mut salt_seed = 0x1234 + digit_count as u64;
        let proof = prove_round_one_key_fri(
            &parameters,
            ring_degree,
            &public,
            &secret,
            &digits,
            &proof_parameters,
            &mut salt_seed,
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
fn masked_multi_digit_key_verifies() {
    let parameters = sixteen_limb_group_field_parameters();
    let ring_degree = 64;
    let (secret, digits, public) = synthetic_key(ring_degree, 4);
    let proof_parameters = KeyFriProofParameters {
        query_count: 40,
        mask_degree: 16,
    };
    let mut salt_seed = 0x5eed;
    let proof = prove_round_one_key_fri(
        &parameters,
        ring_degree,
        &public,
        &secret,
        &digits,
        &proof_parameters,
        &mut salt_seed,
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
    let (secret, mut digits, public) = synthetic_key(ring_degree, 5);
    digits[2].error[7] = 3; // out of eta-2 range and breaks the congruence
    let proof_parameters = KeyFriProofParameters {
        query_count: 40,
        mask_degree: 0,
    };
    let mut salt_seed = 0x9;
    let result = prove_round_one_key_fri(
        &parameters,
        ring_degree,
        &public,
        &secret,
        &digits,
        &proof_parameters,
        &mut salt_seed,
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
    // Committing exactly the public material - what the production path always
    // does - proves and verifies through the dedicated MATERIAL commitment and
    // its sumcheck material forms, both unmasked and masked.
    let parameters = sixteen_limb_group_field_parameters();
    let ring_degree = 64;
    let (secret, digits, public) = synthetic_key(ring_degree, 4);
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
        let mut salt_seed = 0xc0_ffee_22 + mask_degree as u64;
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
            &mut salt_seed,
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
    // The committed MATERIAL column `B_col_j` is load-bearing: the batched
    // sumcheck folds it on its left-hand side with `delta_j * gamma`, so it is
    // the only thing standing in for `B_j` in the atom congruence
    // `B + A(*)s - t e - G source - Q c = 0`. A proof that commits material
    // differing from the correct component in a single coefficient - while the
    // witness, the transcript-bound public data, and every other column are
    // untouched - is refused: the relation no longer holds, so the sumcheck
    // remainder constant misses the target and the prover cannot form the
    // sumcheck (or the verifier's sumcheck query check rejects it). This
    // exercises the relation binding that replaced the removed per-digit pin.
    let parameters = sixteen_limb_group_field_parameters();
    let ring_degree = 64;
    let (secret, digits, public) = synthetic_key(ring_degree, 4);
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
        let mut salt_seed = 0xc0_ffee_11 + mask_degree as u64;
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
            &mut salt_seed,
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
    // against silently admitting a carry large enough to break the field
    // no-wrap exactness bound - the exact failure the reverted base-4
    // decomposition had.
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
    // Well beyond |c| <= N+1 and beyond the representable decomposition range.
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
    let mut salt_seed = 0x4321;
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
        &mut salt_seed,
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
    let (secret, digits, public) = synthetic_key(ring_degree, 4);
    let mut wrong_secret = secret.clone();
    wrong_secret[3] = if wrong_secret[3] == 1 { -1 } else { 1 };
    let proof_parameters = KeyFriProofParameters {
        query_count: 40,
        mask_degree: 0,
    };
    let mut salt_seed = 0xabc;
    let result = prove_round_one_key_fri(
        &parameters,
        ring_degree,
        &public,
        &wrong_secret,
        &digits,
        &proof_parameters,
        &mut salt_seed,
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
    let (secret, digits, public) = synthetic_key(ring_degree, 4);
    let proof_parameters = KeyFriProofParameters {
        query_count: 40,
        mask_degree: 0,
    };
    let mut salt_seed = 0xc0ffee;
    let mut proof = prove_round_one_key_fri(
        &parameters,
        ring_degree,
        &public,
        &secret,
        &digits,
        &proof_parameters,
        &mut salt_seed,
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
    let (secret, digits, public) = synthetic_key(ring_degree, 4);
    let proof_parameters = KeyFriProofParameters {
        query_count: 40,
        mask_degree: 0,
    };
    let mut salt_seed = 0xbadf00d;
    let mut proof = prove_round_one_key_fri(
        &parameters,
        ring_degree,
        &public,
        &secret,
        &digits,
        &proof_parameters,
        &mut salt_seed,
    )
    .expect("prove");
    proof.table_terminals[0] = parameters.add(&proof.table_terminals[0], &parameters.one());
    assert!(
        !verify_round_one_key_fri(&parameters, ring_degree, &public, &proof, &proof_parameters)
            .expect("verify"),
        "a tampered table terminal must not verify"
    );
}

// The forward automorphism image phi_g(s): s(X) -> s(X^g), as a length-N
// signed vector. g is odd, so the coefficient map i -> (i*g mod 2N) is a
// bijection with the negacyclic sign fold.
fn phi_g(secret: &[i64], galois_element: usize) -> Vec<i64> {
    let degree = secret.len();
    let ring_order = 2 * degree;
    let mut image = vec![0_i64; degree];
    for (index, &value) in secret.iter().enumerate() {
        let position = (index * galois_element) % ring_order;
        if position < degree {
            image[position] += value;
        } else {
            image[position - degree] -= value;
        }
    }
    image
}

// Build a synthetic key for a given source, whose every digit congruence
// holds exactly: B_j = t*e_j + G_j*source_j + Q*c_j - A_j*s.
fn synthetic_key_for_source(
    ring_degree: usize,
    digit_count: usize,
    source: &KeySource<13>,
) -> (Vec<i64>, Vec<DigitWitness>, KeyPublic<13>) {
    use super::super::super::negacyclic_transform::NegacyclicDomain;
    let parameters = sixteen_limb_group_field_parameters();
    let domain = NegacyclicDomain::new(&parameters, ring_degree).expect("domain");
    let secret: Vec<i64> = (0..ring_degree).map(|i| ((i * 7) % 3) as i64 - 1).collect();
    let secret_field: Vec<[u64; 13]> = secret
        .iter()
        .map(|v| parameters.signed_word_to_element(*v))
        .collect();
    let group_modulus = parameters.unsigned_word_to_element(1_000_003);
    let plaintext_modulus = parameters.unsigned_word_to_element(65_537);
    let mut digits = Vec::new();
    let mut public_digits = Vec::new();
    for digit_index in 0..digit_count {
        let error: Vec<i64> = (0..ring_degree)
            .map(|i| (((i + digit_index) * 5) % 5) as i64 - 2)
            .collect();
        let carry: Vec<i64> = (0..ring_degree)
            .map(|i| ((i + digit_index) % 3) as i64 - 1)
            .collect();
        let error_field: Vec<[u64; 13]> = error
            .iter()
            .map(|v| parameters.signed_word_to_element(*v))
            .collect();
        let carry_field: Vec<[u64; 13]> = carry
            .iter()
            .map(|v| parameters.signed_word_to_element(*v))
            .collect();
        let mut sample = Vec::with_capacity(ring_degree);
        let mut state = 0xa5_u64.wrapping_add(digit_index as u64 * 0x1000);
        for _ in 0..ring_degree {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            sample.push(parameters.unsigned_word_to_element(state));
        }
        let gadget_idempotent = parameters.unsigned_word_to_element(0x9e37 + digit_index as u64);
        let a_times_s = domain.negacyclic_product(&sample, &secret_field);

        // The diagonal term as field elements: `G * source` for round one and
        // Galois; round two's aggregate is the centered diagonal term with the
        // `G` fold already inside, so its contribution is `aggregate (*) s`
        // unscaled (matching the reduction's semantics).
        let diagonal_term: Vec<[u64; 13]> = match source {
            KeySource::RoundOne => secret_field
                .iter()
                .map(|value| parameters.multiply(&gadget_idempotent, value))
                .collect(),
            KeySource::Galois { galois_element } => phi_g(&secret, *galois_element)
                .iter()
                .map(|v| {
                    parameters.multiply(&gadget_idempotent, &parameters.signed_word_to_element(*v))
                })
                .collect(),
            KeySource::RoundTwo { aggregate_by_digit } => {
                domain.negacyclic_product(&secret_field, &aggregate_by_digit[digit_index])
            }
        };

        let mut component_b = vec![parameters.zero(); ring_degree];
        for index in 0..ring_degree {
            let t_e = parameters.multiply(&plaintext_modulus, &error_field[index]);
            let q_c = parameters.multiply(&group_modulus, &carry_field[index]);
            let mut value = parameters.add(&t_e, &diagonal_term[index]);
            value = parameters.add(&value, &q_c);
            value = parameters.subtract(&value, &a_times_s[index]);
            component_b[index] = value;
        }
        digits.push(DigitWitness { error, carry });
        public_digits.push(DigitPublic {
            recombined_sample: sample,
            recombined_component_b: component_b,
            gadget_idempotent,
        });
    }
    (
        secret,
        digits,
        KeyPublic {
            digits: public_digits,
            group_modulus,
            plaintext_modulus,
        },
    )
}

#[test]
fn honest_galois_key_verifies() {
    let parameters = sixteen_limb_group_field_parameters();
    let ring_degree = 64;
    let source = KeySource::Galois { galois_element: 5 };
    let (secret, digits, public) = synthetic_key_for_source(ring_degree, 4, &source);
    let proof_parameters = KeyFriProofParameters {
        query_count: 40,
        mask_degree: 0,
    };
    let mut salt_seed = 0x6a10;
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
        &mut salt_seed,
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
    let (secret, digits, public) = synthetic_key_for_source(ring_degree, 3, &source);
    let proof_parameters = KeyFriProofParameters {
        query_count: 40,
        mask_degree: 0,
    };
    let mut salt_seed = 0x6a11;
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
        &mut salt_seed,
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
    let (secret, digits, public) = synthetic_key_for_source(ring_degree, digit_count, &source);
    let proof_parameters = KeyFriProofParameters {
        query_count: 40,
        mask_degree: 0,
    };
    let mut salt_seed = 0x7b20;
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
        &mut salt_seed,
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

// The linkage oracle fixture: a REAL VssPublic commitment over the canonical
// message of the key secret, produced by the LIVE commitment function, plus the
// linkage statement/witness inputs that open it. The linkage equations, the
// sampler rows, and the digit encoding all come from the live code, so a
// passing linkage proof means the atom secret opens the real commitment.
struct LinkageOracle {
    seed_hash: String,
    source_message_modulus: u64,
    coordinates: Vec<Vec<u64>>,
    negative_indicator: Vec<i64>,
    randomness: Vec<Vec<i64>>,
}

fn linkage_oracle(secret: &[i64], ring_degree: usize) -> LinkageOracle {
    use crate::bgv::parameters::DATA_PRIMES;
    use crate::bgv::setup::vss_commitment::{
        VssPublicCommitmentOpeningInput, compute_vss_public_commitment_from_opening,
        vss_public_canonical_message_digit_columns,
    };
    let source_message_modulus = DATA_PRIMES[0];
    let seed_hash = "ab".repeat(64);
    let message: Vec<u64> = secret
        .iter()
        .map(|value| (*value as i128).rem_euclid(source_message_modulus as i128) as u64)
        .collect();
    let negative_indicator: Vec<i64> = secret.iter().map(|value| i64::from(*value < 0)).collect();
    let randomness: Vec<Vec<i64>> = (0..2)
        .map(|column| {
            (0..ring_degree)
                .map(|index| (((index + column) * 7) % 3) as i64 - 1)
                .collect()
        })
        .collect();
    let digit_columns =
        vss_public_canonical_message_digit_columns(&message, ring_degree).expect("digits encode");
    let computation = compute_vss_public_commitment_from_opening(VssPublicCommitmentOpeningInput {
        commitment_role: "coefficient",
        commitment_context: &serde_json::json!({ "purpose": "linkage-oracle-test" }),
        public_matrix_seed_hash: &seed_hash,
        rns_limb_index: 0,
        rns_prime: source_message_modulus,
        ring_degree,
        message_coefficients: &message,
        message_digit_columns: &digit_columns,
        message_coefficient_bound: source_message_modulus,
        randomness_by_column: &randomness,
    })
    .expect("live commitment computes");
    let coordinates: Vec<Vec<u64>> = computation.commitment["commitmentLimbs"]
        .as_array()
        .expect("commitment limbs array")
        .iter()
        .map(|limb| {
            limb["coordinates"]
                .as_array()
                .expect("coordinates array")
                .iter()
                .map(|value| value.as_u64().expect("coordinate is u64"))
                .collect()
        })
        .collect();
    LinkageOracle {
        seed_hash,
        source_message_modulus,
        coordinates,
        negative_indicator,
        randomness,
    }
}

#[test]
fn linkage_binds_the_secret_to_a_live_commitment() {
    let parameters = sixteen_limb_group_field_parameters();
    let ring_degree = 64;
    let (secret, digits, public) = synthetic_key(ring_degree, 2);
    let oracle = linkage_oracle(&secret, ring_degree);
    let statement = LinkageStatement {
        public_matrix_seed_hash: &oracle.seed_hash,
        source_rns_limb_index: 0,
        source_message_modulus: oracle.source_message_modulus,
        coordinates_by_commitment_modulus: &oracle.coordinates,
    };
    let witness = LinkageWitness {
        negative_indicator: &oracle.negative_indicator,
        randomness_by_column: &oracle.randomness,
    };
    let proof_parameters = KeyFriProofParameters {
        query_count: 40,
        mask_degree: 0,
    };
    let mut salt_seed = 0x11ac;
    let proof = prove_key_fri(
        &parameters,
        ring_degree,
        &public,
        &KeySource::RoundOne,
        &secret,
        &digits,
        Some((&statement, &witness)),
        &ZERO_STATEMENT_BINDING,
        0,
        &proof_parameters,
        &mut salt_seed,
    )
    .expect("linked key proves");
    assert!(
        verify_key_fri(
            &parameters,
            ring_degree,
            &public,
            &KeySource::RoundOne,
            &proof,
            Some(&statement),
            &ZERO_STATEMENT_BINDING,
            0,
            &proof_parameters,
        )
        .expect("verify runs"),
        "a linked key proof against the live commitment must verify"
    );

    // A masked linked proof also verifies (the linkage columns ride the same
    // masking idiom).
    let masked_parameters = KeyFriProofParameters {
        query_count: 40,
        mask_degree: 16,
    };
    let mut masked_seed = 0x11ad;
    let masked_proof = prove_key_fri(
        &parameters,
        ring_degree,
        &public,
        &KeySource::RoundOne,
        &secret,
        &digits,
        Some((&statement, &witness)),
        &ZERO_STATEMENT_BINDING,
        0,
        &masked_parameters,
        &mut masked_seed,
    )
    .expect("masked linked key proves");
    assert!(
        verify_key_fri(
            &parameters,
            ring_degree,
            &public,
            &KeySource::RoundOne,
            &masked_proof,
            Some(&statement),
            &ZERO_STATEMENT_BINDING,
            0,
            &masked_parameters,
        )
        .expect("verify runs"),
        "a masked linked key proof must verify"
    );

    // Tampered coordinate: the transcript rebinding fails.
    let mut tampered_coordinates = oracle.coordinates.clone();
    tampered_coordinates[0][0] ^= 1;
    let tampered_statement = LinkageStatement {
        public_matrix_seed_hash: &oracle.seed_hash,
        source_rns_limb_index: 0,
        source_message_modulus: oracle.source_message_modulus,
        coordinates_by_commitment_modulus: &tampered_coordinates,
    };
    assert!(
        !verify_key_fri(
            &parameters,
            ring_degree,
            &public,
            &KeySource::RoundOne,
            &proof,
            Some(&tampered_statement),
            &ZERO_STATEMENT_BINDING,
            0,
            &proof_parameters,
        )
        .expect("verify runs"),
        "a tampered linkage coordinate must not verify"
    );

    // A different sampler seed is a different commitment matrix: rejected.
    let other_seed = "cd".repeat(64);
    let other_seed_statement = LinkageStatement {
        public_matrix_seed_hash: &other_seed,
        source_rns_limb_index: 0,
        source_message_modulus: oracle.source_message_modulus,
        coordinates_by_commitment_modulus: &oracle.coordinates,
    };
    assert!(
        !verify_key_fri(
            &parameters,
            ring_degree,
            &public,
            &KeySource::RoundOne,
            &proof,
            Some(&other_seed_statement),
            &ZERO_STATEMENT_BINDING,
            0,
            &proof_parameters,
        )
        .expect("verify runs"),
        "a different sampler seed must not verify"
    );

    // Dropping the linkage from verification is rejected (presence is bound
    // into the transcript).
    assert!(
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
        "a linked proof must not verify without its linkage statement"
    );
}

#[test]
fn linkage_prover_refuses_witness_mismatches() {
    let parameters = sixteen_limb_group_field_parameters();
    let ring_degree = 64;
    let (secret, digits, public) = synthetic_key(ring_degree, 2);
    let oracle = linkage_oracle(&secret, ring_degree);
    let statement = LinkageStatement {
        public_matrix_seed_hash: &oracle.seed_hash,
        source_rns_limb_index: 0,
        source_message_modulus: oracle.source_message_modulus,
        coordinates_by_commitment_modulus: &oracle.coordinates,
    };
    let proof_parameters = KeyFriProofParameters {
        query_count: 40,
        mask_degree: 0,
    };

    // A wrong negative indicator is refused before any proving work.
    let mut wrong_indicator = oracle.negative_indicator.clone();
    wrong_indicator[0] = 1 - wrong_indicator[0];
    let mut salt_seed = 0x2b01;
    assert!(
        prove_key_fri(
            &parameters,
            ring_degree,
            &public,
            &KeySource::RoundOne,
            &secret,
            &digits,
            Some((
                &statement,
                &LinkageWitness {
                    negative_indicator: &wrong_indicator,
                    randomness_by_column: &oracle.randomness,
                },
            )),
            &ZERO_STATEMENT_BINDING,
            0,
            &proof_parameters,
            &mut salt_seed,
        )
        .is_err(),
        "a wrong negative indicator must be refused"
    );

    // Randomness that does not open the commitment is refused (the coordinate
    // congruences do not divide).
    let mut wrong_randomness = oracle.randomness.clone();
    wrong_randomness[0][3] = if wrong_randomness[0][3] == 1 { -1 } else { 1 };
    let mut salt_seed = 0x2b02;
    assert!(
        prove_key_fri(
            &parameters,
            ring_degree,
            &public,
            &KeySource::RoundOne,
            &secret,
            &digits,
            Some((
                &statement,
                &LinkageWitness {
                    negative_indicator: &oracle.negative_indicator,
                    randomness_by_column: &wrong_randomness,
                },
            )),
            &ZERO_STATEMENT_BINDING,
            0,
            &proof_parameters,
            &mut salt_seed,
        )
        .is_err(),
        "randomness that does not open the commitment must be refused"
    );

    // A different secret cannot open the commitment either: its key material
    // is fine unlinked, so only the linkage can be the reason for refusal.
    let other_secret: Vec<i64> = (0..ring_degree)
        .map(|i| ((i * 11) % 3) as i64 - 1)
        .collect();
    let other_indicator: Vec<i64> = other_secret
        .iter()
        .map(|value| i64::from(*value < 0))
        .collect();
    let mut salt_seed = 0x2b03;
    assert!(
        prove_key_fri(
            &parameters,
            ring_degree,
            &public,
            &KeySource::RoundOne,
            &other_secret,
            &digits,
            Some((
                &statement,
                &LinkageWitness {
                    negative_indicator: &other_indicator,
                    randomness_by_column: &oracle.randomness,
                },
            )),
            &ZERO_STATEMENT_BINDING,
            0,
            &proof_parameters,
            &mut salt_seed,
        )
        .is_err(),
        "a different secret must not open the linkage commitment"
    );
}
