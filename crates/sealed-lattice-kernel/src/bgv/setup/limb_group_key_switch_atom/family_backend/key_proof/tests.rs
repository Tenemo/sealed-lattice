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
                    parameters
                        .multiply(&gadget_idempotent, &parameters.signed_word_to_element(*v))
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
            &proof_parameters
        )
        .expect("verify")
    );
}
