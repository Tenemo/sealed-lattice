use super::super::evaluation_domain::negacyclic_ring_product;
use super::super::*;
use super::*;
use crate::bgv::evaluator::key_switch::KEY_SWITCH_ERROR_DOMAIN;
use crate::bgv::setup::commitment::compute_setup_big_signed_lifted_commitment;
use num_bigint::BigInt;

const WITNESS_SECRET_DOMAIN: &str = "sealed-lattice/setup/trustee-evaluation-key/witness-secret-v1";

// Apply the Galois automorphism phi_g coefficient-wise: the monomial X^i maps
// to sign * X^(i*g mod 2N folded into [0, N) with X^N = -1).
pub(crate) fn galois_automorphism_apply(
    values: &[u64],
    galois_element: usize,
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    let degree = values.len();
    let ring_order = 2 * degree;
    if galois_element.is_multiple_of(2) {
        return Err(invalid_succinct_setup_proof("Galois element must be odd"));
    }
    let mut rotated = vec![0_u64; degree];
    for (index, value) in values.iter().enumerate() {
        let target = (index * galois_element) % ring_order;
        if target < degree {
            rotated[target] = *value;
        } else {
            rotated[target - degree] = sub_mod_fast(0, *value, modulus);
        }
    }

    Ok(rotated)
}

fn sample_development_errors(
    key_switch_domain: &str,
    key_switch_seed_hex: &str,
    digit_count: usize,
    ring_degree: usize,
) -> Vec<Vec<i64>> {
    (0..digit_count)
        .map(|digit_index| {
            DeterministicSampler::new(
                KEY_SWITCH_ERROR_DOMAIN,
                &[
                    key_switch_domain.as_bytes(),
                    key_switch_seed_hex.as_bytes(),
                    &(digit_index as u64).to_le_bytes(),
                ],
            )
            .centered_binomial_eta2(ring_degree)
        })
        .collect()
}

// Build component material so the relation holds: for digit j, limb l,
//   b = p * e_j - a_{j,l} (*) s + [l == j] * source_j,
// where source_j is the diagonal source residue vector in field q_j.
fn build_component_material(
    key_switch_domain: &str,
    key_switch_seed_hex: &str,
    level: usize,
    ring_degree: usize,
    secret_coefficients: &[i64],
    error_coefficients_by_digit: &[Vec<i64>],
    diagonal_source_by_digit: &[Vec<u64>],
) -> CanonicalResult<Vec<Vec<Vec<u64>>>> {
    let digit_count = level + 1;
    let mut component_b_by_digit = Vec::with_capacity(digit_count);
    for (digit_index, error_coefficients) in error_coefficients_by_digit.iter().enumerate() {
        let mut component_b_by_limb = Vec::with_capacity(digit_count);
        for (limb_index, modulus) in DATA_PRIMES[..=level].iter().enumerate() {
            let public_sample = public_key_switch_sample(
                key_switch_domain,
                key_switch_seed_hex,
                digit_index,
                *modulus,
                ring_degree,
            );
            let secret_residues = secret_coefficients
                .iter()
                .map(|coefficient| signed_value_residue(*coefficient, *modulus))
                .collect::<Vec<_>>();
            let sample_secret_product =
                negacyclic_ring_product(&public_sample, &secret_residues, *modulus)?;
            let component_b = (0..ring_degree)
                .map(|coefficient_index| {
                    let scaled_error = signed_value_residue(
                        error_coefficients[coefficient_index] * PLAINTEXT_MODULUS_I64,
                        *modulus,
                    );
                    let mut value = sub_mod_fast(
                        scaled_error,
                        sample_secret_product[coefficient_index],
                        *modulus,
                    );
                    if limb_index == digit_index {
                        value = add_mod_fast(
                            value,
                            diagonal_source_by_digit[digit_index][coefficient_index],
                            *modulus,
                        );
                    }
                    value
                })
                .collect::<Vec<_>>();
            component_b_by_limb.push(component_b);
        }
        component_b_by_digit.push(component_b_by_limb);
    }

    Ok(component_b_by_digit)
}

const ROUND_ONE_AGGREGATE_DOMAIN: &str =
    "sealed-lattice/setup/trustee-evaluation-key/development-round-one-aggregate-v1";

// One development key descriptor plus its errors, for an already-sampled
// shared secret.
fn generate_development_key(
    kind: EvaluationKeyShareKind,
    key_switch_seed_hex: &str,
    level: usize,
    ring_degree: usize,
    secret_coefficients: &[i64],
) -> CanonicalResult<(EvaluationKeyShareDescriptor, Vec<Vec<i64>>)> {
    let key_switch_domain = match kind {
        EvaluationKeyShareKind::RelinearizationRoundOne => "relinearization-round-one".to_string(),
        EvaluationKeyShareKind::RelinearizationRoundTwo => "relinearization-round-two".to_string(),
        EvaluationKeyShareKind::GaloisRotation { galois_element } => {
            format!("rotation-{galois_element}")
        }
        EvaluationKeyShareKind::PublicKeyShare => {
            return Err(invalid_succinct_setup_proof(
                "the public-key share family uses its own development generator",
            ));
        }
    };
    let digit_count = level + 1;
    let error_coefficients_by_digit = sample_development_errors(
        &key_switch_domain,
        key_switch_seed_hex,
        digit_count,
        ring_degree,
    );
    let mut round_one_aggregate_diagonal = Vec::new();
    let mut diagonal_source_by_digit = Vec::with_capacity(digit_count);
    for (digit_index, modulus) in DATA_PRIMES[..=level].iter().enumerate() {
        let secret_residues = secret_coefficients
            .iter()
            .map(|coefficient| signed_value_residue(*coefficient, *modulus))
            .collect::<Vec<_>>();
        let source = match kind {
            EvaluationKeyShareKind::RelinearizationRoundOne => secret_residues,
            EvaluationKeyShareKind::RelinearizationRoundTwo => {
                let aggregate = DeterministicSampler::new(
                    ROUND_ONE_AGGREGATE_DOMAIN,
                    &[
                        key_switch_seed_hex.as_bytes(),
                        key_switch_domain.as_bytes(),
                        &(digit_index as u64).to_le_bytes(),
                        &modulus.to_le_bytes(),
                    ],
                )
                .uniform_residues(*modulus, ring_degree);
                let source = negacyclic_ring_product(&secret_residues, &aggregate, *modulus)?;
                round_one_aggregate_diagonal.push(aggregate);
                source
            }
            EvaluationKeyShareKind::GaloisRotation { galois_element } => {
                galois_automorphism_apply(&secret_residues, galois_element, *modulus)?
            }
            EvaluationKeyShareKind::PublicKeyShare => {
                // The key_switch_domain match above already returned an error
                // for the public-key share, so this arm is never reached.
                unreachable!("public-key share uses its own development generator");
            }
        };
        diagonal_source_by_digit.push(source);
    }
    let component_b_by_digit = build_component_material(
        &key_switch_domain,
        key_switch_seed_hex,
        level,
        ring_degree,
        secret_coefficients,
        &error_coefficients_by_digit,
        &diagonal_source_by_digit,
    )?;

    Ok((
        EvaluationKeyShareDescriptor {
            kind,
            level,
            key_switch_domain,
            key_switch_seed_hex: key_switch_seed_hex.to_string(),
            component_b_by_digit,
            round_one_aggregate_diagonal,
        },
        error_coefficients_by_digit,
    ))
}

const LINKAGE_RANDOMNESS_DOMAIN: &str =
    "sealed-lattice/setup/trustee-evaluation-key/linkage-opening-randomness-v1";
const LINKAGE_MATRIX_SEED_DOMAIN: &str =
    "sealed-lattice/setup/trustee-evaluation-key/linkage-matrix-seed-v1";

// Development instance generator for a whole trustee key schedule: one shared
// ternary secret and a list of key kinds at their levels, all with real
// production-shaped component material. When a Q_share limb count is given,
// the instance also carries the same-secret linkage: real BDLOP constant
// commitments to the lifted secret message per Q_share limb, with fresh
// ternary opening randomness.
fn development_context(key_switch_seed_hex: &str, keyless: bool) -> SuccinctSetupProofContext {
    let derived = |label: &str| -> String {
        hash512(
            "sealed-lattice/setup/trustee-evaluation-key/development-context-v1",
            &[key_switch_seed_hex.as_bytes(), label.as_bytes()],
        )
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
    };
    let (proof_family, binding_labels): (&str, &[&str]) = if keyless {
        (
            super::SAME_SECRET_LINKAGE_ANCHOR_PROOF_FAMILY,
            &SAME_SECRET_LINKAGE_ANCHOR_BINDING_LABELS,
        )
    } else {
        (
            super::TRUSTEE_EVALUATION_KEY_PROOF_FAMILY,
            &TRUSTEE_EVALUATION_KEY_BINDING_LABELS,
        )
    };

    SuccinctSetupProofContext {
        proof_family: proof_family.to_string(),
        ceremony_id: format!("development-ceremony-{key_switch_seed_hex}"),
        manifest_hash: derived("manifest"),
        roster_hash: derived("roster"),
        trustee_identity: format!("development-trustee-{key_switch_seed_hex}"),
        trustee_roster_position: 1,
        setup_epoch: "development-epoch-1".to_string(),
        binding_roots: binding_labels
            .iter()
            .map(|label| ((*label).to_string(), derived(label)))
            .collect(),
    }
}

pub(crate) fn generate_development_trustee_instance_with_linkage(
    key_switch_seed_hex: &str,
    key_requests: &[(EvaluationKeyShareKind, usize)],
    ring_degree: usize,
    linkage_commitment_count: Option<usize>,
) -> CanonicalResult<(TrusteeEvaluationKeyStatement, TrusteeEvaluationKeyWitness)> {
    let secret_coefficients =
        DeterministicSampler::new(WITNESS_SECRET_DOMAIN, &[key_switch_seed_hex.as_bytes()])
            .ternary(ring_degree);
    let mut keys = Vec::with_capacity(key_requests.len());
    let mut error_coefficients_by_key = Vec::with_capacity(key_requests.len());
    for (request_index, (kind, level)) in key_requests.iter().enumerate() {
        let key_seed = format!("{key_switch_seed_hex}-{request_index}");
        let (descriptor, errors) =
            generate_development_key(*kind, &key_seed, *level, ring_degree, &secret_coefficients)?;
        keys.push(descriptor);
        error_coefficients_by_key.push(errors);
    }
    let mut same_secret_linkage = None;
    let mut negative_indicator_coefficients = Vec::new();
    let mut opening_randomness_by_limb = Vec::new();
    if let Some(commitment_count) = linkage_commitment_count {
        let public_matrix_seed_hash = {
            let digest = hash512(
                LINKAGE_MATRIX_SEED_DOMAIN,
                &[key_switch_seed_hex.as_bytes()],
            );
            digest
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        negative_indicator_coefficients = secret_coefficients
            .iter()
            .map(|coefficient| i64::from(*coefficient < 0))
            .collect::<Vec<_>>();
        let mut commitments = Vec::with_capacity(commitment_count);
        for (source_limb_index, source_modulus) in
            DATA_PRIMES[..commitment_count].iter().copied().enumerate()
        {
            let randomness = (0..SETUP_COMMITMENT_RANDOMNESS_WIDTH)
                .map(|column| {
                    DeterministicSampler::new(
                        LINKAGE_RANDOMNESS_DOMAIN,
                        &[
                            key_switch_seed_hex.as_bytes(),
                            &(source_limb_index as u64).to_le_bytes(),
                            &(column as u64).to_le_bytes(),
                        ],
                    )
                    .ternary(ring_degree)
                })
                .collect::<Vec<_>>();
            let message = secret_coefficients
                .iter()
                .zip(negative_indicator_coefficients.iter())
                .map(|(secret, indicator)| {
                    BigInt::from(*secret) + BigInt::from(*indicator) * BigInt::from(source_modulus)
                })
                .collect::<Vec<_>>();
            let randomness_i128 = randomness
                .iter()
                .map(|column| column.iter().map(|value| i128::from(*value)).collect())
                .collect::<Vec<Vec<i128>>>();
            commitments.push(compute_setup_big_signed_lifted_commitment(
                &public_matrix_seed_hash,
                source_limb_index,
                source_modulus,
                0,
                &message,
                &randomness_i128,
                ring_degree,
            )?);
            opening_randomness_by_limb.push(randomness);
        }
        same_secret_linkage = Some(SameSecretLinkageStatement {
            public_matrix_seed_hash,
            commitments,
        });
    }

    Ok((
        TrusteeEvaluationKeyStatement {
            context: development_context(key_switch_seed_hex, key_requests.is_empty()),
            ring_degree,
            keys,
            same_secret_linkage,
            private_vss_share: None,
            compact_vss_share_linkage: None,
        },
        TrusteeEvaluationKeyWitness {
            secret_coefficients,
            error_coefficients_by_key,
            negative_indicator_coefficients,
            opening_randomness_by_limb,
            private_vss_coefficient_messages_by_shamir_index: Vec::new(),
            private_vss_opening_randomness_by_shamir_index: Vec::new(),
            private_vss_carry_witnesses: Vec::new(),
            compact_vss_coefficient_messages_by_shamir_index: Vec::new(),
            compact_vss_recipient_share_messages: Vec::new(),
            compact_vss_coefficient_opening_randomness_by_shamir_index: Vec::new(),
            compact_vss_recipient_share_opening_randomness: Vec::new(),
            compact_vss_carry_witnesses: Vec::new(),
        },
    ))
}

pub(crate) fn generate_development_trustee_instance(
    key_switch_seed_hex: &str,
    key_requests: &[(EvaluationKeyShareKind, usize)],
    ring_degree: usize,
) -> CanonicalResult<(TrusteeEvaluationKeyStatement, TrusteeEvaluationKeyWitness)> {
    generate_development_trustee_instance_with_linkage(
        key_switch_seed_hex,
        key_requests,
        ring_degree,
        None,
    )
}

// Development public-key share instance: one ternary secret s and one
// centered-binomial error e produce the published share b_l = p*e - a_l (*) s
// over every Q_share limb against the seed-derived common reference
// polynomial, plus one constant commitment (limb zero) opening s for the
// anchor link.
pub(crate) fn generate_development_public_key_share_instance(
    seed_hex: &str,
    ring_degree: usize,
) -> CanonicalResult<(TrusteeEvaluationKeyStatement, TrusteeEvaluationKeyWitness)> {
    let secret_coefficients =
        DeterministicSampler::new(WITNESS_SECRET_DOMAIN, &[seed_hex.as_bytes()])
            .ternary(ring_degree);
    let error_coefficients = DeterministicSampler::new(
        KEY_SWITCH_ERROR_DOMAIN,
        &[seed_hex.as_bytes(), b"public-key-share-error"],
    )
    .centered_binomial_eta2(ring_degree);
    let public_matrix_seed_hash = {
        let digest = hash512(LINKAGE_MATRIX_SEED_DOMAIN, &[seed_hex.as_bytes()]);
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    // b_l = p * e - a_l (*) s over every Q_share limb.
    let level = DATA_PRIMES.len() - 1;
    let mut component_b_by_limb = Vec::with_capacity(DATA_PRIMES.len());
    for modulus in DATA_PRIMES.iter().copied() {
        let public_sample = dense_public_residues_with_degree(
            &public_matrix_seed_hash,
            PUBLIC_KEY_SHARE_COMMON_REFERENCE_LABEL,
            modulus,
            ring_degree,
        );
        let secret_residues = secret_coefficients
            .iter()
            .map(|coefficient| signed_value_residue(*coefficient, modulus))
            .collect::<Vec<_>>();
        let sample_secret_product =
            negacyclic_ring_product(&public_sample, &secret_residues, modulus)?;
        let component_b = (0..ring_degree)
            .map(|coefficient_index| {
                let scaled_error = signed_value_residue(
                    error_coefficients[coefficient_index] * PLAINTEXT_MODULUS_I64,
                    modulus,
                );
                sub_mod_fast(
                    scaled_error,
                    sample_secret_product[coefficient_index],
                    modulus,
                )
            })
            .collect::<Vec<_>>();
        component_b_by_limb.push(component_b);
    }
    let descriptor = EvaluationKeyShareDescriptor {
        kind: EvaluationKeyShareKind::PublicKeyShare,
        level,
        key_switch_domain: PUBLIC_KEY_SHARE_COMMON_REFERENCE_LABEL.to_string(),
        key_switch_seed_hex: public_matrix_seed_hash.clone(),
        component_b_by_digit: vec![component_b_by_limb],
        round_one_aggregate_diagonal: Vec::new(),
    };
    // One constant commitment (limb zero) linking s to the anchor.
    let negative_indicator_coefficients = secret_coefficients
        .iter()
        .map(|coefficient| i64::from(*coefficient < 0))
        .collect::<Vec<_>>();
    let source_modulus = DATA_PRIMES[0];
    let randomness = (0..SETUP_COMMITMENT_RANDOMNESS_WIDTH)
        .map(|column| {
            DeterministicSampler::new(
                LINKAGE_RANDOMNESS_DOMAIN,
                &[seed_hex.as_bytes(), &(column as u64).to_le_bytes()],
            )
            .ternary(ring_degree)
        })
        .collect::<Vec<_>>();
    let message = secret_coefficients
        .iter()
        .zip(negative_indicator_coefficients.iter())
        .map(|(secret, indicator)| {
            BigInt::from(*secret) + BigInt::from(*indicator) * BigInt::from(source_modulus)
        })
        .collect::<Vec<_>>();
    let randomness_i128 = randomness
        .iter()
        .map(|column| column.iter().map(|value| i128::from(*value)).collect())
        .collect::<Vec<Vec<i128>>>();
    let commitment = compute_setup_big_signed_lifted_commitment(
        &public_matrix_seed_hash,
        0,
        source_modulus,
        0,
        &message,
        &randomness_i128,
        ring_degree,
    )?;
    let same_secret_linkage = Some(SameSecretLinkageStatement {
        public_matrix_seed_hash,
        commitments: vec![commitment],
    });
    let context = development_public_key_share_context(seed_hex);

    Ok((
        TrusteeEvaluationKeyStatement {
            context,
            ring_degree,
            keys: vec![descriptor],
            same_secret_linkage,
            private_vss_share: None,
            compact_vss_share_linkage: None,
        },
        TrusteeEvaluationKeyWitness {
            secret_coefficients,
            error_coefficients_by_key: vec![vec![error_coefficients]],
            negative_indicator_coefficients,
            opening_randomness_by_limb: vec![randomness],
            private_vss_coefficient_messages_by_shamir_index: Vec::new(),
            private_vss_opening_randomness_by_shamir_index: Vec::new(),
            private_vss_carry_witnesses: Vec::new(),
            compact_vss_coefficient_messages_by_shamir_index: Vec::new(),
            compact_vss_recipient_share_messages: Vec::new(),
            compact_vss_coefficient_opening_randomness_by_shamir_index: Vec::new(),
            compact_vss_recipient_share_opening_randomness: Vec::new(),
            compact_vss_carry_witnesses: Vec::new(),
        },
    ))
}

fn development_public_key_share_context(seed_hex: &str) -> SuccinctSetupProofContext {
    let derived = |label: &str| -> String {
        hash512(
            "sealed-lattice/setup/public-key-share/development-context-v1",
            &[seed_hex.as_bytes(), label.as_bytes()],
        )
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
    };

    SuccinctSetupProofContext {
        proof_family: super::PUBLIC_KEY_SHARE_PROOF_FAMILY.to_string(),
        ceremony_id: format!("development-ceremony-{seed_hex}"),
        manifest_hash: derived("manifest"),
        roster_hash: derived("roster"),
        trustee_identity: format!("development-trustee-{seed_hex}"),
        trustee_roster_position: 1,
        setup_epoch: "development-epoch-1".to_string(),
        binding_roots: PUBLIC_KEY_SHARE_SUCCINCT_BINDING_LABELS
            .iter()
            .map(|label| ((*label).to_string(), derived(label)))
            .collect(),
    }
}

// Verifier-side public round-one aggregate diagonals: for digit j, the
// aggregate is the sum of every trustee's accepted round-one component b at
// digit j, limb j, reduced mod q_j. Round-two sources multiply the trustee
// secret by this public aggregate, so each trustee can form its round-two
// share from public material and the verifier rebinds the same values into
// every round-two statement.
pub(crate) fn round_one_aggregate_diagonal_from_components(
    round_one_components_by_trustee: &[&Vec<Vec<Vec<u64>>>],
    level: usize,
    ring_degree: usize,
) -> CanonicalResult<Vec<Vec<u64>>> {
    let digit_count = level + 1;
    if round_one_components_by_trustee.is_empty() {
        return Err(invalid_succinct_setup_proof(
            "round-one aggregate requires at least one trustee component set",
        ));
    }
    let mut aggregate = Vec::with_capacity(digit_count);
    for (digit_index, modulus) in DATA_PRIMES[..digit_count].iter().copied().enumerate() {
        let mut diagonal = vec![0_u64; ring_degree];
        for components in round_one_components_by_trustee {
            let component = components
                .get(digit_index)
                .and_then(|by_limb| by_limb.get(digit_index))
                .ok_or_else(|| {
                    invalid_succinct_setup_proof(
                        "round-one component material does not cover the aggregate diagonal",
                    )
                })?;
            if component.len() != ring_degree {
                return Err(invalid_succinct_setup_proof(
                    "round-one component diagonal length does not match the ring degree",
                ));
            }
            for (accumulated, value) in diagonal.iter_mut().zip(component.iter()) {
                *accumulated = add_mod_fast(*accumulated, *value, modulus);
            }
        }
        aggregate.push(diagonal);
    }

    Ok(aggregate)
}

// Development multi-trustee ceremony slice: every trustee has its own secret,
// errors, and linkage commitments; round-one components are built per trustee
// with the secret as the diagonal source, the public round-one aggregate is
// recomputed from those components, and every trustee's round-two source is
// its secret times that public aggregate, exactly the multi-party-realizable
// flow the package verifier rebinds.
pub(crate) fn generate_development_trustee_ceremony_slice(
    ceremony_seed_hex: &str,
    trustee_count: usize,
    level: usize,
    ring_degree: usize,
    linkage_commitment_count: usize,
) -> CanonicalResult<Vec<(TrusteeEvaluationKeyStatement, TrusteeEvaluationKeyWitness)>> {
    let mut round_one_instances = Vec::with_capacity(trustee_count);
    for trustee_index in 0..trustee_count {
        round_one_instances.push(generate_development_trustee_instance_with_linkage(
            &format!("{ceremony_seed_hex}-trustee-{trustee_index}"),
            &[(EvaluationKeyShareKind::RelinearizationRoundOne, level)],
            ring_degree,
            Some(linkage_commitment_count),
        )?);
    }
    let round_one_components = round_one_instances
        .iter()
        .map(|(statement, _)| &statement.keys[0].component_b_by_digit)
        .collect::<Vec<_>>();
    let aggregate_diagonal =
        round_one_aggregate_diagonal_from_components(&round_one_components, level, ring_degree)?;

    let mut instances = Vec::with_capacity(trustee_count);
    for (trustee_index, (mut statement, mut witness)) in round_one_instances.into_iter().enumerate()
    {
        // Round-two share: source = trustee secret (*) public aggregate.
        let key_switch_domain = "relinearization-round-two".to_string();
        let key_switch_seed_hex = format!("{ceremony_seed_hex}-trustee-{trustee_index}-round-two");
        let digit_count = level + 1;
        let error_coefficients_by_digit = sample_development_errors(
            &key_switch_domain,
            &key_switch_seed_hex,
            digit_count,
            ring_degree,
        );
        let mut diagonal_source_by_digit = Vec::with_capacity(digit_count);
        for (digit_index, modulus) in DATA_PRIMES[..=level].iter().enumerate() {
            let secret_residues = witness
                .secret_coefficients
                .iter()
                .map(|coefficient| signed_value_residue(*coefficient, *modulus))
                .collect::<Vec<_>>();
            diagonal_source_by_digit.push(negacyclic_ring_product(
                &secret_residues,
                &aggregate_diagonal[digit_index],
                *modulus,
            )?);
        }
        let component_b_by_digit = build_component_material(
            &key_switch_domain,
            &key_switch_seed_hex,
            level,
            ring_degree,
            &witness.secret_coefficients,
            &error_coefficients_by_digit,
            &diagonal_source_by_digit,
        )?;
        statement.keys.push(EvaluationKeyShareDescriptor {
            kind: EvaluationKeyShareKind::RelinearizationRoundTwo,
            level,
            key_switch_domain,
            key_switch_seed_hex,
            component_b_by_digit,
            round_one_aggregate_diagonal: aggregate_diagonal.clone(),
        });
        witness
            .error_coefficients_by_key
            .push(error_coefficients_by_digit);
        instances.push((statement, witness));
    }

    Ok(instances)
}
