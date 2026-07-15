use super::super::evaluation_domain::negacyclic_ring_product;
use super::super::{invalid_succinct_setup_proof, signed_value_residue};
use super::key_relation_algebra::public_key_switch_sample;
use super::statement_types::{
    EvaluationKeyShareDescriptor, EvaluationKeyShareKind, KeyBearingWitness,
    SameSecretLinkageStatement, SameSecretLinkageWitness, SetupProofStatement,
    SuccinctSetupProofContext, TrusteeEvaluationKeyStatement, TrusteeEvaluationKeyWitness,
};
use crate::bgv::evaluator::key_switch::{KEY_SWITCH_ERROR_DOMAIN, PLAINTEXT_MODULUS_I64};
use crate::bgv::evaluator::prg::DeterministicSampler;
use crate::bgv::modular_arithmetic::{add_mod_fast, sub_mod_fast};
use crate::bgv::parameters::DATA_PRIMES;
use crate::bgv::setup::commitment::SETUP_COMMITMENT_RANDOMNESS_WIDTH;
use crate::bgv::setup::commitment::compute_setup_big_signed_lifted_commitment;
use crate::bgv::setup::setup_proof::SetupProofFamily;
use crate::encoding::CanonicalResult;
use crate::hashing::{derive_canonical_object_hash, hash_framed_parts_512 as hash512};
use num_bigint::BigInt;
use serde_json::json;

const WITNESS_SECRET_DOMAIN: &str = "sealed-lattice/setup/trustee-evaluation-key/witness-secret";

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
    "sealed-lattice/setup/trustee-evaluation-key/development-round-one-aggregate";

// One development key descriptor plus its errors, for an already-sampled
// shared secret.
fn generate_development_key(
    kind: EvaluationKeyShareKind,
    public_matrix_seed_hash: &str,
    evaluator_key_schedule_root: &str,
    level: usize,
    ring_degree: usize,
    secret_coefficients: &[i64],
) -> CanonicalResult<(EvaluationKeyShareDescriptor, Vec<Vec<i64>>)> {
    let (key_switch_domain, key_switch_seed_hex) = match kind {
        EvaluationKeyShareKind::RelinearizationRoundOne => (
            "relinearization".to_string(),
            derive_canonical_object_hash(&json!({
                "objectType": "RelinearizationKeySwitchPublicSampleSeed",
                "publicMatrixSeedHash": public_matrix_seed_hash,
                "evaluatorKeyScheduleRoot": evaluator_key_schedule_root,
                "round": "round-one",
                "level": level,
            }))?,
        ),
        EvaluationKeyShareKind::RelinearizationRoundTwo => (
            "relinearization".to_string(),
            derive_canonical_object_hash(&json!({
                "objectType": "RelinearizationKeySwitchPublicSampleSeed",
                "publicMatrixSeedHash": public_matrix_seed_hash,
                "evaluatorKeyScheduleRoot": evaluator_key_schedule_root,
                "round": "round-two",
                "level": level,
            }))?,
        ),
        EvaluationKeyShareKind::GaloisRotation { galois_element } => (
            format!("galois-{galois_element}"),
            derive_canonical_object_hash(&json!({
                "objectType": "GaloisKeySwitchPublicSampleSeed",
                "publicMatrixSeedHash": public_matrix_seed_hash,
                "evaluatorKeyScheduleRoot": evaluator_key_schedule_root,
                "rotation": galois_element,
                "level": level,
            }))?,
        ),
    };
    let digit_count = level + 1;
    let error_coefficients_by_digit = sample_development_errors(
        &key_switch_domain,
        &key_switch_seed_hex,
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
        };
        diagonal_source_by_digit.push(source);
    }
    let component_b_by_digit = build_component_material(
        &key_switch_domain,
        &key_switch_seed_hex,
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
            key_switch_seed_hex,
            component_b_by_digit,
            round_one_aggregate_diagonal,
        },
        error_coefficients_by_digit,
    ))
}

const LINKAGE_RANDOMNESS_DOMAIN: &str =
    "sealed-lattice/setup/trustee-evaluation-key/linkage-opening-randomness";
const LINKAGE_MATRIX_SEED_DOMAIN: &str =
    "sealed-lattice/setup/trustee-evaluation-key/linkage-matrix-seed";

// Development instance generator for a whole trustee key schedule: one shared
// ternary secret and a list of key kinds at their levels, all with real
// production-shaped component material and its required same-secret linkage:
// real BDLOP constant commitments to the lifted secret message, with fresh
// ternary opening randomness.
fn development_context(key_switch_seed_hex: &str) -> SuccinctSetupProofContext {
    let derived = |label: &str| -> String {
        hash512(
            "sealed-lattice/setup/trustee-evaluation-key/development-context",
            &[key_switch_seed_hex.as_bytes(), label.as_bytes()],
        )
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
    };
    SuccinctSetupProofContext {
        setup_context_hash: derived("setup-context"),
        trustee_identity: format!("development-trustee-{key_switch_seed_hex}"),
        trustee_roster_position: 1,
        binding_roots: SetupProofFamily::TrusteeEvaluationKey
            .binding_labels()
            .iter()
            .map(|label| derived(label))
            .collect(),
    }
}

pub(crate) fn generate_development_trustee_instance_with_linkage(
    key_switch_seed_hex: &str,
    key_requests: &[(EvaluationKeyShareKind, usize)],
    ring_degree: usize,
    linkage_commitment_count: usize,
) -> CanonicalResult<(TrusteeEvaluationKeyStatement, TrusteeEvaluationKeyWitness)> {
    let secret_coefficients =
        DeterministicSampler::new(WITNESS_SECRET_DOMAIN, &[key_switch_seed_hex.as_bytes()])
            .ternary(ring_degree);
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
    let context = development_context(key_switch_seed_hex);
    let evaluator_key_schedule_root = &context.binding_roots[0];
    let mut keys = Vec::with_capacity(key_requests.len());
    let mut error_coefficients_by_key = Vec::with_capacity(key_requests.len());
    for (kind, level) in key_requests {
        let (descriptor, errors) = generate_development_key(
            *kind,
            &public_matrix_seed_hash,
            evaluator_key_schedule_root,
            *level,
            ring_degree,
            &secret_coefficients,
        )?;
        keys.push(descriptor);
        error_coefficients_by_key.push(errors);
    }
    let negative_indicator_coefficients = secret_coefficients
        .iter()
        .map(|coefficient| i64::from(*coefficient < 0))
        .collect::<Vec<_>>();
    let mut commitments = Vec::with_capacity(linkage_commitment_count);
    let mut opening_randomness_by_limb = Vec::with_capacity(linkage_commitment_count);
    for (source_limb_index, source_modulus) in DATA_PRIMES[..linkage_commitment_count]
        .iter()
        .copied()
        .enumerate()
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
            0,
            &message,
            &randomness_i128,
            ring_degree,
        )?);
        opening_randomness_by_limb.push(randomness);
    }
    let same_secret_linkage = SameSecretLinkageStatement {
        public_matrix_seed_hash,
        commitments,
    };
    let linkage_witness = SameSecretLinkageWitness {
        negative_indicator_coefficients,
        opening_randomness_by_limb,
    };

    Ok((
        TrusteeEvaluationKeyStatement {
            context,
            ring_degree,
            proof: SetupProofStatement::TrusteeEvaluationKey {
                keys,
                same_secret_linkage,
            },
        },
        TrusteeEvaluationKeyWitness::TrusteeEvaluationKey {
            key: KeyBearingWitness {
                secret_coefficients,
                error_coefficients_by_key,
            },
            linkage: linkage_witness,
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
        1,
    )
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
