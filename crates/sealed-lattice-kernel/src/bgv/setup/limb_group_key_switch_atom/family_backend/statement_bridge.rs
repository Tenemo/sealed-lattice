//! Bridge from transported per-limb key-switch material to the atom family
//! backend's statement and witness.
//!
//! The CRT recombination reuses the tested `limb_group_statement` layer: each
//! digit's public sample and component collapse to centered mod-Q proof-field
//! vectors, the diagonal limb's CRT basis constant is the gadget idempotent,
//! and round two's aggregate becomes the centered diagonal term (the
//! recombination of the round-one aggregate placed at the diagonal limb, `G`
//! fold included). The per-digit carry witness is extracted from the exact
//! congruence: `c = (B + A (*) s - t e - diagonal) / Q` over the integers,
//! hosted in the proof field under the same exactness bound and `|c| <= N + 1`
//! carry bound the relation layer checks - a carry outside that bound means the
//! material does not satisfy the key-switch relation and the bridge refuses.

use super::super::limb_group_statement::{LimbGroupContext, validate_signed_support};
use super::super::negacyclic_transform::NegacyclicDomain;
use super::super::proof_field::ProofFieldParameters;
use super::key_proof::{DigitPublic, DigitWitness, KeyPublic, KeySource};
use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};

fn invalid_bridge(message: &str) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidProtocolObject, message)
}

// The key kind as transported: round one and Galois derive their diagonal
// source from the secret; round two carries the digit-diagonal round-one
// aggregate residues (reduced modulo the digit's own prime).
pub(super) enum BridgedKeyKind<'a> {
    RelinearizationRoundOne,
    Galois {
        galois_element: usize,
    },
    RelinearizationRoundTwo {
        aggregate_residues_by_digit: &'a [Vec<u64>],
    },
}

// The bridged statement and witness for one key: the family backend's public
// inputs and source, plus the per-digit witnesses with the extracted carries.
pub(super) struct BridgedKey<const LIMB_COUNT: usize> {
    pub(super) public: KeyPublic<LIMB_COUNT>,
    pub(super) source: KeySource<LIMB_COUNT>,
    pub(super) digits: Vec<DigitWitness>,
}

// The forward automorphism image `phi_g(s)`: `s(X) -> s(X^g)` as a signed
// vector, mirroring the tested transpose map's semantics.
fn galois_signed_image(secret: &[i64], galois_element: usize) -> Vec<i64> {
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

pub(super) struct BridgeKeyMaterialInput<'a, const LIMB_COUNT: usize> {
    pub(super) group: &'a LimbGroupContext<LIMB_COUNT>,
    pub(super) domain: &'a NegacyclicDomain<'a, LIMB_COUNT>,
    // component_b_by_digit[digit][limb] is one coefficient vector mod q_limb.
    pub(super) component_b_by_digit: &'a [Vec<Vec<u64>>],
    // public_sample_by_digit[digit][limb] likewise.
    pub(super) public_sample_by_digit: &'a [Vec<Vec<u64>>],
    pub(super) secret_coefficients: &'a [i64],
    // error_coefficients_by_digit[digit] is the eta-2 error vector.
    pub(super) error_coefficients_by_digit: &'a [Vec<i64>],
    pub(super) kind: BridgedKeyKind<'a>,
    pub(super) plaintext_modulus: u64,
}

pub(super) fn bridge_key_material<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    input: BridgeKeyMaterialInput<'_, LIMB_COUNT>,
) -> CanonicalResult<BridgedKey<LIMB_COUNT>> {
    let ring_degree = input.domain.size;
    let digit_count = input.component_b_by_digit.len();
    if digit_count == 0 || input.public_sample_by_digit.len() != digit_count {
        return Err(invalid_bridge(
            "bridged key digit counts must match and be non-empty",
        ));
    }
    if input.error_coefficients_by_digit.len() != digit_count {
        return Err(invalid_bridge(
            "bridged key error vectors must cover every digit",
        ));
    }
    if input.group.group_primes.len() != digit_count {
        return Err(invalid_bridge(
            "bridged key digit count must match the limb group size",
        ));
    }
    input
        .group
        .validate_exactness_bound(parameters, ring_degree)?;
    validate_signed_support(input.secret_coefficients, ring_degree, 1, "secret")?;
    for error in input.error_coefficients_by_digit {
        validate_signed_support(error, ring_degree, 2, "error")?;
    }

    let secret_field: Vec<[u64; LIMB_COUNT]> = input
        .secret_coefficients
        .iter()
        .map(|value| parameters.signed_word_to_element(*value))
        .collect();
    let plaintext_modulus_signed = i64::try_from(input.plaintext_modulus)
        .map_err(|_| invalid_bridge("plaintext modulus must fit a signed word"))?;

    // The family source and, per digit, the diagonal term the carry extraction
    // subtracts (matching the reduction's semantics exactly: `G * source` for
    // round one and Galois, and the centered diagonal aggregate `(*) s` for
    // round two).
    let mut aggregate_by_digit: Vec<Vec<[u64; LIMB_COUNT]>> = Vec::new();
    let galois_image;
    let source_signed: Option<&[i64]> = match &input.kind {
        BridgedKeyKind::RelinearizationRoundOne => Some(input.secret_coefficients),
        BridgedKeyKind::Galois { galois_element } => {
            galois_image = galois_signed_image(input.secret_coefficients, *galois_element);
            validate_signed_support(&galois_image, ring_degree, 1, "diagonal source")?;
            Some(&galois_image)
        }
        BridgedKeyKind::RelinearizationRoundTwo {
            aggregate_residues_by_digit,
        } => {
            if aggregate_residues_by_digit.len() != digit_count {
                return Err(invalid_bridge(
                    "round-two aggregates must cover every digit",
                ));
            }
            for (digit_index, aggregate_residues) in aggregate_residues_by_digit.iter().enumerate()
            {
                // The centered diagonal term: the aggregate at the diagonal
                // limb, zero at every other limb, CRT-recombined and centered.
                let padded_by_limb = (0..digit_count)
                    .map(|limb_index| {
                        if limb_index == digit_index {
                            aggregate_residues.clone()
                        } else {
                            vec![0_u64; ring_degree]
                        }
                    })
                    .collect::<Vec<_>>();
                aggregate_by_digit.push(input.group.recombine_centered(
                    parameters,
                    &padded_by_limb,
                    ring_degree,
                )?);
            }
            None
        }
    };

    let group_modulus_element = input.group.group_modulus_element(parameters);
    let group_modulus_inverse = parameters.inverse(&group_modulus_element);
    let plaintext_modulus_element = parameters.unsigned_word_to_element(input.plaintext_modulus);
    let carry_bound = ring_degree as u64 + 1;

    let mut public_digits = Vec::with_capacity(digit_count);
    let mut digit_witnesses = Vec::with_capacity(digit_count);
    for (digit_index, (component_b_by_limb, public_sample_by_limb)) in input
        .component_b_by_digit
        .iter()
        .zip(input.public_sample_by_digit.iter())
        .enumerate()
    {
        let recombined_component_b =
            input
                .group
                .recombine_centered(parameters, component_b_by_limb, ring_degree)?;
        let recombined_sample =
            input
                .group
                .recombine_centered(parameters, public_sample_by_limb, ring_degree)?;
        let gadget_idempotent = *input.group.gadget_idempotent(digit_index)?;

        // The diagonal term of this digit's congruence.
        let diagonal_term: Vec<[u64; LIMB_COUNT]> = match &input.kind {
            BridgedKeyKind::RelinearizationRoundOne | BridgedKeyKind::Galois { .. } => {
                let source = source_signed.expect("signed source is set for these kinds");
                source
                    .iter()
                    .map(|value| {
                        parameters.multiply(
                            &gadget_idempotent,
                            &parameters.signed_word_to_element(*value),
                        )
                    })
                    .collect()
            }
            BridgedKeyKind::RelinearizationRoundTwo { .. } => {
                let aggregate = aggregate_by_digit
                    .get(digit_index)
                    .expect("round-two aggregate is present for every digit");
                input.domain.negacyclic_product(aggregate, &secret_field)
            }
        };

        // Carry extraction: c = (B + A (*) s - t e - diagonal) / Q, exact over
        // the integers under the validated exactness bound; a carry outside
        // `|c| <= N + 1` means the material does not satisfy the relation.
        let sample_secret_product = input
            .domain
            .negacyclic_product(&recombined_sample, &secret_field);
        let error = &input.error_coefficients_by_digit[digit_index];
        let mut carry = Vec::with_capacity(ring_degree);
        for coefficient_index in 0..ring_degree {
            let mut difference = parameters.add(
                &recombined_component_b[coefficient_index],
                &sample_secret_product[coefficient_index],
            );
            let scaled_error = parameters
                .signed_word_to_element(error[coefficient_index] * plaintext_modulus_signed);
            difference = parameters.subtract(&difference, &scaled_error);
            difference = parameters.subtract(&difference, &diagonal_term[coefficient_index]);
            let carry_element = parameters.multiply(&difference, &group_modulus_inverse);
            let (is_negative, magnitude) = parameters.centered_raw(&carry_element);
            let magnitude_word = magnitude[0];
            if magnitude[1..].iter().any(|limb| *limb != 0) || magnitude_word > carry_bound {
                return Err(invalid_bridge(
                    "bridged key material does not satisfy the key-switch congruence: the carry lift exceeds its integer bound",
                ));
            }
            let signed = magnitude_word as i64;
            carry.push(if is_negative { -signed } else { signed });
        }

        public_digits.push(DigitPublic {
            recombined_sample,
            recombined_component_b,
            gadget_idempotent,
        });
        digit_witnesses.push(DigitWitness {
            error: error.clone(),
            carry,
        });
    }

    let source = match input.kind {
        BridgedKeyKind::RelinearizationRoundOne => KeySource::RoundOne,
        BridgedKeyKind::Galois { galois_element } => KeySource::Galois { galois_element },
        BridgedKeyKind::RelinearizationRoundTwo { .. } => {
            KeySource::RoundTwo { aggregate_by_digit }
        }
    };

    Ok(BridgedKey {
        public: KeyPublic {
            digits: public_digits,
            group_modulus: group_modulus_element,
            plaintext_modulus: plaintext_modulus_element,
        },
        source,
        digits: digit_witnesses,
    })
}

#[cfg(test)]
mod tests {
    use super::super::super::proof_field::sixteen_limb_group_field_parameters;
    use super::super::key_proof::{KeyFriProofParameters, prove_key_fri, verify_key_fri};
    use super::*;
    use crate::bgv::parameters::{DATA_PRIMES, PLAINTEXT_MODULUS};

    // Schoolbook negacyclic product of a residue vector and a signed vector,
    // reduced modulo one limb prime (the per-limb material construction).
    fn negacyclic_mod(residues: &[u64], signed: &[i64], modulus: u64) -> Vec<u64> {
        let degree = residues.len();
        let mut accumulator = vec![0_i128; degree];
        for (left_index, &left) in residues.iter().enumerate() {
            for (right_index, &right) in signed.iter().enumerate() {
                let position = left_index + right_index;
                let term = left as i128 * right as i128;
                if position < degree {
                    accumulator[position] += term;
                } else {
                    accumulator[position - degree] -= term;
                }
            }
        }
        accumulator
            .into_iter()
            .map(|value| value.rem_euclid(modulus as i128) as u64)
            .collect()
    }

    fn signed_residue(value: i64, modulus: u64) -> u64 {
        (value as i128).rem_euclid(modulus as i128) as u64
    }

    struct SyntheticLimbMaterial {
        component_b_by_digit: Vec<Vec<Vec<u64>>>,
        public_sample_by_digit: Vec<Vec<Vec<u64>>>,
        secret: Vec<i64>,
        errors_by_digit: Vec<Vec<i64>>,
        aggregates_by_digit: Vec<Vec<u64>>,
    }

    // Build per-limb key material at a reduced ring degree that satisfies the
    // real key-switch congruence for the chosen kind: for every digit j and
    // limb l, b_{j,l} = (t e_j + [l == j] source_j - a_{j,l} (*) s) mod q_l.
    fn synthetic_limb_material(
        ring_degree: usize,
        group_primes: &[u64],
        kind: &BridgedKeyKind<'_>,
    ) -> SyntheticLimbMaterial {
        let digit_count = group_primes.len();
        let secret: Vec<i64> = (0..ring_degree).map(|i| ((i * 7) % 3) as i64 - 1).collect();
        let mut errors_by_digit = Vec::with_capacity(digit_count);
        let mut component_b_by_digit = Vec::with_capacity(digit_count);
        let mut public_sample_by_digit = Vec::with_capacity(digit_count);
        let mut aggregates_by_digit = Vec::with_capacity(digit_count);

        for digit_index in 0..digit_count {
            let error: Vec<i64> = (0..ring_degree)
                .map(|i| (((i + digit_index) * 5) % 5) as i64 - 2)
                .collect();
            // Deterministic per-limb uniform samples.
            let samples_by_limb: Vec<Vec<u64>> = group_primes
                .iter()
                .enumerate()
                .map(|(limb_index, prime)| {
                    let mut state = 0x5eed_u64 ^ ((digit_index as u64) << 32) ^ (limb_index as u64);
                    (0..ring_degree)
                        .map(|_| {
                            state = state
                                .wrapping_mul(6_364_136_223_846_793_005)
                                .wrapping_add(1);
                            state % prime
                        })
                        .collect()
                })
                .collect();
            // The digit's diagonal aggregate (round two only), mod the digit's
            // own prime.
            let aggregate: Vec<u64> = {
                let prime = group_primes[digit_index];
                let mut state = 0xa66_u64 ^ (digit_index as u64);
                (0..ring_degree)
                    .map(|_| {
                        state = state
                            .wrapping_mul(6_364_136_223_846_793_005)
                            .wrapping_add(7);
                        state % prime
                    })
                    .collect()
            };
            // The signed diagonal source for this digit at each limb: round one
            // is s, Galois is phi_g(s); round two's diagonal term is
            // aggregate (*) s at the diagonal limb only.
            let source_signed: Option<Vec<i64>> = match kind {
                BridgedKeyKind::RelinearizationRoundOne => Some(secret.clone()),
                BridgedKeyKind::Galois { galois_element } => {
                    Some(galois_signed_image(&secret, *galois_element))
                }
                BridgedKeyKind::RelinearizationRoundTwo { .. } => None,
            };

            let component_b_by_limb: Vec<Vec<u64>> = group_primes
                .iter()
                .enumerate()
                .map(|(limb_index, prime)| {
                    let sample_times_secret =
                        negacyclic_mod(&samples_by_limb[limb_index], &secret, *prime);
                    (0..ring_degree)
                        .map(|coefficient_index| {
                            let mut value = signed_residue(
                                error[coefficient_index] * PLAINTEXT_MODULUS as i64,
                                *prime,
                            ) as i128;
                            if limb_index == digit_index {
                                match kind {
                                    BridgedKeyKind::RelinearizationRoundTwo { .. } => {
                                        let diagonal = negacyclic_mod(&aggregate, &secret, *prime);
                                        value += diagonal[coefficient_index] as i128;
                                    }
                                    _ => {
                                        let source = source_signed
                                            .as_ref()
                                            .expect("signed source for this kind");
                                        value += signed_residue(source[coefficient_index], *prime)
                                            as i128;
                                    }
                                }
                            }
                            value -= sample_times_secret[coefficient_index] as i128;
                            value.rem_euclid(*prime as i128) as u64
                        })
                        .collect()
                })
                .collect();

            errors_by_digit.push(error);
            component_b_by_digit.push(component_b_by_limb);
            public_sample_by_digit.push(samples_by_limb);
            aggregates_by_digit.push(aggregate);
        }

        SyntheticLimbMaterial {
            component_b_by_digit,
            public_sample_by_digit,
            secret,
            errors_by_digit,
            aggregates_by_digit,
        }
    }

    fn bridge_and_prove(
        kind_label: &str,
        material: &SyntheticLimbMaterial,
        kind: BridgedKeyKind<'_>,
    ) {
        let parameters = sixteen_limb_group_field_parameters();
        let ring_degree = material.secret.len();
        let group_primes = &DATA_PRIMES[..material.component_b_by_digit.len()];
        let group = LimbGroupContext::new(&parameters, group_primes).expect("group builds");
        let domain = NegacyclicDomain::new(&parameters, ring_degree).expect("domain builds");

        let bridged = bridge_key_material(
            &parameters,
            BridgeKeyMaterialInput {
                group: &group,
                domain: &domain,
                component_b_by_digit: &material.component_b_by_digit,
                public_sample_by_digit: &material.public_sample_by_digit,
                secret_coefficients: &material.secret,
                error_coefficients_by_digit: &material.errors_by_digit,
                kind,
                plaintext_modulus: PLAINTEXT_MODULUS,
            },
        )
        .expect("bridge accepts satisfying material");

        // Every extracted carry is inside the relation bound.
        for digit in &bridged.digits {
            assert!(
                digit
                    .carry
                    .iter()
                    .all(|carry| carry.unsigned_abs() <= ring_degree as u64 + 1),
                "{kind_label}: extracted carries stay within |c| <= N + 1"
            );
        }

        // The bridged statement and witness satisfy the family prover and
        // verifier end to end.
        let proof_parameters = KeyFriProofParameters {
            query_count: 40,
            mask_degree: 0,
        };
        let mut salt_seed = 0xb41d;
        let proof = prove_key_fri(
            &parameters,
            ring_degree,
            &bridged.public,
            &bridged.source,
            &material.secret,
            &bridged.digits,
            None,
            &proof_parameters,
            &mut salt_seed,
        )
        .expect("bridged material proves");
        assert!(
            verify_key_fri(
                &parameters,
                ring_degree,
                &bridged.public,
                &bridged.source,
                &proof,
                None,
                &proof_parameters
            )
            .expect("verify runs"),
            "{kind_label}: bridged key proof verifies"
        );
    }

    #[test]
    fn bridged_round_one_material_proves_and_verifies() {
        let kind = BridgedKeyKind::RelinearizationRoundOne;
        let material = synthetic_limb_material(64, &DATA_PRIMES[..2], &kind);
        bridge_and_prove("round one", &material, kind);
    }

    #[test]
    fn bridged_galois_material_proves_and_verifies() {
        let kind = BridgedKeyKind::Galois { galois_element: 5 };
        let material = synthetic_limb_material(64, &DATA_PRIMES[..2], &kind);
        bridge_and_prove("galois", &material, kind);
    }

    #[test]
    fn bridged_round_two_material_proves_and_verifies() {
        let placeholder = BridgedKeyKind::RelinearizationRoundTwo {
            aggregate_residues_by_digit: &[],
        };
        let material = synthetic_limb_material(64, &DATA_PRIMES[..2], &placeholder);
        let kind = BridgedKeyKind::RelinearizationRoundTwo {
            aggregate_residues_by_digit: &material.aggregates_by_digit,
        };
        bridge_and_prove("round two", &material, kind);
    }

    #[test]
    fn tampered_limb_material_is_refused_by_the_bridge() {
        // One corrupted limb residue breaks the congruence: the carry lift
        // lands outside |c| <= N + 1 and the bridge refuses instead of
        // producing an unsatisfiable witness.
        let kind = BridgedKeyKind::RelinearizationRoundOne;
        let mut material = synthetic_limb_material(64, &DATA_PRIMES[..2], &kind);
        material.component_b_by_digit[1][0][7] ^= 1;
        let parameters = sixteen_limb_group_field_parameters();
        let group_primes = &DATA_PRIMES[..2];
        let group = LimbGroupContext::new(&parameters, group_primes).expect("group builds");
        let domain = NegacyclicDomain::new(&parameters, 64).expect("domain builds");
        let result = bridge_key_material(
            &parameters,
            BridgeKeyMaterialInput {
                group: &group,
                domain: &domain,
                component_b_by_digit: &material.component_b_by_digit,
                public_sample_by_digit: &material.public_sample_by_digit,
                secret_coefficients: &material.secret,
                error_coefficients_by_digit: &material.errors_by_digit,
                kind,
                plaintext_modulus: PLAINTEXT_MODULUS,
            },
        );
        assert!(
            result.is_err(),
            "tampered limb material must be refused by carry extraction"
        );
    }

    #[test]
    fn wrong_secret_is_refused_by_the_bridge() {
        let kind = BridgedKeyKind::RelinearizationRoundOne;
        let material = synthetic_limb_material(64, &DATA_PRIMES[..2], &kind);
        let mut wrong_secret = material.secret.clone();
        wrong_secret[3] = if wrong_secret[3] == 1 { -1 } else { 1 };
        let parameters = sixteen_limb_group_field_parameters();
        let group = LimbGroupContext::new(&parameters, &DATA_PRIMES[..2]).expect("group builds");
        let domain = NegacyclicDomain::new(&parameters, 64).expect("domain builds");
        let result = bridge_key_material(
            &parameters,
            BridgeKeyMaterialInput {
                group: &group,
                domain: &domain,
                component_b_by_digit: &material.component_b_by_digit,
                public_sample_by_digit: &material.public_sample_by_digit,
                secret_coefficients: &wrong_secret,
                error_coefficients_by_digit: &material.errors_by_digit,
                kind,
                plaintext_modulus: PLAINTEXT_MODULUS,
            },
        );
        assert!(
            result.is_err(),
            "a wrong secret must be refused by carry extraction"
        );
    }
}
