use super::super::{
    negacyclic_transform::NegacyclicDomain, proof_field::sixteen_limb_group_field_parameters,
};
use super::key_proof::{DigitPublic, DigitWitness, KeyPublic, KeySource};

pub(super) fn build_synthetic_key_fixture(
    ring_degree: usize,
    digit_count: usize,
    key_source: &KeySource<13>,
) -> (Vec<i64>, Vec<DigitWitness>, KeyPublic<13>) {
    let proof_field_parameters = sixteen_limb_group_field_parameters();
    let negacyclic_domain =
        NegacyclicDomain::new(&proof_field_parameters, ring_degree).expect("synthetic key domain");
    let secret_coefficients: Vec<i64> = (0..ring_degree)
        .map(|coefficient_index| ((coefficient_index * 7) % 3) as i64 - 1)
        .collect();
    let secret_field_elements: Vec<[u64; 13]> = secret_coefficients
        .iter()
        .map(|coefficient| proof_field_parameters.signed_word_to_element(*coefficient))
        .collect();
    let group_modulus = proof_field_parameters.unsigned_word_to_element(1_000_003);
    let plaintext_modulus = proof_field_parameters.unsigned_word_to_element(65_537);
    let mut digit_witnesses = Vec::with_capacity(digit_count);
    let mut public_digit_records = Vec::with_capacity(digit_count);

    for digit_index in 0..digit_count {
        let error_coefficients: Vec<i64> = (0..ring_degree)
            .map(|coefficient_index| (((coefficient_index + digit_index) * 5) % 5) as i64 - 2)
            .collect();
        let carry_coefficients: Vec<i64> = (0..ring_degree)
            .map(|coefficient_index| ((coefficient_index + digit_index) % 3) as i64 - 1)
            .collect();
        let error_field_elements: Vec<[u64; 13]> = error_coefficients
            .iter()
            .map(|coefficient| proof_field_parameters.signed_word_to_element(*coefficient))
            .collect();
        let carry_field_elements: Vec<[u64; 13]> = carry_coefficients
            .iter()
            .map(|coefficient| proof_field_parameters.signed_word_to_element(*coefficient))
            .collect();
        let mut recombined_sample = Vec::with_capacity(ring_degree);
        let mut sample_state = 0xa5_u64.wrapping_add(digit_index as u64 * 0x1000);
        for _ in 0..ring_degree {
            sample_state = sample_state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            recombined_sample.push(proof_field_parameters.unsigned_word_to_element(sample_state));
        }
        let gadget_idempotent =
            proof_field_parameters.unsigned_word_to_element(0x9e37 + digit_index as u64);
        let sample_times_secret =
            negacyclic_domain.negacyclic_product(&recombined_sample, &secret_field_elements);
        let non_round_one_diagonal_term: Option<Vec<[u64; 13]>> = match key_source {
            KeySource::RoundOne => None,
            KeySource::Galois { galois_element } => Some(
                automorphism_image(&secret_coefficients, *galois_element)
                    .iter()
                    .map(|coefficient| {
                        proof_field_parameters.multiply(
                            &gadget_idempotent,
                            &proof_field_parameters.signed_word_to_element(*coefficient),
                        )
                    })
                    .collect(),
            ),
            KeySource::RoundTwo { aggregate_by_digit } => Some(
                negacyclic_domain
                    .negacyclic_product(&secret_field_elements, &aggregate_by_digit[digit_index]),
            ),
        };
        let mut recombined_component_b = vec![proof_field_parameters.zero(); ring_degree];
        for coefficient_index in 0..ring_degree {
            let plaintext_times_error = proof_field_parameters
                .multiply(&plaintext_modulus, &error_field_elements[coefficient_index]);
            let diagonal_coefficient = if let Some(diagonal_term) = &non_round_one_diagonal_term {
                diagonal_term[coefficient_index]
            } else {
                proof_field_parameters.multiply(
                    &gadget_idempotent,
                    &secret_field_elements[coefficient_index],
                )
            };
            let modulus_times_carry = proof_field_parameters
                .multiply(&group_modulus, &carry_field_elements[coefficient_index]);
            let relation_sum =
                proof_field_parameters.add(&plaintext_times_error, &diagonal_coefficient);
            let relation_sum = proof_field_parameters.add(&relation_sum, &modulus_times_carry);
            recombined_component_b[coefficient_index] = proof_field_parameters
                .subtract(&relation_sum, &sample_times_secret[coefficient_index]);
        }
        digit_witnesses.push(DigitWitness {
            error: error_coefficients,
            carry: carry_coefficients,
        });
        public_digit_records.push(DigitPublic {
            recombined_sample,
            recombined_component_b,
            gadget_idempotent,
        });
    }

    (
        secret_coefficients,
        digit_witnesses,
        KeyPublic {
            digits: public_digit_records,
            group_modulus,
            plaintext_modulus,
        },
    )
}

fn automorphism_image(secret_coefficients: &[i64], galois_element: usize) -> Vec<i64> {
    let ring_degree = secret_coefficients.len();
    let ring_order = 2 * ring_degree;
    let mut image_coefficients = vec![0_i64; ring_degree];
    for (coefficient_index, coefficient) in secret_coefficients.iter().copied().enumerate() {
        let destination_index = (coefficient_index * galois_element) % ring_order;
        if destination_index < ring_degree {
            image_coefficients[destination_index] += coefficient;
        } else {
            image_coefficients[destination_index - ring_degree] -= coefficient;
        }
    }
    image_coefficients
}
