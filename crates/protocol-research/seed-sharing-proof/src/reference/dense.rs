//! Independent integer equations for the reduced seed-sharing experiment.
//! This reference uses direct negacyclic products and physical coefficient
//! rows. It does not use the prover's signed-variable decoder, rotations,
//! coefficient fingerprints or geometric operator builder.

use crate::{DEGREE, RECIPIENTS, SEED_BITS, SUPPORT, modulus, profile, statement::Statement};
use num_bigint::BigInt;
use word_proof::{
    affine::{Operator, PublicColumn},
    field::{self, Element, MODULUS, ONE, ZERO},
    parameters::SYSTEMATIC,
};

fn variable_widths() -> Vec<usize> {
    let parameters = profile();
    let mut widths = vec![
        parameters.share_limb_bits(),
        parameters.sharing_coefficient_bits() - parameters.share_limb_bits(),
    ];
    for _ in 0..RECIPIENTS {
        widths.extend([16, parameters.share_carry_bits(), 7, 16, 16, 7]);
    }
    widths
}

struct Decoded {
    signed: Vec<Vec<BigInt>>,
    support_columns: Vec<[Vec<BigInt>; 2]>,
    seed: Vec<BigInt>,
}

fn decode(columns: &[Vec<u16>]) -> Decoded {
    let widths = variable_widths();
    let words: usize = widths.iter().map(|bits| (bits / 16).max(1)).sum();
    let stride = SYSTEMATIC / DEGREE;
    let mut first_word = 0;
    let mut first_bit = words + 2 * RECIPIENTS + 1;
    let signed = widths
        .iter()
        .map(|&bits| {
            let whole = (bits / 16).max(1);
            let remaining = if bits < 16 { 0 } else { bits % 16 };
            let values = (0..DEGREE)
                .map(|position| {
                    let mut value = BigInt::from(0);
                    for word in 0..whole {
                        value += BigInt::from(columns[first_word + word][stride * position])
                            << (16 * word);
                    }
                    for bit in 0..remaining {
                        value += BigInt::from(columns[first_bit + bit][stride * position])
                            << (16 * whole + bit);
                    }
                    value - (BigInt::from(1u8) << (bits - 1))
                })
                .collect();
            first_word += whole;
            first_bit += remaining;
            values
        })
        .collect();
    assert_eq!(first_word, words);
    assert_eq!(first_bit, columns.len());
    let support_columns = (0..RECIPIENTS)
        .map(|recipient| {
            std::array::from_fn(|sign| {
                (0..DEGREE)
                    .map(|position| {
                        BigInt::from(columns[words + 2 * recipient + sign][stride * position])
                    })
                    .collect()
            })
        })
        .collect();
    let seed = (0..DEGREE)
        .map(|position| {
            if position < SEED_BITS {
                BigInt::from(columns[words + 2 * RECIPIENTS][stride * position])
            } else {
                BigInt::from(0)
            }
        })
        .collect();
    Decoded {
        signed,
        support_columns,
        seed,
    }
}

fn limb(value: &BigInt, index: usize, bits: usize) -> BigInt {
    let negative = value < &BigInt::from(0);
    let magnitude = if negative { -value } else { value.clone() };
    let digit = (magnitude >> (index * bits)) % (BigInt::from(1u8) << bits);
    if negative { -digit } else { digit }
}

fn product(public: &[BigInt], private: &[BigInt]) -> Vec<BigInt> {
    assert_eq!((public.len(), private.len()), (DEGREE, DEGREE));
    let mut output = vec![BigInt::from(0); DEGREE];
    for (left, value) in public.iter().enumerate() {
        for (right, coefficient) in private.iter().enumerate() {
            let term = value * coefficient;
            if left + right < DEGREE {
                output[left + right] += term;
            } else {
                output[left + right - DEGREE] -= term;
            }
        }
    }
    output
}

fn shifted(values: &[BigInt], recipient: usize) -> Vec<BigInt> {
    let exponent = recipient * (DEGREE / profile().interpolation_degree());
    let mut output = vec![BigInt::from(0); DEGREE];
    for (position, value) in values.iter().enumerate() {
        let destination = position + exponent;
        if (destination / DEGREE).is_multiple_of(2) {
            output[destination % DEGREE] += value;
        } else {
            output[destination % DEGREE] -= value;
        }
    }
    output
}

/// Recipient, component, limb and physical coefficient order, followed by
/// each recipient's positive and negative support equations. Range and
/// disjointness are the shared word engine's separate predicates.
pub(crate) fn residuals(statement: &Statement, columns: &[Vec<u16>]) -> Vec<BigInt> {
    let decoded = decode(columns);
    let bits = profile().share_limb_bits();
    let radix = BigInt::from(1u8) << bits;
    let scale = BigInt::from(supported_profile::SHARE_SCALE);
    let modulus = modulus();
    let mut rows = Vec::new();
    for (recipient, public) in statement.recipients.iter().enumerate() {
        let supports = &decoded.support_columns[recipient];
        let ephemeral: Vec<_> = supports[0]
            .iter()
            .zip(&supports[1])
            .map(|(positive, negative)| positive - negative)
            .collect();
        let low = shifted(&decoded.signed[0], recipient);
        let high = shifted(&decoded.signed[1], recipient);
        let offset = shifted(&vec![&scale * (&radix / 2u8); DEGREE], recipient);
        for component in 0..2 {
            let start = 2 + 6 * recipient + 3 * component;
            let quotient = &decoded.signed[start];
            let carry = &decoded.signed[start + 1];
            let error = &decoded.signed[start + 2];
            let common = if component == 0 {
                &public.public_key
            } else {
                &statement.common
            };
            for digit_index in 0..2 {
                let digits: Vec<_> = common
                    .iter()
                    .map(|value| limb(value, digit_index, bits))
                    .collect();
                let convolution = product(&digits, &ephemeral);
                for position in 0..DEGREE {
                    let mut row = &convolution[position]
                        - limb(&public.ciphertext[component][position], digit_index, bits)
                        - limb(&modulus, digit_index, bits) * &quotient[position];
                    if component == 0 {
                        row += limb(&offset[position], digit_index, bits);
                        row += &scale
                            * if digit_index == 0 {
                                &low[position] + &decoded.seed[position]
                            } else {
                                high[position].clone()
                            };
                    }
                    if digit_index == 0 {
                        row += &error[position] - &radix * &carry[position];
                    } else {
                        row += &carry[position];
                    }
                    rows.push(row);
                }
            }
        }
    }
    for supports in decoded.support_columns {
        for column in supports {
            rows.push(column.into_iter().sum::<BigInt>() - BigInt::from(SUPPORT / 2));
        }
    }
    rows
}

pub(crate) fn weighted_residual(
    statement: &Statement,
    columns: &[Vec<u16>],
    alpha: Element,
) -> Element {
    let modulus = BigInt::from(MODULUS);
    let mut weight = ONE;
    let mut result = ZERO;
    for row in residuals(statement, columns) {
        let residue = ((row % &modulus) + &modulus) % &modulus;
        result = field::add(
            result,
            field::scale(weight, u128::try_from(residue).unwrap()),
        );
        weight = field::multiply(weight, alpha);
    }
    result
}

/// Applies the emitted operator by its public term definition, without
/// allocating a full proof-domain matrix or using its geometric helpers.
pub(crate) fn apply_operator(operator: &Operator, columns: &[Vec<u16>]) -> Element {
    let mut result = field::subtract(ZERO, operator.target);
    for term in &operator.terms {
        let values = match &term.public {
            PublicColumn::Ones(degree) => vec![ONE; *degree],
            PublicColumn::Values(values) => values.clone(),
            PublicColumn::Powers(degree) => {
                let mut power = ONE;
                (0..*degree)
                    .map(|_| {
                        let previous = power;
                        power = field::multiply(power, operator.alpha);
                        previous
                    })
                    .collect()
            }
        };
        let stride = SYSTEMATIC / values.len();
        for (column, weight) in &term.weights {
            for (position, value) in values.iter().enumerate() {
                result = field::add(
                    result,
                    field::scale(
                        field::multiply(*value, *weight),
                        u128::from(columns[*column][stride * position]),
                    ),
                );
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{layout::Layout, operator, statement::encoded_bytes};
    use word_proof::oracles::Witness;

    #[test]
    fn quarter_modulus_ciphertext_has_no_bounded_witness_with_zero_public_polynomials() {
        let parameters = profile();
        assert_eq!(parameters.release_threshold(), 2);
        let modulus = modulus();
        let target = &modulus / 4u8;
        let (mut statement, _) = crate::tests::fixture();
        statement.common.fill(BigInt::from(0));
        for recipient in &mut statement.recipients {
            recipient.public_key.fill(BigInt::from(0));
            for component in &mut recipient.ciphertext {
                component.fill(BigInt::from(0));
            }
        }
        statement.recipients[0].ciphertext[0][0] = target.clone();
        let encoded = statement.encode().unwrap();
        assert_eq!(
            Statement::decode(&encoded, &statement.scope).unwrap(),
            statement
        );
        let (emitted, witness) = crate::fixture::impossible_share();
        assert_eq!(emitted, statement);
        let integer_rows = residuals(&statement, &witness.columns);
        assert!(integer_rows.iter().any(|row| *row != BigInt::from(0)));
        let alpha = [17, 29, 43];
        let weighted = weighted_residual(&statement, &witness.columns, alpha);
        assert_ne!(weighted, ZERO);
        assert_eq!(
            apply_operator(
                &operator::build(&statement, alpha).unwrap(),
                &witness.columns
            ),
            weighted
        );
        let (zero_statement, zero_witness) = crate::fixture::zero_source();
        let mut expected_zero = statement.clone();
        expected_zero.recipients[0].ciphertext[0][0] = BigInt::from(0);
        assert_eq!(zero_statement, expected_zero);
        assert!(
            residuals(&zero_statement, &zero_witness.columns)
                .iter()
                .all(|row| *row == BigInt::from(0))
        );

        let bits = parameters.share_limb_bits();
        let radix = BigInt::from(1u8) << bits;
        let sharing_radius = BigInt::from(1u8) << (parameters.sharing_coefficient_bits() - 1);
        let high_radius = BigInt::from(1u8)
            << (parameters.sharing_coefficient_bits() - parameters.share_limb_bits() - 1);
        let low_radius = &radix / 2u8;
        // The independent signed-word decoder represents A1 as low + R*high
        // + R/2. Its full allowed interval is exactly [-B, B-1], not merely
        // the subset that the honest witness generator happens to produce.
        let smallest_sharing = -&low_radius - &radix * &high_radius + &low_radius;
        let largest_sharing = &low_radius - 1u8 + &radix * (&high_radius - 1u8) + &low_radius;
        assert_eq!(smallest_sharing, -&sharing_radius);
        assert_eq!(largest_sharing, &sharing_radius - 1u8);

        let scale = BigInt::from(supported_profile::SHARE_SCALE);
        let error_radius = BigInt::from(64);
        let quotient_radius = BigInt::from(1u8) << 15usize;
        let carry_radius = BigInt::from(1u8) << (parameters.share_carry_bits() - 1);
        let offset = &scale * &low_radius;
        let proof_prime = BigInt::from(MODULUS);
        // Bound both emitted limb rows for every accepted signed witness.
        // Neither can vanish by wrapping the proof field, so vanishing rows
        // imply integer equalities; low + R*high then cancels the carry.
        let low_residual_bound = limb(&target, 0, bits)
            + limb(&modulus, 0, bits) * &quotient_radius
            + &scale * (&low_radius + 1u8)
            + limb(&offset, 0, bits)
            + &error_radius
            + &radix * &carry_radius;
        let high_residual_bound = limb(&target, 1, bits)
            + limb(&modulus, 1, bits) * &quotient_radius
            + &scale * &high_radius
            + limb(&offset, 1, bits)
            + &carry_radius;
        assert!(low_residual_bound < proof_prime);
        assert!(high_residual_bound < proof_prime);
        for value in [&target, &modulus, &offset] {
            assert_eq!(limb(value, 0, bits) + &radix * limb(value, 1, bits), *value);
        }

        // Recipient zero has interpolation point one. Its seed coefficient
        // is 0 or 1, hence M0 lies in [-B, B]. Zero common/key polynomials
        // remove the ephemeral product for every possible private support.
        // Every remaining right-hand side is in [-T,T]. The target lies in
        // (T,q-T), so no integer quotient makes U = scale*M0 + error mod q.
        let maximum_plaintext_term = &scale * (&sharing_radius + 1u8) + error_radius;
        assert!(target > maximum_plaintext_term);
        assert!(&modulus - &target > maximum_plaintext_term);
        assert!(target <= &modulus / 2u8);
    }

    fn boundary_inputs(seed_bit: u8, phase: usize) -> crate::witness::Inputs {
        let radius = 1i128 << (profile().sharing_coefficient_bits() - 1);
        let boundaries = [-radius, -radius + 1, radius - 2, radius - 1];
        crate::witness::Inputs {
            seed: vec![seed_bit; SEED_BITS],
            sharing: (0..DEGREE)
                .map(|position| boundaries[(position + phase) % boundaries.len()])
                .collect(),
            ephemeral: (0..RECIPIENTS)
                .map(|recipient| {
                    (0..DEGREE)
                        .map(|position| {
                            if (position + 13 * recipient) % DEGREE < SUPPORT / 2 {
                                1
                            } else {
                                -1
                            }
                        })
                        .collect()
                })
                .collect(),
            errors: (0..RECIPIENTS)
                .map(|recipient| {
                    std::array::from_fn(|component| {
                        (0..DEGREE)
                            .map(|position| {
                                if (position + recipient + component + phase).is_multiple_of(2) {
                                    -64
                                } else {
                                    63
                                }
                            })
                            .collect()
                    })
                })
                .collect(),
        }
    }

    fn centered(value: BigInt) -> BigInt {
        let divisor = modulus();
        let residue = ((value % &divisor) + &divisor) % &divisor;
        if 2u8 * &residue > divisor {
            residue - divisor
        } else {
            residue
        }
    }

    fn assert_original_key_decryption(statement: &Statement, inputs: &crate::witness::Inputs) {
        let scale = BigInt::from(supported_profile::SHARE_SCALE);
        let sharing: Vec<_> = inputs.sharing.iter().copied().map(BigInt::from).collect();
        // This is the fixed key fixture's independently specified secret
        // sequence, not a secret recovered from the ciphertext or its proof.
        for (recipient, public) in statement.recipients.iter().enumerate() {
            let key: Vec<_> = (0..DEGREE)
                .map(|position| {
                    BigInt::from(if (position + 17 * recipient) % DEGREE < SUPPORT / 2 {
                        1
                    } else {
                        -1
                    })
                })
                .collect();
            let key_product = product(&statement.common, &key);
            let errors: Vec<_> = (0..DEGREE)
                .map(|position| {
                    let actual = centered(&key_product[position] + &public.public_key[position]);
                    assert_eq!(
                        actual,
                        BigInt::from(((position + recipient) % 128) as i128 - 64)
                    );
                    actual
                })
                .collect();
            let ephemeral: Vec<_> = inputs.ephemeral[recipient]
                .iter()
                .copied()
                .map(BigInt::from)
                .collect();
            let key_error_product = product(&errors, &ephemeral);
            let linear_error: Vec<_> = inputs.errors[recipient][1]
                .iter()
                .copied()
                .map(BigInt::from)
                .collect();
            let linear_error_product = product(&linear_error, &key);
            let decoded_product = product(&public.ciphertext[1], &key);
            let mut expected = shifted(&sharing, recipient);
            for (position, bit) in inputs.seed.iter().enumerate() {
                expected[position] += *bit;
            }
            for position in 0..DEGREE {
                let phase = centered(&decoded_product[position] + &public.ciphertext[0][position]);
                let negative = phase < BigInt::from(0);
                let magnitude = if negative { -&phase } else { phase.clone() };
                let nearest = (magnitude + &scale / 2u8) / &scale;
                let plaintext = if negative { -nearest } else { nearest };
                assert_eq!(
                    plaintext, expected[position],
                    "recipient {recipient}, coefficient {position}"
                );
                let error = phase - &scale * &expected[position];
                assert_eq!(
                    error,
                    &key_error_product[position]
                        + &linear_error_product[position]
                        + inputs.errors[recipient][0][position]
                );
                let radius = BigInt::from((2 * SUPPORT + 1) * 64);
                assert!(error >= -&radius && error <= radius);
            }
        }
    }

    #[test]
    fn sharing_endpoints_and_extreme_errors_verify_and_decrypt_under_original_keys() {
        let (public, _) = crate::tests::fixture();
        let keys: Vec<_> = public
            .recipients
            .iter()
            .map(|recipient| recipient.public_key.clone())
            .collect();
        for seed_bit in [0, 1] {
            for phase in 0..4 {
                let inputs = boundary_inputs(seed_bit, phase);
                let (statement, witness) = crate::witness::create(
                    public.scope.clone(),
                    public.common.clone(),
                    keys.clone(),
                    boundary_inputs(seed_bit, phase),
                )
                .unwrap();
                let encoded = statement.encode().unwrap();
                let statement = Statement::decode(&encoded, &statement.scope).unwrap();
                assert_original_key_decryption(&statement, &inputs);
                let rows = residuals(&statement, &witness.columns);
                assert!(
                    rows.iter().all(|row| row == &BigInt::from(0)),
                    "seed {seed_bit}, phase {phase}"
                );
                let alpha = [17 + phase as u128, 29, 43 + u128::from(seed_bit)];
                let operator = operator::build(&statement, alpha).unwrap();
                assert_eq!(weighted_residual(&statement, &witness.columns, alpha), ZERO);
                assert_eq!(apply_operator(&operator, &witness.columns), ZERO);
            }
        }
    }

    #[test]
    fn the_first_outside_sharing_and_error_values_are_refused() {
        let (public, _) = crate::tests::fixture();
        let keys: Vec<_> = public
            .recipients
            .iter()
            .map(|recipient| recipient.public_key.clone())
            .collect();
        let radius = 1i128 << (profile().sharing_coefficient_bits() - 1);
        for (position, value) in [(0, radius), (DEGREE - 1, -radius - 1)] {
            let mut inputs = boundary_inputs(1, 0);
            inputs.sharing[position] = value;
            assert!(
                crate::witness::create(
                    public.scope.clone(),
                    public.common.clone(),
                    keys.clone(),
                    inputs
                )
                .is_err()
            );
        }
        for (recipient, component, value) in [(0, 0, -65), (RECIPIENTS - 1, 1, 64)] {
            let mut inputs = boundary_inputs(0, 0);
            inputs.errors[recipient][component][DEGREE - 1] = value;
            assert!(
                crate::witness::create(
                    public.scope.clone(),
                    public.common.clone(),
                    keys.clone(),
                    inputs
                )
                .is_err()
            );
        }
    }

    #[test]
    fn canonical_public_coefficient_endpoints_round_trip_and_outside_values_refuse() {
        let (mut statement, _) = crate::tests::fixture();
        let half = modulus() >> 1usize;
        statement.common[0] = half.clone();
        statement.common[1] = -&half;
        statement.common[2] = BigInt::from(0);
        for recipient in &mut statement.recipients {
            recipient.public_key[0] = -&half;
            recipient.public_key[1] = half.clone();
            recipient.ciphertext[0][0] = half.clone();
            recipient.ciphertext[1][0] = -&half;
        }
        let bytes = statement.encode().unwrap();
        assert_eq!(
            Statement::decode(&bytes, &statement.scope).unwrap(),
            statement
        );
        for negative in [false, true] {
            let outside: BigInt = if negative { -&half - 1 } else { &half + 1 };
            for polynomial in 0..4 {
                let mut altered = statement.clone();
                match polynomial {
                    0 => altered.common[0] = outside.clone(),
                    1 => altered.recipients[0].public_key[0] = outside.clone(),
                    2 => altered.recipients[0].ciphertext[0][0] = outside.clone(),
                    _ => altered.recipients[0].ciphertext[1][0] = outside.clone(),
                }
                assert!(altered.encode().is_err());
            }
            let mut common = statement.common.clone();
            common[0] = outside.clone();
            let keys: Vec<_> = statement
                .recipients
                .iter()
                .map(|recipient| recipient.public_key.clone())
                .collect();
            assert!(
                crate::witness::create(
                    statement.scope.clone(),
                    common,
                    keys.clone(),
                    boundary_inputs(0, 0)
                )
                .is_err()
            );
            let mut changed_keys = keys;
            changed_keys[RECIPIENTS - 1][DEGREE - 1] = outside;
            assert!(
                crate::witness::create(
                    statement.scope.clone(),
                    statement.common.clone(),
                    changed_keys,
                    boundary_inputs(1, 1)
                )
                .is_err()
            );
        }
    }

    #[test]
    fn direct_integer_rows_match_honest_and_range_valid_hostile_witnesses() {
        let (statement, witness) = crate::tests::fixture();
        let rows = residuals(&statement, &witness.columns);
        assert_eq!(rows.len(), 4 * RECIPIENTS * DEGREE + 2 * RECIPIENTS);
        assert!(rows.iter().all(|row| row == &BigInt::from(0)));
        let layout = Layout::new(encoded_bytes());
        let stride = SYSTEMATIC / DEGREE;
        let alpha = [17, 29, 43];
        let operator = operator::build(&statement, alpha).unwrap();
        assert_eq!(apply_operator(&operator, &witness.columns), ZERO);
        assert_eq!(weighted_residual(&statement, &witness.columns, alpha), ZERO);
        let mut expected_lookup = ONE;
        for _ in &rows {
            expected_lookup = field::multiply(expected_lookup, alpha);
        }
        assert_eq!(operator.lookup_weight, expected_lookup);

        // Every signed variable's low word, at changing physical positions:
        // sharing, both components' quotients, carries and error words of
        // every recipient. These edits stay inside their encoded ranges.
        let mut first_word = 0;
        for (variable, width) in variable_widths().into_iter().enumerate() {
            let mut columns = witness.columns.clone();
            let position = (variable * 37 + 11) % DEGREE;
            columns[first_word][position * stride] ^= 1;
            Witness::from_columns(&layout.relation, witness.statement, columns.clone()).unwrap();
            let dense = weighted_residual(&statement, &columns, alpha);
            assert_ne!(dense, ZERO, "signed variable {variable}");
            assert_eq!(
                apply_operator(&operator, &columns),
                dense,
                "signed variable {variable}"
            );
            first_word += (width / 16).max(1);
        }
        assert_eq!(first_word, layout.relation.words);

        let mut changed = witness.columns.clone();
        changed[layout.seed][0] ^= 1;
        Witness::from_columns(&layout.relation, witness.statement, changed.clone()).unwrap();
        let dense = weighted_residual(&statement, &changed, alpha);
        assert_ne!(dense, ZERO);
        assert_eq!(apply_operator(&operator, &changed), dense);

        // Swap signs at two coefficients while preserving both support
        // counts and disjointness: range checking alone must not accept it.
        let mut changed = witness.columns.clone();
        let positive = first_word;
        let negative = positive + 1;
        let first = (0..DEGREE)
            .find(|position| changed[positive][position * stride] == 1)
            .unwrap();
        let second = (0..DEGREE)
            .find(|position| changed[negative][position * stride] == 1)
            .unwrap();
        changed[positive].swap(first * stride, second * stride);
        changed[negative].swap(first * stride, second * stride);
        Witness::from_columns(&layout.relation, witness.statement, changed.clone()).unwrap();
        let dense = weighted_residual(&statement, &changed, alpha);
        assert_ne!(dense, ZERO);
        assert_eq!(apply_operator(&operator, &changed), dense);
    }

    #[test]
    fn public_operand_changes_reach_the_independent_integer_relation() {
        let (statement, witness) = crate::tests::fixture();
        for change in 0..4 {
            let mut altered = statement.clone();
            match change {
                0 => altered.common[5] += 1,
                1 => altered.recipients[2].public_key[7] += 1,
                2 => altered.recipients[3].ciphertext[0][11] += 1,
                _ => altered.recipients[1].ciphertext[1][13] += 1,
            }
            altered.encode().unwrap();
            let alpha = [911, 71, 5];
            let operator = operator::build(&altered, alpha).unwrap();
            let dense = weighted_residual(&altered, &witness.columns, alpha);
            assert_ne!(dense, ZERO, "public operand {change}");
            assert_eq!(apply_operator(&operator, &witness.columns), dense);
        }
    }
}
