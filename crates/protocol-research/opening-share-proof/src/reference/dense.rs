//! Independent physical-ring equations and original-key decoding. This
//! reference does not use the emitted equation builder, limb decoder,
//! rotations or signed-variable layout to derive its expected values.
use crate::{DEGREE, SELECTED, statement::Statement};
use num_bigint::BigInt;
use word_proof::{
    affine::{Operator, PublicColumn},
    field::{self, Element, MODULUS, ONE, ZERO},
    parameters::SYSTEMATIC,
};

// The registration and recovery model's independently maintained widths:
// one signed word each for quotient/carry, signed-seven key error, and
// signed-seventeen recovery noise. Sparse indicators follow the word columns.
fn widths() -> Vec<usize> {
    let mut widths = vec![16, 16, 7];
    widths.extend((0..SELECTED).flat_map(|_| [16, 16, 17]));
    widths
}
fn centered(value: BigInt, modulus: &BigInt) -> BigInt {
    let residue = ((value % modulus) + modulus) % modulus;
    if residue > modulus / 2u8 {
        residue - modulus
    } else {
        residue
    }
}
fn limb(value: &BigInt, index: usize) -> BigInt {
    let radix = BigInt::from(1u8) << 96usize;
    let magnitude = if value < &BigInt::from(0) {
        -value
    } else {
        value.clone()
    };
    let digit = (magnitude >> (96 * index)) % radix;
    if value < &BigInt::from(0) {
        -digit
    } else {
        digit
    }
}
fn product(public: &[BigInt], private: &[BigInt]) -> Vec<BigInt> {
    assert_eq!((public.len(), private.len()), (DEGREE, DEGREE));
    let mut output = vec![BigInt::from(0); DEGREE];
    for (right, coefficient) in private.iter().enumerate() {
        for (left, value) in public.iter().enumerate() {
            let destination = left + right;
            if destination < DEGREE {
                output[destination] += value * coefficient;
            } else {
                output[destination - DEGREE] -= value * coefficient;
            }
        }
    }
    output
}
struct Decoded {
    signed: Vec<Vec<BigInt>>,
    positive: Vec<BigInt>,
    negative: Vec<BigInt>,
}
fn decode(columns: &[Vec<u16>]) -> Decoded {
    let widths = widths();
    let words: usize = widths.iter().map(|bits| (bits / 16).max(1)).sum();
    let stride = SYSTEMATIC / DEGREE;
    let mut word = 0;
    let mut boolean = words + 2;
    let signed = widths
        .iter()
        .map(|&bits| {
            let whole = (bits / 16).max(1);
            let remaining = if bits < 16 { 0 } else { bits % 16 };
            let values = (0..DEGREE)
                .map(|row| {
                    let mut value = BigInt::from(0);
                    for index in 0..whole {
                        value += BigInt::from(columns[word + index][row * stride]) << (16 * index);
                    }
                    for index in 0..remaining {
                        value += BigInt::from(columns[boolean + index][row * stride])
                            << (16 * whole + index);
                    }
                    value - (BigInt::from(1u8) << (bits - 1))
                })
                .collect();
            word += whole;
            boolean += remaining;
            values
        })
        .collect();
    assert_eq!(boolean, columns.len());
    Decoded {
        signed,
        positive: (0..DEGREE)
            .map(|row| BigInt::from(columns[words][row * stride]))
            .collect(),
        negative: (0..DEGREE)
            .map(|row| BigInt::from(columns[words + 1][row * stride]))
            .collect(),
    }
}
fn residuals(statement: &Statement, columns: &[Vec<u16>]) -> Vec<BigInt> {
    let decoded = decode(columns);
    let secret: Vec<_> = decoded
        .positive
        .iter()
        .zip(&decoded.negative)
        .map(|(positive, negative)| positive - negative)
        .collect();
    let modulus = crate::modulus();
    let radix = BigInt::from(1u8) << 96usize;
    let scale = BigInt::from(supported_profile::SHARE_SCALE);
    let equations = std::iter::once((statement.public_key.clone(), statement.common.as_slice()))
        .chain(statement.packages.iter().map(|package| {
            let difference = package
                .constant
                .iter()
                .zip(&package.message)
                .map(|(constant, message)| centered(constant - &scale * message, &modulus))
                .collect();
            (difference, package.linear.as_slice())
        }));
    let mut rows = Vec::new();
    for (equation, (constant, linear)) in equations.enumerate() {
        let quotient = &decoded.signed[3 * equation];
        let carry = &decoded.signed[3 * equation + 1];
        let error = &decoded.signed[3 * equation + 2];
        for digit in 0..2 {
            let digits: Vec<_> = linear.iter().map(|value| limb(value, digit)).collect();
            let products = product(&digits, &secret);
            for row in 0..DEGREE {
                let mut residual = &products[row] + limb(&constant[row], digit)
                    - limb(&modulus, digit) * &quotient[row];
                if digit == 0 {
                    residual -= &error[row] + &radix * &carry[row];
                } else {
                    residual += &carry[row];
                }
                rows.push(residual);
            }
        }
    }
    for indicators in [&decoded.positive, &decoded.negative] {
        rows.push(indicators.iter().sum::<BigInt>() - BigInt::from(128));
    }
    rows
}
fn weighted(statement: &Statement, columns: &[Vec<u16>], alpha: Element) -> Element {
    let modulus = BigInt::from(MODULUS);
    let mut weight = ONE;
    let mut sum = ZERO;
    for residual in residuals(statement, columns) {
        let residue = ((residual % &modulus) + &modulus) % &modulus;
        sum = field::add(sum, field::scale(weight, u128::try_from(residue).unwrap()));
        weight = field::multiply(weight, alpha);
    }
    sum
}
fn apply(operator: &Operator, columns: &[Vec<u16>]) -> Element {
    let mut sum = field::subtract(ZERO, operator.target);
    for term in &operator.terms {
        let values = match &term.public {
            PublicColumn::Ones(degree) => vec![ONE; *degree],
            PublicColumn::Values(values) => values.clone(),
            PublicColumn::Powers(degree) => {
                let mut current = ONE;
                (0..*degree)
                    .map(|_| {
                        let value = current;
                        current = field::multiply(current, operator.alpha);
                        value
                    })
                    .collect()
            }
        };
        let stride = SYSTEMATIC / values.len();
        for &(column, weight) in &term.weights {
            for (row, value) in values.iter().enumerate() {
                sum = field::add(
                    sum,
                    field::scale(
                        field::multiply(*value, weight),
                        u128::from(columns[column][row * stride]),
                    ),
                );
            }
        }
    }
    sum
}

#[test]
fn original_keys_decode_both_packages_and_satisfy_every_integer_row() {
    use crate::{fixture, operator};
    assert_eq!(crate::LIMB_BITS, 96);
    assert_eq!(crate::SUPPORT, 256);
    assert_eq!(crate::KEY_ERROR_BITS, 7);
    assert_eq!(crate::RECOVERY_ERROR_BITS, 17);
    let modulus = crate::modulus();
    let scale = BigInt::from(supported_profile::SHARE_SCALE);
    for recipient in [0, 1, 3] {
        let (statement, witness, secret) = fixture::algebra(recipient);
        let secret: Vec<_> = secret.into_iter().map(BigInt::from).collect();
        let key_product = product(&statement.common, &secret);
        for (value, public) in key_product.iter().zip(&statement.public_key) {
            let error = centered(value + public, &modulus);
            assert!((-64..64).contains(&i128::try_from(error).unwrap()));
        }
        for package in &statement.packages {
            for ((value, constant), message) in product(&package.linear, &secret)
                .iter()
                .zip(&package.constant)
                .zip(&package.message)
            {
                let phase = centered(value + constant, &modulus);
                let noise = &phase - &scale * message;
                assert!((-32_832..=32_832).contains(&i128::try_from(noise).unwrap()));
                let negative = phase < BigInt::from(0);
                let magnitude = if negative { -phase } else { phase };
                let decoded = (magnitude + &scale / 2u8) / &scale;
                assert_eq!(
                    if negative { -decoded } else { decoded },
                    BigInt::from(*message)
                );
            }
        }
        let rows = residuals(&statement, &witness.columns);
        assert_eq!(rows.len(), 2 * (SELECTED + 1) * DEGREE + 2);
        assert!(rows.iter().all(|row| *row == BigInt::from(0)));
        for alpha in [ZERO, ONE, [17, 29, 43], [911, 71, 5]] {
            let emitted = operator::build(&statement, alpha).unwrap();
            assert_eq!(apply(&emitted, &witness.columns), ZERO);
            let expected_lookup =
                (0..rows.len()).fold(ONE, |weight, _| field::multiply(weight, alpha));
            assert_eq!(emitted.lookup_weight, expected_lookup);
        }
    }
}

#[test]
fn every_signed_family_and_sparse_key_change_reaches_the_independent_relation() {
    use crate::{fixture, layout::Layout, operator, statement::encoded_bytes};
    use word_proof::oracles::Witness;
    let (statement, witness, _) = fixture::algebra(1);
    let layout = Layout::new(encoded_bytes());
    let alpha = [17, 29, 43];
    let emitted = operator::build(&statement, alpha).unwrap();
    let stride = SYSTEMATIC / DEGREE;
    let mut boolean = layout.relation.words + 2;
    for (variable, bits) in widths().into_iter().enumerate() {
        let row = (37 * variable + 11) % DEGREE;
        let mut changed = witness.columns.clone();
        changed[variable][row * stride] ^= 1;
        Witness::from_columns(&layout.relation, witness.statement, changed.clone()).unwrap();
        let expected = weighted(&statement, &changed, alpha);
        assert_ne!(expected, ZERO, "signed variable {variable}");
        assert_eq!(
            apply(&emitted, &changed),
            expected,
            "signed variable {variable}"
        );
        if bits > 16 {
            let mut changed = witness.columns.clone();
            changed[boolean][row * stride] ^= 1;
            boolean += 1;
            Witness::from_columns(&layout.relation, witness.statement, changed.clone()).unwrap();
            let expected = weighted(&statement, &changed, alpha);
            assert_ne!(expected, ZERO, "high bit of variable {variable}");
            assert_eq!(apply(&emitted, &changed), expected);
        }
    }
    assert_eq!(boolean, witness.columns.len());
    let positive = layout.relation.words;
    let first = (0..DEGREE)
        .find(|row| witness.columns[positive][row * stride] == 1)
        .unwrap();
    let second = (0..DEGREE)
        .find(|row| witness.columns[positive + 1][row * stride] == 1)
        .unwrap();
    let mut changed = witness.columns.clone();
    changed[positive].swap(first * stride, second * stride);
    changed[positive + 1].swap(first * stride, second * stride);
    Witness::from_columns(&layout.relation, witness.statement, changed.clone()).unwrap();
    let expected = weighted(&statement, &changed, alpha);
    assert_ne!(expected, ZERO);
    assert_eq!(apply(&emitted, &changed), expected);
}

#[test]
fn every_public_polynomial_and_share_changes_the_independent_equations() {
    use crate::{fixture, operator};
    let (statement, witness, _) = fixture::algebra(3);
    let alpha = [911, 71, 5];
    for change in 0..2 + 3 * SELECTED {
        let mut changed = statement.clone();
        if change == 0 {
            changed.common[7] += 1;
        } else if change == 1 {
            changed.public_key[11] += 1;
        } else {
            let package = &mut changed.packages[(change - 2) / 3];
            match (change - 2) % 3 {
                0 => package.constant[13] += 1,
                1 => package.linear[17] += 1,
                _ => package.message[19] += 1,
            }
        }
        changed.encode().unwrap();
        let expected = weighted(&changed, &witness.columns, alpha);
        assert_ne!(expected, ZERO, "public operand {change}");
        assert_eq!(
            apply(&operator::build(&changed, alpha).unwrap(), &witness.columns),
            expected
        );
    }
}

#[test]
fn signed_error_endpoints_are_inclusive_only_at_the_lower_boundary() {
    use crate::{fixture, witness};
    let (original, _, secret) = fixture::algebra(0);
    let private: Vec<_> = secret.iter().copied().map(BigInt::from).collect();
    let modulus = crate::modulus();
    let scale = BigInt::from(supported_profile::SHARE_SCALE);
    for (key_error, recovery_error, accepted) in [
        (-64, -65_536, true),
        (63, 65_535, true),
        (-65, 0, false),
        (64, 0, false),
        (0, -65_537, false),
        (0, 65_536, false),
    ] {
        // Algebra-only statements exercise the complete accepted noise
        // intervals. They do not mint verified outer-package holders.
        let mut statement = original.clone();
        statement.public_key = product(&statement.common, &private)
            .into_iter()
            .map(|value| centered(BigInt::from(key_error) - value, &modulus))
            .collect();
        for package in &mut statement.packages {
            package.constant = product(&package.linear, &private)
                .into_iter()
                .zip(&package.message)
                .map(|(value, message)| {
                    centered(&scale * message + recovery_error - value, &modulus)
                })
                .collect();
        }
        let produced = witness::create(&statement, &secret);
        if accepted {
            let witness = produced.unwrap();
            assert!(
                residuals(&statement, &witness.columns)
                    .iter()
                    .all(|row| *row == BigInt::from(0))
            );
            let decoded = decode(&witness.columns);
            for (equation, expected) in [key_error, recovery_error, recovery_error]
                .into_iter()
                .enumerate()
            {
                assert!(
                    decoded.signed[3 * equation + 2]
                        .iter()
                        .all(|value| *value == BigInt::from(expected))
                );
            }
        } else {
            assert!(
                produced.is_err(),
                "out-of-range errors {key_error}/{recovery_error}"
            );
        }
    }
}

#[test]
fn shifted_public_share_is_impossible_for_every_bounded_registered_key_witness() {
    use crate::{fixture, operator, witness};
    let modulus = crate::modulus();
    let prime = BigInt::from(MODULUS);
    let scale = BigInt::from(998_244_353u32);
    let radix = BigInt::from(1u8) << 96usize;
    let word_radius = BigInt::from(1u8) << 15usize;
    let recovery_radius = BigInt::from(1u8) << 16usize;
    let honest_error = BigInt::from((256 + 256 + 1) * 64);
    assert_eq!(modulus, &prime * &scale);
    assert_eq!(crate::HONEST_ERROR, 32_832);
    assert_eq!(crate::LIMB_BITS, 96);
    let maximum_share = BigInt::from(crate::maximum_share());
    assert!(&maximum_share * 2u8 < prime);
    assert!(2u8 * (&scale * &maximum_share + &honest_error) < modulus);
    let residual_bound =
        (257u16 + &word_radius) * (&radix - 1u8) + &recovery_radius + &word_radius * (&radix + 1u8);
    assert!(residual_bound < prime);
    assert!(&honest_error + &recovery_radius < scale);
    assert!(&honest_error + &recovery_radius < &modulus - &scale);

    // For any accepted key witness x, the original key equation bounds its
    // error by 64 and its support by 256. A genuine outer encryption then
    // has noise at most 32832 under that same x, regardless of key uniqueness.
    // Changing M by one moves its phase by Delta modulo q. Neither direction
    // fits the real-noise plus accepted-recovery-noise interval. The residual
    // bound above excludes escaping the integer equations via proof-field wrap.
    for recipient in [0, 3] {
        let (original, witness, secret) = fixture::algebra(recipient);
        let changed = fixture::shifted_share(&original).unwrap();
        assert_eq!(changed.selection, original.selection);
        assert_eq!(changed.recipient, original.recipient);
        assert_eq!(changed.common, original.common);
        assert_eq!(changed.public_key, original.public_key);
        let mut differences = Vec::new();
        for (left, right) in changed.packages.iter().zip(&original.packages) {
            assert_eq!(left.constant, right.constant);
            assert_eq!(left.linear, right.linear);
            differences.extend(
                left.message
                    .iter()
                    .zip(&right.message)
                    .map(|(left, right)| left - right)
                    .filter(|difference| *difference != 0),
            );
        }
        assert_eq!(differences, [1]);
        changed.encode().unwrap();
        assert!(witness::create(&changed, &secret).is_err());
        let alpha = [17, 29, 43];
        let expected = weighted(&changed, &witness.columns, alpha);
        assert_ne!(expected, ZERO);
        assert_eq!(
            apply(&operator::build(&changed, alpha).unwrap(), &witness.columns),
            expected
        );
    }
}
