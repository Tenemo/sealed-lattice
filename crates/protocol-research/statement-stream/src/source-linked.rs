//! Affine equations linking contribution operands to registered encryptions.
use crate::{
    Element, ONE, PolynomialStream, ProverFixedTerm, ProverOperatorPlan, Refusal, ZERO, minus,
    plus, power, times,
};
use supported_profile::{
    AUXILIARY_SECRET_SUPPORT, DEGREE, Profile, auxiliary_modulus,
    relation::setup_relation,
    source_linked::{ADDED_WORDS, SOURCE_POLYNOMIALS, original_error_column, remap},
};
fn source_modulus() -> i64 {
    let mut bytes = [0; 8];
    let modulus = auxiliary_modulus();
    bytes[..modulus.len()].copy_from_slice(modulus);
    i64::from_le_bytes(bytes)
}
fn source_scale() -> i64 {
    source_modulus() / 257
}
fn scalar(value: i128) -> u128 {
    if value < 0 {
        crate::MODULUS - value.unsigned_abs()
    } else {
        value as u128
    }
}
fn scale_element(value: Element, factor: u128) -> Element {
    value.map(|entry| crate::proof_field::multiply(entry, factor))
}
pub fn polynomial(
    profile: Profile,
    index: usize,
    alpha: Element,
) -> Result<PolynomialStream, Refusal> {
    if index < profile.setup_polynomials() {
        crate::setup_polynomial_stream(profile, index, alpha)
    } else if index < profile.setup_polynomials() + SOURCE_POLYNOMIALS {
        PolynomialStream::new(auxiliary_modulus(), DEGREE, 96, alpha)
    } else {
        Err(Refusal::Parameters)
    }
}

pub fn plan(profile: Profile, alpha: Element) -> Result<ProverOperatorPlan, Refusal> {
    let mut plan = crate::prover_operator_plan(profile, alpha)?;
    let old = setup_relation(profile);
    for term in &mut plan.fixed_terms {
        for (column, _) in &mut term.columns {
            *column = remap(*column, old.words);
        }
    }
    for columns in &mut plan.common_columns {
        for (column, _) in columns {
            *column = remap(*column, old.words);
        }
    }
    let secret = old.words + ADDED_WORDS;
    let ephemeral = old.columns() + ADDED_WORDS;
    let mut weight = plan.lookup_weight;
    let step = power(alpha, DEGREE);
    let sum = (0..DEGREE)
        .fold((ZERO, ONE), |(sum, value), _| {
            (plus(sum, value), times(value, alpha))
        })
        .0;
    for component in 0..4 {
        plan.common_columns.push(vec![
            (ephemeral, weight),
            (ephemeral + 1, minus(ZERO, weight)),
        ]);
        plan.value_weights.push(ZERO);
        plan.common_columns.push(Vec::new());
        // AffineSum subtracts the weighted public value from its target.
        plan.value_weights.push(minus(ZERO, weight));
        let mut columns = vec![
            (
                old.words + 2 * component,
                scale_element(weight, scalar(-i128::from(source_modulus()))),
            ),
            (old.words + 2 * component + 1, weight),
        ];
        let mut offset = 64i128 - i128::from(source_modulus()) * 32768;
        if component == 0 {
            columns.extend([
                (secret, scale_element(weight, source_scale() as u128)),
                (
                    secret + 1,
                    scale_element(weight, scalar(-i128::from(source_scale()))),
                ),
            ]);
            offset -= i128::from(source_scale());
        }
        if component == 2 {
            columns.push((
                original_error_column(profile),
                scale_element(weight, source_scale() as u128),
            ));
        }
        plan.fixed_terms.push(ProverFixedTerm {
            degree: DEGREE,
            automorphism: 1,
            shift: 0,
            constant: false,
            columns,
        });
        plan.target_offset = plus(
            plan.target_offset,
            scale_element(times(weight, sum), scalar(offset)),
        );
        weight = times(weight, step);
    }
    for column in [ephemeral, ephemeral + 1] {
        plan.fixed_terms.push(ProverFixedTerm {
            degree: DEGREE,
            automorphism: 1,
            shift: 0,
            constant: true,
            columns: vec![(column, weight)],
        });
        plan.target_offset = plus(
            plan.target_offset,
            scale_element(weight, (AUXILIARY_SECRET_SUPPORT / 2) as u128),
        );
        weight = times(weight, alpha);
    }
    plan.lookup_weight = weight;
    Ok(plan)
}
