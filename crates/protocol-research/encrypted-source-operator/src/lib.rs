//! Composition of the native setup witness with its encrypted source link.
//! These public-input and arithmetic objects create no voting authority.

#[cfg(test)]
use parallel_work::ProtocolHash;
#[cfg(test)]
use setup_witness::encrypted_source::centered;
pub use setup_witness::encrypted_source::{
    PublicSource, Refusal, SOURCE_POLYNOMIALS, common_polynomials,
};
use setup_witness::encrypted_source::{modulus, scale};
#[cfg(test)]
use statement_stream::ProverOperatorPlan;
use statement_stream::{
    PolynomialStream,
    affine::{Operator, PublicColumn, Term},
};
use supported_profile::{
    AUXILIARY_SECRET_SUPPORT, DEGREE, Profile, auxiliary_modulus, relation::setup_relation,
};
use word_proof::field::{self, Element, ONE, ZERO};

mod statement;
pub use statement::LinkedStatementStream;

pub use supported_profile::source_linked::{ADDED_WORDS, original_error_column, relation, remap};
fn scalar(value: i128) -> u128 {
    assert!(value.unsigned_abs() < field::MODULUS);
    if value < 0 {
        field::MODULUS - value.unsigned_abs()
    } else {
        value as u128
    }
}
fn power(mut value: Element, mut exponent: usize) -> Element {
    let mut result = ONE;
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = field::multiply(result, value);
        }
        value = field::multiply(value, value);
        exponent >>= 1;
    }
    result
}
/// The extra affine equations, beginning exactly where the original
/// operator's affine rows end. Range/support equations stay in one relation.
pub fn source_operator(
    profile: Profile,
    source: &PublicSource,
    alpha: Element,
    initial_weight: Element,
) -> Result<Operator, Refusal> {
    source.check(DEGREE)?;
    if alpha
        .iter()
        .chain(initial_weight.iter())
        .any(|value| *value >= field::MODULUS)
    {
        return Err(Refusal::Range);
    }
    let old = setup_relation(profile);
    let old_words = old.words;
    let secret = old_words + ADDED_WORDS;
    let ephemeral = old.columns() + ADDED_WORDS;
    let step = power(alpha, DEGREE);
    let mut weight = initial_weight;
    let mut target = ZERO;
    let mut terms = Vec::new();
    let power_sum = PublicColumn::Powers(DEGREE).sum(alpha);
    for component in 0..4 {
        let records = |polynomial: &[i64]| {
            let mut bytes = Vec::with_capacity(DEGREE * 6);
            for value in polynomial {
                bytes.push(u8::from(*value < 0));
                bytes.extend_from_slice(
                    &value.unsigned_abs().to_le_bytes()[..auxiliary_modulus().len()],
                );
            }
            bytes
        };
        let mut common = PolynomialStream::new(auxiliary_modulus(), DEGREE, 96, alpha)
            .map_err(|_| Refusal::Shape)?;
        for chunk in records(&source.polynomials[2 * component]).chunks(65_536) {
            common.push(chunk).map_err(|_| Refusal::Encoding)?;
        }
        terms.push(Term {
            public: PublicColumn::Values(common.adjoint().map_err(|_| Refusal::Arithmetic)?),
            weights: vec![
                (ephemeral, weight),
                (ephemeral + 1, field::subtract(ZERO, weight)),
            ],
        });
        let mut ciphertext = PolynomialStream::new(auxiliary_modulus(), DEGREE, 96, alpha)
            .map_err(|_| Refusal::Shape)?;
        for chunk in records(&source.polynomials[2 * component + 1]).chunks(65_536) {
            ciphertext.push(chunk).map_err(|_| Refusal::Encoding)?;
        }
        target = field::add(
            target,
            field::multiply(
                weight,
                ciphertext.finish_value().map_err(|_| Refusal::Arithmetic)?,
            ),
        );
        let mut weights = vec![
            (
                old_words + 2 * component,
                field::scale(weight, scalar(-i128::from(modulus()))),
            ),
            (old_words + 2 * component + 1, weight),
        ];
        let mut offset = 64i128 - i128::from(modulus()) * 32768;
        if component == 0 {
            weights.push((secret, field::scale(weight, scale() as u128)));
            weights.push((
                secret + 1,
                field::scale(weight, scalar(-i128::from(scale()))),
            ));
            offset -= i128::from(scale());
        }
        if component == 2 {
            weights.push((
                original_error_column(profile),
                field::scale(weight, scale() as u128),
            ));
        }
        target = field::add(
            target,
            field::scale(field::multiply(weight, power_sum), scalar(offset)),
        );
        terms.push(Term {
            public: PublicColumn::Powers(DEGREE),
            weights,
        });
        weight = field::multiply(weight, step);
    }
    for column in [ephemeral, ephemeral + 1] {
        terms.push(Term {
            public: PublicColumn::Ones(DEGREE),
            weights: vec![(column, weight)],
        });
        target = field::add(
            target,
            field::scale(weight, (AUXILIARY_SECRET_SUPPORT / 2) as u128),
        );
        weight = field::multiply(weight, alpha);
    }
    Ok(Operator {
        alpha,
        terms,
        target,
        lookup_weight: weight,
    })
}

#[cfg(test)]
fn combine_operator(
    profile: Profile,
    mut original: Operator,
    source: &PublicSource,
) -> Result<Operator, Refusal> {
    let old_words = profile.setup_shape().word_columns;
    for term in &mut original.terms {
        for (column, _) in &mut term.weights {
            *column = remap(*column, old_words);
        }
    }
    let mut extra = source_operator(profile, source, original.alpha, original.lookup_weight)?;
    original.terms.append(&mut extra.terms);
    original.target = field::add(original.target, extra.target);
    original.lookup_weight = extra.lookup_weight;
    Ok(original)
}

/// The exact original native plan, materialized only for the bounded native
/// integration experiment. The streamed runtime must not retain this bank.
#[cfg(test)]
fn original_operator(
    profile: Profile,
    alpha: Element,
    polynomials: &[Vec<u8>],
) -> Result<Operator, Refusal> {
    let ProverOperatorPlan {
        fixed_terms,
        common_columns,
        value_weights,
        target_offset,
        lookup_weight,
    } = statement_stream::prover_operator_plan(profile, alpha).map_err(|_| Refusal::Shape)?;
    if polynomials.len() != common_columns.len() {
        return Err(Refusal::Shape);
    }
    let mut terms = Vec::new();
    let mut target = target_offset;
    let mut grouped =
        std::collections::BTreeMap::<(usize, usize, usize, bool), Vec<(usize, Element)>>::new();
    for term in fixed_terms {
        grouped
            .entry((term.degree, term.automorphism, term.shift, term.constant))
            .or_default()
            .extend(term.columns);
    }
    for ((degree, automorphism, shift, constant), weights) in grouped {
        let public = if constant {
            PublicColumn::Ones(degree)
        } else if automorphism == 1 && shift == 0 {
            PublicColumn::Powers(degree)
        } else {
            PublicColumn::Values(
                (0..degree)
                    .map(|position| {
                        let exponent = (position * automorphism + shift) % (2 * degree);
                        let value = power(alpha, exponent % degree);
                        if exponent < degree {
                            value
                        } else {
                            field::subtract(ZERO, value)
                        }
                    })
                    .collect(),
            )
        };
        terms.push(Term { public, weights });
    }
    for (index, bytes) in polynomials.iter().enumerate() {
        let mut parser = statement_stream::setup_polynomial_stream(profile, index, alpha)
            .map_err(|_| Refusal::Shape)?;
        for chunk in bytes.chunks(65_536) {
            parser.push(chunk).map_err(|_| Refusal::Encoding)?;
        }
        if common_columns[index].is_empty() {
            target = field::subtract(
                target,
                field::multiply(
                    value_weights[index],
                    parser.finish_value().map_err(|_| Refusal::Arithmetic)?,
                ),
            );
        } else {
            terms.push(Term {
                public: PublicColumn::Values(parser.adjoint().map_err(|_| Refusal::Arithmetic)?),
                weights: common_columns[index].clone(),
            });
        }
    }
    Ok(Operator {
        alpha,
        terms,
        target,
        lookup_weight,
    })
}

#[cfg(test)]
fn statement_digest(
    profile: Profile,
    polynomials: &[Vec<u8>],
    source: &PublicSource,
) -> Result<[u8; 64], Refusal> {
    if polynomials.len() != profile.setup_polynomials() {
        return Err(Refusal::Shape);
    }
    let mut hash = ProtocolHash::new();
    hash.update(profile.setup_statement_header());
    for polynomial in polynomials {
        hash.update(polynomial);
    }
    for polynomial in source.records()? {
        hash.update(polynomial);
    }
    Ok(hash.finalize())
}

#[cfg(test)]
#[path = "operator-tests.rs"]
mod tests;

#[cfg(test)]
#[path = "source-ciphertext-tests.rs"]
mod source_ciphertext_tests;
