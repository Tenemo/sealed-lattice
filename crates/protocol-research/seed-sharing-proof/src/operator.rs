use crate::{
    DEGREE, Error, RECIPIENTS, SCALE, SEED_BITS, SUPPORT, digit,
    layout::{Layout, variable},
    modulus, profile, rotation,
    statement::{Statement, encoded_bytes},
};
use num_bigint::BigInt;
use word_proof::{
    affine::{Operator, PublicColumn, Term},
    field::{self, Element, ONE, ZERO},
};

fn signed(value: i128) -> Element {
    let positive = [value.unsigned_abs(), 0, 0];
    if value < 0 {
        field::subtract(ZERO, positive)
    } else {
        positive
    }
}
/// Collapses the exact two-limb integer equations and support counts at one
/// extension-field challenge. Public coefficients occupy physical ring rows
/// under the common proof engine's strided embedding.
pub fn build(statement: &Statement, alpha: Element) -> Result<Operator, Error> {
    if alpha.iter().any(|value| *value >= field::MODULUS) {
        return Err("Noncanonical affine challenge");
    }
    statement.encode()?;
    let layout = Layout::new(encoded_bytes());
    let mut columns = vec![vec![ZERO; DEGREE]; layout.relation.columns()];
    let mut target = ZERO;
    let mut weight = ONE;
    let radix = 1i128 << profile().share_limb_bits();
    let modulus = modulus();
    for recipient in 0..RECIPIENTS {
        for component in 0..2 {
            let public = if component == 0 {
                &statement.recipients[recipient].public_key
            } else {
                &statement.common
            };
            for limb in 0..2 {
                for row in 0..DEGREE {
                    let mut target_row = signed(digit(
                        &statement.recipients[recipient].ciphertext[component][row],
                        limb,
                    ));
                    let positive = layout.relation.words + 2 * recipient;
                    let (before, after) = columns.split_at_mut(positive + 1);
                    for (source, (positive_value, negative_value)) in
                        before[positive].iter_mut().zip(&mut after[0]).enumerate()
                    {
                        let public_index = (row + DEGREE - source) % DEGREE;
                        let coefficient =
                            digit(&public[public_index], limb) * if source > row { -1 } else { 1 };
                        let value = field::multiply(weight, signed(coefficient));
                        *positive_value = field::add(*positive_value, value);
                        *negative_value = field::subtract(*negative_value, value);
                    }
                    let mut add_signed = |variable: usize, source: usize, coefficient: i128| {
                        let factor = field::multiply(weight, signed(coefficient));
                        for &(column, place) in &layout.signed[variable] {
                            columns[column][source] =
                                field::add(columns[column][source], field::scale(factor, place));
                        }
                        target_row = field::add(
                            target_row,
                            field::scale(
                                signed(coefficient),
                                1u128 << (layout.widths[variable] - 1),
                            ),
                        );
                    };
                    add_signed(
                        variable(recipient, component, 0),
                        row,
                        -digit(&modulus, limb),
                    );
                    add_signed(
                        variable(recipient, component, 1),
                        row,
                        if limb == 0 { -radix } else { 1 },
                    );
                    if limb == 0 {
                        add_signed(variable(recipient, component, 2), row, 1);
                    }
                    if component == 0 {
                        let (source, sign) = rotation(recipient, row);
                        add_signed(limb, source, sign * SCALE);
                        target_row = field::subtract(
                            target_row,
                            signed(digit(&BigInt::from(sign * SCALE * (radix / 2)), limb)),
                        );
                        if limb == 0 && row < SEED_BITS {
                            columns[layout.seed][row] = field::add(
                                columns[layout.seed][row],
                                field::scale(weight, SCALE as u128),
                            );
                        }
                    }
                    target = field::add(target, field::multiply(weight, target_row));
                    weight = field::multiply(weight, alpha);
                }
            }
        }
    }
    for recipient in 0..RECIPIENTS {
        for sign in 0..2 {
            let column = layout.relation.words + 2 * recipient + sign;
            for value in &mut columns[column] {
                *value = field::add(*value, weight);
            }
            target = field::add(target, field::scale(weight, (SUPPORT / 2) as u128));
            weight = field::multiply(weight, alpha);
        }
    }
    Ok(Operator {
        alpha,
        terms: columns
            .into_iter()
            .enumerate()
            .map(|(column, values)| Term {
                public: PublicColumn::Values(values),
                weights: vec![(column, ONE)],
            })
            .collect(),
        target,
        lookup_weight: weight,
    })
}
