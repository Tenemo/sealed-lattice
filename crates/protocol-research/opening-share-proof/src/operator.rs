use crate::{
    DEGREE, Error, SUPPORT, digit,
    layout::Layout,
    modulus,
    statement::{Statement, encoded_bytes},
};
use word_proof::{
    affine::{Operator, PublicColumn, Term},
    field::{self, Element, ONE, ZERO},
};

fn signed(value: i128) -> Element {
    let magnitude = [value.unsigned_abs(), 0, 0];
    if value < 0 {
        field::subtract(ZERO, magnitude)
    } else {
        magnitude
    }
}
/// Exact key equation followed by the selected records' decoding equations,
/// each in low/high limb order, then the two support equations.
pub fn build(statement: &Statement, alpha: Element) -> Result<Operator, Error> {
    if alpha.iter().any(|value| *value >= field::MODULUS) {
        return Err("Noncanonical affine challenge");
    }
    statement.encode()?;
    let layout = Layout::new(encoded_bytes());
    let mut columns = vec![vec![ZERO; DEGREE]; layout.relation.columns()];
    let positive = layout.relation.words;
    let mut target = ZERO;
    let mut weight = ONE;
    let radix = 1i128 << crate::LIMB_BITS;
    let modulus = modulus();
    for (equation, (constant, linear)) in statement.equations().into_iter().enumerate() {
        for limb in 0..2 {
            for (row, constant) in constant.iter().enumerate() {
                let mut target_row = signed(-digit(constant, limb));
                let (before, after) = columns.split_at_mut(positive + 1);
                for (source, (positive_value, negative_value)) in
                    before[positive].iter_mut().zip(&mut after[0]).enumerate()
                {
                    let index = (row + DEGREE - source) % DEGREE;
                    let coefficient =
                        digit(&linear[index], limb) * if source > row { -1 } else { 1 };
                    let value = field::multiply(weight, signed(coefficient));
                    *positive_value = field::add(*positive_value, value);
                    *negative_value = field::subtract(*negative_value, value);
                }
                let mut add_signed = |offset: usize, coefficient: i128| {
                    let variable = 3 * equation + offset;
                    let factor = field::multiply(weight, signed(coefficient));
                    for &(column, place) in &layout.signed[variable] {
                        columns[column][row] =
                            field::add(columns[column][row], field::scale(factor, place));
                    }
                    target_row = field::add(
                        target_row,
                        field::scale(signed(coefficient), 1u128 << (layout.widths[variable] - 1)),
                    );
                };
                add_signed(0, -digit(&modulus, limb));
                add_signed(1, if limb == 0 { -radix } else { 1 });
                if limb == 0 {
                    add_signed(2, -1);
                }
                target = field::add(target, field::multiply(weight, target_row));
                weight = field::multiply(weight, alpha);
            }
        }
    }
    for column in &mut columns[positive..positive + 2] {
        for value in column {
            *value = field::add(*value, weight);
        }
        target = field::add(target, field::scale(weight, (SUPPORT / 2) as u128));
        weight = field::multiply(weight, alpha);
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
