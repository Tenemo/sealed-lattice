//! The registration relation's operator as the statement built it before
//! its public polynomials were weighted: each column's coefficient placed at
//! every row. Tests compare the weighted operator with it.
use super::*;

/// Every relation column's coefficient at every row, the target and the
/// lookup weight.
pub(crate) struct Dense {
    pub(crate) coefficients: Vec<Vec<Element>>,
    pub(crate) target: Element,
    pub(crate) lookup_weight: Element,
}
pub(crate) fn operator_from_parts(
    alpha: Element,
    adjoint: Vec<Element>,
    public_value: Element,
) -> Dense {
    assert_eq!(adjoint.len(), SYSTEMATIC);
    let mut powers = Vec::with_capacity(SYSTEMATIC);
    let mut current = ONE;
    let mut sum = ZERO;
    for _ in 0..SYSTEMATIC {
        powers.push(current);
        sum = field::add(sum, current);
        current = field::multiply(current, alpha);
    }
    let z = current;
    let encoded = header();
    let mut lower = [0; 16];
    lower[..12].copy_from_slice(&encoded[8..20]);
    let mut upper = [0; 16];
    upper[..8].copy_from_slice(&encoded[20..28]);
    let modulus = field::add(
        [u128::from_le_bytes(lower), 0, 0],
        field::scale(z, u128::from_le_bytes(upper)),
    );
    let carry = field::subtract(z, [1u128 << 96, 0, 0]);
    let support_positive = field::multiply(z, z);
    let support_negative = field::multiply(support_positive, alpha);
    let offset = field::add(
        field::subtract(field::scale(modulus, 1 << 15), field::scale(carry, 1 << 15)),
        [64, 0, 0],
    );
    let target = field::add(
        field::subtract(
            field::subtract(ZERO, public_value),
            field::multiply(offset, sum),
        ),
        field::scale(field::add(support_positive, support_negative), 128),
    );
    let coefficients = vec![
        powers
            .iter()
            .map(|power| field::subtract(ZERO, field::multiply(*power, modulus)))
            .collect(),
        powers
            .iter()
            .map(|power| field::multiply(*power, carry))
            .collect(),
        powers
            .iter()
            .map(|power| field::subtract(ZERO, *power))
            .collect(),
        adjoint
            .iter()
            .map(|value| field::add(*value, support_positive))
            .collect(),
        adjoint
            .iter()
            .map(|value| field::subtract(support_negative, *value))
            .collect(),
    ];
    Dense {
        coefficients,
        target,
        lookup_weight: field::multiply(support_negative, alpha),
    }
}
