// The masked affine sum's job terms against their direct evaluation on the
// four cosets.
use crate::{
    field::{self, Element, MODULUS, Transform, ZERO},
    linear_oracle::{AffineValues, Public},
    oracles::{coset, extension_values},
};
use parallel_work::share;
use supported_profile::relation::*;
use zeroize::Zeroizing;

fn element(seed: usize) -> Element {
    let value = |offset: usize| {
        (seed as u128 * 0x9e37_79b9_7f4a_7c15 + offset as u128 * 0x632b_e59b_d9b4_e019) % MODULUS
    };
    [value(1), value(2), value(3)]
}
fn words(columns: usize) -> Vec<Vec<u16>> {
    (0..columns)
        .map(|column| {
            (0..SYSTEMATIC)
                .map(|row| {
                    if (row + column) % 5 == 0 {
                        0
                    } else {
                        ((row * 61 + column * 17) % 65536) as u16
                    }
                })
                .collect()
        })
        .collect()
}
fn masks(columns: usize) -> Vec<Vec<u128>> {
    (0..columns)
        .map(|column| {
            (0..MASKS)
                .map(|index| (index as u128 * 1_000_003 + column as u128 * 7_919) % MODULUS)
                .collect()
        })
        .collect()
}
// The weighted sum of the columns' words and masks as the masked
// polynomial the previous owner loop committed.
fn direct_combination(
    words: &[Vec<u16>],
    masks: &[Vec<u128>],
    columns: &[(usize, Element)],
) -> Vec<Element> {
    let mut values = vec![ZERO; SYSTEMATIC];
    let mut mask = vec![ZERO; MASKS];
    for (column, weight) in columns {
        for (value, raw) in values.iter_mut().zip(&words[*column]) {
            *value = field::add(*value, field::scale(*weight, u128::from(*raw)));
        }
        for (value, raw) in mask.iter_mut().zip(&masks[*column]) {
            *value = field::add(*value, field::scale(*weight, *raw));
        }
    }
    Transform::new(SYSTEMATIC).extension(&mut values, true);
    for (value, mask) in values.iter_mut().zip(&mask) {
        *value = field::subtract(*value, *mask);
    }
    values.extend(mask);
    values
}
// The weighted products of two polynomials' values at each coset row.
fn direct_products(weight: Element, left: &[Element], right: &[Element]) -> Vec<Element> {
    let transform = Transform::new(SYSTEMATIC);
    let mut output = vec![ZERO; DOMAIN];
    for index in 0..4 {
        let left = extension_values(left, coset(index), &transform);
        let right = extension_values(right, coset(index), &transform);
        for (row, (left, right)) in left.iter().zip(&right).enumerate() {
            output[index + 4 * row] = field::multiply(weight, field::multiply(*left, *right));
        }
    }
    output
}
fn finished(values: AffineValues) -> Vec<Element> {
    std::mem::take(&mut *values.finish())
}

#[test]
fn product_jobs_equal_the_direct_products_across_their_chunks() {
    let words = words(40);
    let masks = masks(40);
    let columns: Vec<_> = (0..40)
        .map(|column| (39 - column, element(column + 100)))
        .collect();
    let weight = element(7);
    let values: Vec<_> = (0..SYSTEMATIC).map(element).collect();
    let mut bytes = Zeroizing::new(Vec::new());
    for value in &values {
        bytes.extend(field::encode(*value));
    }
    let shared = share(bytes);
    let mut sums = AffineValues::new();
    sums.products(
        weight,
        Public::Adjoint {
            values: &shared,
            count: SYSTEMATIC,
        },
        &columns,
        &words,
        &masks,
    );
    let mut coefficient = values;
    Transform::new(SYSTEMATIC).extension(&mut coefficient, true);
    let expected = direct_products(
        weight,
        &coefficient,
        &direct_combination(&words, &masks, &columns),
    );
    assert_eq!(finished(sums), expected);
}

#[test]
fn geometric_products_equal_their_adjoint_values() {
    let words = words(3);
    let masks = masks(3);
    let columns = [(0, element(1)), (2, element(2))];
    let (alpha, weight) = (element(3), element(4));
    for (degree, automorphism, shift, constant) in [
        (8, 3, 5, false),
        (SYSTEMATIC, 5, 1, false),
        (16, 1, 0, true),
    ] {
        // The signed powers of the challenge along the automorphism's orbit.
        let powers: Vec<_> = std::iter::successors(Some([1, 0, 0]), |power| {
            Some(field::multiply(*power, alpha))
        })
        .take(degree)
        .collect();
        let values: Vec<_> = (0..degree)
            .map(|index| {
                let exponent = (index * automorphism + shift) % (2 * degree);
                match (constant, exponent < degree) {
                    (true, _) => [1, 0, 0],
                    (false, true) => powers[exponent],
                    (false, false) => field::subtract(ZERO, powers[exponent - degree]),
                }
            })
            .collect();
        let mut bytes = Zeroizing::new(Vec::new());
        for value in &values {
            bytes.extend(field::encode(*value));
        }
        let shared = share(bytes);
        let mut adjoint = AffineValues::new();
        adjoint.products(
            weight,
            Public::Adjoint {
                values: &shared,
                count: degree,
            },
            &columns,
            &words,
            &masks,
        );
        let mut geometric = AffineValues::new();
        geometric.products(
            weight,
            Public::Geometric {
                alpha,
                degree,
                automorphism,
                shift,
                constant,
            },
            &columns,
            &words,
            &masks,
        );
        assert_eq!(finished(geometric), finished(adjoint));
    }
}

// Terms of every coefficient length the oracle adds, with products
// between them, equal the weighted values of their coefficients on the four
// cosets.
#[test]
fn term_jobs_equal_their_direct_values() {
    let words = words(2);
    let masks = masks(2);
    let weights = [element(11), element(12)];
    let terms: Vec<Vec<Element>> = [WITNESS_DEGREE + 1, SYSTEMATIC - 1]
        .into_iter()
        .map(|length| (0..length).map(|index| element(index + 9)).collect())
        .collect();
    let mut sums = AffineValues::new();
    sums.term(weights[0], &terms[0]);
    sums.products(
        weights[1],
        Public::Geometric {
            alpha: element(3),
            degree: 16,
            automorphism: 1,
            shift: 0,
            constant: false,
        },
        &[(1, element(4))],
        &words,
        &masks,
    );
    sums.term(weights[1], &terms[1]);
    let mut products = AffineValues::new();
    products.products(
        weights[1],
        Public::Geometric {
            alpha: element(3),
            degree: 16,
            automorphism: 1,
            shift: 0,
            constant: false,
        },
        &[(1, element(4))],
        &words,
        &masks,
    );
    let products = finished(products);
    let transform = Transform::new(SYSTEMATIC);
    let mut expected = vec![ZERO; DOMAIN];
    for index in 0..4 {
        for (weight, coefficients) in weights.iter().zip(&terms) {
            let values = extension_values(coefficients, coset(index), &transform);
            for (row, value) in values.iter().enumerate() {
                let position = index + 4 * row;
                expected[position] =
                    field::add(expected[position], field::multiply(*weight, *value));
            }
        }
    }
    for (value, product) in expected.iter_mut().zip(&products) {
        *value = field::add(*value, *product);
    }
    assert_eq!(finished(sums), expected);
}
