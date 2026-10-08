use super::*;
use crate::field::MODULUS;

fn element(seed: usize) -> Element {
    let value = |offset: usize| {
        (seed as u128 * 0x9e37_79b9_7f4a_7c15 + offset as u128 * 0x632b_e59b_d9b4_e019) % MODULUS
    };
    [value(1), value(2), value(3)]
}

// Every kind of public column, at full and reduced degrees, gives each
// relation column the values at the queries that evaluating the column's
// every row gives; a column no term names is zero.
#[test]
fn terms_give_every_column_the_values_of_its_rows() {
    let reduced = SYSTEMATIC / 16;
    let terms = vec![
        (PublicColumn::Powers(SYSTEMATIC), vec![0, 1, 3]),
        (PublicColumn::Powers(reduced), vec![1, 4]),
        (PublicColumn::Ones(SYSTEMATIC), vec![2, 3]),
        (PublicColumn::Ones(reduced), vec![0, 4]),
        (
            PublicColumn::Values((0..SYSTEMATIC).map(|row| element(row + 7)).collect()),
            vec![3, 5],
        ),
        (
            PublicColumn::Values((0..reduced).map(|row| element(row + 3)).collect()),
            vec![1, 5],
        ),
    ];
    let operator = Operator {
        alpha: element(1),
        terms: terms
            .into_iter()
            .enumerate()
            .map(|(term, (public, columns))| Term {
                public,
                weights: columns
                    .into_iter()
                    .map(|column| (column, element(100 * term + column)))
                    .collect(),
            })
            .collect(),
        target: ZERO,
        lookup_weight: ZERO,
    };
    let queries = [
        0,
        1,
        2,
        3,
        17,
        1000,
        SYSTEMATIC as u32,
        EVALUATION_DOMAIN_SIZE as u32 - 1,
    ];
    let columns = operator.columns(7);
    assert!(columns[6].iter().all(|value| *value == ZERO));
    let expected = setup_stream_kernel::evaluate_public_columns(columns, &queries).unwrap();
    assert_eq!(operator.at_queries(7, &queries).unwrap(), expected);
}

// A column's sum is the sum of the values it places.
#[test]
fn public_column_sums_add_their_values() {
    let alpha = element(5);
    let mut current = ONE;
    let mut expected = ZERO;
    for _ in 0..SYSTEMATIC / 16 {
        expected = field::add(expected, current);
        current = field::multiply(current, alpha);
    }
    assert_eq!(PublicColumn::Powers(SYSTEMATIC / 16).sum(alpha), expected);
    assert_eq!(PublicColumn::Ones(4096).sum(alpha), [4096, 0, 0]);
    assert_eq!(
        PublicColumn::Values(vec![element(1), element(2)]).sum(alpha),
        field::add(element(1), element(2))
    );
}
