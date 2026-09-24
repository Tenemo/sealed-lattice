use crate::{combination, field, linear, oracles, parameters};
#[path = "reference/combination-before-products.rs"]
mod previous;

#[test]
fn registration_combination_is_unchanged_for_the_same_committed_oracles() {
    use field::{Element, ZERO};
    use oracles::{FirstOracle, SecondOracle, Witness};
    use parameters::*;
    let mut columns = vec![vec![0; SYSTEMATIC]; COLUMNS];
    for column in 0..WORDS {
        for (position, value) in columns[column].iter_mut().enumerate() {
            *value = ((position * 61 + column * 17) % if column == 2 { 128 } else { 65536 }) as u16;
        }
    }
    for position in 0..128 {
        columns[WORDS][position * 2] = 1;
        columns[WORDS + 1][position * 2 + 1] = 1;
    }
    let witness = Witness::from_columns([37; 64], columns).unwrap();
    let role = b"zero-product-regression";
    // Random masks are generated once. Both implementations receive these exact objects.
    let first = FirstOracle::initialize(role, false);
    let beta: Element = [17, 29, 43];
    let inverses = field::batch_inverse(
        &(0..SYSTEMATIC)
            .map(|value| field::subtract(beta, [value as u128, 0, 0]))
            .collect::<Vec<_>>(),
    );
    let second = SecondOracle::initialize(role);
    let linear = linear::LinearOracle {
        target: ZERO,
        claimed_sum: ZERO,
        quotient: (0..SUM_DEGREE - SYSTEMATIC + 1)
            .map(|index| [index as u128, 19, 0])
            .collect(),
        remainder: (0..SYSTEMATIC - 1)
            .map(|index| [41, index as u128, 23])
            .collect(),
        tree: crate::tree::Tree::new(role, 2, DOMAIN, 48),
        lookup_weight: ZERO,
    };
    let message: Vec<u8> = (0..MESSAGE_BYTES)
        .map(|index| (index * 71 + 19) as u8)
        .collect();
    let old = previous::polynomial(
        &witness, &first, &second, &linear, beta, &inverses, &message,
    );
    let new = combination::polynomial(
        &witness, &first, &second, &linear, beta, &inverses, &message,
    );
    assert_eq!(new, old);
}
