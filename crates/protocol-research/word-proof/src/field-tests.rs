use super::*;
#[test]
fn selected_outputs_match_direct_evaluation_for_every_small_subset() {
    for length in [2, 4, 8] {
        let transform = Transform::new(length);
        let source: Vec<_> = (0..length)
            .map(|index| {
                [
                    index as u128,
                    MODULUS - 1 - index as u128,
                    (index * index + 17) as u128,
                ]
            })
            .collect();
        for mask in 0..1usize << length {
            let indices: Vec<_> = (0..length)
                .filter(|index| mask & (1 << index) != 0)
                .collect();
            let expected: Vec<_> = indices
                .iter()
                .map(|point| {
                    source.iter().enumerate().fold(ZERO, |sum, (index, value)| {
                        add(
                            sum,
                            scale(*value, base::power(root(length), (index * point) as u128)),
                        )
                    })
                })
                .collect();
            assert_eq!(
                transform.selected_extension(&mut source.clone(), &indices),
                expected
            );
            let mut base_values: Vec<_> = source.iter().map(|value| value[0]).collect();
            assert_eq!(
                transform.selected_base(&mut base_values, &indices),
                expected.iter().map(|value| value[0]).collect::<Vec<_>>()
            );
        }
        let indices = [length - 1, 0, length - 1];
        let mut complete = source.clone();
        transform.extension(&mut complete, false);
        assert_eq!(
            transform.selected_extension(&mut source.clone(), &indices),
            indices
                .iter()
                .map(|index| complete[*index])
                .collect::<Vec<_>>()
        );
    }
}
#[test]
fn invalid_selection_leaves_input_untouched() {
    let transform = Transform::new(8);
    let mut data = vec![ONE; 8];
    let original = data.clone();
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || transform.selected_extension(&mut data, &[8])
        ))
        .is_err()
    );
    assert_eq!(data, original);
}
#[test]
fn inverse_and_batch_products_are_exact() {
    let values = [
        [1, 0, 0],
        [0, 1, 0],
        [0, 0, 1],
        [17, 37, 91],
        [MODULUS - 1, MODULUS - 2, MODULUS - 3],
    ];
    for (value, inverted) in values.iter().zip(batch_inverse(&values)) {
        assert_eq!(multiply(*value, inverted), ONE);
        assert_eq!(inverted, inverse(*value));
    }
}
#[test]
fn transforms_match_direct_fourier_values() {
    for n in [2, 4, 8, 16] {
        let data: Vec<Element> = (0..n)
            .map(|i| [i as u128, MODULUS - 1 - i as u128, (i * i + 7) as u128])
            .collect();
        let expected: Vec<Element> = (0..n)
            .map(|j| {
                data.iter().enumerate().fold(ZERO, |sum, (i, value)| {
                    add(sum, scale(*value, base::power(root(n), (i * j) as u128)))
                })
            })
            .collect();
        let transform = Transform::new(n);
        let mut actual = data.clone();
        transform.extension(&mut actual, false);
        assert_eq!(actual, expected);
        transform.extension(&mut actual, true);
        assert_eq!(actual, data);
        let mut first: Vec<u128> = data.iter().map(|x| x[0]).collect();
        transform.base(&mut first, false);
        assert_eq!(first, expected.iter().map(|x| x[0]).collect::<Vec<_>>());
    }
}
// One transform's tables give every length the values of that length's
// own transform, both ways and in both fields, whether the length is
// shorter than the tables' or longer; a length that is not a power of
// two, or below two, is refused.
#[test]
fn tables_transform_every_length() {
    let longer = Transform::new(64);
    for n in [2, 4, 16, 32, 64, 128, 512] {
        let data: Vec<Element> = (0..n)
            .map(|i| {
                [
                    (3 * i + 1) as u128,
                    MODULUS - 2 - i as u128,
                    (i * i * i) as u128,
                ]
            })
            .collect();
        let own = Transform::new(n);
        for inverse in [false, true] {
            let (mut expected, mut actual) = (data.clone(), data.clone());
            own.extension(&mut expected, inverse);
            longer.extension(&mut actual, inverse);
            assert_eq!(actual, expected);
            let mut expected: Vec<u128> = data.iter().map(|x| x[2]).collect();
            let mut actual = expected.clone();
            own.base(&mut expected, inverse);
            longer.base(&mut actual, inverse);
            assert_eq!(actual, expected);
        }
    }
    for length in [1, 12, 96] {
        let mut data = vec![ONE; length];
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                || longer.extension(&mut data, false)
            ))
            .is_err()
        );
    }
}
