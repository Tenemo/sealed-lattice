use super::*;
#[test]
fn secret_column_inputs_have_their_exact_length() {
    let words = vec![u16::MAX; SYSTEMATIC];
    let counts = vec![u128::MAX; SYSTEMATIC];
    let base_mask = vec![u128::MAX; MASKS];
    let extension_mask = vec![[u128::MAX; 3]; MASKS];
    for column in [
        base_column(BaseValues::Words(&words), &base_mask),
        base_column(BaseValues::Counts(&counts), &base_mask),
        second_column(
            SecondValues::Lookup {
                words: &words,
                factor: 512,
            },
            &extension_mask,
        ),
        second_column(SecondValues::Counts(&counts), &extension_mask),
    ] {
        assert_eq!(column.capacity(), column.len());
    }
}
