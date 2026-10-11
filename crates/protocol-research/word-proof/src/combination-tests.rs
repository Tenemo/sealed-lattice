use super::*;
use crate::field::ONE;
#[test]
fn secret_job_inputs_have_their_exact_length() {
    // Groups with and without lookups and zero products.
    let relation = Relation {
        tag: b"combination-test",
        proof_magic: b"TEST",
        words: 3,
        booleans: 4,
        narrow: vec![(1, 512), (2, 8)],
        zero_product_pairs: vec![(3, 4), (5, 6)],
        supports: vec![(1, 512)],
        message_bytes: 1,
        statement_bytes: 1,
        parameters: Vec::new(),
    };
    let witness = Witness {
        columns: vec![vec![0; SYSTEMATIC]; relation.columns()],
        counts: vec![0; SYSTEMATIC],
        relation: relation.clone(),
        statement: [0; 64],
    };
    let first_masks = vec![vec![0; MASKS]; relation.columns() + 1];
    let second_masks = vec![vec![ZERO; MASKS]; relation.lookups() + 1];
    let groups = components(&relation);
    assert!(groups.iter().any(|group| group.len() > 1));
    let mut with_lookups = 0;
    for group in groups {
        let (bytes, lookups) = encode_columns(&witness, &first_masks, &second_masks, &group);
        assert_eq!(bytes.capacity(), bytes.len());
        with_lookups += usize::from(lookups);
    }
    assert!(with_lookups > 0);
    for coset in 0..COSETS.len() {
        let bytes = encode_counts(coset, &witness, &first_masks, &second_masks);
        assert_eq!(bytes.capacity(), bytes.len());
    }
}
#[test]
fn collected_reciprocal_terms_equal_the_direct_constraint_for_every_lookup_scale() {
    let mut state = 0x935ac307125aec91u128;
    let mut sample = || {
        state ^= state << 23;
        state ^= state >> 31;
        state ^= state << 17;
        state % MODULUS
    };
    // Whole words and narrow words scaled by powers of two or by a
    // score range's quotient.
    for narrow in [vec![(2, 512)], vec![(6, 8), (9, 512)], vec![(22, 7281)]] {
        let relation = Relation {
            tag: b"combination-test",
            proof_magic: b"TEST",
            words: 27,
            booleans: 5,
            narrow,
            zero_product_pairs: vec![(27, 28), (29, 30), (20, 31)],
            supports: vec![(1, 512), (16, 128)],
            message_bytes: 1 << 18,
            statement_bytes: 1,
            parameters: Vec::new(),
        };
        let (words_count, lookups) = (relation.words(), relation.lookups());
        let weights = Weights {
            coefficients: (0..2 * relation.oracles())
                .map(|_| [sample(), sample(), sample()])
                .collect(),
            // Powers -1, -37, ... and 11, 0, 0, ...
            powers: vec![(MODULUS - 1, 37), (11, 0)],
            classes: (0..relation.oracles()).map(|index| index % 2).collect(),
        };
        let words = [0, 1, MODULUS - 1, sample()];
        let reciprocals = [
            [0, 0, 0],
            [1, 0, 0],
            [MODULUS - 1; 3],
            [sample(), sample(), sample()],
        ];
        for lookup_index in [0, 1, words_count - 1, words_count, lookups - 1] {
            for beta in [ZERO, ONE, [0, 0, 1], [sample(), sample(), sample()]] {
                for inverse_vanishing in [0, 1, MODULUS - 1, sample()] {
                    let mut actual = vec![ONE; words.len()];
                    weights.add_lookup(
                        &mut actual,
                        lookup_oracles(&relation, lookup_index),
                        beta,
                        inverse_vanishing,
                        &words,
                        &reciprocals,
                    );
                    for position in 0..words.len() {
                        let inverse_oracle = relation.columns() + 1 + lookup_index;
                        let residual_oracle = relation.columns()
                            + lookups
                            + 4
                            + relation.booleans()
                            + relation.zero_products()
                            + lookup_index;
                        let residue = field::scale(
                            field::subtract(
                                field::multiply(
                                    reciprocals[position],
                                    field::subtract(
                                        beta,
                                        [
                                            base::multiply(
                                                words[position],
                                                relation.lookup(lookup_index).1,
                                            ),
                                            0,
                                            0,
                                        ],
                                    ),
                                ),
                                ONE,
                            ),
                            inverse_vanishing,
                        );
                        let expected = field::add(
                            ONE,
                            field::add(
                                field::multiply(
                                    weights.values(inverse_oracle).nth(position).unwrap(),
                                    reciprocals[position],
                                ),
                                field::multiply(
                                    weights.values(residual_oracle).nth(position).unwrap(),
                                    residue,
                                ),
                            ),
                        );
                        assert_eq!(actual[position], expected);
                    }
                }
            }
        }
    }
}
