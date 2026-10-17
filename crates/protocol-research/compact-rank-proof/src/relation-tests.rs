use super::*;
use crate::statement::Packet;
use supported_profile::Profile;

fn values<'a>(relation: &Relation, witness: &'a [Vec<u128>], name: &str) -> &'a [u128] {
    &witness[relation
        .variables
        .iter()
        .position(|variable| variable.name == name)
        .unwrap()]
}
fn integer(relation: &Relation, witness: &[Vec<u128>], name: &str, position: usize) -> i128 {
    let descriptor = relation
        .integers
        .iter()
        .find(|integer| integer.name == name)
        .unwrap();
    descriptor
        .parts
        .iter()
        .map(|&(variable, shift)| (witness[variable][position] << shift) as i128)
        .sum::<i128>()
        - if descriptor.signed {
            1 << (descriptor.bits - 1)
        } else {
            0
        }
}
fn convolution(polynomial: &[i64], secret: &[i128]) -> Vec<i128> {
    let mut result = vec![0; DEGREE];
    for (offset, &sign) in secret.iter().enumerate() {
        if sign == 0 {
            continue;
        }
        for (index, &coefficient) in polynomial.iter().enumerate() {
            let position = index + offset;
            result[position % DEGREE] +=
                if position < DEGREE { sign } else { -sign } * coefficient as i128;
        }
    }
    result
}

#[test]
fn compact_rank_transpose_matches_direct_integer_equations() {
    for (participants, options, top, exceptional) in [
        (3usize, 3usize, 1usize, 0usize),
        (3, 3, 1, 1),
        (20, 20, 18, 3),
    ] {
        let queries = options * top;
        let masks = (options * (options - 1)).div_ceil(256) * 128;
        let packets = (masks + 5 * queries * CANDIDATES).div_ceil(DEGREE);
        let polynomial = |seed| {
            (0..DEGREE)
                .map(|index| (index as i64 * 3571 + seed) % modulus() - modulus() / 2)
                .collect::<Vec<_>>()
        };
        let statement = Statement {
            profile: Profile::new(participants, options).unwrap(),
            top,
            queries,
            mask_coordinates: masks,
            common: polynomial(79),
            public_key: polynomial(83),
            aggregate: (0..packets)
                .map(|packet| Packet {
                    constant: polynomial(97 + packet as i64),
                    linear: polynomial(101 + packet as i64),
                })
                .collect(),
            masked: (0..masks).map(|index| index * 13 % PLAINTEXT).collect(),
            selections: (0..queries)
                .map(|query| {
                    if exceptional != 0 && query % exceptional == 0 {
                        CANDIDATES
                    } else {
                        query % CANDIDATES
                    }
                })
                .collect(),
            multiplication: (0..queries * CANDIDATES)
                .map(|index| index * 19 % PLAINTEXT)
                .collect(),
            output: (0..queries).map(|index| index * 23 % PLAINTEXT).collect(),
        };
        let relation = Relation::new(&statement);
        let mut witness: Vec<Vec<u128>> = relation
            .variables
            .iter()
            .enumerate()
            .map(|(variable, descriptor)| {
                (0..descriptor.values)
                    .map(|index| ((index * 29 + variable * 31) % descriptor.range) as u128)
                    .collect()
            })
            .collect();
        for (name, parity) in [
            ("recipient-secret/positive", 0),
            ("recipient-secret/negative", 1),
        ] {
            let variable = relation
                .variables
                .iter()
                .position(|variable| variable.name == name)
                .unwrap();
            witness[variable].fill(0);
            for index in 0..SUPPORT / 2 {
                witness[variable][4 * index + parity] = 1;
            }
        }
        // A wrong support count is still a bounded Boolean input to the affine
        // map. The comparison includes its nonzero support residual.
        if exceptional == 3 {
            let variable = relation
                .variables
                .iter()
                .position(|variable| variable.name == "recipient-secret/positive")
                .unwrap();
            witness[variable][DEGREE - 1] = 1;
        }
        let positive = values(&relation, &witness, "recipient-secret/positive");
        let negative = values(&relation, &witness, "recipient-secret/negative");
        let secret: Vec<_> = positive
            .iter()
            .zip(negative)
            .map(|(&positive, &negative)| positive as i128 - negative as i128)
            .collect();
        let mut residuals = vec![
            positive.iter().sum::<u128>() as i128 - (SUPPORT / 2) as i128,
            negative.iter().sum::<u128>() as i128 - (SUPPORT / 2) as i128,
        ];
        residuals.extend(
            convolution(&statement.common, &secret)
                .iter()
                .enumerate()
                .map(|(index, value)| {
                    value + statement.public_key[index] as i128
                        - integer(&relation, &witness, "recipient-public-key/error", index)
                        - modulus() as i128
                            * integer(&relation, &witness, "recipient-public-key/quotient", index)
                }),
        );
        let products: Vec<_> = statement
            .aggregate
            .iter()
            .map(|packet| convolution(&packet.linear, &secret))
            .collect();
        for (index, coordinate) in relation.coordinates.iter().enumerate() {
            let packet = coordinate.source / DEGREE;
            let position = coordinate.source % DEGREE;
            residuals.push(
                products[packet][position] + statement.aggregate[packet].constant[position] as i128
                    - message_scale() as i128
                        * values(&relation, &witness, coordinate.variable)[coordinate.position]
                            as i128
                    - integer(
                        &relation,
                        &witness,
                        "selected-field-decryption/error",
                        index,
                    )
                    - modulus() as i128
                        * integer(
                            &relation,
                            &witness,
                            "selected-field-decryption/quotient",
                            index,
                        ),
            );
        }
        let (mask_rows, public_parts) = statement.rank_forms();
        let mut ordinary = 0;
        let mut fallback = 0;
        for (query, &candidate) in statement.selections.iter().enumerate() {
            residuals.push(if candidate < CANDIDATES {
                let value = values(&relation, &witness, "selected-low-product-mask")[ordinary]
                    as i128
                    + statement.multiplication[query * CANDIDATES + candidate] as i128
                    + public_parts[query] as i128
                        * values(&relation, &witness, "selected-multiplier")[ordinary] as i128
                    - statement.output[query] as i128
                    - PLAINTEXT as i128
                        * integer(
                            &relation,
                            &witness,
                            "rank-output-reduction-quotients",
                            ordinary,
                        );
                ordinary += 1;
                value
            } else {
                let value = mask_rows[query / top]
                    .iter()
                    .zip(values(&relation, &witness, "recovered-comparison-mask"))
                    .map(|(&coefficient, &value)| coefficient as i128 * value as i128)
                    .sum::<i128>()
                    + public_parts[query] as i128
                    - statement.output[query] as i128
                    - PLAINTEXT as i128
                        * integer(
                            &relation,
                            &witness,
                            "exceptional-rank-output-quotients",
                            fallback,
                        );
                fallback += 1;
                value
            });
        }
        assert_eq!(residuals.len(), relation.affine_rows);
        for challenge in [ZERO, ONE, [2, 3, 5]] {
            let (coefficients, constant) = relation.transpose(&statement, challenge);
            let actual =
                coefficients
                    .iter()
                    .zip(&witness)
                    .fold(constant, |sum, (coefficients, values)| {
                        add(
                            sum,
                            coefficients
                                .iter()
                                .zip(values)
                                .fold(ZERO, |sum, (&coefficient, &value)| {
                                    add(sum, scale(coefficient, value))
                                }),
                        )
                    });
            let expected = residuals.iter().rev().fold(ZERO, |sum, &residual| {
                add(multiply(sum, challenge), [signed(residual), 0, 0])
            });
            assert_eq!(actual, expected, "{participants}/{options}/{exceptional}");
        }
    }
}
