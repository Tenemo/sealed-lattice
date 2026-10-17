use crate::{
    field::*,
    statement::{CANDIDATES, DEGREE, PLAINTEXT, SUPPORT, Statement, message_scale, modulus},
};

pub struct Variable {
    pub name: String,
    pub values: usize,
    pub range: usize,
}
struct Integer {
    name: String,
    bits: usize,
    signed: bool,
    parts: Vec<(usize, usize)>,
}
pub struct Column {
    pub name: String,
    pub active: usize,
    pub range: Option<usize>,
    segments: Vec<(usize, usize, usize)>,
}
struct Coordinate {
    variable: &'static str,
    position: usize,
    source: usize,
}
pub struct Relation {
    variables: Vec<Variable>,
    integers: Vec<Integer>,
    coordinates: Vec<Coordinate>,
    pub columns: Vec<Column>,
    pub families: Vec<usize>,
    pub positive: usize,
    pub negative: usize,
    pub reciprocals: Vec<usize>,
    pub lengths: [usize; 3],
    pub affine_rows: usize,
}

impl Relation {
    fn range(&mut self, name: &str, values: usize, range: usize) -> usize {
        let position = self.variables.len();
        self.variables.push(Variable {
            name: name.into(),
            values,
            range,
        });
        position
    }
    fn integer(&mut self, name: &str, values: usize, bits: usize, signed: bool) {
        let mut parts = Vec::new();
        for shift in (0..bits).step_by(11) {
            let width = 11.min(bits - shift);
            let part_name = format!("{name}/{}-{shift}", if width == 1 { "bit" } else { "word" });
            let variable = self.range(&part_name, values, 1 << width);
            parts.push((variable, shift));
        }
        self.integers.push(Integer {
            name: name.into(),
            bits,
            signed,
            parts,
        });
    }
    pub fn new(statement: &Statement) -> Self {
        let fallback = statement
            .selections
            .iter()
            .filter(|&&candidate| candidate == CANDIDATES)
            .count();
        let ordinary = statement.queries - fallback;
        let recovered = if fallback == 0 {
            0
        } else {
            statement.mask_coordinates
        };
        let decrypted = 2 * ordinary + recovered;
        let contributors = statement.profile.setup_contributors();
        let true_error = contributors * (2 * SUPPORT + 1) * 64 + (contributors - 1) * 122;
        let error_bits = true_error.ilog2() as usize + 2;
        let mut relation = Self {
            variables: Vec::new(),
            integers: Vec::new(),
            coordinates: Vec::new(),
            columns: Vec::new(),
            families: Vec::new(),
            positive: 0,
            negative: 0,
            reciprocals: Vec::new(),
            lengths: [0; 3],
            affine_rows: 2 + DEGREE + decrypted + statement.queries,
        };
        relation.integer("recipient-public-key/quotient", DEGREE, 16, true);
        relation.integer("recipient-public-key/error", DEGREE, 7, true);
        if ordinary != 0 {
            relation.range("selected-low-product-mask", ordinary, PLAINTEXT);
            relation.range("selected-multiplier", ordinary, PLAINTEXT);
            relation.integer("rank-output-reduction-quotients", ordinary, 12, false);
        }
        if fallback != 0 {
            relation.range("recovered-comparison-mask", recovered, PLAINTEXT);
            relation.integer("exceptional-rank-output-quotients", fallback, 20, false);
        }
        relation.integer("selected-field-decryption/quotient", decrypted, 16, true);
        relation.integer(
            "selected-field-decryption/error",
            decrypted,
            error_bits,
            true,
        );
        let mut ordinal = 0;
        for (query, &candidate) in statement.selections.iter().enumerate() {
            if candidate == CANDIDATES {
                continue;
            }
            for (kind, variable) in [(2, "selected-low-product-mask"), (0, "selected-multiplier")] {
                relation.coordinates.push(Coordinate {
                    variable,
                    position: ordinal,
                    source: statement.source_position(kind, query, candidate),
                });
            }
            ordinal += 1;
        }
        for position in 0..recovered {
            relation.coordinates.push(Coordinate {
                variable: "recovered-comparison-mask",
                position,
                source: position,
            });
        }
        // Equal-range buckets retain first occurrence order from the relation.
        let mut buckets: Vec<(usize, Vec<usize>)> = Vec::new();
        let mut booleans = Vec::new();
        for (index, variable) in relation.variables.iter().enumerate() {
            if variable.range == 2 {
                booleans.push(index);
                continue;
            }
            if let Some(bucket) = buckets.iter_mut().find(|bucket| bucket.0 == variable.range) {
                bucket.1.push(index);
            } else {
                buckets.push((variable.range, vec![index]));
            }
        }
        for (ordinal, (range, variables)) in buckets.iter().enumerate() {
            relation.add_bucket(&format!("word-{ordinal}"), variables, Some(*range));
        }
        let positive = relation.range("recipient-secret/positive", DEGREE, 2);
        let negative = relation.range("recipient-secret/negative", DEGREE, 2);
        relation.positive = relation.columns.len();
        relation.add_bucket("positive", &[positive], None);
        relation.negative = relation.columns.len();
        relation.add_bucket("negative", &[negative], None);
        relation.add_bucket("boolean", &booleans, None);
        relation.families = buckets.iter().map(|bucket| bucket.0).collect();
        relation.families.sort_unstable();
        relation.reciprocals = relation
            .columns
            .iter()
            .enumerate()
            .filter_map(|(index, column)| column.range.map(|_| index))
            .collect();
        relation.lengths = [
            relation
                .columns
                .iter()
                .map(|column| column.active + 3)
                .sum::<usize>()
                + relation.families.iter().map(|size| size + 3).sum::<usize>()
                + 3,
            relation
                .reciprocals
                .iter()
                .map(|&column| relation.columns[column].active + 3)
                .sum(),
            3 * DEGREE + 9,
        ];
        let maximum_residual = (2 * DEGREE as u128 + 1) * (modulus() / 2) as u128
            + modulus() as u128 * 32768
            + message_scale() as u128 * (PLAINTEXT - 1) as u128
            + (1 << 24);
        assert!(2 * maximum_residual < MODULUS);
        relation
    }

    fn add_bucket(&mut self, name: &str, variables: &[usize], range: Option<usize>) {
        let mut current = None;
        for &variable in variables {
            let mut consumed = 0;
            while consumed < self.variables[variable].values {
                if current.is_none_or(|index: usize| self.columns[index].active == DEGREE) {
                    current = Some(self.columns.len());
                    self.columns.push(Column {
                        name: format!("{name}/{}", self.columns.len()),
                        active: 0,
                        range,
                        segments: Vec::new(),
                    });
                }
                let column = &mut self.columns[current.unwrap()];
                let length =
                    (DEGREE - column.active).min(self.variables[variable].values - consumed);
                column.segments.push((variable, consumed, length));
                column.active += length;
                consumed += length;
            }
        }
    }

    fn contribute(
        &self,
        coefficients: &mut [Vec<Element>],
        constant: &mut Element,
        name: &str,
        position: usize,
        coefficient: Element,
    ) {
        if let Some(integer) = self.integers.iter().find(|integer| integer.name == name) {
            if integer.signed {
                *constant = subtract(*constant, scale(coefficient, 1 << (integer.bits - 1)));
            }
            for &(variable, shift) in &integer.parts {
                coefficients[variable][position] = add(
                    coefficients[variable][position],
                    scale(coefficient, 1 << shift),
                );
            }
        } else {
            let variable = self
                .variables
                .iter()
                .position(|variable| variable.name == name)
                .expect("Relation variable");
            coefficients[variable][position] = add(coefficients[variable][position], coefficient);
        }
    }

    fn transpose(&self, statement: &Statement, challenge: Element) -> (Vec<Vec<Element>>, Element) {
        let mut coefficients: Vec<_> = self
            .variables
            .iter()
            .map(|variable| vec![ZERO; variable.values])
            .collect();
        let mut constant = ZERO;
        let mut weight = ONE;
        let mut rows = 0;
        for name in ["recipient-secret/positive", "recipient-secret/negative"] {
            for index in 0..DEGREE {
                self.contribute(&mut coefficients, &mut constant, name, index, weight);
            }
            constant = subtract(constant, scale(weight, (SUPPORT / 2) as u128));
            weight = multiply(weight, challenge);
            rows += 1;
        }
        let first_key_weight = weight;
        let mut initial = ZERO;
        let mut power = ONE;
        for &value in &statement.common {
            initial = add(initial, scale_signed(power, value as i128));
            power = multiply(power, challenge);
        }
        let boundary = multiply(first_key_weight, add(power, ONE));
        let mut secret_coefficient = multiply(first_key_weight, initial);
        let mut secret = vec![ZERO; DEGREE];
        for (index, entry) in secret.iter_mut().enumerate() {
            *entry = secret_coefficient;
            secret_coefficient = subtract(
                multiply(challenge, secret_coefficient),
                scale_signed(boundary, statement.common[DEGREE - 1 - index] as i128),
            );
            constant = add(
                constant,
                scale_signed(weight, statement.public_key[index] as i128),
            );
            self.contribute(
                &mut coefficients,
                &mut constant,
                "recipient-public-key/error",
                index,
                scale_signed(weight, -1),
            );
            self.contribute(
                &mut coefficients,
                &mut constant,
                "recipient-public-key/quotient",
                index,
                scale_signed(weight, -i128::from(modulus())),
            );
            weight = multiply(weight, challenge);
            rows += 1;
        }
        for (row, coordinate) in self.coordinates.iter().enumerate() {
            let packet = &statement.aggregate[coordinate.source / DEGREE];
            let position = coordinate.source % DEGREE;
            for (index, entry) in secret.iter_mut().enumerate() {
                let coefficient = packet.linear[(position + DEGREE - index) % DEGREE];
                *entry = add(
                    *entry,
                    scale_signed(
                        weight,
                        if index <= position {
                            coefficient as i128
                        } else {
                            -i128::from(coefficient)
                        },
                    ),
                );
            }
            constant = add(
                constant,
                scale_signed(weight, packet.constant[position] as i128),
            );
            self.contribute(
                &mut coefficients,
                &mut constant,
                coordinate.variable,
                coordinate.position,
                scale_signed(weight, -i128::from(message_scale())),
            );
            self.contribute(
                &mut coefficients,
                &mut constant,
                "selected-field-decryption/error",
                row,
                scale_signed(weight, -1),
            );
            self.contribute(
                &mut coefficients,
                &mut constant,
                "selected-field-decryption/quotient",
                row,
                scale_signed(weight, -i128::from(modulus())),
            );
            weight = multiply(weight, challenge);
            rows += 1;
        }
        let (mask_rows, public_parts) = statement.rank_forms();
        let mut ordinary = 0;
        let mut fallback = 0;
        for (query, &candidate) in statement.selections.iter().enumerate() {
            if candidate < CANDIDATES {
                self.contribute(
                    &mut coefficients,
                    &mut constant,
                    "selected-low-product-mask",
                    ordinary,
                    weight,
                );
                self.contribute(
                    &mut coefficients,
                    &mut constant,
                    "selected-multiplier",
                    ordinary,
                    scale(weight, public_parts[query] as u128),
                );
                self.contribute(
                    &mut coefficients,
                    &mut constant,
                    "rank-output-reduction-quotients",
                    ordinary,
                    scale_signed(weight, -(PLAINTEXT as i128)),
                );
                constant = add(
                    constant,
                    scale_signed(
                        weight,
                        statement.multiplication[query * CANDIDATES + candidate] as i128
                            - statement.output[query] as i128,
                    ),
                );
                ordinary += 1;
            } else {
                for (position, &coefficient) in mask_rows[query / statement.top].iter().enumerate()
                {
                    self.contribute(
                        &mut coefficients,
                        &mut constant,
                        "recovered-comparison-mask",
                        position,
                        scale(weight, coefficient as u128),
                    );
                }
                self.contribute(
                    &mut coefficients,
                    &mut constant,
                    "exceptional-rank-output-quotients",
                    fallback,
                    scale_signed(weight, -(PLAINTEXT as i128)),
                );
                constant = add(
                    constant,
                    scale_signed(
                        weight,
                        public_parts[query] as i128 - statement.output[query] as i128,
                    ),
                );
                fallback += 1;
            }
            weight = multiply(weight, challenge);
            rows += 1;
        }
        for (index, &coefficient) in secret.iter().enumerate() {
            self.contribute(
                &mut coefficients,
                &mut constant,
                "recipient-secret/positive",
                index,
                coefficient,
            );
            self.contribute(
                &mut coefficients,
                &mut constant,
                "recipient-secret/negative",
                index,
                scale_signed(coefficient, -1),
            );
        }
        assert_eq!(rows, self.affine_rows);
        (coefficients, constant)
    }

    pub fn public_weights(
        &self,
        statement: &Statement,
        challenge: Element,
        lagrange: &[Element],
    ) -> (Vec<Element>, Element) {
        let (coefficients, constant) = self.transpose(statement, challenge);
        let weights = self
            .columns
            .iter()
            .map(|column| {
                let mut offset = 0;
                let mut sum = ZERO;
                for &(variable, start, length) in &column.segments {
                    sum = add(
                        sum,
                        dot(
                            &coefficients[variable][start..start + length],
                            &lagrange[offset..offset + length],
                        ),
                    );
                    offset += length;
                }
                sum
            })
            .collect();
        (
            weights,
            scale(constant, base::power(DEGREE as u128, MODULUS - 2)),
        )
    }
}

#[cfg(test)]
#[path = "relation-tests.rs"]
mod tests;
