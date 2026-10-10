//! The ballot relation's operator as the statement built it before its
//! public polynomials were weighted: each column's coefficient placed at
//! every row. Tests compare the weighted operator with it.
use super::*;

/// Every relation column's coefficient at every row, the target and the
/// lookup weight.
pub(crate) struct Dense {
    pub(crate) coefficients: Vec<Vec<Element>>,
    pub(crate) target: Element,
    pub(crate) lookup_weight: Element,
}
/// Rows of the ballot equations: each FHE ciphertext component's limbs,
/// one ring degree per limb, then the packing equation, then each auxiliary
/// ciphertext component, then the secrets' supports.
struct Builder {
    profile: Profile,
    columns: BallotColumns,
    alpha: Element,
    coefficients: Vec<Vec<Element>>,
    target: Element,
    consumed: usize,
}
impl Builder {
    fn new(profile: Profile, alpha: Element, header: &[u8]) -> Result<Self, Error> {
        protocol_foundations::ballot_body::check_context(profile, header)
            .map_err(|_| Error::Shape)?;
        Ok(Self {
            profile,
            columns: BallotColumns::new(profile),
            alpha,
            coefficients: vec![vec![ZERO; SYSTEMATIC]; ballot_relation(profile).columns()],
            target: ZERO,
            consumed: 0,
        })
    }
    fn fhe_row(&self, component: usize) -> usize {
        component * self.columns.fhe_limbs() * SYSTEMATIC
    }
    fn packing_row(&self) -> usize {
        self.fhe_row(2)
    }
    fn auxiliary_row(&self, component: usize) -> usize {
        self.packing_row() + SYSTEMATIC + component * AUXILIARY_DEGREE
    }
    fn add_geometric(&mut self, column: usize, weight: Element, degree: usize) {
        let stride = SYSTEMATIC / degree;
        for (index, value) in powers(self.alpha, degree).into_iter().enumerate() {
            self.coefficients[column][stride * index] = field::add(
                self.coefficients[column][stride * index],
                field::multiply(weight, value),
            );
        }
    }
    fn polynomial(&mut self, index: usize, parser: PolynomialStream) -> Result<(), Error> {
        if self.consumed != index || index >= POLYNOMIALS {
            return Err(Error::Shape);
        }
        self.consumed += 1;
        let auxiliary = family(index) == Family::Auxiliary;
        let local = index % (POLYNOMIALS / 2);
        // The common polynomial and the second ciphertext component enter
        // the second component's equation; the key and the first component
        // enter the first's.
        let component = usize::from(local == 0 || local == 3);
        let weight = power(
            self.alpha,
            if auxiliary {
                self.auxiliary_row(component)
            } else {
                self.fhe_row(component)
            },
        );
        if local < 2 {
            let degree = self.profile.family_degree(family(index));
            let adjoint = parser.adjoint().map_err(|_| Error::Encoding)?;
            let positive = if auxiliary {
                self.columns.auxiliary_positive()
            } else {
                self.columns.fhe_positive()
            };
            for (position, value) in adjoint.into_iter().enumerate() {
                let value = field::multiply(weight, value);
                let position = position * (SYSTEMATIC / degree);
                self.coefficients[positive][position] =
                    field::add(self.coefficients[positive][position], value);
                self.coefficients[positive + 1][position] =
                    field::subtract(self.coefficients[positive + 1][position], value);
            }
        } else {
            self.target = field::add(
                self.target,
                field::multiply(weight, parser.finish_value().map_err(|_| Error::Encoding)?),
            );
        }
        Ok(())
    }
    fn finish(mut self) -> Result<Dense, Error> {
        if self.consumed != POLYNOMIALS {
            return Err(Error::Shape);
        }
        let columns = self.columns;
        let limb_weight = power(self.alpha, SYSTEMATIC);
        let modulus_bytes = self.profile.ciphertext_modulus().to_bytes();
        let modulus = public_digits(&modulus_bytes, limb_weight);
        let raw_modulus = BigInt::from_bytes_le(Sign::Plus, &modulus_bytes);
        let scale = public_digits(
            &((&raw_modulus - BigInt::from(1)) / BigInt::from(PLAINTEXT_MODULUS))
                .to_bytes_le()
                .1,
            limb_weight,
        );
        let radix = [1u128 << FHE_LIMB_BITS, 0, 0];
        let word = 1u128 << WORD_BITS;
        for component in 0..2 {
            let weight = power(self.alpha, self.fhe_row(component));
            self.add_geometric(
                columns.fhe_quotient(component),
                field::subtract(ZERO, field::multiply(weight, modulus)),
                SYSTEMATIC,
            );
            self.add_geometric(columns.fhe_error(component), weight, SYSTEMATIC);
            for carry in 0..columns.fhe_limbs() - 1 {
                let carry_weight = field::multiply(
                    weight,
                    field::multiply(
                        power(limb_weight, carry),
                        field::subtract(limb_weight, radix),
                    ),
                );
                self.add_geometric(
                    columns.fhe_carry(component, carry),
                    carry_weight,
                    SYSTEMATIC,
                );
            }
            if component == 0 {
                self.add_geometric(columns.plaintext(), scale, SYSTEMATIC);
                self.add_geometric(
                    columns.plaintext_high_bit(),
                    field::scale(scale, word),
                    SYSTEMATIC,
                );
            }
        }
        let packing_weight = power(self.alpha, self.packing_row());
        self.add_geometric(columns.plaintext(), packing_weight, SYSTEMATIC);
        self.add_geometric(
            columns.plaintext_high_bit(),
            field::scale(packing_weight, word),
            SYSTEMATIC,
        );
        self.add_geometric(
            columns.packing_quotient(),
            field::scale(packing_weight, signed(-i64::from(PLAINTEXT_MODULUS))),
            SYSTEMATIC,
        );
        let options = self.profile.options();
        let matrix = PackingMatrix::new(options).map_err(|_| Error::Shape)?;
        let geometric = powers(self.alpha, SYSTEMATIC);
        for option in 0..options {
            let column = matrix.column(option).map_err(|_| Error::Shape)?;
            let value = column
                .iter()
                .zip(&geometric)
                .fold(ZERO, |sum, (coefficient, weight)| {
                    field::add(sum, field::scale(*weight, signed(i64::from(*coefficient))))
                });
            self.coefficients[columns.scores()][option] = field::subtract(
                self.coefficients[columns.scores()][option],
                field::multiply(packing_weight, value),
            );
        }
        let mut modulus_word = [0; 16];
        modulus_word[..auxiliary_modulus().len()].copy_from_slice(auxiliary_modulus());
        let auxiliary_modulus = u128::from_le_bytes(modulus_word);
        let auxiliary_scale = (auxiliary_modulus - 1) / u128::from(AUXILIARY_PLAINTEXT_MODULUS);
        for component in 0..2 {
            let weight = power(self.alpha, self.auxiliary_row(component));
            self.add_geometric(
                columns.auxiliary_quotient(component),
                field::scale(weight, MODULUS - auxiliary_modulus),
                AUXILIARY_DEGREE,
            );
            self.add_geometric(columns.auxiliary_error(component), weight, AUXILIARY_DEGREE);
            if component == 0 {
                // The auxiliary plaintext carries each score at its option's
                // coefficient.
                for (option, point) in geometric.iter().take(options).enumerate() {
                    self.coefficients[columns.scores()][option] = field::add(
                        self.coefficients[columns.scores()][option],
                        field::scale(field::multiply(weight, *point), auxiliary_scale),
                    );
                }
            }
        }
        // Each support column sums to half of its secret's support.
        let relation = ballot_relation(self.profile);
        let mut row = self.auxiliary_row(2);
        for pair in 0..relation.support_pairs() {
            let (positive, negative) = relation.zero_product_columns(pair);
            let (stride, half) = relation.support(pair);
            for column in [positive, negative] {
                let weight = power(self.alpha, row);
                row += 1;
                for position in (0..SYSTEMATIC).step_by(stride) {
                    self.coefficients[column][position] =
                        field::add(self.coefficients[column][position], weight);
                }
                self.target = field::add(self.target, field::scale(weight, u128::from(half)));
            }
        }
        // Signed words are offset by half their range and scores less one
        // are stored.
        let narrow = [
            columns.fhe_error(0),
            columns.fhe_error(1),
            columns.auxiliary_error(0),
            columns.auxiliary_error(1),
        ];
        for column in 0..columns.words() {
            let offset = if column == columns.scores() {
                -1
            } else if narrow.contains(&column) {
                1 << (SETUP_ERROR_BITS - 1)
            } else {
                1 << (WORD_BITS - 1)
            };
            let sum = self.coefficients[column]
                .iter()
                .copied()
                .fold(ZERO, field::add);
            self.target = field::add(self.target, field::scale(sum, signed(offset)));
        }
        Ok(Dense {
            coefficients: self.coefficients,
            target: self.target,
            lookup_weight: power(self.alpha, row),
        })
    }
}

/// The dense operator of the statement at the challenge.
pub(crate) fn operator(statement: &PublicStatement, alpha: Element) -> Result<Dense, Error> {
    let mut builder = Builder::new(statement.profile, alpha, &statement.header)?;
    if statement.polynomials.len() != POLYNOMIALS {
        return Err(Error::Shape);
    }
    for (index, bytes) in statement.polynomials.iter().enumerate() {
        let mut parser = polynomial_stream(statement.profile, index, alpha)?;
        for chunk in bytes.chunks(1 << 20) {
            parser.push(chunk).map_err(|_| Error::Encoding)?;
        }
        builder.polynomial(index, parser)?;
    }
    builder.finish()
}
