//! The release relation's operator as the statement built it before its
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
fn times(values: &[Element], weight: Element) -> Vec<Element> {
    values
        .iter()
        .map(|value| field::multiply(*value, weight))
        .collect()
}
struct Builder {
    profile: Profile,
    bits: Vec<usize>,
    starts: Vec<usize>,
    words: usize,
    alpha: Element,
    limb_weight: Element,
    geometric: Vec<Element>,
    coefficients: Vec<Vec<Element>>,
    target: Element,
    consumed: usize,
}
impl Builder {
    fn new(profile: Profile, alpha: Element, header: &[u8]) -> Result<Self, Error> {
        release_header_position(profile, header).ok_or(Error::Shape)?;
        let (starts, words) = release_variable_starts(profile);
        let mut value = ONE;
        let geometric = (0..SYSTEMATIC)
            .map(|_| {
                let previous = value;
                value = field::multiply(value, alpha);
                previous
            })
            .collect();
        Ok(Self {
            profile,
            bits: profile.release_variable_bits(),
            starts,
            words,
            alpha,
            limb_weight: power(alpha, SYSTEMATIC),
            geometric,
            coefficients: vec![vec![ZERO; SYSTEMATIC]; words + 2],
            target: ZERO,
            consumed: 0,
        })
    }
    fn words(
        &mut self,
        first: usize,
        count: usize,
        bias_bits: Option<usize>,
        coefficients: &[Element],
    ) {
        assert!(first + count <= self.words && coefficients.len() == SYSTEMATIC);
        let mut weight = 1u128;
        for column in first..first + count {
            for (target, value) in self.coefficients[column].iter_mut().zip(coefficients) {
                *target = field::add(*target, field::scale(*value, weight));
            }
            weight = field::base::multiply(weight, 65536);
        }
        if let Some(bits) = bias_bits {
            let bias = field::base::power(2, (bits - 1) as u128);
            let sum = coefficients.iter().copied().fold(ZERO, field::add);
            self.target = field::add(self.target, field::scale(sum, bias));
        }
    }
    /// Adds the words of bits `first..first + width` of a signed variable at
    /// the given row coefficients. A part holding the variable's top bits,
    /// or a centered lower part, is offset by half its range.
    fn part(
        &mut self,
        variable: usize,
        first: usize,
        width: usize,
        centered: bool,
        coefficients: &[Element],
    ) {
        assert!(first.is_multiple_of(16) && first + width <= self.bits[variable]);
        self.words(
            self.starts[variable] + first / 16,
            width.div_ceil(16),
            centered.then_some(width),
            coefficients,
        );
    }
    fn variable(&mut self, variable: usize, weight: Element, geometric: &[Element]) {
        self.part(
            variable,
            0,
            self.bits[variable],
            true,
            &times(geometric, weight),
        );
    }
    /// Adds each release limb of a signed variable at the row coefficients
    /// times its limb weight. Every limb but the top one is an unsigned
    /// digit.
    fn release_limbs(
        &mut self,
        variable: usize,
        coefficients: &[Element],
        weight: impl Fn(usize) -> Element,
    ) {
        let bits = self.bits[variable];
        let limbs = bits.div_ceil(RELEASE_LIMB_BITS);
        for limb in 0..limbs {
            let first = limb * RELEASE_LIMB_BITS;
            let top = limb + 1 == limbs;
            let width = if top { bits - first } else { RELEASE_LIMB_BITS };
            self.part(
                variable,
                first,
                width,
                top,
                &times(coefficients, weight(limb)),
            );
        }
    }
    fn polynomial(&mut self, index: usize, polynomial: PolynomialStream) -> Result<(), Error> {
        if index != self.consumed {
            return Err(Error::Shape);
        }
        self.consumed += 1;
        match index {
            0 | 3 => {
                let weight = if index == 0 {
                    ONE
                } else {
                    power(self.alpha, 2 * SYSTEMATIC)
                };
                for (position, value) in polynomial.adjoint()?.into_iter().enumerate() {
                    let value = field::multiply(weight, value);
                    self.coefficients[self.words][position] =
                        field::add(self.coefficients[self.words][position], value);
                    self.coefficients[self.words + 1][position] =
                        field::subtract(self.coefficients[self.words + 1][position], value);
                }
            }
            1 => self.target = field::subtract(self.target, polynomial.finish_value()?),
            2 => {
                self.target = field::subtract(
                    self.target,
                    field::multiply(
                        power(self.alpha, 2 * SYSTEMATIC),
                        polynomial.finish_value()?,
                    ),
                )
            }
            4 => {
                let adjoint = polynomial.adjoint()?;
                let base = power(self.alpha, 4 * SYSTEMATIC);
                let (limb_weight, clearing) =
                    (self.limb_weight, self.profile.clearing_factor() as u128);
                self.release_limbs(SHARE, &adjoint, |limb| {
                    field::scale(field::multiply(base, power(limb_weight, limb)), clearing)
                });
            }
            5 => {
                self.target = field::add(
                    self.target,
                    field::multiply(
                        power(self.alpha, 4 * SYSTEMATIC),
                        polynomial.finish_value()?,
                    ),
                )
            }
            _ => return Err(Error::Shape),
        }
        Ok(())
    }
    fn finish(mut self) -> Result<Dense, Error> {
        if self.consumed != POLYNOMIALS {
            return Err(Error::Shape);
        }
        let geometric = std::mem::take(&mut self.geometric);
        let limb_weight = self.limb_weight;
        let share_modulus = fingerprint(
            supported_profile::share_modulus(),
            DECODING_CHUNK,
            limb_weight,
        );
        let release_modulus = fingerprint(
            &self.profile.release_modulus().to_bytes(),
            RELEASE_CHUNK,
            limb_weight,
        );
        let decoding_carry =
            field::subtract(limb_weight, [1u128 << RELEASE_DECODING_LIMB_BITS, 0, 0]);
        // The recipient key equation.
        self.variable(
            KEY_QUOTIENT,
            field::subtract(ZERO, share_modulus),
            &geometric,
        );
        self.variable(KEY_CARRY, decoding_carry, &geometric);
        self.variable(KEY_ERROR, field::subtract(ZERO, ONE), &geometric);
        // The aggregate share's decoding equation, with the share scale times
        // the centered lower decoding limb and the signed upper part.
        let decryption = power(self.alpha, 2 * SYSTEMATIC);
        self.variable(
            DECODING_ERROR,
            field::subtract(ZERO, decryption),
            &geometric,
        );
        self.variable(
            DECODING_QUOTIENT,
            field::subtract(ZERO, field::multiply(decryption, share_modulus)),
            &geometric,
        );
        self.variable(
            DECODING_CARRY,
            field::multiply(decryption, decoding_carry),
            &geometric,
        );
        let share_bits = self.bits[SHARE];
        for (limb, first, width) in [
            (0, 0, RELEASE_DECODING_LIMB_BITS),
            (
                1,
                RELEASE_DECODING_LIMB_BITS,
                share_bits - RELEASE_DECODING_LIMB_BITS,
            ),
        ] {
            let weight = field::scale(
                field::multiply(decryption, power(limb_weight, limb)),
                signed(-i128::from(SHARE_SCALE)),
            );
            self.part(SHARE, first, width, true, &times(&geometric, weight));
        }
        let offset = BigInt::from(SHARE_SCALE) << (RELEASE_DECODING_LIMB_BITS - 1);
        let offset = fingerprint(&offset.to_bytes_le().1, DECODING_CHUNK, limb_weight);
        let geometric_sum = geometric.iter().copied().fold(ZERO, field::add);
        self.target = field::add(
            self.target,
            field::multiply(field::multiply(decryption, offset), geometric_sum),
        );
        // The partial decryption equation in release limbs.
        let release = power(self.alpha, 4 * SYSTEMATIC);
        let clearing = self.profile.clearing_factor() as u128;
        self.release_limbs(NOISE, &geometric, |limb| {
            field::scale(field::multiply(release, power(limb_weight, limb)), clearing)
        });
        self.release_limbs(RELEASE_QUOTIENT, &geometric, |limb| {
            field::subtract(
                ZERO,
                field::multiply(
                    field::multiply(release, power(limb_weight, limb)),
                    release_modulus,
                ),
            )
        });
        let release_carry = field::subtract(limb_weight, [1u128 << RELEASE_LIMB_BITS, 0, 0]);
        let output_limbs = self.profile.release_output_limbs();
        for limb in 0..output_limbs - 1 {
            self.variable(
                FIRST_RELEASE_CARRY + limb,
                field::multiply(
                    field::multiply(release, power(limb_weight, limb)),
                    release_carry,
                ),
                &geometric,
            );
        }
        // Each half of the recipient secret's support follows every limb row.
        let rows = (4 + output_limbs) * SYSTEMATIC;
        for sign in 0..2 {
            let weight = power(self.alpha, rows + sign);
            for value in &mut self.coefficients[self.words + sign] {
                *value = field::add(*value, weight);
            }
            self.target = field::add(
                self.target,
                field::scale(weight, (RECIPIENT_SECRET_SUPPORT / 2) as u128),
            );
        }
        Ok(Dense {
            coefficients: self.coefficients,
            target: self.target,
            lookup_weight: power(self.alpha, rows + 2),
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
        for chunk in bytes.chunks(CHUNK_LIMIT) {
            parser.push(chunk)?;
        }
        builder.polynomial(index, parser)?;
    }
    builder.finish()
}
