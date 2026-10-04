use crate::{
    DEGREE, Error, LIMB_BITS, SELECTED, SUPPORT, digit,
    layout::Layout,
    modulus,
    statement::{Statement, encoded_bytes},
};
use seed_sharing_proof::statement::feed_polynomial;
use setup_stream_kernel::PolynomialStream;
use word_proof::{
    affine::{Operator, PublicColumn, Term},
    field::{self, Element, ONE, ZERO},
};

fn signed(value: i128) -> Element {
    let magnitude = [value.unsigned_abs(), 0, 0];
    if value < 0 {
        field::subtract(ZERO, magnitude)
    } else {
        magnitude
    }
}
/// Public arithmetic only. The canonical stream order is A, P, V0, D0,
/// V1, D1. It creates no proof, statement, verified record or authority.
pub struct Accumulator {
    degree: usize,
    alpha: Element,
    layout: Layout,
    geometric_sum: Element,
    equation_step: Element,
    modulus_fingerprint: Element,
    carry_factor: Element,
    adjoint: Vec<Element>,
    geometric: Vec<(usize, Element)>,
    target: Element,
    weight: Element,
    polynomial: usize,
    parser: Option<PolynomialStream>,
    failed: bool,
}
impl Accumulator {
    pub fn new(degree: usize, alpha: Element) -> Result<Self, Error> {
        if !degree.is_power_of_two()
            || !(SUPPORT..=supported_profile::relation::SYSTEMATIC).contains(&degree)
        {
            return Err("Opening operator degree");
        }
        if alpha.iter().any(|value| *value >= field::MODULUS) {
            return Err("Noncanonical affine challenge");
        }
        let parser =
            PolynomialStream::new(supported_profile::share_modulus(), degree, LIMB_BITS, alpha)
                .map_err(|_| "Opening polynomial parameters")?;
        let mut limb_weight = ONE;
        let mut geometric_sum = ZERO;
        for _ in 0..degree {
            geometric_sum = field::add(geometric_sum, limb_weight);
            limb_weight = field::multiply(limb_weight, alpha);
        }
        let modulus = modulus();
        Ok(Self {
            degree,
            alpha,
            layout: Layout::new(encoded_bytes()),
            geometric_sum,
            equation_step: field::multiply(limb_weight, limb_weight),
            modulus_fingerprint: field::add(
                signed(digit(&modulus, 0)),
                field::multiply(limb_weight, signed(digit(&modulus, 1))),
            ),
            carry_factor: field::subtract(limb_weight, signed(1i128 << LIMB_BITS)),
            adjoint: vec![ZERO; degree],
            geometric: Vec::new(),
            target: ZERO,
            weight: ONE,
            polynomial: 0,
            parser: Some(parser),
            failed: false,
        })
    }
    fn refuse(&mut self, error: Error) -> Result<(), Error> {
        self.failed = true;
        self.parser = None;
        Err(error)
    }
    pub fn push(&mut self, polynomial: usize, bytes: &[u8]) -> Result<(), Error> {
        if self.failed || polynomial != self.polynomial || self.parser.is_none() {
            return self.refuse("Opening operator stream order");
        }
        if self.parser.as_mut().unwrap().push(bytes).is_err() {
            return self.refuse("Opening polynomial encoding");
        }
        Ok(())
    }
    pub fn finish_polynomial(&mut self, polynomial: usize) -> Result<(), Error> {
        if self.failed || polynomial != self.polynomial || self.parser.is_none() {
            return self.refuse("Opening operator stream order");
        }
        let parser = self.parser.take().unwrap();
        if polynomial.is_multiple_of(2) {
            let values = match parser.adjoint() {
                Ok(values) => values,
                Err(_) => return self.refuse("Opening polynomial adjoint"),
            };
            for (accumulated, value) in self.adjoint.iter_mut().zip(values) {
                *accumulated = field::add(*accumulated, field::multiply(self.weight, value));
            }
        } else {
            let value = match parser.finish_value() {
                Ok(value) => value,
                Err(_) => return self.refuse("Opening polynomial value"),
            };
            // Public constants and recovery errors enter the residual with
            // opposite signs. Move only the constant to the target here.
            self.target = field::subtract(self.target, field::multiply(self.weight, value));
            let factors = [
                field::subtract(ZERO, field::multiply(self.weight, self.modulus_fingerprint)),
                field::multiply(self.weight, self.carry_factor),
                field::subtract(ZERO, self.weight),
            ];
            for (offset, factor) in factors.into_iter().enumerate() {
                let variable = 3 * (polynomial / 2) + offset;
                for &(column, place) in &self.layout.signed[variable] {
                    self.geometric.push((column, field::scale(factor, place)));
                }
                let bias = field::scale(factor, 1u128 << (self.layout.widths[variable] - 1));
                self.target = field::add(self.target, field::multiply(self.geometric_sum, bias));
            }
            self.weight = field::multiply(self.weight, self.equation_step);
        }
        self.polynomial += 1;
        if self.polynomial < 2 * (SELECTED + 1) {
            self.parser = match PolynomialStream::new(
                supported_profile::share_modulus(),
                self.degree,
                LIMB_BITS,
                self.alpha,
            ) {
                Ok(parser) => Some(parser),
                Err(_) => return self.refuse("Opening polynomial parameters"),
            };
        }
        Ok(())
    }
    pub fn finish(mut self) -> Result<Operator, Error> {
        if self.failed || self.polynomial != 2 * (SELECTED + 1) || self.parser.is_some() {
            return Err("Incomplete opening operator");
        }
        let negative_weight = field::multiply(self.weight, self.alpha);
        self.target = field::add(
            self.target,
            field::scale(
                field::add(self.weight, negative_weight),
                (SUPPORT / 2) as u128,
            ),
        );
        let positive = self.layout.relation.words;
        Ok(Operator {
            alpha: self.alpha,
            terms: vec![
                Term {
                    public: PublicColumn::Values(self.adjoint),
                    weights: vec![(positive, ONE), (positive + 1, field::subtract(ZERO, ONE))],
                },
                Term {
                    public: PublicColumn::Powers(self.degree),
                    weights: self.geometric,
                },
                Term {
                    public: PublicColumn::Ones(self.degree),
                    weights: vec![(positive, self.weight), (positive + 1, negative_weight)],
                },
            ],
            target: self.target,
            lookup_weight: field::multiply(negative_weight, self.alpha),
        })
    }
}

/// The normal proof path admits only its unchanged bounded statement.
pub fn build(statement: &Statement, alpha: Element) -> Result<Operator, Error> {
    if alpha.iter().any(|value| *value >= field::MODULUS) {
        return Err("Noncanonical affine challenge");
    }
    statement.validate()?;
    let mut accumulator = Accumulator::new(DEGREE, alpha)?;
    for (equation, (constant, linear)) in statement.equations().enumerate() {
        for (component, values) in [linear, constant.as_slice()].into_iter().enumerate() {
            let polynomial = 2 * equation + component;
            feed_polynomial(values, DEGREE, |bytes| accumulator.push(polynomial, bytes))?;
            accumulator.finish_polynomial(polynomial)?;
        }
    }
    accumulator.finish()
}
