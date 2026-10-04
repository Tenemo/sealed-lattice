use crate::{
    DEGREE, Error, RECIPIENTS, SCALE, SEED_BITS, SUPPORT, digit,
    layout::{Layout, variable},
    modulus, profile, rotation_for_degree,
    statement::{Statement, encoded_bytes, feed_polynomial},
};
use num_bigint::BigInt;
use setup_stream_kernel::PolynomialStream;
use word_proof::{
    affine::{Operator, PublicColumn, Term},
    field::{self, Element, ONE, ZERO},
    parameters::SYSTEMATIC,
};

fn signed(value: i128) -> Element {
    let positive = [value.unsigned_abs(), 0, 0];
    if value < 0 {
        field::subtract(ZERO, positive)
    } else {
        positive
    }
}

// The two signed integer limbs have relative row weight alpha^physical_degree.
fn fingerprint(value: &BigInt, limb_weight: Element) -> Element {
    field::add(
        signed(digit(value, 0)),
        field::multiply(limb_weight, signed(digit(value, 1))),
    )
}

// The word/Boolean digits of a signed variable share one public basis.
// Its offset moves to the target with the same coefficient.
fn signed_weights(
    layout: &Layout,
    variable: usize,
    factor: Element,
    weights: &mut Vec<(usize, Element)>,
) -> Element {
    for &(column, place) in &layout.signed[variable] {
        weights.push((column, field::scale(factor, place)));
    }
    field::scale(factor, 1u128 << (layout.widths[variable] - 1))
}

/// Public arithmetic for the fixed four-recipient, degree-one sharing
/// relation. It consumes canonical common/key/U/V records in that order;
/// it verifies no proof and creates no participant authority.
pub struct Accumulator {
    degree: usize,
    seed_bits: usize,
    alpha: Element,
    next: usize,
    parser: Option<PolynomialStream>,
    adjoints: Vec<Vec<Element>>,
    ciphertext_values: Vec<Element>,
    failed: bool,
}
impl Accumulator {
    pub fn new(degree: usize, seed_bits: usize, alpha: Element) -> Result<Self, Error> {
        if !degree.is_power_of_two()
            || !(SUPPORT..=SYSTEMATIC).contains(&degree)
            || seed_bits == 0
            || seed_bits > degree
        {
            return Err("Public operator dimensions");
        }
        let parser = PolynomialStream::new(
            supported_profile::share_modulus(),
            degree,
            profile().share_limb_bits(),
            alpha,
        )
        .map_err(|_| "Public operator parameters")?;
        Ok(Self {
            degree,
            seed_bits,
            alpha,
            next: 0,
            parser: Some(parser),
            adjoints: Vec::with_capacity(1 + RECIPIENTS),
            ciphertext_values: Vec::with_capacity(2 * RECIPIENTS),
            failed: false,
        })
    }
    fn check_order(&mut self, polynomial: usize) -> Result<(), Error> {
        if self.failed || polynomial != self.next || self.parser.is_none() {
            self.failed = true;
            return Err("Public polynomial order");
        }
        Ok(())
    }
    pub fn push(&mut self, polynomial: usize, bytes: &[u8]) -> Result<(), Error> {
        self.check_order(polynomial)?;
        let result = self
            .parser
            .as_mut()
            .unwrap()
            .push(bytes)
            .map_err(|_| "Public polynomial encoding");
        self.failed |= result.is_err();
        result
    }
    pub fn finish_polynomial(&mut self, polynomial: usize) -> Result<(), Error> {
        self.check_order(polynomial)?;
        let parser = self.parser.take().unwrap();
        let result = if polynomial == 0 || (polynomial - 1).is_multiple_of(3) {
            parser.adjoint().map(|values| self.adjoints.push(values))
        } else {
            parser
                .finish_value()
                .map(|value| self.ciphertext_values.push(value))
        };
        if result.is_err() {
            self.failed = true;
            return Err("Public polynomial incomplete");
        }
        self.next += 1;
        if self.next < 1 + 3 * RECIPIENTS {
            self.parser = Some(
                PolynomialStream::new(
                    supported_profile::share_modulus(),
                    self.degree,
                    profile().share_limb_bits(),
                    self.alpha,
                )
                .expect("Previously checked public operator parameters"),
            );
        }
        Ok(())
    }
    pub fn finish(self) -> Result<Operator, Error> {
        if self.failed || self.next != 1 + 3 * RECIPIENTS || self.parser.is_some() {
            return Err("Public operator incomplete");
        }
        Ok(finish_operator(
            self.degree,
            self.seed_bits,
            self.alpha,
            self.adjoints,
            self.ciphertext_values,
        ))
    }
}

/// Keeps the bounded proof's exact statement checks, then consumes the same
/// public-data accumulator as the full-ring arithmetic screen.
pub fn build(statement: &Statement, alpha: Element) -> Result<Operator, Error> {
    if alpha.iter().any(|value| *value >= field::MODULUS) {
        return Err("Noncanonical affine challenge");
    }
    statement.validate()?;
    let mut accumulator = Accumulator::new(DEGREE, SEED_BITS, alpha)?;
    for (index, values) in std::iter::once(&statement.common)
        .chain(statement.recipients.iter().flat_map(|recipient| {
            [
                &recipient.public_key,
                &recipient.ciphertext[0],
                &recipient.ciphertext[1],
            ]
        }))
        .enumerate()
    {
        feed_polynomial(values, DEGREE, |bytes| accumulator.push(index, bytes))?;
        accumulator.finish_polynomial(index)?;
    }
    accumulator.finish()
}

// The adjoints and values are complete and in canonical order. Geometric
// bases are materialized only after the last polynomial parser is released.
fn finish_operator(
    degree: usize,
    seed_bits: usize,
    alpha: Element,
    adjoints: Vec<Vec<Element>>,
    ciphertext_values: Vec<Element>,
) -> Operator {
    let layout = Layout::new(encoded_bytes());
    let parameters = profile();
    let radix = 1i128 << parameters.share_limb_bits();
    let mut seed = vec![ZERO; degree];
    let mut sum = ZERO;
    let mut limb_weight = ONE;
    for (row, value) in seed.iter_mut().enumerate() {
        sum = field::add(sum, limb_weight);
        if row < seed_bits {
            *value = limb_weight;
        }
        limb_weight = field::multiply(limb_weight, alpha);
    }
    let equation_weight = field::multiply(limb_weight, limb_weight);
    let quotient = field::subtract(ZERO, fingerprint(&modulus(), limb_weight));
    let carry = field::subtract(limb_weight, signed(radix));
    let mut sharing = vec![ZERO; degree];
    let mut common_weights = Vec::with_capacity(2 * RECIPIENTS);
    let mut fixed_weights = Vec::new();
    let mut terms = Vec::with_capacity(RECIPIENTS + 5);
    let mut target = ZERO;
    let mut fixed_offset = ZERO;
    let mut seed_weight = ZERO;
    let mut weight = ONE;
    let mut adjoints = adjoints.into_iter();
    let common_adjoint = adjoints.next().unwrap();
    for (recipient, key_adjoint) in adjoints.enumerate() {
        let positive = layout.relation.words + 2 * recipient;
        terms.push(Term {
            public: PublicColumn::Values(key_adjoint),
            weights: vec![
                (positive, weight),
                (positive + 1, field::subtract(ZERO, weight)),
            ],
        });
        seed_weight = field::add(seed_weight, weight);
        let mut row_weight = weight;
        for row in 0..degree {
            let (source, sign) = rotation_for_degree(degree, recipient, row);
            sharing[source] = field::add(
                sharing[source],
                if sign < 0 {
                    field::subtract(ZERO, row_weight)
                } else {
                    row_weight
                },
            );
            row_weight = field::multiply(row_weight, alpha);
        }
        for component in 0..2 {
            if component == 1 {
                common_weights.extend([
                    (positive, weight),
                    (positive + 1, field::subtract(ZERO, weight)),
                ]);
            }
            let value = ciphertext_values[2 * recipient + component];
            target = field::add(target, field::multiply(weight, value));
            for (offset, coefficient) in [quotient, carry, ONE].into_iter().enumerate() {
                fixed_offset = field::add(
                    fixed_offset,
                    signed_weights(
                        &layout,
                        variable(recipient, component, offset),
                        field::multiply(weight, coefficient),
                        &mut fixed_weights,
                    ),
                );
            }
            weight = field::multiply(weight, equation_weight);
        }
    }
    // Form the centering constant as an integer before fingerprinting its
    // limbs: distributing digit extraction over the product would differ.
    let centering = fingerprint(&BigInt::from(SCALE * (radix / 2)), limb_weight);
    let mut sharing_weights = Vec::new();
    let sharing_offset = field::subtract(
        field::add(
            signed_weights(&layout, 0, signed(SCALE), &mut sharing_weights),
            signed_weights(
                &layout,
                1,
                field::scale(limb_weight, SCALE as u128),
                &mut sharing_weights,
            ),
        ),
        centering,
    );
    target = field::add(
        target,
        field::add(
            field::multiply(fixed_offset, sum),
            field::multiply(
                sharing_offset,
                sharing.iter().copied().fold(ZERO, field::add),
            ),
        ),
    );
    terms.extend([
        Term {
            public: PublicColumn::Values(common_adjoint),
            weights: common_weights,
        },
        Term {
            public: PublicColumn::Powers(degree),
            weights: fixed_weights,
        },
        Term {
            public: PublicColumn::Values(sharing),
            weights: sharing_weights,
        },
        Term {
            public: PublicColumn::Values(seed),
            weights: vec![(layout.seed, field::scale(seed_weight, SCALE as u128))],
        },
    ]);
    let mut supports = Vec::with_capacity(2 * RECIPIENTS);
    for recipient in 0..RECIPIENTS {
        for sign in 0..2 {
            supports.push((layout.relation.words + 2 * recipient + sign, weight));
            target = field::add(target, field::scale(weight, (SUPPORT / 2) as u128));
            weight = field::multiply(weight, alpha);
        }
    }
    terms.push(Term {
        public: PublicColumn::Ones(degree),
        weights: supports,
    });
    Operator {
        alpha,
        terms,
        target,
        lookup_weight: weight,
    }
}
