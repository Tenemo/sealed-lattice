//! Selected entries from the original integer equations. This expands a
//! negacyclic product forward at one private coordinate; no adjoint,
//! recurrence, emitted term weights or witness constructor is used.
use crate::{
    Case, DEGREE, SEED_BITS, Sample,
    recipe::{Recipe, digit, modulus_digits},
};
use word_proof::field::{self, Element, ONE, ZERO};

pub struct Geometry {
    pub degree: usize,
    pub seed_bits: usize,
    pub alpha: Element,
}

pub fn power(mut value: Element, mut exponent: usize) -> Element {
    let mut result = ONE;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = field::multiply(result, value);
        }
        value = field::multiply(value, value);
        exponent >>= 1;
    }
    result
}
fn scaled(value: Element, scalar: i128) -> Element {
    let result = field::scale(value, scalar.unsigned_abs());
    if scalar < 0 {
        field::subtract(ZERO, result)
    } else {
        result
    }
}

pub struct Layout {
    pub widths: Vec<usize>,
    pub signed: Vec<Vec<(usize, u128)>>,
    pub words: usize,
    pub columns: usize,
}
impl Layout {
    pub fn new(case: Case) -> Self {
        let profile = supported_profile::Profile::new(4, 2).unwrap();
        let widths = match case {
            Case::Seed => {
                let mut widths = vec![96, profile.sharing_coefficient_bits() - 96];
                for _ in 0..4 {
                    widths.extend([16, profile.share_carry_bits(), 7, 16, 16, 7]);
                }
                widths
            }
            Case::Opening => vec![16, 16, 7, 16, 16, 17, 16, 16, 17],
        };
        let words = widths.iter().map(|bits| (bits / 16).max(1)).sum();
        let mut boolean = words + if case == Case::Seed { 9 } else { 2 };
        let mut word = 0;
        let signed = widths
            .iter()
            .map(|bits| {
                let whole = (bits / 16).max(1);
                let mut digits = Vec::new();
                for index in 0..whole {
                    digits.push((word, 1u128 << (16 * index)));
                    word += 1;
                }
                if *bits >= 16 {
                    for bit in 0..bits % 16 {
                        digits.push((boolean, 1u128 << (16 * whole + bit)));
                        boolean += 1;
                    }
                }
                digits
            })
            .collect();
        Self {
            widths,
            signed,
            words,
            columns: boolean,
        }
    }

    pub fn samples(&self, case: Case) -> Vec<Sample> {
        let mut coordinates = Vec::new();
        let first = |variable: usize| self.signed[variable][0].0;
        let last = |variable: usize| self.signed[variable].last().unwrap().0;
        match case {
            Case::Seed => {
                coordinates.extend([(first(0), 0), (last(0), DEGREE - 1), (first(1), DEGREE / 2)]);
                for (recipient, row) in [0, DEGREE / 4 - 1, DEGREE / 2, DEGREE - 1]
                    .into_iter()
                    .enumerate()
                {
                    coordinates.push((self.words + 2 * recipient, row));
                    coordinates.push((self.words + 2 * recipient + 1, DEGREE - 1 - row));
                }
                coordinates.extend([(first(2), 0), (last(3), DEGREE - 1), (first(4), DEGREE / 4)]);
                for row in [0, SEED_BITS - 1, SEED_BITS, DEGREE - 1] {
                    coordinates.push((self.words + 8, row));
                }
            }
            Case::Opening => {
                for row in [0, DEGREE / 2 - 1, DEGREE - 1] {
                    coordinates.push((self.words, row));
                }
                for row in [1, DEGREE / 2, DEGREE - 2] {
                    coordinates.push((self.words + 1, row));
                }
                coordinates.extend([
                    (first(0), 0),
                    (first(1), DEGREE - 1),
                    (first(2), DEGREE / 2),
                    (last(5), DEGREE / 4),
                    (last(8), DEGREE - 1),
                ]);
            }
        }
        coordinates
            .into_iter()
            .map(|(column, index)| Sample {
                column,
                index,
                value: ZERO,
            })
            .collect()
    }
}

fn convolution(
    recipe: &Recipe,
    case: Case,
    polynomial: usize,
    position: usize,
    row_start: usize,
    geometry: &Geometry,
) -> Element {
    let Geometry { degree, alpha, .. } = *geometry;
    let mut result = ZERO;
    for limb in 0..2 {
        let mut weight = power(alpha, row_start + limb * degree + position);
        for public_row in 0..degree {
            if public_row + position == degree {
                weight = power(alpha, row_start + limb * degree);
            }
            let sign = if public_row + position < degree {
                1
            } else {
                -1
            };
            let coefficient = digit(&recipe.coefficient(case, polynomial, public_row), limb);
            result = field::add(result, scaled(weight, sign * coefficient));
            weight = field::multiply(weight, alpha);
        }
    }
    result
}

pub fn coefficient(
    recipe: &Recipe,
    case: Case,
    layout: &Layout,
    geometry: &Geometry,
    column: usize,
    row: usize,
) -> Element {
    let Geometry {
        degree,
        seed_bits,
        alpha,
    } = *geometry;
    let scale = supported_profile::SHARE_SCALE as i128;
    for (variable, encoding) in layout.signed.iter().enumerate() {
        if let Some((_, place)) = encoding.iter().find(|(candidate, _)| *candidate == column) {
            let mut result = ZERO;
            if case == Case::Seed && variable < 2 {
                for recipient in 0..4 {
                    let destination = row + recipient * (degree / 2);
                    let sign = if (destination / degree).is_multiple_of(2) {
                        1
                    } else {
                        -1
                    };
                    result = field::add(
                        result,
                        scaled(
                            power(
                                alpha,
                                (4 * recipient + variable) * degree + destination % degree,
                            ),
                            sign * scale,
                        ),
                    );
                }
            } else {
                let (equation, offset) = if case == Case::Seed {
                    ((variable - 2) / 3, (variable - 2) % 3)
                } else {
                    (variable / 3, variable % 3)
                };
                let low = power(alpha, 2 * equation * degree + row);
                let high = power(alpha, (2 * equation + 1) * degree + row);
                result = match offset {
                    0 => {
                        let digits = modulus_digits();
                        field::add(scaled(low, -digits[0]), scaled(high, -digits[1]))
                    }
                    1 => field::add(scaled(low, -(1i128 << 96)), high),
                    _ => scaled(low, if case == Case::Seed { 1 } else { -1 }),
                };
            }
            return field::scale(result, *place);
        }
    }
    if case == Case::Seed && column == layout.words + 8 {
        if row >= seed_bits {
            return ZERO;
        }
        return (0..4).fold(ZERO, |value, recipient| {
            field::add(
                value,
                scaled(power(alpha, 4 * recipient * degree + row), scale),
            )
        });
    }
    let support = column - layout.words;
    let negative = support % 2 == 1;
    let mut result = ZERO;
    match case {
        Case::Seed => {
            let recipient = support / 2;
            for (component, polynomial) in [1 + 3 * recipient, 0].into_iter().enumerate() {
                result = field::add(
                    result,
                    convolution(
                        recipe,
                        case,
                        polynomial,
                        row,
                        (4 * recipient + 2 * component) * degree,
                        geometry,
                    ),
                );
            }
        }
        Case::Opening => {
            for (equation, polynomial) in [0, 2, 4].into_iter().enumerate() {
                result = field::add(
                    result,
                    convolution(
                        recipe,
                        case,
                        polynomial,
                        row,
                        2 * equation * degree,
                        geometry,
                    ),
                );
            }
        }
    }
    if negative {
        result = field::subtract(ZERO, result);
    }
    let equation_rows = if case == Case::Seed {
        16 * degree
    } else {
        6 * degree
    };
    field::add(result, power(alpha, equation_rows + support))
}

/// Zero encoded columns represent each signed variable's negative bias.
/// Evaluating those literal residuals gives the negative affine target.
pub fn target(
    recipe: &Recipe,
    case: Case,
    layout: &Layout,
    geometry: &Geometry,
) -> (Element, Element) {
    let Geometry { degree, alpha, .. } = *geometry;
    let q = modulus_digits();
    let radix = 1i128 << 96;
    let scale = supported_profile::SHARE_SCALE as i128;
    let zero: Vec<i128> = layout
        .widths
        .iter()
        .map(|bits| -(1i128 << (bits - 1)))
        .collect();
    let equations = if case == Case::Seed { 8 } else { 3 };
    let mut weight = ONE;
    let mut residual = ZERO;
    for equation in 0..equations {
        let (polynomial, first) = if case == Case::Seed {
            (2 + 3 * (equation / 2) + equation % 2, 2 + 3 * equation)
        } else {
            (1 + 2 * equation, 3 * equation)
        };
        for (limb, modulus_digit) in q.into_iter().enumerate() {
            for row in 0..degree {
                let constant = digit(&recipe.coefficient(case, polynomial, row), limb);
                // Reduce each literal integer term through the field map.
                // A radix times a signed carry bias can exceed i128 even
                // when later residual terms cancel most of that value.
                let mut value = scaled(
                    weight,
                    if case == Case::Seed {
                        -constant
                    } else {
                        constant
                    },
                );
                value = field::subtract(value, scaled(scaled(weight, modulus_digit), zero[first]));
                if limb == 0 {
                    value = field::subtract(value, scaled(scaled(weight, radix), zero[first + 1]));
                    value = field::add(
                        value,
                        scaled(
                            weight,
                            if case == Case::Seed {
                                zero[first + 2]
                            } else {
                                -zero[first + 2]
                            },
                        ),
                    );
                } else {
                    value = field::add(value, scaled(weight, zero[first + 1]));
                }
                if case == Case::Seed && equation % 2 == 0 {
                    let exponent = (equation / 2) * (degree / 2);
                    let source = (row + 2 * degree - exponent) % degree;
                    let sign = if ((source + exponent) / degree).is_multiple_of(2) {
                        1
                    } else {
                        -1
                    };
                    let center = scale * (radix / 2);
                    let center_digit = if limb == 0 {
                        center % radix
                    } else {
                        center / radix
                    };
                    value = field::add(value, scaled(scaled(weight, sign * scale), zero[limb]));
                    value = field::add(value, scaled(weight, sign * center_digit));
                }
                residual = field::add(residual, value);
                weight = field::multiply(weight, alpha);
            }
        }
    }
    let supports = if case == Case::Seed { 8 } else { 2 };
    let support = if case == Case::Seed {
        supported_profile::SHARE_EPHEMERAL_SUPPORT
    } else {
        supported_profile::RECIPIENT_SECRET_SUPPORT
    };
    for _ in 0..supports {
        residual = field::add(residual, scaled(weight, -(support as i128 / 2)));
        weight = field::multiply(weight, alpha);
    }
    (field::subtract(ZERO, residual), weight)
}
