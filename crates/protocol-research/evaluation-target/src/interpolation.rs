#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Fraction {
    numerator: i128,
    denominator: i128,
}
impl Fraction {
    const ZERO: Self = Self {
        numerator: 0,
        denominator: 1,
    };
    const ONE: Self = Self {
        numerator: 1,
        denominator: 1,
    };
    fn new(numerator: i128, denominator: i128) -> Self {
        assert_ne!(denominator, 0);
        let sign = if denominator < 0 { -1 } else { 1 };
        let mut left = numerator.abs();
        let mut right = denominator.abs();
        while right != 0 {
            (left, right) = (right, left % right);
        }
        Self {
            numerator: sign * numerator / left,
            denominator: denominator.abs() / left,
        }
    }
    fn add(self, other: Self) -> Self {
        Self::new(
            self.numerator
                .checked_mul(other.denominator)
                .unwrap()
                .checked_add(other.numerator.checked_mul(self.denominator).unwrap())
                .unwrap(),
            self.denominator.checked_mul(other.denominator).unwrap(),
        )
    }
    fn negative(self) -> Self {
        Self {
            numerator: -self.numerator,
            ..self
        }
    }
    fn multiply(self, other: Self) -> Self {
        Self::new(
            self.numerator.checked_mul(other.numerator).unwrap(),
            self.denominator.checked_mul(other.denominator).unwrap(),
        )
    }
    fn inverse(self) -> Self {
        Self::new(self.denominator, self.numerator)
    }
}
type Ring = [Fraction; 8];
fn monomial(exponent: usize) -> Ring {
    let mut value = [Fraction::ZERO; 8];
    value[exponent % 8] = Fraction::new(if exponent % 16 >= 8 { -1 } else { 1 }, 1);
    value
}
fn product(left: &Ring, right: &Ring) -> Ring {
    let mut result = [Fraction::ZERO; 8];
    for (i, a) in left.iter().enumerate() {
        for (j, b) in right.iter().enumerate() {
            let term = a.multiply(*b);
            result[(i + j) % 8] =
                result[(i + j) % 8].add(if i + j >= 8 { term.negative() } else { term });
        }
    }
    result
}
fn inverse(value: &Ring) -> Ring {
    let columns: [Ring; 8] = std::array::from_fn(|column| product(value, &monomial(column)));
    let mut rows: [[Fraction; 9]; 8] = std::array::from_fn(|row| {
        std::array::from_fn(|column| {
            if column < 8 {
                columns[column][row]
            } else if row == 0 {
                Fraction::ONE
            } else {
                Fraction::ZERO
            }
        })
    });
    for column in 0..8 {
        let pivot = (column..8)
            .find(|row| rows[*row][column].numerator != 0)
            .expect("Distinct interpolation points are units");
        rows.swap(column, pivot);
        let scale = rows[column][column].inverse();
        for value in &mut rows[column] {
            *value = value.multiply(scale);
        }
        let pivot = rows[column];
        for (row, values) in rows.iter_mut().enumerate() {
            if row != column {
                let scale = values[column];
                for (value, coefficient) in values.iter_mut().zip(pivot) {
                    *value = value.add(scale.multiply(coefficient).negative());
                }
            }
        }
    }
    std::array::from_fn(|index| rows[index][8])
}

/// Four times the exact zero-interpolation weights in Z[X]/(X^8+1).
/// The caller lifts X to X^(65536/8) in the actual ciphertext ring.
pub(crate) fn cleared_weights(positions: [usize; 4]) -> Result<[[i128; 8]; 4], ()> {
    if positions.iter().any(|position| *position >= 10)
        || positions.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(());
    }
    let points = positions.map(monomial);
    Ok(std::array::from_fn(|selected| {
        let mut numerator = monomial(0);
        let mut denominator = monomial(0);
        for other in 0..4 {
            if other == selected {
                continue;
            }
            numerator = product(&numerator, &points[other].map(Fraction::negative));
            denominator = product(
                &denominator,
                &std::array::from_fn(|index| {
                    points[selected][index].add(points[other][index].negative())
                }),
            );
        }
        product(&numerator, &inverse(&denominator)).map(|value| {
            let scaled = value.multiply(Fraction::new(4, 1));
            assert_eq!(
                scaled.denominator, 1,
                "The selected profile requires the original denominator clearing factor"
            );
            scaled.numerator
        })
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_actual_release_subset_reconstructs_all_sharing_basis_terms() {
        let mut subsets = 0;
        for a in 0..10 {
            for b in a + 1..10 {
                for c in b + 1..10 {
                    for d in c + 1..10 {
                        let positions = [a, b, c, d];
                        let weights = cleared_weights(positions).unwrap();
                        for power in 0..4 {
                            let mut sum = [0i128; 8];
                            for (position, weight) in positions.iter().zip(weights) {
                                for (coefficient, value) in weight.into_iter().enumerate() {
                                    let exponent = coefficient + position * power;
                                    sum[exponent % 8] += if (exponent / 8) % 2 == 0 {
                                        value
                                    } else {
                                        -value
                                    };
                                }
                            }
                            let mut expected = [0i128; 8];
                            if power == 0 {
                                expected[0] = 4;
                            }
                            assert_eq!(sum, expected);
                        }
                        subsets += 1;
                    }
                }
            }
        }
        assert_eq!(subsets, 210);
        assert!(cleared_weights([0, 0, 1, 2]).is_err());
        assert!(cleared_weights([0, 1, 2, 10]).is_err());
    }
}
