use crate::{
    field::{self, Element, MODULUS, ONE, Transform, ZERO, base},
    oracles::{FirstOracle, SecondOracle, Witness, extension_values},
    parameters::*,
};
use setup_stream_kernel::{PolynomialStream, prover_operator_plan};
use std::{collections::BTreeMap, fs::File, io::Read, path::Path};
use zeroize::Zeroizing;

fn combined_witness(
    witness: &Witness,
    first: &FirstOracle,
    columns: &[(usize, Element)],
    transform: &Transform,
) -> Vec<Element> {
    let mut values = Zeroizing::new(vec![ZERO; SYSTEMATIC]);
    let mut masks = Zeroizing::new(vec![ZERO; MASKS]);
    for (column, weight) in columns {
        for (value, raw) in values.iter_mut().zip(&witness.columns[*column]) {
            if *raw != 0 {
                *value = field::add(*value, field::scale(*weight, u128::from(*raw)));
            }
        }
        for (value, mask) in masks.iter_mut().zip(&first.masks[*column]) {
            *value = field::add(*value, field::scale(*weight, *mask));
        }
    }
    transform.extension(&mut values, true);
    for (index, mask) in masks.iter().enumerate() {
        values[index] = field::subtract(values[index], *mask);
    }
    values.extend_from_slice(&masks);
    std::mem::take(&mut *values)
}
fn embed(mut values: Vec<Element>) -> Vec<Element> {
    let degree = values.len();
    Transform::new(degree).extension(&mut values, true);
    let stride = SYSTEMATIC / degree;
    let inverse = base::power(stride as u128, MODULUS - 2);
    let mut coefficients = vec![ZERO; SYSTEMATIC];
    for (block, value) in coefficients.iter_mut().enumerate() {
        *value = field::scale(values[block % degree], inverse);
    }
    coefficients
}
fn geometric(
    alpha: Element,
    degree: usize,
    automorphism: usize,
    shift: usize,
    constant: bool,
) -> Vec<Element> {
    if constant {
        return embed(vec![ONE; degree]);
    }
    let mut powers = Vec::with_capacity(degree);
    let mut current = ONE;
    for _ in 0..degree {
        powers.push(current);
        current = field::multiply(current, alpha);
    }
    embed(
        (0..degree)
            .map(|index| {
                let exponent = (index * automorphism + shift) % (2 * degree);
                if exponent < degree {
                    powers[exponent % degree]
                } else {
                    field::subtract(ZERO, powers[exponent % degree])
                }
            })
            .collect(),
    )
}
fn add_product(output: &mut [Element], left: &[Element], right: &[Element], transform: &Transform) {
    for coset in 0..4 {
        let twist = base::multiply(7, base::power(field::root(DOMAIN), coset as u128));
        let left = extension_values(left, twist, transform);
        let right = Zeroizing::new(extension_values(right, twist, transform));
        for (index, (left, right)) in left.into_iter().zip(right.iter()).enumerate() {
            output[coset + 4 * index] =
                field::add(output[coset + 4 * index], field::multiply(left, *right));
        }
    }
}
pub use crate::linear_oracle::LinearOracle;
pub struct Challenges {
    pub alpha: Element,
    pub mask: Element,
}
pub enum PreparedPolynomial {
    Value(Element),
    Adjoint(Vec<Element>),
}
impl LinearOracle {
    pub fn create(
        directory: &Path,
        role: &[u8],
        witness: &Witness,
        first: &FirstOracle,
        second: &SecondOracle,
        challenges: Challenges,
        adversarial_affine: bool,
    ) -> Self {
        let plan = prover_operator_plan(challenges.alpha).unwrap();
        let alpha = challenges.alpha;
        let polynomials = (0..75).map(|index| {
            let family = if index < 42 {
                0
            } else if index < 73 {
                1
            } else {
                2
            };
            let mut parser = PolynomialStream::new(family, alpha).unwrap();
            let mut file =
                File::open(directory.join(format!("polynomial-{index:02}.bin"))).unwrap();
            let mut buffer = vec![0; 1 << 20];
            loop {
                let length = file.read(&mut buffer).unwrap();
                if length == 0 {
                    break;
                }
                parser.push(&buffer[..length]).unwrap();
            }
            if plan.common_columns[index].is_empty() {
                PreparedPolynomial::Value(parser.finish_value().unwrap())
            } else {
                PreparedPolynomial::Adjoint(parser.adjoint().unwrap())
            }
        });
        Self::create_prepared(
            role,
            witness,
            first,
            second,
            challenges,
            adversarial_affine,
            polynomials,
        )
    }
    pub fn create_prepared(
        role: &[u8],
        witness: &Witness,
        first: &FirstOracle,
        second: &SecondOracle,
        challenges: Challenges,
        adversarial_affine: bool,
        mut polynomials: impl Iterator<Item = PreparedPolynomial>,
    ) -> Self {
        let Challenges {
            alpha,
            mask: mask_challenge,
        } = challenges;
        let plan = prover_operator_plan(alpha).unwrap();
        let mut target = plan.target_offset;
        let mut evaluations = Zeroizing::new(vec![ZERO; DOMAIN]);
        let transform = Transform::new(SYSTEMATIC);
        let mut groups: BTreeMap<(usize, usize, usize, bool), Vec<Element>> = BTreeMap::new();
        for term in &plan.fixed_terms {
            let group = groups
                .entry((term.degree, term.automorphism, term.shift, term.constant))
                .or_insert_with(|| vec![ZERO; COLUMNS]);
            for (column, weight) in &term.columns {
                group[*column] = field::add(group[*column], *weight);
            }
        }
        for ((degree, automorphism, shift, constant), weights) in groups {
            let columns: Vec<_> = weights
                .into_iter()
                .enumerate()
                .filter(|(_, weight)| *weight != ZERO)
                .collect();
            if columns.is_empty() {
                continue;
            }
            let variable = Zeroizing::new(combined_witness(witness, first, &columns, &transform));
            let coefficient = geometric(alpha, degree, automorphism, shift, constant);
            add_product(&mut evaluations, &coefficient, &variable, &transform);
        }
        #[cfg(not(target_arch = "wasm32"))]
        println!("Accumulated fixed affine bases");
        for index in 0..75 {
            let polynomial = polynomials.next().unwrap();
            if plan.common_columns[index].is_empty() {
                let PreparedPolynomial::Value(value) = polynomial else {
                    panic!("Expected public value");
                };
                target = field::subtract(target, field::multiply(plan.value_weights[index], value));
            } else {
                let PreparedPolynomial::Adjoint(values) = polynomial else {
                    panic!("Expected public adjoint");
                };
                let coefficient = embed(values);
                let variable = Zeroizing::new(combined_witness(
                    witness,
                    first,
                    &plan.common_columns[index],
                    &transform,
                ));
                add_product(&mut evaluations, &coefficient, &variable, &transform);
            }
            if index % 14 == 0 {
                #[cfg(not(target_arch = "wasm32"))]
                println!("Accumulated public polynomial {index}");
            }
        }
        assert!(polynomials.next().is_none());
        for coset in 0..4 {
            let twist = base::multiply(7, base::power(field::root(DOMAIN), coset as u128));
            let lookup = Zeroizing::new(extension_values(
                &second.lookup_coefficients,
                twist,
                &transform,
            ));
            let mask = Zeroizing::new(extension_values(&second.sum_mask, twist, &transform));
            for (index, (lookup, mask)) in lookup.iter().zip(mask.iter()).enumerate() {
                let position = coset + 4 * index;
                let linear = field::add(
                    evaluations[position],
                    field::multiply(plan.lookup_weight, *lookup),
                );
                evaluations[position] = field::add(field::multiply(mask_challenge, linear), *mask);
            }
        }
        Self::from_evaluations(
            role,
            std::mem::take(&mut *evaluations),
            target,
            plan.lookup_weight,
            mask_challenge,
            second.mask_sum,
            adversarial_affine,
        )
    }
}
