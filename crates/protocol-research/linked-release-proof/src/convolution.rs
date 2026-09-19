use crate::field::{self, MODULUS, Transform, base};
use num_bigint::BigInt;
use num_traits::{Signed, ToPrimitive};
use zeroize::Zeroizing;

pub fn signed_digit(value: &BigInt, limb: usize, bits: usize) -> i128 {
    let result = ((value.abs() >> (limb * bits)) & ((BigInt::from(1u32) << bits) - 1u32))
        .to_i128()
        .unwrap();
    if value.is_negative() { -result } else { result }
}
fn residue(value: i128) -> u128 {
    if value < 0 {
        MODULUS - value.unsigned_abs()
    } else {
        value as u128
    }
}
pub fn multiply_digits(
    public: &[BigInt],
    private: &[Vec<i128>],
    bits: usize,
    public_limbs: usize,
) -> Zeroizing<Vec<Vec<i128>>> {
    let degree = public.len();
    assert!(degree.is_power_of_two() && (2..=65536).contains(&degree));
    assert!((1..=48).contains(&bits));
    assert!((1..=4).contains(&public_limbs) && private.len() <= 3 && !private.is_empty());
    assert!(private.iter().all(|values| values.len() == degree));
    let bound = (degree as u128) * (private.len() as u128) * ((1u128 << bits) - 1).pow(2);
    assert!(bound < MODULUS / 2);
    assert!(
        private
            .iter()
            .flatten()
            .all(|value| value.unsigned_abs() < (1u128 << bits))
    );
    let transform = Transform::new(degree);
    let root = field::root(2 * degree);
    let inverse_root = base::power(root, MODULUS - 2);
    let mut twist = vec![1; degree];
    let mut inverse = vec![1; degree];
    for index in 1..degree {
        twist[index] = base::multiply(twist[index - 1], root);
        inverse[index] = base::multiply(inverse[index - 1], inverse_root);
    }
    let mut private_transforms = Zeroizing::new(Vec::with_capacity(private.len()));
    for values in private {
        let mut values: Vec<_> = values
            .iter()
            .zip(&twist)
            .map(|(value, twist)| base::multiply(residue(*value), *twist))
            .collect();
        transform.base(&mut values, false);
        private_transforms.push(values);
    }
    let mut products = Zeroizing::new(vec![vec![0u128; degree]; public_limbs + private.len() - 1]);
    for limb in 0..public_limbs {
        let mut public_values: Vec<_> = public
            .iter()
            .zip(&twist)
            .map(|(value, twist)| base::multiply(residue(signed_digit(value, limb, bits)), *twist))
            .collect();
        transform.base(&mut public_values, false);
        for (private_limb, values) in private_transforms.iter().enumerate() {
            for ((output, left), right) in products[limb + private_limb]
                .iter_mut()
                .zip(&public_values)
                .zip(values)
            {
                *output = base::add(*output, base::multiply(*left, *right));
            }
        }
    }
    let mut output = Zeroizing::new(Vec::with_capacity(products.len()));
    for values in products.iter_mut() {
        transform.base(values, true);
        output.push(
            values
                .iter()
                .zip(&inverse)
                .map(|(value, twist)| {
                    let value = base::multiply(*value, *twist);
                    let signed = if value > MODULUS / 2 {
                        -((MODULUS - value) as i128)
                    } else {
                        value as i128
                    };
                    assert!(signed.unsigned_abs() <= bound);
                    signed
                })
                .collect(),
        );
    }
    output
}
