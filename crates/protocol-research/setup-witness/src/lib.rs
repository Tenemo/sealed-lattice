pub mod contribution;
mod convolution;
mod gaussian;
mod reduction;
pub mod registration;
use convolution::{Plan, RADIX_BITS, digit, digit_in};
use num_bigint::{BigInt, Sign};
use num_traits::Signed;
use sha3::digest::XofReader;
#[path = "common-polynomial.rs"]
mod common_polynomial;
use common_polynomial::{public_polynomial, public_records};
pub use supported_profile::Profile;
use supported_profile::{
    AUXILIARY_DEGREE, DEGREE, SETUP_ERROR_BITS, SETUP_FHE_CARRY_BITS, SETUP_QUOTIENT_BITS,
};
use zeroize::{Zeroize, Zeroizing};

const SCALE: i128 = supported_profile::SHARE_SCALE as i128;

/// The jobs this crate defines.
pub static JOBS: [&parallel_work::Job; 1] = [&contribution::COMMON_RECORDS];

fn errors(label: &str, degree: usize) -> Vec<i128> {
    let mut random = private_reader(label);
    (0..degree)
        .map(|_| {
            let mut bytes = Zeroizing::new([0; 20]);
            random.read(bytes.as_mut());
            gaussian::sample(&bytes)
        })
        .collect()
}
fn sparse_values(label: &str, degree: usize, support: usize) -> Vec<i8> {
    assert!(degree.is_power_of_two() && support.is_multiple_of(2) && support <= degree);
    let mut random = private_reader(label);
    let mut values = vec![0; degree];
    let mut selected = 0;
    while selected < support {
        let mut bytes = [0; 4];
        random.read(&mut bytes);
        let position = u32::from_le_bytes(bytes) as usize % degree;
        if values[position] == 0 {
            values[position] = if selected < support / 2 { 1 } else { -1 };
            selected += 1;
        }
    }
    values
}
fn integer(bytes: &[u8]) -> BigInt {
    BigInt::from_bytes_le(Sign::Plus, bytes)
}
struct Sparse {
    values: Zeroizing<Vec<i8>>,
    transform: Zeroizing<Vec<u128>>,
}
struct Witness {
    words: Vec<Vec<u16>>,
    booleans: Vec<Vec<u16>>,
}
impl Witness {
    fn new() -> Self {
        Self {
            words: Vec::new(),
            booleans: Vec::new(),
        }
    }
    fn sparse(&mut self, label: &str, degree: usize, support: usize, plan: &Plan) -> Sparse {
        let values = Zeroizing::new(sparse_values(label, degree, support));
        let stride = DEGREE / degree;
        for sign in [1, -1] {
            let mut column = vec![0; DEGREE];
            for (position, value) in values.iter().enumerate() {
                column[position * stride] = u16::from(*value == sign);
            }
            self.booleans.push(column);
        }
        let transform = Zeroizing::new(plan.sparse_transform(&values));
        Sparse { values, transform }
    }
    fn signed(&mut self, width: usize, values: &[i128]) {
        assert!(width > 0 && width < 127 && DEGREE.is_multiple_of(values.len()));
        let offset = 1i128 << (width - 1);
        let stride = DEGREE / values.len();
        assert!(
            values
                .iter()
                .all(|value| *value >= -offset && *value < offset)
        );
        let mut remaining = width;
        let mut shift = 0;
        while remaining >= 16 || shift == 0 {
            let bits = remaining.min(16);
            let mut column = vec![0; DEGREE];
            for (position, value) in values.iter().enumerate() {
                column[position * stride] =
                    (((value + offset) as u128 >> shift) & ((1u128 << bits) - 1)) as u16;
            }
            self.words.push(column);
            remaining -= bits;
            shift += bits;
        }
        for bit in 0..remaining {
            let mut column = vec![0; DEGREE];
            for (position, value) in values.iter().enumerate() {
                column[position * stride] =
                    (((value + offset) as u128 >> (shift + bit)) & 1) as u16;
            }
            self.booleans.push(column);
        }
    }
}
pub trait PolynomialOutput {
    fn polynomial(&mut self, values: &[BigInt], modulus: &BigInt, width: usize);
}
impl Drop for Witness {
    fn drop(&mut self) {
        self.words.zeroize();
        self.booleans.zeroize();
    }
}

fn transformed(values: &[i8], automorphism: usize) -> Vec<i8> {
    let mut result = vec![0; values.len()];
    for (position, value) in values.iter().enumerate() {
        let exponent = position * automorphism;
        result[exponent % values.len()] = if (exponent / values.len()).is_multiple_of(2) {
            *value
        } else {
            -*value
        };
    }
    result
}

struct KeyInput<'a> {
    label: &'a str,
    common: &'a [BigInt],
    left: &'a Sparse,
    right: &'a [i8],
    multiplier: BigInt,
    automorphism: usize,
    modulus: &'a BigInt,
    limbs: usize,
    width: usize,
}
fn key(
    witness: &mut Witness,
    output: &mut impl PolynomialOutput,
    plan: &Plan,
    input: KeyInput<'_>,
) {
    let degree = input.common.len();
    let products = Zeroizing::new(plan.digit_products(
        input.common,
        &input.left.values,
        &input.left.transform,
        input.limbs,
        RADIX_BITS,
    ));
    let error = Zeroizing::new(errors(input.label, degree));
    let transformed = Zeroizing::new(transformed(input.right, input.automorphism));
    let modulus = reduction::Modulus::new(&input.modulus.to_bytes_le().1, RADIX_BITS).unwrap();
    let direct: Vec<i128> = (0..input.limbs)
        .map(|limb| digit(&input.multiplier, limb))
        .collect();
    let mut values = Vec::with_capacity(degree);
    let mut quotients = Zeroizing::new(Vec::with_capacity(degree));
    for position in 0..degree {
        let mut raw = Zeroizing::new([0i128; reduction::MAXIMUM_LIMBS]);
        for limb in 0..input.limbs {
            raw[limb] = -products[limb][position]
                + direct[limb] * i128::from(transformed[position])
                + if limb == 0 { error[position] } else { 0 };
        }
        let mut reduced = [0u128; reduction::MAXIMUM_LIMBS];
        let result = modulus
            .reduce(&raw[..input.limbs], &mut reduced[..input.limbs])
            .unwrap();
        let magnitude = reduced[..input.limbs]
            .iter()
            .rev()
            .fold(BigInt::from(0), |sum, value| {
                (sum << RADIX_BITS) + BigInt::from(*value)
            });
        let value = if result.negative {
            -magnitude
        } else {
            magnitude
        };
        quotients.push(-result.quotient);
        values.push(value);
    }
    let mut carries = Zeroizing::new(vec![vec![0i128; degree]; input.limbs - 1]);
    for position in 0..degree {
        let mut carry = 0;
        for limb in 0..input.limbs {
            let row = products[limb][position] + digit(&values[position], limb)
                - digit(&input.multiplier, limb) * i128::from(transformed[position])
                - if limb == 0 { error[position] } else { 0 }
                - digit(input.modulus, limb) * quotients[position]
                + carry;
            if limb + 1 < input.limbs {
                assert_eq!(row % convolution::RADIX, 0);
                carry = row / convolution::RADIX;
                carries[limb][position] = carry;
            } else {
                assert_eq!(row, 0, "final key carry at {position}");
            }
        }
    }
    witness.signed(SETUP_QUOTIENT_BITS, &quotients);
    for carry in carries.iter() {
        witness.signed(SETUP_FHE_CARRY_BITS, carry);
    }
    witness.signed(SETUP_ERROR_BITS, &error);
    output.polynomial(&values, input.modulus, input.width);
    #[cfg(not(target_arch = "wasm32"))]
    println!("Generated {}", input.label);
}

struct ShareInput<'a> {
    profile: Profile,
    recipient: usize,
    common: &'a [BigInt],
    public_key: &'a [BigInt],
    secret: &'a Sparse,
    sharing: &'a [Vec<i128>],
    ephemeral: &'a Sparse,
    modulus: &'a BigInt,
}
// Share equations use the profile's share limb for every digit, including
// the sharing coefficients' low and high parts.
fn share_ciphertexts(
    witness: &mut Witness,
    output: &mut impl PolynomialOutput,
    plan: &Plan,
    input: ShareInput<'_>,
) -> Vec<Vec<BigInt>> {
    let ShareInput {
        profile,
        recipient,
        common,
        public_key,
        secret,
        sharing,
        ephemeral,
        modulus,
    } = input;
    let radix_bits = profile.share_limb_bits();
    let radix = 1i128 << radix_bits;
    let point = recipient * profile.point_stride();
    let mut message = Zeroizing::new(
        secret
            .values
            .iter()
            .map(|value| i128::from(*value))
            .collect::<Vec<i128>>(),
    );
    let mut low_sum = Zeroizing::new(vec![0i128; DEGREE]);
    let mut high_sum = Zeroizing::new(vec![0i128; DEGREE]);
    let mut offset = vec![0i128; DEGREE];
    for (coefficient, values) in sharing.iter().enumerate() {
        for (input, value) in values.iter().enumerate() {
            let exponent = input + point * (coefficient + 1);
            let position = exponent % DEGREE;
            let sign = if (exponent / DEGREE).is_multiple_of(2) {
                1
            } else {
                -1
            };
            message[position] += sign * value;
            low_sum[position] += sign * (value.rem_euclid(radix) - radix / 2);
            high_sum[position] += sign * value.div_euclid(radix);
            offset[position] += sign * SCALE * (radix / 2);
        }
    }
    let mut ciphertexts = Vec::new();
    let reduction = reduction::Modulus::new(&modulus.to_bytes_le().1, radix_bits).unwrap();
    let width = supported_profile::share_modulus().len();
    for (component, common) in [public_key, common].into_iter().enumerate() {
        let products = Zeroizing::new(plan.digit_products(
            common,
            &ephemeral.values,
            &ephemeral.transform,
            2,
            radix_bits,
        ));
        let error = Zeroizing::new(errors(
            &format!("share-{recipient}-{component}-error"),
            DEGREE,
        ));
        let mut values = Vec::with_capacity(DEGREE);
        let mut quotients = Zeroizing::new(Vec::with_capacity(DEGREE));
        for position in 0..DEGREE {
            let mut raw = Zeroizing::new([
                products[0][position] + error[position],
                products[1][position],
            ]);
            if component == 0 {
                raw[0] += SCALE * (message[position] % radix);
                raw[1] += SCALE * (message[position] / radix);
            }
            let mut digits = [0; 2];
            let reduced = reduction.reduce(raw.as_ref(), &mut digits).unwrap();
            let magnitude = (BigInt::from(digits[1]) << radix_bits) + BigInt::from(digits[0]);
            let value = if reduced.negative {
                -magnitude
            } else {
                magnitude
            };
            quotients.push(reduced.quotient);
            values.push(value);
        }
        let mut carries = Zeroizing::new(vec![0i128; DEGREE]);
        for position in 0..DEGREE {
            let mut carry = 0;
            for (limb, product) in products.iter().enumerate() {
                let shared = if component == 0 {
                    digit_in(&BigInt::from(offset[position]), limb, radix_bits)
                        + SCALE
                            * if limb == 0 {
                                low_sum[position] + i128::from(secret.values[position])
                            } else {
                                high_sum[position]
                            }
                } else {
                    0
                };
                let row = product[position] - digit_in(&values[position], limb, radix_bits)
                    + shared
                    + if limb == 0 { error[position] } else { 0 }
                    - digit_in(modulus, limb, radix_bits) * quotients[position]
                    + carry;
                if limb == 0 {
                    assert_eq!(row % radix, 0);
                    carry = row / radix;
                    carries[position] = carry;
                } else {
                    assert_eq!(row, 0, "final share carry at {position}");
                }
            }
        }
        witness.signed(SETUP_QUOTIENT_BITS, &quotients);
        witness.signed(
            if component == 0 {
                profile.share_carry_bits()
            } else {
                SETUP_FHE_CARRY_BITS
            },
            &carries,
        );
        witness.signed(SETUP_ERROR_BITS, &error);
        output.polynomial(&values, modulus, width);
        ciphertexts.push(values);
    }
    #[cfg(not(target_arch = "wasm32"))]
    println!("Generated encrypted share {recipient}");
    ciphertexts
}

#[cfg(not(target_arch = "wasm32"))]
fn private_reader(_label: &str) -> impl XofReader + use<> {
    struct NativeRandom;
    impl XofReader for NativeRandom {
        fn read(&mut self, bytes: &mut [u8]) {
            getrandom::fill(bytes).expect("OS private entropy unavailable");
        }
    }
    NativeRandom
}
#[cfg(target_arch = "wasm32")]
mod browser_random;
#[cfg(target_arch = "wasm32")]
fn private_reader(_label: &str) -> impl XofReader + use<> {
    browser_random::Reader::new()
}
