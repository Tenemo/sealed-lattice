pub mod contribution;
mod convolution;
mod gaussian;
mod reduction;
pub mod registration;
use convolution::{Plan, RADIX_BITS, digit, digit_in};
use num_bigint::{BigInt, BigUint, Sign};
use num_traits::Signed;
use parallel_work::{Job, Part, Ticket, share, submit};
use sha3::digest::XofReader;
use std::{cell::RefCell, collections::BTreeMap, rc::Rc};
#[path = "common-polynomial.rs"]
mod common_polynomial;
use common_polynomial::{public_polynomial, public_records};
#[path = "proth-common-polynomial.rs"]
mod proth_common_polynomial;
use proth_common_polynomial::{proth_public_polynomial, proth_public_records};
pub use supported_profile::Profile;
use supported_profile::{
    AUXILIARY_DEGREE, DEGREE, SETUP_ERROR_BITS, SETUP_FHE_CARRY_BITS, SETUP_QUOTIENT_BITS,
};
use zeroize::{Zeroize, Zeroizing};

const SCALE: i128 = supported_profile::SHARE_SCALE as i128;

/// The jobs this crate defines.
pub static JOBS: [&Job; 2] = [&contribution::COMMON_RECORDS, &CONVOLUTION];

/// One limb's centered products of a public polynomial with a sparse
/// secret. Its input is the ring degree, the limb's signed digits and the
/// secret's transform.
pub static CONVOLUTION: Job = Job {
    kind: 0x0501,
    run: convolve,
};
thread_local! {
    // Each ring degree's transform tables, built once where its jobs run.
    static PLANS: RefCell<BTreeMap<usize, Rc<Plan>>> = RefCell::default();
}
fn convolve(input: &[u8]) -> Vec<u8> {
    let degree = u32::from_le_bytes(input[..4].try_into().unwrap()) as usize;
    let (digits, transformed) = input[4..].split_at(16 * degree);
    assert_eq!(transformed.len(), 16 * degree);
    let plan = PLANS.with(|plans| {
        plans
            .borrow_mut()
            .entry(degree)
            .or_insert_with(|| Rc::new(Plan::new(degree)))
            .clone()
    });
    let products = Zeroizing::new(
        plan.limb_products(
            digits
                .chunks_exact(16)
                .map(|bytes| i128::from_le_bytes(bytes.try_into().unwrap())),
            transformed
                .chunks_exact(16)
                .map(|bytes| u128::from_le_bytes(bytes.try_into().unwrap())),
        ),
    );
    let mut output = Vec::with_capacity(16 * degree);
    for value in products.iter() {
        output.extend_from_slice(&value.to_le_bytes());
    }
    output
}
/// The digit products of a public polynomial with a sparse secret, whose
/// limbs' jobs run while the caller continues. Native builds check the
/// products against the public polynomial and a zeroized copy of the secret.
struct Products {
    tickets: Vec<Ticket>,
    #[cfg(not(target_arch = "wasm32"))]
    check: (Vec<BigInt>, Zeroizing<Vec<i8>>, usize),
}
impl Products {
    fn start(public: &[BigInt], secret: &Sparse, limbs: usize, radix_bits: usize) -> Self {
        let degree = public.len();
        assert_eq!(secret.values.len(), degree);
        convolution::check_support(&secret.values, radix_bits);
        let mut transform = Zeroizing::new(Vec::with_capacity(16 * degree));
        for value in secret.transform.iter() {
            transform.extend(value.to_le_bytes());
        }
        let transform = share(transform);
        let header = (degree as u32).to_le_bytes();
        let tickets = (0..limbs)
            .map(|limb| {
                let mut digits = Vec::with_capacity(16 * degree);
                for value in public {
                    digits.extend_from_slice(&digit_in(value, limb, radix_bits).to_le_bytes());
                }
                submit(
                    &CONVOLUTION,
                    None,
                    &[
                        Part::Bytes(&header),
                        Part::Bytes(&digits),
                        Part::Shared(&transform),
                    ],
                    16 * degree,
                )
            })
            .collect();
        Self {
            tickets,
            #[cfg(not(target_arch = "wasm32"))]
            check: (
                public.to_vec(),
                Zeroizing::new(secret.values.to_vec()),
                radix_bits,
            ),
        }
    }
    fn wait(self) -> Zeroizing<Vec<Vec<i128>>> {
        let products = Zeroizing::new(
            self.tickets
                .into_iter()
                .map(|ticket| {
                    ticket
                        .wait()
                        .chunks_exact(16)
                        .map(|bytes| i128::from_le_bytes(bytes.try_into().unwrap()))
                        .collect()
                })
                .collect::<Vec<Vec<i128>>>(),
        );
        #[cfg(not(target_arch = "wasm32"))]
        {
            let (public, sparse, radix_bits) = &self.check;
            convolution::check_products(public, sparse, &products, *radix_bits);
        }
        products
    }
}

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
/// The integer of the sign and the little-endian digits of `radix_bits`
/// bits each.
fn from_digits(digits: &[u128], radix_bits: usize, negative: bool) -> BigInt {
    let mut words = Vec::with_capacity((digits.len() * radix_bits).div_ceil(32) + 1);
    let (mut pending, mut bits) = (0u128, 0);
    for digit in digits {
        debug_assert!(*digit >> radix_bits == 0);
        pending |= digit << bits;
        bits += radix_bits;
        while bits >= 32 {
            words.push(pending as u32);
            pending >>= 32;
            bits -= 32;
        }
    }
    words.push(pending as u32);
    BigInt::from_biguint(
        if negative { Sign::Minus } else { Sign::Plus },
        BigUint::new(words),
    )
}
/// The limb's signed digit of a word-sized integer.
fn signed_digit(value: i128, limb: usize, radix_bits: usize) -> i128 {
    let magnitude = (value.unsigned_abs() >> (radix_bits * limb)) & ((1u128 << radix_bits) - 1);
    if value < 0 {
        -(magnitude as i128)
    } else {
        magnitude as i128
    }
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
impl KeyInput<'_> {
    /// Starts the key's products of the common polynomial with its left
    /// secret.
    fn products(&self) -> Products {
        Products::start(self.common, self.left, self.limbs, RADIX_BITS)
    }
}
/// The key from its input and the products that input started.
fn key(
    witness: &mut Witness,
    output: &mut impl PolynomialOutput,
    input: KeyInput<'_>,
    products: Products,
) {
    let degree = input.common.len();
    let error = Zeroizing::new(errors(input.label, degree));
    let transformed = Zeroizing::new(transformed(input.right, input.automorphism));
    let limbs = input.limbs;
    let modulus = reduction::Modulus::new(&input.modulus.to_bytes_le().1, RADIX_BITS).unwrap();
    let direct: Vec<i128> = (0..limbs)
        .map(|limb| digit(&input.multiplier, limb))
        .collect();
    let modulus_digits: Vec<i128> = (0..limbs).map(|limb| digit(input.modulus, limb)).collect();
    let products = products.wait();
    // Each value's digits and sign, which give its signed digits.
    let mut digits = vec![0u128; degree * limbs];
    let mut negative = vec![false; degree];
    let mut quotients = Zeroizing::new(Vec::with_capacity(degree));
    for position in 0..degree {
        let mut raw = Zeroizing::new([0i128; reduction::MAXIMUM_LIMBS]);
        for limb in 0..limbs {
            raw[limb] = -products[limb][position]
                + direct[limb] * i128::from(transformed[position])
                + if limb == 0 { error[position] } else { 0 };
        }
        let result = modulus
            .reduce(
                &raw[..limbs],
                &mut digits[position * limbs..(position + 1) * limbs],
            )
            .unwrap();
        negative[position] = result.negative;
        quotients.push(-result.quotient);
    }
    let signed = |position: usize, limb: usize| {
        let value = digits[position * limbs + limb] as i128;
        if negative[position] { -value } else { value }
    };
    let mut carries = Zeroizing::new(vec![vec![0i128; degree]; limbs - 1]);
    for position in 0..degree {
        let mut carry = 0;
        for limb in 0..limbs {
            let row = products[limb][position] + signed(position, limb)
                - direct[limb] * i128::from(transformed[position])
                - if limb == 0 { error[position] } else { 0 }
                - modulus_digits[limb] * quotients[position]
                + carry;
            if limb + 1 < limbs {
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
    let values: Vec<BigInt> = (0..degree)
        .map(|position| {
            from_digits(
                &digits[position * limbs..(position + 1) * limbs],
                RADIX_BITS,
                negative[position],
            )
        })
        .collect();
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
    let modulus_digits = [0, 1].map(|limb| digit_in(modulus, limb, radix_bits));
    // Both components' products run while this instance reduces the first.
    let products =
        [public_key, common].map(|public| Products::start(public, ephemeral, 2, radix_bits));
    for (component, products) in products.into_iter().enumerate() {
        let error = Zeroizing::new(errors(
            &format!("share-{recipient}-{component}-error"),
            DEGREE,
        ));
        let products = products.wait();
        let mut digits = vec![[0u128; 2]; DEGREE];
        let mut negative = vec![false; DEGREE];
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
            let reduced = reduction
                .reduce(raw.as_ref(), &mut digits[position])
                .unwrap();
            negative[position] = reduced.negative;
            quotients.push(reduced.quotient);
        }
        let mut carries = Zeroizing::new(vec![0i128; DEGREE]);
        for position in 0..DEGREE {
            let mut carry = 0;
            for (limb, product) in products.iter().enumerate() {
                let shared = if component == 0 {
                    signed_digit(offset[position], limb, radix_bits)
                        + SCALE
                            * if limb == 0 {
                                low_sum[position] + i128::from(secret.values[position])
                            } else {
                                high_sum[position]
                            }
                } else {
                    0
                };
                let value = digits[position][limb] as i128;
                let value = if negative[position] { -value } else { value };
                let row = product[position] - value
                    + shared
                    + if limb == 0 { error[position] } else { 0 }
                    - modulus_digits[limb] * quotients[position]
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
        let values: Vec<BigInt> = digits
            .iter()
            .zip(&negative)
            .map(|(digits, negative)| from_digits(digits, radix_bits, *negative))
            .collect();
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
