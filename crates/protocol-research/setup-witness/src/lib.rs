pub mod contribution;
mod convolution;
mod gaussian;
mod reduction;
pub mod registration;
#[cfg(not(target_arch = "wasm32"))]
use convolution::reconstruct;
use convolution::{Plan, RADIX, digit};
use num_bigint::{BigInt, Sign};
use num_traits::Signed;
use sha3::digest::XofReader;
#[cfg(not(target_arch = "wasm32"))]
use sha3::{Digest, Sha3_512};
#[path = "common-polynomial.rs"]
mod common_polynomial;
#[cfg(not(target_arch = "wasm32"))]
use common_polynomial::center;
use common_polynomial::public_polynomial;
#[cfg(not(target_arch = "wasm32"))]
use std::{
    fs::{File, OpenOptions},
    io::{BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
};
use zeroize::{Zeroize, Zeroizing};

const DEGREE: usize = 65_536;
const AUXILIARY_DEGREE: usize = 4_096;
const WORD_COLUMNS: usize = 333;
const BOOLEAN_COLUMNS: usize = 32;
const SCALE: i128 = 998_244_353;
const PARAMETERS: &[u8; 137] = include_bytes!("../../setup-proof/parameters.bin");

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
struct Sparse {
    values: Zeroizing<Vec<i8>>,
    transform: Zeroizing<Vec<u128>>,
}
pub struct Witness {
    words: Vec<Vec<u16>>,
    booleans: Vec<Vec<u16>>,
}
impl Witness {
    pub fn into_columns(mut self) -> Vec<Vec<u16>> {
        assert_eq!(self.words.len(), WORD_COLUMNS);
        assert_eq!(self.booleans.len(), BOOLEAN_COLUMNS);
        let mut columns = std::mem::take(&mut self.words);
        columns.append(&mut self.booleans);
        columns
    }
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
    #[cfg(not(target_arch = "wasm32"))]
    fn write(&self, path: &Path, statement_digest: &[u8; 64]) {
        assert_eq!(self.words.len(), WORD_COLUMNS);
        assert_eq!(self.booleans.len(), BOOLEAN_COLUMNS);
        let mut file = BufWriter::new(
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .unwrap(),
        );
        file.write_all(b"SFW1").unwrap();
        for value in [DEGREE, WORD_COLUMNS, BOOLEAN_COLUMNS] {
            file.write_all(&(value as u32).to_le_bytes()).unwrap();
        }
        file.write_all(statement_digest).unwrap();
        for column in self.words.iter().chain(&self.booleans) {
            for value in column {
                file.write_all(&value.to_le_bytes()).unwrap();
            }
        }
        file.flush().unwrap();
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
#[cfg(not(target_arch = "wasm32"))]
struct Output {
    directory: PathBuf,
    hash: Sha3_512,
    next: usize,
}
#[cfg(not(target_arch = "wasm32"))]
impl Output {
    fn new(directory: PathBuf) -> Self {
        let mut header = Vec::from(b"SCO1".as_slice());
        header.extend((DEGREE as u32).to_le_bytes());
        header.extend((AUXILIARY_DEGREE as u32).to_le_bytes());
        header.extend(&PARAMETERS[4..]);
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(directory.join("header.bin"))
            .unwrap();
        file.write_all(&header).unwrap();
        let mut hash = Sha3_512::new();
        Digest::update(&mut hash, &header);
        Self {
            directory,
            hash,
            next: 0,
        }
    }
    fn polynomial(&mut self, values: &[BigInt], modulus: &BigInt, width: usize) {
        let mut file = BufWriter::new(
            OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(
                    self.directory
                        .join(format!("polynomial-{:02}.bin", self.next)),
                )
                .unwrap(),
        );
        let half = modulus >> 1usize;
        for value in values {
            assert!(value.abs() <= half);
            let (negative, mut magnitude) = value.to_bytes_le();
            assert!(magnitude.len() <= width);
            magnitude.resize(width, 0);
            let sign = [u8::from(negative == Sign::Minus)];
            file.write_all(&sign).unwrap();
            file.write_all(&magnitude).unwrap();
            Digest::update(&mut self.hash, sign);
            Digest::update(&mut self.hash, &magnitude);
        }
        file.flush().unwrap();
        self.next += 1;
    }
    fn finish(self) -> [u8; 64] {
        assert_eq!(self.next, 75);
        self.hash.finalize().into()
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
    ));
    let error = Zeroizing::new(errors(input.label, degree));
    let transformed = Zeroizing::new(transformed(input.right, input.automorphism));
    let modulus = reduction::Modulus::from_bytes(&input.modulus.to_bytes_le().1).unwrap();
    let direct: Vec<i128> = (0..input.limbs)
        .map(|limb| digit(&input.multiplier, limb))
        .collect();
    let mut values = Vec::with_capacity(degree);
    let mut quotients = Zeroizing::new(Vec::with_capacity(degree));
    for position in 0..degree {
        let mut raw = Zeroizing::new([0i128; 9]);
        for limb in 0..input.limbs {
            raw[limb] = -products[limb][position]
                + direct[limb] * i128::from(transformed[position])
                + if limb == 0 { error[position] } else { 0 };
        }
        let mut reduced = [0u128; 9];
        let result = modulus
            .reduce(&raw[..input.limbs], &mut reduced[..input.limbs])
            .unwrap();
        let magnitude = reduced[..input.limbs]
            .iter()
            .rev()
            .fold(BigInt::from(0), |sum, value| {
                (sum << 96usize) + BigInt::from(*value)
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
                assert_eq!(row % RADIX, 0);
                carry = row / RADIX;
                carries[limb][position] = carry;
            } else {
                assert_eq!(row, 0, "final key carry at {position}");
            }
        }
    }
    witness.signed(16, &quotients);
    for carry in carries.iter() {
        witness.signed(16, carry);
    }
    witness.signed(7, &error);
    output.polynomial(&values, input.modulus, input.width);
    #[cfg(not(target_arch = "wasm32"))]
    println!("Generated {}", input.label);
}

struct ShareInput<'a> {
    recipient: usize,
    common: &'a [BigInt],
    public_key: &'a [BigInt],
    secret: &'a Sparse,
    sharing: &'a [Vec<i128>],
    ephemeral: &'a Sparse,
    modulus: &'a BigInt,
}
fn share_ciphertexts(
    witness: &mut Witness,
    output: &mut impl PolynomialOutput,
    plan: &Plan,
    input: ShareInput<'_>,
) -> Vec<Vec<BigInt>> {
    let ShareInput {
        recipient,
        common,
        public_key,
        secret,
        sharing,
        ephemeral,
        modulus,
    } = input;
    let point = recipient * DEGREE / 8;
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
            low_sum[position] += sign * (value.rem_euclid(RADIX) - RADIX / 2);
            high_sum[position] += sign * value.div_euclid(RADIX);
            offset[position] += sign * SCALE * (RADIX / 2);
        }
    }
    let mut ciphertexts = Vec::new();
    let reduction = reduction::Modulus::from_bytes(&modulus.to_bytes_le().1).unwrap();
    for (component, common) in [public_key, common].into_iter().enumerate() {
        let products =
            Zeroizing::new(plan.digit_products(common, &ephemeral.values, &ephemeral.transform, 2));
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
                raw[0] += SCALE * (message[position] % RADIX);
                raw[1] += SCALE * (message[position] / RADIX);
            }
            let mut digits = [0; 2];
            let reduced = reduction.reduce(raw.as_ref(), &mut digits).unwrap();
            let magnitude = (BigInt::from(digits[1]) << 96usize) + BigInt::from(digits[0]);
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
                    digit(&BigInt::from(offset[position]), limb)
                        + SCALE
                            * if limb == 0 {
                                low_sum[position] + i128::from(secret.values[position])
                            } else {
                                high_sum[position]
                            }
                } else {
                    0
                };
                let row = product[position] - digit(&values[position], limb)
                    + shared
                    + if limb == 0 { error[position] } else { 0 }
                    - digit(modulus, limb) * quotients[position]
                    + carry;
                if limb == 0 {
                    assert_eq!(row % RADIX, 0);
                    carry = row / RADIX;
                    carries[position] = carry;
                } else {
                    assert_eq!(row, 0, "final share carry at {position}");
                }
            }
        }
        witness.signed(16, &quotients);
        witness.signed(if component == 0 { 32 } else { 16 }, &carries);
        witness.signed(7, &error);
        output.polynomial(&values, modulus, 20);
        ciphertexts.push(values);
    }
    #[cfg(not(target_arch = "wasm32"))]
    println!("Generated encrypted share {recipient}");
    ciphertexts
}

#[cfg(not(target_arch = "wasm32"))]
pub fn generate_fixture(directory: &Path) {
    let directory = directory.to_path_buf();
    assert!(directory.is_dir());
    let mut contribution = contribution::Contribution::new();
    let mut output = Output::new(directory.clone());
    for gadget in 0..6 {
        contribution.gadget(gadget, &mut output).unwrap();
    }
    contribution.begin_shares(&mut output).unwrap();
    let common = public_polynomial("common-share", DEGREE, &contribution.share_modulus);
    for recipient in 0..10 {
        let values = Zeroizing::new(sparse_values(
            &format!("recipient-secret-{recipient}"),
            DEGREE,
            256,
        ));
        let recipient_secret = Sparse {
            transform: Zeroizing::new(contribution.plan.sparse_transform(&values)),
            values,
        };
        let products = contribution.plan.digit_products(
            &common,
            &recipient_secret.values,
            &recipient_secret.transform,
            2,
        );
        let error = errors(&format!("recipient-error-{recipient}"), DEGREE);
        let public_key: Vec<BigInt> = (0..DEGREE)
            .map(|position| {
                center(
                    -reconstruct(&products, position) + BigInt::from(error[position]),
                    &contribution.share_modulus,
                )
            })
            .collect();
        let ciphertexts = contribution
            .share(recipient, &public_key, &mut output)
            .unwrap();
        // Only the native fixture checker owns the recipients' synthetic keys.
        let product = contribution.plan.digit_products(
            &ciphertexts[1],
            &recipient_secret.values,
            &recipient_secret.transform,
            2,
        );
        for (position, ciphertext) in ciphertexts[0].iter().enumerate() {
            let mut expected = i128::from(contribution.secret.values[position]);
            for (coefficient, values) in contribution.sharing.iter().enumerate() {
                let shift = recipient * (coefficient + 1) * DEGREE / 8;
                let input = (position + DEGREE - shift % DEGREE) % DEGREE;
                let sign = if ((input + shift) / DEGREE).is_multiple_of(2) {
                    1
                } else {
                    -1
                };
                expected += sign * values[input];
            }
            let phase = center(
                ciphertext + reconstruct(&product, position),
                &contribution.share_modulus,
            );
            assert!(
                (phase - BigInt::from(SCALE) * BigInt::from(expected)).abs()
                    < BigInt::from(SCALE / 2)
            );
        }
    }
    contribution.finish(&mut output).unwrap();
    let digest = output.finish();
    contribution
        .into_witness()
        .unwrap()
        .write(&directory.join("witness.bin"), &digest);
    let mut hash = Sha3_512::new();
    let mut file = BufReader::new(File::open(directory.join("witness.bin")).unwrap());
    let mut buffer = vec![0; 1 << 20];
    let mut length = 0;
    loop {
        let read = Read::read(&mut file, &mut buffer).unwrap();
        if read == 0 {
            break;
        }
        Digest::update(&mut hash, &buffer[..read]);
        length += read;
    }
    println!(
        "statement_digest={}",
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    println!("witness_bytes={length}");
    println!(
        "witness_sha3_512={}",
        hash.finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
}

#[cfg(not(target_arch = "wasm32"))]
impl PolynomialOutput for Output {
    fn polynomial(&mut self, values: &[BigInt], modulus: &BigInt, width: usize) {
        Output::polynomial(self, values, modulus, width);
    }
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
