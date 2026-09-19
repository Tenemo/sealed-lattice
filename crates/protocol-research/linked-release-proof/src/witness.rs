use crate::{
    convolution::{multiply_digits, signed_digit},
    parameters::*,
    statement::{self, PublicStatement, SHARE_SCALE},
};
use num_bigint::{BigInt, Sign};
use num_traits::{Signed, ToPrimitive};
use zeroize::Zeroizing;
#[path = "../../setup-witness/src/common-polynomial.rs"]
mod common_polynomial;
#[path = "../../setup-witness/src/gaussian.rs"]
mod gaussian;

struct Random {
    bytes: Zeroizing<Vec<u8>>,
    offset: usize,
}
impl Random {
    fn new() -> Self {
        Self {
            bytes: Zeroizing::new(vec![0; 65536]),
            offset: 65536,
        }
    }
    fn take<const N: usize>(&mut self) -> Zeroizing<[u8; N]> {
        let mut output = Zeroizing::new([0; N]);
        let mut used = 0;
        while used < N {
            if self.offset == self.bytes.len() {
                crate::random::fill(&mut self.bytes);
                self.offset = 0;
            }
            let count = (N - used).min(self.bytes.len() - self.offset);
            output[used..used + count]
                .copy_from_slice(&self.bytes[self.offset..self.offset + count]);
            self.bytes[self.offset..self.offset + count].fill(0);
            used += count;
            self.offset += count;
        }
        output
    }
    fn sparse(&mut self, count: usize) -> Zeroizing<Vec<i128>> {
        let mut values = Zeroizing::new(vec![0; SYSTEMATIC]);
        let mut used = 0;
        while used < count {
            let index = (u32::from_le_bytes(*self.take::<4>()) as usize) & (SYSTEMATIC - 1);
            if values[index] == 0 {
                values[index] = if used < count / 2 { 1 } else { -1 };
                used += 1;
            }
        }
        values
    }
    fn error(&mut self) -> i128 {
        gaussian::sample(&self.take::<20>())
    }
    fn signed_share(&mut self) -> i128 {
        let bytes = self.take::<16>();
        let value = u128::from_le_bytes(*bytes) & ((1u128 << 114) - 1);
        value as i128 - (1i128 << 113)
    }
}
fn center(value: BigInt, modulus: &BigInt) -> BigInt {
    let value = (value % modulus + modulus) % modulus;
    if value > modulus >> 1usize {
        value - modulus
    } else {
        value
    }
}
fn reconstruct(digits: &[Vec<i128>], position: usize) -> BigInt {
    digits.iter().rev().fold(BigInt::from(0), |sum, values| {
        (sum << 48usize) + values[position]
    })
}
fn private_digit(value: &BigInt, limb: usize, bits: usize, total_bits: usize) -> i128 {
    if limb * bits >= total_bits {
        return 0;
    }
    let count = total_bits.div_ceil(bits);
    if limb + 1 == count {
        (value >> (limb * bits)).to_i128().unwrap()
    } else {
        ((value >> (limb * bits)) & ((BigInt::from(1u32) << bits) - 1u32))
            .to_i128()
            .unwrap()
    }
}
fn signed_column(columns: &mut [Vec<u16>], variable: usize, position: usize, value: &BigInt) {
    let bits = WIDTHS[variable];
    let radius = BigInt::from(1u32) << (bits - 1);
    assert!(*value >= -&radius && *value < radius);
    let encoded = value + radius;
    let bytes = Zeroizing::new(encoded.to_bytes_le().1);
    for word in 0..bits.div_ceil(16) {
        let low = bytes.get(2 * word).copied().unwrap_or(0);
        let high = bytes.get(2 * word + 1).copied().unwrap_or(0);
        columns[STARTS[variable] + word][position] = u16::from_le_bytes([low, high]);
    }
}
pub struct ReleaseInputs {
    common: Vec<BigInt>,
    public_key: Vec<BigInt>,
    encrypted_constant: Vec<BigInt>,
    encrypted_linear: Vec<BigInt>,
    target_linear: Vec<BigInt>,
    secret: Zeroizing<Vec<i128>>,
    expected_share: Option<Zeroizing<Vec<i128>>>,
}
pub struct PreparedRelease {
    pub statement: PublicStatement,
    pub(crate) columns: Zeroizing<Vec<Vec<u16>>>,
}
impl PreparedRelease {
    pub fn check_equations(&self) {
        let witness =
            crate::oracles::Witness::from_columns(self.statement.digest(), self.columns.to_vec())
                .unwrap();
        for alpha in [[13, 17, 19], [29, 31, 37]] {
            let operator = self.statement.operator(alpha).unwrap();
            let actual = operator.coefficients.iter().zip(self.columns.iter()).fold(
                crate::field::ZERO,
                |sum, (coefficients, column)| {
                    coefficients
                        .iter()
                        .zip(column)
                        .fold(sum, |sum, (coefficient, value)| {
                            crate::field::add(
                                sum,
                                crate::field::scale(*coefficient, u128::from(*value)),
                            )
                        })
                },
            );
            assert!(
                actual == operator.target,
                "Complete linked-release affine projection differs"
            );
        }
        drop(witness);
    }
}

// This constructor generates its own independent synthetic recipient and target.
// It cannot import an original participant's secret or authorize a release.
pub fn synthetic_inputs() -> ReleaseInputs {
    let mut random = Random::new();
    let modulus = statement::share_modulus();
    let release_modulus = statement::release_modulus();
    let common = common_polynomial::public_polynomial("common-share", SYSTEMATIC, &modulus);
    let secret = random.sparse(256);
    let private = Zeroizing::new(vec![secret.to_vec()]);
    let key_product = multiply_digits(&common, &private, 48, 4);
    let public_key: Vec<_> = (0..SYSTEMATIC)
        .map(|position| {
            center(
                -reconstruct(&key_product, position) + random.error(),
                &modulus,
            )
        })
        .collect();
    drop(key_product);
    drop(private);
    let mut encrypted_constant = vec![BigInt::from(0); SYSTEMATIC];
    let mut encrypted_linear = vec![BigInt::from(0); SYSTEMATIC];
    let mut expected_share = Zeroizing::new(vec![0i128; SYSTEMATIC]);
    for _ in 0..10 {
        let constant = random.sparse(1024);
        let ephemeral = Zeroizing::new(vec![random.sparse(256).to_vec()]);
        let first = multiply_digits(&public_key, &ephemeral, 48, 4);
        let second = multiply_digits(&common, &ephemeral, 48, 4);
        for position in 0..SYSTEMATIC {
            let message = constant[position]
                + random.signed_share()
                + random.signed_share()
                + random.signed_share();
            expected_share[position] += message;
            encrypted_constant[position] = center(
                &encrypted_constant[position]
                    + reconstruct(&first, position)
                    + BigInt::from(SHARE_SCALE) * message
                    + random.error(),
                &modulus,
            );
            encrypted_linear[position] = center(
                &encrypted_linear[position] + reconstruct(&second, position) + random.error(),
                &modulus,
            );
        }
    }
    let target_linear = (0..SYSTEMATIC)
        .map(|_| {
            center(
                BigInt::from_bytes_le(Sign::Plus, &*random.take::<48>()),
                &release_modulus,
            )
        })
        .collect();
    ReleaseInputs {
        common,
        public_key,
        encrypted_constant,
        encrypted_linear,
        target_linear,
        secret,
        expected_share: Some(expected_share),
    }
}
#[derive(Debug)]
pub enum ReleaseInputError {
    Shape,
    Key,
    Share,
}
impl ReleaseInputs {
    pub fn new(
        common: Vec<BigInt>,
        public_key: Vec<BigInt>,
        encrypted_constant: Vec<BigInt>,
        encrypted_linear: Vec<BigInt>,
        target_linear: Vec<BigInt>,
        secret: Zeroizing<Vec<i128>>,
    ) -> Result<Self, ReleaseInputError> {
        let share_half = statement::share_modulus() >> 1usize;
        let release_half = statement::release_modulus() >> 1usize;
        if [&common, &public_key, &encrypted_constant, &encrypted_linear]
            .iter()
            .any(|values| {
                values.len() != SYSTEMATIC || values.iter().any(|value| value.abs() > share_half)
            })
            || target_linear.len() != SYSTEMATIC
            || target_linear.iter().any(|value| value.abs() > release_half)
            || secret.len() != SYSTEMATIC
            || secret.iter().filter(|value| **value == 1).count() != 128
            || secret.iter().filter(|value| **value == -1).count() != 128
            || secret.iter().any(|value| !(-1..=1).contains(value))
        {
            return Err(ReleaseInputError::Shape);
        }
        Ok(Self {
            common,
            public_key,
            encrypted_constant,
            encrypted_linear,
            target_linear,
            secret,
            expected_share: None,
        })
    }
}
pub fn derive(inputs: ReleaseInputs) -> PreparedRelease {
    derive_inner(inputs, None).expect("Synthetic release inputs must satisfy the relation")
}
pub fn derive_bound(
    inputs: ReleaseInputs,
    header: [u8; HEADER_BYTES],
) -> Result<PreparedRelease, ReleaseInputError> {
    if &header[..4] != b"LRS1" || u16::from_le_bytes(header[196..198].try_into().unwrap()) >= 10 {
        return Err(ReleaseInputError::Shape);
    }
    derive_inner(inputs, Some(header))
}
fn derive_inner(
    inputs: ReleaseInputs,
    header: Option<[u8; HEADER_BYTES]>,
) -> Result<PreparedRelease, ReleaseInputError> {
    let mut random = Random::new();
    let modulus = statement::share_modulus();
    let release_modulus = statement::release_modulus();
    let radix = 1i128 << 96;
    let release_radix = 1i128 << 48;
    let private = Zeroizing::new(vec![inputs.secret.to_vec()]);
    let key_product = multiply_digits(&inputs.common, &private, 48, 4);
    let decryption_product = multiply_digits(&inputs.encrypted_linear, &private, 48, 4);
    drop(private);
    let mut columns = Zeroizing::new(vec![vec![0u16; SYSTEMATIC]; COLUMNS]);
    let mut shares = Zeroizing::new(vec![0i128; SYSTEMATIC]);
    for position in 0..SYSTEMATIC {
        let raw_key = reconstruct(&key_product, position) + &inputs.public_key[position];
        let error = center(raw_key.clone(), &modulus);
        if error < -(BigInt::from(1) << 6usize) || error >= (BigInt::from(1) << 6usize) {
            return Err(ReleaseInputError::Key);
        }
        let quotient = (&raw_key - &error) / &modulus;
        assert!(
            &quotient * &modulus + &error == raw_key,
            "Recipient-key reconstruction differs"
        );
        let key_low = key_product[0][position]
            + (key_product[1][position] << 48)
            + signed_digit(&inputs.public_key[position], 0, 96)
            - signed_digit(&modulus, 0, 96) * quotient.to_i128().unwrap()
            - error.to_i128().unwrap();
        assert!(key_low % radix == 0, "Recipient-key carry is not integral");
        signed_column(&mut columns, 0, position, &quotient);
        signed_column(&mut columns, 1, position, &BigInt::from(key_low / radix));
        signed_column(&mut columns, 2, position, &error);
        let raw_phase =
            reconstruct(&decryption_product, position) + &inputs.encrypted_constant[position];
        let phase = center(raw_phase.clone(), &modulus);
        let sign: i32 = if phase.is_negative() { -1 } else { 1 };
        let share: BigInt = (&phase.abs() + SHARE_SCALE / 2) / SHARE_SCALE * sign;
        let error = &phase - SHARE_SCALE * &share;
        if share < -(BigInt::from(1) << 119usize)
            || share >= (BigInt::from(1) << 119usize)
            || error < -(BigInt::from(1) << 23usize)
            || error >= (BigInt::from(1) << 23usize)
        {
            return Err(ReleaseInputError::Share);
        }
        let quotient = (&raw_phase - SHARE_SCALE * &share - &error) / &modulus;
        assert!(
            SHARE_SCALE * &share + &error + &quotient * &modulus == raw_phase,
            "Aggregate-decryption reconstruction differs"
        );
        shares[position] = share.to_i128().unwrap();
        if let Some(expected) = inputs.expected_share.as_ref() {
            assert!(
                shares[position] == expected[position],
                "Synthetic aggregate share differs"
            );
        }
        let lower = shares[position].rem_euclid(radix) - radix / 2;
        let offset = BigInt::from(SHARE_SCALE) * (radix / 2);
        let raw = decryption_product[0][position]
            + (decryption_product[1][position] << 48)
            + signed_digit(&inputs.encrypted_constant[position], 0, 96)
            - SHARE_SCALE * lower
            - signed_digit(&offset, 0, 96)
            - signed_digit(&modulus, 0, 96) * quotient.to_i128().unwrap()
            - error.to_i128().unwrap();
        assert!(
            raw % radix == 0,
            "Aggregate-decryption carry is not integral"
        );
        signed_column(&mut columns, 3, position, &share);
        signed_column(&mut columns, 4, position, &error);
        signed_column(&mut columns, 5, position, &quotient);
        signed_column(&mut columns, 6, position, &BigInt::from(raw / radix));
        columns[WORDS][position] = u16::from(inputs.secret[position] == 1);
        columns[WORDS + 1][position] = u16::from(inputs.secret[position] == -1);
    }
    drop(key_product);
    drop(decryption_product);
    let mut private = Zeroizing::new(vec![vec![0; SYSTEMATIC]; 3]);
    for (position, share) in shares.iter().enumerate() {
        private[0][position] = share.rem_euclid(release_radix);
        private[1][position] = (share >> 48).rem_euclid(release_radix);
        private[2][position] = share >> 96;
    }
    let product = multiply_digits(&inputs.target_linear, &private, 48, 4);
    drop(private);
    let mut partial = Vec::with_capacity(SYSTEMATIC);
    for position in 0..SYSTEMATIC {
        let noise = BigInt::from_bytes_le(Sign::Plus, &*random.take::<21>())
            - (BigInt::from(1) << 167usize);
        let raw = 4u32 * (reconstruct(&product, position) + &noise);
        let value = center(raw.clone(), &release_modulus);
        let quotient = (&raw - &value) / &release_modulus;
        assert!(
            &value + &quotient * &release_modulus == raw,
            "Partial-decryption reconstruction differs"
        );
        signed_column(&mut columns, 7, position, &noise);
        signed_column(&mut columns, 8, position, &quotient);
        let mut carry = 0i128;
        for limb in 0..6 {
            let mut residual = carry + 4 * product[limb][position] - signed_digit(&value, limb, 48)
                + 4 * private_digit(&noise, limb, 48, 168);
            for public_limb in 0..4 {
                if limb >= public_limb && limb - public_limb < 3 {
                    residual -= signed_digit(&release_modulus, public_limb, 48)
                        * private_digit(&quotient, limb - public_limb, 48, 144);
                }
            }
            if limb < 5 {
                assert!(
                    residual % release_radix == 0,
                    "Partial-decryption carry is not integral"
                );
                carry = residual / release_radix;
                signed_column(&mut columns, 9 + limb, position, &BigInt::from(carry));
            } else {
                assert!(residual == 0, "Partial-decryption final carry differs");
            }
        }
        partial.push(value);
    }
    let header = if let Some(header) = header {
        header.to_vec()
    } else {
        let mut header = Vec::from(b"LRS1".as_slice());
        header.extend(&*random.take::<192>());
        header.extend(0u16.to_le_bytes());
        header
    };
    let polynomials = [
        &inputs.common,
        &inputs.public_key,
        &inputs.encrypted_constant,
        &inputs.encrypted_linear,
        &inputs.target_linear,
        &partial,
    ]
    .into_iter()
    .enumerate()
    .map(|(index, values)| {
        statement::encode_polynomial(values, if index < 4 { 21 } else { 25 }).unwrap()
    })
    .collect();
    Ok(PreparedRelease {
        statement: PublicStatement {
            header,
            polynomials,
        },
        columns,
    })
}
