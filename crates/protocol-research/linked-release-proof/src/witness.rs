use crate::{
    convolution::{multiply_digits, signed_digit},
    parameters::*,
    statement::{
        self, DECODING_CARRY, DECODING_ERROR, DECODING_QUOTIENT, FIRST_RELEASE_CARRY, KEY_CARRY,
        KEY_ERROR, KEY_QUOTIENT, NOISE, PublicStatement, RELEASE_QUOTIENT, SHARE,
    },
};
use num_bigint::{BigInt, Sign};
use num_traits::{Signed, ToPrimitive};
use supported_profile::{
    Profile, RECIPIENT_SECRET_SUPPORT, RELEASE_DECODING_LIMB_BITS, RELEASE_LIMB_BITS, SHARE_SCALE,
};
use zeroize::Zeroizing;

struct Random {
    bytes: Zeroizing<Vec<u8>>,
    offset: usize,
}
impl Random {
    fn new() -> Self {
        Self {
            bytes: Zeroizing::new(vec![0; RANDOM_READ_BYTES]),
            offset: RANDOM_READ_BYTES,
        }
    }
    fn fill(&mut self, output: &mut [u8]) {
        let mut used = 0;
        while used < output.len() {
            if self.offset == self.bytes.len() {
                crate::random::fill(&mut self.bytes);
                self.offset = 0;
            }
            let count = (output.len() - used).min(self.bytes.len() - self.offset);
            output[used..used + count]
                .copy_from_slice(&self.bytes[self.offset..self.offset + count]);
            self.bytes[self.offset..self.offset + count].fill(0);
            used += count;
            self.offset += count;
        }
    }
    /// A uniform signed integer of the given width.
    fn signed(&mut self, bits: usize) -> BigInt {
        let mut bytes = Zeroizing::new(vec![0; bits.div_ceil(8)]);
        self.fill(&mut bytes);
        let value = BigInt::from_bytes_le(Sign::Plus, &bytes) & ((BigInt::from(1) << bits) - 1u32);
        value - (BigInt::from(1) << (bits - 1))
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
        (sum << RELEASE_LIMB_BITS) + values[position]
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
/// The signed release variables' widths and first word columns.
struct Layout {
    bits: Vec<usize>,
    starts: Vec<usize>,
}
impl Layout {
    fn signed_column(
        &self,
        columns: &mut [Vec<u16>],
        variable: usize,
        position: usize,
        value: &BigInt,
    ) {
        let bits = self.bits[variable];
        let radius = BigInt::from(1u32) << (bits - 1);
        assert!(*value >= -&radius && *value < radius);
        let encoded = value + radius;
        let bytes = Zeroizing::new(encoded.to_bytes_le().1);
        for word in 0..bits.div_ceil(16) {
            let low = bytes.get(2 * word).copied().unwrap_or(0);
            let high = bytes.get(2 * word + 1).copied().unwrap_or(0);
            columns[self.starts[variable] + word][position] = u16::from_le_bytes([low, high]);
        }
    }
}
pub struct ReleaseInputs {
    profile: Profile,
    common: Vec<BigInt>,
    public_key: Vec<BigInt>,
    encrypted_constant: Vec<BigInt>,
    encrypted_linear: Vec<BigInt>,
    target_linear: Vec<BigInt>,
    secret: Zeroizing<Vec<i128>>,
}
pub struct PreparedRelease {
    pub statement: PublicStatement,
    pub(crate) columns: Zeroizing<Vec<Vec<u16>>>,
}
#[derive(Debug)]
pub enum ReleaseInputError {
    Shape,
    Key,
    Share,
}
impl ReleaseInputs {
    pub fn new(
        profile: Profile,
        common: Vec<BigInt>,
        public_key: Vec<BigInt>,
        encrypted_constant: Vec<BigInt>,
        encrypted_linear: Vec<BigInt>,
        target_linear: Vec<BigInt>,
        secret: Zeroizing<Vec<i128>>,
    ) -> Result<Self, ReleaseInputError> {
        let share_half = statement::share_modulus() >> 1usize;
        let release_half = statement::release_modulus(profile) >> 1usize;
        let half_support = RECIPIENT_SECRET_SUPPORT / 2;
        if [&common, &public_key, &encrypted_constant, &encrypted_linear]
            .iter()
            .any(|values| {
                values.len() != SYSTEMATIC || values.iter().any(|value| value.abs() > share_half)
            })
            || target_linear.len() != SYSTEMATIC
            || target_linear.iter().any(|value| value.abs() > release_half)
            || secret.len() != SYSTEMATIC
            || secret.iter().filter(|value| **value == 1).count() != half_support
            || secret.iter().filter(|value| **value == -1).count() != half_support
            || secret.iter().any(|value| !(-1..=1).contains(value))
        {
            return Err(ReleaseInputError::Shape);
        }
        Ok(Self {
            profile,
            common,
            public_key,
            encrypted_constant,
            encrypted_linear,
            target_linear,
            secret,
        })
    }
}
/// Derives the release of the header's roster position.
pub fn derive_bound(
    inputs: ReleaseInputs,
    header: [u8; RELEASE_HEADER_BYTES],
) -> Result<PreparedRelease, ReleaseInputError> {
    statement::header_position(inputs.profile, &header).ok_or(ReleaseInputError::Shape)?;
    derive_inner(inputs, header)
}
fn derive_inner(
    inputs: ReleaseInputs,
    header: [u8; RELEASE_HEADER_BYTES],
) -> Result<PreparedRelease, ReleaseInputError> {
    let profile = inputs.profile;
    let (starts, words) = release_variable_starts(profile);
    let layout = Layout {
        bits: profile.release_variable_bits(),
        starts,
    };
    let mut random = Random::new();
    let modulus = statement::share_modulus();
    let release_modulus = statement::release_modulus(profile);
    let radix = 1i128 << RELEASE_DECODING_LIMB_BITS;
    let release_radix = 1i128 << RELEASE_LIMB_BITS;
    let share_digits = (8 * supported_profile::share_modulus().len()).div_ceil(RELEASE_LIMB_BITS);
    let key_error_radius = BigInt::from(1) << (layout.bits[KEY_ERROR] - 1);
    let share_radius = BigInt::from(1) << (layout.bits[SHARE] - 1);
    let decoding_error_radius = BigInt::from(1) << (layout.bits[DECODING_ERROR] - 1);
    let private = Zeroizing::new(vec![inputs.secret.to_vec()]);
    let key_product = multiply_digits(&inputs.common, &private, RELEASE_LIMB_BITS, share_digits);
    let decryption_product = multiply_digits(
        &inputs.encrypted_linear,
        &private,
        RELEASE_LIMB_BITS,
        share_digits,
    );
    drop(private);
    let mut columns = Zeroizing::new(vec![vec![0u16; SYSTEMATIC]; words + 2]);
    let mut shares = Zeroizing::new(vec![0i128; SYSTEMATIC]);
    // Each equation's lowest decoding limb is its two lowest release limbs.
    let decoding_limb = |digits: &[Vec<i128>], position: usize| {
        digits[0][position] + (digits[1][position] << RELEASE_LIMB_BITS)
    };
    for position in 0..SYSTEMATIC {
        let raw_key = reconstruct(&key_product, position) + &inputs.public_key[position];
        let error = center(raw_key.clone(), &modulus);
        if error < -&key_error_radius || error >= key_error_radius {
            return Err(ReleaseInputError::Key);
        }
        let quotient = (&raw_key - &error) / &modulus;
        assert!(
            &quotient * &modulus + &error == raw_key,
            "Recipient-key reconstruction differs"
        );
        let key_low = decoding_limb(&key_product, position)
            + signed_digit(&inputs.public_key[position], 0, RELEASE_DECODING_LIMB_BITS)
            - signed_digit(&modulus, 0, RELEASE_DECODING_LIMB_BITS) * quotient.to_i128().unwrap()
            - error.to_i128().unwrap();
        assert!(key_low % radix == 0, "Recipient-key carry is not integral");
        layout.signed_column(&mut columns, KEY_QUOTIENT, position, &quotient);
        layout.signed_column(
            &mut columns,
            KEY_CARRY,
            position,
            &BigInt::from(key_low / radix),
        );
        layout.signed_column(&mut columns, KEY_ERROR, position, &error);
        let raw_phase =
            reconstruct(&decryption_product, position) + &inputs.encrypted_constant[position];
        let phase = center(raw_phase.clone(), &modulus);
        let sign: i32 = if phase.is_negative() { -1 } else { 1 };
        let scale = i128::from(SHARE_SCALE);
        let share: BigInt = (&phase.abs() + scale / 2) / scale * sign;
        let error = &phase - scale * &share;
        if share < -&share_radius
            || share >= share_radius
            || error < -&decoding_error_radius
            || error >= decoding_error_radius
        {
            return Err(ReleaseInputError::Share);
        }
        let quotient = (&raw_phase - scale * &share - &error) / &modulus;
        assert!(
            scale * &share + &error + &quotient * &modulus == raw_phase,
            "Aggregate-decryption reconstruction differs"
        );
        shares[position] = share.to_i128().unwrap();
        let lower = shares[position].rem_euclid(radix) - radix / 2;
        let offset = BigInt::from(SHARE_SCALE) * (radix / 2);
        let raw = decoding_limb(&decryption_product, position)
            + signed_digit(
                &inputs.encrypted_constant[position],
                0,
                RELEASE_DECODING_LIMB_BITS,
            )
            - scale * lower
            - signed_digit(&offset, 0, RELEASE_DECODING_LIMB_BITS)
            - signed_digit(&modulus, 0, RELEASE_DECODING_LIMB_BITS) * quotient.to_i128().unwrap()
            - error.to_i128().unwrap();
        assert!(
            raw % radix == 0,
            "Aggregate-decryption carry is not integral"
        );
        layout.signed_column(&mut columns, SHARE, position, &share);
        layout.signed_column(&mut columns, DECODING_ERROR, position, &error);
        layout.signed_column(&mut columns, DECODING_QUOTIENT, position, &quotient);
        layout.signed_column(
            &mut columns,
            DECODING_CARRY,
            position,
            &BigInt::from(raw / radix),
        );
        columns[words][position] = u16::from(inputs.secret[position] == 1);
        columns[words + 1][position] = u16::from(inputs.secret[position] == -1);
    }
    drop(key_product);
    drop(decryption_product);
    // The share's release limbs: unsigned digits below a signed top limb.
    let share_limbs = profile.release_share_limbs();
    let mut private = Zeroizing::new(vec![vec![0; SYSTEMATIC]; share_limbs]);
    for (position, share) in shares.iter().enumerate() {
        for (limb, digits) in private.iter_mut().enumerate() {
            let shifted = share >> (limb * RELEASE_LIMB_BITS);
            digits[position] = if limb + 1 < share_limbs {
                shifted.rem_euclid(release_radix)
            } else {
                shifted
            };
        }
    }
    let public_limbs = profile.release_public_limbs();
    let product = multiply_digits(
        &inputs.target_linear,
        &private,
        RELEASE_LIMB_BITS,
        public_limbs,
    );
    drop(private);
    let clearing = profile.clearing_factor() as i128;
    let noise_bits = layout.bits[NOISE];
    let quotient_bits = layout.bits[RELEASE_QUOTIENT];
    let quotient_limbs = profile.release_quotient_limbs();
    let output_limbs = profile.release_output_limbs();
    let mut partial = Vec::with_capacity(SYSTEMATIC);
    for position in 0..SYSTEMATIC {
        let noise = random.signed(noise_bits);
        let raw = clearing * (reconstruct(&product, position) + &noise);
        let value = center(raw.clone(), &release_modulus);
        let quotient = (&raw - &value) / &release_modulus;
        assert!(
            &value + &quotient * &release_modulus == raw,
            "Partial-decryption reconstruction differs"
        );
        layout.signed_column(&mut columns, NOISE, position, &noise);
        layout.signed_column(&mut columns, RELEASE_QUOTIENT, position, &quotient);
        let mut carry = 0i128;
        for limb in 0..output_limbs {
            let mut residual = carry
                + clearing * product.get(limb).map_or(0, |values| values[position])
                - signed_digit(&value, limb, RELEASE_LIMB_BITS)
                + clearing * private_digit(&noise, limb, RELEASE_LIMB_BITS, noise_bits);
            for public_limb in 0..public_limbs.min(limb + 1) {
                if limb - public_limb < quotient_limbs {
                    residual -= signed_digit(&release_modulus, public_limb, RELEASE_LIMB_BITS)
                        * private_digit(
                            &quotient,
                            limb - public_limb,
                            RELEASE_LIMB_BITS,
                            quotient_bits,
                        );
                }
            }
            if limb + 1 < output_limbs {
                assert!(
                    residual % release_radix == 0,
                    "Partial-decryption carry is not integral"
                );
                carry = residual / release_radix;
                layout.signed_column(
                    &mut columns,
                    FIRST_RELEASE_CARRY + limb,
                    position,
                    &BigInt::from(carry),
                );
            } else {
                assert!(residual == 0, "Partial-decryption final carry differs");
            }
        }
        partial.push(value);
    }
    let release_bytes = statement::release_coefficient_bytes(profile);
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
        statement::encode_polynomial(
            values,
            if index < 4 {
                statement::share_coefficient_bytes()
            } else {
                release_bytes
            },
        )
        .unwrap()
    })
    .collect();
    Ok(PreparedRelease {
        statement: PublicStatement {
            profile,
            header: header.to_vec(),
            polynomials,
        },
        columns,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::field::{self, Element, ZERO};
    #[path = "../../../../setup-witness/src/common-polynomial.rs"]
    mod common_polynomial;
    #[path = "../../../../setup-witness/src/gaussian.rs"]
    mod gaussian;

    impl Random {
        fn sparse(&mut self, count: usize) -> Zeroizing<Vec<i128>> {
            let mut values = Zeroizing::new(vec![0; SYSTEMATIC]);
            let mut used = 0;
            while used < count {
                let mut bytes = [0; 4];
                self.fill(&mut bytes);
                let index = (u32::from_le_bytes(bytes) as usize) & (SYSTEMATIC - 1);
                if values[index] == 0 {
                    values[index] = if used < count / 2 { 1 } else { -1 };
                    used += 1;
                }
            }
            values
        }
        fn error(&mut self) -> i128 {
            let mut bytes = [0; 20];
            self.fill(&mut bytes);
            gaussian::sample(&bytes)
        }
    }

    // An independent synthetic recipient and one encrypted aggregate share of
    // the profile's full signed width, with both range ends present.
    pub(crate) fn synthetic_release(profile: Profile) -> (PreparedRelease, Vec<BigInt>) {
        let mut random = Random::new();
        let modulus = statement::share_modulus();
        let common = common_polynomial::public_polynomial(
            "common-share",
            SYSTEMATIC,
            &modulus,
            supported_profile::fixed_common_sample_bits(),
        );
        let secret = random.sparse(RECIPIENT_SECRET_SUPPORT);
        let digits = (8 * supported_profile::share_modulus().len()).div_ceil(RELEASE_LIMB_BITS);
        let private = Zeroizing::new(vec![secret.to_vec()]);
        let key_product = multiply_digits(&common, &private, RELEASE_LIMB_BITS, digits);
        let public_key: Vec<_> = (0..SYSTEMATIC)
            .map(|position| {
                center(
                    -reconstruct(&key_product, position) + random.error(),
                    &modulus,
                )
            })
            .collect();
        let share_bits = profile.release_share_bits();
        let mut shares: Vec<_> = (0..SYSTEMATIC).map(|_| random.signed(share_bits)).collect();
        shares[0] = -(BigInt::from(1) << (share_bits - 1));
        shares[1] = (BigInt::from(1) << (share_bits - 1)) - 1u32;
        let ephemeral = Zeroizing::new(vec![random.sparse(RECIPIENT_SECRET_SUPPORT).to_vec()]);
        let first = multiply_digits(&public_key, &ephemeral, RELEASE_LIMB_BITS, digits);
        let second = multiply_digits(&common, &ephemeral, RELEASE_LIMB_BITS, digits);
        let encrypted_constant = (0..SYSTEMATIC)
            .map(|position| {
                center(
                    reconstruct(&first, position)
                        + BigInt::from(SHARE_SCALE) * &shares[position]
                        + random.error(),
                    &modulus,
                )
            })
            .collect();
        let encrypted_linear = (0..SYSTEMATIC)
            .map(|position| center(reconstruct(&second, position) + random.error(), &modulus))
            .collect();
        let release_modulus = statement::release_modulus(profile);
        let target_linear = (0..SYSTEMATIC)
            .map(|_| {
                center(
                    random.signed(release_modulus.bits() as usize + 64),
                    &release_modulus,
                )
            })
            .collect();
        let inputs = ReleaseInputs::new(
            profile,
            common,
            public_key,
            encrypted_constant,
            encrypted_linear,
            target_linear,
            secret,
        )
        .unwrap();
        let mut header = [0; RELEASE_HEADER_BYTES];
        header[..4].copy_from_slice(statement::HEADER_MAGIC);
        let position = (profile.participants() - 1) as u16;
        header[RELEASE_HEADER_BYTES - 2..].copy_from_slice(&position.to_le_bytes());
        (derive_bound(inputs, header).unwrap(), shares)
    }

    fn affine_value(prepared: &PreparedRelease, alpha: Element) -> (Element, Element) {
        let operator = prepared.statement.operator(alpha).unwrap();
        let actual = operator
            .columns(prepared.columns.len())
            .iter()
            .zip(prepared.columns.iter())
            .fold(ZERO, |sum, (coefficients, column)| {
                coefficients
                    .iter()
                    .zip(column)
                    .fold(sum, |sum, (coefficient, value)| {
                        field::add(sum, field::scale(*coefficient, u128::from(*value)))
                    })
            });
        (actual, operator.target)
    }

    fn column_value(prepared: &PreparedRelease, variable: usize, position: usize) -> BigInt {
        let profile = prepared.statement.profile;
        let bits = profile.release_variable_bits()[variable];
        let start = release_variable_starts(profile).0[variable];
        let encoded = (0..bits.div_ceil(16))
            .rev()
            .fold(BigInt::from(0), |sum, word| {
                (sum << 16usize) + prepared.columns[start + word][position]
            });
        encoded - (BigInt::from(1) << (bits - 1))
    }

    #[test]
    fn releases_satisfy_the_affine_relation_at_two_shares_and_the_widest_profiles() {
        for (participants, options) in [(3, 2), (16, 2), (20, 20)] {
            let profile = Profile::new(participants, options).unwrap();
            let (mut prepared, shares) = synthetic_release(profile);
            for position in [0, 1, 2, SYSTEMATIC - 1] {
                assert_eq!(column_value(&prepared, SHARE, position), shares[position]);
            }
            for alpha in [[13, 17, 19], [29, 31, 37]] {
                let (actual, target) = affine_value(&prepared, alpha);
                assert_eq!(actual, target);
            }
            // A changed noise word no longer meets the partial decryption.
            let noise = release_variable_starts(profile).0[NOISE];
            prepared.columns[noise][5] ^= 1;
            let (actual, target) = affine_value(&prepared, [13, 17, 19]);
            assert_ne!(actual, target);
        }
    }

    #[test]
    fn headers_outside_the_roster_or_with_another_magic_are_refused() {
        let profile = Profile::new(3, 2).unwrap();
        let mut header = [0; RELEASE_HEADER_BYTES];
        header[..4].copy_from_slice(statement::HEADER_MAGIC);
        header[RELEASE_HEADER_BYTES - 2] = 2;
        assert_eq!(statement::header_position(profile, &header), Some(2));
        header[RELEASE_HEADER_BYTES - 2] = 3;
        assert_eq!(statement::header_position(profile, &header), None);
        header[RELEASE_HEADER_BYTES - 2] = 0;
        header[0] ^= 1;
        assert_eq!(statement::header_position(profile, &header), None);
        assert_eq!(statement::header_position(profile, &header[1..]), None);
    }
}
