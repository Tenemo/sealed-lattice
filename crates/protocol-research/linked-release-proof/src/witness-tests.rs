use super::*;
use word_proof::field::{self, Element, ZERO};

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

// The weighted operator places at every row of every column the
// coefficient the dense reference builds there, with the same target and
// lookup weight.
#[test]
fn weighted_operators_equal_the_dense_reference_at_every_row() {
    use word_proof::field::MODULUS;
    for (participants, options) in [(3, 2), (10, 10), (20, 20)] {
        let profile = Profile::new(participants, options).unwrap();
        let (prepared, _) = synthetic_release(profile);
        for alpha in [
            [1, 0, 0],
            [13, 17, 19],
            [MODULUS - 2, MODULUS - 3, MODULUS - 5],
        ] {
            let weighted = prepared.statement.operator(alpha).unwrap();
            let dense = statement::dense_operator::operator(&prepared.statement, alpha).unwrap();
            assert_eq!(weighted.columns(prepared.columns.len()), dense.coefficients);
            assert_eq!(
                (weighted.target, weighted.lookup_weight),
                (dense.target, dense.lookup_weight)
            );
        }
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
