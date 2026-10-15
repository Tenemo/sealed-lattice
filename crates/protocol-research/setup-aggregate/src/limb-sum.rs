//! Unnormalized signed key-limb sums and their canonical FHE residues.
use num_bigint::{BigInt, Sign};
use statement_stream::{
    coefficient::{self, CenteredCodec},
    proof_field::MODULUS,
};
use supported_profile::{
    FHE_LIMB_BITS, FHE_SECRET_SUPPORT, Family, Profile, SETUP_ERROR_BITS, SETUP_FHE_CARRY_BITS,
    SETUP_QUOTIENT_BITS,
};

#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    Shape,
    Encoding,
}

/// A committed digit is minus the other terms of its bounded FHE limb row.
pub fn limb_magnitude_bound(profile: Profile) -> u128 {
    let radix = 1u128 << FHE_LIMB_BITS;
    let rest = FHE_SECRET_SUPPORT as u128 * (radix - 1)
        + (radix - 1)
        + (1u128 << SETUP_QUOTIENT_BITS) * (radix - 1)
        + (1u128 << SETUP_FHE_CARRY_BITS) * radix
        + (1u128 << SETUP_FHE_CARRY_BITS)
        + (1u128 << SETUP_ERROR_BITS);
    rest * profile.setup_contributors() as u128
}

fn signed_width(magnitude: u128) -> usize {
    (129 - magnitude.leading_zeros() as usize).div_ceil(8)
}

pub fn generated_limb_bytes(profile: Profile) -> usize {
    signed_width(profile.setup_contributors() as u128 * ((1u128 << FHE_LIMB_BITS) - 1))
}

pub fn maximum_limb_bytes(profile: Profile) -> usize {
    signed_width(limb_magnitude_bound(profile))
}

fn read_signed(bytes: &[u8]) -> i128 {
    let mut padded = [if bytes[bytes.len() - 1] & 128 == 0 {
        0
    } else {
        255
    }; 16];
    padded[..bytes.len()].copy_from_slice(bytes);
    i128::from_le_bytes(padded)
}

fn write_signed(value: i128, bytes: &mut [u8]) -> Result<(), Refusal> {
    let encoded = value.to_le_bytes();
    let sign = if value < 0 { 255 } else { 0 };
    if encoded[bytes.len()..].iter().any(|byte| *byte != sign)
        || (encoded[bytes.len() - 1] & 128 != 0) != (value < 0)
    {
        return Err(Refusal::Encoding);
    }
    bytes.copy_from_slice(&encoded[..bytes.len()]);
    Ok(())
}

pub fn field_value(value: i128) -> u128 {
    if value < 0 {
        MODULUS - value.unsigned_abs()
    } else {
        value as u128
    }
}

pub struct LimbSumCodec {
    limbs: usize,
    width: usize,
    bound: u128,
    modulus: BigInt,
    centered: CenteredCodec,
}

impl LimbSumCodec {
    pub fn new(profile: Profile, width: usize) -> Result<Self, Refusal> {
        if !(generated_limb_bytes(profile)..=maximum_limb_bytes(profile)).contains(&width) {
            return Err(Refusal::Shape);
        }
        let bytes = profile.family_modulus(Family::Fhe);
        Ok(Self {
            limbs: profile.fhe_limbs(),
            width,
            bound: limb_magnitude_bound(profile),
            modulus: BigInt::from_bytes_le(Sign::Plus, &bytes),
            centered: CenteredCodec::new(&bytes),
        })
    }

    pub fn record_bytes(&self) -> usize {
        self.limbs * self.width
    }
    pub fn centered_record_bytes(&self) -> usize {
        self.centered.record_bytes()
    }

    pub fn decode(&self, record: &[u8], values: &mut [i128]) -> Result<(), Refusal> {
        if record.len() != self.record_bytes() || values.len() != self.limbs {
            return Err(Refusal::Shape);
        }
        for (bytes, value) in record.chunks_exact(self.width).zip(values) {
            *value = read_signed(bytes);
            if value.unsigned_abs() > self.bound {
                return Err(Refusal::Encoding);
            }
        }
        Ok(())
    }

    pub fn normalize(&self, values: &[i128], output: &mut [u8]) -> Result<(), Refusal> {
        if values.len() != self.limbs
            || output.len() != self.centered.record_bytes()
            || values.iter().any(|value| value.unsigned_abs() > self.bound)
        {
            return Err(Refusal::Shape);
        }
        let mut value = BigInt::from(0);
        for limb in values.iter().rev() {
            value = (value << FHE_LIMB_BITS) + BigInt::from(*limb);
        }
        value %= &self.modulus;
        let half = &self.modulus >> 1usize;
        if value > half {
            value -= &self.modulus;
        } else if value < -half {
            value += &self.modulus;
        }
        coefficient::encode(&value, output);
        Ok(())
    }

    /// Adds canonical source coefficients to the previous unnormalized sums.
    pub fn add_records(&self, incoming: &[u8], output: &mut [u8]) -> Result<(), Refusal> {
        let source_width = self.centered.record_bytes();
        if incoming.is_empty()
            || incoming.len() > crate::CHUNK_BYTES
            || !incoming.len().is_multiple_of(source_width)
            || output.len() != incoming.len() / source_width * self.record_bytes()
        {
            return Err(Refusal::Shape);
        }
        for (record, sum) in incoming
            .chunks_exact(source_width)
            .zip(output.chunks_exact_mut(self.record_bytes()))
        {
            if !self.centered.is_canonical(record) {
                return Err(Refusal::Encoding);
            }
            for (limb, destination) in sum.chunks_exact_mut(self.width).enumerate() {
                let previous = read_signed(destination);
                if previous.unsigned_abs() > self.bound {
                    return Err(Refusal::Encoding);
                }
                let start = 1 + limb * (FHE_LIMB_BITS / 8);
                let mut bytes = [0; 16];
                let count = (FHE_LIMB_BITS / 8).min(record.len() - start);
                bytes[..count].copy_from_slice(&record[start..start + count]);
                let incoming = u128::from_le_bytes(bytes) as i128;
                let value = previous + if record[0] == 1 { -incoming } else { incoming };
                if value.unsigned_abs() > self.bound {
                    return Err(Refusal::Encoding);
                }
                write_signed(value, destination)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_profile_lifts_sums_without_field_wrap() {
        for profile in Profile::all() {
            assert!(2 * limb_magnitude_bound(profile) < MODULUS);
            assert_eq!(generated_limb_bytes(profile), 13);
            assert!(maximum_limb_bytes(profile) <= 15);
        }
    }

    #[test]
    fn unnormalized_sums_match_independent_integer_residues() {
        for profile in [
            Profile::new(3, 2).unwrap(),
            Profile::new(10, 10).unwrap(),
            Profile::new(20, 20).unwrap(),
        ] {
            let codec = LimbSumCodec::new(profile, generated_limb_bytes(profile)).unwrap();
            let half = &codec.modulus >> 1usize;
            let values = [
                BigInt::from(0),
                BigInt::from(-1),
                BigInt::from(1),
                &half - 1,
                -half,
                BigInt::from(1) << 96usize,
            ];
            let mut output = vec![0; values.len() * codec.record_bytes()];
            let mut expected = vec![BigInt::from(0); values.len()];
            for contributor in 0..profile.setup_contributors() {
                let mut incoming = vec![0; values.len() * codec.centered_record_bytes()];
                for (position, record) in incoming
                    .chunks_exact_mut(codec.centered_record_bytes())
                    .enumerate()
                {
                    let value = &values[(position + contributor) % values.len()];
                    coefficient::encode(value, record);
                    expected[position] += value;
                }
                codec.add_records(&incoming, &mut output).unwrap();
            }
            let mut limbs = vec![0; profile.fhe_limbs()];
            let mut normalized = vec![0; codec.centered_record_bytes()];
            for (record, expected) in output.chunks_exact(codec.record_bytes()).zip(expected) {
                codec.decode(record, &mut limbs).unwrap();
                codec.normalize(&limbs, &mut normalized).unwrap();
                let actual = codec.centered.decode(&normalized).unwrap();
                assert_eq!((&actual - expected) % &codec.modulus, BigInt::from(0));
            }
        }
    }

    #[test]
    fn refuses_width_length_and_magnitude_overflows() {
        let profile = Profile::new(20, 20).unwrap();
        assert!(LimbSumCodec::new(profile, generated_limb_bytes(profile) - 1).is_err());
        assert!(LimbSumCodec::new(profile, maximum_limb_bytes(profile) + 1).is_err());
        let codec = LimbSumCodec::new(profile, maximum_limb_bytes(profile)).unwrap();
        let mut limbs = vec![0; profile.fhe_limbs()];
        let mut record = vec![0; codec.record_bytes()];
        write_signed((codec.bound + 1) as i128, &mut record[..codec.width]).unwrap();
        assert_eq!(codec.decode(&record, &mut limbs), Err(Refusal::Encoding));
        assert_eq!(
            codec.decode(&record[..record.len() - 1], &mut limbs),
            Err(Refusal::Shape)
        );
    }
}
