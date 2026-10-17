//! Canonical FHE coefficient records split into their signed radix limbs.
//! The columns are coefficient polynomials, without interpolation or masks.
use crate::{CHUNK_LIMIT, Refusal, coefficient::CenteredCodec, limb_value, proof_field};
use supported_profile::{DEGREE, FHE_LIMB_BITS, Family, Profile};

pub struct CommittedPolynomial {
    codec: CenteredCodec,
    columns: Vec<Vec<u128>>,
    record: Vec<u8>,
    used: usize,
    coefficients: usize,
    degree: usize,
    failed: bool,
}

impl CommittedPolynomial {
    pub fn new(profile: Profile) -> Self {
        Self::with_modulus(&profile.family_modulus(Family::Fhe), DEGREE)
    }

    fn with_modulus(modulus: &[u8], degree: usize) -> Self {
        Self {
            codec: CenteredCodec::new(modulus),
            columns: (0..(8 * modulus.len()).div_ceil(FHE_LIMB_BITS))
                .map(|_| Vec::with_capacity(degree))
                .collect(),
            record: vec![0; 1 + modulus.len()],
            used: 0,
            coefficients: 0,
            degree,
            failed: false,
        }
    }

    pub fn push(&mut self, mut bytes: &[u8]) -> Result<(), Refusal> {
        if self.failed {
            return Err(Refusal::Encoding);
        }
        if bytes.len() > CHUNK_LIMIT
            || bytes.len() > (self.degree - self.coefficients) * self.record.len() - self.used
        {
            self.failed = true;
            return Err(Refusal::Length);
        }
        while !bytes.is_empty() {
            let count = bytes.len().min(self.record.len() - self.used);
            self.record[self.used..self.used + count].copy_from_slice(&bytes[..count]);
            self.used += count;
            bytes = &bytes[count..];
            if self.used != self.record.len() {
                continue;
            }
            if !self.codec.is_canonical(&self.record) {
                self.failed = true;
                return Err(Refusal::Encoding);
            }
            for (limb, column) in self.columns.iter_mut().enumerate() {
                let value = limb_value(&self.record[1..], limb, FHE_LIMB_BITS);
                column.push(if self.record[0] == 1 && value != 0 {
                    proof_field::MODULUS - value
                } else {
                    value
                });
            }
            self.used = 0;
            self.coefficients += 1;
        }
        Ok(())
    }

    pub fn finish(self) -> Result<Vec<Vec<u128>>, Refusal> {
        if self.failed {
            return Err(Refusal::Encoding);
        }
        if self.coefficients != self.degree || self.used != 0 {
            return Err(Refusal::Incomplete);
        }
        Ok(self.columns)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PolynomialStream, ZERO, coefficient, plus, power, times};
    use num_bigint::BigInt;

    fn fixture() -> (Vec<u8>, Vec<BigInt>, Vec<u8>) {
        let modulus = (BigInt::from(1) << 203usize) - BigInt::from(9);
        let values = vec![
            BigInt::from(0),
            BigInt::from(-1),
            (BigInt::from(1) << 96usize) - BigInt::from(1),
            -((BigInt::from(1) << 193usize) + BigInt::from(7)),
            &modulus >> 1usize,
            -(&modulus >> 1usize),
            BigInt::from(1) << 96usize,
            BigInt::from(1) << 192usize,
        ];
        let modulus = modulus.to_bytes_le().1;
        let mut bytes = Vec::new();
        for value in &values {
            let mut record = vec![0; modulus.len() + 1];
            coefficient::encode(value, &mut record);
            bytes.extend(record);
        }
        (modulus, values, bytes)
    }

    #[test]
    fn signed_columns_reconstruct_values_and_the_statement_fingerprint() {
        let (modulus, values, bytes) = fixture();
        let alpha = [17, 23, 41];
        for chunk in [1, 13, 27, 53, bytes.len()] {
            let mut parser = CommittedPolynomial::with_modulus(&modulus, values.len());
            let mut statement = PolynomialStream::new(&modulus, values.len(), 96, alpha).unwrap();
            for bytes in bytes.chunks(chunk) {
                parser.push(bytes).unwrap();
                statement.push(bytes).unwrap();
            }
            let columns = parser.finish().unwrap();
            for (position, expected) in values.iter().enumerate() {
                let mut actual = BigInt::from(0);
                for (limb, column) in columns.iter().enumerate() {
                    let value = column[position];
                    let signed = if value > proof_field::MODULUS / 2 {
                        -BigInt::from(proof_field::MODULUS - value)
                    } else {
                        BigInt::from(value)
                    };
                    actual += signed << (96 * limb);
                }
                assert_eq!(&actual, expected);
            }
            let mut fingerprint = ZERO;
            for (limb, column) in columns.iter().enumerate() {
                let value = column.iter().rev().fold(ZERO, |sum, coefficient| {
                    plus(times(sum, alpha), [*coefficient, 0, 0])
                });
                fingerprint = plus(fingerprint, times(value, power(alpha, limb * values.len())));
            }
            assert_eq!(fingerprint, statement.finish_value().unwrap());
        }
    }

    #[test]
    fn incomplete_noncanonical_and_excess_records_never_finish() {
        let (modulus, values, bytes) = fixture();
        for length in [0, 1, bytes.len() - 1] {
            let mut parser = CommittedPolynomial::with_modulus(&modulus, values.len());
            parser.push(&bytes[..length]).unwrap();
            assert!(parser.finish().is_err());
        }
        for malformed in [
            {
                let mut changed = bytes.clone();
                changed[0] = 1;
                changed
            },
            {
                let mut changed = bytes.clone();
                changed[0] = 2;
                changed
            },
            {
                let mut changed = bytes.clone();
                changed[1..1 + modulus.len()].copy_from_slice(&modulus);
                changed
            },
            {
                let mut changed = bytes.clone();
                changed.push(0);
                changed
            },
        ] {
            let mut parser = CommittedPolynomial::with_modulus(&modulus, values.len());
            assert!(parser.push(&malformed).is_err());
            assert!(parser.push(&bytes).is_err());
            assert!(parser.finish().is_err());
        }
    }
}
