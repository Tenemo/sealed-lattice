//! The suite's public auxiliary encryption pair. Neither coordinate depends
//! on a poll, roster or contributor, and no participant holds its secret key.

use crate::{
    common_polynomial::{public_polynomial, public_records},
    integer,
};
use num_bigint::BigInt;
use supported_profile::{AUXILIARY_DEGREE, auxiliary_modulus, fixed_common_sample_bits};

fn polynomial(label: &str) -> Vec<BigInt> {
    public_polynomial(
        label,
        AUXILIARY_DEGREE,
        &integer(auxiliary_modulus()),
        fixed_common_sample_bits(),
    )
}

fn records(label: &str) -> Vec<u8> {
    public_records(
        label,
        AUXILIARY_DEGREE,
        auxiliary_modulus(),
        fixed_common_sample_bits(),
    )
}

pub fn common_polynomial() -> Vec<BigInt> {
    polynomial("common-auxiliary")
}

pub fn public_key() -> Vec<BigInt> {
    polynomial("common-auxiliary-key")
}

pub fn common_records() -> Vec<u8> {
    records("common-auxiliary")
}

pub fn public_key_records() -> Vec<u8> {
    records("common-auxiliary-key")
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::Sign;
    use sha3::{
        Shake256,
        digest::{ExtendableOutput, Update, XofReader},
    };

    #[test]
    fn both_complete_streams_match_independent_sampling_and_canonical_records() {
        let modulus = integer(auxiliary_modulus());
        let half = &modulus >> 1usize;
        let width = 1 + auxiliary_modulus().len();
        let common = common_polynomial();
        let key = public_key();
        assert_ne!(common, key);
        for (label, values, records) in [
            ("common-auxiliary", common, common_records()),
            ("common-auxiliary-key", key, public_key_records()),
        ] {
            let mut hash = Shake256::default();
            hash.update(b"synthetic-full-setup-witness/1");
            hash.update(&(label.len() as u32).to_le_bytes());
            hash.update(label.as_bytes());
            let mut stream = hash.finalize_xof();
            let mut sample = vec![0; fixed_common_sample_bits() / 8];
            assert_eq!(values.len(), AUXILIARY_DEGREE);
            assert_eq!(records.len(), AUXILIARY_DEGREE * width);
            for (value, record) in values.iter().zip(records.chunks_exact(width)) {
                stream.read(&mut sample);
                let residue = BigInt::from_bytes_le(Sign::Plus, &sample) % &modulus;
                let expected = if residue > half {
                    residue - &modulus
                } else {
                    residue
                };
                assert_eq!(*value, expected);
                assert!(record[0] <= 1);
                let magnitude = BigInt::from_bytes_le(Sign::Plus, &record[1..]);
                assert!(magnitude <= half);
                assert!(record[0] == 0 || magnitude != BigInt::from(0));
                let decoded = if record[0] == 0 {
                    magnitude
                } else {
                    -magnitude
                };
                assert_eq!(decoded, expected);
            }
        }
    }
}
