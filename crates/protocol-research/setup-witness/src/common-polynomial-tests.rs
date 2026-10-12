use super::*;

// Each coefficient is the centered residue of its sample: the least
// nonnegative residue, less the modulus above half the modulus.
#[test]
fn coefficients_are_the_centered_residues_of_the_samples() {
    for (modulus, sample_bits) in [
        (vec![0x01, 0x00, 0x00, 0x10], 64),
        (supported_profile::auxiliary_modulus().to_vec(), 128),
        (supported_profile::share_modulus().to_vec(), 192),
    ] {
        let degree = 512;
        let modulus = BigInt::from_bytes_le(Sign::Plus, &modulus);
        let values = public_polynomial("centered-test", degree, &modulus, sample_bits);
        let mut random = public_reader("centered-test");
        let mut sample = vec![0u8; sample_bits / 8];
        let mut negatives = 0;
        for value in values {
            random.read(&mut sample);
            let sample = BigInt::from_bytes_le(Sign::Plus, &sample);
            let residue = (sample % &modulus + &modulus) % &modulus;
            let centered = if residue > (&modulus >> 1usize) {
                residue - &modulus
            } else {
                residue
            };
            negatives += usize::from(centered.sign() == Sign::Minus);
            assert_eq!(value, centered);
        }
        assert!(negatives > 0 && negatives < degree);
    }
}

// Each record is the canonical encoding of the coefficient in its
// position: a sign byte of zero or one, never a negative zero, and the
// magnitude in the modulus bytes.
#[test]
fn records_encode_the_coefficients_canonically() {
    for (modulus, sample_bits) in [
        (vec![0x01, 0x00, 0x00, 0x10], 64),
        (supported_profile::share_modulus().to_vec(), 192),
    ] {
        let degree = 512;
        let records = public_records("records-test", degree, &modulus, sample_bits);
        assert_eq!(records.len(), degree * (1 + modulus.len()));
        let integer = BigInt::from_bytes_le(Sign::Plus, &modulus);
        let values = public_polynomial("records-test", degree, &integer, sample_bits);
        for (record, value) in records.chunks_exact(1 + modulus.len()).zip(values) {
            let magnitude = BigUint::from_bytes_le(&record[1..]);
            assert!(record[0] == 0 || (record[0] == 1 && magnitude != BigUint::ZERO));
            let sign = if record[0] == 1 {
                Sign::Minus
            } else {
                Sign::Plus
            };
            assert_eq!(BigInt::from_biguint(sign, magnitude), value);
        }
    }
}
