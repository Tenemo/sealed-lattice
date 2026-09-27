use num_bigint::{BigInt, Sign};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

pub(crate) fn public_reader(label: &str) -> impl XofReader + use<> {
    let mut state = Shake256::default();
    Update::update(&mut state, b"synthetic-full-setup-witness/1");
    Update::update(&mut state, &(label.len() as u32).to_le_bytes());
    Update::update(&mut state, label.as_bytes());
    state.finalize_xof()
}
// Each coefficient reduces one uniform little-endian sample of sample_bits
// to its centered residue. A sample is nonnegative, so its remainder is
// already the least residue.
pub(crate) fn public_polynomial(
    label: &str,
    degree: usize,
    modulus: &BigInt,
    sample_bits: usize,
) -> Vec<BigInt> {
    assert!(sample_bits.is_multiple_of(8));
    let mut random = public_reader(label);
    let mut bytes = vec![0u8; sample_bits / 8];
    let half = modulus >> 1usize;
    (0..degree)
        .map(|_| {
            random.read(&mut bytes);
            let value = BigInt::from_bytes_le(Sign::Plus, &bytes) % modulus;
            if value > half { value - modulus } else { value }
        })
        .collect()
}

#[cfg(test)]
mod tests {
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
}
