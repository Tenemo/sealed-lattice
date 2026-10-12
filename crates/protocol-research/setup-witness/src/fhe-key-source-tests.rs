use super::*;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update},
};

fn source(profile: Profile, seed: u8) -> FheKeySource {
    let mut hash = Shake256::default();
    hash.update(&[seed; 64]);
    FheKeySource::from_reader(profile, &mut hash.finalize_xof())
}

#[test]
fn explicit_reader_reproduces_both_original_private_operands() {
    let profile = Profile::new(3, 2).unwrap();
    let first = source(profile, 7);
    let repeated = source(profile, 7);
    let different = source(profile, 11);
    assert!(first.secret == repeated.secret);
    assert!(first.error == repeated.error);
    assert!(first.secret != different.secret);
    assert!(first.error != different.error);
    assert_eq!(first.secret.len(), DEGREE);
    for sign in [-1, 1] {
        assert_eq!(
            first.secret.iter().filter(|value| **value == sign).count(),
            FHE_SECRET_SUPPORT / 2
        );
    }
    assert!(first.secret.iter().all(|value| (-1..=1).contains(value)));
    assert_eq!(first.error.len(), DEGREE);
    assert!(first.error.iter().all(|value| (-64..64).contains(value)));
}

#[test]
fn wrong_modulus_or_common_sampler_width_refuses_before_continuation() {
    let profile = Profile::new(3, 2).unwrap();
    let original = source(profile, 7);
    let modulus = profile.ciphertext_modulus().to_bytes();
    assert!(original.matches_family(&modulus, profile.fhe_common_sample_bits()));
    assert!(!original.matches_family(&modulus, profile.fhe_common_sample_bits() + 8));
    let mut changed_modulus = modulus;
    changed_modulus[0] ^= 2;
    assert!(!original.matches_family(&changed_modulus, profile.fhe_common_sample_bits()));

    let other = Profile::all()
        .find(|candidate| candidate.ciphertext_modulus() != profile.ciphertext_modulus())
        .unwrap();
    assert!(matches!(
        contribution::Contribution::from_source(other, original),
        Err(contribution::Error::SourceFamily)
    ));
}
