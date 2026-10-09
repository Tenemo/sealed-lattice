use super::*;
use zeroize::ZeroizeOnDrop;

#[test]
fn retained_key_rejects_changed_secret_with_the_same_support() {
    let mut key = RegistrationKey::new();
    key.validate_retained().unwrap();
    let positive = key.secret.iter().position(|value| *value == 1).unwrap();
    let zero = key.secret.iter().position(|value| *value == 0).unwrap();
    key.secret.swap(positive, zero);
    assert!(key.validate_retained().is_err());
}

// Accepts only a value that zeroizes when it is dropped.
fn zeroizes_on_drop<T: ZeroizeOnDrop>(_: &T) {}

#[test]
fn lends_a_copy_of_the_secret_that_zeroizes_when_dropped() {
    let key = RegistrationKey::new();
    zeroizes_on_drop(&key.secret);
    let same = key
        .lend_secret(|secret| {
            zeroizes_on_drop(&secret);
            secret
                .iter()
                .copied()
                .eq(key.secret.iter().copied().map(i128::from))
        })
        .unwrap();
    assert!(same);
}

#[test]
fn lends_nothing_from_a_key_that_fails_its_check() {
    let mut key = RegistrationKey::new();
    let positive = key.secret.iter().position(|value| *value == 1).unwrap();
    let zero = key.secret.iter().position(|value| *value == 0).unwrap();
    key.secret.swap(positive, zero);
    assert!(
        key.lend_secret(|_| panic!("A key that fails its check lent its secret."))
            .is_err()
    );
}
