use super::*;
#[test]
fn retained_key_rejects_changed_secret_with_the_same_support() {
    let mut key = RegistrationKey::new();
    key.validate_retained().unwrap();
    let positive = key.secret.iter().position(|value| *value == 1).unwrap();
    let zero = key.secret.iter().position(|value| *value == 0).unwrap();
    key.secret.swap(positive, zero);
    assert!(key.validate_retained().is_err());
}
