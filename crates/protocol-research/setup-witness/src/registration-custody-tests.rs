use super::*;
#[test]
fn sealed_keys_restore_without_resealing_authority() {
    let mut original = RegistrationKey::new();
    let key = [7; 32];
    let sealed = original
        .seal_retained(&key, b"registration/context")
        .unwrap();
    assert_eq!(sealed.len(), SEALED_BYTES);
    assert!(
        original
            .seal_retained(&key, b"registration/context")
            .is_err()
    );
    let mut restored = RegistrationKey::open_retained(
        original.public.clone(),
        &key,
        b"registration/context",
        &sealed,
    )
    .unwrap();
    assert_eq!(*original.secret, *restored.secret);
    assert!(
        restored
            .seal_retained(&key, b"registration/context")
            .is_err()
    );
    let mut changed = sealed.clone();
    changed[32] ^= 1;
    assert!(
        RegistrationKey::open_retained(
            original.public.clone(),
            &key,
            b"registration/context",
            &changed
        )
        .is_err()
    );
    assert!(
        RegistrationKey::open_retained(original.public.clone(), &key, b"other/context", &sealed)
            .is_err()
    );
    assert!(
        RegistrationKey::open_retained(
            original.public.clone(),
            &[8; 32],
            b"registration/context",
            &sealed
        )
        .is_err()
    );
    assert!(
        RegistrationKey::open_retained(
            original.public.clone(),
            &key,
            b"registration/context",
            &sealed[..SEALED_BYTES - 1]
        )
        .is_err()
    );
    let mut changed_public = original.public.clone();
    changed_public[0] += 1024;
    assert!(
        RegistrationKey::open_retained(changed_public, &key, b"registration/context", &sealed)
            .is_err()
    );
}
