use super::*;
#[test]
fn sealed_keys_restore_without_resealing_authority() {
    let mut original = RegistrationKey::new();
    let context: &[u8] = b"registration/context";
    let sealed = original.seal_retained(context).unwrap();
    assert_eq!(sealed.bytes.len(), SEALED_BYTES);
    assert!(original.seal_retained(context).is_err());
    let open = RegistrationKey::open_retained;
    let mut restored = open(original.public.clone(), &sealed.key, context, &sealed.bytes).unwrap();
    assert_eq!(*original.secret, *restored.secret);
    assert!(restored.seal_retained(context).is_err());
    let mut changed = sealed.bytes.clone();
    changed[32] ^= 1;
    assert!(open(original.public.clone(), &sealed.key, context, &changed).is_err());
    assert!(
        open(
            original.public.clone(),
            &sealed.key,
            b"other/context",
            &sealed.bytes
        )
        .is_err()
    );
    assert!(open(original.public.clone(), &[8; 32], context, &sealed.bytes).is_err());
    assert!(
        open(
            original.public.clone(),
            &sealed.key,
            context,
            &sealed.bytes[..SEALED_BYTES - 1]
        )
        .is_err()
    );
    let mut changed_public = original.public.clone();
    changed_public[0] += 1024;
    assert!(open(changed_public, &sealed.key, context, &sealed.bytes).is_err());
}
