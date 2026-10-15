use super::*;
#[test]
fn exact_target_owner_and_signature_context_are_required() {
    let mut key = purpose_signature::Credential::new([19; 64]);
    let keys = [key.public_key()];
    let target = [23; 64];
    let signature = key.sign_context(CERTIFICATION_CONTEXT, &target).unwrap();
    let mut packet = Vec::from(0u16.to_le_bytes());
    packet.extend(target);
    packet.extend(signature);
    assert_eq!(
        authenticate_vote(&target, &keys, &packet).unwrap().encode(),
        packet
    );
    assert!(matches!(
        authenticate_vote(&[24; 64], &keys, &packet),
        Err(Refusal::Context)
    ));
    let mut changed = packet.clone();
    changed[0] = 1;
    assert!(matches!(
        authenticate_vote(&target, &keys, &changed),
        Err(Refusal::Context)
    ));
    // A vote relabeled with another roster position fails under that
    // position's key.
    let other = purpose_signature::Credential::new([20; 64]);
    let roster = [keys[0], other.public_key()];
    assert!(matches!(
        authenticate_vote(&target, &roster, &changed),
        Err(Refusal::Signature)
    ));
    let mut changed = packet.clone();
    changed[100] ^= 1;
    assert!(matches!(
        authenticate_vote(&target, &keys, &changed),
        Err(Refusal::Signature)
    ));
    let signature = key
        .sign_context(b"sealed-lattice/close-response", &target)
        .unwrap();
    let mut changed = packet;
    changed[66..].copy_from_slice(&signature);
    assert!(matches!(
        authenticate_vote(&target, &keys, &changed),
        Err(Refusal::Signature)
    ));
}
