use super::*;
use fips204::traits::{KeyGen, Signer};
#[test]
fn exact_target_owner_and_signature_context_are_required() {
    let (public, key) = ml_dsa_65::KG::keygen_from_seed(&[19; 32]);
    let keys = [public.into_bytes()];
    let target = [23; 64];
    let signature = key
        .try_sign_with_seed(&[31; 32], &target, CERTIFICATION_CONTEXT)
        .unwrap();
    let mut packet = Vec::from(0u16.to_le_bytes());
    packet.extend(target);
    packet.extend(signature);
    assert_eq!(
        authenticate_vote(&target, &keys, &packet).unwrap().encode(),
        packet
    );
    assert!(matches!(
        authenticate_vote(&[24; 64], &keys, &packet),
        Err(Error::Context)
    ));
    let mut changed = packet.clone();
    changed[0] = 1;
    assert!(matches!(
        authenticate_vote(&target, &keys, &changed),
        Err(Error::Context)
    ));
    // A vote relabeled with another roster position fails under that
    // position's key.
    let (other, _) = ml_dsa_65::KG::keygen_from_seed(&[20; 32]);
    let roster = [keys[0], other.into_bytes()];
    assert!(matches!(
        authenticate_vote(&target, &roster, &changed),
        Err(Error::Signature)
    ));
    let mut changed = packet.clone();
    changed[100] ^= 1;
    assert!(matches!(
        authenticate_vote(&target, &keys, &changed),
        Err(Error::Signature)
    ));
    let signature = key
        .try_sign_with_seed(&[31; 32], &target, b"sealed-lattice/close-response/v1")
        .unwrap();
    let mut changed = packet;
    changed[66..].copy_from_slice(&signature);
    assert!(matches!(
        authenticate_vote(&target, &keys, &changed),
        Err(Error::Signature)
    ));
}
