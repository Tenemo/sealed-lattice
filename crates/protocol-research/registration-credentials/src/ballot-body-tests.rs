use super::*;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
fn context(profile: Profile) -> Vec<u8> {
    let mut context = vec![0; CONTEXT_BYTES];
    context[..4].copy_from_slice(b"LBS1");
    context[132..134].copy_from_slice(&(profile.participants() as u16 - 1).to_le_bytes());
    context[134] = profile.options() as u8;
    context[135] = profile.options() as u8;
    context
}
#[test]
fn framing_refuses_contexts_and_proof_lengths_outside_the_profile() {
    for (participants, options) in [(3, 2), (10, 10), (20, 20)] {
        let profile = Profile::new(participants, options).unwrap();
        let proofs = proof_lengths(profile);
        let context = context(profile);
        for length in [*proofs.start(), *proofs.end()] {
            let bytes = header(profile, &context, length).unwrap();
            assert_eq!(proof_length(profile, &bytes).unwrap(), length);
        }
        for length in [proofs.start() - 1, proofs.end() + 1, usize::MAX] {
            assert!(header(profile, &context, length).is_err());
        }
        let mut changed = context.clone();
        changed[135] = options as u8 + 1;
        assert!(header(profile, &changed, *proofs.start()).is_err());
        changed[135] = 0;
        assert!(header(profile, &changed, *proofs.start()).is_err());
        changed = context.clone();
        changed[134] = options as u8 - 1;
        changed[135] = 1;
        assert!(header(profile, &changed, *proofs.start()).is_err());
        changed = context.clone();
        changed[132..134].copy_from_slice(&(participants as u16).to_le_bytes());
        assert!(header(profile, &changed, *proofs.start()).is_err());
        // A header of another option count is refused by this profile.
        let other = Profile::new(participants, if options == 2 { 3 } else { 2 }).unwrap();
        let bytes = header(profile, &context, *proofs.start()).unwrap();
        assert!(proof_length(other, &bytes).is_err());
    }
    // The completion profile's body model: two FHE components of 108
    // magnitude bytes and two auxiliary components of 5.
    let completion = Profile::new(10, 10).unwrap();
    assert_eq!(
        ciphertext_bytes(completion),
        2 * 65_536 * 109 + 2 * 4_096 * 6
    );
    assert_eq!(*proof_lengths(completion).end(), 11_105_120);
}
#[test]
fn incomplete_oversized_and_excess_streams_cannot_return_a_digest() {
    let profile = Profile::new(3, 2).unwrap();
    let header = header(profile, &context(profile), PROOF_HEADER_BYTES).unwrap();
    assert!(
        header_body_hasher(profile, &header)
            .unwrap()
            .finish()
            .is_err()
    );
    let mut hasher = header_body_hasher(profile, &header).unwrap();
    assert!(hasher.push(&vec![0; (1 << 20) + 1]).is_err());
    assert!(hasher.finish().is_err());
    let mut hasher = header_body_hasher(profile, &header).unwrap();
    let mut body = header.clone();
    body.extend((0..ciphertext_bytes(profile) + PROOF_HEADER_BYTES).map(|index| index as u8));
    for part in body[header.len()..].chunks(1 << 20) {
        hasher.push(part).unwrap();
    }
    assert!(hasher.push(&[0]).is_err());
    assert!(hasher.finish().is_err());
    let lengths = body_lengths(profile);
    for length in [lengths.start() - 1, lengths.end() + 1] {
        assert!(body_hasher(profile, length).is_err());
    }
}
#[test]
fn body_digest_matches_the_framed_shake256_across_part_boundaries() {
    let profile = Profile::new(3, 2).unwrap();
    let mut body = header(profile, &context(profile), PROOF_HEADER_BYTES).unwrap();
    body.extend(
        (0..ciphertext_bytes(profile) + PROOF_HEADER_BYTES).map(|index| (index % 251) as u8),
    );
    // SHAKE256 over the canonical tuple of the domain text and the body as
    // one raw-byte item: schema, version and item count, then each item's
    // type, length and length-prefixed bytes.
    let domain = BODY_DOMAIN.as_bytes();
    let mut sponge = Shake256::default();
    for part in [
        &0x0001_u16.to_le_bytes()[..],
        &1_u16.to_le_bytes(),
        &2_u32.to_le_bytes(),
        &0x02_u16.to_le_bytes(),
        &(domain.len() as u32 + 4).to_le_bytes(),
        &(domain.len() as u32).to_le_bytes(),
        domain,
        &0x01_u16.to_le_bytes(),
        &(body.len() as u32 + 4).to_le_bytes(),
        &(body.len() as u32).to_le_bytes(),
        &body,
    ] {
        sponge.update(part);
    }
    let mut expected = [0; 64];
    sponge.finalize_xof().read(&mut expected);
    for part_size in [4093, 1 << 20] {
        let mut hasher = header_body_hasher(profile, &body[..HEADER_BYTES]).unwrap();
        for part in body[HEADER_BYTES..].chunks(part_size) {
            hasher.push(part).unwrap();
        }
        assert_eq!(hasher.finish().unwrap(), expected);
    }
}
