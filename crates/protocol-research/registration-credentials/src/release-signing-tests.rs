use super::*;
use crate::foundation::{CanonicalItem, hash_foundation_tuple_512};

fn context(position: usize) -> [u8; RELEASE_HEADER_BYTES] {
    let mut context = [0; RELEASE_HEADER_BYTES];
    context[..4].copy_from_slice(b"LRS1");
    context[4..68].fill(1);
    context[68..132].fill(2);
    context[132..196].fill(3);
    context[196..].copy_from_slice(&(position as u16).to_le_bytes());
    context
}
#[test]
fn release_framing_bounds_context_and_exact_body_length() {
    for (participants, options) in [(3, 2), (20, 20)] {
        let profile = Profile::new(participants, options).unwrap();
        let last = participants - 1;
        let bodies = body_lengths(profile);
        for length in [*bodies.start(), *bodies.end()] {
            let envelope =
                ReleaseEnvelope::new(profile, [1; 64], [2; 64], [3; 64], last, length, [4; 64])
                    .unwrap();
            assert_eq!(
                ReleaseEnvelope::decode(profile, envelope.bytes())
                    .unwrap()
                    .bytes(),
                envelope.bytes()
            );
            assert!(
                ReleaseEnvelope::decode(profile, &envelope.bytes()[..RELEASE_ENVELOPE_BYTES - 1])
                    .is_err()
            );
            let mut excess = envelope.bytes().to_vec();
            excess.push(0);
            assert!(ReleaseEnvelope::decode(profile, &excess).is_err());
            let mut changed = envelope.bytes().to_vec();
            changed[196..198].copy_from_slice(&(participants as u16).to_le_bytes());
            assert!(ReleaseEnvelope::decode(profile, &changed).is_err());
            changed = envelope.bytes().to_vec();
            changed[198..206].copy_from_slice(&u64::MAX.to_le_bytes());
            assert!(ReleaseEnvelope::decode(profile, &changed).is_err());
        }
        for length in [bodies.start() - 1, bodies.end() + 1, usize::MAX] {
            assert!(
                ReleaseEnvelope::new(profile, [1; 64], [2; 64], [3; 64], 0, length, [4; 64])
                    .is_err()
            );
            assert!(ReleaseBodyHasher::new(profile, length).is_err());
        }
        let proofs = proof_lengths(profile);
        for length in [*proofs.start(), *proofs.end()] {
            let bytes = body_header(profile, &context(last), length).unwrap();
            assert_eq!(proof_length(profile, &bytes).unwrap(), length);
            let mut changed = bytes.clone();
            changed.push(0);
            assert!(proof_length(profile, &changed).is_err());
            assert!(proof_length(profile, &bytes[..bytes.len() - 1]).is_err());
            for offset in [0, 12] {
                let mut changed = bytes.clone();
                changed[offset] ^= 1;
                assert!(proof_length(profile, &changed).is_err());
            }
        }
        for length in [proofs.start() - 1, proofs.end() + 1, usize::MAX] {
            assert!(body_header(profile, &context(last), length).is_err());
        }
        assert!(body_header(profile, &context(participants), *proofs.start()).is_err());
    }
    // A three-participant header names no position of another roster's
    // last participant, and every release body carries a 25-byte
    // coefficient per row of the completion profile's partial.
    let small = Profile::new(3, 2).unwrap();
    let wide = Profile::new(20, 20).unwrap();
    let header = body_header(wide, &context(19), PROOF_HEADER_BYTES).unwrap();
    assert!(proof_length(small, &header).is_err());
    assert_eq!(partial_bytes(Profile::new(10, 10).unwrap()), 65_536 * 25);
}
#[test]
fn release_digest_matches_canonical_hash_across_chunk_boundaries() {
    let profile = Profile::new(3, 2).unwrap();
    let partial = partial_bytes(profile);
    let mut body = body_header(profile, &context(0), PROOF_HEADER_BYTES).unwrap();
    body.extend((0..partial + PROOF_HEADER_BYTES).map(|index| (index % 251) as u8));
    let expected = hash_foundation_tuple_512(
        "sealed-lattice/release-body/v1",
        &[CanonicalItem::variable_bytes(&body).unwrap()],
    )
    .unwrap()
    .into_bytes();
    for chunk_size in [4093, 1 << 20] {
        let mut hasher = ReleaseBodyHasher::new(profile, body.len()).unwrap();
        for chunk in body.chunks(chunk_size) {
            hasher.push(chunk).unwrap();
        }
        assert_eq!(hasher.finish().unwrap(), expected);
    }
    let mut changed = body.clone();
    changed[RELEASE_BODY_HEADER_BYTES + partial - 1] ^= 1;
    let mut hasher = ReleaseBodyHasher::new(profile, changed.len()).unwrap();
    for chunk in changed.chunks(1 << 20) {
        hasher.push(chunk).unwrap();
    }
    assert_ne!(hasher.finish().unwrap(), expected);
    let mut hasher = ReleaseBodyHasher::new(profile, body.len()).unwrap();
    for chunk in body.chunks(1 << 20) {
        hasher.push(chunk).unwrap();
    }
    assert!(hasher.push(&[0]).is_err());
    assert!(hasher.finish().is_err());
    for invalid in [Vec::new(), vec![0; (1 << 20) + 1]] {
        let mut hasher = ReleaseBodyHasher::new(profile, body.len()).unwrap();
        assert!(hasher.push(&invalid).is_err());
        assert!(hasher.finish().is_err());
    }
    assert!(
        ReleaseBodyHasher::new(profile, body.len())
            .unwrap()
            .finish()
            .is_err()
    );
}
