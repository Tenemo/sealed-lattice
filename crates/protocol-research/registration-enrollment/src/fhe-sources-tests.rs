use super::*;
use registration_credentials::{
    foundation::{
        StabilizedDisplayText,
        ceremony::{Manifest, OptionDefinition},
    },
    poll::{PollDraft, verify_poll},
};
use sha3::digest::XofReader;

fn poll() -> (VerifiedPoll, Credential) {
    let text = |value: &str| StabilizedDisplayText::from_ingress_utf8(value.as_bytes()).unwrap();
    let options = (0..2)
        .map(|index| {
            OptionDefinition::new(
                index,
                format!("option-{index}"),
                text(&format!("Option {index}")),
            )
            .unwrap()
        })
        .collect();
    let draft = PollDraft::new(Manifest::new(text("Question"), options).unwrap(), 1, 3).unwrap();
    let mut credential = Credential::from_seed([19; 32]);
    let signed = credential.create_poll(draft, [7; 64], [11; 32]).unwrap();
    (
        verify_poll(signed.identity, [7; 64], &signed.body, &signed.signature).unwrap(),
        credential,
    )
}

#[test]
fn coordinate_hash_matches_canonical_coefficients_across_chunk_boundaries() {
    use num_bigint::Sign;
    use supported_profile::{DEGREE, Family};

    let (poll, credential) = poll();
    let profile = Profile::new(3, 2).unwrap();
    let modulus = BigInt::from_bytes_le(Sign::Plus, &profile.family_modulus(Family::Fhe));
    let half = &modulus >> 1usize;
    let samples = [
        -&half,
        half,
        BigInt::from(0),
        BigInt::from(1),
        BigInt::from(-1),
    ];
    let values: Vec<_> = (0..DEGREE)
        .map(|index| samples[index % samples.len()].clone())
        .collect();
    let width = profile.family_magnitude_bytes(Family::Fhe);
    let hasher = || {
        FheKeyCommitmentHasher::for_registration(&poll, &credential, profile, &[41; SALT_BYTES])
            .unwrap()
    };
    let mut output = CoordinateHash {
        hash: Some(hasher()),
        result: None,
    };
    output.polynomial(&values, &modulus, width);

    // Independent canonical conversion, delivered one coefficient at a
    // time instead of through the producer's reused fixed-size chunk.
    let mut expected = hasher();
    for (index, value) in values.iter().enumerate() {
        let (sign, magnitude) = value.to_bytes_le();
        let mut encoded = vec![0; 1 + width];
        encoded[0] = u8::from(sign == Sign::Minus);
        encoded[1..1 + magnitude.len()].copy_from_slice(&magnitude);
        expected.push(index * encoded.len(), &encoded).unwrap();
    }
    assert_eq!(output.result, Some(expected.finish().unwrap()));
}

#[test]
fn source_stream_matches_canonical_tuple_and_binds_each_original_context() {
    let profile = Profile::new(3, 2).unwrap();
    let owner = [23; SIGNING_PUBLIC_KEY_BYTES];
    let seed = [29; 64];
    let canonical = CanonicalTuple::new(
        1,
        1,
        vec![
            CanonicalItem::nonempty_ascii("sealed-lattice/fhe-source-randomness/v1").unwrap(),
            CanonicalItem::fixed_bytes(owner).unwrap(),
            CanonicalItem::hash512([3; 64]),
            CanonicalItem::hash512([5; 64]),
            CanonicalItem::variable_bytes(profile.ciphertext_modulus().to_bytes()).unwrap(),
            CanonicalItem::unsigned64(profile.fhe_common_sample_bits() as u64),
            CanonicalItem::fixed_bytes(seed).unwrap(),
        ],
    )
    .encode()
    .unwrap();
    let mut hash = Shake256::default();
    hash.update(&canonical);
    let mut expected = [0; 160];
    hash.finalize_xof().read(&mut expected);
    let output =
        |poll, runtime, owner: &[u8; SIGNING_PUBLIC_KEY_BYTES], profile, seed: &[u8; 64]| {
            let mut bytes = [0; 160];
            stream(poll, runtime, owner, profile, seed).read(&mut bytes);
            bytes
        };
    assert_eq!(output([3; 64], [5; 64], &owner, profile, &seed), expected);
    assert_ne!(output([4; 64], [5; 64], &owner, profile, &seed), expected);
    assert_ne!(output([3; 64], [6; 64], &owner, profile, &seed), expected);
    assert_ne!(
        output(
            [3; 64],
            [5; 64],
            &[24; SIGNING_PUBLIC_KEY_BYTES],
            profile,
            &seed
        ),
        expected
    );
    assert_ne!(
        output([3; 64], [5; 64], &owner, profile, &[30; 64]),
        expected
    );
    let other = Profile::all()
        .find(|candidate| candidate.ciphertext_modulus() != profile.ciphertext_modulus())
        .unwrap();
    assert_ne!(output([3; 64], [5; 64], &owner, other, &seed), expected);
}

#[test]
fn source_capsule_restores_original_entries_and_refuses_damage_or_resealing() {
    let (poll, credential) = poll();
    let families = fhe_key_families(&poll);
    // A custody fixture, not a verified registration or public key proof.
    let commitments = vec![[31; 64]; families.len()];
    let mut sources = Sources {
        poll: poll.identity(),
        runtime: poll.runtime(),
        owner: *credential.signing_public(),
        entries: families
            .iter()
            .enumerate()
            .map(|(index, _)| Entry {
                seed: Zeroizing::new([index as u8 + 41; 64]),
                salt: Zeroizing::new([index as u8 + 53; 64]),
            })
            .collect(),
        families,
        commitments: commitments.clone(),
        sealed: false,
    };
    let body = [61; 64];
    let key = [67; 32];
    let capsule = sources.seal(body, &key).unwrap();
    assert_eq!(capsule.len(), capsule_bytes(&poll));
    assert!(capsule.len() <= maximum_capsule_bytes());
    assert!(sources.seal(body, &key).is_err());
    let mut restored =
        Sources::open(&poll, &credential, &commitments, body, &key, &capsule).unwrap();
    for (original, retained) in sources.entries.iter().zip(&restored.entries) {
        assert_eq!(original.seed, retained.seed);
        assert_eq!(original.salt, retained.salt);
    }
    assert!(restored.seal(body, &key).is_err());
    assert!(Sources::open(&poll, &credential, &commitments, [62; 64], &key, &capsule).is_err());
    assert!(Sources::open(&poll, &credential, &commitments, body, &[68; 32], &capsule).is_err());
    assert!(Sources::open(&poll, &credential, &commitments[..0], body, &key, &capsule).is_err());
    for offset in [0, 4, capsule.len() - 1] {
        let mut changed = capsule.clone();
        changed[offset] ^= 1;
        assert!(Sources::open(&poll, &credential, &commitments, body, &key, &changed).is_err());
    }
    assert!(
        Sources::open(
            &poll,
            &credential,
            &commitments,
            body,
            &key,
            &capsule[..capsule.len() - 1]
        )
        .is_err()
    );
}
