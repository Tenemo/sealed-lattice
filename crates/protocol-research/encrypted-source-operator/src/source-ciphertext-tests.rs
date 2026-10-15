use super::*;
use setup_witness::encrypted_source::SourceCiphertextVerifier;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

// Independent byte framing and SHAKE implementation, including the fixed
// protocol-hash prefix. Malformed records receive matching expected hashes so
// that the refusal tests exercise parsing rather than merely digest mismatch.
fn binding(profile: Profile, poll: &[u8; 64], owner: &[u8; 64], bytes: &[u8]) -> [u8; 64] {
    let mut state = Shake256::default();
    let mut prefix = [0u8; 64];
    let label = b"sealed-lattice/fixed-hash";
    prefix[..label.len()].copy_from_slice(label);
    state.update(&prefix);
    state.update(b"sealed-lattice/registered-source/v1");
    state.update(poll);
    state.update(owner);
    state.update(&(DEGREE as u32).to_le_bytes());
    let modulus = profile.ciphertext_modulus().to_bytes();
    state.update(&(modulus.len() as u16).to_le_bytes());
    state.update(&modulus);
    state.update(&(profile.fhe_common_sample_bits() as u32).to_le_bytes());
    state.update(&((4 * DEGREE * 6) as u64).to_le_bytes());
    state.update(bytes);
    let mut output = [0u8; 64];
    state.finalize_xof().read(&mut output);
    output
}

#[test]
fn registration_ciphertexts_require_canonical_complete_context_bound_bytes() {
    let profile = Profile::new(3, 2).unwrap();
    let poll = [17; 64];
    let owner = [31; 64];
    let common = common_polynomials();
    let values = [0, 1, -1, modulus() / 2, -modulus() / 2];
    let public = PublicSource {
        polynomials: common
            .into_iter()
            .enumerate()
            .flat_map(|(component, common)| {
                [
                    common,
                    (0..DEGREE)
                        .map(|index| values[(index + component) % values.len()])
                        .collect(),
                ]
            })
            .collect(),
    };
    let bytes = public.ciphertext_records().unwrap().concat();
    let expected = binding(profile, &poll, &owner, &bytes);
    assert_eq!(public.binding(profile, &poll, &owner).unwrap(), expected);
    for chunk in [7, 65_537, parallel_work::CHUNK_LIMIT] {
        let mut verifier = SourceCiphertextVerifier::new(profile, &poll, &owner, expected);
        for part in bytes.chunks(chunk) {
            verifier.push(part).unwrap();
        }
        assert_eq!(
            verifier.finish().unwrap().public().polynomials,
            public.polynomials
        );
    }
    let verify = |profile, poll: &[u8; 64], owner: &[u8; 64], expected, bytes: &[u8]| {
        let mut verifier = SourceCiphertextVerifier::new(profile, poll, owner, expected);
        for part in bytes.chunks(65_537) {
            if let Err(error) = verifier.push(part) {
                assert!(verifier.push(&[0]).is_err());
                assert_eq!(verifier.finish().err(), Some(Refusal::Shape));
                return Err(error);
            }
        }
        verifier.finish().map(|_| ())
    };
    let mut refused = 0;
    for position in [0, bytes.len() - 6] {
        for malformed in [0, 1, 2] {
            let mut changed = bytes.clone();
            let record = &mut changed[position..position + 6];
            record.fill(0);
            let error = match malformed {
                0 => {
                    record[0] = 2;
                    Refusal::Encoding
                }
                1 => {
                    record[0] = 1;
                    Refusal::Encoding
                }
                _ => {
                    record[1..].copy_from_slice(&((modulus() / 2 + 1) as u64).to_le_bytes()[..5]);
                    Refusal::Range
                }
            };
            let matching = binding(profile, &poll, &owner, &changed);
            assert_eq!(
                verify(profile, &poll, &owner, matching, &changed),
                Err(error)
            );
            refused += 1;
        }
    }
    let mut changed = bytes.clone();
    changed[1] = 1;
    assert_eq!(
        verify(profile, &poll, &owner, expected, &changed),
        Err(Refusal::Binding)
    );
    refused += 1;
    let other_family = Profile::all()
        .find(|other| {
            other.ciphertext_modulus().to_bytes() != profile.ciphertext_modulus().to_bytes()
        })
        .unwrap();
    for (profile, poll, owner) in [
        (profile, [18; 64], owner),
        (profile, poll, [32; 64]),
        (other_family, poll, owner),
    ] {
        assert_eq!(
            verify(profile, &poll, &owner, expected, &bytes),
            Err(Refusal::Binding)
        );
        refused += 1;
    }
    assert_eq!(
        verify(profile, &poll, &owner, expected, &bytes[..bytes.len() - 1]),
        Err(Refusal::Shape)
    );
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        verify(profile, &poll, &owner, expected, &trailing),
        Err(Refusal::Shape)
    );
    refused += 2;
    for length in [0, parallel_work::CHUNK_LIMIT + 1] {
        let mut verifier = SourceCiphertextVerifier::new(profile, &poll, &owner, expected);
        assert_eq!(verifier.push(&vec![0; length]), Err(Refusal::Shape));
        assert!(verifier.push(&bytes[..6]).is_err());
        assert_eq!(verifier.finish().err(), Some(Refusal::Shape));
        refused += 1;
    }
    assert_eq!(refused, 14);
    println!(
        "Source ciphertext stream: 3 accepted, {refused} refused; independent matching malformed hashes"
    );
}
