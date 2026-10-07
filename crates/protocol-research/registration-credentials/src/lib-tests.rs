use super::*;
fn body(credential: &Credential, poll: [u8; 64]) -> BodyDigest {
    BodyDigest::new(RegistrationHeader {
        username: foundation::normalize_username(b"Participant").unwrap(),
        poll,
        runtime: [2; 64],
        signing_public: *credential.signing_public(),
        recipient_key_hash: [3; 64],
        fhe_key_commitments: vec![[7; 64]],
    })
    .unwrap()
}
#[test]
fn credentials_sign_one_body_and_bind_the_full_public_context() {
    let mut credential = Credential::from_seed([7; 32]);
    let signature = credential
        .sign_registration(body(&credential, [1; 64]))
        .unwrap();
    assert!(verify_registration_signature(
        body(&credential, [1; 64]),
        &signature
    ));
    assert!(!verify_registration_signature(
        body(&credential, [2; 64]),
        &signature
    ));
    assert!(!verify_registration_signature(
        body(&credential, [1; 64]),
        &signature[..3308]
    ));
    assert!(
        credential
            .sign_registration(body(&credential, [1; 64]))
            .is_err()
    );
}
#[test]
fn deterministic_signing_replays_the_locked_frame_without_fresh_coins() {
    for seed in [0, 7, 255] {
        for poll in [1, 2] {
            let mut original = Credential::from_seed([seed; 32]);
            let digest = body(&original, [poll; 64]).bytes();
            let signature = original
                .sign_registration(body(&original, [poll; 64]))
                .unwrap();
            // FIPS 204 Algorithm 2 fixes rnd to zero. The dependency's
            // seeded primitive is independently checked against Wycheproof.
            let (_, key) = ml_dsa_65::KG::keygen_from_seed(&[seed; 32]);
            assert_eq!(
                signature,
                key.try_sign_with_seed(&[0; 32], &digest, SIGNATURE_CONTEXT)
                    .unwrap()
            );
            let mut interrupted = Credential::from_seed([seed; 32]);
            assert_eq!(
                interrupted
                    .sign_registration(body(&interrupted, [poll; 64]))
                    .unwrap(),
                signature
            );
            assert!(
                original
                    .sign_registration(body(&original, [poll + 1; 64]))
                    .is_err()
            );
            assert!(!verify_registration_signature(
                body(&original, [poll + 1; 64]),
                &signature
            ));
        }
    }
}
#[test]
fn canonical_headers_bind_context_and_refuse_trailing_bytes() {
    let credential = Credential::from_seed([7; 32]);
    let header = RegistrationHeader {
        username: foundation::normalize_username(b"Participant").unwrap(),
        poll: [1; 64],
        runtime: [2; 64],
        signing_public: *credential.signing_public(),
        recipient_key_hash: [3; 64],

        fhe_key_commitments: vec![[7; 64]],
    }
    .encode()
    .unwrap();
    let mut combined = header.clone();
    combined.extend([4; 128]);
    assert!(BodyDigest::from_header(&combined, [1; 64], [2; 64]).is_err());
    let decoded = BodyDigest::from_header(&header, [1; 64], [2; 64]).unwrap();
    assert_eq!(decoded.bytes(), body(&credential, [1; 64]).bytes());
    assert!(BodyDigest::from_header(&header, [9; 64], [2; 64]).is_err());
    let mut altered = header.clone();
    altered[2] = 2;
    assert!(BodyDigest::from_header(&altered, [1; 64], [2; 64]).is_err());
    assert!(BodyDigest::from_header(&header[..header.len() - 1], [1; 64], [2; 64]).is_err());
}

#[test]
fn signed_usernames_are_canonical_bounded_and_not_replaceable() {
    let mut credential = Credential::from_seed([7; 32]);
    let make = |name: &[u8]| RegistrationHeader {
        username: foundation::normalize_username(name).unwrap(),
        poll: [1; 64],
        runtime: [2; 64],
        signing_public: *credential.signing_public(),
        recipient_key_hash: [3; 64],

        fhe_key_commitments: vec![[7; 64]],
    };
    let original = make(b"Jose\xcc\x81");
    assert_eq!(original.username.as_str(), "Jos\u{e9}");
    let encoded = original.encode().unwrap();
    let mut changed = make(b"Other");
    let other = changed.encode().unwrap();
    changed.username = foundation::normalize_username(&[b'n'; 128]).unwrap();
    assert!(changed.encode().is_ok());
    assert!(foundation::normalize_username(&[b'n'; 129]).is_err());
    assert!(foundation::normalize_username(b"").is_err());
    assert!(foundation::normalize_username(&[0xff]).is_err());
    let hash = |header: &[u8]| BodyDigest::from_header(header, [1; 64], [2; 64]).unwrap();
    let signature = credential.sign_registration(hash(&encoded)).unwrap();
    assert!(verify_registration_signature(hash(&encoded), &signature));
    assert!(!verify_registration_signature(hash(&other), &signature));
    let name_end = encoded.len() - (6 + 6 + 64);
    let mut noncanonical = encoded[..name_end - 15].to_vec();
    noncanonical.extend(12u16.to_le_bytes());
    noncanonical.extend(10u32.to_le_bytes());
    noncanonical.extend(6u32.to_le_bytes());
    noncanonical.extend(b"Jose\xcc\x81");
    noncanonical.extend(&encoded[name_end..]);
    assert!(BodyDigest::from_header(&noncanonical, [1; 64], [2; 64]).is_err());
}
