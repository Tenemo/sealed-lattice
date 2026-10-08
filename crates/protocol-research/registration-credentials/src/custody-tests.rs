use super::*;
use crate::{
    BodyDigest,
    foundation::{RegistrationHeader, normalize_username},
};
#[test]
fn restored_signing_keys_cannot_recreate_authority_the_root_does_not_unlock() {
    let mut original = Credential::from_seed([7; 32]);
    let data_key = [11; 32];
    assert!(original.seal_complete(&data_key).is_err());
    let make = || {
        BodyDigest::new(RegistrationHeader {
            username: normalize_username(b"Participant").unwrap(),
            poll: [1; 64],
            runtime: [2; 64],
            signing_public: *original.signing_public(),
            recipient_key_hash: [3; 64],

            fhe_key_commitments: vec![[7; 64]],
        })
        .unwrap()
    };
    let digest = make();
    let body = digest.bytes();
    let for_repeat = make();
    original.sign_registration(digest).unwrap();
    let sealed = original.seal_complete(&data_key).unwrap();
    assert_eq!(sealed.len(), SEALED_SIGNING_SEED_BYTES);
    assert!(original.seal_complete(&data_key).is_err());
    let mut restored =
        Credential::open_complete(*original.signing_public(), body, &data_key, &sealed).unwrap();
    assert!(restored.check_retained());
    assert!(restored.sign_registration(for_repeat).is_err());
    assert!(restored.seal_complete(&data_key).is_err());
    let purposes = [
        SigningPurpose::Proposal,
        SigningPurpose::Offer,
        SigningPurpose::SelectionProposal,
        SigningPurpose::SelectionEndorsement,
        SigningPurpose::Ballot,
        SigningPurpose::CloseIntent,
        SigningPurpose::CloseResponse,
        SigningPurpose::CloseProposal,
        SigningPurpose::Target,
        SigningPurpose::Release,
    ];
    for purpose in purposes {
        assert!(original.check_unlocked(purpose).is_ok());
        assert!(matches!(
            restored.check_unlocked(purpose),
            Err(Error::Consumed)
        ));
    }
    for undefined in [SigningPurpose::Release.mask() << 1, u16::MAX] {
        assert!(matches!(
            restored.unlock_unused_purposes(undefined),
            Err(Error::Shape)
        ));
    }
    restored.unlock_unused_purposes(0).unwrap();
    restored
        .unlock_unused_purposes(
            SigningPurpose::Ballot.mask() | SigningPurpose::CloseResponse.mask(),
        )
        .unwrap();
    for purpose in purposes {
        assert_eq!(
            restored.check_unlocked(purpose).is_ok(),
            matches!(
                purpose,
                SigningPurpose::Ballot | SigningPurpose::CloseResponse
            )
        );
    }
    let mut changed = sealed.clone();
    changed[20] ^= 1;
    assert!(
        Credential::open_complete(*original.signing_public(), body, &data_key, &changed).is_err()
    );
    let mut wrong_seed = Vec::from(b"RCS1".as_slice());
    wrong_seed.extend([6u8; 32]);
    Aes256Gcm::new((&data_key).into())
        .encrypt_in_place(
            Nonce::from_slice(&[0; 12]),
            &associated(body),
            &mut wrong_seed,
        )
        .unwrap();
    assert!(
        Credential::open_complete(*original.signing_public(), body, &data_key, &wrong_seed)
            .is_err()
    );
    let mut extra = sealed.clone();
    extra.push(0);
    assert!(
        Credential::open_complete(*original.signing_public(), body, &data_key, &extra).is_err()
    );
    assert!(
        Credential::open_complete(*original.signing_public(), [0; 64], &data_key, &sealed).is_err()
    );
}

// The worker computes the unused-purpose mask from these positions.
#[test]
fn signing_purpose_positions_are_fixed() {
    for (purpose, position) in [
        (SigningPurpose::Proposal, 0),
        (SigningPurpose::Offer, 1),
        (SigningPurpose::SelectionProposal, 2),
        (SigningPurpose::SelectionEndorsement, 3),
        (SigningPurpose::Ballot, 4),
        (SigningPurpose::CloseIntent, 5),
        (SigningPurpose::CloseResponse, 6),
        (SigningPurpose::CloseProposal, 7),
        (SigningPurpose::Target, 8),
        (SigningPurpose::Release, 9),
    ] {
        assert_eq!(purpose.mask(), 1 << position);
    }
}
