use super::*;
use fips204::traits::{KeyGen, Signer};
fn identity(value: u8) -> [u8; 64] {
    [value; 64]
}
#[test]
fn quorum_and_maximum_lengths_follow_the_roster() {
    for (participants, quorum) in [(3, 3), (4, 3), (6, 5), (7, 5), (10, 7), (13, 9), (20, 14)] {
        assert_eq!(close_quorum(participants), quorum);
    }
    for participants in 3..=20 {
        let listed: Vec<_> = (0..participants)
            .flat_map(|author| [(author, identity(1)), (author, identity(2))])
            .collect();
        let response = CloseResponseMessage::new(
            identity(7),
            identity(8),
            identity(9),
            0,
            participants,
            &listed,
        )
        .unwrap();
        assert_eq!(
            response.body().len(),
            maximum_close_message_bytes(ClosePurpose::Response, participants)
        );
        let responses: Vec<_> = (0..close_quorum(participants))
            .map(|responder| (responder, identity(3)))
            .collect();
        let proposal = CloseProposalMessage::new(
            identity(7),
            identity(8),
            identity(9),
            participants,
            0,
            &responses,
        )
        .unwrap();
        assert_eq!(
            proposal.body().len(),
            maximum_close_message_bytes(ClosePurpose::Proposal, participants)
        );
    }
    let intent = CloseIntentMessage::new(identity(7), identity(8), u64::MAX).unwrap();
    assert_eq!(
        intent.body().len(),
        maximum_close_message_bytes(ClosePurpose::Intent, 3)
    );
    assert_eq!(intent.close_time(), u64::MAX);
    assert_eq!(
        CloseIntentMessage::parse(intent.body()).unwrap().identity(),
        intent.identity()
    );
}
#[test]
fn response_listings_are_canonical_and_capped_per_slot() {
    let make = |listed: &[(usize, [u8; 64])]| {
        CloseResponseMessage::new(identity(7), identity(8), identity(9), 1, 4, listed)
    };
    let valid = make(&[(0, identity(1)), (0, identity(2)), (3, identity(1))]).unwrap();
    assert_eq!(valid.responder(), 1);
    assert_eq!(valid.listed().len(), 3);
    assert!(make(&[]).unwrap().listed().is_empty());
    for refused in [
        vec![(0, identity(2)), (0, identity(1))],
        vec![(3, identity(1)), (0, identity(1))],
        vec![(0, identity(1)), (0, identity(1))],
        vec![(0, identity(1)), (0, identity(2)), (0, identity(3))],
        vec![(4, identity(1))],
    ] {
        assert!(make(&refused).is_err(), "{refused:?}");
    }
    assert!(CloseResponseMessage::new(identity(7), identity(8), identity(9), 4, 4, &[]).is_err());
    let mut truncated = valid.body().to_vec();
    truncated.pop();
    assert!(CloseResponseMessage::parse(&truncated, 4).is_err());
    let mut extended = valid.body().to_vec();
    extended.push(0);
    assert!(CloseResponseMessage::parse(&extended, 4).is_err());
    assert!(CloseResponseMessage::parse(valid.body(), 3).is_err());
    assert!(CloseIntentMessage::parse(valid.body()).is_err());
    assert!(CloseProposalMessage::parse(valid.body(), 4, 0).is_err());
}
#[test]
fn proposals_carry_exactly_the_quorum_including_the_organizer() {
    let make = |responses: &[(usize, [u8; 64])], organizer| {
        CloseProposalMessage::new(
            identity(7),
            identity(8),
            identity(9),
            10,
            organizer,
            responses,
        )
    };
    let quorum: Vec<_> = (0..7).map(|responder| (responder, identity(3))).collect();
    assert!(make(&quorum, 0).is_ok());
    assert!(make(&quorum, 6).is_ok());
    assert!(make(&quorum, 7).is_err());
    assert!(make(&quorum[..6], 0).is_err());
    let mut extra = quorum.clone();
    extra.push((7, identity(3)));
    assert!(make(&extra, 0).is_err());
    let mut repeated = quorum.clone();
    repeated[1] = (0, identity(4));
    assert!(make(&repeated, 0).is_err());
    let mut unordered = quorum;
    unordered.swap(1, 2);
    assert!(make(&unordered, 0).is_err());
}
#[test]
fn signatures_bind_the_purpose_context() {
    let (public, private) = ml_dsa_65::KG::keygen_from_seed(&[9; 32]);
    let public = public.into_bytes();
    let intent = CloseIntentMessage::new(identity(7), identity(8), 5).unwrap();
    let signature = private
        .try_sign_with_seed(
            &[10; 32],
            intent.identity(),
            ClosePurpose::Intent.context().as_bytes(),
        )
        .unwrap();
    assert!(verify_close_signature(
        &public,
        ClosePurpose::Intent,
        intent.identity(),
        &signature
    ));
    assert!(!verify_close_signature(
        &public,
        ClosePurpose::Response,
        intent.identity(),
        &signature
    ));
    assert!(!verify_close_signature(
        &public,
        ClosePurpose::Intent,
        &identity(1),
        &signature
    ));
    assert!(!verify_close_signature(
        &public,
        ClosePurpose::Intent,
        intent.identity(),
        &signature[1..]
    ));
    let later = CloseIntentMessage::new(identity(7), identity(8), 6).unwrap();
    assert_ne!(later.identity(), intent.identity());
}
