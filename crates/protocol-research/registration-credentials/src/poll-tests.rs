use super::*;
use crate::foundation::{StabilizedDisplayText, ceremony::OptionDefinition};
fn label(value: &str) -> StabilizedDisplayText {
    StabilizedDisplayText::from_ingress_utf8(value.as_bytes()).unwrap()
}
fn manifest(title: &str, first: &str, second: &str, count: u16) -> Manifest {
    let mut options = vec![
        OptionDefinition::new(0, "first".to_owned(), label(first)).unwrap(),
        OptionDefinition::new(1, "second".to_owned(), label(second)).unwrap(),
    ];
    for index in 2..count {
        options.push(
            OptionDefinition::new(
                index,
                format!("option-{index}"),
                label(&format!("Option {index}")),
            )
            .unwrap(),
        );
    }
    Manifest::new(label(title), options).unwrap()
}
fn draft(top_count: u16) -> Result<PollDraft, Error> {
    PollDraft::new(manifest("Question", "First", "Second", 10), top_count, 10)
}
#[test]
fn poll_identity_binds_creator_definition_and_runtime_without_a_future_key() {
    let mut creator = Credential::from_seed([7; 32]);
    let original = *creator.signing_public();
    let packet = creator
        .create_poll(draft(2).unwrap(), [2; 64], [3; 32])
        .unwrap();
    let verified = verify_poll(packet.identity, [2; 64], &packet.body, &packet.signature).unwrap();
    assert_eq!(verified.organizer(), &original);
    assert_eq!(verified.manifest().option_count(), 10);
    assert_eq!(verified.top_count(), 2);
    assert_eq!(verified.maximum_participants(), 10);
    // The body is its fixed fields around the canonical manifest.
    assert_eq!(
        packet.body.len(),
        POLL_BODY_OVERHEAD
            + manifest("Question", "First", "Second", 10)
                .encode()
                .unwrap()
                .len()
    );
    assert!(
        creator
            .create_poll(draft(1).unwrap(), [2; 64], [4; 32])
            .is_err()
    );
    assert!(verify_poll(packet.identity, [9; 64], &packet.body, &packet.signature).is_err());
    let mut changed = packet.body.clone();
    *changed.last_mut().unwrap() ^= 1;
    assert!(verify_poll(packet.identity, [2; 64], &changed, &packet.signature).is_err());
    assert!(draft(0).is_err());
    assert!(draft(10).is_ok());
    assert!(draft(11).is_err());
}

#[test]
fn every_supported_option_count_and_top_count_can_be_created() {
    for count in Profile::option_range() {
        let count = u16::try_from(count).unwrap();
        for top_count in [1, count] {
            let draft = PollDraft::new(
                manifest("Question", "First", "Second", count),
                top_count,
                10,
            )
            .unwrap();
            let packet = Credential::from_seed([7; 32])
                .create_poll(draft, [2; 64], [3; 32])
                .unwrap();
            let verified =
                verify_poll(packet.identity, [2; 64], &packet.body, &packet.signature).unwrap();
            assert_eq!(verified.manifest().option_count(), usize::from(count));
        }
        assert!(matches!(
            PollDraft::new(
                manifest("Question", "First", "Second", count),
                count + 1,
                10
            ),
            Err(Error::Shape)
        ));
    }
    assert_eq!(Profile::option_range(), 2..=20);
}

#[test]
fn every_supported_participant_maximum_can_be_created() {
    for maximum in Profile::participant_range() {
        let maximum = u16::try_from(maximum).unwrap();
        let draft = PollDraft::new(manifest("Question", "First", "Second", 2), 1, maximum).unwrap();
        let packet = Credential::from_seed([7; 32])
            .create_poll(draft, [2; 64], [3; 32])
            .unwrap();
        let verified =
            verify_poll(packet.identity, [2; 64], &packet.body, &packet.signature).unwrap();
        assert_eq!(verified.maximum_participants(), maximum);
    }
    for maximum in [0, 2, 21] {
        assert!(matches!(
            PollDraft::new(manifest("Question", "First", "Second", 2), 1, maximum),
            Err(Error::Shape)
        ));
    }
    assert_eq!(Profile::participant_range(), 3..=20);
}

#[test]
fn valid_signatures_do_not_authorize_invalid_poll_fields() {
    let mut creator = Credential::from_seed([7; 32]);
    let packet = creator
        .create_poll(draft(10).unwrap(), [2; 64], [3; 32])
        .unwrap();
    let original = CanonicalTuple::decode(&packet.body, &CanonicalDecodeLimits::default()).unwrap();
    let (_, private) = ml_dsa_65::KG::keygen_from_seed(&[7; 32]);
    let signed_refusal = |tuple: CanonicalTuple| {
        let body = tuple.encode().unwrap();
        let digest = identity(&body).unwrap();
        let signature = private
            .try_sign_with_seed(&[5; 32], &digest, POLL_SIGNATURE_CONTEXT)
            .unwrap();
        assert!(verify_poll(digest, [2; 64], &body, &signature).is_err());
    };
    let mut top = original.clone();
    top.items[5] = CanonicalItem::unsigned16(11);
    signed_refusal(top);
    for maximum in [2, 21] {
        let mut participants = original.clone();
        participants.items[6] = CanonicalItem::unsigned16(maximum);
        signed_refusal(participants);
    }
    // A maximum of another type is refused although its bytes name a
    // supported roster size.
    let mut typed = original.clone();
    typed.items[6] = CanonicalItem::fixed_bytes([10, 0]).unwrap();
    signed_refusal(typed);
    // Nine options cannot carry the signed top count of ten.
    let mut body = original.clone();
    body.items[4] =
        CanonicalItem::variable_bytes(manifest("Question", "First", "Second", 9).encode().unwrap())
            .unwrap();
    signed_refusal(body);
    let mut wrong_runtime = original;
    wrong_runtime.items[1] = CanonicalItem::hash512([9; 64]);
    signed_refusal(wrong_runtime);
    assert!(matches!(
        verify_poll(
            packet.identity,
            [2; 64],
            &vec![0; MAXIMUM_POLL_BYTES + 1],
            &packet.signature
        ),
        Err(Error::Shape)
    ));
}
