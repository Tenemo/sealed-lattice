use super::*;
use crate::ballot_body::*;
use crate::foundation::{
    StabilizedDisplayText,
    ceremony::{Manifest, OptionDefinition},
};
use crate::poll::{PollDraft, verify_poll};
fn verified_poll(runtime: [u8; 64]) -> VerifiedPoll {
    let label = |value: &str| StabilizedDisplayText::from_ingress_utf8(value.as_bytes()).unwrap();
    let options = (0..10)
        .map(|index| {
            OptionDefinition::new(
                index,
                format!("option-{index}"),
                label(&format!("O{index}")),
            )
            .unwrap()
        })
        .collect();
    let draft = PollDraft::new(Manifest::new(label("Question"), options).unwrap(), 10, 10).unwrap();
    let packet = Credential::from_seed([20; 32])
        .create_poll(draft, runtime, [3; 32])
        .unwrap();
    verify_poll(packet.identity, runtime, &packet.body, &packet.signature).unwrap()
}
#[test]
fn retained_setup_tags_bind_the_credential_poll_and_exact_reference() {
    let participant = Credential::from_seed([7; 32]);
    let same_seed = Credential::from_seed([7; 32]);
    let other = Credential::from_seed([10; 32]);
    let poll = verified_poll([2; 64]);
    let reference = [b"SAV1".as_slice(), &[5; 64], &[6; 128]].concat();
    let tag = participant.retained_setup_tag(&poll, &reference);
    assert!(
        participant
            .check_retained_setup_tag(&poll, &reference, &tag)
            .is_ok()
    );
    // The key is the signing seed alone, so a restored credential accepts
    // its earlier tag while every other credential refuses it.
    assert!(
        same_seed
            .check_retained_setup_tag(&poll, &reference, &tag)
            .is_ok()
    );
    assert!(
        other
            .check_retained_setup_tag(&poll, &reference, &tag)
            .is_err()
    );
    assert!(
        participant
            .check_retained_setup_tag(&verified_poll([9; 64]), &reference, &tag)
            .is_err()
    );
    let mut changed = reference.clone();
    changed[70] ^= 1;
    let extended = [reference.as_slice(), &[0]].concat();
    for candidate in [&changed[..], &reference[..reference.len() - 1], &extended] {
        assert!(
            participant
                .check_retained_setup_tag(&poll, candidate, &tag)
                .is_err()
        );
    }
    let mut forged = tag;
    forged[RETAINED_TAG_BYTES - 1] ^= 1;
    let long_tag = [tag.as_slice(), &[0]].concat();
    for candidate in [&forged[..], &tag[..RETAINED_TAG_BYTES - 1], &long_tag, &[]] {
        assert!(
            participant
                .check_retained_setup_tag(&poll, &reference, candidate)
                .is_err()
        );
    }
}
#[test]
fn envelope_lengths_and_positions_are_bounded_before_body_work() {
    for (participants, options) in [(3, 2), (20, 20)] {
        let profile = Profile::new(participants, options).unwrap();
        let lengths = body_lengths(profile);
        let (minimum, maximum) = (*lengths.start(), *lengths.end());
        let last = participants - 1;
        for (length, time) in [(minimum, 0), (maximum, u64::MAX)] {
            let value = BallotEnvelope::new(profile, [1; 64], [2; 64], last, time, length, [3; 64])
                .unwrap();
            let decoded = BallotEnvelope::decode(profile, value.bytes()).unwrap();
            assert_eq!(decoded.bytes(), value.bytes());
            assert_eq!(decoded.ballot_time(), time);
            assert_eq!(decoded.body_length(), length);
            assert_eq!(decoded.identity(), value.identity());
            let mut retimed = *value.bytes();
            retimed[134] ^= 1;
            assert_ne!(
                BallotEnvelope::decode(profile, &retimed)
                    .unwrap()
                    .identity(),
                value.identity()
            );
            let mut former = *value.bytes();
            former[3] = b'1';
            assert!(BallotEnvelope::decode(profile, &former).is_err());
            assert!(BallotEnvelope::decode(profile, &value.bytes()[..ENVELOPE_BYTES - 1]).is_err());
            let mut extended = value.bytes().to_vec();
            extended.push(0);
            assert!(BallotEnvelope::decode(profile, &extended).is_err());
        }
        for length in [minimum - 1, maximum + 1, usize::MAX] {
            assert!(BallotEnvelope::new(profile, [1; 64], [2; 64], 0, 5, length, [3; 64]).is_err());
        }
        assert!(
            BallotEnvelope::new(profile, [1; 64], [2; 64], participants, 5, minimum, [3; 64])
                .is_err()
        );
    }
    // The widest profile's last position is no position of a
    // three-participant roster.
    let wide = Profile::new(20, 20).unwrap();
    let value = BallotEnvelope::new(
        wide,
        [1; 64],
        [2; 64],
        19,
        5,
        *body_lengths(wide).start(),
        [3; 64],
    )
    .unwrap();
    assert!(BallotEnvelope::decode(Profile::new(3, 2).unwrap(), value.bytes()).is_err());
}
