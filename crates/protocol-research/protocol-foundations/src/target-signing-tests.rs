use super::*;
// Absent, invalid and conflicting classifications cycle after the accepted ones.
fn body(participants: usize, accepted: usize, evaluated: bool) -> Vec<u8> {
    let classifications: Vec<u8> = (0..participants)
        .map(|position| {
            if position < accepted {
                2
            } else {
                [0, 1, 3][position % 3]
            }
        })
        .collect();
    let mut items = vec![
        CanonicalItem::nonempty_ascii(TARGET_PURPOSE).unwrap(),
        CanonicalItem::hash512([1; 64]),
        CanonicalItem::hash512([2; 64]),
        CanonicalItem::hash512([3; 64]),
        CanonicalItem::variable_bytes(&classifications).unwrap(),
        CanonicalItem::unsigned16(u16::from(evaluated)),
    ];
    if evaluated {
        items.extend([
            CanonicalItem::hash512([4; 64]),
            CanonicalItem::hash512([5; 64]),
            CanonicalItem::unsigned64(3276800),
        ]);
    }
    CanonicalTuple::new(1, 1, items).encode().unwrap()
}
#[test]
fn minimum_turnout_is_two_more_than_the_compromise_bound() {
    for (participants, turnout) in [(3, 2), (4, 3), (6, 3), (7, 4), (10, 5), (13, 6), (20, 8)] {
        assert_eq!(minimum_turnout(participants), turnout);
    }
}
#[test]
fn only_the_minimum_turnout_selects_the_evaluated_branch() {
    for participants in 3..=20 {
        let minimum = minimum_turnout(participants);
        for accepted in 0..=participants {
            let evaluated = accepted >= minimum;
            let message =
                TargetMessage::parse(&body(participants, accepted, evaluated), participants)
                    .unwrap();
            assert_eq!(message.encrypted(), evaluated);
            for position in 0..participants {
                assert_eq!(
                    message.classification(position),
                    Some(if position < accepted {
                        2
                    } else {
                        [0, 1, 3][position % 3]
                    })
                );
            }
            assert_eq!(message.classification(participants), None);
            assert!(
                TargetMessage::parse(&body(participants, accepted, !evaluated), participants)
                    .is_err(),
                "participants={participants}, accepted={accepted}"
            );
        }
    }
}
#[test]
fn signing_data_is_canonical_and_cannot_switch_branch_or_roster_shape() {
    for participants in 3..=20 {
        for evaluated in [false, true] {
            let accepted = if evaluated { participants } else { 0 };
            let bytes = body(participants, accepted, evaluated);
            let message = TargetMessage::parse(&bytes, participants).unwrap();
            assert_eq!(message.body(), bytes);
            assert!(
                TargetMessage::parse(
                    &bytes,
                    if participants == 20 {
                        19
                    } else {
                        participants + 1
                    }
                )
                .is_err()
            );
            let mut excess = bytes.clone();
            excess.push(0);
            assert!(TargetMessage::parse(&excess, participants).is_err());
            let mut tuple =
                CanonicalTuple::decode(&bytes, &CanonicalDecodeLimits::default()).unwrap();
            let mut classifications = tuple.items[4].variable_value_bytes().unwrap().to_vec();
            classifications[participants - 1] = 4;
            tuple.items[4] = CanonicalItem::variable_bytes(&classifications).unwrap();
            assert!(TargetMessage::parse(&tuple.encode().unwrap(), participants).is_err());
            let mut tuple =
                CanonicalTuple::decode(&bytes, &CanonicalDecodeLimits::default()).unwrap();
            tuple.items[5] = CanonicalItem::unsigned16(u16::from(!evaluated));
            assert!(TargetMessage::parse(&tuple.encode().unwrap(), participants).is_err());
        }
    }
}
#[test]
fn vote_framing_refuses_missing_extra_and_out_of_range_data() {
    let value = TargetVote {
        position: 19,
        target: [6; 64],
        signature: [7; SIGNATURE_BYTES],
    };
    let bytes = value.encode();
    assert_eq!(TargetVote::parse(&bytes).unwrap().encode(), bytes);
    assert!(TargetVote::parse(&bytes[..bytes.len() - 1]).is_err());
    let mut changed = bytes.clone();
    changed.push(0);
    assert!(TargetVote::parse(&changed).is_err());
    let mut changed = bytes;
    changed[..2].copy_from_slice(&20u16.to_le_bytes());
    assert!(TargetVote::parse(&changed).is_err());
}
