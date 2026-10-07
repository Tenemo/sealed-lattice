use super::*;
#[test]
fn a_classified_status_needs_a_timely_ballot_in_a_usable_slot() {
    let close = 1_000;
    for (classification, timely) in [
        (None, OwnBallotStatus::Omitted),
        (Some(0), OwnBallotStatus::Omitted),
        (Some(1), OwnBallotStatus::Included),
        (Some(2), OwnBallotStatus::Included),
        (Some(3), OwnBallotStatus::Omitted),
    ] {
        assert_eq!(
            classified_ballot_status(None, close, classification),
            OwnBallotStatus::NotCast
        );
        for time in [0, close] {
            assert_eq!(
                classified_ballot_status(Some(time), close, classification),
                timely
            );
        }
        for time in [close + 1, u64::MAX] {
            assert_eq!(
                classified_ballot_status(Some(time), close, classification),
                OwnBallotStatus::Late
            );
        }
    }
}
