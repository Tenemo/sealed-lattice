use super::*;
#[test]
fn a_classified_status_needs_a_timely_ballot_in_a_usable_slot() {
    let close = 1_000;
    for (classification, timely) in [
        (None, OwnBallotInclusion::Omitted),
        (Some(0), OwnBallotInclusion::Omitted),
        (Some(1), OwnBallotInclusion::Included),
        (Some(2), OwnBallotInclusion::Included),
        (Some(3), OwnBallotInclusion::Omitted),
    ] {
        assert_eq!(
            classified_ballot_inclusion(None, close, classification),
            OwnBallotInclusion::NotCast
        );
        for time in [0, close] {
            assert_eq!(
                classified_ballot_inclusion(Some(time), close, classification),
                timely
            );
        }
        for time in [close + 1, u64::MAX] {
            assert_eq!(
                classified_ballot_inclusion(Some(time), close, classification),
                OwnBallotInclusion::Late
            );
        }
    }
}
