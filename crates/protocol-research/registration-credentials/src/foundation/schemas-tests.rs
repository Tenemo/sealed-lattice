use super::*;

// The entries skip their own position check, so the roster's checks see
// every size.
fn roster_entries(participant_count: u16) -> Vec<RosterEntry> {
    (0..participant_count)
        .map(|roster_position| {
            let mut signing_verification_key = [0x23_u8; ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH];
            signing_verification_key[0..2].copy_from_slice(&roster_position.to_le_bytes());
            RosterEntry {
                roster_position,
                signing_verification_key,
            }
        })
        .collect()
}

// A poll has 3 to 20 participants; the literals restate that owner
// independently of the implementation constants.
const GOAL_PARTICIPANT_COUNTS: std::ops::RangeInclusive<u16> = 3..=20;

#[test]
fn roster_admits_every_configurable_size() {
    for participant_count in GOAL_PARTICIPANT_COUNTS {
        let roster = Roster::new(roster_entries(participant_count)).expect("roster is valid");
        assert_eq!(roster.entries.len(), usize::from(participant_count));
    }
}

#[test]
fn roster_refuses_duplicates_reordering_and_unsupported_sizes() {
    let mut entries = roster_entries(3);
    entries.swap(0, 1);
    assert_eq!(
        Roster::new(entries)
            .expect_err("reordered positions refuse")
            .refusal_reason,
        RefusalReason::WrongTypeOrLength
    );

    let mut duplicate = roster_entries(3);
    duplicate[2].signing_verification_key = duplicate[0].signing_verification_key;
    assert_eq!(
        Roster::new(duplicate)
            .expect_err("duplicate identity refuses")
            .refusal_reason,
        RefusalReason::DuplicateIdentity
    );

    for participant_count in [
        *GOAL_PARTICIPANT_COUNTS.start() - 1,
        *GOAL_PARTICIPANT_COUNTS.end() + 1,
    ] {
        assert_eq!(
            Roster::new(roster_entries(participant_count))
                .expect_err("an unsupported roster size must refuse")
                .refusal_reason,
            RefusalReason::OutsideSupportedProfile
        );
    }
    assert_eq!(
        RosterEntry::new(
            *GOAL_PARTICIPANT_COUNTS.end(),
            [0x23_u8; ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH],
        )
        .expect_err("a position beyond the largest roster must refuse")
        .refusal_reason,
        RefusalReason::OutsideSupportedProfile
    );
}
