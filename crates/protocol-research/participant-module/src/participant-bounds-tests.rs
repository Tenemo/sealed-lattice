use super::*;

#[test]
fn the_largest_roster_proposal_fits_its_cap() {
    assert!(proposal_bytes(*Profile::participant_range().end()) <= MAXIMUM_PROPOSAL_BYTES);
}

#[test]
fn records_have_their_declared_lengths() {
    let limits = limits();
    assert_eq!(limits.len(), 34);
    for profile in [Profile::new(3, 2).unwrap(), Profile::new(20, 20).unwrap()] {
        let bounds = profile_bounds(profile);
        let checkpoints = bounds[25] as usize;
        let polynomials = bounds[26 + checkpoints] as usize;
        assert_eq!(bounds.len(), 27 + checkpoints + 3 * polynomials);
        assert_eq!(
            bounds[14],
            (profile.setup_contributors() + profile.maximum_corrupt_participants()) as u64
        );
        assert_eq!(
            bounds[..2],
            [profile.participants() as u64, profile.options() as u64]
        );
    }
}
