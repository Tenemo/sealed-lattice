use super::*;

#[test]
fn the_largest_roster_proposal_fits_its_cap() {
    assert!(proposal_bytes(*Profile::participant_range().end()) <= MAXIMUM_PROPOSAL_BYTES);
}

#[test]
fn records_have_their_declared_lengths() {
    let limits = limits();
    assert_eq!(limits.len(), 43);
    for profile in [Profile::new(3, 2).unwrap(), Profile::new(20, 20).unwrap()] {
        let bounds = profile_bounds(profile);
        let checkpoints = bounds[26] as usize;
        let polynomials = bounds[27 + checkpoints] as usize;
        let source_start =
            37 + checkpoints + 3 * polynomials + profile.committed_polynomials().len();
        assert_eq!(bounds[source_start], SOURCE_POLYNOMIALS as u64);
        assert_eq!(bounds.len(), source_start + 1 + 3 * SOURCE_POLYNOMIALS);
        for (index, values) in bounds[source_start + 1..].chunks_exact(3).enumerate() {
            assert_eq!(
                values,
                [
                    (profile.setup_polynomials() + index) as u64,
                    (DEGREE * (1 + supported_profile::auxiliary_modulus().len())) as u64,
                    DEGREE as u64,
                ]
            );
        }
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
