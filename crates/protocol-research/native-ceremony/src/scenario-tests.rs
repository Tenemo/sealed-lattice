use super::*;
#[test]
fn selection_fork_has_only_a_corrupt_organizer_and_no_unavailable_participant() {
    let scenario = Scenario::selection_fork();
    assert_eq!(scenario.active(), [0, 1, 2, 3]);
    assert_eq!(scenario.honest(), [1, 2, 3]);
    assert_eq!(scenario.voters, scenario.active());
    assert!(scenario.corrupt(0));
    assert!(scenario.departed.is_none());
    assert_eq!(scenario.profile().inventory_threshold(), 3);
}
#[test]
fn setup_departure_keeps_the_original_roster_and_separates_corruption_from_loss() {
    let scenario = Scenario::setup_departure();
    assert_eq!(scenario.profile().participants(), 4);
    assert_eq!(scenario.profile().maximum_corrupt_participants(), 1);
    assert_eq!(scenario.profile().setup_eligible_contributors(), 3);
    assert_eq!(scenario.profile().setup_contributors(), 2);
    assert_eq!(scenario.profile().inventory_threshold(), 3);
    assert_eq!(scenario.profile().release_threshold(), 2);
    assert_eq!(scenario.honest(), [0, 1, 3]);
    assert_eq!(scenario.active(), [0, 2, 3]);
    assert!(scenario.corrupt(2));
    assert!(!scenario.corrupt(scenario.departed.unwrap()));
    assert_eq!(scenario.voters, scenario.active());
    assert_eq!(scenario.first_honest_responder(), 3);
    assert!(scenario.equivocator.is_none());
}

#[test]
fn completion_profile_roles_match_the_documented_case() {
    let scenario = Scenario::new(Profile::new(10, 10).unwrap());
    assert_eq!(scenario.equivocator, Some(3));
    assert_eq!(scenario.invalid_proof, Some(2));
    assert_eq!(scenario.wrong_position, Some(1));
    assert_eq!(scenario.voters, [0, 4, 5, 6, 7]);
    assert_eq!(scenario.omitted, Some(9));
    assert_eq!(scenario.nonvoters, [8]);
    assert_eq!(scenario.usable(), [0, 1, 2, 4, 5, 6, 7]);
    assert_eq!(scenario.omitted_holders(), 7..10);
    assert_eq!(scenario.equivocation_holders(false), [1, 2, 4, 5]);
    assert_eq!(scenario.equivocation_holders(true), [6, 7, 8]);
}

#[test]
fn every_profile_meets_the_turnout_and_bounds_its_omission() {
    for participants in 3..=20 {
        let profile = Profile::new(participants, 2).unwrap();
        let scenario = Scenario::new(profile);
        let corrupt = profile.maximum_corrupt_participants();
        assert_eq!(scenario.voters.len(), profile.minimum_turnout());
        assert!(
            scenario
                .voters
                .iter()
                .all(|voter| !scenario.corrupt(*voter))
        );
        assert_eq!(scenario.honest().len(), profile.inventory_threshold());
        let mut roles: Vec<_> = scenario
            .voters
            .iter()
            .chain(&scenario.nonvoters)
            .chain(&scenario.omitted)
            .copied()
            .collect();
        roles.sort_unstable();
        assert_eq!(roles, scenario.honest());
        if let Some(omitted) = scenario.omitted {
            // The omitted ballot's holders are honest and outside the
            // proposal's responses 0 to n - f - 1.
            assert!(scenario.omitted_holders().contains(&omitted));
            assert_eq!(scenario.omitted_holders().len(), corrupt);
            assert!(
                scenario
                    .omitted_holders()
                    .all(|holder| holder >= profile.inventory_threshold()
                        && !scenario.corrupt(holder))
            );
        }
        let expected_roles = [0, 1, 2, 3].map(|rank: usize| rank < corrupt.min(3));
        assert_eq!(
            [
                scenario.equivocator.is_some(),
                scenario.invalid_proof.is_some(),
                scenario.wrong_position.is_some(),
                false
            ],
            expected_roles
        );
        for position in [
            scenario.equivocator,
            scenario.invalid_proof,
            scenario.wrong_position,
        ]
        .into_iter()
        .flatten()
        {
            assert!(scenario.corrupt(position));
        }
        if let Some(equivocator) = scenario.equivocator {
            assert!(equivocator < profile.inventory_threshold());
            assert!(!scenario.corrupt(scenario.first_honest_responder()));
        }
    }
}

#[test]
fn scores_stay_in_range_for_every_option_count() {
    for options in 2..=20 {
        let scenario = Scenario::new(Profile::new(20, options).unwrap());
        for position in 0..20 {
            let scores = scenario.scores(position);
            assert_eq!(scores.len(), options);
            assert!(
                scores
                    .iter()
                    .all(|score| (1..=MAXIMUM_SCORE).contains(&usize::from(*score)))
            );
        }
    }
}

#[test]
fn small_families_are_complete_and_large_ones_are_bounded_samples() {
    assert_eq!(checked_subsets(10, 4).len(), 210);
    assert_eq!(checked_subsets(10, 4)[0], [0, 1, 2, 3]);
    assert_eq!(checked_subsets(3, 2), [vec![0, 1], vec![0, 2], vec![1, 2]]);
    assert_eq!(checked_departures(10, 3).len(), 176);
    assert_eq!(checked_departures(3, 0), [Vec::<usize>::new()]);
    for (count, size) in [(20, 7), (19, 7), (13, 5)] {
        let sample = checked_subsets(count, size);
        assert_eq!(sample.len(), CHECKED_SETS);
        assert!(sample.contains(&(0..size).collect()));
        assert!(sample.contains(&(count - size..count).collect()));
        let distinct: std::collections::BTreeSet<_> = sample.iter().collect();
        assert_eq!(distinct.len(), CHECKED_SETS);
        assert!(sample.iter().all(|subset| subset.len() == size
            && subset.windows(2).all(|pair| pair[0] < pair[1])
            && subset.iter().all(|position| *position < count)));
    }
    for (count, bound) in [(20, 6), (13, 4)] {
        let sample = checked_departures(count, bound);
        assert_eq!(sample.len(), CHECKED_SETS);
        assert!(sample.contains(&Vec::new()));
        assert!(sample.iter().all(|set| set.len() <= bound));
        let distinct: std::collections::BTreeSet<_> = sample.iter().collect();
        assert_eq!(distinct.len(), sample.len());
    }
    assert_eq!(binomial(20, 7), 77_520);
}
