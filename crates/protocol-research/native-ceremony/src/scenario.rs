use supported_profile::{MAXIMUM_SCORE, Profile};

/// Release subsets and departure sets checked after share generation. Every
/// set is checked when there are at most this many; otherwise the first and
/// last sets and a deterministic sample of others.
pub const CHECKED_SETS: usize = 256;

/// The fixture roles of the result case, derived from the profile.
///
/// Positions one to `f` form the corrupt set. The last corrupt position
/// equivocates: it signs two on-time envelopes over one body and a late one,
/// each from its own fork. The corrupt position before it signs position
/// zero's body with its own position in the statement, so the proof fails,
/// and the one before that signs position zero's unchanged body under its own
/// envelope. Any other corrupt position casts nothing, and every corrupt
/// position withholds its target signature.
///
/// The first `f + 2` honest positions cast accepted ballots, which meets the
/// minimum turnout. When `f` is positive and another honest position remains,
/// the relay delivers the last position's ballot only to the last `f`
/// positions, whose close responses the organizer's proposal of `n - f`
/// responses does not use. The remaining honest positions cast nothing.
pub struct Scenario {
    profile: Profile,
    pub equivocator: Option<usize>,
    pub invalid_proof: Option<usize>,
    pub wrong_position: Option<usize>,
    pub voters: Vec<usize>,
    pub omitted: Option<usize>,
    pub nonvoters: Vec<usize>,
}
impl Scenario {
    pub fn new(profile: Profile) -> Self {
        let corrupt = profile.corrupt();
        let role = |rank: usize| corrupt.checked_sub(rank).filter(|position| *position > 0);
        let honest: Vec<_> = (0..profile.participants())
            .filter(|position| *position == 0 || *position > corrupt)
            .collect();
        let turnout = profile.minimum_turnout();
        let voters = honest[..turnout].to_vec();
        let omitted = (corrupt > 0 && honest.len() > turnout).then(|| profile.participants() - 1);
        let nonvoters = honest[turnout..]
            .iter()
            .copied()
            .filter(|position| Some(*position) != omitted)
            .collect();
        Self {
            profile,
            equivocator: role(0),
            invalid_proof: role(1),
            wrong_position: role(2),
            voters,
            omitted,
            nonvoters,
        }
    }
    pub fn profile(&self) -> Profile {
        self.profile
    }
    pub fn honest(&self) -> Vec<usize> {
        (0..self.profile.participants())
            .filter(|position| !self.corrupt(*position))
            .collect()
    }
    pub fn corrupt(&self, position: usize) -> bool {
        (1..=self.profile.corrupt()).contains(&position)
    }
    /// The authors of the usable slots: every accepted voter and the corrupt
    /// authors of authenticated invalid ballots.
    pub fn usable(&self) -> Vec<usize> {
        let mut authors = self.voters.clone();
        authors.extend(self.invalid_proof);
        authors.extend(self.wrong_position);
        authors.sort_unstable();
        authors
    }
    /// The positions that hold the omitted ballot: the last `f`, including
    /// its author.
    pub fn omitted_holders(&self) -> std::ops::Range<usize> {
        let participants = self.profile.participants();
        participants - self.profile.corrupt()..participants
    }
    /// The positions the equivocator's first and second on-time envelopes
    /// reach besides itself. The organizer holds neither and the omitted
    /// voter only its own ballot.
    pub fn equivocation_holders(&self, second: bool) -> Vec<usize> {
        let participants = self.profile.participants();
        (1..participants)
            .filter(|position| {
                Some(*position) != self.equivocator
                    && Some(*position) != self.omitted
                    && (*position > participants / 2) == second
            })
            .collect()
    }
    /// The first honest position after the organizer, which receives the
    /// late envelope before the close intent.
    pub fn first_honest_responder(&self) -> usize {
        self.profile.corrupt() + 1
    }
    /// A ballot's scores: every option receives a score from one to the
    /// maximum.
    pub fn scores(&self, position: usize) -> Vec<u8> {
        (0..self.profile.options())
            .map(|option| {
                let value = position * position + 5 * position + 3 * option + 7 * position * option;
                (1 + value % MAXIMUM_SCORE) as u8
            })
            .collect()
    }
}

/// The subsets of the given size of `0..count` in lexicographic order, when
/// there are at most `CHECKED_SETS`; otherwise the first, the last and a
/// deterministic sample of distinct others.
pub fn checked_subsets(count: usize, size: usize) -> Vec<Vec<usize>> {
    let mut all = Vec::new();
    let mut chosen = Vec::with_capacity(size);
    fn extend(
        next: usize,
        count: usize,
        size: usize,
        chosen: &mut Vec<usize>,
        all: &mut Vec<Vec<usize>>,
    ) -> bool {
        if chosen.len() == size {
            all.push(chosen.clone());
            return all.len() <= CHECKED_SETS;
        }
        for position in next..count {
            chosen.push(position);
            let continuing = extend(position + 1, count, size, chosen, all);
            chosen.pop();
            if !continuing {
                return false;
            }
        }
        true
    }
    if extend(0, count, size, &mut chosen, &mut all) {
        return all;
    }
    let mut sample = std::collections::BTreeSet::from([
        (0..size).collect::<Vec<_>>(),
        (count - size..count).collect(),
    ]);
    let mut state = 0x2545_f491_4f6c_dd1d_u64 ^ ((count as u64) << 32 | size as u64);
    while sample.len() < CHECKED_SETS {
        let mut positions: Vec<usize> = (0..count).collect();
        for index in (1..count).rev() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            positions.swap(index, (state % (index as u64 + 1)) as usize);
        }
        let mut subset = positions[..size].to_vec();
        subset.sort_unstable();
        sample.insert(subset);
    }
    sample.into_iter().collect()
}
/// The sets of at most `bound` missing positions of `0..count`, by size:
/// every one when there are at most `CHECKED_SETS`, otherwise evenly spaced
/// members of the sizes' checked subsets, starting with no departure.
pub fn checked_departures(count: usize, bound: usize) -> Vec<Vec<usize>> {
    let all: Vec<_> = (0..=bound)
        .flat_map(|size| checked_subsets(count, size))
        .collect();
    let total: usize = (0..=bound).map(|size| binomial(count, size)).sum();
    if total <= CHECKED_SETS {
        assert_eq!(all.len(), total);
        return all;
    }
    (0..CHECKED_SETS)
        .map(|index| all[index * all.len() / CHECKED_SETS].clone())
        .collect()
}
pub fn binomial(count: usize, size: usize) -> usize {
    (0..size).fold(1, |value, index| value * (count - index) / (index + 1))
}

#[cfg(test)]
mod tests {
    use super::*;

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
            let corrupt = profile.corrupt();
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
}
