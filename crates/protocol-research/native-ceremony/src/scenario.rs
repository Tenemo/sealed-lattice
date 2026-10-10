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
    pub departed: Option<usize>,
    pub selection_fork: bool,
}
impl Scenario {
    pub fn new(profile: Profile) -> Self {
        let corrupt = profile.maximum_corrupt_participants();
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
            departed: None,
            selection_fork: false,
        }
    }
    pub fn setup_departure() -> Self {
        Self {
            profile: Profile::new(4, 2).unwrap(),
            equivocator: None,
            invalid_proof: None,
            wrong_position: None,
            voters: vec![0, 2, 3],
            omitted: None,
            nonvoters: Vec::new(),
            departed: Some(1),
            selection_fork: false,
        }
    }
    pub fn selection_fork() -> Self {
        Self {
            profile: Profile::new(4, 2).unwrap(),
            equivocator: None,
            invalid_proof: None,
            wrong_position: None,
            voters: vec![0, 1, 2, 3],
            omitted: None,
            nonvoters: Vec::new(),
            departed: None,
            selection_fork: true,
        }
    }
    pub fn active(&self) -> Vec<usize> {
        (0..self.profile.participants())
            .filter(|position| Some(*position) != self.departed)
            .collect()
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
        if self.selection_fork {
            position == 0
        } else if self.departed.is_some() {
            position == 2
        } else {
            (1..=self.profile.maximum_corrupt_participants()).contains(&position)
        }
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
        participants - self.profile.maximum_corrupt_participants()..participants
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
        self.honest()
            .into_iter()
            .find(|position| *position != 0 && Some(*position) != self.departed)
            .unwrap()
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
#[path = "scenario-tests.rs"]
mod tests;
