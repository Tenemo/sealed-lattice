use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::{
    bgv::{
        encoding::CandidatePlaintextRing,
        modular_arithmetic::{inverse_mod, pow_mod},
        parameters::{
            CANDIDATE_PLAINTEXT_DEGREE, CANDIDATE_PLAINTEXT_MODULUS, LOGICAL_SLOT_GENERATOR,
        },
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
};

pub(crate) const CHARACTER_ROW_COUNT: usize = 256;
pub(crate) const TILE_WIDTH: usize = 64;
pub(crate) const SIGN_SLOT_COUNT: usize = TILE_WIDTH * CHARACTER_ROW_COUNT;
pub(crate) const CHARACTER_SLOT_COUNT: usize = 2 * SIGN_SLOT_COUNT;
const OPTION_COUNT: usize = 20;
const PAIR_COUNT: usize = OPTION_COUNT * (OPTION_COUNT - 1) / 2;
const LOGICAL_GENERATOR_ORDER: usize = CANDIDATE_PLAINTEXT_DEGREE / 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum PairTile {
    First,
    Second,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum PairSign {
    Positive,
    Negative,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PairBin {
    pub(crate) tile: PairTile,
    pub(crate) sign: PairSign,
    pub(crate) option_shift: usize,
    pub(crate) destination_start: usize,
    pub(crate) pair_count: usize,
}

const fn pair_bin(
    tile: PairTile,
    sign: PairSign,
    option_shift: usize,
    destination_start: usize,
    pair_count: usize,
) -> PairBin {
    PairBin {
        tile,
        sign,
        option_shift,
        destination_start,
        pair_count,
    }
}

pub(crate) const EXACT_PAIR_BINS: [PairBin; 19] = [
    pair_bin(PairTile::First, PairSign::Positive, 10, 0, 10),
    pair_bin(PairTile::First, PairSign::Positive, 9, 10, 11),
    pair_bin(PairTile::First, PairSign::Positive, 6, 21, 14),
    pair_bin(PairTile::First, PairSign::Positive, 7, 35, 13),
    pair_bin(PairTile::First, PairSign::Positive, 4, 48, 16),
    pair_bin(PairTile::First, PairSign::Negative, 16, 0, 4),
    pair_bin(PairTile::First, PairSign::Negative, 3, 4, 17),
    pair_bin(PairTile::First, PairSign::Negative, 18, 21, 2),
    pair_bin(PairTile::First, PairSign::Negative, 15, 23, 5),
    pair_bin(PairTile::First, PairSign::Negative, 11, 28, 9),
    pair_bin(PairTile::First, PairSign::Negative, 8, 37, 12),
    pair_bin(PairTile::First, PairSign::Negative, 5, 49, 15),
    pair_bin(PairTile::Second, PairSign::Positive, 17, 0, 3),
    pair_bin(PairTile::Second, PairSign::Positive, 2, 3, 18),
    pair_bin(PairTile::Second, PairSign::Positive, 19, 21, 1),
    pair_bin(PairTile::Second, PairSign::Positive, 14, 22, 6),
    pair_bin(PairTile::Second, PairSign::Positive, 13, 28, 7),
    pair_bin(PairTile::Second, PairSign::Positive, 12, 35, 8),
    pair_bin(PairTile::Second, PairSign::Positive, 1, 43, 19),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PairLocation {
    pub(crate) lower_option: usize,
    pub(crate) higher_option: usize,
    pub(crate) tile: PairTile,
    pub(crate) sign: PairSign,
    pub(crate) destination_candidate: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PairwiseCharacterTopology {
    bins: Vec<PairBin>,
}

impl PairwiseCharacterTopology {
    pub(crate) fn exact() -> CanonicalResult<Self> {
        Self::new(EXACT_PAIR_BINS.to_vec())
    }

    fn new(bins: Vec<PairBin>) -> CanonicalResult<Self> {
        if bins.len() != OPTION_COUNT - 1 {
            return Err(topology_error(
                "pair topology must contain one bin for every nonzero option shift",
            ));
        }

        let mut shift_seen = [false; OPTION_COUNT];
        let mut total_pair_count = 0_usize;
        for bin in &bins {
            if bin.option_shift == 0
                || bin.option_shift >= OPTION_COUNT
                || bin.pair_count != OPTION_COUNT - bin.option_shift
                || bin.pair_count == 0
                || bin
                    .destination_start
                    .checked_add(bin.pair_count)
                    .map_or(true, |end| end > TILE_WIDTH)
                || shift_seen[bin.option_shift]
            {
                return Err(topology_error("pair topology contains a malformed bin"));
            }
            shift_seen[bin.option_shift] = true;
            total_pair_count = total_pair_count
                .checked_add(bin.pair_count)
                .ok_or_else(|| topology_error("pair topology count overflowed"))?;
        }
        if !shift_seen[1..].iter().all(|was_seen| *was_seen) || total_pair_count != PAIR_COUNT {
            return Err(topology_error(
                "pair topology does not cover every unordered option pair exactly once",
            ));
        }

        for tile in [PairTile::First, PairTile::Second] {
            for sign in [PairSign::Positive, PairSign::Negative] {
                let mut ranges = bins
                    .iter()
                    .filter(|bin| bin.tile == tile && bin.sign == sign)
                    .map(|bin| {
                        (
                            bin.destination_start,
                            bin.destination_start + bin.pair_count,
                        )
                    })
                    .collect::<Vec<_>>();
                ranges.sort_unstable();
                if !ranges.is_empty()
                    && (ranges[0].0 != 0
                        || ranges
                            .windows(2)
                            .any(|adjacent| adjacent[0].1 != adjacent[1].0))
                {
                    return Err(topology_error(
                        "pair topology destination ranges must be compact and disjoint",
                    ));
                }
            }
        }

        Ok(Self { bins })
    }

    pub(crate) fn bins(&self) -> &[PairBin] {
        &self.bins
    }

    pub(crate) fn pair_locations(&self) -> Vec<PairLocation> {
        self.bins
            .iter()
            .flat_map(|bin| {
                (0..bin.pair_count).map(|lower_option| PairLocation {
                    lower_option,
                    higher_option: lower_option + bin.option_shift,
                    tile: bin.tile,
                    sign: bin.sign,
                    destination_candidate: bin.destination_start + lower_option,
                })
            })
            .collect()
    }

    pub(crate) fn mask_slots(&self, bin: PairBin) -> CanonicalResult<Vec<u64>> {
        if !self.bins.contains(&bin) {
            return Err(topology_error("pair mask requested an unknown bin"));
        }
        let mut slots = vec![0_u64; CHARACTER_SLOT_COUNT];
        for row in 0..CHARACTER_ROW_COUNT {
            for destination_candidate in
                bin.destination_start..bin.destination_start + bin.pair_count
            {
                slots[logical_slot(bin.sign, destination_candidate, row)?] = 1;
            }
        }
        Ok(slots)
    }

    pub(crate) fn source_automorphisms(
        &self,
        bin: PairBin,
    ) -> CanonicalResult<(SourceAutomorphism, SourceAutomorphism)> {
        if !self.bins.contains(&bin) {
            return Err(topology_error("pair routing requested an unknown bin"));
        }
        let lower_conjugated = bin.sign == PairSign::Negative;
        Ok((
            SourceAutomorphism {
                generator_exponent: -(bin.destination_start as i32),
                conjugated: lower_conjugated,
            },
            SourceAutomorphism {
                generator_exponent: bin.option_shift as i32 - bin.destination_start as i32,
                conjugated: !lower_conjugated,
            },
        ))
    }

    pub(crate) fn rank_scatter_automorphisms(
        &self,
        bin: PairBin,
    ) -> CanonicalResult<(SourceAutomorphism, SourceAutomorphism)> {
        if !self.bins.contains(&bin) {
            return Err(topology_error("rank scatter requested an unknown pair bin"));
        }
        let conjugated = bin.sign == PairSign::Negative;
        Ok((
            SourceAutomorphism {
                generator_exponent: bin.destination_start as i32,
                conjugated,
            },
            SourceAutomorphism {
                generator_exponent: bin.destination_start as i32 - bin.option_shift as i32,
                conjugated,
            },
        ))
    }

    pub(crate) fn distinct_gather_sources(&self) -> CanonicalResult<Vec<SourceAutomorphism>> {
        let mut sources = BTreeSet::new();
        for bin in &self.bins {
            let (lower_source, higher_source) = self.source_automorphisms(*bin)?;
            sources.insert(lower_source);
            sources.insert(higher_source);
        }
        Ok(sources.into_iter().collect())
    }

    pub(crate) fn rank_scatter_routes(&self) -> CanonicalResult<Vec<RankScatterRoute>> {
        let mut terms_by_automorphism = BTreeMap::<SourceAutomorphism, Vec<RankScatterTerm>>::new();
        for bin in &self.bins {
            let (lower_scatter, higher_scatter) = self.rank_scatter_automorphisms(*bin)?;
            terms_by_automorphism
                .entry(lower_scatter)
                .or_default()
                .push(RankScatterTerm {
                    bin: *bin,
                    contribution: RankContribution::Negative,
                });
            terms_by_automorphism
                .entry(higher_scatter)
                .or_default()
                .push(RankScatterTerm {
                    bin: *bin,
                    contribution: RankContribution::Positive,
                });
        }
        Ok(terms_by_automorphism
            .into_iter()
            .map(|(automorphism, terms)| RankScatterRoute {
                automorphism,
                terms,
            })
            .collect())
    }
}

pub(crate) fn logical_slot(sign: PairSign, candidate: usize, row: usize) -> CanonicalResult<usize> {
    if candidate >= TILE_WIDTH || row >= CHARACTER_ROW_COUNT {
        return Err(topology_error(
            "pair topology logical slot coordinate is outside its geometry",
        ));
    }
    let sign_offset = match sign {
        PairSign::Positive => 0,
        PairSign::Negative => SIGN_SLOT_COUNT,
    };
    Ok(sign_offset + candidate + TILE_WIDTH * row)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct SourceAutomorphism {
    generator_exponent: i32,
    conjugated: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RankContribution {
    Negative,
    Positive,
}

impl RankContribution {
    pub(crate) const fn residue(self) -> u64 {
        match self {
            Self::Negative => CANDIDATE_PLAINTEXT_MODULUS - 1,
            Self::Positive => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RankScatterTerm {
    pub(crate) bin: PairBin,
    pub(crate) contribution: RankContribution,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RankScatterRoute {
    pub(crate) automorphism: SourceAutomorphism,
    pub(crate) terms: Vec<RankScatterTerm>,
}

impl SourceAutomorphism {
    pub(crate) const fn generator_exponent(self) -> i32 {
        self.generator_exponent
    }

    pub(crate) const fn is_conjugated(self) -> bool {
        self.conjugated
    }

    pub(crate) fn galois_element(
        self,
        candidate_ring: CandidatePlaintextRing,
    ) -> CanonicalResult<usize> {
        let automorphism_modulus = candidate_ring
            .ring_degree()
            .checked_mul(2)
            .ok_or_else(|| topology_error("candidate automorphism modulus overflowed"))?;
        let generator_power =
            signed_generator_power(self.generator_exponent, automorphism_modulus)?;
        Ok(if self.conjugated {
            automorphism_modulus - generator_power
        } else {
            generator_power
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum BaseGaloisKey {
    PositiveThirtyEight,
    NegativeSeven,
    NegativeOne,
    Conjugation,
}

const BASE_GALOIS_KEYS: [BaseGaloisKey; 4] = [
    BaseGaloisKey::PositiveThirtyEight,
    BaseGaloisKey::NegativeSeven,
    BaseGaloisKey::NegativeOne,
    BaseGaloisKey::Conjugation,
];

impl BaseGaloisKey {
    fn source_automorphism(self) -> SourceAutomorphism {
        match self {
            Self::PositiveThirtyEight => SourceAutomorphism {
                generator_exponent: 38,
                conjugated: false,
            },
            Self::NegativeSeven => SourceAutomorphism {
                generator_exponent: -7,
                conjugated: false,
            },
            Self::NegativeOne => SourceAutomorphism {
                generator_exponent: -1,
                conjugated: false,
            },
            Self::Conjugation => SourceAutomorphism {
                generator_exponent: 0,
                conjugated: true,
            },
        }
    }
}

#[derive(Clone, Copy)]
struct SearchPredecessor {
    previous_state: usize,
    key: BaseGaloisKey,
}

pub(crate) fn shortest_base_key_path(
    target: SourceAutomorphism,
) -> CanonicalResult<Vec<BaseGaloisKey>> {
    let state_count = 2 * LOGICAL_GENERATOR_ORDER;
    let target_state = search_state_index(target);
    let mut predecessors = vec![None; state_count];
    let mut queue = VecDeque::from([0_usize]);
    predecessors[0] = Some(SearchPredecessor {
        previous_state: 0,
        key: BaseGaloisKey::Conjugation,
    });
    while let Some(state) = queue.pop_front() {
        if state == target_state {
            break;
        }
        for key in BASE_GALOIS_KEYS {
            let next_state = apply_search_key(state, key);
            if predecessors[next_state].is_none() {
                predecessors[next_state] = Some(SearchPredecessor {
                    previous_state: state,
                    key,
                });
                queue.push_back(next_state);
            }
        }
    }
    if predecessors[target_state].is_none() {
        return Err(topology_error(
            "base Galois keys do not reach a required source automorphism",
        ));
    }

    let mut reversed_path = Vec::new();
    let mut state = target_state;
    while state != 0 {
        let predecessor = predecessors[state]
            .ok_or_else(|| topology_error("Galois shortest-path predecessor is missing"))?;
        reversed_path.push(predecessor.key);
        state = predecessor.previous_state;
    }
    reversed_path.reverse();
    Ok(reversed_path)
}

pub(crate) fn shared_prefix_key_hop_count(
    targets: &[SourceAutomorphism],
) -> CanonicalResult<usize> {
    let mut prefixes = BTreeSet::<Vec<BaseGaloisKey>>::new();
    for target in targets {
        let path = shortest_base_key_path(*target)?;
        for prefix_length in 1..=path.len() {
            prefixes.insert(path[..prefix_length].to_vec());
        }
    }
    Ok(prefixes.len())
}

fn search_state_index(source: SourceAutomorphism) -> usize {
    usize::from(source.conjugated) * LOGICAL_GENERATOR_ORDER
        + source
            .generator_exponent
            .rem_euclid(LOGICAL_GENERATOR_ORDER as i32) as usize
}

fn apply_search_key(state: usize, key: BaseGaloisKey) -> usize {
    let conjugated = state >= LOGICAL_GENERATOR_ORDER;
    let exponent = state % LOGICAL_GENERATOR_ORDER;
    let source = key.source_automorphism();
    usize::from(conjugated ^ source.conjugated) * LOGICAL_GENERATOR_ORDER
        + (exponent as i32 + source.generator_exponent).rem_euclid(LOGICAL_GENERATOR_ORDER as i32)
            as usize
}

fn signed_generator_power(exponent: i32, modulus: usize) -> CanonicalResult<usize> {
    let modulus_u64 = u64::try_from(modulus)
        .map_err(|_| topology_error("candidate automorphism modulus does not fit u64"))?;
    let generator = u64::try_from(LOGICAL_SLOT_GENERATOR)
        .map_err(|_| topology_error("logical-slot generator does not fit u64"))?;
    let (base, magnitude) = if exponent < 0 {
        (
            inverse_mod(generator, modulus_u64)?,
            exponent.unsigned_abs() as u64,
        )
    } else {
        (generator, exponent as u64)
    };
    usize::try_from(pow_mod(base, magnitude, modulus_u64)?)
        .map_err(|_| topology_error("candidate Galois element does not fit usize"))
}

fn topology_error(message: &'static str) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidProtocolObject, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXACT_MASK_NORMS: [(u128, u64, usize); 19] = [
        (2_186_502, 32_734, 127),
        (2_147_350, 32_768, 128),
        (1_725_188, 32_746, 127),
        (2_071_442, 32_768, 128),
        (1_533_564, 32_159, 99),
        (2_165_425, 32_759, 123),
        (1_731_640, 32_768, 128),
        (1_914_209, 32_649, 127),
        (2_054_901, 32_768, 128),
        (1_952_100, 32_768, 128),
        (2_111_568, 32_620, 123),
        (1_735_650, 32_768, 128),
        (1_941_915, 32_768, 128),
        (1_774_773, 32_746, 127),
        (1_786_320, 32_768, 128),
        (1_967_379, 32_702, 127),
        (2_146_485, 32_768, 128),
        (1_901_520, 32_693, 115),
        (1_981_801, 32_768, 128),
    ];

    #[test]
    fn exact_bins_cover_all_pairs_and_the_three_compact_destinations() {
        let topology = PairwiseCharacterTopology::exact().expect("exact pair topology");
        let locations = topology.pair_locations();
        assert_eq!(locations.len(), PAIR_COUNT);

        let mut pair_seen = [[false; OPTION_COUNT]; OPTION_COUNT];
        for location in locations {
            assert!(location.lower_option < location.higher_option);
            assert!(!pair_seen[location.lower_option][location.higher_option]);
            pair_seen[location.lower_option][location.higher_option] = true;
            assert!(location.destination_candidate < TILE_WIDTH);
        }
        assert!((0..OPTION_COUNT).all(|lower_option| {
            (lower_option + 1..OPTION_COUNT)
                .all(|higher_option| pair_seen[lower_option][higher_option])
        }));

        let occupied_counts = [
            (PairTile::First, PairSign::Positive, 64),
            (PairTile::First, PairSign::Negative, 64),
            (PairTile::Second, PairSign::Positive, 62),
        ];
        for (tile, sign, expected_count) in occupied_counts {
            assert_eq!(
                topology
                    .bins()
                    .iter()
                    .filter(|bin| bin.tile == tile && bin.sign == sign)
                    .map(|bin| bin.pair_count)
                    .sum::<usize>(),
                expected_count,
            );
        }
        assert!(
            topology
                .bins()
                .iter()
                .all(|bin| !(bin.tile == PairTile::Second && bin.sign == PairSign::Negative))
        );
    }

    #[test]
    fn exact_masks_use_logical_orbit_order_and_match_dense_coefficient_norms() {
        let topology = PairwiseCharacterTopology::exact().expect("exact pair topology");
        let mut maximum_infinity_norm = 0_u64;
        for (bin, expected_norms) in topology.bins().iter().zip(EXACT_MASK_NORMS) {
            let mask_slots = topology.mask_slots(*bin).expect("bin mask slots");
            assert_eq!(
                mask_slots.iter().filter(|slot| **slot == 1).count(),
                bin.pair_count * CHARACTER_ROW_COUNT,
            );
            let fully_split_coefficients = CandidatePlaintextRing::FullySplit
                .encode_logical_slots(&mask_slots)
                .expect("fully split mask encoding");
            let (l1_norm, infinity_norm) = centered_norms(&fully_split_coefficients);
            assert_eq!(
                (
                    l1_norm,
                    infinity_norm,
                    fully_split_coefficients
                        .iter()
                        .filter(|coefficient| **coefficient != 0)
                        .count(),
                ),
                expected_norms,
                "bin {bin:?}",
            );
            maximum_infinity_norm = maximum_infinity_norm.max(infinity_norm);

            let even_subring_coefficients = CandidatePlaintextRing::EvenSubring
                .encode_logical_slots(&mask_slots)
                .expect("even-subring mask encoding");
            assert_eq!(
                centered_norms(&even_subring_coefficients),
                (l1_norm, infinity_norm),
                "the fallback embedding must preserve exact mask norms",
            );
        }
        assert_eq!(maximum_infinity_norm, 32_768);
        assert_eq!(
            EXACT_MASK_NORMS
                .into_iter()
                .map(|(l1_norm, _, _)| l1_norm)
                .max(),
            Some(2_186_502),
        );
    }

    #[test]
    fn shortest_paths_use_the_four_base_keys_and_total_172_hops() {
        let topology = PairwiseCharacterTopology::exact().expect("exact pair topology");
        let mut group_hops = [0_usize; 3];
        for bin in topology.bins() {
            let (lower_source, higher_source) = topology
                .source_automorphisms(*bin)
                .expect("source automorphisms");
            for source in [lower_source, higher_source] {
                let path = shortest_base_key_path(source).expect("shortest base-key path");
                assert_path_product(&path, source, CandidatePlaintextRing::FullySplit);
                assert_path_product(&path, source, CandidatePlaintextRing::EvenSubring);
                let group_index = match (bin.tile, bin.sign) {
                    (PairTile::First, PairSign::Positive) => 0,
                    (PairTile::First, PairSign::Negative) => 1,
                    (PairTile::Second, PairSign::Positive) => 2,
                    (PairTile::Second, PairSign::Negative) => unreachable!(),
                };
                group_hops[group_index] += path.len();
            }
        }
        assert_eq!(group_hops, [50, 66, 56]);
        assert_eq!(group_hops.into_iter().sum::<usize>(), 172);
    }

    #[test]
    fn shared_gather_dag_reuses_duplicate_sources_and_common_path_prefixes() {
        let topology = PairwiseCharacterTopology::exact().expect("exact pair topology");
        let distinct_sources = topology
            .distinct_gather_sources()
            .expect("distinct gather sources");
        assert_eq!(distinct_sources.len(), 30);
        assert_eq!(
            distinct_sources
                .iter()
                .map(|source| shortest_base_key_path(*source).expect("source path").len())
                .sum::<usize>(),
            144,
        );
        assert_eq!(
            shared_prefix_key_hop_count(&distinct_sources).expect("shared gather path DAG"),
            49,
        );
    }

    #[test]
    fn grouped_rank_scatter_routes_cover_both_pair_contributions_in_207_hops() {
        let topology = PairwiseCharacterTopology::exact().expect("exact pair topology");
        let routes = topology.rank_scatter_routes().expect("rank scatter routes");
        assert_eq!(routes.len(), 32);
        assert_eq!(
            routes.iter().map(|route| route.terms.len()).sum::<usize>(),
            2 * (OPTION_COUNT - 1),
        );
        assert_eq!(
            routes
                .iter()
                .map(|route| shortest_base_key_path(route.automorphism)
                    .expect("scatter route path")
                    .len())
                .sum::<usize>(),
            207,
        );

        let mut bin_contributions = BTreeMap::<PairBin, Vec<RankContribution>>::new();
        for route in routes {
            assert_path_product(
                &shortest_base_key_path(route.automorphism).expect("scatter route path"),
                route.automorphism,
                CandidatePlaintextRing::FullySplit,
            );
            for term in route.terms {
                bin_contributions
                    .entry(term.bin)
                    .or_default()
                    .push(term.contribution);
            }
        }
        assert_eq!(bin_contributions.len(), OPTION_COUNT - 1);
        assert!(bin_contributions.values().all(|contributions| {
            contributions.len() == 2
                && contributions.contains(&RankContribution::Negative)
                && contributions.contains(&RankContribution::Positive)
        }));
    }

    #[test]
    fn base_key_and_orbit_elements_match_both_candidate_ring_geometries() {
        assert_eq!(
            BASE_GALOIS_KEYS.map(|key| key
                .source_automorphism()
                .galois_element(CandidatePlaintextRing::FullySplit)
                .expect("fully split key")),
            [64_857, 7_971, 43_691, 65_535],
        );
        assert_eq!(
            BASE_GALOIS_KEYS.map(|key| key
                .source_automorphism()
                .galois_element(CandidatePlaintextRing::EvenSubring)
                .expect("full-ring key")),
            [130_393, 7_971, 43_691, 131_071],
        );

        let full_ring_modulus = 2 * CandidatePlaintextRing::EvenSubring.ring_degree();
        let orbit_generator =
            signed_generator_power(64, full_ring_modulus).expect("full-ring orbit generator");
        assert_eq!(orbit_generator, 48_385);
        let orbit_powers = (1..=8)
            .map(|power| {
                usize::try_from(
                    pow_mod(orbit_generator as u64, power, full_ring_modulus as u64)
                        .expect("orbit power"),
                )
                .expect("orbit power fits usize")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            orbit_powers,
            [
                48_385, 31_233, 62_465, 124_929, 118_785, 106_497, 81_921, 32_769
            ],
        );
    }

    #[test]
    fn orbit_power_256_is_identity_only_on_even_full_ring_messages() {
        let ring_degree = CandidatePlaintextRing::EvenSubring.ring_degree();
        let automorphism_modulus = 2 * ring_degree;
        let orbit_generator =
            signed_generator_power(64, automorphism_modulus).expect("orbit generator");
        let orbit_power_256 = usize::try_from(
            pow_mod(
                orbit_generator as u64,
                CHARACTER_ROW_COUNT as u64,
                automorphism_modulus as u64,
            )
            .expect("orbit power 256"),
        )
        .expect("orbit power fits usize");
        assert_eq!(orbit_power_256, 65_537);

        let mut even_message = vec![0_u64; ring_degree];
        for coefficient_index in (0..ring_degree).step_by(2) {
            even_message[coefficient_index] = (coefficient_index as u64 + 1) % 65_537;
        }
        assert_eq!(
            apply_automorphism(&even_message, orbit_power_256),
            even_message,
        );

        let mut odd_message = even_message;
        odd_message[1] = 1;
        assert_ne!(
            apply_automorphism(&odd_message, orbit_power_256),
            odd_message,
        );
        assert_eq!(apply_automorphism(&odd_message, orbit_power_256)[1], 65_536);
    }

    #[test]
    fn malformed_pair_maps_reject_before_mask_or_routing_use() {
        let mutations: [fn(&mut [PairBin]); 4] = [
            |bins: &mut [PairBin]| bins[1].option_shift = bins[0].option_shift,
            |bins: &mut [PairBin]| bins[0].pair_count -= 1,
            |bins: &mut [PairBin]| bins[1].destination_start -= 1,
            |bins: &mut [PairBin]| bins[0].destination_start = TILE_WIDTH,
        ];
        for mutate in mutations {
            let mut bins = EXACT_PAIR_BINS.to_vec();
            mutate(&mut bins);
            assert!(PairwiseCharacterTopology::new(bins).is_err());
        }
        assert!(
            PairwiseCharacterTopology::new(EXACT_PAIR_BINS[..EXACT_PAIR_BINS.len() - 1].to_vec())
                .is_err()
        );
        assert!(logical_slot(PairSign::Positive, TILE_WIDTH, 0).is_err());
        assert!(logical_slot(PairSign::Negative, 0, CHARACTER_ROW_COUNT).is_err());
    }

    fn centered_norms(coefficients: &[u64]) -> (u128, u64) {
        coefficients
            .iter()
            .fold((0_u128, 0_u64), |(l1_norm, infinity_norm), coefficient| {
                let magnitude = if *coefficient > CANDIDATE_PLAINTEXT_MODULUS / 2 {
                    CANDIDATE_PLAINTEXT_MODULUS - *coefficient
                } else {
                    *coefficient
                };
                (
                    l1_norm + u128::from(magnitude),
                    infinity_norm.max(magnitude),
                )
            })
    }

    fn assert_path_product(
        path: &[BaseGaloisKey],
        expected: SourceAutomorphism,
        candidate_ring: CandidatePlaintextRing,
    ) {
        let automorphism_modulus = 2 * candidate_ring.ring_degree();
        let actual = path.iter().fold(1_usize, |product, key| {
            let key_element = key
                .source_automorphism()
                .galois_element(candidate_ring)
                .expect("base key element");
            usize::try_from(product as u128 * key_element as u128 % automorphism_modulus as u128)
                .expect("path product fits usize")
        });
        assert_eq!(
            actual,
            expected
                .galois_element(candidate_ring)
                .expect("expected source element"),
        );
    }

    fn apply_automorphism(coefficients: &[u64], galois_element: usize) -> Vec<u64> {
        let ring_degree = coefficients.len();
        let automorphism_modulus = 2 * ring_degree;
        let mut output = vec![0_u64; ring_degree];
        for (coefficient_index, coefficient) in coefficients.iter().copied().enumerate() {
            let mapped_exponent = usize::try_from(
                coefficient_index as u128 * galois_element as u128 % automorphism_modulus as u128,
            )
            .expect("automorphism exponent fits usize");
            output[mapped_exponent % ring_degree] =
                if mapped_exponent >= ring_degree && coefficient != 0 {
                    CANDIDATE_PLAINTEXT_MODULUS - coefficient
                } else {
                    coefficient
                };
        }
        output
    }
}
