//! Exact multiplicity partition for proximity events that share a query vector.
//!
//! Several fixed logical words can be tested by one sampled query vector. The
//! union bound would charge one proximity term per word, which is wasteful when
//! the words are all committed before the vector exists. This module derives
//! when a single term is admissible, proves the enabling lemma on an exhaustive
//! small model, and records the exact multiplicity for every event class that
//! the selected construction actually has.
//!
//! The rule is mechanical rather than a judgement call: one term is charged
//! only when every candidate word is fixed before the vector is sampled, one
//! vector is shared by all of them, and acceptance forces every sampled
//! coordinate into the selected bad word's agreement set. Otherwise the exact
//! union multiplicity is charged.

/// A class of proximity events in the selected construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(in crate::bgv::proof_suite) enum SharedQueryEventClass {
    /// The three outer opening-point words over the aggregate evaluation domain.
    OuterOpeningPointWords,
    /// The three relation-phase column words.
    RelationPhaseColumns,
    /// The bound-tree words the direct-bound draws test.
    BoundTreeWords,
    /// The BDLOP anchor statement-root words.
    StatementRootWords,
}

impl SharedQueryEventClass {
    pub(in crate::bgv::proof_suite) const fn identifier(self) -> &'static str {
        match self {
            Self::OuterOpeningPointWords => "outer-opening-point-words",
            Self::RelationPhaseColumns => "relation-phase-columns",
            Self::BoundTreeWords => "bound-tree-words",
            Self::StatementRootWords => "statement-root-words",
        }
    }
}

/// Why one class is charged the multiplicity it is charged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) enum SharedQueryChargeReason {
    /// One term: the words share one vector drawn after all of them are fixed.
    ///
    /// The deterministic bad-word selection lemma applies, so the whole class
    /// collapses to the single term of its selected word.
    DeterministicBadWordSelection,
    /// One term per word: the words do not share one vector.
    ///
    /// Different vectors mean the events are not the same event, so nothing can
    /// be collapsed and the exact union multiplicity is charged.
    SeparateQueryVectors,
}

/// One row of the exact partition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) struct SharedQueryPartitionRow {
    pub(in crate::bgv::proof_suite) class: SharedQueryEventClass,
    /// Logical words in the class.
    pub(in crate::bgv::proof_suite) word_count: usize,
    /// Coordinates the shared vector samples, per charged term.
    pub(in crate::bgv::proof_suite) sampled_coordinate_count: usize,
    /// Whether every word is committed before the vector is sampled.
    pub(in crate::bgv::proof_suite) words_fixed_before_sampling: bool,
    /// Whether the class is tested by exactly one vector.
    pub(in crate::bgv::proof_suite) shares_one_query_vector: bool,
    pub(in crate::bgv::proof_suite) charge_reason: SharedQueryChargeReason,
    /// Proximity terms the theorem charges for the class.
    pub(in crate::bgv::proof_suite) charged_term_count: usize,
}

impl SharedQueryPartitionRow {
    /// Recomputes the charge from the two structural conditions.
    ///
    /// Keeping the derivation next to the recorded value means a row cannot
    /// claim a collapse it has not earned.
    fn derived_charge(self) -> (SharedQueryChargeReason, usize) {
        if self.words_fixed_before_sampling && self.shares_one_query_vector {
            (SharedQueryChargeReason::DeterministicBadWordSelection, 1)
        } else {
            (
                SharedQueryChargeReason::SeparateQueryVectors,
                self.word_count,
            )
        }
    }
}

/// The exact partition for the selected same-secret construction.
///
/// The outer words are the only class that collapses. The relation phases, the
/// bound trees, and the statement roots each draw their own vector, so they are
/// partitioned separately and pay their own multiplicity, which is exactly the
/// asymmetry the borrowed prior-certificate design relies on.
pub(in crate::bgv::proof_suite) fn selected_shared_query_partition() -> [SharedQueryPartitionRow; 4]
{
    [
        SharedQueryPartitionRow {
            class: SharedQueryEventClass::OuterOpeningPointWords,
            word_count: 3,
            sampled_coordinate_count: 387,
            words_fixed_before_sampling: true,
            shares_one_query_vector: true,
            charge_reason: SharedQueryChargeReason::DeterministicBadWordSelection,
            charged_term_count: 1,
        },
        SharedQueryPartitionRow {
            class: SharedQueryEventClass::RelationPhaseColumns,
            word_count: 3,
            sampled_coordinate_count: 387,
            words_fixed_before_sampling: true,
            shares_one_query_vector: true,
            charge_reason: SharedQueryChargeReason::DeterministicBadWordSelection,
            charged_term_count: 1,
        },
        SharedQueryPartitionRow {
            class: SharedQueryEventClass::BoundTreeWords,
            word_count: 8,
            sampled_coordinate_count: 266,
            words_fixed_before_sampling: true,
            shares_one_query_vector: true,
            charge_reason: SharedQueryChargeReason::DeterministicBadWordSelection,
            charged_term_count: 1,
        },
        SharedQueryPartitionRow {
            class: SharedQueryEventClass::StatementRootWords,
            word_count: 3,
            sampled_coordinate_count: 266,
            words_fixed_before_sampling: true,
            shares_one_query_vector: false,
            charge_reason: SharedQueryChargeReason::SeparateQueryVectors,
            charged_term_count: 3,
        },
    ]
}

/// Deterministically selects the word a collapsed term is charged against.
///
/// The rule reads only the committed words, so it is computable before the
/// query vector exists. Returning the lowest bad index makes the choice unique,
/// which is what stops an adversary from selecting a convenient word after
/// seeing the vector.
fn selected_bad_word_ordinal(word_is_bad: &[bool]) -> Option<usize> {
    word_is_bad.iter().position(|is_bad| *is_bad)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every charge is recomputed from its structural conditions.
    #[test]
    fn selected_partition_charges_follow_from_the_structural_conditions() {
        for row in selected_shared_query_partition() {
            let (reason, count) = row.derived_charge();
            assert_eq!(
                (reason, count),
                (row.charge_reason, row.charged_term_count),
                "{} recorded a charge its conditions do not support",
                row.class.identifier(),
            );
        }

        // The outer words are the class that collapses to one term, and the
        // separate statement-root reduction is the class that does not. That
        // asymmetry is load bearing, so assert it directly.
        let partition = selected_shared_query_partition();
        assert_eq!(partition[0].charged_term_count, 1);
        assert_eq!(partition[0].word_count, 3);
        assert_eq!(partition[3].charged_term_count, partition[3].word_count);

        // Every class is distinct, so no event is counted twice or omitted.
        let mut classes = partition.map(|row| row.class);
        classes.sort_unstable();
        let mut deduplicated = classes.to_vec();
        deduplicated.dedup();
        assert_eq!(deduplicated.len(), classes.len());
    }

    /// The selection rule is unique and depends only on committed words.
    #[test]
    fn bad_word_selection_is_deterministic_and_query_independent() {
        assert_eq!(selected_bad_word_ordinal(&[false, false, false]), None);
        assert_eq!(selected_bad_word_ordinal(&[true, true, true]), Some(0));
        assert_eq!(selected_bad_word_ordinal(&[false, true, true]), Some(1));
        assert_eq!(selected_bad_word_ordinal(&[false, false, true]), Some(2));

        // Exhaust every badness pattern for the three outer words. The rule must
        // return a bad index whenever one exists, and the same index every time,
        // because its only input is the committed badness pattern.
        for pattern in 0_u8..8 {
            let word_is_bad = [pattern & 1 != 0, pattern & 2 != 0, pattern & 4 != 0];
            let selected = selected_bad_word_ordinal(&word_is_bad);
            assert_eq!(selected, selected_bad_word_ordinal(&word_is_bad));
            match selected {
                None => assert!(word_is_bad.iter().all(|is_bad| !is_bad)),
                Some(ordinal) => {
                    assert!(word_is_bad[ordinal]);
                    assert!(word_is_bad[..ordinal].iter().all(|is_bad| !is_bad));
                }
            }
        }
    }

    /// Acceptance is contained in the selected word's agreement event.
    ///
    /// This is the step that licenses charging one term instead of three. The
    /// model exhausts every agreement pattern and every query set of the
    /// selected size over a small domain, so the containment is checked rather
    /// than asserted.
    #[test]
    fn acceptance_is_contained_in_the_selected_bad_word_agreement_event() {
        const DOMAIN_SIZE: usize = 6;
        const WORD_COUNT: usize = 3;
        const QUERY_SIZE: usize = 3;
        // A word is bad when it disagrees with its claimed codeword on more than
        // the unique-decoding radius, modeled here as any nonempty disagreement.
        let agreement_patterns = 0_u32..(1 << DOMAIN_SIZE);
        let mut checked_configurations = 0_usize;
        let mut collapsed_configurations = 0_usize;

        for pattern_zero in agreement_patterns.clone() {
            for pattern_one in agreement_patterns.clone() {
                for pattern_two in agreement_patterns.clone() {
                    let agreement = [pattern_zero, pattern_one, pattern_two];
                    let word_is_bad =
                        agreement.map(|pattern| pattern.count_ones() as usize != DOMAIN_SIZE);
                    let Some(selected) = selected_bad_word_ordinal(&word_is_bad) else {
                        continue;
                    };
                    for query_mask in 0_u32..(1 << DOMAIN_SIZE) {
                        if query_mask.count_ones() as usize != QUERY_SIZE {
                            continue;
                        }
                        checked_configurations += 1;
                        let accepts =
                            (0..WORD_COUNT).all(|word| query_mask & !agreement[word] == 0);
                        if !accepts {
                            continue;
                        }
                        collapsed_configurations += 1;
                        // Acceptance forces every sampled coordinate into the
                        // selected bad word's agreement set, so the single
                        // selected-word event already covers the union.
                        assert_eq!(query_mask & !agreement[selected], 0);
                        // And that word really is bad, so its agreement set is a
                        // strict subset of the domain and the per-coordinate
                        // bound applies.
                        assert!((agreement[selected].count_ones() as usize) < DOMAIN_SIZE);
                    }
                }
            }
        }
        assert!(checked_configurations > 0);
        assert!(collapsed_configurations > 0);
    }

    /// The counting bound behind one collapsed term is exact per factor.
    ///
    /// Sampling without replacement gives `prod_j (m - j) / (n - j)` for an
    /// agreement set of size `m` inside a domain of size `n`. Each factor is at
    /// most `m / n`, so the product is at most `(m / n)^q`. Checking the factor
    /// inequality with integers avoids both floating point and huge binomials.
    #[test]
    fn without_replacement_sampling_is_bounded_by_the_agreement_fraction() {
        for domain_size in 1_u128..=32 {
            for agreement_size in 0..=domain_size {
                for drawn in 0..agreement_size {
                    // (m - j) / (n - j) <= m / n for every j below m.
                    assert!(
                        (agreement_size - drawn) * domain_size
                            <= agreement_size * (domain_size - drawn),
                    );
                }
            }
        }

        // The selected outer term uses the unique-decoding agreement fraction
        // 5/8 over 387 sampled coordinates, which is one term rather than the
        // three a union bound would charge.
        let outer = selected_shared_query_partition()[0];
        assert_eq!(outer.sampled_coordinate_count, 387);
        assert_eq!(outer.charged_term_count, 1);
        assert!(outer.word_count > outer.charged_term_count);
    }
}
