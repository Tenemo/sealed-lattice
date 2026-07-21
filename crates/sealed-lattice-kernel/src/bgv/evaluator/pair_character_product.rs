//! Canonical streaming product topology for one pair-character ciphertext.
//!
//! The two ordered character ciphertexts use this same deterministic topology.
//! Ballots enter in their already-verified roster order, equal-depth nodes merge
//! immediately, and finalization combines the rightmost smaller subtrees first.

use zeroize::Zeroize;

use crate::{
    bgv::{
        direct_ballots::{MAXIMUM_SCORE, MINIMUM_SCORE},
        parameters::POLYNOMIAL_DEGREE,
        proof_suite::SelectedEvaluatorEntryKind,
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    foundation::FOUNDATION_PROFILE,
};

use super::{
    engine::{Ciphertext, ciphertext_tensor, modulus_switch, plaintext_mul},
    replay::VerifiedEvaluatorKeyContext,
    top_k::{
        CHARACTER_OUTPUT_LEVEL, SELECTED_EVALUATOR_MODULUS_SCHEDULE,
        SELECTED_EVALUATOR_WORKING_LEVEL, SELECTED_RELINEARIZATION_KEY_LEVEL,
    },
};

const PAIR_CHARACTER_SCORE_DIFFERENCE_BOUND: usize = (MAXIMUM_SCORE - MINIMUM_SCORE) as usize;
const FRESH_PAIR_CHARACTER_WIDTH: usize = 2 * PAIR_CHARACTER_SCORE_DIFFERENCE_BOUND + 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PairCharacterBallotSpan {
    pub(crate) first_ballot_ordinal: usize,
    pub(crate) ballot_count: usize,
}

impl PairCharacterBallotSpan {
    pub(crate) fn end_ballot_ordinal_exclusive(self) -> usize {
        self.first_ballot_ordinal + self.ballot_count
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PairCharacterProductNode {
    pub(crate) node_ordinal: usize,
    pub(crate) ballot_span: PairCharacterBallotSpan,
    pub(crate) multiplication_depth: usize,
    pub(crate) level: usize,
    pub(crate) message_width: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PairCharacterProductMergeKind {
    OnlineEqualDepth,
    RightmostFinalization,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PairCharacterProductMerge {
    pub(crate) kind: PairCharacterProductMergeKind,
    pub(crate) left_node_ordinal: usize,
    pub(crate) right_node_ordinal: usize,
    pub(crate) output_node_ordinal: usize,
    pub(crate) alignment_level: usize,
    pub(crate) left_alignment_drop_count: usize,
    pub(crate) right_alignment_drop_count: usize,
    pub(crate) depth_drop_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PairCharacterNormalization {
    pub(crate) coefficient_ordinal: usize,
    pub(crate) centered_coefficient_l1_norm: u64,
    pub(crate) convolution_infinity_operator_norm: u64,
}

impl PairCharacterNormalization {
    pub(crate) fn requires_plaintext_multiplication(&self) -> bool {
        self.coefficient_ordinal != 0
    }

    pub(crate) fn plaintext_coefficients(&self) -> Vec<u64> {
        let mut coefficients = vec![0_u64; POLYNOMIAL_DEGREE];
        coefficients[self.coefficient_ordinal] = 1;
        coefficients
    }
}

/// Exact per-character-stream operation and live-ciphertext accounting.
///
/// The resident count includes an operation's newly allocated output while its
/// input ciphertexts and every unrelated forest node are still live. It also
/// includes the corresponding input/output overlap for plaintext
/// normalization and modulus switching.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PairCharacterProductAccounting {
    pub(crate) ballot_ciphertext_count: usize,
    pub(crate) ciphertext_multiplication_count: usize,
    pub(crate) relinearization_count: usize,
    pub(crate) normalization_plaintext_multiplication_count: usize,
    pub(crate) alignment_modulus_switch_count: usize,
    pub(crate) alignment_modulus_drop_count: usize,
    pub(crate) depth_modulus_switch_count: usize,
    pub(crate) depth_modulus_drop_count: usize,
    pub(crate) terminal_modulus_switch_count: usize,
    pub(crate) terminal_modulus_drop_count: usize,
    pub(crate) maximum_resident_ciphertext_count: usize,
}

impl PairCharacterProductAccounting {
    pub(crate) fn modulus_switch_count(self) -> usize {
        self.alignment_modulus_switch_count
            + self.depth_modulus_switch_count
            + self.terminal_modulus_switch_count
    }

    pub(crate) fn modulus_drop_count(self) -> usize {
        self.alignment_modulus_drop_count
            + self.depth_modulus_drop_count
            + self.terminal_modulus_drop_count
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PairCharacterProductSchedule {
    pub(crate) ballot_count: usize,
    pub(crate) nodes: Vec<PairCharacterProductNode>,
    pub(crate) merges: Vec<PairCharacterProductMerge>,
    pub(crate) root_node_ordinal: usize,
    pub(crate) normalization: PairCharacterNormalization,
    pub(crate) terminal_output_level: usize,
    pub(crate) accounting: PairCharacterProductAccounting,
}

/// Derives the one canonical streaming product schedule for an accepted ballot
/// count. The schedule applies independently, and identically, to both ordered
/// pair-character ciphertexts.
pub(crate) fn canonical_pair_character_product_schedule(
    ballot_count: usize,
) -> CanonicalResult<PairCharacterProductSchedule> {
    let maximum_ballot_count = usize::from(FOUNDATION_PROFILE.participant_count);
    if ballot_count == 0 || ballot_count > maximum_ballot_count || maximum_ballot_count != 10 {
        return Err(invalid_schedule(
            "pair-character product schedule requires one through ten accepted ballots",
        ));
    }
    if PAIR_CHARACTER_SCORE_DIFFERENCE_BOUND != 9
        || FRESH_PAIR_CHARACTER_WIDTH != 19
        || SELECTED_EVALUATOR_MODULUS_SCHEDULE.character_depth_drop_counts != [1, 2, 0, 0]
        || SELECTED_EVALUATOR_WORKING_LEVEL != 22
        || CHARACTER_OUTPUT_LEVEL != 19
    {
        return Err(invalid_schedule(
            "pair-character product schedule does not match the selected evaluator profile",
        ));
    }

    let mut nodes = Vec::with_capacity(
        ballot_count
            .checked_mul(2)
            .and_then(|count| count.checked_sub(1))
            .ok_or_else(|| invalid_schedule("pair-character node count overflowed"))?,
    );
    let mut merges = Vec::with_capacity(ballot_count.saturating_sub(1));
    let mut forest = Vec::<usize>::new();
    let mut accounting = PairCharacterProductAccounting {
        ballot_ciphertext_count: ballot_count,
        ciphertext_multiplication_count: 0,
        relinearization_count: 0,
        normalization_plaintext_multiplication_count: 0,
        alignment_modulus_switch_count: 0,
        alignment_modulus_drop_count: 0,
        depth_modulus_switch_count: 0,
        depth_modulus_drop_count: 0,
        terminal_modulus_switch_count: 0,
        terminal_modulus_drop_count: 0,
        maximum_resident_ciphertext_count: 0,
    };

    for ballot_ordinal in 0..ballot_count {
        let node_ordinal = nodes.len();
        nodes.push(PairCharacterProductNode {
            node_ordinal,
            ballot_span: PairCharacterBallotSpan {
                first_ballot_ordinal: ballot_ordinal,
                ballot_count: 1,
            },
            multiplication_depth: 0,
            level: SELECTED_EVALUATOR_WORKING_LEVEL,
            message_width: FRESH_PAIR_CHARACTER_WIDTH,
        });
        forest.push(node_ordinal);
        accounting.maximum_resident_ciphertext_count = accounting
            .maximum_resident_ciphertext_count
            .max(forest.len());

        while forest.len() >= 2 {
            let right_node_ordinal = forest[forest.len() - 1];
            let left_node_ordinal = forest[forest.len() - 2];
            if nodes[left_node_ordinal].multiplication_depth
                != nodes[right_node_ordinal].multiplication_depth
            {
                break;
            }
            merge_rightmost_nodes(
                PairCharacterProductMergeKind::OnlineEqualDepth,
                &mut forest,
                &mut nodes,
                &mut merges,
                &mut accounting,
            )?;
        }
    }

    while forest.len() > 1 {
        merge_rightmost_nodes(
            PairCharacterProductMergeKind::RightmostFinalization,
            &mut forest,
            &mut nodes,
            &mut merges,
            &mut accounting,
        )?;
    }

    let root_node_ordinal = *forest
        .first()
        .ok_or_else(|| invalid_schedule("pair-character forest has no product root"))?;
    let root = nodes[root_node_ordinal];
    if root.ballot_span
        != (PairCharacterBallotSpan {
            first_ballot_ordinal: 0,
            ballot_count,
        })
        || root.message_width
            != PAIR_CHARACTER_SCORE_DIFFERENCE_BOUND
                .checked_mul(2)
                .and_then(|width_per_ballot| width_per_ballot.checked_mul(ballot_count))
                .and_then(|width| width.checked_add(1))
                .ok_or_else(|| invalid_schedule("pair-character root width overflowed"))?
        || root.level < CHARACTER_OUTPUT_LEVEL
    {
        return Err(invalid_schedule(
            "pair-character product root does not cover the selected ballot sequence",
        ));
    }

    let normalization_exponent = PAIR_CHARACTER_SCORE_DIFFERENCE_BOUND
        .checked_mul(maximum_ballot_count - ballot_count)
        .ok_or_else(|| invalid_schedule("pair-character normalization exponent overflowed"))?;
    if normalization_exponent >= POLYNOMIAL_DEGREE {
        return Err(invalid_schedule(
            "pair-character normalization exponent exceeds the plaintext ring",
        ));
    }
    let normalization = PairCharacterNormalization {
        coefficient_ordinal: normalization_exponent,
        centered_coefficient_l1_norm: 1,
        convolution_infinity_operator_norm: 1,
    };
    if normalization.requires_plaintext_multiplication() {
        accounting.normalization_plaintext_multiplication_count = 1;
        accounting.maximum_resident_ciphertext_count =
            accounting.maximum_resident_ciphertext_count.max(2);
    }

    let terminal_modulus_drop_count = root.level - CHARACTER_OUTPUT_LEVEL;
    if terminal_modulus_drop_count > 0 {
        accounting.terminal_modulus_switch_count = 1;
        accounting.terminal_modulus_drop_count = terminal_modulus_drop_count;
        accounting.maximum_resident_ciphertext_count =
            accounting.maximum_resident_ciphertext_count.max(2);
    }

    Ok(PairCharacterProductSchedule {
        ballot_count,
        nodes,
        merges,
        root_node_ordinal,
        normalization,
        terminal_output_level: CHARACTER_OUTPUT_LEVEL,
        accounting,
    })
}

/// One production pair-character product accumulated in accepted-ballot order.
///
/// Every resident ciphertext is owned by a zeroizing node. A failed absorb
/// poisons the forest, while dropping or explicitly poisoning an unfinished
/// forest clears every remaining ciphertext before releasing its allocation.
pub(crate) struct PairCharacterProductForest {
    nodes: Vec<PairCharacterProductNode>,
    merges: Vec<PairCharacterProductMerge>,
    forest: Vec<ResidentPairCharacterProductNode>,
    accounting: PairCharacterProductAccounting,
    poisoned: bool,
}

impl PairCharacterProductForest {
    pub(crate) fn new() -> Self {
        Self {
            nodes: Vec::with_capacity(19),
            merges: Vec::with_capacity(9),
            forest: Vec::with_capacity(4),
            accounting: PairCharacterProductAccounting {
                ballot_ciphertext_count: 0,
                ciphertext_multiplication_count: 0,
                relinearization_count: 0,
                normalization_plaintext_multiplication_count: 0,
                alignment_modulus_switch_count: 0,
                alignment_modulus_drop_count: 0,
                depth_modulus_switch_count: 0,
                depth_modulus_drop_count: 0,
                terminal_modulus_switch_count: 0,
                terminal_modulus_drop_count: 0,
                maximum_resident_ciphertext_count: 0,
            },
            poisoned: false,
        }
    }

    pub(crate) const fn accounting(&self) -> PairCharacterProductAccounting {
        self.accounting
    }

    /// Absorbs the next verified level-22 character ciphertext. The first leaf
    /// and every odd leaf need no key; an absorb that creates one or more
    /// equal-depth merges requires the selected borrowed relinearization key.
    pub(crate) fn absorb(
        &mut self,
        ciphertext: Ciphertext,
        relinearization_key_context: Option<&VerifiedEvaluatorKeyContext>,
    ) -> CanonicalResult<()> {
        let ciphertext = ZeroizingCiphertext::new(ciphertext);
        if self.poisoned {
            return Err(invalid_schedule(
                "pair-character product forest is poisoned",
            ));
        }
        let maximum_ballot_count = usize::from(FOUNDATION_PROFILE.participant_count);
        if self.accounting.ballot_ciphertext_count >= maximum_ballot_count {
            let error =
                invalid_schedule("pair-character product forest exceeds the selected ballot count");
            self.poison();
            return Err(error);
        }
        if let Err(error) =
            validate_ciphertext(ciphertext.as_ref(), SELECTED_EVALUATOR_WORKING_LEVEL, 2)
        {
            self.poison();
            return Err(error);
        }

        let ballot_ordinal = self.accounting.ballot_ciphertext_count;
        let node_ordinal = self.nodes.len();
        let node = PairCharacterProductNode {
            node_ordinal,
            ballot_span: PairCharacterBallotSpan {
                first_ballot_ordinal: ballot_ordinal,
                ballot_count: 1,
            },
            multiplication_depth: 0,
            level: SELECTED_EVALUATOR_WORKING_LEVEL,
            message_width: FRESH_PAIR_CHARACTER_WIDTH,
        };
        self.nodes.push(node);
        self.forest
            .push(ResidentPairCharacterProductNode { node, ciphertext });
        self.accounting.ballot_ciphertext_count += 1;
        self.accounting.maximum_resident_ciphertext_count = self
            .accounting
            .maximum_resident_ciphertext_count
            .max(self.forest.len());

        let absorb_result = (|| {
            while self.forest.len() >= 2 {
                let right = self.forest[self.forest.len() - 1].node;
                let left = self.forest[self.forest.len() - 2].node;
                if left.multiplication_depth != right.multiplication_depth {
                    break;
                }
                self.merge_rightmost_ciphertexts(
                    PairCharacterProductMergeKind::OnlineEqualDepth,
                    relinearization_key_context.ok_or_else(|| {
                        invalid_schedule(
                            "pair-character product merge requires the selected relinearization key",
                        )
                    })?,
                )?;
            }
            Ok(())
        })();
        if absorb_result.is_err() {
            self.poison();
        }
        absorb_result
    }

    /// Completes the rightmost-first forest reduction, applies the exact public
    /// count normalization, and switches the result to level 19. A key is only
    /// required when finalization still has ciphertext nodes to merge.
    pub(crate) fn finalize(
        mut self,
        relinearization_key_context: Option<&VerifiedEvaluatorKeyContext>,
    ) -> CanonicalResult<(Ciphertext, PairCharacterProductAccounting)> {
        if self.poisoned || self.accounting.ballot_ciphertext_count == 0 {
            return Err(invalid_schedule(
                "pair-character product forest cannot finalize its current state",
            ));
        }
        while self.forest.len() > 1 {
            self.merge_rightmost_ciphertexts(
                PairCharacterProductMergeKind::RightmostFinalization,
                relinearization_key_context.ok_or_else(|| {
                    invalid_schedule(
                        "pair-character product finalization requires the selected relinearization key",
                    )
                })?,
            )?;
        }

        let schedule =
            canonical_pair_character_product_schedule(self.accounting.ballot_ciphertext_count)?;
        let mut root = self
            .forest
            .pop()
            .ok_or_else(|| invalid_schedule("pair-character product root is absent"))?;
        if root.node != schedule.nodes[schedule.root_node_ordinal]
            || self.nodes != schedule.nodes
            || self.merges != schedule.merges
        {
            return Err(invalid_schedule(
                "executed pair-character product topology differs from its canonical schedule",
            ));
        }

        if schedule.normalization.requires_plaintext_multiplication() {
            self.accounting.maximum_resident_ciphertext_count =
                self.accounting.maximum_resident_ciphertext_count.max(2);
            let normalized = ZeroizingCiphertext::new(plaintext_mul(
                root.ciphertext.as_ref(),
                &schedule.normalization.plaintext_coefficients(),
            )?);
            validate_ciphertext(normalized.as_ref(), root.node.level, 2)?;
            root.ciphertext = normalized;
            self.accounting.normalization_plaintext_multiplication_count += 1;
        }

        if root.node.level > schedule.terminal_output_level {
            let terminal_drop_count = root.node.level - schedule.terminal_output_level;
            self.accounting.maximum_resident_ciphertext_count =
                self.accounting.maximum_resident_ciphertext_count.max(2);
            root.ciphertext =
                switch_owned_ciphertext_to_level(root.ciphertext, schedule.terminal_output_level)?;
            self.accounting.terminal_modulus_switch_count += 1;
            self.accounting.terminal_modulus_drop_count += terminal_drop_count;
        }
        validate_ciphertext(root.ciphertext.as_ref(), CHARACTER_OUTPUT_LEVEL, 2)?;
        if self.accounting != schedule.accounting {
            return Err(invalid_schedule(
                "executed pair-character operations differ from canonical accounting",
            ));
        }

        let accounting = self.accounting;
        Ok((root.ciphertext.into_inner(), accounting))
    }

    pub(crate) fn poison(&mut self) {
        self.poisoned = true;
        self.forest.clear();
        self.nodes.clear();
        self.merges.clear();
    }

    fn merge_rightmost_ciphertexts(
        &mut self,
        kind: PairCharacterProductMergeKind,
        relinearization_key_context: &VerifiedEvaluatorKeyContext,
    ) -> CanonicalResult<()> {
        if !matches!(
            relinearization_key_context.position().key_kind(),
            SelectedEvaluatorEntryKind::Relinearization { catalog_level }
                if catalog_level == SELECTED_RELINEARIZATION_KEY_LEVEL
        ) {
            return Err(invalid_schedule(
                "pair-character product received the wrong evaluator key",
            ));
        }
        let right = self
            .forest
            .pop()
            .ok_or_else(|| invalid_schedule("pair-character merge has no right ciphertext"))?;
        let left = self
            .forest
            .pop()
            .ok_or_else(|| invalid_schedule("pair-character merge has no left ciphertext"))?;
        let left_node = left.node;
        let right_node = right.node;
        if left_node.ballot_span.end_ballot_ordinal_exclusive()
            != right_node.ballot_span.first_ballot_ordinal
            || (kind == PairCharacterProductMergeKind::OnlineEqualDepth
                && left_node.multiplication_depth != right_node.multiplication_depth)
            || (kind == PairCharacterProductMergeKind::RightmostFinalization
                && left_node.multiplication_depth < right_node.multiplication_depth)
        {
            return Err(invalid_schedule(
                "pair-character ciphertext merge does not preserve its ordered forest",
            ));
        }
        let alignment_level = left_node.level.min(right_node.level);
        let left_alignment_drop_count = left_node.level - alignment_level;
        let right_alignment_drop_count = right_node.level - alignment_level;
        let multiplication_depth = left_node
            .multiplication_depth
            .max(right_node.multiplication_depth)
            .checked_add(1)
            .ok_or_else(|| invalid_schedule("pair-character multiplication depth overflowed"))?;
        let depth_drop_count = *SELECTED_EVALUATOR_MODULUS_SCHEDULE
            .character_depth_drop_counts
            .get(multiplication_depth - 1)
            .ok_or_else(|| {
                invalid_schedule("pair-character multiplication depth is unsupported")
            })?;
        let output_level = alignment_level
            .checked_sub(depth_drop_count)
            .ok_or_else(|| invalid_schedule("pair-character depth drop exceeds its input level"))?;
        let output_node_ordinal = self.nodes.len();
        let output_node = PairCharacterProductNode {
            node_ordinal: output_node_ordinal,
            ballot_span: PairCharacterBallotSpan {
                first_ballot_ordinal: left_node.ballot_span.first_ballot_ordinal,
                ballot_count: left_node
                    .ballot_span
                    .ballot_count
                    .checked_add(right_node.ballot_span.ballot_count)
                    .ok_or_else(|| invalid_schedule("pair-character ballot span overflowed"))?,
            },
            multiplication_depth,
            level: output_level,
            message_width: left_node
                .message_width
                .checked_add(right_node.message_width)
                .and_then(|width| width.checked_sub(1))
                .ok_or_else(|| invalid_schedule("pair-character message width overflowed"))?,
        };
        let merge = PairCharacterProductMerge {
            kind,
            left_node_ordinal: left_node.node_ordinal,
            right_node_ordinal: right_node.node_ordinal,
            output_node_ordinal,
            alignment_level,
            left_alignment_drop_count,
            right_alignment_drop_count,
            depth_drop_count,
        };

        let left = switch_owned_ciphertext_to_level(left.ciphertext, alignment_level)?;
        let right = switch_owned_ciphertext_to_level(right.ciphertext, alignment_level)?;
        let tensor = ZeroizingCiphertext::new(ciphertext_tensor(left.as_ref(), right.as_ref())?);
        drop(left);
        drop(right);
        let relinearized =
            ZeroizingCiphertext::new(relinearization_key_context.relinearize(tensor.as_ref())?);
        drop(tensor);
        let output = switch_owned_ciphertext_to_level(relinearized, output_level)?;
        validate_ciphertext(output.as_ref(), output_level, 2)?;

        self.nodes.push(output_node);
        self.merges.push(merge);
        self.forest.push(ResidentPairCharacterProductNode {
            node: output_node,
            ciphertext: output,
        });
        self.accounting.ciphertext_multiplication_count += 1;
        self.accounting.relinearization_count += 1;
        for alignment_drop_count in [left_alignment_drop_count, right_alignment_drop_count] {
            if alignment_drop_count > 0 {
                self.accounting.alignment_modulus_switch_count += 1;
                self.accounting.alignment_modulus_drop_count += alignment_drop_count;
            }
        }
        if depth_drop_count > 0 {
            self.accounting.depth_modulus_switch_count += 1;
            self.accounting.depth_modulus_drop_count += depth_drop_count;
        }
        self.accounting.maximum_resident_ciphertext_count = self
            .accounting
            .maximum_resident_ciphertext_count
            .max(self.forest.len() + 2);
        Ok(())
    }
}

impl Default for PairCharacterProductForest {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for PairCharacterProductForest {
    fn drop(&mut self) {
        self.poison();
    }
}

struct ResidentPairCharacterProductNode {
    node: PairCharacterProductNode,
    ciphertext: ZeroizingCiphertext,
}

struct ZeroizingCiphertext {
    ciphertext: Option<Ciphertext>,
}

impl ZeroizingCiphertext {
    fn new(ciphertext: Ciphertext) -> Self {
        Self {
            ciphertext: Some(ciphertext),
        }
    }

    fn as_ref(&self) -> &Ciphertext {
        self.ciphertext
            .as_ref()
            .expect("zeroizing ciphertext ownership is present")
    }

    fn into_inner(mut self) -> Ciphertext {
        self.ciphertext
            .take()
            .expect("zeroizing ciphertext ownership is present")
    }
}

impl Drop for ZeroizingCiphertext {
    fn drop(&mut self) {
        if let Some(mut ciphertext) = self.ciphertext.take() {
            zeroize_ciphertext(&mut ciphertext);
        }
    }
}

fn switch_owned_ciphertext_to_level(
    mut ciphertext: ZeroizingCiphertext,
    target_level: usize,
) -> CanonicalResult<ZeroizingCiphertext> {
    if target_level > ciphertext.as_ref().level {
        return Err(invalid_schedule(
            "pair-character modulus switch cannot raise a ciphertext level",
        ));
    }
    while ciphertext.as_ref().level > target_level {
        ciphertext = ZeroizingCiphertext::new(modulus_switch(ciphertext.as_ref())?);
    }
    Ok(ciphertext)
}

fn validate_ciphertext(
    ciphertext: &Ciphertext,
    expected_level: usize,
    expected_component_count: usize,
) -> CanonicalResult<()> {
    if ciphertext.level != expected_level
        || ciphertext.decrypt_scaling != 1
        || ciphertext.components.len() != expected_component_count
        || ciphertext.components.iter().any(|component| {
            component.len() != expected_level + 1
                || component.iter().any(|limb| limb.len() != POLYNOMIAL_DEGREE)
        })
    {
        return Err(invalid_schedule(
            "pair-character ciphertext has incompatible selected geometry",
        ));
    }
    Ok(())
}

fn zeroize_ciphertext(ciphertext: &mut Ciphertext) {
    ciphertext.components.zeroize();
    ciphertext.level.zeroize();
    ciphertext.decrypt_scaling.zeroize();
}

fn merge_rightmost_nodes(
    kind: PairCharacterProductMergeKind,
    forest: &mut Vec<usize>,
    nodes: &mut Vec<PairCharacterProductNode>,
    merges: &mut Vec<PairCharacterProductMerge>,
    accounting: &mut PairCharacterProductAccounting,
) -> CanonicalResult<()> {
    let right_node_ordinal = forest
        .pop()
        .ok_or_else(|| invalid_schedule("pair-character merge has no right input"))?;
    let left_node_ordinal = forest
        .pop()
        .ok_or_else(|| invalid_schedule("pair-character merge has no left input"))?;
    let left = nodes[left_node_ordinal];
    let right = nodes[right_node_ordinal];
    if left.ballot_span.end_ballot_ordinal_exclusive() != right.ballot_span.first_ballot_ordinal
        || (kind == PairCharacterProductMergeKind::OnlineEqualDepth
            && left.multiplication_depth != right.multiplication_depth)
        || (kind == PairCharacterProductMergeKind::RightmostFinalization
            && left.multiplication_depth < right.multiplication_depth)
    {
        return Err(invalid_schedule(
            "pair-character merge does not preserve contiguous ordered spans",
        ));
    }

    let alignment_level = left.level.min(right.level);
    let left_alignment_drop_count = left.level - alignment_level;
    let right_alignment_drop_count = right.level - alignment_level;
    let multiplication_depth = left
        .multiplication_depth
        .max(right.multiplication_depth)
        .checked_add(1)
        .ok_or_else(|| invalid_schedule("pair-character multiplication depth overflowed"))?;
    let depth_drop_count = *SELECTED_EVALUATOR_MODULUS_SCHEDULE
        .character_depth_drop_counts
        .get(multiplication_depth - 1)
        .ok_or_else(|| invalid_schedule("pair-character multiplication depth is unsupported"))?;
    let level = alignment_level
        .checked_sub(depth_drop_count)
        .ok_or_else(|| invalid_schedule("pair-character depth drop exceeds its input level"))?;
    let ballot_span = PairCharacterBallotSpan {
        first_ballot_ordinal: left.ballot_span.first_ballot_ordinal,
        ballot_count: left
            .ballot_span
            .ballot_count
            .checked_add(right.ballot_span.ballot_count)
            .ok_or_else(|| invalid_schedule("pair-character ballot span overflowed"))?,
    };
    let message_width = left
        .message_width
        .checked_add(right.message_width)
        .and_then(|width| width.checked_sub(1))
        .ok_or_else(|| invalid_schedule("pair-character message width overflowed"))?;
    let output_node_ordinal = nodes.len();
    nodes.push(PairCharacterProductNode {
        node_ordinal: output_node_ordinal,
        ballot_span,
        multiplication_depth,
        level,
        message_width,
    });
    merges.push(PairCharacterProductMerge {
        kind,
        left_node_ordinal,
        right_node_ordinal,
        output_node_ordinal,
        alignment_level,
        left_alignment_drop_count,
        right_alignment_drop_count,
        depth_drop_count,
    });
    forest.push(output_node_ordinal);

    accounting.ciphertext_multiplication_count += 1;
    accounting.relinearization_count += 1;
    for alignment_drop_count in [left_alignment_drop_count, right_alignment_drop_count] {
        if alignment_drop_count > 0 {
            accounting.alignment_modulus_switch_count += 1;
            accounting.alignment_modulus_drop_count += alignment_drop_count;
        }
    }
    if depth_drop_count > 0 {
        accounting.depth_modulus_switch_count += 1;
        accounting.depth_modulus_drop_count += depth_drop_count;
    }
    // The two popped inputs, the untouched forest, and the allocated output are
    // simultaneously live until the inputs can be zeroized and released.
    accounting.maximum_resident_ciphertext_count = accounting
        .maximum_resident_ciphertext_count
        .max(forest.len() + 2);
    Ok(())
}

fn invalid_schedule(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidProtocolObject, message)
}

#[cfg(test)]
mod tests;
