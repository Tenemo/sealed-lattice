//! Streaming column commitment and ordinary Merkle authentication.

use core::mem::size_of;
use std::collections::{BTreeMap, BTreeSet};

use p3_field::PrimeField64;
use p3_goldilocks::Goldilocks;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use tiny_keccak::keccakf;
use zeroize::Zeroizing;

use crate::bgv::proof_suite::ProofBaseFieldElement;

use super::private_leaf_salt::{
    PRIVATE_LEAF_SALT_BYTE_LENGTH, PrivateLeafSalt, derive_private_leaf_salt,
};

// The project security ledger models Fiat-Shamir with 512-bit random-oracle
// outputs. Keep the outer matrix commitment at the same width: truncating it
// to 320 bits would cap generic collision work at 160 bits before the
// multi-proof compiler loss is considered.
pub(super) const COLUMN_DIGEST_WORD_LENGTH: usize = 8;
pub(super) const COLUMN_DIGEST_BYTE_LENGTH: usize = COLUMN_DIGEST_WORD_LENGTH * size_of::<u64>();
const SHAKE256_STATE_WORD_LENGTH: usize = 25;
const SHAKE256_RATE_WORD_LENGTH: usize = 17;
const SHAKE256_DELIMITER: u64 = 0x1f;
const SHAKE256_FINAL_RATE_BYTE: u64 = 0x80_u64 << 56;

pub(super) type ColumnDigest = [u64; COLUMN_DIGEST_WORD_LENGTH];

pub(super) struct PrivateColumnLeafSaltContext {
    private_seed: Zeroizing<[u8; 64]>,
    commitment_role: &'static [u8],
}

impl PrivateColumnLeafSaltContext {
    pub(super) fn new(private_seed: &[u8; 64], commitment_role: &'static [u8]) -> Self {
        Self {
            private_seed: Zeroizing::new(*private_seed),
            commitment_role,
        }
    }

    pub(super) fn salt(
        &self,
        leaf_count: usize,
        logical_leaf_width: usize,
        leaf_index: usize,
    ) -> Result<PrivateLeafSalt, String> {
        derive_private_leaf_salt(
            self.private_seed.as_slice(),
            self.commitment_role,
            leaf_count,
            logical_leaf_width,
            0,
            leaf_index,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct StreamingColumnCommitment {
    pub(super) root: ColumnDigest,
    pub(super) frontier: Vec<ColumnDigest>,
}

/// One SHAKE256 state per encoded column, updated in row-major order.
///
/// All states have the same byte offset. Keeping that offset once, rather
/// than inside every hasher object, makes the exact resident state 200 bytes
/// per column.
pub(super) struct StreamingColumnHasher {
    states: Vec<[u64; SHAKE256_STATE_WORD_LENGTH]>,
    next_rate_word: usize,
    expected_row_count: usize,
    absorbed_row_count: usize,
}

impl Drop for StreamingColumnHasher {
    fn drop(&mut self) {
        for state in &mut self.states {
            state.fill(0);
        }
        self.next_rate_word = 0;
        self.absorbed_row_count = 0;
    }
}

impl StreamingColumnHasher {
    #[cfg(test)]
    pub(super) fn new(
        expected_row_count: usize,
        encoded_column_count: usize,
    ) -> Result<Self, String> {
        Self::new_stripe(
            expected_row_count,
            encoded_column_count,
            encoded_column_count,
            0,
            None,
        )
    }

    #[cfg(test)]
    pub(super) fn new_with_private_salt(
        expected_row_count: usize,
        encoded_column_count: usize,
        private_leaf_salt: &PrivateColumnLeafSaltContext,
    ) -> Result<Self, String> {
        Self::new_stripe(
            expected_row_count,
            encoded_column_count,
            encoded_column_count,
            0,
            Some(private_leaf_salt),
        )
    }

    #[cfg(test)]
    fn new_stripe(
        expected_row_count: usize,
        encoded_column_count: usize,
        stripe_column_count: usize,
        stripe_start_column_index: usize,
        private_leaf_salt: Option<&PrivateColumnLeafSaltContext>,
    ) -> Result<Self, String> {
        if expected_row_count == 0 {
            return Err("column commitment requires at least one row".to_owned());
        }
        if !encoded_column_count.is_power_of_two() {
            return Err(format!(
                "encoded column count {encoded_column_count} is not a non-zero power of two"
            ));
        }
        if stripe_column_count == 0 || stripe_column_count > encoded_column_count {
            return Err(format!(
                "column commitment stripe has {stripe_column_count} columns for an encoded width of {encoded_column_count}"
            ));
        }
        let stripe_end_column_index = stripe_start_column_index
            .checked_add(stripe_column_count)
            .ok_or_else(|| "column commitment stripe coordinate overflowed".to_owned())?;
        if stripe_end_column_index > encoded_column_count {
            return Err("column commitment stripe is outside the encoded width".to_owned());
        }

        Self::new_for_column_indices(
            expected_row_count,
            encoded_column_count,
            stripe_start_column_index..stripe_end_column_index,
            private_leaf_salt,
        )
    }

    fn new_interleaved_lane(
        expected_row_count: usize,
        encoded_column_count: usize,
        lane_count: usize,
        lane_ordinal: usize,
        private_leaf_salt: Option<&PrivateColumnLeafSaltContext>,
    ) -> Result<Self, String> {
        if lane_count == 0
            || !lane_count.is_power_of_two()
            || !encoded_column_count.is_multiple_of(lane_count)
            || lane_ordinal >= lane_count
        {
            return Err("column commitment interleaved lane geometry is invalid".to_owned());
        }
        let lane_column_count = encoded_column_count / lane_count;
        Self::new_for_column_indices(
            expected_row_count,
            encoded_column_count,
            (0..lane_column_count)
                .map(|within_lane_index| within_lane_index * lane_count + lane_ordinal),
            private_leaf_salt,
        )
    }

    fn new_for_column_indices(
        expected_row_count: usize,
        encoded_column_count: usize,
        column_indices: impl ExactSizeIterator<Item = usize>,
        private_leaf_salt: Option<&PrivateColumnLeafSaltContext>,
    ) -> Result<Self, String> {
        if expected_row_count == 0
            || !encoded_column_count.is_power_of_two()
            || column_indices.len() == 0
            || column_indices.len() > encoded_column_count
        {
            return Err("column commitment coordinate geometry is invalid".to_owned());
        }

        let mut states = Vec::new();
        states
            .try_reserve_exact(column_indices.len())
            .map_err(|_| "column commitment stripe state allocation failed".to_owned())?;
        let mut previous_column_index = None;
        for column_index in column_indices {
            if column_index >= encoded_column_count
                || previous_column_index.is_some_and(|previous| previous >= column_index)
            {
                return Err("column commitment coordinates are not canonical".to_owned());
            }
            previous_column_index = Some(column_index);
            let salt = private_leaf_salt
                .map(|context| context.salt(encoded_column_count, expected_row_count, column_index))
                .transpose()?;
            let (state, next_rate_word) = initialized_column_hash_state(
                expected_row_count,
                encoded_column_count,
                salt.as_ref(),
            );
            if states.is_empty() {
                states.push(state);
                debug_assert_eq!(next_rate_word, column_hash_next_rate_word(salt.is_some()));
            } else {
                states.push(state);
            }
        }
        let next_rate_word = column_hash_next_rate_word(private_leaf_salt.is_some());
        Ok(Self {
            states,
            next_rate_word,
            expected_row_count,
            absorbed_row_count: 0,
        })
    }

    #[cfg(test)]
    pub(super) fn absorb_row(&mut self, encoded_row: &[Goldilocks]) -> Result<(), String> {
        self.absorb_canonical_row(
            encoded_row.len(),
            encoded_row.iter().map(|value| value.as_canonical_u64()),
        )
    }

    pub(super) fn absorb_base_row(
        &mut self,
        encoded_row: &[ProofBaseFieldElement],
    ) -> Result<(), String> {
        self.absorb_canonical_row(
            encoded_row.len(),
            encoded_row.iter().map(|value| value.canonical()),
        )
    }

    fn absorb_canonical_row(
        &mut self,
        encoded_column_count: usize,
        canonical_values: impl ExactSizeIterator<Item = u64>,
    ) -> Result<(), String> {
        if self.absorbed_row_count == self.expected_row_count {
            return Err(format!(
                "column commitment received more than {} rows",
                self.expected_row_count
            ));
        }
        if encoded_column_count != self.states.len()
            || canonical_values.len() != encoded_column_count
        {
            return Err(format!(
                "encoded row has {} columns, expected {}",
                encoded_column_count,
                self.states.len()
            ));
        }

        let rate_word = self.next_rate_word;
        for (state, value) in self.states.iter_mut().zip(canonical_values) {
            state[rate_word] ^= value;
        }
        self.next_rate_word += 1;
        if self.next_rate_word == SHAKE256_RATE_WORD_LENGTH {
            for state in &mut self.states {
                keccakf(state);
            }
            self.next_rate_word = 0;
        }
        self.absorbed_row_count += 1;
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn finalize(self) -> Result<Vec<ColumnDigest>, String> {
        let mut digests = Vec::with_capacity(self.states.len());
        self.finalize_digests(|digest| {
            digests.push(digest);
            Ok(())
        })?;
        Ok(digests)
    }

    #[cfg(test)]
    pub(super) fn finalize_root(self) -> Result<ColumnDigest, String> {
        self.finalize_commitment(&[])
            .map(|commitment| commitment.root)
    }

    #[cfg(test)]
    pub(super) fn finalize_commitment(
        mut self,
        opened_column_indices: &[usize],
    ) -> Result<StreamingColumnCommitment, String> {
        if self.absorbed_row_count != self.expected_row_count {
            return Err(format!(
                "column commitment received {} rows, expected {}",
                self.absorbed_row_count, self.expected_row_count
            ));
        }
        let delimiter_word = self.next_rate_word;
        let mut builder = StreamingMerkleBuilder::new(self.states.len(), opened_column_indices)?;
        for (column_index, mut state) in self.states.drain(..).enumerate() {
            state[delimiter_word] ^= SHAKE256_DELIMITER;
            state[SHAKE256_RATE_WORD_LENGTH - 1] ^= SHAKE256_FINAL_RATE_BYTE;
            keccakf(&mut state);
            let digest = core::array::from_fn(|word_index| state[word_index]);
            state.fill(0);
            builder.push_leaf(column_index, digest)?;
        }
        builder.finish()
    }

    pub(super) const fn exact_state_byte_length(encoded_column_count: usize) -> Option<usize> {
        encoded_column_count.checked_mul(size_of::<[u64; SHAKE256_STATE_WORD_LENGTH]>())
    }

    fn finalize_digests(
        mut self,
        mut consume_digest: impl FnMut(ColumnDigest) -> Result<(), String>,
    ) -> Result<(), String> {
        if self.absorbed_row_count != self.expected_row_count {
            return Err(format!(
                "column commitment received {} rows, expected {}",
                self.absorbed_row_count, self.expected_row_count
            ));
        }
        let delimiter_word = self.next_rate_word;
        for mut state in self.states.drain(..) {
            state[delimiter_word] ^= SHAKE256_DELIMITER;
            state[SHAKE256_RATE_WORD_LENGTH - 1] ^= SHAKE256_FINAL_RATE_BYTE;
            keccakf(&mut state);
            let digest = core::array::from_fn(|word_index| state[word_index]);
            state.fill(0);
            consume_digest(digest)?;
        }
        Ok(())
    }
}

/// Builds the canonical column commitment with a bounded number of live
/// SHAKE256 states. The caller replays the encoded rows once per stripe; the
/// stripe width is an implementation choice and does not enter the root.
#[cfg(test)]
pub(super) struct StripedColumnCommitmentBuilder {
    expected_row_count: usize,
    encoded_column_count: usize,
    maximum_stripe_column_count: usize,
    next_column_index: usize,
    private_leaf_salt: Option<PrivateColumnLeafSaltContext>,
    active_stripe_hasher: Option<StreamingColumnHasher>,
    merkle_builder: StreamingMerkleBuilder,
}

#[cfg(test)]
impl StripedColumnCommitmentBuilder {
    #[cfg(test)]
    pub(super) fn new(
        expected_row_count: usize,
        encoded_column_count: usize,
        maximum_stripe_column_count: usize,
    ) -> Result<Self, String> {
        Self::new_with_opened_columns(
            expected_row_count,
            encoded_column_count,
            maximum_stripe_column_count,
            &[],
        )
    }

    #[cfg(test)]
    pub(super) fn new_with_opened_columns(
        expected_row_count: usize,
        encoded_column_count: usize,
        maximum_stripe_column_count: usize,
        opened_column_indices: &[usize],
    ) -> Result<Self, String> {
        Self::new_with_opened_columns_and_private_salt(
            expected_row_count,
            encoded_column_count,
            maximum_stripe_column_count,
            opened_column_indices,
            None,
        )
    }

    pub(super) fn new_with_opened_columns_and_private_salt(
        expected_row_count: usize,
        encoded_column_count: usize,
        maximum_stripe_column_count: usize,
        opened_column_indices: &[usize],
        private_leaf_salt: Option<PrivateColumnLeafSaltContext>,
    ) -> Result<Self, String> {
        if maximum_stripe_column_count == 0 {
            return Err("column commitment stripe width must be positive".to_owned());
        }
        let merkle_builder =
            StreamingMerkleBuilder::new(encoded_column_count, opened_column_indices)?;
        let first_stripe_column_count = maximum_stripe_column_count.min(encoded_column_count);
        let active_stripe_hasher = StreamingColumnHasher::new_stripe(
            expected_row_count,
            encoded_column_count,
            first_stripe_column_count,
            0,
            private_leaf_salt.as_ref(),
        )?;
        Ok(Self {
            expected_row_count,
            encoded_column_count,
            maximum_stripe_column_count,
            next_column_index: 0,
            private_leaf_salt,
            active_stripe_hasher: Some(active_stripe_hasher),
            merkle_builder,
        })
    }

    pub(super) fn active_column_range(&self) -> Option<core::ops::Range<usize>> {
        self.active_stripe_hasher
            .as_ref()
            .map(|hasher| self.next_column_index..self.next_column_index + hasher.states.len())
    }

    #[cfg(test)]
    pub(super) fn absorb_active_stripe_row(
        &mut self,
        row_index: usize,
        encoded_row_stripe: &[Goldilocks],
    ) -> Result<(), String> {
        let hasher = self
            .active_stripe_hasher
            .as_mut()
            .ok_or_else(|| "column commitment has no active stripe".to_owned())?;
        if row_index != hasher.absorbed_row_count {
            return Err(format!(
                "column commitment received row {row_index}, expected {}",
                hasher.absorbed_row_count
            ));
        }
        hasher.absorb_row(encoded_row_stripe)
    }

    pub(super) fn absorb_active_stripe_base_row(
        &mut self,
        row_index: usize,
        encoded_row_stripe: &[ProofBaseFieldElement],
    ) -> Result<(), String> {
        let hasher = self
            .active_stripe_hasher
            .as_mut()
            .ok_or_else(|| "column commitment has no active stripe".to_owned())?;
        if row_index != hasher.absorbed_row_count {
            return Err(format!(
                "column commitment received row {row_index}, expected {}",
                hasher.absorbed_row_count
            ));
        }
        hasher.absorb_base_row(encoded_row_stripe)
    }

    /// Completes the current stripe after every row was replayed. Returns
    /// `true` only after the final encoded column entered the Merkle root.
    pub(super) fn complete_active_stripe(&mut self) -> Result<bool, String> {
        let hasher = self
            .active_stripe_hasher
            .take()
            .ok_or_else(|| "column commitment has no active stripe".to_owned())?;
        let stripe_column_count = hasher.states.len();
        let expected_column_start = self.next_column_index;
        let merkle_builder = &mut self.merkle_builder;
        let mut column_index = expected_column_start;
        hasher.finalize_digests(|digest| {
            merkle_builder.push_leaf(column_index, digest)?;
            column_index = column_index
                .checked_add(1)
                .ok_or_else(|| "column commitment column index overflowed".to_owned())?;
            Ok(())
        })?;
        let expected_column_end = expected_column_start
            .checked_add(stripe_column_count)
            .ok_or_else(|| "column commitment stripe end overflowed".to_owned())?;
        if column_index != expected_column_end || expected_column_end > self.encoded_column_count {
            return Err("column commitment stripe produced the wrong leaf count".to_owned());
        }
        self.next_column_index = expected_column_end;
        if self.next_column_index == self.encoded_column_count {
            return Ok(true);
        }
        let remaining_column_count = self.encoded_column_count - self.next_column_index;
        self.active_stripe_hasher = Some(StreamingColumnHasher::new_stripe(
            self.expected_row_count,
            self.encoded_column_count,
            self.maximum_stripe_column_count.min(remaining_column_count),
            self.next_column_index,
            self.private_leaf_salt.as_ref(),
        )?);
        Ok(false)
    }

    #[cfg(test)]
    pub(super) fn finish(self) -> Result<ColumnDigest, String> {
        self.finish_commitment().map(|commitment| commitment.root)
    }

    pub(super) fn finish_commitment(self) -> Result<StreamingColumnCommitment, String> {
        if self.active_stripe_hasher.is_some()
            || self.next_column_index != self.encoded_column_count
        {
            return Err("column commitment is incomplete".to_owned());
        }
        self.merkle_builder.finish()
    }

    pub(super) fn maximum_hash_state_byte_length(&self) -> Result<usize, String> {
        StreamingColumnHasher::exact_state_byte_length(
            self.maximum_stripe_column_count
                .min(self.encoded_column_count),
        )
        .ok_or_else(|| "column commitment stripe state byte length overflowed".to_owned())
    }
}

/// Builds the canonical ascending column commitment from interleaved DFT
/// lanes.
///
/// A lane contains columns `r, r + lane_count, ...`. Once each lane digest is
/// available, one digest plane per occupied low tree level carries the
/// interleaved leaves back into their original consecutive blocks. The upper
/// tree receives those completed blocks in ascending order, so the root and
/// compact frontier are byte-identical to direct natural-order construction.
pub(super) struct InterleavedColumnCommitmentBuilder {
    expected_row_count: usize,
    encoded_column_count: usize,
    lane_column_count: usize,
    lane_count: usize,
    next_lane_ordinal: usize,
    private_leaf_salt: Option<PrivateColumnLeafSaltContext>,
    active_lane_hasher: Option<StreamingColumnHasher>,
    opened_column_indices: Vec<usize>,
    lower_subtree_digest_planes: Vec<Option<Vec<ColumnDigest>>>,
    lower_frontier_by_level_and_index: Vec<(usize, usize, ColumnDigest)>,
    expected_frontier_node_count: usize,
    upper_merkle_builder: StreamingMerkleBuilder,
}

impl InterleavedColumnCommitmentBuilder {
    pub(super) fn new_with_opened_columns_and_private_salt(
        expected_row_count: usize,
        encoded_column_count: usize,
        maximum_lane_column_count: usize,
        opened_column_indices: &[usize],
        private_leaf_salt: Option<PrivateColumnLeafSaltContext>,
    ) -> Result<Self, String> {
        if expected_row_count == 0
            || !encoded_column_count.is_power_of_two()
            || maximum_lane_column_count == 0
            || !maximum_lane_column_count.is_power_of_two()
        {
            return Err("interleaved column commitment geometry is invalid".to_owned());
        }
        let expected_frontier_node_count = canonical_frontier_node_count_from_sorted_indices(
            opened_column_indices,
            encoded_column_count,
        )?;
        let lane_column_count = maximum_lane_column_count.min(encoded_column_count);
        let lane_count = encoded_column_count / lane_column_count;
        if !lane_count.is_power_of_two() {
            return Err("interleaved column commitment lane count is invalid".to_owned());
        }
        let mut opened_columns = Vec::new();
        opened_columns
            .try_reserve_exact(opened_column_indices.len())
            .map_err(|_| "interleaved opening-index allocation failed".to_owned())?;
        opened_columns.extend_from_slice(opened_column_indices);
        let mut opened_block_indices = Vec::new();
        opened_block_indices
            .try_reserve_exact(opened_column_indices.len())
            .map_err(|_| "interleaved opened-block allocation failed".to_owned())?;
        for column_index in opened_column_indices {
            let block_index = *column_index / lane_count;
            if opened_block_indices.last().copied() != Some(block_index) {
                opened_block_indices.push(block_index);
            }
        }
        let upper_merkle_builder =
            StreamingMerkleBuilder::new(lane_column_count, &opened_block_indices)?;
        let active_lane_hasher = StreamingColumnHasher::new_interleaved_lane(
            expected_row_count,
            encoded_column_count,
            lane_count,
            0,
            private_leaf_salt.as_ref(),
        )?;
        let lower_tree_depth = lane_count.ilog2() as usize;
        let mut lower_subtree_digest_planes = Vec::new();
        lower_subtree_digest_planes
            .try_reserve_exact(lower_tree_depth)
            .map_err(|_| "interleaved digest-plane catalog allocation failed".to_owned())?;
        lower_subtree_digest_planes.resize_with(lower_tree_depth, || None);
        let mut lower_frontier_by_level_and_index = Vec::new();
        lower_frontier_by_level_and_index
            .try_reserve_exact(expected_frontier_node_count)
            .map_err(|_| "interleaved frontier allocation failed".to_owned())?;

        Ok(Self {
            expected_row_count,
            encoded_column_count,
            lane_column_count,
            lane_count,
            next_lane_ordinal: 0,
            private_leaf_salt,
            active_lane_hasher: Some(active_lane_hasher),
            opened_column_indices: opened_columns,
            lower_subtree_digest_planes,
            lower_frontier_by_level_and_index,
            expected_frontier_node_count,
            upper_merkle_builder,
        })
    }

    pub(super) const fn lane_count(&self) -> usize {
        self.lane_count
    }

    pub(super) const fn lane_column_count(&self) -> usize {
        self.lane_column_count
    }

    pub(super) const fn active_lane_ordinal(&self) -> Option<usize> {
        if self.active_lane_hasher.is_some() {
            Some(self.next_lane_ordinal)
        } else {
            None
        }
    }

    #[cfg(test)]
    pub(super) fn absorb_active_lane_row(
        &mut self,
        row_index: usize,
        encoded_row_lane: &[Goldilocks],
    ) -> Result<(), String> {
        let hasher = self
            .active_lane_hasher
            .as_mut()
            .ok_or_else(|| "interleaved column commitment has no active lane".to_owned())?;
        if row_index != hasher.absorbed_row_count {
            return Err(format!(
                "interleaved column commitment received row {row_index}, expected {}",
                hasher.absorbed_row_count
            ));
        }
        hasher.absorb_row(encoded_row_lane)
    }

    pub(super) fn absorb_active_lane_base_row(
        &mut self,
        row_index: usize,
        encoded_row_lane: &[ProofBaseFieldElement],
    ) -> Result<(), String> {
        let hasher = self
            .active_lane_hasher
            .as_mut()
            .ok_or_else(|| "interleaved column commitment has no active lane".to_owned())?;
        if row_index != hasher.absorbed_row_count {
            return Err(format!(
                "interleaved column commitment received row {row_index}, expected {}",
                hasher.absorbed_row_count
            ));
        }
        hasher.absorb_base_row(encoded_row_lane)
    }

    /// Completes one interleaved lane. Returns `true` only after every natural
    /// column entered the original binary Merkle tree.
    pub(super) fn complete_active_lane(&mut self) -> Result<bool, String> {
        let hasher = self
            .active_lane_hasher
            .take()
            .ok_or_else(|| "interleaved column commitment has no active lane".to_owned())?;
        let lane_ordinal = self.next_lane_ordinal;
        if lane_ordinal >= self.lane_count {
            return Err("interleaved column commitment lane ordinal overflowed".to_owned());
        }
        let lower_tree_depth = self.lower_subtree_digest_planes.len();
        let completed_lower_level_count = lane_ordinal.trailing_ones() as usize;
        if completed_lower_level_count > lower_tree_depth {
            return Err("interleaved column commitment carry depth is invalid".to_owned());
        }
        for level in 0..completed_lower_level_count {
            let plane = self
                .lower_subtree_digest_planes
                .get(level)
                .and_then(Option::as_ref)
                .ok_or_else(|| "interleaved column commitment carry plane is absent".to_owned())?;
            if plane.len() != self.lane_column_count {
                return Err(
                    "interleaved column commitment carry plane has the wrong size".to_owned(),
                );
            }
        }
        let output_level =
            (completed_lower_level_count < lower_tree_depth).then_some(completed_lower_level_count);
        if output_level.is_some_and(|level| {
            self.lower_subtree_digest_planes
                .get(level)
                .is_some_and(Option::is_some)
        }) {
            return Err("interleaved column commitment output plane is occupied".to_owned());
        }
        let mut output_plane = output_level
            .map(|_| allocate_digest_plane(self.lane_column_count))
            .transpose()?;
        let lane_count = self.lane_count;
        let lane_column_count = self.lane_column_count;
        let opened_column_indices = &self.opened_column_indices;
        let lower_subtree_digest_planes = &self.lower_subtree_digest_planes;
        let lower_frontier = &mut self.lower_frontier_by_level_and_index;
        let upper_merkle_builder = &mut self.upper_merkle_builder;
        let mut block_index = 0_usize;
        hasher.finalize_digests(|digest| {
            if block_index >= lane_column_count {
                return Err(
                    "interleaved column commitment emitted too many lane digests".to_owned(),
                );
            }
            let mut carried_digest = digest;
            for (level, digest_plane) in lower_subtree_digest_planes
                .iter()
                .take(completed_lower_level_count)
                .enumerate()
            {
                let left_digest = digest_plane
                    .as_ref()
                    .and_then(|plane| plane.get(block_index))
                    .copied()
                    .ok_or_else(|| {
                        "interleaved column commitment left digest is absent".to_owned()
                    })?;
                capture_interleaved_frontier_sibling(
                    opened_column_indices,
                    lane_count,
                    block_index,
                    lane_ordinal,
                    level,
                    left_digest,
                    carried_digest,
                    lower_frontier,
                )?;
                carried_digest = hash_merkle_parent(&left_digest, &carried_digest);
            }
            if let Some(plane) = output_plane.as_mut() {
                *plane.get_mut(block_index).ok_or_else(|| {
                    "interleaved column commitment output coordinate is absent".to_owned()
                })? = carried_digest;
            } else {
                upper_merkle_builder.push_leaf(block_index, carried_digest)?;
            }
            block_index += 1;
            Ok(())
        })?;
        if block_index != lane_column_count {
            return Err("interleaved column commitment emitted the wrong lane width".to_owned());
        }
        for level in 0..completed_lower_level_count {
            if let Some(mut completed_plane) = self.lower_subtree_digest_planes[level].take() {
                completed_plane.fill([0_u64; COLUMN_DIGEST_WORD_LENGTH]);
            }
        }
        if let Some(level) = output_level {
            self.lower_subtree_digest_planes[level] = output_plane;
        }

        self.next_lane_ordinal = self
            .next_lane_ordinal
            .checked_add(1)
            .ok_or_else(|| "interleaved column commitment lane ordinal overflowed".to_owned())?;
        if self.next_lane_ordinal == self.lane_count {
            if self.lower_subtree_digest_planes.iter().any(Option::is_some) {
                return Err(
                    "interleaved column commitment retained a completed carry plane".to_owned(),
                );
            }
            return Ok(true);
        }
        self.active_lane_hasher = Some(StreamingColumnHasher::new_interleaved_lane(
            self.expected_row_count,
            self.encoded_column_count,
            self.lane_count,
            self.next_lane_ordinal,
            self.private_leaf_salt.as_ref(),
        )?);
        Ok(false)
    }

    pub(super) fn finish_commitment(self) -> Result<StreamingColumnCommitment, String> {
        if self.active_lane_hasher.is_some()
            || self.next_lane_ordinal != self.lane_count
            || self.lower_subtree_digest_planes.iter().any(Option::is_some)
        {
            return Err("interleaved column commitment is incomplete".to_owned());
        }
        let lower_tree_depth = self.lane_count.ilog2() as usize;
        let upper = self.upper_merkle_builder.finish_with_coordinates()?;
        let mut frontier_by_level_and_index = self.lower_frontier_by_level_and_index;
        frontier_by_level_and_index
            .try_reserve_exact(upper.frontier_by_level_and_index.len())
            .map_err(|_| "interleaved result frontier allocation failed".to_owned())?;
        frontier_by_level_and_index.extend(
            upper
                .frontier_by_level_and_index
                .into_iter()
                .map(|(level, index, digest)| (level + lower_tree_depth, index, digest)),
        );
        frontier_by_level_and_index.sort_unstable_by_key(|(level, index, _)| (*level, *index));
        if frontier_by_level_and_index.len() != self.expected_frontier_node_count {
            return Err("interleaved column commitment frontier has the wrong size".to_owned());
        }
        Ok(StreamingColumnCommitment {
            root: upper.root,
            frontier: frontier_by_level_and_index
                .into_iter()
                .map(|(_, _, digest)| digest)
                .collect(),
        })
    }

    pub(super) fn maximum_hash_state_byte_length(&self) -> Result<usize, String> {
        StreamingColumnHasher::exact_state_byte_length(self.lane_column_count)
            .ok_or_else(|| "interleaved hash-state byte length overflowed".to_owned())
    }

    pub(super) fn maximum_digest_plane_byte_length(&self) -> Result<usize, String> {
        self.lane_column_count
            .checked_mul(self.lane_count.ilog2() as usize)
            .and_then(|digest_count| digest_count.checked_mul(COLUMN_DIGEST_BYTE_LENGTH))
            .ok_or_else(|| "interleaved digest-plane byte length overflowed".to_owned())
    }

    pub(super) fn metadata_allocation_byte_length(&self) -> Result<usize, String> {
        self.opened_column_indices
            .capacity()
            .checked_mul(size_of::<usize>())
            .and_then(|total| {
                self.lower_subtree_digest_planes
                    .capacity()
                    .checked_mul(size_of::<Option<Vec<ColumnDigest>>>())
                    .and_then(|byte_length| total.checked_add(byte_length))
            })
            .and_then(|total| {
                self.lower_frontier_by_level_and_index
                    .capacity()
                    .checked_mul(size_of::<(usize, usize, ColumnDigest)>())
                    .and_then(|byte_length| total.checked_add(byte_length))
            })
            .and_then(|total| {
                self.upper_merkle_builder
                    .opened_columns
                    .capacity()
                    .checked_mul(size_of::<usize>())
                    .and_then(|byte_length| total.checked_add(byte_length))
            })
            .and_then(|total| {
                self.upper_merkle_builder
                    .stack
                    .capacity()
                    .checked_mul(size_of::<StreamingMerkleNode>())
                    .and_then(|byte_length| total.checked_add(byte_length))
            })
            .and_then(|total| {
                self.upper_merkle_builder
                    .frontier_by_level_and_index
                    .capacity()
                    .checked_mul(size_of::<(usize, usize, ColumnDigest)>())
                    .and_then(|byte_length| total.checked_add(byte_length))
            })
            .ok_or_else(|| "interleaved commitment metadata byte length overflowed".to_owned())
    }
}

/// Maximum heap payload retained by the interleaved Merkle scheduler apart
/// from column-hash states, digest planes, and transported opening values.
///
/// The lower frontier reserves the complete canonical frontier because the
/// split between low and upper levels depends on the sampled coordinates. The
/// upper builder simultaneously retains its own coordinate-bearing frontier,
/// opened-block indices, and logarithmic stack.
pub(super) fn maximum_interleaved_commitment_metadata_byte_length(
    encoded_column_count: usize,
    maximum_lane_column_count: usize,
    opened_column_count: usize,
    opened_block_count: usize,
    complete_frontier_node_count: usize,
    upper_frontier_node_count: usize,
) -> Result<usize, String> {
    if !encoded_column_count.is_power_of_two()
        || maximum_lane_column_count == 0
        || !maximum_lane_column_count.is_power_of_two()
        || opened_column_count > encoded_column_count
    {
        return Err("interleaved commitment metadata geometry is invalid".to_owned());
    }
    let lane_column_count = maximum_lane_column_count.min(encoded_column_count);
    let lane_count = encoded_column_count / lane_column_count;
    if !lane_count.is_power_of_two() {
        return Err("interleaved commitment metadata lane count is invalid".to_owned());
    }
    if (opened_column_count == 0) != (opened_block_count == 0)
        || opened_block_count > opened_column_count.min(lane_column_count)
    {
        return Err("interleaved commitment opened-block count is invalid".to_owned());
    }
    let opened_index_byte_length = opened_column_count
        .checked_add(opened_block_count)
        .and_then(|count| count.checked_mul(size_of::<usize>()))
        .ok_or_else(|| "interleaved commitment opening-index liveness overflowed".to_owned())?;
    let frontier_byte_length = complete_frontier_node_count
        .checked_add(upper_frontier_node_count)
        .and_then(|count| count.checked_mul(size_of::<(usize, usize, ColumnDigest)>()))
        .ok_or_else(|| "interleaved commitment frontier liveness overflowed".to_owned())?;
    let stack_byte_length = (lane_column_count.ilog2() as usize)
        .checked_add(1)
        .and_then(|count| count.checked_mul(size_of::<StreamingMerkleNode>()))
        .ok_or_else(|| "interleaved commitment stack liveness overflowed".to_owned())?;
    let plane_catalog_byte_length = (lane_count.ilog2() as usize)
        .checked_mul(size_of::<Option<Vec<ColumnDigest>>>())
        .ok_or_else(|| "interleaved commitment plane-catalog liveness overflowed".to_owned())?;
    opened_index_byte_length
        .checked_add(frontier_byte_length)
        .and_then(|total| total.checked_add(stack_byte_length))
        .and_then(|total| total.checked_add(plane_catalog_byte_length))
        .ok_or_else(|| "interleaved commitment metadata liveness overflowed".to_owned())
}

fn allocate_digest_plane(column_count: usize) -> Result<Vec<ColumnDigest>, String> {
    let mut plane = Vec::new();
    plane
        .try_reserve_exact(column_count)
        .map_err(|_| "interleaved digest-plane allocation failed".to_owned())?;
    plane.resize(column_count, [0_u64; COLUMN_DIGEST_WORD_LENGTH]);
    Ok(plane)
}

#[allow(clippy::too_many_arguments)]
fn capture_interleaved_frontier_sibling(
    opened_column_indices: &[usize],
    lane_count: usize,
    block_index: usize,
    lane_ordinal: usize,
    level: usize,
    left_digest: ColumnDigest,
    right_digest: ColumnDigest,
    frontier_by_level_and_index: &mut Vec<(usize, usize, ColumnDigest)>,
) -> Result<(), String> {
    let subtree_column_count = 1_usize
        .checked_shl(
            u32::try_from(level)
                .map_err(|_| "interleaved frontier level exceeds u32".to_owned())?,
        )
        .ok_or_else(|| "interleaved frontier subtree size overflowed".to_owned())?;
    let right_offset = lane_ordinal
        .checked_add(1)
        .and_then(|end| end.checked_sub(subtree_column_count))
        .ok_or_else(|| "interleaved frontier right coordinate underflowed".to_owned())?;
    let left_offset = right_offset
        .checked_sub(subtree_column_count)
        .ok_or_else(|| "interleaved frontier left coordinate underflowed".to_owned())?;
    let block_start = block_index
        .checked_mul(lane_count)
        .ok_or_else(|| "interleaved frontier block coordinate overflowed".to_owned())?;
    let left_start = block_start
        .checked_add(left_offset)
        .ok_or_else(|| "interleaved frontier left coordinate overflowed".to_owned())?;
    let right_start = block_start
        .checked_add(right_offset)
        .ok_or_else(|| "interleaved frontier right coordinate overflowed".to_owned())?;
    let left_contains_opening = sorted_indices_intersect_range(
        opened_column_indices,
        left_start,
        left_start + subtree_column_count,
    );
    let right_contains_opening = sorted_indices_intersect_range(
        opened_column_indices,
        right_start,
        right_start + subtree_column_count,
    );
    if left_contains_opening != right_contains_opening {
        let (sibling_start, sibling_digest) = if left_contains_opening {
            (right_start, right_digest)
        } else {
            (left_start, left_digest)
        };
        frontier_by_level_and_index.push((level, sibling_start >> level, sibling_digest));
    }
    Ok(())
}

fn sorted_indices_intersect_range(
    sorted_indices: &[usize],
    range_start: usize,
    range_end: usize,
) -> bool {
    let first_possible = sorted_indices.partition_point(|index| *index < range_start);
    sorted_indices
        .get(first_possible)
        .is_some_and(|index| *index < range_end)
}

struct StreamingMerkleNode {
    level: usize,
    index: usize,
    digest: ColumnDigest,
    contains_opened_column: bool,
}

struct StreamingMerkleBuilder {
    leaf_count: usize,
    opened_columns: Vec<usize>,
    stack: Vec<StreamingMerkleNode>,
    frontier_by_level_and_index: Vec<(usize, usize, ColumnDigest)>,
    expected_frontier_node_count: usize,
    next_leaf_index: usize,
}

struct StreamingMerkleCommitmentWithCoordinates {
    root: ColumnDigest,
    frontier_by_level_and_index: Vec<(usize, usize, ColumnDigest)>,
}

impl StreamingMerkleBuilder {
    fn new(leaf_count: usize, opened_column_indices: &[usize]) -> Result<Self, String> {
        let frontier_node_count =
            canonical_frontier_node_count_from_sorted_indices(opened_column_indices, leaf_count)?;
        let tree_depth = leaf_count.ilog2() as usize;
        let stack_capacity = tree_depth
            .checked_add(1)
            .ok_or_else(|| "streaming Merkle stack capacity overflowed".to_owned())?;
        let mut opened_columns = Vec::new();
        opened_columns
            .try_reserve_exact(opened_column_indices.len())
            .map_err(|_| "streaming Merkle opening index allocation failed".to_owned())?;
        opened_columns.extend_from_slice(opened_column_indices);
        let mut stack = Vec::new();
        stack
            .try_reserve_exact(stack_capacity)
            .map_err(|_| "streaming Merkle stack allocation failed".to_owned())?;
        let mut frontier_by_level_and_index = Vec::new();
        frontier_by_level_and_index
            .try_reserve_exact(frontier_node_count)
            .map_err(|_| "streaming Merkle frontier allocation failed".to_owned())?;
        Ok(Self {
            leaf_count,
            opened_columns,
            stack,
            frontier_by_level_and_index,
            expected_frontier_node_count: frontier_node_count,
            next_leaf_index: 0,
        })
    }

    fn push_leaf(&mut self, column_index: usize, digest: ColumnDigest) -> Result<(), String> {
        if column_index != self.next_leaf_index || column_index >= self.leaf_count {
            return Err("streaming Merkle leaves are not in canonical order".to_owned());
        }
        self.next_leaf_index += 1;
        self.stack.push(StreamingMerkleNode {
            level: 0,
            index: column_index,
            digest,
            contains_opened_column: self.opened_columns.binary_search(&column_index).is_ok(),
        });
        while self.stack.len() >= 2 {
            let right_position = self.stack.len() - 1;
            let left_position = right_position - 1;
            if self.stack[left_position].level != self.stack[right_position].level {
                break;
            }
            let right = self.stack.pop().expect("right node exists");
            let left = self.stack.pop().expect("left node exists");
            if left.index ^ 1 != right.index || left.index & 1 != 0 {
                return Err("streaming Merkle siblings are not canonical".to_owned());
            }
            if left.contains_opened_column != right.contains_opened_column {
                let frontier_node = if left.contains_opened_column {
                    &right
                } else {
                    &left
                };
                if self.frontier_by_level_and_index.len() == self.expected_frontier_node_count {
                    return Err("streaming Merkle frontier exceeded its checked size".to_owned());
                }
                self.frontier_by_level_and_index.push((
                    frontier_node.level,
                    frontier_node.index,
                    frontier_node.digest,
                ));
            }
            self.stack.push(StreamingMerkleNode {
                level: left.level + 1,
                index: left.index >> 1,
                digest: hash_merkle_parent(&left.digest, &right.digest),
                contains_opened_column: left.contains_opened_column || right.contains_opened_column,
            });
        }
        Ok(())
    }

    #[cfg(test)]
    fn finish(self) -> Result<StreamingColumnCommitment, String> {
        let commitment = self.finish_with_coordinates()?;
        Ok(StreamingColumnCommitment {
            root: commitment.root,
            frontier: commitment
                .frontier_by_level_and_index
                .into_iter()
                .map(|(_, _, digest)| digest)
                .collect(),
        })
    }

    fn finish_with_coordinates(
        mut self,
    ) -> Result<StreamingMerkleCommitmentWithCoordinates, String> {
        if self.next_leaf_index != self.leaf_count
            || self.stack.len() != 1
            || self.stack[0].level != self.leaf_count.ilog2() as usize
            || self.stack[0].index != 0
        {
            return Err("streaming Merkle tree is incomplete".to_owned());
        }
        self.frontier_by_level_and_index
            .sort_unstable_by_key(|(level, index, _)| (*level, *index));
        if self.frontier_by_level_and_index.len() != self.expected_frontier_node_count {
            return Err("streaming Merkle frontier has the wrong size".to_owned());
        }
        Ok(StreamingMerkleCommitmentWithCoordinates {
            root: self.stack.pop().expect("root exists").digest,
            frontier_by_level_and_index: self.frontier_by_level_and_index,
        })
    }
}

fn column_hash_preamble(
    expected_row_count: usize,
    encoded_column_count: usize,
    salt_byte_length: usize,
) -> [u64; 7] {
    let mut words = [0_u64; 7];
    for (word_index, chunk) in super::ROW_CODE_WHIR_PHASE_COLUMN_LEAF_DOMAIN
        .chunks_exact(8)
        .enumerate()
    {
        words[word_index] = u64::from_le_bytes(chunk.try_into().expect("eight-byte domain word"));
    }
    words[4] = expected_row_count as u64;
    words[5] = encoded_column_count as u64;
    words[6] = salt_byte_length as u64;
    words
}

fn initialized_column_hash_state(
    expected_row_count: usize,
    encoded_column_count: usize,
    salt: Option<&PrivateLeafSalt>,
) -> ([u64; SHAKE256_STATE_WORD_LENGTH], usize) {
    let mut state = [0_u64; SHAKE256_STATE_WORD_LENGTH];
    let mut next_rate_word = 0_usize;
    for word in column_hash_preamble(
        expected_row_count,
        encoded_column_count,
        salt.map_or(0, |_| PRIVATE_LEAF_SALT_BYTE_LENGTH),
    ) {
        absorb_word(&mut state, &mut next_rate_word, word);
    }
    if let Some(salt) = salt {
        for chunk in salt.chunks_exact(size_of::<u64>()) {
            absorb_word(
                &mut state,
                &mut next_rate_word,
                u64::from_le_bytes(chunk.try_into().expect("eight-byte salt word")),
            );
        }
    }
    (state, next_rate_word)
}

const fn column_hash_next_rate_word(has_salt: bool) -> usize {
    (7 + if has_salt {
        PRIVATE_LEAF_SALT_BYTE_LENGTH / size_of::<u64>()
    } else {
        0
    }) % SHAKE256_RATE_WORD_LENGTH
}

fn absorb_word(
    state: &mut [u64; SHAKE256_STATE_WORD_LENGTH],
    next_rate_word: &mut usize,
    word: u64,
) {
    state[*next_rate_word] ^= word;
    *next_rate_word += 1;
    if *next_rate_word == SHAKE256_RATE_WORD_LENGTH {
        keccakf(state);
        *next_rate_word = 0;
    }
}

#[cfg(test)]
pub(super) fn hash_opened_column(
    values: &[Goldilocks],
    encoded_column_count: usize,
) -> ColumnDigest {
    hash_opened_column_with_salt(values, encoded_column_count, None)
}

pub(super) fn hash_opened_column_with_salt(
    values: &[Goldilocks],
    encoded_column_count: usize,
    salt: Option<&PrivateLeafSalt>,
) -> ColumnDigest {
    let mut state = Shake256::default();
    for word in column_hash_preamble(
        values.len(),
        encoded_column_count,
        salt.map_or(0, |_| PRIVATE_LEAF_SALT_BYTE_LENGTH),
    ) {
        state.update(&word.to_le_bytes());
    }
    if let Some(salt) = salt {
        state.update(salt);
    }
    for value in values {
        state.update(&value.as_canonical_u64().to_le_bytes());
    }
    finish_shake256(state)
}

#[cfg(all(test, feature = "theorem-evidence"))]
pub(super) fn canonical_phase_column_leaf_oracle_input_bytes(
    values: &[Goldilocks],
    encoded_column_count: usize,
    salt: Option<&PrivateLeafSalt>,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    for word in column_hash_preamble(
        values.len(),
        encoded_column_count,
        salt.map_or(0, |_| PRIVATE_LEAF_SALT_BYTE_LENGTH),
    ) {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    if let Some(salt) = salt {
        bytes.extend_from_slice(salt);
    }
    for value in values {
        bytes.extend_from_slice(&value.as_canonical_u64().to_le_bytes());
    }
    bytes
}

fn visit_phase_column_parent_oracle_input(
    left: &ColumnDigest,
    right: &ColumnDigest,
    mut visit: impl FnMut(&[u8]),
) {
    visit(&(super::ROW_CODE_WHIR_PHASE_COLUMN_NODE_DOMAIN.len() as u64).to_le_bytes());
    visit(super::ROW_CODE_WHIR_PHASE_COLUMN_NODE_DOMAIN);
    for word in left.iter().chain(right) {
        visit(&word.to_le_bytes());
    }
}

pub(super) fn hash_merkle_parent(left: &ColumnDigest, right: &ColumnDigest) -> ColumnDigest {
    let mut state = Shake256::default();
    visit_phase_column_parent_oracle_input(left, right, |bytes| state.update(bytes));
    finish_shake256(state)
}

#[cfg(all(test, feature = "theorem-evidence"))]
pub(super) fn canonical_phase_column_parent_oracle_input_bytes(
    left: &ColumnDigest,
    right: &ColumnDigest,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    visit_phase_column_parent_oracle_input(left, right, |part| bytes.extend_from_slice(part));
    bytes
}

fn finish_shake256(state: Shake256) -> ColumnDigest {
    let mut bytes = [0_u8; COLUMN_DIGEST_BYTE_LENGTH];
    state.finalize_xof().read(&mut bytes);
    core::array::from_fn(|word_index| {
        u64::from_le_bytes(
            bytes[word_index * 8..(word_index + 1) * 8]
                .try_into()
                .expect("eight-byte digest word"),
        )
    })
}

#[cfg(test)]
pub(super) struct ColumnMerkleTree {
    levels: Vec<Vec<ColumnDigest>>,
}

#[cfg(test)]
impl ColumnMerkleTree {
    pub(super) fn new(leaves: Vec<ColumnDigest>) -> Result<Self, String> {
        if !leaves.len().is_power_of_two() {
            return Err(format!(
                "column Merkle leaf count {} is not a non-zero power of two",
                leaves.len()
            ));
        }
        let mut levels = vec![leaves];
        while levels.last().expect("at least one Merkle level").len() > 1 {
            let previous = levels.last().expect("at least one Merkle level");
            levels.push(
                previous
                    .chunks_exact(2)
                    .map(|children| hash_merkle_parent(&children[0], &children[1]))
                    .collect(),
            );
        }
        Ok(Self { levels })
    }

    pub(super) fn root(&self) -> ColumnDigest {
        self.levels.last().expect("at least one Merkle level")[0]
    }

    #[cfg(test)]
    pub(super) fn opening(&self, column_index: usize) -> Result<Vec<ColumnDigest>, String> {
        if column_index >= self.levels[0].len() {
            return Err(format!(
                "column index {column_index} is outside Merkle leaf count {}",
                self.levels[0].len()
            ));
        }
        let mut position = column_index;
        let mut path = Vec::with_capacity(self.levels.len() - 1);
        for level in &self.levels[..self.levels.len() - 1] {
            path.push(level[position ^ 1]);
            position >>= 1;
        }
        Ok(path)
    }

    pub(super) fn canonical_frontier(
        &self,
        column_indices: &[usize],
    ) -> Result<Vec<ColumnDigest>, String> {
        let mut active = canonical_column_index_set(column_indices, self.levels[0].len())?;
        let frontier_node_count =
            canonical_frontier_node_count_from_set(active.clone(), self.levels[0].len())?;
        let mut frontier = Vec::new();
        frontier
            .try_reserve_exact(frontier_node_count)
            .map_err(|_| "column Merkle frontier allocation failed".to_owned())?;
        for level in &self.levels[..self.levels.len() - 1] {
            for sibling_index in missing_sibling_indices(&active) {
                frontier.push(level[sibling_index]);
            }
            active = active.into_iter().map(|position| position >> 1).collect();
        }
        Ok(frontier)
    }

    #[cfg(test)]
    pub(super) fn exact_stored_byte_length(&self) -> usize {
        self.levels
            .iter()
            .map(|level| level.len() * size_of::<ColumnDigest>())
            .sum()
    }
}

#[cfg(test)]
pub(super) fn canonical_frontier_node_count(
    column_indices: &[usize],
    encoded_column_count: usize,
) -> Result<usize, String> {
    let active = canonical_column_index_set(column_indices, encoded_column_count)?;
    canonical_frontier_node_count_from_set(active, encoded_column_count)
}

fn canonical_frontier_node_count_from_set(
    mut active: BTreeSet<usize>,
    encoded_column_count: usize,
) -> Result<usize, String> {
    let mut count = 0_usize;
    for _ in 0..encoded_column_count.ilog2() {
        count = count
            .checked_add(missing_sibling_indices(&active).len())
            .ok_or_else(|| "column Merkle frontier node count overflowed".to_owned())?;
        active = active.into_iter().map(|position| position >> 1).collect();
    }
    Ok(count)
}

fn canonical_frontier_node_count_from_sorted_indices(
    column_indices: &[usize],
    encoded_column_count: usize,
) -> Result<usize, String> {
    validate_optional_column_indices(column_indices, encoded_column_count)?;
    let mut active_indices = Vec::new();
    active_indices
        .try_reserve_exact(column_indices.len())
        .map_err(|_| "column Merkle active-index allocation failed".to_owned())?;
    active_indices.extend_from_slice(column_indices);
    let mut parent_indices = Vec::new();
    parent_indices
        .try_reserve_exact(column_indices.len())
        .map_err(|_| "column Merkle parent-index allocation failed".to_owned())?;
    let mut frontier_node_count = 0_usize;
    for _ in 0..encoded_column_count.ilog2() {
        for position in &active_indices {
            if active_indices.binary_search(&(*position ^ 1)).is_err() {
                frontier_node_count = frontier_node_count
                    .checked_add(1)
                    .ok_or_else(|| "column Merkle frontier node count overflowed".to_owned())?;
            }
        }
        parent_indices.clear();
        for position in &active_indices {
            let parent_index = *position >> 1;
            if parent_indices.last().copied() != Some(parent_index) {
                parent_indices.push(parent_index);
            }
        }
        core::mem::swap(&mut active_indices, &mut parent_indices);
    }
    Ok(frontier_node_count)
}

fn canonical_column_index_set(
    column_indices: &[usize],
    encoded_column_count: usize,
) -> Result<BTreeSet<usize>, String> {
    if column_indices.is_empty() {
        return Err("column frontier geometry is invalid".to_owned());
    }
    canonical_optional_column_index_set(column_indices, encoded_column_count)
}

fn canonical_optional_column_index_set(
    column_indices: &[usize],
    encoded_column_count: usize,
) -> Result<BTreeSet<usize>, String> {
    validate_optional_column_indices(column_indices, encoded_column_count)?;
    Ok(column_indices.iter().copied().collect())
}

fn validate_optional_column_indices(
    column_indices: &[usize],
    encoded_column_count: usize,
) -> Result<(), String> {
    if !encoded_column_count.is_power_of_two() {
        return Err("column frontier geometry is invalid".to_owned());
    }
    if column_indices.windows(2).any(|pair| pair[0] >= pair[1])
        || column_indices
            .last()
            .is_some_and(|column_index| *column_index >= encoded_column_count)
    {
        return Err("column frontier indices are not sorted, distinct, and in range".to_owned());
    }
    Ok(())
}

fn missing_sibling_indices(active: &BTreeSet<usize>) -> Vec<usize> {
    active
        .iter()
        .copied()
        .map(|position| position ^ 1)
        .filter(|sibling| !active.contains(sibling))
        .collect()
}

#[cfg(test)]
pub(super) fn verify_column_opening(
    root: &ColumnDigest,
    column_index: usize,
    encoded_column_count: usize,
    values: &[Goldilocks],
    path: &[ColumnDigest],
) -> Result<(), String> {
    if !encoded_column_count.is_power_of_two() || column_index >= encoded_column_count {
        return Err("column opening index or encoded column count is invalid".to_owned());
    }
    if path.len() != encoded_column_count.ilog2() as usize {
        return Err(format!(
            "column Merkle path has {} nodes, expected {}",
            path.len(),
            encoded_column_count.ilog2()
        ));
    }
    let mut position = column_index;
    let mut digest = hash_opened_column(values, encoded_column_count);
    for sibling in path {
        digest = if position & 1 == 0 {
            hash_merkle_parent(&digest, sibling)
        } else {
            hash_merkle_parent(sibling, &digest)
        };
        position >>= 1;
    }
    if &digest != root {
        return Err("column opening does not match the committed Merkle root".to_owned());
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn verify_column_frontier(
    root: &ColumnDigest,
    encoded_column_count: usize,
    opened_columns: &[(usize, &[Goldilocks])],
    frontier: &[ColumnDigest],
) -> Result<(), String> {
    let opened_column_digests = opened_columns
        .iter()
        .map(|(column_index, values)| {
            (
                *column_index,
                hash_opened_column(values, encoded_column_count),
            )
        })
        .collect::<Vec<_>>();
    verify_prehashed_column_frontier(root, encoded_column_count, &opened_column_digests, frontier)
}

/// Verifies a canonical frontier after the caller has recomputed every leaf
/// digest from its canonical opened values. This keeps large opened columns
/// out of resident verifier state without accepting producer-supplied leaf
/// digests from the proof wire.
pub(super) fn verify_prehashed_column_frontier(
    root: &ColumnDigest,
    encoded_column_count: usize,
    opened_column_digests: &[(usize, ColumnDigest)],
    frontier: &[ColumnDigest],
) -> Result<(), String> {
    let column_indices = opened_column_digests
        .iter()
        .map(|(column_index, _)| *column_index)
        .collect::<Vec<_>>();
    if column_indices.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("column frontier indices are not in canonical order".to_owned());
    }
    let mut active_indices = canonical_column_index_set(&column_indices, encoded_column_count)?;
    let expected_frontier_node_count =
        canonical_frontier_node_count_from_set(active_indices.clone(), encoded_column_count)?;
    if frontier.len() != expected_frontier_node_count {
        return Err(format!(
            "column Merkle frontier has {} nodes, expected {expected_frontier_node_count}",
            frontier.len()
        ));
    }

    let mut active_digests = opened_column_digests
        .iter()
        .copied()
        .collect::<BTreeMap<_, _>>();
    if active_digests.len() != opened_column_digests.len() {
        return Err("column frontier contains a duplicated opening".to_owned());
    }
    let mut frontier_cursor = 0_usize;
    for _ in 0..encoded_column_count.ilog2() {
        for sibling_index in missing_sibling_indices(&active_indices) {
            let digest = *frontier
                .get(frontier_cursor)
                .ok_or_else(|| "column Merkle frontier ended early".to_owned())?;
            if active_digests.insert(sibling_index, digest).is_some() {
                return Err("column Merkle frontier duplicates an active node".to_owned());
            }
            frontier_cursor += 1;
        }
        let parent_indices = active_indices
            .iter()
            .map(|position| position >> 1)
            .collect::<BTreeSet<_>>();
        let mut parent_digests = BTreeMap::new();
        for parent_index in &parent_indices {
            let left_index = parent_index << 1;
            let left = active_digests
                .get(&left_index)
                .ok_or_else(|| "column Merkle frontier lacks a left child".to_owned())?;
            let right = active_digests
                .get(&(left_index | 1))
                .ok_or_else(|| "column Merkle frontier lacks a right child".to_owned())?;
            parent_digests.insert(*parent_index, hash_merkle_parent(left, right));
        }
        active_indices = parent_indices;
        active_digests = parent_digests;
    }
    if frontier_cursor != frontier.len()
        || active_digests.len() != 1
        || active_digests.get(&0) != Some(root)
    {
        return Err("column Merkle frontier does not reconstruct the committed root".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use p3_field::PrimeCharacteristicRing;

    use super::*;

    fn sample_rows(row_count: usize, column_count: usize) -> Vec<Vec<Goldilocks>> {
        (0..row_count)
            .map(|row_index| {
                (0..column_count)
                    .map(|column_index| {
                        Goldilocks::from_u64(
                            (row_index as u64 + 5) * 131 + column_index as u64 * 17,
                        )
                    })
                    .collect()
            })
            .collect()
    }

    fn build_striped_commitment(
        rows: &[Vec<Goldilocks>],
        maximum_stripe_column_count: usize,
        opened_column_indices: &[usize],
    ) -> StreamingColumnCommitment {
        let mut builder = StripedColumnCommitmentBuilder::new_with_opened_columns(
            rows.len(),
            rows[0].len(),
            maximum_stripe_column_count,
            opened_column_indices,
        )
        .expect("valid striped geometry");
        while let Some(active_range) = builder.active_column_range() {
            for (row_index, row) in rows.iter().enumerate() {
                builder
                    .absorb_active_stripe_row(row_index, &row[active_range.clone()])
                    .expect("valid striped row");
            }
            builder.complete_active_stripe().expect("complete stripe");
        }
        builder
            .finish_commitment()
            .expect("complete striped commitment")
    }

    fn build_privately_salted_striped_commitment(
        rows: &[Vec<Goldilocks>],
        maximum_stripe_column_count: usize,
        opened_column_indices: &[usize],
        private_seed: &[u8; 64],
        commitment_role: &'static [u8],
    ) -> StreamingColumnCommitment {
        let mut builder = StripedColumnCommitmentBuilder::new_with_opened_columns_and_private_salt(
            rows.len(),
            rows[0].len(),
            maximum_stripe_column_count,
            opened_column_indices,
            Some(PrivateColumnLeafSaltContext::new(
                private_seed,
                commitment_role,
            )),
        )
        .expect("valid privately salted stripe geometry");
        while let Some(active_range) = builder.active_column_range() {
            for (row_index, row) in rows.iter().enumerate() {
                builder
                    .absorb_active_stripe_row(row_index, &row[active_range.clone()])
                    .expect("valid privately salted stripe row");
            }
            builder
                .complete_active_stripe()
                .expect("complete privately salted stripe");
        }
        builder
            .finish_commitment()
            .expect("complete privately salted commitment")
    }

    fn build_interleaved_commitment(
        rows: &[Vec<Goldilocks>],
        maximum_lane_column_count: usize,
        opened_column_indices: &[usize],
        private_salt: Option<(&[u8; 64], &'static [u8])>,
    ) -> StreamingColumnCommitment {
        let mut builder =
            InterleavedColumnCommitmentBuilder::new_with_opened_columns_and_private_salt(
                rows.len(),
                rows[0].len(),
                maximum_lane_column_count,
                opened_column_indices,
                private_salt.map(|(private_seed, commitment_role)| {
                    PrivateColumnLeafSaltContext::new(private_seed, commitment_role)
                }),
            )
            .expect("valid interleaved commitment geometry");
        let lane_count = builder.lane_count();
        let lane_column_count = builder.lane_column_count();
        while let Some(lane_ordinal) = builder.active_lane_ordinal() {
            for (row_index, row) in rows.iter().enumerate() {
                let lane = row
                    .iter()
                    .skip(lane_ordinal)
                    .step_by(lane_count)
                    .copied()
                    .collect::<Vec<_>>();
                assert_eq!(lane.len(), lane_column_count);
                builder
                    .absorb_active_lane_row(row_index, &lane)
                    .expect("valid interleaved row lane");
            }
            builder
                .complete_active_lane()
                .expect("complete interleaved lane");
        }
        builder
            .finish_commitment()
            .expect("complete interleaved commitment")
    }

    #[test]
    fn base_field_stripes_match_the_canonical_goldilocks_commitment_and_frontier() {
        let rows = sample_rows(7, 32);
        let opened_column_indices = [0, 3, 11, 16, 30];
        let expected = build_striped_commitment(&rows, 9, &opened_column_indices);
        let base_rows = rows
            .iter()
            .map(|row| {
                row.iter()
                    .map(|value| {
                        ProofBaseFieldElement::from_reduced(u128::from(value.as_canonical_u64()))
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let mut builder = StripedColumnCommitmentBuilder::new_with_opened_columns(
            base_rows.len(),
            base_rows[0].len(),
            9,
            &opened_column_indices,
        )
        .expect("the base-field stripe geometry is valid");
        while let Some(active_range) = builder.active_column_range() {
            for (row_index, row) in base_rows.iter().enumerate() {
                builder
                    .absorb_active_stripe_base_row(row_index, &row[active_range.clone()])
                    .expect("the base-field stripe row is canonical");
            }
            builder
                .complete_active_stripe()
                .expect("the base-field stripe completes");
        }
        assert_eq!(
            builder
                .finish_commitment()
                .expect("the base-field commitment completes"),
            expected,
        );
    }

    #[test]
    fn parallel_column_hashes_match_independent_shake256() {
        let rows = sample_rows(31, 16);
        let mut hasher =
            StreamingColumnHasher::new(rows.len(), rows[0].len()).expect("valid column geometry");
        for row in &rows {
            hasher.absorb_row(row).expect("valid encoded row");
        }
        let parallel = hasher.finalize().expect("complete row stream");
        for column_index in 0..rows[0].len() {
            let column = rows.iter().map(|row| row[column_index]).collect::<Vec<_>>();
            assert_eq!(
                parallel[column_index],
                hash_opened_column(&column, rows[0].len())
            );
        }
    }

    #[test]
    fn private_coordinate_salts_authenticate_compact_frontiers_and_refuse_substitution() {
        const COMMITMENT_ROLE: &[u8] = b"phase/base";
        let rows = sample_rows(19, 64);
        let private_seed = [0x43_u8; 64];
        let changed_private_seed = [0x44_u8; 64];
        let opened_column_indices = [0, 1, 9, 31, 32, 61];
        let commitment = build_privately_salted_striped_commitment(
            &rows,
            7,
            &opened_column_indices,
            &private_seed,
            COMMITMENT_ROLE,
        );
        let complete_width_commitment = build_privately_salted_striped_commitment(
            &rows,
            rows[0].len(),
            &opened_column_indices,
            &private_seed,
            COMMITMENT_ROLE,
        );
        assert_eq!(commitment, complete_width_commitment);
        assert_ne!(
            commitment.root,
            build_striped_commitment(&rows, 7, &opened_column_indices).root
        );
        assert_ne!(
            commitment.root,
            build_privately_salted_striped_commitment(
                &rows,
                7,
                &opened_column_indices,
                &changed_private_seed,
                COMMITMENT_ROLE,
            )
            .root
        );

        let opened_values = opened_column_indices
            .iter()
            .map(|column_index| {
                rows.iter()
                    .map(|row| row[*column_index])
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let salts = opened_column_indices
            .iter()
            .map(|column_index| {
                derive_private_leaf_salt(
                    &private_seed,
                    COMMITMENT_ROLE,
                    rows[0].len(),
                    rows.len(),
                    0,
                    *column_index,
                )
                .expect("opened coordinate salt derives")
            })
            .collect::<Vec<_>>();
        let opened_digests = opened_column_indices
            .iter()
            .zip(&opened_values)
            .zip(&salts)
            .map(|((column_index, values), salt)| {
                (
                    *column_index,
                    hash_opened_column_with_salt(values, rows[0].len(), Some(salt)),
                )
            })
            .collect::<Vec<_>>();
        verify_prehashed_column_frontier(
            &commitment.root,
            rows[0].len(),
            &opened_digests,
            &commitment.frontier,
        )
        .expect("genuine privately salted frontier verifies");

        let mut changed_salt = salts[2];
        changed_salt[0] ^= 1;
        let mut changed_salt_digests = opened_digests.clone();
        changed_salt_digests[2].1 =
            hash_opened_column_with_salt(&opened_values[2], rows[0].len(), Some(&changed_salt));
        assert!(
            verify_prehashed_column_frontier(
                &commitment.root,
                rows[0].len(),
                &changed_salt_digests,
                &commitment.frontier,
            )
            .is_err()
        );

        let mut reused_salt_digests = opened_digests.clone();
        reused_salt_digests[2].1 =
            hash_opened_column_with_salt(&opened_values[2], rows[0].len(), Some(&salts[1]));
        assert!(
            verify_prehashed_column_frontier(
                &commitment.root,
                rows[0].len(),
                &reused_salt_digests,
                &commitment.frontier,
            )
            .is_err()
        );

        let mut missing_salt_digests = opened_digests.clone();
        missing_salt_digests[2].1 =
            hash_opened_column_with_salt(&opened_values[2], rows[0].len(), None);
        assert!(
            verify_prehashed_column_frontier(
                &commitment.root,
                rows[0].len(),
                &missing_salt_digests,
                &commitment.frontier,
            )
            .is_err()
        );
    }

    #[test]
    fn column_hash_binds_geometry_and_row_order() {
        let values = (0..19)
            .map(|value| Goldilocks::from_u64(value + 1))
            .collect::<Vec<_>>();
        let digest = hash_opened_column(&values, 32);
        let mut reordered = values.clone();
        reordered.swap(0, 18);
        assert_ne!(digest, hash_opened_column(&reordered, 32));
        assert_ne!(digest, hash_opened_column(&values, 64));
        assert_ne!(digest, hash_opened_column(&values[..values.len() - 1], 32));
    }

    #[test]
    fn merkle_openings_reject_value_index_path_and_root_mutations() {
        let rows = sample_rows(7, 16);
        let leaves = (0..16)
            .map(|column_index| {
                hash_opened_column(
                    &rows.iter().map(|row| row[column_index]).collect::<Vec<_>>(),
                    16,
                )
            })
            .collect();
        let tree = ColumnMerkleTree::new(leaves).expect("power-of-two Merkle tree");
        for column_index in 0..16 {
            let values = rows.iter().map(|row| row[column_index]).collect::<Vec<_>>();
            let path = tree.opening(column_index).expect("valid leaf index");
            verify_column_opening(&tree.root(), column_index, 16, &values, &path)
                .expect("genuine column opening");

            let mut changed_values = values.clone();
            changed_values[0] += Goldilocks::ONE;
            assert!(
                verify_column_opening(&tree.root(), column_index, 16, &changed_values, &path,)
                    .is_err()
            );
            assert!(
                verify_column_opening(&tree.root(), column_index ^ 1, 16, &values, &path,).is_err()
            );

            let mut changed_path = path.clone();
            changed_path[0][0] ^= 1;
            assert!(
                verify_column_opening(&tree.root(), column_index, 16, &values, &changed_path,)
                    .is_err()
            );
            let mut changed_root = tree.root();
            changed_root[0] ^= 1;
            assert!(
                verify_column_opening(&changed_root, column_index, 16, &values, &path,).is_err()
            );
        }
    }

    #[test]
    fn canonical_frontier_authenticates_distinct_columns_and_rejects_mutations() {
        let rows = sample_rows(9, 64);
        let leaves = (0..64)
            .map(|column_index| {
                hash_opened_column(
                    &rows.iter().map(|row| row[column_index]).collect::<Vec<_>>(),
                    64,
                )
            })
            .collect();
        let tree = ColumnMerkleTree::new(leaves).expect("power-of-two Merkle tree");
        let indices = [1, 2, 3, 17, 41, 62];
        let values = indices
            .iter()
            .map(|column_index| {
                rows.iter()
                    .map(|row| row[*column_index])
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let opened = indices
            .iter()
            .copied()
            .zip(values.iter().map(Vec::as_slice))
            .collect::<Vec<_>>();
        let frontier = tree
            .canonical_frontier(&indices)
            .expect("valid canonical frontier");
        assert_eq!(
            frontier.len(),
            canonical_frontier_node_count(&indices, 64).expect("valid geometry")
        );
        assert!(frontier.len() < indices.len() * 6);
        verify_column_frontier(&tree.root(), 64, &opened, &frontier)
            .expect("genuine frontier verifies");
        let opened_digests = opened
            .iter()
            .map(|(column_index, values)| (*column_index, hash_opened_column(values, 64)))
            .collect::<Vec<_>>();
        verify_prehashed_column_frontier(&tree.root(), 64, &opened_digests, &frontier)
            .expect("genuine prehashed frontier verifies");

        let mut changed_digest = opened_digests.clone();
        changed_digest[2].1[0] ^= 1;
        assert!(
            verify_prehashed_column_frontier(&tree.root(), 64, &changed_digest, &frontier).is_err()
        );
        let mut duplicated_digest = opened_digests.clone();
        duplicated_digest[1].0 = duplicated_digest[0].0;
        assert!(
            verify_prehashed_column_frontier(&tree.root(), 64, &duplicated_digest, &frontier)
                .is_err()
        );
        let mut unsorted_digests = opened_digests.clone();
        unsorted_digests.swap(1, 2);
        assert!(
            verify_prehashed_column_frontier(&tree.root(), 64, &unsorted_digests, &frontier)
                .is_err()
        );
        let mut wrong_root = tree.root();
        wrong_root[0] ^= 1;
        assert!(
            verify_prehashed_column_frontier(&wrong_root, 64, &opened_digests, &frontier).is_err()
        );
        assert!(
            verify_prehashed_column_frontier(
                &tree.root(),
                64,
                &opened_digests,
                &frontier[..frontier.len() - 1],
            )
            .is_err()
        );

        let mut changed_values = values.clone();
        changed_values[3][4] += Goldilocks::ONE;
        let changed_opened = indices
            .iter()
            .copied()
            .zip(changed_values.iter().map(Vec::as_slice))
            .collect::<Vec<_>>();
        assert!(verify_column_frontier(&tree.root(), 64, &changed_opened, &frontier).is_err());

        let mut changed_frontier = frontier.clone();
        changed_frontier[0][0] ^= 1;
        assert!(verify_column_frontier(&tree.root(), 64, &opened, &changed_frontier).is_err());
        assert!(
            verify_column_frontier(&tree.root(), 64, &opened, &frontier[..frontier.len() - 1])
                .is_err()
        );
        assert!(canonical_frontier_node_count(&[1, 1], 64).is_err());
        assert!(canonical_frontier_node_count(&[64], 64).is_err());
    }

    #[test]
    fn streaming_merkle_root_and_frontier_match_the_materialized_tree() {
        for row_count in [1, 2, 17, 31] {
            for column_count in [2, 8, 64, 256] {
                let rows = sample_rows(row_count, column_count);
                let mut materialized_hasher =
                    StreamingColumnHasher::new(row_count, column_count).expect("valid geometry");
                let mut streaming_hasher =
                    StreamingColumnHasher::new(row_count, column_count).expect("valid geometry");
                for row in &rows {
                    materialized_hasher.absorb_row(row).expect("valid row");
                    streaming_hasher.absorb_row(row).expect("valid row");
                }
                let tree = ColumnMerkleTree::new(
                    materialized_hasher
                        .finalize()
                        .expect("complete materialized hashes"),
                )
                .expect("valid tree");
                let indices = (0..column_count)
                    .filter(|column_index| {
                        column_index % 5 == 1 || *column_index + 1 == column_count
                    })
                    .collect::<Vec<_>>();
                let streaming = streaming_hasher
                    .finalize_commitment(&indices)
                    .expect("complete streaming tree");
                assert_eq!(streaming.root, tree.root());
                assert_eq!(
                    streaming.frontier,
                    tree.canonical_frontier(&indices)
                        .expect("canonical frontier")
                );
                let opened_values = indices
                    .iter()
                    .map(|column_index| {
                        (
                            *column_index,
                            rows.iter()
                                .map(|row| row[*column_index])
                                .collect::<Vec<_>>(),
                        )
                    })
                    .collect::<Vec<_>>();
                let opened = opened_values
                    .iter()
                    .map(|(column_index, values)| (*column_index, values.as_slice()))
                    .collect::<Vec<_>>();
                verify_column_frontier(&streaming.root, column_count, &opened, &streaming.frontier)
                    .expect("streamed frontier verifies");
            }
        }
    }

    #[test]
    fn striped_commitment_matches_the_complete_state_across_irregular_boundaries() {
        for row_count in [1, 2, 7, 31] {
            for column_count in [2, 8, 64, 256] {
                let rows = sample_rows(row_count, column_count);
                let mut complete_hasher =
                    StreamingColumnHasher::new(row_count, column_count).expect("valid geometry");
                for row in &rows {
                    complete_hasher.absorb_row(row).expect("valid complete row");
                }
                let expected_root = complete_hasher
                    .finalize_root()
                    .expect("complete commitment");

                for maximum_stripe_column_count in [1, 2, 3, 7, 17, column_count + 3] {
                    let mut builder = StripedColumnCommitmentBuilder::new(
                        row_count,
                        column_count,
                        maximum_stripe_column_count,
                    )
                    .expect("valid striped geometry");
                    while let Some(active_range) = builder.active_column_range() {
                        for (row_index, row) in rows.iter().enumerate() {
                            builder
                                .absorb_active_stripe_row(row_index, &row[active_range.clone()])
                                .expect("valid striped row");
                        }
                        builder.complete_active_stripe().expect("complete stripe");
                    }
                    assert_eq!(
                        builder.finish().expect("complete striped commitment"),
                        expected_root,
                        "row count {row_count}, column count {column_count}, stripe width {maximum_stripe_column_count}"
                    );
                }
            }
        }
    }

    #[test]
    fn interleaved_lanes_preserve_natural_roots_and_compact_frontiers() {
        for row_count in [1, 2, 7, 31] {
            for column_count in [2, 8, 64, 256] {
                let rows = sample_rows(row_count, column_count);
                let opened_column_indices = (0..column_count)
                    .filter(|column_index| {
                        *column_index == 0
                            || *column_index + 1 == column_count
                            || column_index % 11 == 3
                    })
                    .collect::<Vec<_>>();
                let expected =
                    build_striped_commitment(&rows, column_count, &opened_column_indices);
                for maximum_lane_column_count in [1, 2, 4, 16, 64, 256] {
                    let commitment = build_interleaved_commitment(
                        &rows,
                        maximum_lane_column_count,
                        &opened_column_indices,
                        None,
                    );
                    assert_eq!(
                        commitment, expected,
                        "row count {row_count}, column count {column_count}, lane width {maximum_lane_column_count}",
                    );
                }
            }
        }
    }

    #[test]
    fn interleaved_lanes_preserve_private_salts_and_refuse_wrong_progress() {
        const COMMITMENT_ROLE: &[u8] = b"phase/interleaved";
        let rows = sample_rows(19, 64);
        let private_seed = [0x57_u8; 64];
        let opened_column_indices = [0, 1, 7, 8, 17, 31, 32, 63];
        let expected = build_privately_salted_striped_commitment(
            &rows,
            rows[0].len(),
            &opened_column_indices,
            &private_seed,
            COMMITMENT_ROLE,
        );
        let commitment = build_interleaved_commitment(
            &rows,
            16,
            &opened_column_indices,
            Some((&private_seed, COMMITMENT_ROLE)),
        );
        assert_eq!(commitment, expected);

        let mut builder =
            InterleavedColumnCommitmentBuilder::new_with_opened_columns_and_private_salt(
                rows.len(),
                rows[0].len(),
                16,
                &opened_column_indices,
                Some(PrivateColumnLeafSaltContext::new(
                    &private_seed,
                    COMMITMENT_ROLE,
                )),
            )
            .expect("valid interleaved geometry");
        let first_lane = rows[0]
            .iter()
            .step_by(builder.lane_count())
            .copied()
            .collect::<Vec<_>>();
        assert!(builder.absorb_active_lane_row(1, &first_lane).is_err());
        assert!(builder.complete_active_lane().is_err());
        assert!(builder.finish_commitment().is_err());

        assert!(
            InterleavedColumnCommitmentBuilder::new_with_opened_columns_and_private_salt(
                rows.len(),
                rows[0].len(),
                3,
                &opened_column_indices,
                None,
            )
            .is_err()
        );
        assert!(
            InterleavedColumnCommitmentBuilder::new_with_opened_columns_and_private_salt(
                rows.len(),
                rows[0].len(),
                16,
                &[8, 7],
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn interleaved_metadata_liveness_matches_every_owned_coordinate_allocation() {
        let encoded_column_count = 256;
        let lane_column_count = 8;
        let opened_column_indices = [0, 1, 7, 8, 31, 32, 127, 191, 255];
        let builder = InterleavedColumnCommitmentBuilder::new_with_opened_columns_and_private_salt(
            19,
            encoded_column_count,
            lane_column_count,
            &opened_column_indices,
            None,
        )
        .expect("the focused interleaved geometry is valid");
        let complete_frontier_node_count = canonical_frontier_node_count_from_sorted_indices(
            &opened_column_indices,
            encoded_column_count,
        )
        .expect("the focused complete frontier derives");
        let opened_block_indices = opened_column_indices
            .iter()
            .map(|column_index| column_index / builder.lane_count())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let upper_frontier_node_count = canonical_frontier_node_count_from_sorted_indices(
            &opened_block_indices,
            builder.lane_column_count(),
        )
        .expect("the focused upper frontier derives");
        assert_eq!(
            builder
                .metadata_allocation_byte_length()
                .expect("the live metadata allocation derives"),
            maximum_interleaved_commitment_metadata_byte_length(
                encoded_column_count,
                lane_column_count,
                opened_column_indices.len(),
                opened_block_indices.len(),
                complete_frontier_node_count,
                upper_frontier_node_count,
            )
            .expect("the static metadata allocation derives"),
        );
        assert!(
            maximum_interleaved_commitment_metadata_byte_length(
                encoded_column_count,
                3,
                opened_column_indices.len(),
                opened_block_indices.len(),
                complete_frontier_node_count,
                upper_frontier_node_count,
            )
            .is_err()
        );
        assert!(
            maximum_interleaved_commitment_metadata_byte_length(
                encoded_column_count,
                lane_column_count,
                encoded_column_count + 1,
                opened_block_indices.len(),
                complete_frontier_node_count,
                upper_frontier_node_count,
            )
            .is_err()
        );
    }

    #[test]
    fn striped_opening_frontier_matches_the_materialized_tree_at_boundaries() {
        let cases = [
            (1, 1, 1, vec![0]),
            (1, 2, 1, Vec::new()),
            (2, 8, 3, vec![0]),
            (7, 8, 3, vec![7]),
            (17, 64, 7, vec![6, 7, 13, 14, 63]),
        ];
        for (row_count, column_count, stripe_width, opened_column_indices) in cases {
            let rows = sample_rows(row_count, column_count);
            let mut complete_hasher =
                StreamingColumnHasher::new(row_count, column_count).expect("valid geometry");
            for row in &rows {
                complete_hasher.absorb_row(row).expect("valid complete row");
            }
            let tree = ColumnMerkleTree::new(
                complete_hasher
                    .finalize()
                    .expect("complete materialized hashes"),
            )
            .expect("valid materialized tree");
            let commitment = build_striped_commitment(&rows, stripe_width, &opened_column_indices);
            assert_eq!(commitment.root, tree.root());
            if opened_column_indices.is_empty() {
                assert!(commitment.frontier.is_empty());
                continue;
            }
            assert_eq!(
                commitment.frontier,
                tree.canonical_frontier(&opened_column_indices)
                    .expect("canonical materialized frontier")
            );
            let opened_values = opened_column_indices
                .iter()
                .map(|column_index| {
                    (
                        *column_index,
                        rows.iter()
                            .map(|row| row[*column_index])
                            .collect::<Vec<_>>(),
                    )
                })
                .collect::<Vec<_>>();
            let opened_columns = opened_values
                .iter()
                .map(|(column_index, values)| (*column_index, values.as_slice()))
                .collect::<Vec<_>>();
            verify_column_frontier(
                &commitment.root,
                column_count,
                &opened_columns,
                &commitment.frontier,
            )
            .expect("striped frontier verifies");
        }
    }

    #[test]
    fn selected_row_geometry_keeps_opening_capture_bounded_and_root_identical() {
        let row_count = 247;
        let column_count = 256;
        let stripe_width = 31;
        let opened_column_indices = [0, 30, 31, 127, 128, 247, 248, 255];
        let rows = sample_rows(row_count, column_count);
        let commitment = build_striped_commitment(&rows, stripe_width, &opened_column_indices);

        let mut complete_hasher =
            StreamingColumnHasher::new(row_count, column_count).expect("valid geometry");
        for row in &rows {
            complete_hasher.absorb_row(row).expect("valid complete row");
        }
        let tree = ColumnMerkleTree::new(
            complete_hasher
                .finalize()
                .expect("complete materialized hashes"),
        )
        .expect("valid materialized tree");
        assert_eq!(commitment.root, tree.root());
        assert_eq!(
            commitment.frontier,
            tree.canonical_frontier(&opened_column_indices)
                .expect("canonical materialized frontier")
        );
        assert_eq!(
            commitment.frontier.len(),
            canonical_frontier_node_count(&opened_column_indices, column_count)
                .expect("valid frontier geometry")
        );
        assert!(
            commitment.frontier.len()
                <= opened_column_indices.len() * column_count.ilog2() as usize
        );
    }

    #[test]
    fn striped_opening_capture_refuses_noncanonical_indices() {
        assert!(StripedColumnCommitmentBuilder::new_with_opened_columns(3, 8, 3, &[1, 1]).is_err());
        assert!(StripedColumnCommitmentBuilder::new_with_opened_columns(3, 8, 3, &[2, 1]).is_err());
        assert!(StripedColumnCommitmentBuilder::new_with_opened_columns(3, 8, 3, &[8]).is_err());
        assert!(canonical_frontier_node_count(&[2, 1], 8).is_err());

        let mut merkle_builder = StreamingMerkleBuilder::new(8, &[1]).expect("valid capture");
        assert!(
            merkle_builder
                .push_leaf(1, [0; COLUMN_DIGEST_WORD_LENGTH])
                .is_err()
        );
        assert!(merkle_builder.finish().is_err());
    }

    #[test]
    fn striped_commitment_refuses_incomplete_reordered_and_wrong_width_rows() {
        assert!(StripedColumnCommitmentBuilder::new(3, 8, 0).is_err());
        assert!(StripedColumnCommitmentBuilder::new(0, 8, 2).is_err());
        assert!(StripedColumnCommitmentBuilder::new(3, 7, 2).is_err());

        let rows = sample_rows(3, 8);
        let mut reordered =
            StripedColumnCommitmentBuilder::new(3, 8, 3).expect("valid striped geometry");
        let first_range = reordered
            .active_column_range()
            .expect("first stripe exists");
        assert!(
            reordered
                .absorb_active_stripe_row(1, &rows[1][first_range.clone()])
                .is_err()
        );
        assert!(
            reordered
                .absorb_active_stripe_row(0, &rows[0][first_range.start..first_range.end - 1])
                .is_err()
        );
        reordered
            .absorb_active_stripe_row(0, &rows[0][first_range.clone()])
            .expect("first canonical row");
        assert!(reordered.complete_active_stripe().is_err());
        assert!(reordered.finish().is_err());

        let incomplete =
            StripedColumnCommitmentBuilder::new(3, 8, 3).expect("valid striped geometry");
        assert!(incomplete.finish().is_err());
    }

    #[test]
    fn target_state_and_tree_accounting_is_exact() {
        let encoded_column_count = 1_usize << 19;
        assert_eq!(size_of::<[u64; SHAKE256_STATE_WORD_LENGTH]>(), 200);
        assert_eq!(
            StreamingColumnHasher::exact_state_byte_length(encoded_column_count),
            Some(100 * 1_024 * 1_024)
        );

        let small_tree = ColumnMerkleTree::new(vec![[0; COLUMN_DIGEST_WORD_LENGTH]; 16])
            .expect("power-of-two Merkle tree");
        assert_eq!(
            small_tree.exact_stored_byte_length(),
            (2 * 16 - 1) * COLUMN_DIGEST_BYTE_LENGTH
        );
        assert_eq!(
            (2 * encoded_column_count - 1) * COLUMN_DIGEST_BYTE_LENGTH,
            64 * 1_024 * 1_024 - COLUMN_DIGEST_BYTE_LENGTH
        );

        let selected_width_builder = StripedColumnCommitmentBuilder::new(247, 1 << 21, 1 << 15)
            .expect("selected striped geometry");
        assert_eq!(
            selected_width_builder
                .maximum_hash_state_byte_length()
                .expect("bounded state byte length"),
            6_400 * 1_024
        );
    }

    #[test]
    fn malformed_stream_geometry_is_rejected() {
        assert!(StreamingColumnHasher::new(0, 8).is_err());
        assert!(StreamingColumnHasher::new(3, 7).is_err());

        let mut short = StreamingColumnHasher::new(2, 8).expect("valid geometry");
        short.absorb_row(&[Goldilocks::ZERO; 8]).expect("first row");
        assert!(short.finalize().is_err());

        let mut wrong_width = StreamingColumnHasher::new(1, 8).expect("valid geometry");
        assert!(wrong_width.absorb_row(&[Goldilocks::ZERO; 7]).is_err());

        let mut excess = StreamingColumnHasher::new(1, 8).expect("valid geometry");
        excess
            .absorb_row(&[Goldilocks::ZERO; 8])
            .expect("only expected row");
        assert!(excess.absorb_row(&[Goldilocks::ZERO; 8]).is_err());
    }
}
