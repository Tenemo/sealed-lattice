//! Allocation lower bound for the pinned Plonky3 HidingWhir implementation.
//!
//! The formulas mirror the concrete allocations in Plonky3 commit
//! `f07da1c479c519040cca27924184c2730315e202`:
//!
//! - `HidingWhirProverData` retains the original base-field `Poly`;
//! - `zk_padded_matrix` and `dft_batch` create and retain the full encoded
//!   initial oracle in the Merkle prover data;
//! - `MerkleTree` retains every 64-byte digest layer;
//! - opening allocates a degree-five extension vector for the lifted message
//!   and another for the equality weights while the retained data is live.
//!
//! This deliberately excludes randomness, vector capacities, allocator
//! metadata, later masks, code-switch rounds, and transient copies. It is a
//! simultaneous-allocation lower bound, not a peak estimate.

const BASE_FIELD_ELEMENT_BYTE_LENGTH: u128 = 8;
const CHALLENGE_FIELD_ELEMENT_BYTE_LENGTH: u128 = 40;
const MERKLE_DIGEST_BYTE_LENGTH: u128 = 64;
const INITIAL_FOLDING_FACTOR_LOG: u32 = 4;
const STARTING_LOG_INVERSE_RATE: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HidingWhirAllocationLowerBound {
    pub(crate) witness_variable_count: u32,
    pub(crate) message_byte_length: u128,
    pub(crate) encoded_oracle_byte_length: u128,
    pub(crate) merkle_digest_layers_byte_length: u128,
    pub(crate) lifted_message_byte_length: u128,
    pub(crate) equality_weights_byte_length: u128,
    pub(crate) retained_commitment_byte_length: u128,
    pub(crate) opening_simultaneous_byte_length: u128,
}

impl HidingWhirAllocationLowerBound {
    pub(crate) const fn exceeds(self, byte_limit: u128) -> bool {
        self.opening_simultaneous_byte_length > byte_limit
    }
}

pub(crate) fn pinned_hiding_whir_allocation_lower_bound(
    witness_variable_count: u32,
) -> Option<HidingWhirAllocationLowerBound> {
    if witness_variable_count < INITIAL_FOLDING_FACTOR_LOG {
        return None;
    }
    let message_element_count = 1_u128.checked_shl(witness_variable_count)?;
    let leaf_count = 1_u128.checked_shl(
        witness_variable_count - INITIAL_FOLDING_FACTOR_LOG + STARTING_LOG_INVERSE_RATE,
    )?;
    let leaf_width = 1_u128 << INITIAL_FOLDING_FACTOR_LOG;
    let encoded_element_count = leaf_count.checked_mul(leaf_width)?;
    let merkle_digest_count = leaf_count.checked_mul(2)?.checked_sub(1)?;

    let message_byte_length = message_element_count.checked_mul(BASE_FIELD_ELEMENT_BYTE_LENGTH)?;
    let encoded_oracle_byte_length =
        encoded_element_count.checked_mul(BASE_FIELD_ELEMENT_BYTE_LENGTH)?;
    let merkle_digest_layers_byte_length =
        merkle_digest_count.checked_mul(MERKLE_DIGEST_BYTE_LENGTH)?;
    let lifted_message_byte_length =
        message_element_count.checked_mul(CHALLENGE_FIELD_ELEMENT_BYTE_LENGTH)?;
    let equality_weights_byte_length = lifted_message_byte_length;
    let retained_commitment_byte_length = message_byte_length
        .checked_add(encoded_oracle_byte_length)?
        .checked_add(merkle_digest_layers_byte_length)?;
    let opening_simultaneous_byte_length = retained_commitment_byte_length
        .checked_add(lifted_message_byte_length)?
        .checked_add(equality_weights_byte_length)?;

    Some(HidingWhirAllocationLowerBound {
        witness_variable_count,
        message_byte_length,
        encoded_oracle_byte_length,
        merkle_digest_layers_byte_length,
        lifted_message_byte_length,
        equality_weights_byte_length,
        retained_commitment_byte_length,
        opening_simultaneous_byte_length,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MEBIBYTE: u128 = 1_048_576;
    const GIBIBYTE: u128 = 1_073_741_824;

    #[test]
    fn full_width_pinned_backend_exceeds_both_memory_limits_before_transients() {
        let plan = pinned_hiding_whir_allocation_lower_bound(26)
            .expect("the full-width shape is representable");
        assert_eq!(plan.message_byte_length, 512 * MEBIBYTE);
        assert_eq!(plan.encoded_oracle_byte_length, GIBIBYTE);
        assert_eq!(
            plan.merkle_digest_layers_byte_length,
            GIBIBYTE - MERKLE_DIGEST_BYTE_LENGTH
        );
        assert_eq!(plan.lifted_message_byte_length, 2_560 * MEBIBYTE);
        assert_eq!(plan.equality_weights_byte_length, 2_560 * MEBIBYTE);
        assert_eq!(
            plan.opening_simultaneous_byte_length,
            7_679 * MEBIBYTE + (MEBIBYTE - MERKLE_DIGEST_BYTE_LENGTH)
        );
        assert!(plan.exceeds(256 * MEBIBYTE));
        assert!(plan.exceeds(640 * MEBIBYTE));
    }

    #[test]
    fn lower_bound_crosses_the_working_limit_between_twenty_one_and_twenty_two_variables() {
        let twenty = pinned_hiding_whir_allocation_lower_bound(20).expect("twenty variables");
        let twenty_one =
            pinned_hiding_whir_allocation_lower_bound(21).expect("twenty-one variables");
        assert!(twenty.opening_simultaneous_byte_length < 256 * MEBIBYTE);
        assert!(twenty_one.opening_simultaneous_byte_length < 256 * MEBIBYTE);
        let twenty_two =
            pinned_hiding_whir_allocation_lower_bound(22).expect("twenty-two variables");
        assert!(twenty_two.opening_simultaneous_byte_length > 256 * MEBIBYTE);
    }

    #[test]
    fn planner_rejects_shapes_smaller_than_the_initial_interleave() {
        assert_eq!(pinned_hiding_whir_allocation_lower_bound(3), None);
    }
}
