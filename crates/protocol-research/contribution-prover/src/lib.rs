#![deny(unsafe_op_in_unsafe_fn)]
#[cfg(target_arch = "wasm32")]
pub mod browser;

use supported_profile::{Profile, relation::setup_relation};
use word_proof::bridge::first_checkpoint;

/// The longest checkpoint header of a profile's contribution and each of its
/// sealed checkpoint records' lengths, in record order.
pub fn checkpoint_layout(profile: Profile) -> (usize, Vec<usize>) {
    (
        first_checkpoint::maximum_header_bytes(profile),
        first_checkpoint::record_lengths(&setup_relation(profile)),
    )
}
