//! Independent evaluator-key quotient counts from the selected topology.
//!
//! This test-only derivation deliberately does not call a relation compiler,
//! inspect a compiled source layout, or construct compact geometry. It uses the
//! suite-owned evaluator schedule and the normative hybrid key-switch formulas
//! directly, then compares its result with the separately tested compiler path.

use crate::bgv::{
    evaluator::top_k::{
        SELECTED_RELINEARIZATION_KEY_LEVEL, selected_evaluator_rotation_key_schedule,
    },
    key_switch_topology::KEY_SWITCH_DATA_PRIMES_PER_BLOCK,
    parameters::{DATA_PRIMES, SPECIAL_PRIMES},
    setup::{SETUP_COMMITMENT_MODULE_RANK, SETUP_COMMITMENT_MODULUS_LIMB_INDICES},
};
use crate::foundation::FOUNDATION_PROFILE;

#[derive(Clone, Debug, PartialEq, Eq)]
struct EvaluatorKeyQuotientTopology {
    relinearization_modulus_row_count: u64,
    ordered_galois_modulus_row_counts: Box<[u64]>,
    shared_anchor_quotient_count: u64,
    relinearization_round_one_quotient_count: u64,
    relinearization_round_two_quotient_count: u64,
    galois_key_share_quotient_count: u64,
}

fn modulus_row_count_for_level(level: usize) -> Option<u64> {
    let active_data_modulus_count = level.checked_add(1)?;
    if active_data_modulus_count > DATA_PRIMES.len() {
        return None;
    }
    let active_decomposition_block_count =
        active_data_modulus_count.div_ceil(KEY_SWITCH_DATA_PRIMES_PER_BLOCK);
    let extended_modulus_count = active_data_modulus_count.checked_add(SPECIAL_PRIMES.len())?;
    u64::try_from(active_decomposition_block_count)
        .ok()?
        .checked_mul(u64::try_from(extended_modulus_count).ok()?)
}

fn derive_selected_evaluator_key_quotient_topology() -> Option<EvaluatorKeyQuotientTopology> {
    let relinearization_modulus_row_count =
        modulus_row_count_for_level(SELECTED_RELINEARIZATION_KEY_LEVEL)?;
    let ordered_galois_modulus_row_counts =
        selected_evaluator_rotation_key_schedule(usize::from(FOUNDATION_PROFILE.option_count))
            .ok()?
            .into_iter()
            .map(|(_, level)| modulus_row_count_for_level(level))
            .collect::<Option<Vec<_>>>()?
            .into_boxed_slice();
    let shared_anchor_quotient_count = u64::try_from(SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len())
        .ok()?
        .checked_mul(u64::try_from(SETUP_COMMITMENT_MODULE_RANK.checked_add(1)?).ok()?)?;
    let relinearization_round_one_quotient_count = relinearization_modulus_row_count
        .checked_mul(2)?
        .checked_add(shared_anchor_quotient_count)?;
    let relinearization_round_two_quotient_count = relinearization_modulus_row_count
        .checked_mul(3)?
        .checked_add(shared_anchor_quotient_count)?;
    let galois_key_share_quotient_count = ordered_galois_modulus_row_counts
        .iter()
        .try_fold(shared_anchor_quotient_count, |count, row_count| {
            count.checked_add(*row_count)
        })?;

    Some(EvaluatorKeyQuotientTopology {
        relinearization_modulus_row_count,
        ordered_galois_modulus_row_counts,
        shared_anchor_quotient_count,
        relinearization_round_one_quotient_count,
        relinearization_round_two_quotient_count,
        galois_key_share_quotient_count,
    })
}

#[test]
fn selected_topology_independently_rederives_evaluator_key_quotient_counts() {
    assert_eq!(modulus_row_count_for_level(0), Some(4));
    assert_eq!(modulus_row_count_for_level(2), Some(6));
    assert_eq!(modulus_row_count_for_level(3), Some(14));
    assert_eq!(modulus_row_count_for_level(DATA_PRIMES.len()), None);

    assert_eq!(
        derive_selected_evaluator_key_quotient_topology(),
        Some(EvaluatorKeyQuotientTopology {
            relinearization_modulus_row_count: 208,
            ordered_galois_modulus_row_counts: vec![90, 90, 90, 154, 154, 154].into_boxed_slice(),
            shared_anchor_quotient_count: 6,
            relinearization_round_one_quotient_count: 422,
            relinearization_round_two_quotient_count: 630,
            galois_key_share_quotient_count: 738,
        })
    );
}
