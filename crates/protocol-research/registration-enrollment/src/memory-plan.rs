//! The linear-memory plan of an operation's instances, which together stay
//! within the absolute bound. Each helper keeps the state its jobs share,
//! the rows of the proof shards it holds or, when the operation evaluates
//! the ranking program, the larger of those and the evaluation's kept
//! memory, since one worker's jobs either evaluate or prove, beside one
//! job's memory. The worker keeps what its helpers leave. Each instance
//! lowers its bound to its share before its first allocation, so an
//! operation that needs more ends pending rather than growing beyond it.
use evaluation_target::MAXIMUM_LINEAR_MEMORY_BYTES;
use parallel_work::{JOB_MEMORY_BYTES, MAXIMUM_HELPERS};

const PAGE_BYTES: usize = 65_536;

/// The bound of each of an operation's helpers, or none beyond the most
/// helpers an operation starts.
pub fn helper_memory_bytes(helpers: usize, evaluation: bool) -> Option<usize> {
    if helpers == 0 || helpers > MAXIMUM_HELPERS {
        return None;
    }
    let rows = registration_proof::rows::helper_rows_bytes(helpers);
    let kept = if evaluation {
        rns_arithmetic_probe::ranking::helper_memory_bytes(helpers)
    } else {
        0
    };
    Some((rows.max(kept) + JOB_MEMORY_BYTES).next_multiple_of(PAGE_BYTES))
}
/// The bound of an operation's worker beside its helpers: what they leave
/// of the absolute bound.
pub fn worker_memory_bytes(helpers: usize, evaluation: bool) -> Option<usize> {
    if helpers == 0 {
        return Some(MAXIMUM_LINEAR_MEMORY_BYTES);
    }
    MAXIMUM_LINEAR_MEMORY_BYTES.checked_sub(helpers * helper_memory_bytes(helpers, evaluation)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use supported_profile::Profile;

    // Every helper count's bounds are whole pages, and the helpers and the
    // worker together take no more than the absolute bound; no plan exists
    // for more helpers than an operation starts.
    #[test]
    fn instances_together_stay_within_the_absolute_bound() {
        for evaluation in [false, true] {
            assert_eq!(
                worker_memory_bytes(0, evaluation),
                Some(MAXIMUM_LINEAR_MEMORY_BYTES)
            );
            assert_eq!(helper_memory_bytes(0, evaluation), None);
            for helpers in 1..=MAXIMUM_HELPERS {
                let helper = helper_memory_bytes(helpers, evaluation).unwrap();
                let worker = worker_memory_bytes(helpers, evaluation).unwrap();
                assert!(helper.is_multiple_of(PAGE_BYTES) && worker.is_multiple_of(PAGE_BYTES));
                assert_eq!(helpers * helper + worker, MAXIMUM_LINEAR_MEMORY_BYTES);
            }
            assert_eq!(helper_memory_bytes(MAXIMUM_HELPERS + 1, evaluation), None);
            assert_eq!(worker_memory_bytes(MAXIMUM_HELPERS + 1, evaluation), None);
        }
    }

    // An evaluating operation's helpers hold what the evaluation keeps
    // there beside one job, and its worker's share leaves every kind of
    // instruction of each representative profile room for its two inputs
    // and its output.
    #[test]
    fn an_evaluating_worker_keeps_room_for_every_instruction() {
        for helpers in 1..=MAXIMUM_HELPERS {
            let helper = helper_memory_bytes(helpers, true).unwrap();
            assert!(
                helper
                    >= rns_arithmetic_probe::ranking::helper_memory_bytes(helpers)
                        + JOB_MEMORY_BYTES
            );
            let worker = worker_memory_bytes(helpers, true).unwrap();
            for (participants, options) in [(3, 2), (3, 20), (10, 10), (20, 2), (20, 20)] {
                let profile = Profile::new(participants, options).unwrap();
                assert!(
                    rns_arithmetic_probe::ranking::fewest_resident_values(profile, helpers, worker)
                        .unwrap()
                        >= 3
                );
            }
        }
    }
}
