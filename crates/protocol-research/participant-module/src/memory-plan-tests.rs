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
            helper >= encrypted_ranking::ranking::helper_memory_bytes(helpers) + JOB_MEMORY_BYTES
        );
        let worker = worker_memory_bytes(helpers, true).unwrap();
        for (participants, options) in [(3, 2), (3, 20), (10, 10), (20, 2), (20, 20)] {
            let profile = Profile::new(participants, options).unwrap();
            assert!(
                encrypted_ranking::ranking::fewest_resident_values(profile, helpers, worker)
                    .unwrap()
                    >= 3
            );
        }
    }
}
