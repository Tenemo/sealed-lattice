use super::HELPER_JOBS;

// Every job kind a helper runs names one job, so a helper runs the job its
// submitter named.
#[test]
fn every_helper_job_kind_names_one_job() {
    let mut kinds: Vec<u32> = HELPER_JOBS
        .iter()
        .flat_map(|jobs| jobs.iter().map(|job| job.kind))
        .collect();
    let count = kinds.len();
    kinds.sort_unstable();
    kinds.dedup();
    assert_eq!(kinds.len(), count);
}
