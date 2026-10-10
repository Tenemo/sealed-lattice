use super::*;
use parallel_work::MAXIMUM_JOB_BYTES;

// Every common polynomial's records fit one job output. The job, which
// reconstructs the profile from its input, returns the direct records,
// which decode to the common polynomial, and refuses other polynomials.
#[test]
fn common_records_jobs_match_the_direct_records() {
    let profiles: Vec<Profile> = Profile::all().collect();
    for profile in &profiles {
        for index in 0..profile.setup_polynomials() {
            if let Ok((_, degree, modulus, _)) = common_source(*profile, index) {
                assert!(degree * (1 + modulus.len()) <= MAXIMUM_JOB_BYTES);
            }
        }
    }
    let widest = profiles
        .iter()
        .max_by_key(|profile| profile.family_magnitude_bytes(Family::Fhe))
        .unwrap();
    for profile in [profiles[0], *widest] {
        let last = profile.gadget_length() - 1;
        for index in [
            profile.fhe_polynomial(0, 0),
            profile.fhe_polynomial(last, 3),
            profile.fhe_polynomial(last, 5),
            profile.share_common_polynomial(),
        ] {
            let records = common_records(profile, index).unwrap();
            assert_eq!(*common_records_job(profile, index).unwrap().wait(), records);
            let values = common_polynomial(profile, index).unwrap();
            let width = records.len() / values.len();
            for (record, value) in records.chunks_exact(width).zip(values) {
                let sign = if record[0] == 1 {
                    Sign::Minus
                } else {
                    Sign::Plus
                };
                assert_eq!(BigInt::from_bytes_le(sign, &record[1..]), value);
            }
        }
        for index in [
            profile.fhe_polynomial(0, 1),
            profile.recipient_key_polynomial(0),
        ] {
            assert!(common_records_job(profile, index).is_err());
        }
    }
}
