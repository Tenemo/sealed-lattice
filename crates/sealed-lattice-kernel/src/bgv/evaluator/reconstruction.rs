use crate::{
    bgv::evaluator::engine::{Ciphertext, ciphertext_add, scalar_mul},
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
};

// One selected direct aggregate contributor: the centered Lagrange
// interpolation coefficient and the contributor's encrypted share ciphertext.
pub(crate) struct AggregateContributor {
    pub(crate) interpolation_coefficient: i64,
    pub(crate) encrypted_share: Ciphertext,
}

// Homomorphic Lagrange-weighted reconstruction of the direct encrypted
// aggregate from the selected contributors: C_aggregate = sum_r lambda_r * C_r.
// The centered coefficients are bounded by the aggregate-interpolation
// coefficient certificate; scalar multiplication keeps the scaling factor, so
// the weighted shares add directly.
pub(crate) fn reconstruct_aggregate(
    contributors: &[AggregateContributor],
) -> CanonicalResult<Ciphertext> {
    let (first, rest) = contributors.split_first().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "aggregate reconstruction requires at least one selected contributor",
        )
    })?;
    let mut accumulator = scalar_mul(&first.encrypted_share, first.interpolation_coefficient)?;
    for contributor in rest {
        let weighted = scalar_mul(
            &contributor.encrypted_share,
            contributor.interpolation_coefficient,
        )?;
        accumulator = ciphertext_add(&accumulator, &weighted)?;
    }

    Ok(accumulator)
}

// Reconstruct the direct encrypted score from the encrypted histogram
// buckets: Enc(Score[a]) = sum_{s=1}^{bucket_count} s * Enc(H[a, s]). The bucket
// at index s-1 holds the count of voters who assigned score s.
pub(crate) fn score_from_histogram(buckets: &[Ciphertext]) -> CanonicalResult<Ciphertext> {
    let (first, rest) = buckets.split_first().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "score reconstruction requires at least one histogram bucket",
        )
    })?;
    let mut accumulator = scalar_mul(first, 1)?;
    for (offset, bucket) in rest.iter().enumerate() {
        let score_weight = i64::try_from(offset + 2).expect("score weight fits i64");
        accumulator = ciphertext_add(&accumulator, &scalar_mul(bucket, score_weight)?)?;
    }

    Ok(accumulator)
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use super::{AggregateContributor, reconstruct_aggregate, score_from_histogram};
    use crate::bgv::evaluator::engine::DevelopmentBgvKey;

    fn shared_key() -> &'static DevelopmentBgvKey {
        static KEY: OnceLock<DevelopmentBgvKey> = OnceLock::new();
        KEY.get_or_init(|| {
            DevelopmentBgvKey::generate("reconstruction-seed-v1").expect("development key")
        })
    }

    #[test]
    fn lagrange_weighted_reconstruction_sums_contributor_shares() {
        let key = shared_key();
        // Two contributors with shares [4, 1, 0] and [3, 6, 5], coefficients 2
        // and -1: aggregate slot a = 2*share0[a] - share1[a].
        let contributors = vec![
            AggregateContributor {
                interpolation_coefficient: 2,
                encrypted_share: key.encrypt_slots(&[4, 1, 0], "share-0").expect("share 0"),
            },
            AggregateContributor {
                interpolation_coefficient: -1,
                encrypted_share: key.encrypt_slots(&[3, 6, 5], "share-1").expect("share 1"),
            },
        ];
        let aggregate = reconstruct_aggregate(&contributors).expect("reconstruct");
        // 2*4-3=5, 2*1-6=-4 -> 65533, 2*0-5=-5 -> 65532
        assert_eq!(
            &key.decrypt_to_slots(&aggregate).expect("decrypt")[..3],
            &[5, 65_533, 65_532]
        );
    }

    #[test]
    fn score_reconstruction_weights_histogram_buckets_by_score() {
        let key = shared_key();
        // Histogram for one option across two slots: bucket s has counts in slot
        // 0 and slot 1. Score = sum_s s * H[s].
        let buckets = [
            key.encrypt_slots(&[2, 0], "bucket-1").expect("bucket 1"),
            key.encrypt_slots(&[1, 0], "bucket-2").expect("bucket 2"),
            key.encrypt_slots(&[0, 3], "bucket-3").expect("bucket 3"),
        ];
        let score = score_from_histogram(&buckets).expect("score");
        // slot 0: 1*2 + 2*1 + 3*0 = 4; slot 1: 1*0 + 2*0 + 3*3 = 9
        assert_eq!(
            &key.decrypt_to_slots(&score).expect("decrypt")[..2],
            &[4, 9]
        );
    }
}
