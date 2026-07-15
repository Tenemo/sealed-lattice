use super::{
    merkle::{leaf_hash, node_hash},
    transcript::{
        CanonicalProofTranscript, CanonicalTranscriptEngine, DistinctQuerySamplingError,
        TranscriptError, sample_distinct_query_positions_from_values,
        sample_distinct_query_positions_with_blocks,
    },
};

#[test]
fn transcript_and_distinct_query_sampler_are_deterministic_and_bounded() {
    let suite_identifier = [0x41_u8; 64];
    let mut first = CanonicalProofTranscript::new(1, suite_identifier, 0x2110, b"header");
    let mut second = CanonicalProofTranscript::new(1, suite_identifier, 0x2110, b"header");
    for transcript in [&mut first, &mut second] {
        transcript
            .absorb_engine_round(
                CanonicalTranscriptEngine::TrusteeEvaluationKey,
                "witness-tree-root",
                b"root",
            )
            .expect("enumerated round tag");
    }
    let sample = |transcript: &CanonicalProofTranscript| {
        sample_distinct_query_positions_with_blocks(1 << 16, 168, 64, |output, counter| {
            transcript
                .squeeze_engine_challenge(
                    CanonicalTranscriptEngine::TrusteeEvaluationKey,
                    &format!("shared-query-position/{output:08x}"),
                    counter,
                )
                .ok()
        })
    };
    assert_eq!(
        sample(&first).expect("first query sample"),
        sample(&second).expect("second query sample"),
    );
    assert_eq!(
        first.absorb_engine_round(
            CanonicalTranscriptEngine::TrusteeEvaluationKey,
            "unknown-root",
            b"wrong tag",
        ),
        Err(TranscriptError::InvalidTag),
    );

    assert_eq!(
        sample_distinct_query_positions_from_values(&[9, 9, 1, 1, 7, 3], 16, 4, 3)
            .expect("duplicates are retried"),
        [1, 3, 7, 9],
    );
    assert_eq!(
        sample_distinct_query_positions_from_values(&[4, 4, 4], 8, 2, 2),
        Err(DistinctQuerySamplingError::CandidateDrawsExhausted { output_index: 1 }),
    );
    assert_eq!(
        sample_distinct_query_positions_from_values(&[1], 0, 1, 1),
        Err(DistinctQuerySamplingError::InvalidQueryDomain),
    );
    assert_eq!(
        sample_distinct_query_positions_from_values(&[1], 1, 2, 1),
        Err(DistinctQuerySamplingError::QueryCountExceedsDomain),
    );
}

#[test]
fn merkle_hashes_bind_their_tree_coordinates_and_node_order() {
    let leaf = leaf_hash(0x1212, 3, 7, b"row");
    assert_ne!(leaf, leaf_hash(0x1211, 3, 7, b"row"));
    assert_ne!(leaf, leaf_hash(0x1212, 4, 7, b"row"));
    assert_ne!(leaf, leaf_hash(0x1212, 3, 8, b"row"));
    assert_ne!(leaf, leaf_hash(0x1212, 3, 7, b"changed row"));

    let sibling = leaf_hash(0x1212, 3, 8, b"sibling");
    let parent = node_hash(0x1212, 3, 1, 3, leaf, sibling);
    assert_ne!(parent, node_hash(0x1212, 3, 1, 3, sibling, leaf));
    assert_ne!(parent, node_hash(0x1212, 3, 2, 3, leaf, sibling));
    assert_ne!(parent, node_hash(0x1212, 3, 1, 4, leaf, sibling));
}
