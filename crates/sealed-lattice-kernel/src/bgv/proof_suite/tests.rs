use super::{
    PROOF_BASE_FIELD_MODULUS, ProofChallengeExtensionElement,
    merkle::{leaf_hash, node_hash},
    transcript::{
        CommonProofApplicationChallengeGroup, CommonProofChallenge, CommonProofPrivacyMode,
        CommonProofTranscript, CommonProofTranscriptSchedule, DistinctQuerySamplingError,
        TranscriptError, sample_distinct_query_positions_from_values,
        sample_distinct_query_positions_with_blocks,
    },
};

fn transcript_extension_value(value: u64) -> ProofChallengeExtensionElement {
    ProofChallengeExtensionElement::from_canonical_coordinates([value, 0, 0, 0, 0])
        .expect("small transcript test value is canonical")
}

fn common_proof_schedule(privacy_mode: CommonProofPrivacyMode) -> CommonProofTranscriptSchedule {
    CommonProofTranscriptSchedule::new(
        vec![0, 2],
        vec![
            CommonProofApplicationChallengeGroup::new(
                CommonProofChallenge::Theta { modulus_ordinal: 0 },
                PROOF_BASE_FIELD_MODULUS,
                2,
            )
            .expect("theta descriptor is valid"),
            CommonProofApplicationChallengeGroup::new(
                CommonProofChallenge::Alpha { modulus_ordinal: 0 },
                65_537,
                3,
            )
            .expect("alpha descriptor is valid"),
        ],
        vec![1],
        2,
        2,
        2,
        3,
        2,
        8,
        4,
        32,
        128,
        privacy_mode,
    )
    .expect("common-proof schedule is valid")
}

#[test]
fn common_proof_transcript_enforces_the_exact_round_chain() {
    let mut transcript = CommonProofTranscript::new(
        1,
        [0x31; 64],
        0x1216,
        b"header",
        common_proof_schedule(CommonProofPrivacyMode::SecretBearing),
    )
    .expect("transcript schedule is valid");

    assert_eq!(
        transcript.absorb_auxiliary_root(1, [0x10; 64]),
        Err(TranscriptError::UnexpectedCommonProofRound),
    );
    transcript
        .absorb_base_root(0, [0x01; 64])
        .expect("first base root is in order");
    assert_eq!(
        transcript.absorb_base_root(0, [0x01; 64]),
        Err(TranscriptError::UnexpectedCommonProofRound),
    );
    transcript
        .absorb_base_root(2, [0x02; 64])
        .expect("second base root is in order");
    let theta = transcript
        .sample_application_challenge_group(CommonProofChallenge::Theta { modulus_ordinal: 0 })
        .expect("theta derives");
    let alpha = transcript
        .sample_application_challenge_group(CommonProofChallenge::Alpha { modulus_ordinal: 0 })
        .expect("alpha derives");
    assert_eq!(theta.len(), 2);
    assert_eq!(alpha.len(), 3);
    assert!(theta.iter().all(|value| *value < PROOF_BASE_FIELD_MODULUS));
    assert!(theta.iter().any(|value| *value >= 65_537));
    assert!(alpha.iter().all(|value| *value < 65_537));
    transcript
        .absorb_auxiliary_root(1, [0x03; 64])
        .expect("auxiliary root follows application challenges");
    for constraint_ordinal in 0..2 {
        transcript
            .sample_composition_challenge(constraint_ordinal)
            .expect("composition challenge derives");
    }
    for component_ordinal in 0..2 {
        transcript
            .absorb_quotient_root(component_ordinal, [component_ordinal as u8; 64])
            .expect("quotient root is ordered");
    }
    for point_ordinal in 0..2 {
        transcript
            .sample_out_of_domain_point(point_ordinal, |_| false)
            .expect("distinct nonzero out-of-domain point derives");
    }
    transcript
        .absorb_out_of_domain_evaluations(&[
            transcript_extension_value(1),
            transcript_extension_value(2),
            transcript_extension_value(3),
        ])
        .expect("out-of-domain values follow points");
    transcript
        .absorb_opening_batch_mask_root([0x09; 64])
        .expect("secret mode requires the opening mask root");
    for claim_ordinal in 0..3 {
        transcript
            .sample_opening_batch_challenge(claim_ordinal)
            .expect("opening coefficient derives");
    }
    transcript
        .sample_fri_fold_challenge(0)
        .expect("first fold challenge derives");
    transcript
        .absorb_fri_layer_root(0, [0x0a; 64])
        .expect("nonterminal fold root is absorbed");
    transcript
        .sample_fri_fold_challenge(1)
        .expect("terminal fold challenge derives");
    transcript
        .absorb_fri_terminal_coefficients(
            &(10_u64..18)
                .map(transcript_extension_value)
                .collect::<Vec<_>>(),
        )
        .expect("terminal follows the last fold");
    let representatives = transcript
        .sample_query_representatives()
        .expect("the query vector derives in one verifier message");
    assert_eq!(
        representatives
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        4,
    );
    let sorted = transcript
        .sorted_query_representatives()
        .expect("all representatives have been sampled");
    assert!(sorted.windows(2).all(|pair| pair[0] < pair[1]));
    let canonical_query_openings = b"canonical-openings-and-frontiers";
    let mut streamed_transcript = transcript.clone();
    transcript
        .absorb_query_openings(canonical_query_openings)
        .expect("query openings terminate the transcript");

    let mut streaming_absorber = streamed_transcript
        .begin_query_openings(canonical_query_openings.len())
        .expect("the exact query-opening length initializes streaming absorption");
    for fragment in canonical_query_openings.chunks(3) {
        streaming_absorber
            .absorb(fragment)
            .expect("each fragment stays within the declared round length");
    }
    streamed_transcript
        .finish_query_openings(streaming_absorber)
        .expect("the complete streamed query-opening round terminates");
    assert_eq!(
        streamed_transcript.transcript_state_for_test(),
        transcript.transcript_state_for_test(),
    );
    transcript.finish().expect("all rounds were consumed");
    streamed_transcript
        .finish()
        .expect("the streamed transcript consumed the same rounds");
}

#[test]
fn public_common_proof_transcript_rejects_a_secret_mode_round() {
    let mut transcript = CommonProofTranscript::new(
        1,
        [0x41; 64],
        0x1213,
        b"header",
        common_proof_schedule(CommonProofPrivacyMode::PublicOnly),
    )
    .expect("transcript schedule is valid");
    transcript.absorb_base_root(0, [1; 64]).expect("root zero");
    transcript.absorb_base_root(2, [2; 64]).expect("root two");
    transcript
        .sample_application_challenge_group(CommonProofChallenge::Theta { modulus_ordinal: 0 })
        .expect("theta");
    transcript
        .sample_application_challenge_group(CommonProofChallenge::Alpha { modulus_ordinal: 0 })
        .expect("alpha");
    transcript
        .absorb_auxiliary_root(1, [3; 64])
        .expect("auxiliary root");
    for constraint_ordinal in 0..2 {
        transcript
            .sample_composition_challenge(constraint_ordinal)
            .expect("composition");
    }
    transcript
        .absorb_quotient_root(0, [4; 64])
        .expect("quotient zero");
    transcript
        .absorb_quotient_root(1, [5; 64])
        .expect("quotient one");
    transcript
        .sample_out_of_domain_point(0, |_| false)
        .expect("out-of-domain zero");
    transcript
        .sample_out_of_domain_point(1, |_| false)
        .expect("out-of-domain one");
    transcript
        .absorb_out_of_domain_values(b"canonical-out-of-domain-values")
        .expect("out-of-domain values");
    assert_eq!(
        transcript.absorb_opening_batch_mask_root([9; 64]),
        Err(TranscriptError::UnexpectedCommonProofRound),
    );
}

#[test]
fn distinct_query_sampler_is_deterministic_and_bounded() {
    let sample = || {
        sample_distinct_query_positions_with_blocks(1 << 16, 387, 64, |output, counter| {
            let mut block = [0_u8; 64];
            let candidate = u16::try_from(output)
                .expect("the selected query count fits u16")
                .wrapping_add(u16::try_from(counter).expect("the selected draw ceiling fits u16"));
            block[..2].copy_from_slice(&candidate.to_le_bytes());
            Some(block)
        })
    };
    assert_eq!(
        sample().expect("deterministic query sample"),
        (0..387).collect::<Vec<_>>(),
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
