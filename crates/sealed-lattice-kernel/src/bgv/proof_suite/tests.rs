use crate::bgv::{
    proof_suite::{
        BoundedProofDecoder, COMMON_PROOF_PROFILE, ProofDecodeError, ProofFamily,
        build_relation_plan_catalog, generate_proof_suite_candidate,
    },
    setup::ProofByteSource,
};
use crate::foundation::{CanonicalDecodeLimits, FOUNDATION_PROFILE, SuiteRecord};

use super::{
    deterministic_artifacts::SuiteArtifactSemanticBlocker,
    suite::{SuiteGenerationError, generate_incomplete_development_proof_suite_candidate},
};
use super::{
    field::{
        GOLDILOCKS_MAXIMUM_TWO_ADIC_GENERATOR, GOLDILOCKS_MODULUS, Goldilocks, GoldilocksQuintic,
        maximum_two_adic_generator_has_exact_order, quintic_polynomial_is_irreducible,
    },
    profile::security_accounting,
    relation_plan::{
        ProofPrivacyMode, ProofTreeRole, RelationColumnSource, RelationPlanValidationError,
        RelationPlanVariantSelector,
    },
    suite::{CommonProofAcceptanceBlocker, require_common_proof_acceptance},
    transcript::{
        CanonicalProofTranscript, CanonicalTranscriptEngine, DistinctQuerySamplingError,
        TranscriptError, sample_distinct_query_positions_from_values,
        sample_distinct_query_positions_with_blocks,
    },
};

#[test]
fn goldilocks_and_quintic_arithmetic_are_canonical() {
    let maximum = Goldilocks::from_canonical_u64(GOLDILOCKS_MODULUS - 1).expect("p-1 is canonical");
    assert_eq!(maximum.add(Goldilocks::ONE), Goldilocks::ZERO);
    assert_eq!(maximum.negate(), Goldilocks::ONE);
    assert_eq!(Goldilocks::TWO.subtract(Goldilocks::THREE), maximum);
    assert!(Goldilocks::from_canonical_u64(GOLDILOCKS_MODULUS).is_none());
    assert!(Goldilocks::decode_canonical(GOLDILOCKS_MODULUS.to_le_bytes()).is_none());
    for value in [1_u64, 2, 3, 7, 65_537, GOLDILOCKS_MODULUS - 1] {
        let element = Goldilocks::from_canonical_u64(value).expect("test value is canonical");
        assert_eq!(
            element.multiply(element.inverse().expect("nonzero element has inverse")),
            Goldilocks::ONE
        );
        assert_eq!(
            Goldilocks::decode_canonical(element.canonical_bytes()),
            Some(element)
        );
    }
    assert!(Goldilocks::ZERO.inverse().is_none());

    let indeterminate = GoldilocksQuintic::from_coefficients([
        Goldilocks::ZERO,
        Goldilocks::ONE,
        Goldilocks::ZERO,
        Goldilocks::ZERO,
        Goldilocks::ZERO,
    ]);
    let mut fifth_power = GoldilocksQuintic::ONE;
    for _ in 0..5 {
        fifth_power = fifth_power.multiply(indeterminate);
    }
    assert_eq!(
        fifth_power,
        GoldilocksQuintic::from_coefficients([
            Goldilocks::THREE,
            Goldilocks::ZERO,
            Goldilocks::ZERO,
            Goldilocks::ZERO,
            Goldilocks::ZERO,
        ])
    );
    let element = GoldilocksQuintic::from_coefficients([
        Goldilocks::TWO,
        Goldilocks::ONE,
        Goldilocks::THREE,
        Goldilocks::from_canonical_u64(5).expect("five"),
        Goldilocks::from_canonical_u64(8).expect("eight"),
    ]);
    assert_eq!(
        element.multiply(
            element
                .inverse()
                .expect("nonzero extension element has inverse")
        ),
        GoldilocksQuintic::ONE
    );
    assert_eq!(
        GoldilocksQuintic::decode_canonical(element.canonical_bytes()),
        Some(element)
    );
    assert!(GoldilocksQuintic::ZERO.inverse().is_none());
    assert!(quintic_polynomial_is_irreducible());
    assert!(maximum_two_adic_generator_has_exact_order());
    assert_eq!(
        Goldilocks::from_canonical_u64(GOLDILOCKS_MAXIMUM_TWO_ADIC_GENERATOR)
            .expect("stored generator")
            .pow_u64(1_u64 << 32),
        Goldilocks::ONE
    );
}

#[test]
fn transcript_and_distinct_query_sampler_are_deterministic_and_bounded() {
    let suite_id = [0x41_u8; 64];
    let mut first = CanonicalProofTranscript::new(1, suite_id, 0x2110, b"header");
    let mut second = CanonicalProofTranscript::new(1, suite_id, 0x2110, b"header");
    first
        .absorb_engine_round(
            CanonicalTranscriptEngine::TrusteeEvaluationKey,
            "witness-tree-root",
            b"root",
        )
        .expect("enumerated round tag");
    second
        .absorb_engine_round(
            CanonicalTranscriptEngine::TrusteeEvaluationKey,
            "witness-tree-root",
            b"root",
        )
        .expect("enumerated round tag");
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
        sample(&first).expect("query sample"),
        sample(&second).expect("query sample")
    );
    assert_eq!(
        first.absorb_engine_round(
            CanonicalTranscriptEngine::TrusteeEvaluationKey,
            "unknown-root",
            b"wrong tag",
        ),
        Err(TranscriptError::InvalidTag)
    );

    let sampled = sample_distinct_query_positions_from_values(&[9, 9, 1, 1, 7, 3], 16, 4, 3)
        .expect("duplicates are retried");
    assert_eq!(sampled, vec![1, 3, 7, 9]);
    assert_eq!(
        sample_distinct_query_positions_from_values(&[4, 4, 4], 8, 2, 2),
        Err(DistinctQuerySamplingError::CandidateDrawsExhausted { output_index: 1 })
    );
    assert_eq!(
        sample_distinct_query_positions_from_values(&[1], 0, 1, 1),
        Err(DistinctQuerySamplingError::InvalidQueryDomain)
    );
    assert_eq!(
        sample_distinct_query_positions_from_values(&[1], 1, 2, 1),
        Err(DistinctQuerySamplingError::QueryCountExceedsDomain)
    );
}

struct FragmentedProofBytes {
    chunks: Vec<Vec<u8>>,
    byte_length: usize,
}

impl FragmentedProofBytes {
    fn new(bytes: &[u8], chunk_lengths: &[usize]) -> Self {
        let mut chunks = Vec::new();
        let mut offset = 0_usize;
        for chunk_length in chunk_lengths {
            let end = (offset + chunk_length).min(bytes.len());
            chunks.push(bytes[offset..end].to_vec());
            offset = end;
        }
        if offset < bytes.len() {
            chunks.push(bytes[offset..].to_vec());
        }
        Self {
            chunks,
            byte_length: bytes.len(),
        }
    }
}

impl ProofByteSource for FragmentedProofBytes {
    fn byte_length(&self) -> usize {
        self.byte_length
    }

    fn copy_bytes(&self, offset: usize, destination: &mut [u8]) -> bool {
        let Some(end) = offset.checked_add(destination.len()) else {
            return false;
        };
        if end > self.byte_length {
            return false;
        }
        let mut source_start = 0_usize;
        let mut destination_start = 0_usize;
        for chunk in &self.chunks {
            let source_end = source_start + chunk.len();
            if source_end > offset && source_start < end {
                let copy_start = offset.max(source_start);
                let copy_end = end.min(source_end);
                let copy_length = copy_end - copy_start;
                destination[destination_start..destination_start + copy_length]
                    .copy_from_slice(&chunk[copy_start - source_start..copy_end - source_start]);
                destination_start += copy_length;
            }
            source_start = source_end;
        }
        destination_start == destination.len()
    }
}

#[test]
fn bounded_decoder_crosses_every_fragment_and_rejects_hostile_lengths() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"SLPROOF1");
    bytes.extend_from_slice(&23_u64.to_le_bytes());
    bytes.extend_from_slice(&[0x5a; 73]);
    for split in 1..bytes.len() {
        let source = FragmentedProofBytes::new(&bytes, &[split, 1, 2, 3]);
        let mut decoder =
            BoundedProofDecoder::new(&source, bytes.len(), bytes.len()).expect("bounded source");
        assert_eq!(decoder.read_array::<8>().expect("magic"), *b"SLPROOF1");
        assert_eq!(decoder.read_u64().expect("u64"), 23);
        assert_eq!(decoder.read_bytes(73).expect("payload"), [0x5a; 73]);
        decoder.finish().expect("no trailing bytes");
    }

    let trailing = FragmentedProofBytes::new(&[1, 2], &[1]);
    let mut decoder = BoundedProofDecoder::new(&trailing, 2, 2).expect("bounded source");
    let mut first_byte = [0_u8; 1];
    decoder.read_exact(&mut first_byte).expect("first byte");
    assert_eq!(decoder.finish(), Err(ProofDecodeError::TrailingBytes));
    assert_eq!(
        BoundedProofDecoder::new(&trailing, 2, 1).map(|_| ()),
        Err(ProofDecodeError::ProofByteCeilingExceeded)
    );
}

#[test]
fn profile_and_security_bounds_are_exact_integer_gates() {
    assert!(COMMON_PROOF_PROFILE.rbr_conditions_hold());
    COMMON_PROOF_PROFILE
        .validate(1 << 15, 1 << 19)
        .expect("selected profile domain");
    let accounting = security_accounting(483, 1 << 19, 900_000, 20);
    assert!(accounting.query_term_dominates_field_term);
    assert!(accounting.weighted_rbr_below_two_to_minus_176);
    assert!(accounting.cms_database_game_below_one_quarter_after_multiplicity);
    assert!(accounting.cms_compiled_bound_below_one_quarter_after_multiplicity);
    assert_eq!(accounting.cms_programmable_points, 900_041);
}

#[test]
fn relation_plan_catalog_is_complete_and_public_plans_are_maskless() {
    let catalog = build_relation_plan_catalog(1, 16).expect("first profile catalog");
    assert_eq!(catalog.plans.len(), 12);
    assert_eq!(
        catalog
            .plan(ProofFamily::EvaluatorKeyAggregate)
            .expect("aggregate plan")
            .variants
            .len(),
        20
    );
    assert_eq!(
        catalog
            .plan(ProofFamily::GaloisKeyShare)
            .expect("Galois plan")
            .variants
            .len(),
        16
    );
    for plan in &catalog.plans {
        for variant in &plan.variants {
            if plan.family.privacy_mode() == ProofPrivacyMode::PublicOnly {
                assert!(variant.ordered_masks.is_empty());
                assert!(
                    !variant
                        .ordered_columns
                        .iter()
                        .any(|column| { column.source == RelationColumnSource::Prover })
                );
                assert!(!variant.ordered_trees.iter().any(|tree| {
                    tree.role == ProofTreeRole::Witness
                        || tree.role == ProofTreeRole::OpeningBatchMask
                        || tree.secret_bearing
                        || tree.salted_leaves
                }));
            } else {
                assert!(!variant.ordered_masks.is_empty());
                assert!(
                    variant
                        .ordered_columns
                        .iter()
                        .any(|column| { column.source == RelationColumnSource::Prover })
                );
            }
            assert!(variant.proof_grammar_metrics.proof_byte_ceiling <= 5_242_880);
        }
    }
    let mut changed = catalog.clone();
    changed
        .plan(ProofFamily::CollectivePublicKey)
        .expect("public plan");
    changed.plans[2].variants[0]
        .ordered_masks
        .push(super::relation_plan::RelationMaskDescriptor {
            purpose: 1,
            degree_bound_exclusive: 1,
        });
    assert_eq!(
        changed.validate(1, 16),
        Err(RelationPlanValidationError::PrivacyModeMismatch)
    );
    assert!(build_relation_plan_catalog(0, 16).is_err());
    assert!(build_relation_plan_catalog(1, 0).is_err());
    assert_eq!(
        catalog.plans[3].variants[0].selector,
        RelationPlanVariantSelector::SchedulePosition(0)
    );
}

#[test]
fn relation_plan_mask_purposes_are_globally_allocated_and_variant_bound() {
    let catalog = build_relation_plan_catalog(20, 64).expect("expanded relation-plan catalog");
    let ordered_purposes = catalog
        .plans
        .iter()
        .flat_map(|plan| &plan.variants)
        .flat_map(|variant| &variant.ordered_masks)
        .map(|mask| mask.purpose)
        .collect::<Vec<_>>();
    assert_eq!(
        ordered_purposes,
        (1..=u16::try_from(ordered_purposes.len()).expect("purpose count fits u16"))
            .collect::<Vec<_>>()
    );
    assert!(ordered_purposes.iter().all(|purpose| *purpose < 0xff00));

    let relinearization_plan = catalog
        .plan(ProofFamily::RelinearizationRoundTwo)
        .expect("relinearization plan");
    let first_variant = &relinearization_plan.variants[0];
    let second_variant = &relinearization_plan.variants[1];
    for mask in &first_variant.ordered_masks {
        catalog
            .validate_mask_purpose(
                ProofFamily::RelinearizationRoundTwo,
                RelationPlanVariantSelector::SchedulePosition(0),
                mask.purpose,
            )
            .expect("selected variant accepts its assigned purpose");
    }
    assert_eq!(
        catalog.validate_mask_purpose(
            ProofFamily::RelinearizationRoundTwo,
            RelationPlanVariantSelector::SchedulePosition(0),
            second_variant.ordered_masks[0].purpose,
        ),
        Err(RelationPlanValidationError::InvalidMaskCatalog)
    );
    assert_eq!(
        catalog.validate_mask_purpose(
            ProofFamily::CollectivePublicKey,
            RelationPlanVariantSelector::Unscheduled,
            1,
        ),
        Err(RelationPlanValidationError::InvalidMaskCatalog)
    );

    let mut duplicated = catalog.clone();
    duplicated.plans[3].variants[1].ordered_masks[0].purpose =
        duplicated.plans[3].variants[0].ordered_masks[0].purpose;
    assert_eq!(
        duplicated.validate(20, 64),
        Err(RelationPlanValidationError::InvalidMaskCatalog)
    );
}

#[test]
fn deterministic_suite_reproduces_all_family_slots_and_artifacts() {
    assert_eq!(
        generate_proof_suite_candidate(FOUNDATION_PROFILE.participant_count),
        Err(SuiteGenerationError::SemanticIncompleteness(vec![
            SuiteArtifactSemanticBlocker::ProofRelationProgramsNotLowered,
            SuiteArtifactSemanticBlocker::PersistentMaterialMaskImageEvidenceMissing,
            SuiteArtifactSemanticBlocker::LatticeCommitmentConcreteSecurityEvidenceMissing,
            SuiteArtifactSemanticBlocker::EvaluatorProgramNotMaterialized,
            SuiteArtifactSemanticBlocker::EvaluatorCorrectnessAndErrorEvidenceMissing,
            SuiteArtifactSemanticBlocker::TargetDecryptionTheoremEvidenceMissing,
        ]))
    );

    let first =
        generate_incomplete_development_proof_suite_candidate(FOUNDATION_PROFILE.participant_count)
            .expect("development transcript-domain candidate");
    let second =
        generate_incomplete_development_proof_suite_candidate(FOUNDATION_PROFILE.participant_count)
            .expect("deterministic development regeneration");
    assert_eq!(first.suite_id, second.suite_id);
    assert_eq!(
        first.canonical_suite_record_bytes,
        second.canonical_suite_record_bytes
    );
    assert_eq!(first.artifacts, second.artifacts);
    assert_eq!(first.suite_record.artifacts, second.suite_record.artifacts);
    assert_eq!(first.action_schedules.len(), 20);
    assert_eq!(first.ordered_galois_elements.len(), 16);
    assert!(first.action_schedules.iter().all(|schedule| {
        schedule.relinearization_positions == [0]
            && schedule.galois_positions == (0_u32..16).collect::<Vec<_>>()
    }));
    assert_eq!(first.suite_record.maximum_candidate_packages_per_action, 10);
    assert_eq!(first.suite_record.maximum_proof_objects_per_action, 243);
    assert_eq!(first.artifacts.len(), 6);
    assert_eq!(
        first
            .suite_record
            .artifacts
            .iter()
            .map(|reference| reference.artifact_kind.canonical_code())
            .collect::<Vec<_>>(),
        [1, 2, 3, 4, 5, 6]
    );
    assert_eq!(
        SuiteRecord::decode(
            &first.canonical_suite_record_bytes,
            &CanonicalDecodeLimits::default(),
        )
        .expect("canonical suite record decodes"),
        first.suite_record
    );
    for artifact in &first.artifacts {
        artifact
            .reference
            .verify_canonical_artifact(&artifact.canonical_bytes)
            .expect("generated artifact matches its reference");
        let mut changed_bytes = artifact.canonical_bytes.clone();
        let changed_byte = changed_bytes
            .last_mut()
            .expect("suite artifacts are nonempty");
        *changed_byte ^= 1;
        assert!(
            artifact
                .reference
                .verify_canonical_artifact(&changed_bytes)
                .is_err()
        );
    }
    assert!(first.security_accounting.query_term_dominates_field_term);
    assert!(
        first
            .security_accounting
            .weighted_rbr_below_two_to_minus_176
    );
    assert!(
        first
            .security_accounting
            .cms_compiled_bound_below_one_quarter_after_multiplicity
    );
    assert!(generate_proof_suite_candidate(2).is_err());
    assert!(generate_proof_suite_candidate(20).is_err());

    let acceptance_error = require_common_proof_acceptance(&first)
        .expect_err("an arithmetic candidate cannot authorize proof acceptance");
    assert_eq!(
        acceptance_error.blockers,
        vec![
            CommonProofAcceptanceBlocker::CanonicalRelationProgramsNotLowered,
            CommonProofAcceptanceBlocker::CommonWitnessExtractionTheoremMissing,
            CommonProofAcceptanceBlocker::ApplicationToProximityReductionMissing,
            CommonProofAcceptanceBlocker::CompleteIntegerRelationCertificatesMissing,
            CommonProofAcceptanceBlocker::ConstructionSpecificZeroKnowledgeSimulatorMissing,
            CommonProofAcceptanceBlocker::AdaptiveSharedOracleQromReductionMissing,
            CommonProofAcceptanceBlocker::CompleteResourceFixedPointMissing,
            CommonProofAcceptanceBlocker::LegacyProofFamiliesNotMigrated,
            CommonProofAcceptanceBlocker::ScalarWasmBrowserResourceSpikeMissing,
        ]
    );
}
