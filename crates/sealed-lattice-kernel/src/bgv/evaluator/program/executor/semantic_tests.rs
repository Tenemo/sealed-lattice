//! Guarded encrypted semantic evidence for the selected evaluator program.

use std::collections::{BTreeMap, BTreeSet};

use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{Signed, ToPrimitive, Zero};

use crate::bgv::{
    direct_ballots::pair_character_plaintexts,
    encoding::{
        decode_plaintext_coefficients_to_extension_lanes,
        encode_extension_lanes_to_plaintext_coefficients,
    },
    evaluator::{
        engine::{
            Ciphertext, DevelopmentBgvKey, ExactDecryptionErrorObserver,
            add_plaintext_coefficients, ciphertext_add, ciphertext_tensor, modulus_switch,
            modulus_switch_to, negacyclic_mul, normalize_scaling, plaintext_mul,
        },
        key_switch::{
            KeySwitchKey, generate_galois_key, generate_relinearization_key, relinearize, rotate,
            special_basis_modulus_residue,
        },
        noise_recurrence::{
            SelectedEvaluatorStreamNoiseTrace, SymbolicCiphertextBound,
            direct_ballot_evaluator_noise_traces,
        },
        pair_character_product::{
            PairCharacterProductMerge, canonical_pair_character_product_schedule,
        },
        semantic_oracle::{
            self, ORACLE_CIPHERTEXT_COUNT, ORACLE_EXTENSION_DEGREE, ORACLE_LANE_COUNT,
            ORACLE_OPTION_COUNT, OracleRingValue,
        },
        top_k::{
            CHARACTER_OUTPUT_LEVEL, SELECTED_RELINEARIZATION_KEY_LEVEL,
            selected_evaluator_rotation_key_schedule,
        },
    },
    key_switch_topology::{KeySwitchDecompositionTopology, canonical_residue_byte_length},
    modular_arithmetic::{add_mod_fast, inverse_mod, mul_mod_fast, sub_mod_fast},
    parameters::{DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE},
    proof_suite::{
        ComponentMaterialOwnershipBinding, SelectedEvaluatorEntryKind,
        SelectedEvaluatorEntryPosition, VerifiedEvaluatorKeyStore,
        VerifiedEvaluatorKeyStoreMaterial, selected_evaluator_entry_positions,
    },
    setup::{VerifiedAcceptedSetupAuthorityHandle, sample_galois_common_reference_limb},
    target_decryption::kllps_release::{
        KLLPS_DENOMINATOR_CLEARING_FACTOR, KLLPS_PARTICIPANT_COUNT, KLLPS_POINT_STRIDE,
        KLLPS_RECONSTRUCTION_THRESHOLD, KLLPS_SUBRING_DEGREE, KllpsParticipantReleaseBinding,
        KllpsReleaseBinding, VerifiedKllpsPairedShare,
        authorized_lagrange_coefficient_at_zero_for_tests,
        generate_verified_factor_four_paired_share_for_tests,
        kllps_target_pair_from_verified_evaluator_execution_for_tests,
        reconstruct_factor_four_target_scalar_lanes_for_tests, selected_factor_four_flooding_bound,
    },
};

use crate::foundation::{FOUNDATION_PROFILE, Hash512, selected_suite_capability_for_tests};

use super::super::{
    EvaluatorCompilerStage, EvaluatorCompilerStreamStageRegisters, EvaluatorInstruction,
    EvaluatorOpcode, EvaluatorProgramSet, selected_evaluator_program_set_with_stage_registers,
};
use super::{
    SelectedEvaluatorExecutionProgress, SelectedEvaluatorProgramExecution,
    VerifiedEvaluatorAggregate, VerifiedEvaluatorAggregateContext,
    VerifiedEvaluatorAggregationAuthority, encode_constant_coefficients, zeroize_ciphertext,
};

const DEVELOPMENT_KEY_SEED: &str = "selected-encrypted-evaluator-semantic-development-key";
const PRODUCTION_EXECUTION_CEREMONY_CONTEXT_HASH: [u8; 64] = [0x21; 64];
const PRODUCTION_EXECUTION_ACTION_CONTEXT_HASH: [u8; 64] = [0x32; 64];
const PRODUCTION_EXECUTION_MANIFEST_HASH: [u8; 64] = [0x43; 64];
const PRODUCTION_EXECUTION_ROSTER_HASH: [u8; 64] = [0x54; 64];
const PRODUCTION_EXECUTION_SETUP_PROOF_CONTEXT_HASH: [u8; 64] = [0x65; 64];
const PRODUCTION_EXECUTION_VERIFIED_SETUP_SOURCE_HASH: [u8; 64] = [0x76; 64];
const PRODUCTION_EXECUTION_AGGREGATE_SOURCE_HASH: [u8; 64] = [0x87; 64];
const PRODUCTION_EXECUTION_APPLICATION_CONTEXT_HASH: [u8; 64] = [0x98; 64];
const PRODUCTION_EXECUTION_TOP_COUNT: usize = 4;

struct EncryptedSemanticCase {
    name: String,
    aggregate_scores: Vec<u64>,
    ballot_count: usize,
    top_counts: Vec<usize>,
    calibrate_product_error: bool,
    calibrate_evaluator_error: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EvaluatorErrorObservationMode {
    None,
    Complete,
    TopCountTail,
}

struct EncryptedEvaluatorExecution<'a> {
    aggregate_ciphertexts: [Ciphertext; ORACLE_CIPHERTEXT_COUNT],
    expected_inputs: [OracleRingValue; ORACLE_CIPHERTEXT_COUNT],
    aggregate_scores: &'a [u64],
    ballot_count: usize,
    top_count: usize,
    case_name: &'a str,
    error_observation_mode: EvaluatorErrorObservationMode,
}

struct TestConstant {
    coefficients: Vec<u64>,
    lanes: OracleRingValue,
}

struct EncryptedEvaluatorHarness {
    development_key: DevelopmentBgvKey,
    error_observer: ExactDecryptionErrorObserver,
    relinearization_key: KeySwitchKey,
    galois_keys: BTreeMap<usize, KeySwitchKey>,
    program: EvaluatorProgramSet,
    stage_registers: Vec<EvaluatorCompilerStreamStageRegisters>,
    noise_traces_by_ballot_count: BTreeMap<usize, Vec<SelectedEvaluatorStreamNoiseTrace>>,
    constants: BTreeMap<[u8; 64], TestConstant>,
}

#[derive(Clone, Copy)]
struct ExactErrorObservationContext<'a> {
    categories: &'a [&'static str],
    stages: &'a [EvaluatorCompilerStage],
    case_name: &'a str,
}

impl<'a> ExactErrorObservationContext<'a> {
    const fn new(
        categories: &'a [&'static str],
        stages: &'a [EvaluatorCompilerStage],
        case_name: &'a str,
    ) -> Self {
        Self {
            categories,
            stages,
            case_name,
        }
    }
}

struct ExactErrorLedger {
    expected_observation_counts: BTreeMap<&'static str, usize>,
    observation_counts: BTreeMap<&'static str, usize>,
    maximum_norms: BTreeMap<&'static str, BigUint>,
    observed_stages: BTreeSet<EvaluatorCompilerStage>,
    observed_ballot_counts: BTreeSet<usize>,
}

impl ExactErrorLedger {
    fn new(expected_observation_counts: BTreeMap<&'static str, usize>) -> Self {
        assert!(
            expected_observation_counts
                .values()
                .all(|expected_count| *expected_count > 0),
            "every exact-error observation category must have a positive expected count"
        );
        Self {
            expected_observation_counts,
            observation_counts: BTreeMap::new(),
            maximum_norms: BTreeMap::new(),
            observed_stages: BTreeSet::new(),
            observed_ballot_counts: BTreeSet::new(),
        }
    }

    fn observe(
        &mut self,
        observer: &ExactDecryptionErrorObserver,
        ciphertext: &Ciphertext,
        expected_lanes: &OracleRingValue,
        context: ExactErrorObservationContext<'_>,
    ) {
        self.observe_internal(observer, ciphertext, expected_lanes, context, None);
    }

    fn observe_with_symbolic_bound(
        &mut self,
        observer: &ExactDecryptionErrorObserver,
        ciphertext: &Ciphertext,
        expected_lanes: &OracleRingValue,
        context: ExactErrorObservationContext<'_>,
        symbolic_bound: &SymbolicCiphertextBound,
    ) {
        self.observe_internal(
            observer,
            ciphertext,
            expected_lanes,
            context,
            Some(symbolic_bound),
        );
    }

    fn observe_internal(
        &mut self,
        observer: &ExactDecryptionErrorObserver,
        ciphertext: &Ciphertext,
        expected_lanes: &OracleRingValue,
        context: ExactErrorObservationContext<'_>,
        symbolic_bound: Option<&SymbolicCiphertextBound>,
    ) {
        let ExactErrorObservationContext {
            categories,
            stages,
            case_name,
        } = context;
        let expected_coefficients =
            encode_extension_lanes_to_plaintext_coefficients(expected_lanes)
                .expect("expected encrypted semantic lanes encode");
        let infinity_norm = observer
            .measure_infinity_norm(ciphertext, &expected_coefficients)
            .unwrap_or_else(|error| {
                panic!(
                    "exact encrypted error observation failed for {case_name} at level {} for categories {categories:?} and stages {stages:?}: {error}",
                    ciphertext.level,
                )
            });
        if let Some(symbolic_bound) = symbolic_bound {
            assert_exact_observation_fits_symbolic_bound(
                ciphertext,
                &expected_coefficients,
                &infinity_norm,
                symbolic_bound,
                case_name,
            );
        }
        for category in categories.iter().copied() {
            let expected_count = *self
                .expected_observation_counts
                .get(&category)
                .unwrap_or_else(|| {
                    panic!("unexpected exact-error observation category {category}")
                });
            let observed_count = self.observation_counts.entry(category).or_default();
            *observed_count += 1;
            assert!(
                *observed_count <= expected_count,
                "exact-error observation category {category} exceeded its expected count {expected_count}"
            );
            self.maximum_norms
                .entry(category)
                .and_modify(|maximum| *maximum = maximum.clone().max(infinity_norm.clone()))
                .or_insert_with(|| infinity_norm.clone());
        }
        self.observed_stages.extend(stages.iter().copied());
    }

    fn assert_complete(&self, expected_stages: &BTreeSet<EvaluatorCompilerStage>) {
        assert_eq!(
            &self.observation_counts, &self.expected_observation_counts,
            "the exact encrypted error ledger did not observe every scheduled operation count"
        );
        assert_eq!(
            self.maximum_norms.keys().copied().collect::<BTreeSet<_>>(),
            self.expected_observation_counts
                .keys()
                .copied()
                .collect::<BTreeSet<_>>()
        );
        assert_eq!(
            self.observed_ballot_counts,
            (1..=10).collect::<BTreeSet<_>>()
        );
        assert_eq!(&self.observed_stages, expected_stages);
    }
}

fn assert_exact_observation_fits_symbolic_bound(
    ciphertext: &Ciphertext,
    expected_coefficients: &[u64],
    exact_error_infinity_norm: &BigUint,
    symbolic_bound: &SymbolicCiphertextBound,
    case_name: &str,
) {
    assert_eq!(
        ciphertext.level, symbolic_bound.level,
        "symbolic level drifted for {case_name}",
    );
    assert_eq!(
        ciphertext.decrypt_scaling, symbolic_bound.decrypt_scaling,
        "symbolic decryption multiplier drifted for {case_name}",
    );
    assert_eq!(
        ciphertext.component_count(),
        symbolic_bound.component_count,
        "symbolic component count drifted for {case_name}",
    );
    assert_eq!(
        symbolic_bound.collective_secret_coefficient_bound, 10,
        "symbolic collective-secret bound drifted for {case_name}",
    );
    assert!(
        symbolic_bound.minimum_decryption_margin.is_positive(),
        "symbolic path reached a non-positive decryption margin for {case_name}",
    );

    let exact_message_infinity_norm = expected_coefficients
        .iter()
        .copied()
        .map(|coefficient| coefficient.min(PLAINTEXT_MODULUS - coefficient))
        .max()
        .map(BigUint::from)
        .unwrap_or_default();
    assert!(
        exact_message_infinity_norm <= symbolic_bound.message_coefficient_bound,
        "full-ring message exceeded its symbolic bound for {case_name}: exact={exact_message_infinity_norm}, symbolic={}",
        symbolic_bound.message_coefficient_bound,
    );
    assert!(
        exact_error_infinity_norm <= &symbolic_bound.error_coefficient_bound,
        "full-ring error exceeded its symbolic bound for {case_name}: exact={exact_error_infinity_norm}, symbolic={}",
        symbolic_bound.error_coefficient_bound,
    );

    let active_modulus = DATA_PRIMES[..=ciphertext.level]
        .iter()
        .copied()
        .map(BigUint::from)
        .product::<BigUint>();
    let doubled_exact_raw_bound = BigUint::from(2_u8)
        * (&exact_message_infinity_norm
            + BigUint::from(PLAINTEXT_MODULUS) * exact_error_infinity_norm);
    assert!(
        doubled_exact_raw_bound < active_modulus,
        "full-ring observation exhausted its exact no-wrap margin for {case_name}",
    );
    let current_symbolic_margin = BigInt::from(active_modulus)
        - BigInt::from(
            BigUint::from(2_u8)
                * (&symbolic_bound.message_coefficient_bound
                    + BigUint::from(PLAINTEXT_MODULUS) * &symbolic_bound.error_coefficient_bound),
        );
    assert!(
        current_symbolic_margin >= symbolic_bound.minimum_decryption_margin,
        "symbolic minimum margin omitted an earlier evaluator state for {case_name}",
    );
}

#[test]
#[ignore = "guarded selected-suite encrypted evaluator semantic and exact-error evidence"]
fn encrypted_evaluator_matches_direct_stable_top_k_across_covering_matrix() {
    let harness = EncryptedEvaluatorHarness::new();
    let cases = encrypted_semantic_cases();
    let mut exact_error_ledger =
        ExactErrorLedger::new(harness.expected_exact_error_observation_counts());
    let expected_stages = harness
        .stage_registers
        .iter()
        .flat_map(|stream| stream.stage_registers().iter().map(|entry| entry.stage()))
        .collect::<BTreeSet<_>>();

    assert_active_lane_boundaries_across_both_ciphertexts();
    for case in cases {
        assert_eq!(case.aggregate_scores.len(), ORACLE_OPTION_COUNT);
        assert!((1..=10).contains(&case.ballot_count));
        assert!(
            case.aggregate_scores
                .iter()
                .all(|score| *score <= u64::try_from(9 * case.ballot_count).unwrap()),
            "{} cannot be decomposed into its selected ballot count",
            case.name
        );
        let expected_inputs = semantic_oracle::aggregate_character_inputs(&case.aggregate_scores);
        let aggregate_ciphertexts = if case.calibrate_product_error {
            let calibrated_products = harness.build_pair_character_products(
                &case.aggregate_scores,
                case.ballot_count,
                &case.name,
                true,
                &mut exact_error_ledger,
            );
            assert!(
                exact_error_ledger
                    .observed_ballot_counts
                    .insert(case.ballot_count),
                "ballot count {} has more than one product calibration case",
                case.ballot_count
            );
            calibrated_products
        } else {
            harness.encrypt_aggregate_character_inputs(&expected_inputs, &case.name)
        };

        for top_count in case.top_counts {
            let error_observation_mode = if case.calibrate_evaluator_error && top_count == 1 {
                EvaluatorErrorObservationMode::Complete
            } else if case.calibrate_evaluator_error {
                EvaluatorErrorObservationMode::TopCountTail
            } else {
                EvaluatorErrorObservationMode::None
            };
            harness.execute_and_assert_case(
                EncryptedEvaluatorExecution {
                    aggregate_ciphertexts: aggregate_ciphertexts.clone(),
                    expected_inputs: expected_inputs.clone(),
                    aggregate_scores: &case.aggregate_scores,
                    ballot_count: case.ballot_count,
                    top_count,
                    case_name: &case.name,
                    error_observation_mode,
                },
                &mut exact_error_ledger,
            );
        }
    }
    exact_error_ledger.assert_complete(&expected_stages);
}

#[test]
#[ignore = "guarded production authenticated-store evaluator and threshold-release evidence"]
fn production_evaluator_execution_releases_four_threshold_shares() {
    let harness = EncryptedEvaluatorHarness::new_for_authenticated_store_execution();
    let aggregate_scores: [u64; ORACLE_OPTION_COUNT] = [90, 90, 89, 74, 74, 63, 51, 51, 1, 0];
    let expected_inputs = semantic_oracle::aggregate_character_inputs(&aggregate_scores);
    let aggregate_ciphertexts = harness.encrypt_aggregate_character_inputs(
        &expected_inputs,
        "production-authenticated-store-release",
    );
    let [expected_identifier_values, expected_order_values] =
        independent_stable_target_values(&aggregate_scores, PRODUCTION_EXECUTION_TOP_COUNT);
    let expected_identifier_coefficients = encode_extension_lanes_to_plaintext_coefficients(
        &scalar_values_as_extension_lanes(&expected_identifier_values),
    )
    .expect("expected identifier target encodes");
    let expected_order_coefficients = encode_extension_lanes_to_plaintext_coefficients(
        &scalar_values_as_extension_lanes(&expected_order_values),
    )
    .expect("expected order target encodes");

    let selected_suite = selected_suite_capability_for_tests();
    let ordered_store_components = complete_production_replay_store_components(
        harness.development_key.secret(),
        &harness.relinearization_key,
    );
    let ownership_binding = ComponentMaterialOwnershipBinding::from_verified_application(
        selected_suite.suite_identifier(),
        PRODUCTION_EXECUTION_ACTION_CONTEXT_HASH,
        PRODUCTION_EXECUTION_APPLICATION_CONTEXT_HASH,
    );
    let (store_material, store_bytes) =
        VerifiedEvaluatorKeyStoreMaterial::from_test_authenticated_complete_physical_material(
            ownership_binding,
            ordered_store_components,
        )
        .expect("complete production evaluator store authenticates");
    let verified_store = VerifiedEvaluatorKeyStore::from_test_authenticated_replay_material(
        FOUNDATION_PROFILE.protocol_version,
        selected_suite.suite_identifier(),
        PRODUCTION_EXECUTION_CEREMONY_CONTEXT_HASH,
        PRODUCTION_EXECUTION_ACTION_CONTEXT_HASH,
        PRODUCTION_EXECUTION_MANIFEST_HASH,
        PRODUCTION_EXECUTION_ROSTER_HASH,
        PRODUCTION_EXECUTION_SETUP_PROOF_CONTEXT_HASH,
        store_material,
    )
    .expect("complete authenticated evaluator store retains replay authority");
    let accepted_setup =
        VerifiedAcceptedSetupAuthorityHandle::retain_test_minted_with_evaluator_store(
            verified_store,
            PRODUCTION_EXECUTION_VERIFIED_SETUP_SOURCE_HASH,
        )
        .expect("test accepted setup retains the complete authenticated evaluator store");
    let aggregation_authority =
        VerifiedEvaluatorAggregationAuthority::take_from_accepted_setup(&accepted_setup, |setup| {
            setup.exact_verified_setup_source_hash()
                == PRODUCTION_EXECUTION_VERIFIED_SETUP_SOURCE_HASH
        })
        .expect("accepted setup transfers its sole evaluator-store authority");
    let aggregate = VerifiedEvaluatorAggregate::from_verified_ballot_aggregate(
        VerifiedEvaluatorAggregateContext::from_verified_sources(
            FOUNDATION_PROFILE.protocol_version,
            selected_suite.suite_identifier(),
            PRODUCTION_EXECUTION_CEREMONY_CONTEXT_HASH,
            PRODUCTION_EXECUTION_ACTION_CONTEXT_HASH,
            PRODUCTION_EXECUTION_ROSTER_HASH,
            PRODUCTION_EXECUTION_VERIFIED_SETUP_SOURCE_HASH,
            PRODUCTION_EXECUTION_AGGREGATE_SOURCE_HASH,
        ),
        FOUNDATION_PROFILE.participant_count,
        u16::try_from(PRODUCTION_EXECUTION_TOP_COUNT).expect("selected top count fits u16"),
        aggregate_ciphertexts,
    )
    .expect("verified aggregate binds the two production evaluator inputs");
    let mut execution = SelectedEvaluatorProgramExecution::begin(
        aggregation_authority
            .bind_aggregate(aggregate)
            .expect("aggregate and authenticated evaluator store share one context"),
    )
    .expect("production evaluator execution begins");
    while let SelectedEvaluatorExecutionProgress::StoreReadRequired(request) = execution
        .advance()
        .expect("production evaluator polling advances")
    {
        let start = usize::try_from(request.store_byte_offset())
            .expect("requested store offset fits usize");
        let end = start
            .checked_add(request.byte_length())
            .expect("requested store range fits usize");
        execution
            .absorb_next_store_chunk(
                request.store_byte_offset(),
                store_bytes
                    .get(start..end)
                    .expect("poll requests an authenticated in-store range"),
            )
            .expect("exact authenticated evaluator-store range is accepted");
    }
    let verified_execution = execution
        .finish()
        .expect("production evaluator completes from actual polled store reads");
    drop(store_bytes);
    assert_eq!(
        verified_execution.target_identifier.level,
        crate::bgv::evaluator::top_k::CANONICAL_TARGET_CIPHERTEXT_LEVEL,
    );
    let exact_identifier_error = harness
        .error_observer
        .measure_infinity_norm(
            &verified_execution.target_identifier,
            &expected_identifier_coefficients,
        )
        .expect("independent full-ring observer measures identifier target error");
    let exact_order_error = harness
        .error_observer
        .measure_infinity_norm(
            &verified_execution.target_order,
            &expected_order_coefficients,
        )
        .expect("independent full-ring observer measures order target error");
    let symbolic_bounds = harness
        .noise_traces_by_ballot_count
        .get(&usize::from(FOUNDATION_PROFILE.participant_count))
        .and_then(|traces| traces.get(PRODUCTION_EXECUTION_TOP_COUNT - 1))
        .expect("selected target has a symbolic evaluator trace");
    let identifier_error_bound = &symbolic_bounds
        .register_bound(selected_target_register(
            &harness.program,
            PRODUCTION_EXECUTION_TOP_COUNT,
            1,
        ))
        .expect("identifier target has a symbolic bound")
        .error_coefficient_bound;
    let order_error_bound = &symbolic_bounds
        .register_bound(selected_target_register(
            &harness.program,
            PRODUCTION_EXECUTION_TOP_COUNT,
            2,
        ))
        .expect("order target has a symbolic bound")
        .error_coefficient_bound;
    assert!(&exact_identifier_error <= identifier_error_bound);
    assert!(&exact_order_error <= order_error_bound);

    let target_identifier = verified_execution.target_identifier.clone();
    let target_order = verified_execution.target_order.clone();
    drop(verified_execution);
    let release_binding = production_execution_release_binding();
    let reconstruction_target_pair = kllps_target_pair_from_verified_evaluator_execution_for_tests(
        release_binding.clone(),
        production_execution_participant_binding(0),
        target_identifier.clone(),
        target_order.clone(),
    )
    .expect("actual evaluator targets enter the release arithmetic");
    let flooding_bound = selected_factor_four_flooding_bound()
        .expect("selected evaluator recurrence derives the release flooding support");
    let threshold_sharing_polynomials =
        deterministic_threshold_sharing_polynomials(harness.development_key.secret());
    let mut verified_shares = Vec::with_capacity(KLLPS_PARTICIPANT_COUNT);
    for roster_position in 0..KLLPS_PARTICIPANT_COUNT {
        let target_pair = kllps_target_pair_from_verified_evaluator_execution_for_tests(
            release_binding.clone(),
            production_execution_participant_binding(roster_position),
            target_identifier.clone(),
            target_order.clone(),
        )
        .expect("participant target pair retains the common evaluator output");
        let threshold_share = deterministic_threshold_share(
            &threshold_sharing_polynomials,
            roster_position,
            target_identifier.level,
        );
        let role_flooding_errors = [
            hostile_centered_release_flooding_error(roster_position, 0, &flooding_bound),
            hostile_centered_release_flooding_error(roster_position, 1, &flooding_bound),
        ];
        let verified_share = generate_verified_factor_four_paired_share_for_tests(
            &target_pair,
            roster_position,
            &threshold_share,
            &role_flooding_errors[0],
            &role_flooding_errors[1],
            &flooding_bound,
        )
        .expect("independently generated paired share passes the production arithmetic boundary");
        assert_partial_share_matches_independent_full_ring_oracle(
            [&target_identifier, &target_order],
            &threshold_share,
            &role_flooding_errors,
            &verified_share,
        );
        verified_shares.push(verified_share);
    }

    let relay_order = [7, 4, 0, 3, 1].map(|roster_position| &verified_shares[roster_position]);
    let reordered_relay = [1, 3, 0, 4, 7].map(|roster_position| &verified_shares[roster_position]);
    let alternate_quartet = [2, 5, 6, 9].map(|roster_position| &verified_shares[roster_position]);
    let decoded = reconstruct_factor_four_target_scalar_lanes_for_tests(
        &reconstruction_target_pair,
        &relay_order,
    )
    .expect("lowest four distinct shares reconstruct both actual evaluator targets");
    assert_eq!(
        reconstruct_factor_four_target_scalar_lanes_for_tests(
            &reconstruction_target_pair,
            &reordered_relay,
        )
        .expect("relay order does not alter deterministic share selection"),
        decoded,
    );
    assert_eq!(
        reconstruct_factor_four_target_scalar_lanes_for_tests(
            &reconstruction_target_pair,
            &alternate_quartet,
        )
        .expect("an alternate authorized quartet reconstructs the same targets"),
        decoded,
    );
    assert_scalar_release_result(&decoded.0, &expected_identifier_values, "identifier");
    assert_scalar_release_result(&decoded.1, &expected_order_values, "order");

    let independently_decoded = independent_full_ring_release_reconstruction(
        [&target_identifier, &target_order],
        &[0, 1, 3, 4],
        &[
            &verified_shares[0],
            &verified_shares[1],
            &verified_shares[3],
            &verified_shares[4],
        ],
    );
    assert_eq!(independently_decoded, decoded);

    accepted_setup
        .release_test_minted()
        .expect("consumed test accepted setup authority releases cleanly");
}

impl EncryptedEvaluatorHarness {
    fn new() -> Self {
        Self::new_with_manual_galois_keys(true)
    }

    fn new_for_authenticated_store_execution() -> Self {
        Self::new_with_manual_galois_keys(false)
    }

    fn new_with_manual_galois_keys(include_manual_galois_keys: bool) -> Self {
        let development_key = DevelopmentBgvKey::generate(DEVELOPMENT_KEY_SEED)
            .expect("selected development BGV key generates");
        let error_observer = development_key
            .exact_decryption_error_observer()
            .expect("selected exact decryption-error observer initializes");
        let relinearization_key = generate_relinearization_key(
            &development_key,
            SELECTED_RELINEARIZATION_KEY_LEVEL,
            "selected-encrypted-evaluator-semantic-relinearization-key",
        )
        .expect("selected relinearization key generates");
        let galois_keys = if include_manual_galois_keys {
            selected_evaluator_rotation_key_schedule(ORACLE_OPTION_COUNT)
                .expect("selected evaluator rotation catalog")
                .into_iter()
                .map(|(galois_element, catalog_level)| {
                    let seed = format!(
                        "selected-encrypted-evaluator-semantic-galois-{galois_element}-{catalog_level}"
                    );
                    let key = generate_galois_key(
                        &development_key,
                        galois_element,
                        catalog_level,
                        &seed,
                    )
                    .expect("selected Galois key generates");
                    (galois_element, key)
                })
                .collect()
        } else {
            BTreeMap::new()
        };
        let (program, stage_registers) = selected_evaluator_program_set_with_stage_registers()
            .expect("selected evaluator program and stage registers compile");
        assert_eq!(program.streams().len(), ORACLE_OPTION_COUNT);
        assert_eq!(stage_registers.len(), ORACLE_OPTION_COUNT);
        let noise_traces_by_ballot_count = (1..=10)
            .map(|ballot_count| {
                let traces = direct_ballot_evaluator_noise_traces(
                    10,
                    ballot_count,
                    ORACLE_OPTION_COUNT,
                    1,
                    10,
                )
                .expect("selected evaluator noise trace derives");
                assert_eq!(traces.len(), ORACLE_OPTION_COUNT);
                (ballot_count, traces)
            })
            .collect();
        assert_eq!(
            program
                .streams()
                .iter()
                .flat_map(|stream| stream.instructions())
                .filter(|instruction| {
                    instruction.opcode() == EvaluatorOpcode::NormalizeDecryptionMultiplier
                })
                .count(),
            0,
            "the selected evaluator emits no decryption-multiplier normalization opcode"
        );
        let constants = program
            .constants()
            .iter()
            .map(|constant| {
                let hash = *constant
                    .constant_hash()
                    .expect("selected evaluator constant hashes")
                    .as_bytes();
                let coefficients = encode_constant_coefficients(constant)
                    .expect("selected evaluator constant encodes");
                let lanes = decode_plaintext_coefficients_to_extension_lanes(&coefficients)
                    .expect("selected evaluator constant decodes into extension lanes");
                (
                    hash,
                    TestConstant {
                        coefficients,
                        lanes,
                    },
                )
            })
            .collect();
        Self {
            development_key,
            error_observer,
            relinearization_key,
            galois_keys,
            program,
            stage_registers,
            noise_traces_by_ballot_count,
            constants,
        }
    }

    fn expected_exact_error_observation_counts(&self) -> BTreeMap<&'static str, usize> {
        let mut expected_counts = BTreeMap::new();
        for ballot_count in 1..=10 {
            let schedule = canonical_pair_character_product_schedule(ballot_count)
                .expect("selected product calibration schedule");
            add_expected_observation_count(
                &mut expected_counts,
                "fresh character",
                2 * ballot_count,
            );
            add_expected_observation_count(
                &mut expected_counts,
                "product multiplication",
                2 * (ballot_count - 1),
            );
            add_expected_observation_count(
                &mut expected_counts,
                "product relinearization",
                2 * (ballot_count - 1),
            );
            add_expected_observation_count(
                &mut expected_counts,
                "product modulus switch",
                2 * schedule.accounting.modulus_drop_count(),
            );
            if schedule.normalization.requires_plaintext_multiplication() {
                add_expected_observation_count(&mut expected_counts, "product normalization", 2);
            }
        }

        let stream = &self.program.streams()[0];
        let mut register_levels = vec![Some(CHARACTER_OUTPUT_LEVEL), Some(CHARACTER_OUTPUT_LEVEL)];
        for instruction in stream.instructions() {
            let output_level = match instruction.opcode() {
                EvaluatorOpcode::DropRegister => {
                    let register_ordinal =
                        usize::try_from(instruction.input_registers()[0]).unwrap();
                    assert!(register_levels[register_ordinal].take().is_some());
                    None
                }
                EvaluatorOpcode::DeclareOutput => None,
                EvaluatorOpcode::ModulusSwitchToLevel => {
                    let source_level = expected_register_level(&register_levels, instruction, 0);
                    let target_level = usize::try_from(instruction.immediate0()).unwrap();
                    assert!(target_level < source_level);
                    add_expected_observation_count(
                        &mut expected_counts,
                        "evaluator modulus switch",
                        source_level - target_level,
                    );
                    Some(target_level)
                }
                EvaluatorOpcode::NormalizeDecryptionMultiplier => {
                    Some(expected_register_level(&register_levels, instruction, 0))
                }
                EvaluatorOpcode::CiphertextAdd => {
                    let level = expected_register_level(&register_levels, instruction, 0);
                    assert_eq!(
                        expected_register_level(&register_levels, instruction, 1),
                        level
                    );
                    Some(level)
                }
                EvaluatorOpcode::PlaintextAdd => {
                    Some(expected_register_level(&register_levels, instruction, 0))
                }
                EvaluatorOpcode::PlaintextMultiply => {
                    add_expected_observation_count(
                        &mut expected_counts,
                        "evaluator plaintext multiplication",
                        1,
                    );
                    Some(expected_register_level(&register_levels, instruction, 0))
                }
                EvaluatorOpcode::CiphertextMultiplyRelinearizeAndDrop
                | EvaluatorOpcode::CiphertextMultiplyAndRelinearize => {
                    let level = expected_register_level(&register_levels, instruction, 0);
                    assert_eq!(
                        expected_register_level(&register_levels, instruction, 1),
                        level
                    );
                    add_expected_observation_count(
                        &mut expected_counts,
                        "evaluator ciphertext multiplication",
                        1,
                    );
                    add_expected_observation_count(
                        &mut expected_counts,
                        "evaluator relinearization",
                        1,
                    );
                    if instruction.opcode() == EvaluatorOpcode::CiphertextMultiplyRelinearizeAndDrop
                    {
                        add_expected_observation_count(
                            &mut expected_counts,
                            "evaluator modulus switch",
                            1,
                        );
                        Some(level.checked_sub(1).expect("selected product level drops"))
                    } else {
                        Some(level)
                    }
                }
                EvaluatorOpcode::GaloisRotate => {
                    add_expected_observation_count(&mut expected_counts, "evaluator rotation", 1);
                    Some(expected_register_level(&register_levels, instruction, 0))
                }
            };
            if let Some(output_level) = output_level {
                assert_eq!(
                    usize::try_from(instruction.output_register().unwrap()).unwrap(),
                    register_levels.len()
                );
                register_levels.push(Some(output_level));
            }
        }

        let complete_stage_register_count = self.stage_registers[0]
            .stage_registers()
            .iter()
            .map(|entry| entry.register_ordinal())
            .collect::<BTreeSet<_>>()
            .len();
        add_expected_observation_count(
            &mut expected_counts,
            "compiler stage",
            complete_stage_register_count,
        );
        for stage_registers in &self.stage_registers[1..] {
            let tail_stage_register_count = stage_registers
                .stage_registers()
                .iter()
                .filter(|entry| {
                    should_observe_stage(EvaluatorErrorObservationMode::TopCountTail, entry.stage())
                })
                .map(|entry| entry.register_ordinal())
                .collect::<BTreeSet<_>>()
                .len();
            add_expected_observation_count(
                &mut expected_counts,
                "compiler stage",
                tail_stage_register_count,
            );
        }
        expected_counts
    }

    fn build_pair_character_products(
        &self,
        aggregate_scores: &[u64],
        ballot_count: usize,
        case_name: &str,
        calibrate_exact_error: bool,
        exact_error_ledger: &mut ExactErrorLedger,
    ) -> [Ciphertext; ORACLE_CIPHERTEXT_COUNT] {
        core::array::from_fn(|ciphertext_ordinal| {
            self.build_pair_character_product(
                aggregate_scores,
                ballot_count,
                ciphertext_ordinal,
                case_name,
                calibrate_exact_error,
                exact_error_ledger,
            )
        })
    }

    fn encrypt_aggregate_character_inputs(
        &self,
        expected_inputs: &[OracleRingValue; ORACLE_CIPHERTEXT_COUNT],
        case_name: &str,
    ) -> [Ciphertext; ORACLE_CIPHERTEXT_COUNT] {
        core::array::from_fn(|ciphertext_ordinal| {
            let coefficients = encode_extension_lanes_to_plaintext_coefficients(
                &expected_inputs[ciphertext_ordinal],
            )
            .expect("independent aggregate pair-character lanes encode");
            let fresh = self
                .development_key
                .encrypt_coefficients(
                    &coefficients,
                    &format!(
                        "encrypted-evaluator-semantic-aggregate-{case_name}-{ciphertext_ordinal}"
                    ),
                )
                .expect("independent aggregate pair-character input encrypts");
            modulus_switch_to(&fresh, CHARACTER_OUTPUT_LEVEL)
                .expect("independent aggregate pair-character input reaches evaluator level")
        })
    }

    fn build_pair_character_product(
        &self,
        aggregate_scores: &[u64],
        ballot_count: usize,
        ciphertext_ordinal: usize,
        case_name: &str,
        calibrate_exact_error: bool,
        exact_error_ledger: &mut ExactErrorLedger,
    ) -> Ciphertext {
        let schedule = canonical_pair_character_product_schedule(ballot_count)
            .expect("selected pair-character product schedule");
        let mut states = (0..schedule.nodes.len())
            .map(|_| None)
            .collect::<Vec<Option<EncryptedProductState>>>();
        let mut next_merge_ordinal = 0_usize;

        for ballot_ordinal in 0..ballot_count {
            let ballot_scores =
                ballot_scores_for_aggregate(aggregate_scores, ballot_count, ballot_ordinal);
            let plaintexts =
                pair_character_plaintexts(&ballot_scores, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE)
                    .expect("selected pair-character plaintexts encode");
            let plaintext_coefficients = plaintexts[ciphertext_ordinal]
                .message_coefficients()
                .to_vec();
            let expected_lanes =
                decode_plaintext_coefficients_to_extension_lanes(&plaintext_coefficients)
                    .expect("fresh pair-character plaintext decodes");
            let encryption_seed = format!(
                "encrypted-evaluator-semantic-{case_name}-{ballot_count}-{ciphertext_ordinal}-{ballot_ordinal}"
            );
            let ciphertext = self
                .development_key
                .encrypt_coefficients(&plaintext_coefficients, &encryption_seed)
                .expect("fresh pair-character ciphertext encrypts");
            if calibrate_exact_error {
                exact_error_ledger.observe(
                    &self.error_observer,
                    &ciphertext,
                    &expected_lanes,
                    ExactErrorObservationContext::new(&["fresh character"], &[], case_name),
                );
            }
            let leaf = schedule
                .nodes
                .iter()
                .find(|node| {
                    node.ballot_span.first_ballot_ordinal == ballot_ordinal
                        && node.ballot_span.ballot_count == 1
                })
                .expect("selected schedule contains each fresh leaf");
            assert!(
                states[leaf.node_ordinal]
                    .replace(EncryptedProductState {
                        ciphertext,
                        expected_lanes,
                    })
                    .is_none()
            );
            while schedule
                .merges
                .get(next_merge_ordinal)
                .is_some_and(|merge| {
                    states[merge.left_node_ordinal].is_some()
                        && states[merge.right_node_ordinal].is_some()
                })
            {
                self.execute_product_merge(
                    &schedule.merges[next_merge_ordinal],
                    &schedule,
                    &mut states,
                    exact_error_ledger,
                    case_name,
                    calibrate_exact_error,
                );
                next_merge_ordinal += 1;
            }
        }
        while next_merge_ordinal < schedule.merges.len() {
            self.execute_product_merge(
                &schedule.merges[next_merge_ordinal],
                &schedule,
                &mut states,
                exact_error_ledger,
                case_name,
                calibrate_exact_error,
            );
            next_merge_ordinal += 1;
        }

        let mut root = states[schedule.root_node_ordinal]
            .take()
            .expect("selected pair-character root exists");
        assert!(states.iter().all(Option::is_none));
        if schedule.normalization.requires_plaintext_multiplication() {
            let normalization_coefficients = schedule.normalization.plaintext_coefficients();
            let normalization_lanes =
                decode_plaintext_coefficients_to_extension_lanes(&normalization_coefficients)
                    .expect("selected product normalization decodes");
            root.expected_lanes =
                semantic_oracle::multiply(&root.expected_lanes, &normalization_lanes);
            root.ciphertext = plaintext_mul(&root.ciphertext, &normalization_coefficients)
                .expect("selected pair-character product normalizes");
            if calibrate_exact_error {
                exact_error_ledger.observe(
                    &self.error_observer,
                    &root.ciphertext,
                    &root.expected_lanes,
                    ExactErrorObservationContext::new(&["product normalization"], &[], case_name),
                );
            }
        }
        switch_product_state_to_level(
            &mut root,
            schedule.terminal_output_level,
            &self.error_observer,
            exact_error_ledger,
            case_name,
            calibrate_exact_error,
        );
        assert_eq!(root.ciphertext.level, CHARACTER_OUTPUT_LEVEL);
        let expected_coefficients =
            encode_extension_lanes_to_plaintext_coefficients(&root.expected_lanes)
                .expect("selected pair-character root lanes encode");
        let exact_error_infinity_norm = self
            .error_observer
            .measure_infinity_norm(&root.ciphertext, &expected_coefficients)
            .expect("selected pair-character root error is observed");
        let symbolic_bound = &self
            .noise_traces_by_ballot_count
            .get(&ballot_count)
            .expect("selected ballot count has a symbolic trace")[0]
            .pair_character_input_bounds()[ciphertext_ordinal];
        assert_exact_observation_fits_symbolic_bound(
            &root.ciphertext,
            &expected_coefficients,
            &exact_error_infinity_norm,
            symbolic_bound,
            case_name,
        );
        root.ciphertext
    }

    fn execute_and_assert_case(
        &self,
        execution: EncryptedEvaluatorExecution<'_>,
        exact_error_ledger: &mut ExactErrorLedger,
    ) {
        let EncryptedEvaluatorExecution {
            aggregate_ciphertexts,
            expected_inputs,
            aggregate_scores,
            ballot_count,
            top_count,
            case_name,
            error_observation_mode,
        } = execution;
        assert!((1..=10).contains(&ballot_count));
        assert!((1..=ORACLE_OPTION_COUNT).contains(&top_count));
        let stream = &self.program.streams()[top_count - 1];
        let stage_registers = &self.stage_registers[top_count - 1];
        let symbolic_trace = &self
            .noise_traces_by_ballot_count
            .get(&ballot_count)
            .expect("selected ballot count has a symbolic trace")[top_count - 1];
        assert_eq!(usize::from(stream.top_count()), top_count);
        assert_eq!(usize::from(stage_registers.top_count()), top_count);
        assert_eq!(usize::from(symbolic_trace.top_count()), top_count);
        let stages_by_register = stage_registers.stage_registers().iter().fold(
            BTreeMap::<u32, Vec<EvaluatorCompilerStage>>::new(),
            |mut stages, entry| {
                stages
                    .entry(entry.register_ordinal())
                    .or_default()
                    .push(entry.stage());
                stages
            },
        );
        let expected_observed_stage_registers = stages_by_register
            .iter()
            .filter(|(_, stages)| {
                stages
                    .iter()
                    .copied()
                    .any(|stage| should_observe_stage(error_observation_mode, stage))
            })
            .map(|(register_ordinal, _)| *register_ordinal)
            .collect::<BTreeSet<_>>();
        let mut encountered_stage_registers = BTreeSet::new();
        let mut ciphertext_registers = aggregate_ciphertexts
            .into_iter()
            .map(Some)
            .collect::<Vec<_>>();
        let mut expected_registers = expected_inputs.into_iter().map(Some).collect::<Vec<_>>();
        for register_ordinal in 0..ORACLE_CIPHERTEXT_COUNT {
            let register_ordinal_u32 = u32::try_from(register_ordinal).unwrap();
            let stages = stages_by_register
                .get(&register_ordinal_u32)
                .into_iter()
                .flatten()
                .copied()
                .filter(|stage| should_observe_stage(error_observation_mode, *stage))
                .collect::<Vec<_>>();
            if !stages.is_empty() {
                encountered_stage_registers.insert(register_ordinal_u32);
                exact_error_ledger.observe_with_symbolic_bound(
                    &self.error_observer,
                    ciphertext_registers[register_ordinal]
                        .as_ref()
                        .expect("selected input ciphertext is live"),
                    expected_registers[register_ordinal]
                        .as_ref()
                        .expect("selected input shadow is live"),
                    ExactErrorObservationContext::new(&["compiler stage"], &stages, case_name),
                    &symbolic_trace.pair_character_input_bounds()[register_ordinal],
                );
            }
        }

        let mut target_registers = [None, None];
        for instruction in stream.instructions() {
            match instruction.opcode() {
                EvaluatorOpcode::DropRegister => {
                    let register_ordinal = usize::try_from(instruction.input_registers()[0])
                        .expect("selected register ordinal fits usize");
                    let mut ciphertext = ciphertext_registers[register_ordinal]
                        .take()
                        .expect("selected dropped ciphertext register is live");
                    assert!(expected_registers[register_ordinal].take().is_some());
                    zeroize_ciphertext(&mut ciphertext);
                }
                EvaluatorOpcode::DeclareOutput => {
                    let register_ordinal = instruction.input_registers()[0];
                    let target_ordinal = usize::try_from(instruction.immediate0() - 1)
                        .expect("selected target ordinal fits usize");
                    assert!(
                        ciphertext_registers[usize::try_from(register_ordinal).unwrap()].is_some()
                    );
                    assert!(
                        target_registers[target_ordinal]
                            .replace(register_ordinal)
                            .is_none()
                    );
                }
                opcode => {
                    let expected_output =
                        self.expected_instruction_output(instruction, &expected_registers);
                    let (ciphertext_output, operation_categories) = self.execute_test_instruction(
                        instruction,
                        &ciphertext_registers,
                        &expected_output,
                        case_name,
                        error_observation_mode == EvaluatorErrorObservationMode::Complete,
                        exact_error_ledger,
                    );
                    let output_register = usize::try_from(
                        instruction
                            .output_register()
                            .expect("selected evaluator operation produces a register"),
                    )
                    .expect("selected output register fits usize");
                    assert_eq!(output_register, ciphertext_registers.len());
                    assert_eq!(output_register, expected_registers.len());
                    let output_register_u32 = u32::try_from(output_register).unwrap();
                    let stages = stages_by_register
                        .get(&output_register_u32)
                        .into_iter()
                        .flatten()
                        .copied()
                        .filter(|stage| should_observe_stage(error_observation_mode, *stage))
                        .collect::<Vec<_>>();
                    if !stages.is_empty() {
                        encountered_stage_registers.insert(output_register_u32);
                    }
                    let mut operation_categories =
                        if error_observation_mode == EvaluatorErrorObservationMode::Complete {
                            operation_categories
                        } else {
                            Vec::new()
                        };
                    if !operation_categories.is_empty() || !stages.is_empty() {
                        if !stages.is_empty() {
                            operation_categories.push("compiler stage");
                        }
                        let symbolic_bound = symbolic_trace
                            .register_bound(output_register_u32)
                            .expect("observed evaluator output has a symbolic register bound");
                        exact_error_ledger.observe_with_symbolic_bound(
                            &self.error_observer,
                            &ciphertext_output,
                            &expected_output,
                            ExactErrorObservationContext::new(
                                &operation_categories,
                                &stages,
                                case_name,
                            ),
                            symbolic_bound,
                        );
                    }
                    ciphertext_registers.push(Some(ciphertext_output));
                    expected_registers.push(Some(expected_output));
                    assert!(!matches!(
                        opcode,
                        EvaluatorOpcode::DropRegister | EvaluatorOpcode::DeclareOutput
                    ));
                }
            }
        }
        assert_eq!(
            encountered_stage_registers, expected_observed_stage_registers,
            "compiler stage register was not observed for {case_name} at top count {top_count}"
        );

        let target_identifier_register =
            usize::try_from(target_registers[0].expect("identifier target register is declared"))
                .unwrap();
        let target_order_register =
            usize::try_from(target_registers[1].expect("order target register is declared"))
                .unwrap();
        let target_identifier = ciphertext_registers[target_identifier_register]
            .take()
            .expect("identifier target remains live");
        let target_order = ciphertext_registers[target_order_register]
            .take()
            .expect("order target remains live");
        let expected_identifier = expected_registers[target_identifier_register]
            .take()
            .expect("identifier target shadow remains live");
        let expected_order = expected_registers[target_order_register]
            .take()
            .expect("order target shadow remains live");
        assert!(ciphertext_registers.iter().all(Option::is_none));
        assert!(expected_registers.iter().all(Option::is_none));

        let [expected_identifier_values, expected_order_values] =
            independent_stable_target_values(aggregate_scores, top_count);
        assert_scalar_target(
            &expected_identifier,
            &expected_identifier_values,
            case_name,
            top_count,
            "identifier plaintext shadow",
        );
        assert_scalar_target(
            &expected_order,
            &expected_order_values,
            case_name,
            top_count,
            "order plaintext shadow",
        );
        if error_observation_mode == EvaluatorErrorObservationMode::None {
            let expected_identifier_coefficients =
                encode_extension_lanes_to_plaintext_coefficients(&expected_identifier)
                    .expect("expected identifier target encodes");
            let expected_order_coefficients =
                encode_extension_lanes_to_plaintext_coefficients(&expected_order)
                    .expect("expected order target encodes");
            let identifier_error = self
                .error_observer
                .measure_infinity_norm(&target_identifier, &expected_identifier_coefficients)
                .unwrap_or_else(|error| {
                    panic!(
                        "encrypted identifier target failed exact error observation for {case_name}, top count {top_count}: {error}"
                    )
                });
            let order_error = self
                .error_observer
                .measure_infinity_norm(&target_order, &expected_order_coefficients)
                .unwrap_or_else(|error| {
                    panic!(
                        "encrypted order target failed exact error observation for {case_name}, top count {top_count}: {error}"
                    )
                });
            let identifier_bound = symbolic_trace
                .register_bound(
                    u32::try_from(target_identifier_register)
                        .expect("identifier target register fits u32"),
                )
                .expect("identifier target has a symbolic register bound");
            let order_bound = symbolic_trace
                .register_bound(
                    u32::try_from(target_order_register).expect("order target register fits u32"),
                )
                .expect("order target has a symbolic register bound");
            assert_exact_observation_fits_symbolic_bound(
                &target_identifier,
                &expected_identifier_coefficients,
                &identifier_error,
                identifier_bound,
                case_name,
            );
            assert_exact_observation_fits_symbolic_bound(
                &target_order,
                &expected_order_coefficients,
                &order_error,
                order_bound,
                case_name,
            );
        }
    }

    fn execute_test_instruction(
        &self,
        instruction: &EvaluatorInstruction,
        ciphertext_registers: &[Option<Ciphertext>],
        expected_output: &OracleRingValue,
        case_name: &str,
        calibrate_exact_error: bool,
        exact_error_ledger: &mut ExactErrorLedger,
    ) -> (Ciphertext, Vec<&'static str>) {
        let input = |input_ordinal: usize| {
            let register_ordinal =
                usize::try_from(instruction.input_registers()[input_ordinal]).unwrap();
            ciphertext_registers[register_ordinal]
                .as_ref()
                .expect("selected encrypted instruction input is live")
        };
        match instruction.opcode() {
            EvaluatorOpcode::ModulusSwitchToLevel => {
                let target_level = usize::try_from(instruction.immediate0())
                    .expect("selected target level fits usize");
                assert!(target_level < input(0).level);
                let mut switched =
                    modulus_switch(input(0)).expect("selected evaluator modulus switch executes");
                if calibrate_exact_error {
                    exact_error_ledger.observe(
                        &self.error_observer,
                        &switched,
                        expected_output,
                        ExactErrorObservationContext::new(
                            &["evaluator modulus switch"],
                            &[],
                            case_name,
                        ),
                    );
                }
                while switched.level > target_level {
                    switched = modulus_switch(&switched)
                        .expect("selected evaluator modulus switch step executes");
                    if calibrate_exact_error {
                        exact_error_ledger.observe(
                            &self.error_observer,
                            &switched,
                            expected_output,
                            ExactErrorObservationContext::new(
                                &["evaluator modulus switch"],
                                &[],
                                case_name,
                            ),
                        );
                    }
                }
                assert_eq!(switched.level, target_level);
                (switched, Vec::new())
            }
            EvaluatorOpcode::NormalizeDecryptionMultiplier => (
                normalize_scaling(input(0)).expect("selected evaluator normalization executes"),
                vec!["evaluator normalization"],
            ),
            EvaluatorOpcode::CiphertextAdd => (
                ciphertext_add(input(0), input(1)).expect("selected evaluator addition executes"),
                Vec::new(),
            ),
            EvaluatorOpcode::PlaintextAdd => (
                add_plaintext_coefficients(input(0), &self.constant(instruction).coefficients)
                    .expect("selected evaluator plaintext addition executes"),
                Vec::new(),
            ),
            EvaluatorOpcode::PlaintextMultiply => (
                plaintext_mul(input(0), &self.constant(instruction).coefficients)
                    .expect("selected evaluator plaintext multiplication executes"),
                vec!["evaluator plaintext multiplication"],
            ),
            EvaluatorOpcode::CiphertextMultiplyRelinearizeAndDrop
            | EvaluatorOpcode::CiphertextMultiplyAndRelinearize => {
                let tensor = ciphertext_tensor(input(0), input(1))
                    .expect("selected evaluator ciphertext multiplication executes");
                if calibrate_exact_error {
                    exact_error_ledger.observe(
                        &self.error_observer,
                        &tensor,
                        expected_output,
                        ExactErrorObservationContext::new(
                            &["evaluator ciphertext multiplication"],
                            &[],
                            case_name,
                        ),
                    );
                }
                let relinearized = relinearize(&tensor, &self.relinearization_key)
                    .expect("selected evaluator ciphertext product relinearizes");
                if calibrate_exact_error {
                    exact_error_ledger.observe(
                        &self.error_observer,
                        &relinearized,
                        expected_output,
                        ExactErrorObservationContext::new(
                            &["evaluator relinearization"],
                            &[],
                            case_name,
                        ),
                    );
                }
                if instruction.opcode() == EvaluatorOpcode::CiphertextMultiplyRelinearizeAndDrop {
                    (
                        modulus_switch(&relinearized)
                            .expect("selected evaluator product modulus switches"),
                        vec!["evaluator modulus switch"],
                    )
                } else {
                    (relinearized, Vec::new())
                }
            }
            EvaluatorOpcode::GaloisRotate => {
                let galois_element = usize::try_from(instruction.immediate0())
                    .expect("selected Galois element fits usize");
                let galois_key = self
                    .galois_keys
                    .get(&galois_element)
                    .expect("selected Galois key is generated");
                (
                    rotate(input(0), galois_element, galois_key)
                        .expect("selected evaluator rotation executes"),
                    vec!["evaluator rotation"],
                )
            }
            EvaluatorOpcode::DropRegister | EvaluatorOpcode::DeclareOutput => {
                unreachable!("non-producing instructions are handled before the test driver")
            }
        }
    }

    fn expected_instruction_output(
        &self,
        instruction: &EvaluatorInstruction,
        expected_registers: &[Option<OracleRingValue>],
    ) -> OracleRingValue {
        let input = |input_ordinal: usize| {
            let register_ordinal =
                usize::try_from(instruction.input_registers()[input_ordinal]).unwrap();
            expected_registers[register_ordinal]
                .as_ref()
                .expect("selected plaintext-shadow input is live")
        };
        match instruction.opcode() {
            EvaluatorOpcode::ModulusSwitchToLevel
            | EvaluatorOpcode::NormalizeDecryptionMultiplier => input(0).clone(),
            EvaluatorOpcode::CiphertextAdd => semantic_oracle::add(input(0), input(1)),
            EvaluatorOpcode::PlaintextAdd => {
                semantic_oracle::add(input(0), &self.constant(instruction).lanes)
            }
            EvaluatorOpcode::PlaintextMultiply => {
                semantic_oracle::multiply(input(0), &self.constant(instruction).lanes)
            }
            EvaluatorOpcode::CiphertextMultiplyRelinearizeAndDrop
            | EvaluatorOpcode::CiphertextMultiplyAndRelinearize => {
                semantic_oracle::multiply(input(0), input(1))
            }
            EvaluatorOpcode::GaloisRotate => semantic_oracle::apply_galois_action(
                input(0),
                usize::try_from(instruction.immediate0())
                    .expect("selected Galois element fits usize"),
            ),
            EvaluatorOpcode::DropRegister | EvaluatorOpcode::DeclareOutput => {
                unreachable!("non-producing instructions have no plaintext shadow output")
            }
        }
    }

    fn constant(&self, instruction: &EvaluatorInstruction) -> &TestConstant {
        self.constants
            .get(
                instruction
                    .constant_hash()
                    .expect("selected plaintext instruction has a constant")
                    .as_bytes(),
            )
            .expect("selected plaintext instruction constant is cataloged")
    }
}

struct EncryptedProductState {
    ciphertext: Ciphertext,
    expected_lanes: OracleRingValue,
}

impl EncryptedEvaluatorHarness {
    fn execute_product_merge(
        &self,
        merge: &PairCharacterProductMerge,
        schedule: &crate::bgv::evaluator::pair_character_product::PairCharacterProductSchedule,
        states: &mut [Option<EncryptedProductState>],
        exact_error_ledger: &mut ExactErrorLedger,
        case_name: &str,
        calibrate_exact_error: bool,
    ) {
        let mut left = states[merge.left_node_ordinal]
            .take()
            .expect("selected product merge has its left input");
        let mut right = states[merge.right_node_ordinal]
            .take()
            .expect("selected product merge has its right input");
        switch_product_state_to_level(
            &mut left,
            merge.alignment_level,
            &self.error_observer,
            exact_error_ledger,
            case_name,
            calibrate_exact_error,
        );
        switch_product_state_to_level(
            &mut right,
            merge.alignment_level,
            &self.error_observer,
            exact_error_ledger,
            case_name,
            calibrate_exact_error,
        );
        let expected_lanes = semantic_oracle::multiply(&left.expected_lanes, &right.expected_lanes);
        let tensor = ciphertext_tensor(&left.ciphertext, &right.ciphertext)
            .expect("selected pair-character ciphertexts multiply");
        if calibrate_exact_error {
            exact_error_ledger.observe(
                &self.error_observer,
                &tensor,
                &expected_lanes,
                ExactErrorObservationContext::new(&["product multiplication"], &[], case_name),
            );
        }
        let relinearized = relinearize(&tensor, &self.relinearization_key)
            .expect("selected pair-character product relinearizes");
        if calibrate_exact_error {
            exact_error_ledger.observe(
                &self.error_observer,
                &relinearized,
                &expected_lanes,
                ExactErrorObservationContext::new(&["product relinearization"], &[], case_name),
            );
        }
        let mut output = EncryptedProductState {
            ciphertext: relinearized,
            expected_lanes,
        };
        let output_level = schedule.nodes[merge.output_node_ordinal].level;
        switch_product_state_to_level(
            &mut output,
            output_level,
            &self.error_observer,
            exact_error_ledger,
            case_name,
            calibrate_exact_error,
        );
        assert!(states[merge.output_node_ordinal].replace(output).is_none());
    }
}

fn switch_product_state_to_level(
    state: &mut EncryptedProductState,
    target_level: usize,
    error_observer: &ExactDecryptionErrorObserver,
    exact_error_ledger: &mut ExactErrorLedger,
    case_name: &str,
    calibrate_exact_error: bool,
) {
    assert!(target_level <= state.ciphertext.level);
    while state.ciphertext.level > target_level {
        state.ciphertext = modulus_switch(&state.ciphertext)
            .expect("selected pair-character ciphertext modulus switches");
        if calibrate_exact_error {
            exact_error_ledger.observe(
                error_observer,
                &state.ciphertext,
                &state.expected_lanes,
                ExactErrorObservationContext::new(&["product modulus switch"], &[], case_name),
            );
        }
    }
}

fn ballot_scores_for_aggregate(
    aggregate_scores: &[u64],
    ballot_count: usize,
    ballot_ordinal: usize,
) -> Vec<u64> {
    let ballot_count_u64 = u64::try_from(ballot_count).expect("selected ballot count fits u64");
    aggregate_scores
        .iter()
        .map(|aggregate_score| {
            let quotient = aggregate_score / ballot_count_u64;
            let remainder = aggregate_score % ballot_count_u64;
            let zero_based_score =
                quotient + u64::from(u64::try_from(ballot_ordinal).unwrap() < remainder);
            assert!(zero_based_score <= 9);
            zero_based_score + 1
        })
        .collect()
}

fn should_observe_stage(
    mode: EvaluatorErrorObservationMode,
    stage: EvaluatorCompilerStage,
) -> bool {
    match mode {
        EvaluatorErrorObservationMode::None => false,
        EvaluatorErrorObservationMode::Complete => true,
        EvaluatorErrorObservationMode::TopCountTail => matches!(
            stage,
            EvaluatorCompilerStage::IdentifierPolynomialBeforeSelector
                | EvaluatorCompilerStage::OrderPolynomialBeforeSelector
                | EvaluatorCompilerStage::FinalIdentifierTarget
                | EvaluatorCompilerStage::FinalOrderTarget
        ),
    }
}

fn add_expected_observation_count(
    expected_counts: &mut BTreeMap<&'static str, usize>,
    category: &'static str,
    additional_count: usize,
) {
    if additional_count == 0 {
        return;
    }
    let expected_count = expected_counts.entry(category).or_default();
    *expected_count = expected_count
        .checked_add(additional_count)
        .expect("exact-error expected observation count fits usize");
}

fn expected_register_level(
    register_levels: &[Option<usize>],
    instruction: &EvaluatorInstruction,
    input_ordinal: usize,
) -> usize {
    let register_ordinal = usize::try_from(instruction.input_registers()[input_ordinal]).unwrap();
    register_levels[register_ordinal].expect("expected evaluator input register is live")
}

fn independent_stable_target_values(aggregate_scores: &[u64], top_count: usize) -> [Vec<u64>; 2] {
    assert_eq!(aggregate_scores.len(), ORACLE_OPTION_COUNT);
    assert!((1..=ORACLE_OPTION_COUNT).contains(&top_count));
    let mut option_ordinals = (0..ORACLE_OPTION_COUNT).collect::<Vec<_>>();
    option_ordinals.sort_by(|left_ordinal, right_ordinal| {
        aggregate_scores[*right_ordinal].cmp(&aggregate_scores[*left_ordinal])
    });
    for adjacent in option_ordinals.windows(2) {
        let left_ordinal = adjacent[0];
        let right_ordinal = adjacent[1];
        assert!(aggregate_scores[left_ordinal] >= aggregate_scores[right_ordinal]);
        if aggregate_scores[left_ordinal] == aggregate_scores[right_ordinal] {
            assert!(left_ordinal < right_ordinal, "stable tie order changed");
        }
    }

    let mut identifiers = vec![0_u64; ORACLE_OPTION_COUNT];
    let mut order = vec![0_u64; ORACLE_OPTION_COUNT];
    for (rank_ordinal, option_ordinal) in option_ordinals.into_iter().enumerate() {
        if rank_ordinal >= top_count {
            continue;
        }
        identifiers[option_ordinal] =
            u64::try_from(option_ordinal + 1).expect("selected option identifier fits u64");
        order[option_ordinal] =
            u64::try_from(rank_ordinal + 1).expect("selected stable rank fits u64");
    }
    [identifiers, order]
}

fn encrypted_semantic_cases() -> Vec<EncryptedSemanticCase> {
    let mut cases = vec![
        EncryptedSemanticCase {
            name: "all equal".to_owned(),
            aggregate_scores: vec![7; ORACLE_OPTION_COUNT],
            ballot_count: 1,
            top_counts: (1..=ORACLE_OPTION_COUNT).collect(),
            calibrate_product_error: true,
            calibrate_evaluator_error: true,
        },
        EncryptedSemanticCase {
            name: "strict increasing".to_owned(),
            aggregate_scores: (0..ORACLE_OPTION_COUNT)
                .map(|score| u64::try_from(score).unwrap())
                .collect(),
            ballot_count: 9,
            top_counts: vec![7],
            calibrate_product_error: true,
            calibrate_evaluator_error: false,
        },
        EncryptedSemanticCase {
            name: "strict decreasing".to_owned(),
            aggregate_scores: (0..ORACLE_OPTION_COUNT)
                .rev()
                .map(|score| u64::try_from(score).unwrap())
                .collect(),
            ballot_count: 9,
            top_counts: vec![13],
            calibrate_product_error: false,
            calibrate_evaluator_error: false,
        },
        EncryptedSemanticCase {
            name: "zero and ninety boundary".to_owned(),
            aggregate_scores: (0..ORACLE_OPTION_COUNT)
                .map(|option_ordinal| if option_ordinal % 2 == 0 { 0 } else { 90 })
                .collect(),
            ballot_count: 10,
            top_counts: vec![10],
            calibrate_product_error: true,
            calibrate_evaluator_error: false,
        },
    ];

    for ballot_count in 2..=8 {
        let aggregate_score_modulus = 9 * ballot_count + 1;
        cases.push(EncryptedSemanticCase {
            name: format!("product composition with {ballot_count} ballots"),
            aggregate_scores: (0..ORACLE_OPTION_COUNT)
                .map(|option_ordinal| {
                    u64::try_from(option_ordinal * (ballot_count + 1) % aggregate_score_modulus)
                        .unwrap()
                })
                .collect(),
            ballot_count,
            top_counts: vec![2 * ballot_count],
            calibrate_product_error: true,
            calibrate_evaluator_error: false,
        });
    }

    for winner_ordinal in 1..ORACLE_OPTION_COUNT - 1 {
        let loser_ordinal = if winner_ordinal + 1 == ORACLE_OPTION_COUNT - 1 {
            1
        } else {
            winner_ordinal + 1
        };
        let mut unique_extremes = vec![45; ORACLE_OPTION_COUNT];
        unique_extremes[winner_ordinal] = 90;
        unique_extremes[loser_ordinal] = 0;
        cases.push(EncryptedSemanticCase {
            name: format!("unique winner {winner_ordinal} and loser {loser_ordinal}"),
            aggregate_scores: unique_extremes,
            ballot_count: 10,
            top_counts: vec![winner_ordinal + 1],
            calibrate_product_error: false,
            calibrate_evaluator_error: false,
        });
    }

    for top_count in 1..ORACLE_OPTION_COUNT {
        let tie_count = top_count + 1;
        let mut aggregate_scores = (0..ORACLE_OPTION_COUNT)
            .map(|option_ordinal| u64::try_from(ORACLE_OPTION_COUNT - option_ordinal).unwrap())
            .collect::<Vec<_>>();
        aggregate_scores[..tie_count].fill(60);
        cases.push(EncryptedSemanticCase {
            name: format!("tie at top count {top_count} with multiplicity {tie_count}"),
            aggregate_scores,
            ballot_count: 10,
            top_counts: vec![top_count],
            calibrate_product_error: false,
            calibrate_evaluator_error: false,
        });
    }

    let mut seed = 0x5eed_5eed_cafe_babe_u64;
    for case_ordinal in 0..8 {
        let aggregate_scores = (0..ORACLE_OPTION_COUNT)
            .map(|_| {
                seed = seed
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                seed % 91
            })
            .collect();
        cases.push(EncryptedSemanticCase {
            name: format!("seeded adversarial {case_ordinal}"),
            aggregate_scores,
            ballot_count: 10,
            top_counts: vec![case_ordinal * 2 + 3],
            calibrate_product_error: false,
            calibrate_evaluator_error: false,
        });
    }
    cases
}

fn assert_active_lane_boundaries_across_both_ciphertexts() {
    let aggregate_inputs = semantic_oracle::aggregate_character_inputs(&[0; ORACLE_OPTION_COUNT]);
    let assignments = semantic_oracle::pair_assignments();
    for (ciphertext_ordinal, aggregate_input) in aggregate_inputs.iter().enumerate() {
        let occupied_lanes = assignments
            .iter()
            .filter(|assignment| assignment.ciphertext_ordinal == ciphertext_ordinal)
            .map(|assignment| assignment.lane_ordinal)
            .collect::<BTreeSet<_>>();
        let first_lane = *occupied_lanes
            .first()
            .expect("each pair-character ciphertext has an active first lane");
        let last_lane = *occupied_lanes
            .last()
            .expect("each pair-character ciphertext has an active last lane");
        for lane_ordinal in [first_lane, last_lane] {
            assert!(
                aggregate_input[lane_ordinal]
                    .iter()
                    .any(|coordinate| *coordinate != 0),
                "pair-character ciphertext {ciphertext_ordinal} boundary lane {lane_ordinal} is inactive"
            );
        }
    }
}

fn assert_scalar_target(
    target: &OracleRingValue,
    expected_values: &[u64],
    case_name: &str,
    top_count: usize,
    target_name: &str,
) {
    assert_eq!(target.len(), ORACLE_LANE_COUNT);
    assert_eq!(expected_values.len(), ORACLE_OPTION_COUNT);
    for (lane_ordinal, lane) in target.iter().enumerate() {
        let expected_value = expected_values.get(lane_ordinal).copied().unwrap_or(0);
        assert_eq!(
            lane[0], expected_value,
            "{target_name} drifted for {case_name}, top count {top_count}, lane {lane_ordinal}"
        );
        assert!(
            lane[1..].iter().all(|coordinate| *coordinate == 0),
            "{target_name} stopped being scalar for {case_name}, top count {top_count}, lane {lane_ordinal}"
        );
    }
}

fn scalar_values_as_extension_lanes(values: &[u64]) -> OracleRingValue {
    assert!(values.len() <= ORACLE_LANE_COUNT);
    let mut lanes = vec![[0_u64; ORACLE_EXTENSION_DEGREE]; ORACLE_LANE_COUNT];
    for (lane, value) in lanes.iter_mut().zip(values.iter().copied()) {
        lane[0] = value;
    }
    lanes
}

fn complete_production_replay_store_components(
    collective_secret: &[i64],
    relinearization_key: &KeySwitchKey,
) -> Vec<(SelectedEvaluatorEntryPosition, Vec<u8>, Option<Vec<u8>>)> {
    let positions = selected_evaluator_entry_positions(FOUNDATION_PROFILE.option_count)
        .expect("selected suite-maximal evaluator positions derive");
    let mut relinearization_components = Some(
        relinearization_key
            .canonical_coefficient_store_components_for_tests()
            .expect("development relinearization key serializes canonically"),
    );
    positions
        .into_iter()
        .map(|position| match position.key_kind() {
            SelectedEvaluatorEntryKind::Relinearization { catalog_level } => {
                assert_eq!(catalog_level, relinearization_key.level());
                let [runtime, auxiliary] = relinearization_components
                    .take()
                    .expect("selected evaluator catalog has one relinearization entry");
                (position, runtime, Some(auxiliary))
            }
            SelectedEvaluatorEntryKind::Galois { .. } => (
                position,
                production_galois_runtime_component_bytes(collective_secret, position),
                None,
            ),
        })
        .collect()
}

fn production_galois_runtime_component_bytes(
    collective_secret: &[i64],
    position: SelectedEvaluatorEntryPosition,
) -> Vec<u8> {
    let SelectedEvaluatorEntryKind::Galois {
        galois_element,
        catalog_level,
    } = position.key_kind()
    else {
        panic!("only Galois positions have a derived common component");
    };
    assert_eq!(collective_secret.len(), POLYNOMIAL_DEGREE);
    let topology = KeySwitchDecompositionTopology::for_level(catalog_level)
        .expect("selected Galois topology derives");
    let automorphed_secret =
        apply_signed_negacyclic_automorphism(collective_secret, galois_element);
    let expected_byte_length = usize::try_from(
        topology
            .canonical_component_wire_byte_length(POLYNOMIAL_DEGREE)
            .expect("selected Galois component length derives"),
    )
    .expect("selected Galois component length fits usize");
    let mut canonical_bytes = Vec::with_capacity(expected_byte_length);
    for decomposition_block_index in 0..topology.data_block_count() {
        let block_range = topology
            .data_block_range(decomposition_block_index)
            .expect("selected Galois block range derives");
        for (extended_limb_index, modulus) in topology.extended_moduli().iter().copied().enumerate()
        {
            let (modulus_catalog_identifier, modulus_index) =
                if extended_limb_index < topology.data_prime_count() {
                    (1_u16, extended_limb_index)
                } else {
                    (2_u16, extended_limb_index - topology.data_prime_count())
                };
            let common_reference = sample_galois_common_reference_limb(
                &[0x5a; Hash512::BYTE_LENGTH],
                position.schedule_position(),
                u16::try_from(decomposition_block_index)
                    .expect("selected decomposition block fits u16"),
                modulus_catalog_identifier,
                u16::try_from(modulus_index).expect("selected modulus index fits u16"),
                POLYNOMIAL_DEGREE,
            )
            .expect("accepted-setup Galois common component derives");
            let secret_residues = collective_secret
                .iter()
                .copied()
                .map(|coefficient| signed_i64_residue(coefficient, modulus))
                .collect::<Vec<_>>();
            let common_reference_secret_product =
                negacyclic_mul(&common_reference, &secret_residues, modulus)
                    .expect("Galois common component multiplies the collective secret");
            let gadget_residue = block_range
                .contains(&extended_limb_index)
                .then(|| special_basis_modulus_residue(modulus));
            let residue_byte_length = canonical_residue_byte_length(modulus)
                .expect("selected Galois residue width derives");
            for (coefficient_index, common_product) in
                common_reference_secret_product.into_iter().enumerate()
            {
                let mut runtime_coefficient = sub_mod_fast(0, common_product, modulus);
                if let Some(gadget_residue) = gadget_residue {
                    runtime_coefficient = add_mod_fast(
                        runtime_coefficient,
                        mul_mod_fast(
                            gadget_residue,
                            signed_i64_residue(automorphed_secret[coefficient_index], modulus),
                            modulus,
                        ),
                        modulus,
                    );
                }
                canonical_bytes
                    .extend_from_slice(&runtime_coefficient.to_le_bytes()[..residue_byte_length]);
            }
        }
    }
    assert_eq!(canonical_bytes.len(), expected_byte_length);
    canonical_bytes
}

fn apply_signed_negacyclic_automorphism(input: &[i64], galois_element: usize) -> Vec<i64> {
    assert_eq!(input.len(), POLYNOMIAL_DEGREE);
    assert!(galois_element > 1 && !galois_element.is_multiple_of(2));
    let automorphism_modulus = 2 * POLYNOMIAL_DEGREE;
    let mut output = vec![0_i64; POLYNOMIAL_DEGREE];
    for (source_index, coefficient) in input.iter().copied().enumerate() {
        let mapped_exponent = source_index * galois_element % automorphism_modulus;
        output[mapped_exponent % POLYNOMIAL_DEGREE] = if mapped_exponent >= POLYNOMIAL_DEGREE {
            coefficient
                .checked_neg()
                .expect("selected small secret coefficient negates")
        } else {
            coefficient
        };
    }
    output
}

fn selected_target_register(
    program: &EvaluatorProgramSet,
    top_count: usize,
    output_role: u64,
) -> u32 {
    program
        .streams()
        .iter()
        .find(|stream| usize::from(stream.top_count()) == top_count)
        .and_then(|stream| {
            stream.instructions().iter().find_map(|instruction| {
                (instruction.opcode() == EvaluatorOpcode::DeclareOutput
                    && instruction.immediate0() == output_role)
                    .then(|| instruction.input_registers()[0])
            })
        })
        .expect("selected evaluator stream declares both target roles")
}

fn production_execution_release_binding() -> KllpsReleaseBinding {
    KllpsReleaseBinding {
        suite_id: selected_suite_capability_for_tests().suite_identifier(),
        ceremony_context_hash: PRODUCTION_EXECUTION_CEREMONY_CONTEXT_HASH,
        action_context_hash: PRODUCTION_EXECUTION_ACTION_CONTEXT_HASH,
        roster_hash: PRODUCTION_EXECUTION_ROSTER_HASH,
        verified_setup_source_hash: PRODUCTION_EXECUTION_VERIFIED_SETUP_SOURCE_HASH,
        finality_hash: [0xa9; 64],
        authorization_hash: [0xba; 64],
        target_identifier_full_digest: [0xcb; 64],
        target_order_full_digest: [0xdc; 64],
    }
}

fn production_execution_participant_binding(
    roster_position: usize,
) -> KllpsParticipantReleaseBinding {
    let position = u8::try_from(roster_position).expect("selected roster position fits u8");
    KllpsParticipantReleaseBinding {
        reservation_intent_object_hash: [0xed_u8.wrapping_add(position); 64],
        subject_participant_id: [position.wrapping_add(1); 64],
        state_key: [0xfe_u8.wrapping_sub(position); 64],
    }
}

fn deterministic_threshold_sharing_polynomials(collective_secret: &[i64]) -> Vec<Vec<i64>> {
    assert_eq!(collective_secret.len(), POLYNOMIAL_DEGREE);
    vec![
        collective_secret.to_vec(),
        sparse_signed_release_polynomial(&[(0, 1), (7, -1), (4_097, 1)]),
        sparse_signed_release_polynomial(&[(1, 2), (71, -2), (8_193, 1)]),
        sparse_signed_release_polynomial(&[(2, -1), (1_023, 3), (12_289, -2)]),
    ]
}

fn sparse_signed_release_polynomial(entries: &[(usize, i64)]) -> Vec<i64> {
    let mut polynomial = vec![0_i64; POLYNOMIAL_DEGREE];
    for (coefficient_index, coefficient) in entries.iter().copied() {
        polynomial[coefficient_index] = coefficient;
    }
    polynomial
}

fn deterministic_threshold_share(
    sharing_polynomials: &[Vec<i64>],
    roster_position: usize,
    level: usize,
) -> Vec<Vec<u64>> {
    assert_eq!(sharing_polynomials.len(), KLLPS_RECONSTRUCTION_THRESHOLD);
    DATA_PRIMES[..=level]
        .iter()
        .copied()
        .map(|modulus| {
            let mut share = vec![0_u64; POLYNOMIAL_DEGREE];
            for (sharing_degree, polynomial) in sharing_polynomials.iter().enumerate() {
                accumulate_signed_monomial_shift(
                    &mut share,
                    polynomial,
                    roster_position * sharing_degree * KLLPS_POINT_STRIDE,
                    modulus,
                );
            }
            share
        })
        .collect()
}

fn accumulate_signed_monomial_shift(
    accumulator: &mut [u64],
    polynomial: &[i64],
    exponent: usize,
    modulus: u64,
) {
    assert_eq!(accumulator.len(), POLYNOMIAL_DEGREE);
    assert_eq!(polynomial.len(), POLYNOMIAL_DEGREE);
    let reduced_exponent = exponent % (2 * POLYNOMIAL_DEGREE);
    let initial_negative = reduced_exponent >= POLYNOMIAL_DEGREE;
    let shift = reduced_exponent % POLYNOMIAL_DEGREE;
    for (source_index, coefficient) in polynomial.iter().copied().enumerate() {
        let destination_sum = source_index + shift;
        let wrap_negative = destination_sum >= POLYNOMIAL_DEGREE;
        let destination = destination_sum % POLYNOMIAL_DEGREE;
        let mut residue = signed_i64_residue(coefficient, modulus);
        if initial_negative ^ wrap_negative {
            residue = sub_mod_fast(0, residue, modulus);
        }
        accumulator[destination] = add_mod_fast(accumulator[destination], residue, modulus);
    }
}

fn hostile_centered_release_flooding_error(
    roster_position: usize,
    role: usize,
    flooding_bound: &BigUint,
) -> Vec<BigInt> {
    let mut error = vec![BigInt::zero(); POLYNOMIAL_DEGREE];
    let first_magnitude = flooding_bound - BigUint::from(roster_position + role + 1);
    let second_magnitude = flooding_bound - BigUint::from(roster_position * 3 + role + 2);
    let first_sign = if (roster_position + role).is_multiple_of(2) {
        Sign::Plus
    } else {
        Sign::Minus
    };
    let second_sign = if first_sign == Sign::Plus {
        Sign::Minus
    } else {
        Sign::Plus
    };
    error[(roster_position * 97 + role * 13) % POLYNOMIAL_DEGREE] =
        BigInt::from_biguint(first_sign, first_magnitude);
    error[(roster_position * 193 + role * 29 + 1) % POLYNOMIAL_DEGREE] =
        BigInt::from_biguint(second_sign, second_magnitude);
    error
}

fn assert_partial_share_matches_independent_full_ring_oracle(
    targets: [&Ciphertext; 2],
    threshold_share_by_limb: &[Vec<u64>],
    flooding_errors: &[Vec<BigInt>; 2],
    verified_share: &VerifiedKllpsPairedShare,
) {
    for (((target, flooding_error), actual_by_limb), role_name) in targets
        .into_iter()
        .zip(flooding_errors)
        .zip(verified_share.role_partials_for_tests())
        .zip(["identifier", "order"])
    {
        for (limb_index, modulus) in DATA_PRIMES[..=target.level].iter().copied().enumerate() {
            let product = negacyclic_mul(
                &target.components[1][limb_index],
                &threshold_share_by_limb[limb_index],
                modulus,
            )
            .expect("independent full-ring target/share product computes");
            let positive_conversion_scale = sub_mod_fast(
                0,
                inverse_mod(PLAINTEXT_MODULUS % modulus, modulus)
                    .expect("plaintext modulus is invertible"),
                modulus,
            );
            let scaled_conversion = mul_mod_fast(
                KLLPS_DENOMINATOR_CLEARING_FACTOR,
                positive_conversion_scale,
                modulus,
            );
            let expected = product
                .into_iter()
                .zip(flooding_error)
                .map(|(product_coefficient, flooding_coefficient)| {
                    add_mod_fast(
                        mul_mod_fast(product_coefficient, scaled_conversion, modulus),
                        mul_mod_fast(
                            bigint_test_residue(flooding_coefficient, modulus),
                            KLLPS_DENOMINATOR_CLEARING_FACTOR,
                            modulus,
                        ),
                        modulus,
                    )
                })
                .collect::<Vec<_>>();
            assert_eq!(
                actual_by_limb[limb_index], expected,
                "{role_name} partial share differs from the independent full-ring oracle at limb {limb_index}",
            );
        }
    }
}

fn independent_full_ring_release_reconstruction(
    targets: [&Ciphertext; 2],
    selected_positions: &[usize],
    selected_shares: &[&VerifiedKllpsPairedShare],
) -> (Vec<u64>, Vec<u64>) {
    assert_eq!(selected_positions.len(), KLLPS_RECONSTRUCTION_THRESHOLD);
    assert_eq!(selected_shares.len(), KLLPS_RECONSTRUCTION_THRESHOLD);
    let decoded_roles = targets
        .into_iter()
        .enumerate()
        .map(|(role_index, target)| {
            let mut accumulator_by_limb = Vec::with_capacity(target.level + 1);
            for (limb_index, modulus) in DATA_PRIMES[..=target.level].iter().copied().enumerate() {
                let positive_conversion_scale = sub_mod_fast(
                    0,
                    inverse_mod(PLAINTEXT_MODULUS % modulus, modulus)
                        .expect("plaintext modulus is invertible"),
                    modulus,
                );
                let component_zero_scale = mul_mod_fast(
                    KLLPS_DENOMINATOR_CLEARING_FACTOR,
                    positive_conversion_scale,
                    modulus,
                );
                let mut accumulator = target.components[0][limb_index]
                    .iter()
                    .copied()
                    .map(|coefficient| mul_mod_fast(coefficient, component_zero_scale, modulus))
                    .collect::<Vec<_>>();
                for (selected_index, share) in selected_shares.iter().enumerate() {
                    let lagrange_coefficient = authorized_lagrange_coefficient_at_zero_for_tests(
                        selected_positions,
                        selected_index,
                        modulus,
                    )
                    .expect("authorized interpolation coefficient derives");
                    accumulate_full_ring_times_subring_independently(
                        &mut accumulator,
                        share.role_partials_for_tests()[role_index][limb_index].as_slice(),
                        &lagrange_coefficient,
                        modulus,
                    );
                }
                accumulator_by_limb.push(accumulator);
            }
            let plaintext_coefficients = independent_full_modulus_round_and_decode(
                &accumulator_by_limb,
                &DATA_PRIMES[..=target.level],
                target.decrypt_scaling,
            );
            let lanes = decode_plaintext_coefficients_to_extension_lanes(&plaintext_coefficients)
                .expect("independent reconstruction decodes into extension lanes");
            lanes
                .into_iter()
                .map(|lane| {
                    assert!(lane[1..].iter().all(|coordinate| *coordinate == 0));
                    lane[0]
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    (decoded_roles[0].clone(), decoded_roles[1].clone())
}

fn accumulate_full_ring_times_subring_independently(
    accumulator: &mut [u64],
    full_ring_polynomial: &[u64],
    subring_polynomial: &[u64; KLLPS_SUBRING_DEGREE],
    modulus: u64,
) {
    assert_eq!(accumulator.len(), POLYNOMIAL_DEGREE);
    assert_eq!(full_ring_polynomial.len(), POLYNOMIAL_DEGREE);
    for (subring_index, subring_coefficient) in subring_polynomial.iter().copied().enumerate() {
        if subring_coefficient == 0 {
            continue;
        }
        let shift = subring_index * KLLPS_POINT_STRIDE;
        for (source_index, full_ring_coefficient) in
            full_ring_polynomial.iter().copied().enumerate()
        {
            let destination_sum = source_index + shift;
            let term = mul_mod_fast(full_ring_coefficient, subring_coefficient, modulus);
            let destination = destination_sum % POLYNOMIAL_DEGREE;
            accumulator[destination] = if destination_sum >= POLYNOMIAL_DEGREE {
                sub_mod_fast(accumulator[destination], term, modulus)
            } else {
                add_mod_fast(accumulator[destination], term, modulus)
            };
        }
    }
}

fn independent_full_modulus_round_and_decode(
    accumulator_by_limb: &[Vec<u64>],
    active_primes: &[u64],
    target_plaintext_multiplier: u64,
) -> Vec<u64> {
    assert_eq!(accumulator_by_limb.len(), active_primes.len());
    let full_modulus = active_primes
        .iter()
        .copied()
        .map(BigInt::from)
        .product::<BigInt>();
    let half_modulus = &full_modulus / BigInt::from(2_u8);
    let crt_factors = active_primes
        .iter()
        .copied()
        .map(|prime| {
            let prime_bigint = BigInt::from(prime);
            let cofactor = &full_modulus / &prime_bigint;
            let cofactor_residue = (&cofactor % &prime_bigint)
                .to_u64()
                .expect("CRT cofactor residue fits u64");
            cofactor
                * BigInt::from(
                    inverse_mod(cofactor_residue, prime).expect("CRT cofactor is invertible"),
                )
        })
        .collect::<Vec<_>>();
    let inverse_clearing_factor = inverse_mod(
        KLLPS_DENOMINATOR_CLEARING_FACTOR % PLAINTEXT_MODULUS,
        PLAINTEXT_MODULUS,
    )
    .expect("factor four is invertible modulo the plaintext modulus");
    (0..POLYNOMIAL_DEGREE)
        .map(|coefficient_index| {
            let mut full_lift = accumulator_by_limb
                .iter()
                .zip(&crt_factors)
                .map(|(limb, factor)| BigInt::from(limb[coefficient_index]) * factor)
                .sum::<BigInt>();
            full_lift %= &full_modulus;
            if full_lift > half_modulus {
                full_lift -= &full_modulus;
            }
            let rounded_magnitude =
                (full_lift.abs() * BigInt::from(PLAINTEXT_MODULUS) + &half_modulus) / &full_modulus;
            let rounded = if full_lift.sign() == Sign::Minus {
                -rounded_magnitude
            } else {
                rounded_magnitude
            };
            mul_mod_fast(
                bigint_test_residue(&rounded, PLAINTEXT_MODULUS),
                mul_mod_fast(
                    inverse_clearing_factor,
                    target_plaintext_multiplier,
                    PLAINTEXT_MODULUS,
                ),
                PLAINTEXT_MODULUS,
            )
        })
        .collect()
}

fn assert_scalar_release_result(actual_lanes: &[u64], expected: &[u64], role_name: &str) {
    assert_eq!(actual_lanes.len(), ORACLE_LANE_COUNT);
    assert_eq!(expected.len(), ORACLE_OPTION_COUNT);
    assert_eq!(
        &actual_lanes[..expected.len()],
        expected,
        "{role_name} target"
    );
    assert!(
        actual_lanes[expected.len()..]
            .iter()
            .all(|value| *value == 0),
        "{role_name} target has a nonzero unused lane",
    );
}

fn signed_i64_residue(value: i64, modulus: u64) -> u64 {
    u64::try_from(i128::from(value).rem_euclid(i128::from(modulus)))
        .expect("signed coefficient residue fits u64")
}

fn bigint_test_residue(value: &BigInt, modulus: u64) -> u64 {
    let modulus = BigInt::from(modulus);
    let mut residue = value % &modulus;
    if residue.sign() == Sign::Minus {
        residue += &modulus;
    }
    residue.to_u64().expect("canonical residue fits u64")
}
