use super::*;
use crate::bgv::proof_suite::external_memory::MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_OBJECT_COUNT;
use crate::bgv::proof_suite::relation_plan::RelationColumnOrigin;
use crate::bgv::proof_suite::{
    AuthenticatedCompactCommittedMaterialSource, COMMITTED_MATERIAL_PROOF_UNIQUE_QUERY_COUNT,
    CommittedMaterialError, CommittedMaterialRelationPlanInput,
    CommittedMaterialSourcePolynomialAdapter, CommonProofAuthenticatedSourceReadRequest,
    CommonProofBoundTreeLeafSaltRequest, CommonProofGenerationPoll,
    CommonProofSourcePolynomialProvider, CommonProofSourcePolynomialProviderPoll,
    CommonProofSourcePolynomialRequest, CommonProofSourceProviderMemoryAccounting,
    PROOF_EVALUATION_BLOWUP_FACTOR, ProvidedCommonProofSourcePolynomial,
    compile_aggregate_threshold_share_relation_plan, compile_vss_share_linkage_relation_plan,
};
use zeroize::Zeroizing;

const VSS_ENGINE_TEST_RING_DEGREE: usize = 1_024;
const VSS_ENGINE_TEST_EVALUATION_DOMAIN_SIZE: usize = 65_536;
const VSS_ENGINE_TEST_OPENING_DEGREE_BOUND_EXCLUSIVE: u64 = 8_192;
const VSS_ENGINE_TEST_MODULUS: u64 = 97;
const VSS_ENGINE_TEST_MAXIMUM_PROOF_BYTE_LENGTH: usize = 64 * 1_024 * 1_024;
const VSS_ENGINE_TEST_MAXIMUM_EXTERNAL_MEMORY_BYTE_LENGTH: usize = 512 * 1_024 * 1_024;

type VssEngineTestGenerationError = CommonProofGenerationError<
    TestExternalMemoryError,
    TestPrivateCoinError,
    crate::bgv::proof_suite::prover::BoundedCommonProofByteSinkError,
>;

struct CompactVssProofFixture {
    engine: CommonProofEngineFixture,
    statement_owned_trees: Vec<VerifiedStatementOwnedTree>,
    source_polynomial_provider: Option<Box<dyn CommonProofSourcePolynomialProvider>>,
}

struct FaultingBoundProjectionProvider {
    inner: CommittedMaterialSourcePolynomialAdapter,
    faulted_column_ordinal: u32,
    fault_applied: bool,
}

impl CommonProofSourcePolynomialProvider for FaultingBoundProjectionProvider {
    fn memory_accounting(
        &self,
    ) -> Result<CommonProofSourceProviderMemoryAccounting, CommonProofProverError> {
        self.inner.memory_accounting()
    }

    fn poll_source_polynomial(
        &mut self,
        request: CommonProofSourcePolynomialRequest<'_>,
    ) -> Result<CommonProofSourcePolynomialProviderPoll, CommonProofProverError> {
        let requested_column_ordinal = request.column_ordinal();
        match self.inner.poll_source_polynomial(request)? {
            CommonProofSourcePolynomialProviderPoll::Ready(provided)
                if requested_column_ordinal == self.faulted_column_ordinal =>
            {
                assert!(!self.fault_applied, "the projection fault is one-shot");
                self.fault_applied = true;
                let (mut polynomial, replay_identity) = provided.into_parts_for_test();
                let CommonProofSourcePolynomial::Base(coefficients) = &mut polynomial else {
                    panic!("a committed-material projection is a base-field polynomial");
                };
                let first_coefficient = coefficients
                    .first_mut()
                    .expect("a committed-material projection is nonempty");
                *first_coefficient = first_coefficient.add(ProofBaseFieldElement::ONE);
                Ok(CommonProofSourcePolynomialProviderPoll::Ready(
                    ProvidedCommonProofSourcePolynomial::new(polynomial, replay_identity),
                ))
            }
            poll => Ok(poll),
        }
    }

    fn pending_authenticated_source_read_request(
        &self,
    ) -> Result<Option<CommonProofAuthenticatedSourceReadRequest>, CommonProofProverError> {
        self.inner.pending_authenticated_source_read_request()
    }

    fn supply_authenticated_source_range(
        &mut self,
        request: CommonProofAuthenticatedSourceReadRequest,
        authenticated_bytes: Zeroizing<Box<[u8]>>,
    ) -> Result<(), CommonProofProverError> {
        self.inner
            .supply_authenticated_source_range(request, authenticated_bytes)
    }

    fn cancel_pending_authenticated_source_read(&mut self) {
        self.inner.cancel_pending_authenticated_source_read();
    }

    fn finish(&mut self) -> Result<(), CommonProofProverError> {
        if !self.fault_applied {
            return Err(CommonProofProverError::InvalidColumn);
        }
        self.inner.finish()
    }

    fn provide_bound_tree_leaf_salt(
        &mut self,
        request: CommonProofBoundTreeLeafSaltRequest,
    ) -> Result<Option<[u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]>, CommonProofProverError>
    {
        self.inner.provide_bound_tree_leaf_salt(request)
    }

    fn finish_bound_tree_leaf_salts(&mut self) -> Result<(), CommonProofProverError> {
        self.inner.finish_bound_tree_leaf_salts()
    }

    fn rewind_bound_tree_leaf_salts(&mut self) -> Result<(), CommonProofProverError> {
        self.inner.rewind_bound_tree_leaf_salts()
    }
}

fn compact_vss_relation_input() -> CommittedMaterialRelationPlanInput {
    CommittedMaterialRelationPlanInput {
        ring_degree: VSS_ENGINE_TEST_RING_DEGREE as u64,
        evaluation_domain_size: VSS_ENGINE_TEST_EVALUATION_DOMAIN_SIZE as u64,
        opening_degree_bound_exclusive: VSS_ENGINE_TEST_OPENING_DEGREE_BOUND_EXCLUSIVE,
        material_column_degree_bound_exclusive: VSS_ENGINE_TEST_RING_DEGREE as u64,
        participant_count: FOUNDATION_PROFILE.participant_count,
        threshold: FOUNDATION_PROFILE.reconstruction_threshold,
        sharing_data_modulus_indices: vec![0],
        trace_mask_degree_bound_exclusive: (VSS_ENGINE_TEST_RING_DEGREE / 2) as u64,
    }
}

fn compact_engine_fri_fold_count() -> u16 {
    let final_degree_bound = u64::from(PROOF_FINAL_POLYNOMIAL_DEGREE_BOUND_EXCLUSIVE);
    let mut folded_degree_bound = VSS_ENGINE_TEST_OPENING_DEGREE_BOUND_EXCLUSIVE
        .checked_sub(1)
        .expect("the bounded opening degree has a nonzero initial FRI bound");
    assert!(
        folded_degree_bound > final_degree_bound,
        "the bounded opening degree exceeds the final FRI degree",
    );
    let mut fold_count = 0_u16;
    while folded_degree_bound > final_degree_bound {
        folded_degree_bound = folded_degree_bound
            .checked_add(1)
            .and_then(|degree| degree.checked_div(2))
            .expect("the bounded FRI degree halves");
        fold_count = fold_count
            .checked_add(1)
            .expect("the bounded FRI fold count fits u16");
    }
    fold_count
}

fn compact_vss_relation_context() -> RelationPlanCheckContext {
    let input = compact_vss_relation_input();
    let evaluation_domain = ProofEvaluationDomain::new(
        VSS_ENGINE_TEST_EVALUATION_DOMAIN_SIZE,
        PROOF_EVALUATION_COSET_OFFSET,
    )
    .expect("the bounded VSS engine evaluation domain is valid");
    let quotient_component_count = 3_u64;
    let rounded_mask_degree = quotient_component_count
        .checked_add(1)
        .and_then(|count| count.checked_mul(input.trace_mask_degree_bound_exclusive))
        .and_then(|degree| degree.checked_add(quotient_component_count - 1))
        .and_then(|degree| degree.checked_div(quotient_component_count))
        .expect("the bounded quotient mask degree derives");
    let quotient_decomposition_stride = input
        .relation_trace_domain_size()
        .expect("the bounded VSS trace domain derives")
        .checked_add(rounded_mask_degree)
        .expect("the bounded quotient stride derives");
    let minimum_telescoping_mask_degree_bound_exclusive =
        u64::from(COMMITTED_MATERIAL_PROOF_UNIQUE_QUERY_COUNT)
            .checked_mul(2)
            .and_then(|coordinate_count| {
                coordinate_count.checked_add(u64::from(PROOF_DEEP_POINT_COUNT))
            })
            .expect("the bounded telescoping mask degree derives");
    RelationPlanCheckContext {
        base_field_modulus: PROOF_BASE_FIELD_MODULUS,
        challenge_extension_degree: PROOF_CHALLENGE_EXTENSION_DEGREE as u16,
        evaluation_blowup_factor: PROOF_EVALUATION_BLOWUP_FACTOR,
        evaluation_domain_generator: evaluation_domain.generator().canonical(),
        evaluation_coset_offset: PROOF_EVALUATION_COSET_OFFSET,
        deep_point_count: PROOF_DEEP_POINT_COUNT,
        quotient_component_count: quotient_component_count as u32,
        quotient_component_degree_bound_exclusive: quotient_decomposition_stride
            + minimum_telescoping_mask_degree_bound_exclusive,
        fri_fold_count: compact_engine_fri_fold_count(),
        final_polynomial_degree_bound_exclusive: PROOF_FINAL_POLYNOMIAL_DEGREE_BOUND_EXCLUSIVE,
        unique_query_count: COMMITTED_MATERIAL_PROOF_UNIQUE_QUERY_COUNT,
        non_native_modular_identity_challenge_count: PROOF_NON_NATIVE_IDENTITY_CHALLENGE_COUNT,
        maximum_fiat_shamir_candidate_draws_per_output:
            PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
        resolved_moduli: vec![ResolvedSuiteModulus::new(
            SuiteModulusReference::data(0),
            VSS_ENGINE_TEST_MODULUS,
        )],
    }
}

fn dense_negacyclic_monomial_action(source: &[u64], exponent: u64, modulus: u64) -> Vec<u64> {
    let ring_degree = u64::try_from(source.len()).expect("the test ring degree fits u64");
    let reduced_exponent = exponent % (2 * ring_degree);
    let unsigned_exponent = reduced_exponent % ring_degree;
    (0..ring_degree)
        .map(|target_ordinal| {
            let wraps_below_zero = target_ordinal < unsigned_exponent;
            let source_ordinal = if wraps_below_zero {
                target_ordinal + ring_degree - unsigned_exponent
            } else {
                target_ordinal - unsigned_exponent
            };
            let value = i128::from(source[source_ordinal as usize]);
            let signed_value = if (reduced_exponent >= ring_degree) ^ wraps_below_zero {
                -value
            } else {
                value
            };
            u64::try_from(signed_value.rem_euclid(i128::from(modulus)))
                .expect("the canonical test residue fits u64")
        })
        .collect()
}

fn add_canonical_messages(left: &[u64], right: &[u64], modulus: u64) -> Vec<u64> {
    left.iter()
        .copied()
        .zip(right.iter().copied())
        .map(|(left_value, right_value)| (left_value + right_value) % modulus)
        .collect()
}

fn compact_vss_messages() -> Vec<Vec<u64>> {
    let input = compact_vss_relation_input();
    let coefficient_messages = (0..usize::from(input.threshold))
        .map(|coefficient_ordinal| {
            (0..VSS_ENGINE_TEST_RING_DEGREE)
                .map(|coefficient_index| {
                    (u64::try_from(coefficient_ordinal + 1)
                        .expect("the coefficient ordinal fits u64")
                        * 17
                        * u64::try_from(coefficient_index + 3)
                            .expect("the coefficient index fits u64")
                        + u64::try_from(coefficient_ordinal * 11 + 7)
                            .expect("the deterministic offset fits u64"))
                        % VSS_ENGINE_TEST_MODULUS
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let point_stride = input
        .point_stride()
        .expect("the fixed-roster point stride derives");
    let recipient_messages = (0..usize::from(input.participant_count))
        .map(|recipient_ordinal| {
            coefficient_messages.iter().enumerate().fold(
                vec![0_u64; VSS_ENGINE_TEST_RING_DEGREE],
                |accumulated, (coefficient_ordinal, coefficient_message)| {
                    let exponent = u64::try_from(recipient_ordinal)
                        .expect("the recipient ordinal fits u64")
                        * u64::try_from(coefficient_ordinal)
                            .expect("the coefficient ordinal fits u64")
                        * point_stride;
                    add_canonical_messages(
                        &accumulated,
                        &dense_negacyclic_monomial_action(
                            coefficient_message,
                            exponent,
                            VSS_ENGINE_TEST_MODULUS,
                        ),
                        VSS_ENGINE_TEST_MODULUS,
                    )
                },
            )
        })
        .collect::<Vec<_>>();
    coefficient_messages
        .into_iter()
        .chain(recipient_messages)
        .collect()
}

fn compact_vss_application_statement(ordered_roots: &[[u8; 64]], binding_fill: u8) -> Vec<u8> {
    let coefficient_root_count = usize::from(FOUNDATION_PROFILE.reconstruction_threshold);
    assert_eq!(
        ordered_roots.len(),
        coefficient_root_count + usize::from(FOUNDATION_PROFILE.participant_count),
        "the bounded VSS roots retain the exact fixed-roster inventory",
    );
    let (ordered_coefficient_roots, ordered_recipient_roots) =
        ordered_roots.split_at(coefficient_root_count);
    let coefficient_root_items = ordered_coefficient_roots
        .iter()
        .copied()
        .map(CanonicalItem::hash512)
        .collect::<Vec<_>>();
    let recipient_root_items = ordered_recipient_roots
        .iter()
        .copied()
        .map(CanonicalItem::hash512)
        .collect::<Vec<_>>();
    CanonicalTuple::new(
        ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
        SCHEMA_VERSION,
        vec![
            CanonicalItem::unsigned16(FOUNDATION_PROFILE.protocol_version),
            CanonicalItem::hash512([0x11; 64]),
            CanonicalItem::hash512([0x31; 64]),
            CanonicalItem::hash512([binding_fill; 64]),
            CanonicalItem::hash512([0x41; 64]),
            CanonicalItem::hash512([0x42; 64]),
            CanonicalItem::participant_identity([0x43; 64]),
            CanonicalItem::unsigned16(0),
            CanonicalItem::homogeneous_list(CanonicalItemType::Hash512, &coefficient_root_items)
                .expect("the bounded VSS coefficient root list encodes"),
            CanonicalItem::homogeneous_list(CanonicalItemType::Hash512, &recipient_root_items)
                .expect("the bounded VSS recipient root list encodes"),
        ],
    )
    .encode()
    .expect("the bounded VSS engine statement encodes")
}

fn compact_vss_proof_fixture(
    mutate_recipient_share: bool,
    mutate_bound_projection: bool,
) -> CompactVssProofFixture {
    let input = compact_vss_relation_input();
    let relation_context = compact_vss_relation_context();
    let relation_plan = compile_vss_share_linkage_relation_plan(&input, &relation_context)
        .expect("the bounded fixed-roster VSS relation compiles");
    let selected_variant = relation_plan
        .select_variant(None, None)
        .expect("the bounded VSS relation has one variant");
    let material_profile = CommittedMaterialProfile::for_common_proof_evaluation_domain(
        VSS_ENGINE_TEST_RING_DEGREE,
        VSS_ENGINE_TEST_EVALUATION_DOMAIN_SIZE,
    )
    .expect("the bounded committed-material profile derives");
    let mut ordered_messages = compact_vss_messages();
    if mutate_recipient_share {
        let first_recipient_message = ordered_messages
            .get_mut(usize::from(input.threshold))
            .expect("the first recipient message exists");
        first_recipient_message[0] = (first_recipient_message[0] + 1) % VSS_ENGINE_TEST_MODULUS;
    }
    let bound_tree_descriptors = selected_variant
        .ordered_trees()
        .iter()
        .enumerate()
        .filter_map(|(tree_catalog_index, descriptor)| match descriptor {
            RelationTreeDescriptor::BoundPublic {
                expected_root_source_ordinal,
                ordered_column_ordinals,
                ..
            } => Some((
                tree_catalog_index,
                *expected_root_source_ordinal,
                ordered_column_ordinals.len(),
            )),
            RelationTreeDescriptor::ProofCreated { .. } => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(bound_tree_descriptors.len(), ordered_messages.len());
    let mut statement_owned_trees = Vec::with_capacity(ordered_messages.len());
    let mut ordered_sources = Vec::with_capacity(ordered_messages.len());
    let mut ordered_roots = Vec::with_capacity(ordered_messages.len());
    for (
        logical_root_ordinal,
        (message, (tree_catalog_index, expected_root_source_ordinal, column_count)),
    ) in ordered_messages
        .into_iter()
        .zip(bound_tree_descriptors)
        .enumerate()
    {
        let root_fill = u8::try_from(logical_root_ordinal + 1)
            .expect("the bounded logical root ordinal fits u8");
        let tree = CommittedMaterialTree::from_canonical_message(
            material_profile,
            [root_fill; 64],
            [root_fill.wrapping_add(0x70); 64],
            &message,
            VSS_ENGINE_TEST_MODULUS,
        )
        .expect("the bounded committed-material tree derives");
        ordered_roots.push(tree.root());
        statement_owned_trees.push(VerifiedStatementOwnedTree::from_committed_material_tree(
            u32::try_from(tree_catalog_index).expect("the bounded tree index fits u32"),
            expected_root_source_ordinal,
            &tree,
            vec![None; column_count],
        ));
        ordered_sources.push(
            AuthenticatedCompactCommittedMaterialSource::from_recomputed_tree_and_canonical_message(
                tree,
                Zeroizing::new(message.into_boxed_slice()),
                VSS_ENGINE_TEST_MODULUS,
            )
            .expect("the bounded committed-material source authenticates"),
        );
    }
    let canonical_application_statement_bytes =
        compact_vss_application_statement(&ordered_roots, 0x51);
    let schema_identifier =
        ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER;
    let suite_identifier = [0x11; 64];
    let application_statement_hash = verified_application_statement_hash(
        FOUNDATION_PROFILE.protocol_version,
        suite_identifier,
        schema_identifier,
        &canonical_application_statement_bytes,
    );
    let relation_plan_capability = CommonProofRelationPlanCapability::from_compiled_plan(
        &relation_plan,
        &relation_context,
        None,
        None,
    )
    .expect("the bounded VSS relation plan is checked");
    let mut compact_adapter = CommittedMaterialSourcePolynomialAdapter::new_vss_share_linkage(
        input,
        &relation_context,
        &relation_plan,
        FOUNDATION_PROFILE.protocol_version,
        suite_identifier,
        application_statement_hash,
        &relation_plan_capability,
        ordered_sources,
    )
    .expect("the bounded authenticated VSS sources prepare the real compact adapter");
    let relation_trees = compact_adapter
        .relation_tree_inputs()
        .expect("the bounded compact adapter releases one exact tree catalog");
    let source_polynomial_provider: Box<dyn CommonProofSourcePolynomialProvider> =
        if mutate_bound_projection {
            let faulted_column_ordinal = selected_variant
                .ordered_columns()
                .iter()
                .position(|column| {
                    matches!(column.origin(), RelationColumnOrigin::BoundTree { .. })
                })
                .and_then(|ordinal| u32::try_from(ordinal).ok())
                .expect("the bounded VSS relation has a bound projection column");
            Box::new(FaultingBoundProjectionProvider {
                inner: compact_adapter,
                faulted_column_ordinal,
                fault_applied: false,
            })
        } else {
            Box::new(compact_adapter)
        };
    CompactVssProofFixture {
        engine: CommonProofEngineFixture {
            relation_context,
            relation_plan,
            canonical_application_statement_bytes,
            relation_trees,
            provided_columns: BTreeMap::new(),
            setup_polynomial_trees: Vec::new(),
            schedule_position: None,
            top_count: None,
        },
        statement_owned_trees,
        source_polynomial_provider: Some(source_polynomial_provider),
    }
}

fn attempt_compact_vss_proof_generation(
    fixture: &mut CompactVssProofFixture,
) -> (Result<(), VssEngineTestGenerationError>, Vec<u8>) {
    let source_polynomial_provider = fixture
        .source_polynomial_provider
        .take()
        .expect("the bounded source provider is consumed exactly once");
    let mut external_memory =
        BoundedInMemoryExternalMemory::new(VSS_ENGINE_TEST_MAXIMUM_EXTERNAL_MEMORY_BYTE_LENGTH);
    let mut private_coins = BoundedDeterministicTestPrivateCoins::new(
        10_000_000,
        VSS_ENGINE_TEST_MAXIMUM_EXTERNAL_MEMORY_BYTE_LENGTH,
    );
    let mut sink = BoundedCommonProofByteSink::new(VSS_ENGINE_TEST_MAXIMUM_PROOF_BYTE_LENGTH)
        .expect("the bounded VSS proof sink initializes");
    let result = generate_common_proof(
        CommonProofGenerationInput {
            protocol_version: FOUNDATION_PROFILE.protocol_version,
            suite_identifier: [0x11; 64],
            canonical_application_statement_bytes: &fixture
                .engine
                .canonical_application_statement_bytes,
            relation_plan: &fixture.engine.relation_plan,
            relation_context: &fixture.engine.relation_context,
            schedule_position: None,
            top_count: None,
            relation_trees: fixture.engine.relation_trees.clone(),
            source_polynomial_provider,
            maximum_external_memory_chunk_byte_length:
                MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
            maximum_proof_transport_chunk_byte_length: MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH,
            maximum_prefetched_query_byte_length: VSS_ENGINE_TEST_MAXIMUM_PROOF_BYTE_LENGTH as u64,
        },
        &mut external_memory,
        &mut private_coins,
        &mut sink,
    );
    (result, sink.finish())
}

fn verify_compact_vss_proof(
    fixture: &CompactVssProofFixture,
    proof_bytes: &[u8],
    canonical_application_statement_bytes: &[u8],
    statement_owned_trees: &[VerifiedStatementOwnedTree],
) -> Result<VerifiedCommonProof, CommonProofVerifierError> {
    verify_common_proof(
        CommonProofVerificationInput {
            protocol_version: FOUNDATION_PROFILE.protocol_version,
            suite_identifier: [0x11; 64],
            canonical_application_statement_bytes,
            relation_plan: &fixture.engine.relation_plan,
            relation_context: &fixture.engine.relation_context,
            schedule_position: None,
            top_count: None,
            statement_owned_trees,
            evaluator_auxiliary_roots: &[],
            proof_source: proof_bytes,
            declared_proof_byte_length: proof_bytes.len(),
            proof_byte_ceiling: VSS_ENGINE_TEST_MAXIMUM_PROOF_BYTE_LENGTH,
        },
        &mut NoVerifiedSequenceColumns,
    )
}

#[test]
fn compact_committed_material_relation_geometry_covers_the_fixed_roster() {
    let input = compact_vss_relation_input();
    assert_eq!(input.participant_count, 10);
    assert_eq!(input.threshold, 4);
    let context = compact_vss_relation_context();
    compile_vss_share_linkage_relation_plan(&input, &context)
        .expect("the bounded fixed-roster VSS relation compiles");
    compile_aggregate_threshold_share_relation_plan(&input, &context)
        .expect("the bounded fixed-roster aggregate-threshold-share relation compiles");
}

#[test]
fn bounded_external_memory_preserves_protection_through_abort_and_lifecycle_reuse() {
    let public_object = ProofExternalMemoryObject::new(1);
    let secret_object = ProofExternalMemoryObject::new(2);
    let mut storage = BoundedInMemoryExternalMemory::new(16);

    storage
        .begin_transaction(4, 6)
        .expect("the bounded mixed-protection transaction begins");
    storage
        .create_object(
            public_object,
            ProofExternalMemoryProtection::PublicIntegrity,
            2,
        )
        .expect("the public-integrity object is created");
    storage
        .append_object_bytes(public_object, 0, &[1, 2])
        .expect("the public-integrity object is written");
    storage
        .seal_object(public_object)
        .expect("the public-integrity object is sealed");
    storage
        .create_object(
            secret_object,
            ProofExternalMemoryProtection::SecretAuthenticatedEncryption,
            2,
        )
        .expect("the secret-bearing object is created");
    storage
        .append_object_bytes(secret_object, 0, &[3, 4])
        .expect("the secret-bearing object is written");
    storage
        .seal_object(secret_object)
        .expect("the secret-bearing object is sealed");
    storage
        .commit_transaction()
        .expect("the mixed-protection transaction commits");
    assert_eq!(
        storage
            .committed
            .get(&public_object)
            .map(|object| object.protection),
        Some(ProofExternalMemoryProtection::PublicIntegrity),
    );
    assert_eq!(
        storage
            .committed
            .get(&secret_object)
            .map(|object| object.protection),
        Some(ProofExternalMemoryProtection::SecretAuthenticatedEncryption),
    );

    storage
        .begin_transaction(2, 1)
        .expect("the bounded secret-read transaction begins");
    let mut secret_bytes = [0_u8; 2];
    storage
        .read_object_bytes(secret_object, 0, &mut secret_bytes)
        .expect("the sealed secret-bearing object is readable");
    storage
        .commit_transaction()
        .expect("the bounded secret-read transaction commits");
    assert_eq!(secret_bytes, [3, 4]);

    storage
        .begin_transaction(0, 1)
        .expect("the bounded delete transaction begins");
    storage
        .delete_object(secret_object)
        .expect("the secret-bearing object is tentatively deleted");
    storage
        .abort_transaction()
        .expect("aborting restores the secret-bearing object");
    let restored_secret_object = storage
        .committed
        .get(&secret_object)
        .expect("the aborted delete restores the exact object");
    assert_eq!(
        restored_secret_object.protection,
        ProofExternalMemoryProtection::SecretAuthenticatedEncryption,
    );
    assert!(restored_secret_object.sealed);
    assert_eq!(restored_secret_object.bytes, [3, 4]);

    storage
        .begin_transaction(0, 1)
        .expect("the committed delete transaction begins");
    storage
        .delete_object(secret_object)
        .expect("the secret-bearing lifecycle is deleted");
    storage
        .commit_transaction()
        .expect("the secret-bearing lifecycle deletion commits");
    storage
        .begin_transaction(2, 3)
        .expect("the reused-ordinal transaction begins");
    storage
        .create_object(
            secret_object,
            ProofExternalMemoryProtection::PublicIntegrity,
            2,
        )
        .expect("a completed ordinal may begin a new public lifecycle");
    storage
        .append_object_bytes(secret_object, 0, &[5, 6])
        .expect("the reused public object is written");
    storage
        .seal_object(secret_object)
        .expect("the reused public object is sealed");
    storage
        .commit_transaction()
        .expect("the reused public lifecycle commits");
    let reused_object = storage
        .committed
        .get(&secret_object)
        .expect("the reused public object is retained");
    assert_eq!(
        reused_object.protection,
        ProofExternalMemoryProtection::PublicIntegrity,
    );
    assert_eq!(reused_object.bytes, [5, 6]);
}

#[test]
fn compact_vss_generation_plan_reuses_storage_and_accepts_canonical_secret_source_replay() {
    let mut fixture = compact_vss_proof_fixture(false, false);
    let relation_plan_capability = CommonProofRelationPlanCapability::from_compiled_plan(
        &fixture.engine.relation_plan,
        &fixture.engine.relation_context,
        None,
        None,
    )
    .expect("the bounded VSS relation plan is checked");
    assert_eq!(
        relation_plan_capability.relation_plan_hash(),
        fixture
            .engine
            .relation_plan
            .canonical_hash()
            .expect("the checked VSS relation plan has one canonical hash"),
        "a checked capability retains the compiled plan's canonical identity",
    );
    let source_polynomial_provider = fixture
        .source_polynomial_provider
        .take()
        .expect("the bounded source provider is consumed exactly once");
    let mut state = CommonProofGenerationStateMachine::new(CommonProofGenerationInput {
        protocol_version: FOUNDATION_PROFILE.protocol_version,
        suite_identifier: [0x11; 64],
        canonical_application_statement_bytes: &fixture
            .engine
            .canonical_application_statement_bytes,
        relation_plan: &fixture.engine.relation_plan,
        relation_context: &fixture.engine.relation_context,
        schedule_position: None,
        top_count: None,
        relation_trees: fixture.engine.relation_trees.clone(),
        source_polynomial_provider,
        maximum_external_memory_chunk_byte_length:
            MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
        maximum_proof_transport_chunk_byte_length: MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH,
        maximum_prefetched_query_byte_length: VSS_ENGINE_TEST_MAXIMUM_PROOF_BYTE_LENGTH as u64,
    })
    .expect("the bounded VSS generation storage plan fits its enforced limits");
    let requirement = state.external_memory_requirement();
    assert!(
        usize::try_from(requirement.distinct_physical_object_count())
            .is_ok_and(|count| count <= MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_OBJECT_COUNT),
        "the bounded VSS plan fits the physical-object ceiling",
    );
    assert!(
        requirement.object_lifecycle_count() > requirement.distinct_physical_object_count(),
        "the bounded VSS plan reuses nonoverlapping physical-object lifecycles",
    );
    assert!(
        usize::try_from(requirement.peak_stored_byte_length())
            .is_ok_and(|bytes| bytes <= VSS_ENGINE_TEST_MAXIMUM_EXTERNAL_MEMORY_BYTE_LENGTH),
        "the bounded VSS plan fits the test backend storage ceiling",
    );
    let mut external_memory =
        BoundedInMemoryExternalMemory::new(VSS_ENGINE_TEST_MAXIMUM_EXTERNAL_MEMORY_BYTE_LENGTH);
    let mut private_coins = BoundedDeterministicTestPrivateCoins::new(
        10_000_000,
        VSS_ENGINE_TEST_MAXIMUM_EXTERNAL_MEMORY_BYTE_LENGTH,
    );
    let mut sink = BoundedCommonProofByteSink::new(VSS_ENGINE_TEST_MAXIMUM_PROOF_BYTE_LENGTH)
        .expect("the bounded VSS proof sink initializes");
    let preparation_poll = state
        .poll(&mut external_memory, &mut private_coins, &mut sink)
        .expect("the bounded generation state prepares its canonical source cursor");
    assert_eq!(
        preparation_poll,
        CommonProofGenerationPoll::ArithmeticStepCompleted,
    );
    let first_source_poll = state
        .poll(&mut external_memory, &mut private_coins, &mut sink)
        .expect("the first committed-material source accepts the canonical relation-plan binding");
    assert_eq!(
        first_source_poll,
        CommonProofGenerationPoll::ArithmeticStepCompleted,
    );
    let first_source_storage_poll = state
        .poll(&mut external_memory, &mut private_coins, &mut sink)
        .expect("the first secret-bearing source begins its bounded replay object");
    assert_eq!(
        first_source_storage_poll,
        CommonProofGenerationPoll::StorageTransactionCompleted,
    );
}

#[test]
fn authenticated_compact_vss_source_refuses_a_detached_canonical_message() {
    let material_profile = CommittedMaterialProfile::for_common_proof_evaluation_domain(
        VSS_ENGINE_TEST_RING_DEGREE,
        VSS_ENGINE_TEST_EVALUATION_DOMAIN_SIZE,
    )
    .expect("the bounded committed-material profile derives");
    let canonical_message = compact_vss_messages()
        .into_iter()
        .next()
        .expect("the first deterministic coefficient message exists");
    let tree = CommittedMaterialTree::from_canonical_message(
        material_profile,
        [0x21; 64],
        [0x42; 64],
        &canonical_message,
        VSS_ENGINE_TEST_MODULUS,
    )
    .expect("the bounded committed-material tree derives");
    let mut detached_message = canonical_message;
    detached_message[0] = (detached_message[0] + 1) % VSS_ENGINE_TEST_MODULUS;
    assert_eq!(
        AuthenticatedCompactCommittedMaterialSource::from_recomputed_tree_and_canonical_message(
            tree,
            Zeroizing::new(detached_message.into_boxed_slice()),
            VSS_ENGINE_TEST_MODULUS,
        )
        .expect_err("a changed canonical message cannot inherit another source root"),
        CommittedMaterialError::InvalidInput,
    );
}

#[test]
#[ignore = "manual guarded compact committed-material proof evidence"]
fn heavy_rust_kernel_compact_vss_share_linkage_proof_verifies_and_refuses_each_bound_mutation() {
    let mut positive_fixture = compact_vss_proof_fixture(false, false);
    let (positive_result, proof_bytes) =
        attempt_compact_vss_proof_generation(&mut positive_fixture);
    positive_result.expect("the real compact VSS adapter generates one bounded common proof");
    assert!(!proof_bytes.is_empty());
    assert!(proof_bytes.len() <= VSS_ENGINE_TEST_MAXIMUM_PROOF_BYTE_LENGTH);
    let verified = verify_compact_vss_proof(
        &positive_fixture,
        &proof_bytes,
        &positive_fixture
            .engine
            .canonical_application_statement_bytes,
        &positive_fixture.statement_owned_trees,
    )
    .expect("the independently supplied committed roots verify the bounded VSS proof");
    assert_eq!(
        verified.application_statement_schema_identifier(),
        ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
    );

    let mut wrong_root_trees = positive_fixture.statement_owned_trees.clone();
    let mut wrong_root = wrong_root_trees[0].expected_root();
    wrong_root[0] ^= 1;
    wrong_root_trees[0] = wrong_root_trees[0].with_test_expected_root(wrong_root);
    let wrong_root_error = match verify_compact_vss_proof(
        &positive_fixture,
        &proof_bytes,
        &positive_fixture
            .engine
            .canonical_application_statement_bytes,
        &wrong_root_trees,
    ) {
        Ok(_) => panic!("a changed statement-owned source root must refuse"),
        Err(error) => error,
    };
    assert_eq!(wrong_root_error, CommonProofVerifierError::InvalidBoundTree);

    let statement_roots = positive_fixture
        .statement_owned_trees
        .iter()
        .map(VerifiedStatementOwnedTree::expected_root)
        .collect::<Vec<_>>();
    let changed_proof_binding = compact_vss_application_statement(&statement_roots, 0x52);
    let changed_binding_error = match verify_compact_vss_proof(
        &positive_fixture,
        &proof_bytes,
        &changed_proof_binding,
        &positive_fixture.statement_owned_trees,
    ) {
        Ok(_) => panic!("a changed canonical application binding must refuse"),
        Err(error) => error,
    };
    assert_eq!(
        changed_binding_error,
        CommonProofVerifierError::InvalidProofHeader,
    );

    let mut quotient_fault_fixture = compact_vss_proof_fixture(true, false);
    let (quotient_fault_result, _) =
        attempt_compact_vss_proof_generation(&mut quotient_fault_fixture);
    assert!(matches!(
        quotient_fault_result,
        Err(CommonProofGenerationError::Prover(
            CommonProofProverError::InvalidColumn
        )),
    ));

    let mut projection_fault_fixture = compact_vss_proof_fixture(false, true);
    let (projection_fault_result, _) =
        attempt_compact_vss_proof_generation(&mut projection_fault_fixture);
    assert!(matches!(
        projection_fault_result,
        Err(CommonProofGenerationError::Prover(
            CommonProofProverError::InvalidTree
        )),
    ));
}

const AGGREGATE_THRESHOLD_SHARE_ENGINE_TEST_SUITE_IDENTIFIER: [u8; 64] = [0x31; 64];

type AggregateThresholdShareEngineTestGenerationError = CommonProofGenerationError<
    TestExternalMemoryError,
    TestPrivateCoinError,
    crate::bgv::proof_suite::prover::BoundedCommonProofByteSinkError,
>;

#[derive(Clone, Copy)]
enum AggregateThresholdShareColumnFault {
    BoundProjection,
    AggregateQuotient,
}

struct CompactAggregateThresholdShareProofFixture {
    engine: CommonProofEngineFixture,
    statement_owned_trees: Vec<VerifiedStatementOwnedTree>,
    source_polynomial_provider: Option<Box<dyn CommonProofSourcePolynomialProvider>>,
}

struct FaultingAggregateThresholdShareColumnProvider {
    inner: CommittedMaterialSourcePolynomialAdapter,
    faulted_column_ordinal: u32,
    fault_applied: bool,
}

impl CommonProofSourcePolynomialProvider for FaultingAggregateThresholdShareColumnProvider {
    fn memory_accounting(
        &self,
    ) -> Result<CommonProofSourceProviderMemoryAccounting, CommonProofProverError> {
        self.inner.memory_accounting()
    }

    fn poll_source_polynomial(
        &mut self,
        request: CommonProofSourcePolynomialRequest<'_>,
    ) -> Result<CommonProofSourcePolynomialProviderPoll, CommonProofProverError> {
        let requested_column_ordinal = request.column_ordinal();
        match self.inner.poll_source_polynomial(request)? {
            CommonProofSourcePolynomialProviderPoll::Ready(provided)
                if requested_column_ordinal == self.faulted_column_ordinal =>
            {
                assert!(
                    !self.fault_applied,
                    "the aggregate column fault is one-shot"
                );
                self.fault_applied = true;
                let (mut polynomial, replay_identity) = provided.into_parts_for_test();
                let CommonProofSourcePolynomial::Base(coefficients) = &mut polynomial else {
                    panic!("an aggregate committed-material column uses the base field");
                };
                let first_coefficient = coefficients
                    .first_mut()
                    .expect("an aggregate committed-material column is nonempty");
                *first_coefficient = first_coefficient.add(ProofBaseFieldElement::ONE);
                Ok(CommonProofSourcePolynomialProviderPoll::Ready(
                    ProvidedCommonProofSourcePolynomial::new(polynomial, replay_identity),
                ))
            }
            poll => Ok(poll),
        }
    }

    fn pending_authenticated_source_read_request(
        &self,
    ) -> Result<Option<CommonProofAuthenticatedSourceReadRequest>, CommonProofProverError> {
        self.inner.pending_authenticated_source_read_request()
    }

    fn supply_authenticated_source_range(
        &mut self,
        request: CommonProofAuthenticatedSourceReadRequest,
        authenticated_bytes: Zeroizing<Box<[u8]>>,
    ) -> Result<(), CommonProofProverError> {
        self.inner
            .supply_authenticated_source_range(request, authenticated_bytes)
    }

    fn cancel_pending_authenticated_source_read(&mut self) {
        self.inner.cancel_pending_authenticated_source_read();
    }

    fn finish(&mut self) -> Result<(), CommonProofProverError> {
        if !self.fault_applied {
            return Err(CommonProofProverError::InvalidColumn);
        }
        self.inner.finish()
    }

    fn provide_bound_tree_leaf_salt(
        &mut self,
        request: CommonProofBoundTreeLeafSaltRequest,
    ) -> Result<Option<[u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]>, CommonProofProverError>
    {
        self.inner.provide_bound_tree_leaf_salt(request)
    }

    fn finish_bound_tree_leaf_salts(&mut self) -> Result<(), CommonProofProverError> {
        self.inner.finish_bound_tree_leaf_salts()
    }

    fn rewind_bound_tree_leaf_salts(&mut self) -> Result<(), CommonProofProverError> {
        self.inner.rewind_bound_tree_leaf_salts()
    }
}

fn compact_aggregate_threshold_share_relation_input() -> CommittedMaterialRelationPlanInput {
    compact_vss_relation_input()
}

fn compact_aggregate_threshold_share_relation_context() -> RelationPlanCheckContext {
    compact_vss_relation_context()
}

fn compact_aggregate_threshold_share_messages() -> Vec<Vec<u64>> {
    let participant_count = usize::from(FOUNDATION_PROFILE.participant_count);
    let source_messages = (0..participant_count)
        .map(|source_ordinal| {
            (0..VSS_ENGINE_TEST_RING_DEGREE)
                .map(|coefficient_ordinal| {
                    (u64::try_from(source_ordinal + 2).expect("the source ordinal fits u64")
                        * 19
                        * u64::try_from(coefficient_ordinal + 5)
                            .expect("the coefficient ordinal fits u64")
                        + u64::try_from(source_ordinal * 13 + coefficient_ordinal * 7 + 3)
                            .expect("the deterministic source offset fits u64"))
                        % VSS_ENGINE_TEST_MODULUS
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let aggregate_message = source_messages.iter().fold(
        vec![0_u64; VSS_ENGINE_TEST_RING_DEGREE],
        |accumulated, source_message| {
            add_canonical_messages(&accumulated, source_message, VSS_ENGINE_TEST_MODULUS)
        },
    );
    source_messages
        .into_iter()
        .chain(std::iter::once(aggregate_message))
        .collect()
}

fn compact_aggregate_threshold_share_application_statement(
    ordered_source_roots: &[[u8; 64]],
    ordered_aggregate_roots: &[[u8; 64]],
    action_context_fill: u8,
) -> Vec<u8> {
    let source_root_items = ordered_source_roots
        .iter()
        .copied()
        .map(CanonicalItem::hash512)
        .collect::<Vec<_>>();
    let aggregate_root_items = ordered_aggregate_roots
        .iter()
        .copied()
        .map(CanonicalItem::hash512)
        .collect::<Vec<_>>();
    CanonicalTuple::new(
        ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
        SCHEMA_VERSION,
        vec![
            CanonicalItem::unsigned16(FOUNDATION_PROFILE.protocol_version),
            CanonicalItem::hash512(AGGREGATE_THRESHOLD_SHARE_ENGINE_TEST_SUITE_IDENTIFIER),
            CanonicalItem::hash512([0x41; 64]),
            CanonicalItem::hash512([action_context_fill; 64]),
            CanonicalItem::hash512([0x43; 64]),
            CanonicalItem::participant_identity([0x44; 64]),
            CanonicalItem::unsigned16(0),
            CanonicalItem::hash512([0x45; 64]),
            CanonicalItem::homogeneous_list(CanonicalItemType::Hash512, &source_root_items)
                .expect("the bounded aggregate source-root list encodes"),
            CanonicalItem::homogeneous_list(CanonicalItemType::Hash512, &aggregate_root_items)
                .expect("the bounded aggregate output-root list encodes"),
        ],
    )
    .encode()
    .expect("the bounded aggregate-threshold-share statement encodes")
}

fn compact_aggregate_threshold_share_proof_fixture(
    column_fault: Option<AggregateThresholdShareColumnFault>,
) -> CompactAggregateThresholdShareProofFixture {
    let input = compact_aggregate_threshold_share_relation_input();
    let relation_context = compact_aggregate_threshold_share_relation_context();
    let relation_plan = compile_aggregate_threshold_share_relation_plan(&input, &relation_context)
        .expect("the bounded fixed-roster aggregate-threshold-share relation compiles");
    let selected_variant = relation_plan
        .select_variant(None, None)
        .expect("the bounded aggregate-threshold-share relation has one variant");
    let material_profile = CommittedMaterialProfile::for_common_proof_evaluation_domain(
        VSS_ENGINE_TEST_RING_DEGREE,
        VSS_ENGINE_TEST_EVALUATION_DOMAIN_SIZE,
    )
    .expect("the bounded committed-material profile derives");
    let bound_tree_descriptors = selected_variant
        .ordered_trees()
        .iter()
        .enumerate()
        .filter_map(|(tree_catalog_index, descriptor)| match descriptor {
            RelationTreeDescriptor::BoundPublic {
                expected_root_source_ordinal,
                ordered_column_ordinals,
                ..
            } => Some((
                tree_catalog_index,
                *expected_root_source_ordinal,
                ordered_column_ordinals
                    .iter()
                    .map(|column_ordinal| {
                        selected_variant.ordered_columns()[*column_ordinal as usize]
                            .canonical_residue_modulus()
                    })
                    .collect::<Vec<_>>(),
            )),
            RelationTreeDescriptor::ProofCreated { .. } => None,
        })
        .collect::<Vec<_>>();
    let ordered_messages = compact_aggregate_threshold_share_messages();
    assert_eq!(bound_tree_descriptors.len(), ordered_messages.len());
    let mut statement_owned_trees = Vec::with_capacity(ordered_messages.len());
    let mut ordered_sources = Vec::with_capacity(ordered_messages.len());
    let mut ordered_roots = Vec::with_capacity(ordered_messages.len());
    for (
        logical_root_ordinal,
        (
            message,
            (tree_catalog_index, expected_root_source_ordinal, ordered_canonical_residue_moduli),
        ),
    ) in ordered_messages
        .into_iter()
        .zip(bound_tree_descriptors)
        .enumerate()
    {
        let root_fill = u8::try_from(logical_root_ordinal + 0x51)
            .expect("the bounded aggregate logical root ordinal fits u8");
        let tree = CommittedMaterialTree::from_canonical_message(
            material_profile,
            [root_fill; 64],
            [root_fill.wrapping_add(0x30); 64],
            &message,
            VSS_ENGINE_TEST_MODULUS,
        )
        .expect("the bounded aggregate committed-material tree derives");
        ordered_roots.push(tree.root());
        statement_owned_trees.push(VerifiedStatementOwnedTree::from_committed_material_tree(
            u32::try_from(tree_catalog_index).expect("the bounded tree index fits u32"),
            expected_root_source_ordinal,
            &tree,
            ordered_canonical_residue_moduli,
        ));
        ordered_sources.push(
            AuthenticatedCompactCommittedMaterialSource::from_recomputed_tree_and_canonical_message(
                tree,
                Zeroizing::new(message.into_boxed_slice()),
                VSS_ENGINE_TEST_MODULUS,
            )
            .expect("the bounded aggregate committed-material source authenticates"),
        );
    }
    let source_root_count = usize::from(input.participant_count)
        .checked_mul(input.sharing_data_modulus_indices.len())
        .expect("the bounded aggregate source-root count derives");
    let (ordered_source_roots, ordered_aggregate_roots) = ordered_roots.split_at(source_root_count);
    let canonical_application_statement_bytes =
        compact_aggregate_threshold_share_application_statement(
            ordered_source_roots,
            ordered_aggregate_roots,
            0x42,
        );
    let schema_identifier =
        ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER;
    let application_statement_hash = verified_application_statement_hash(
        FOUNDATION_PROFILE.protocol_version,
        AGGREGATE_THRESHOLD_SHARE_ENGINE_TEST_SUITE_IDENTIFIER,
        schema_identifier,
        &canonical_application_statement_bytes,
    );
    let relation_plan_capability = CommonProofRelationPlanCapability::from_compiled_plan(
        &relation_plan,
        &relation_context,
        None,
        None,
    )
    .expect("the bounded aggregate-threshold-share relation plan is checked");
    let mut compact_adapter =
        CommittedMaterialSourcePolynomialAdapter::new_aggregate_threshold_share(
            input,
            &relation_context,
            &relation_plan,
            FOUNDATION_PROFILE.protocol_version,
            AGGREGATE_THRESHOLD_SHARE_ENGINE_TEST_SUITE_IDENTIFIER,
            application_statement_hash,
            &relation_plan_capability,
            ordered_sources,
        )
        .expect("the bounded authenticated aggregate sources prepare the real compact adapter");
    let faulted_column_ordinal = column_fault.map(|fault| {
        let [
            projection_column_ordinal,
            _digit_column_ordinal,
            quotient_column_ordinal,
        ] = compact_adapter
            .representative_aggregate_projection_digit_and_quotient_column_ordinals()
            .expect("the aggregate witness exposes distinct semantic test columns");
        match fault {
            AggregateThresholdShareColumnFault::BoundProjection => projection_column_ordinal,
            AggregateThresholdShareColumnFault::AggregateQuotient => quotient_column_ordinal,
        }
    });
    let relation_trees = compact_adapter
        .relation_tree_inputs()
        .expect("the bounded aggregate compact adapter releases one exact tree catalog");
    let source_polynomial_provider: Box<dyn CommonProofSourcePolynomialProvider> =
        match faulted_column_ordinal {
            Some(faulted_column_ordinal) => {
                Box::new(FaultingAggregateThresholdShareColumnProvider {
                    inner: compact_adapter,
                    faulted_column_ordinal,
                    fault_applied: false,
                })
            }
            None => Box::new(compact_adapter),
        };
    CompactAggregateThresholdShareProofFixture {
        engine: CommonProofEngineFixture {
            relation_context,
            relation_plan,
            canonical_application_statement_bytes,
            relation_trees,
            provided_columns: BTreeMap::new(),
            setup_polynomial_trees: Vec::new(),
            schedule_position: None,
            top_count: None,
        },
        statement_owned_trees,
        source_polynomial_provider: Some(source_polynomial_provider),
    }
}

fn attempt_compact_aggregate_threshold_share_proof_generation(
    fixture: &mut CompactAggregateThresholdShareProofFixture,
) -> (
    Result<(), AggregateThresholdShareEngineTestGenerationError>,
    Vec<u8>,
) {
    let source_polynomial_provider = fixture
        .source_polynomial_provider
        .take()
        .expect("the bounded aggregate source provider is consumed exactly once");
    let mut external_memory =
        BoundedInMemoryExternalMemory::new(VSS_ENGINE_TEST_MAXIMUM_EXTERNAL_MEMORY_BYTE_LENGTH);
    let mut private_coins = BoundedDeterministicTestPrivateCoins::new(
        10_000_000,
        VSS_ENGINE_TEST_MAXIMUM_EXTERNAL_MEMORY_BYTE_LENGTH,
    );
    let mut sink = BoundedCommonProofByteSink::new(VSS_ENGINE_TEST_MAXIMUM_PROOF_BYTE_LENGTH)
        .expect("the bounded aggregate proof sink initializes");
    let result = generate_common_proof(
        CommonProofGenerationInput {
            protocol_version: FOUNDATION_PROFILE.protocol_version,
            suite_identifier: AGGREGATE_THRESHOLD_SHARE_ENGINE_TEST_SUITE_IDENTIFIER,
            canonical_application_statement_bytes: &fixture
                .engine
                .canonical_application_statement_bytes,
            relation_plan: &fixture.engine.relation_plan,
            relation_context: &fixture.engine.relation_context,
            schedule_position: None,
            top_count: None,
            relation_trees: fixture.engine.relation_trees.clone(),
            source_polynomial_provider,
            maximum_external_memory_chunk_byte_length:
                MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
            maximum_proof_transport_chunk_byte_length: MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH,
            maximum_prefetched_query_byte_length: VSS_ENGINE_TEST_MAXIMUM_PROOF_BYTE_LENGTH as u64,
        },
        &mut external_memory,
        &mut private_coins,
        &mut sink,
    );
    (result, sink.finish())
}

fn verify_compact_aggregate_threshold_share_proof(
    fixture: &CompactAggregateThresholdShareProofFixture,
    proof_bytes: &[u8],
    canonical_application_statement_bytes: &[u8],
    statement_owned_trees: &[VerifiedStatementOwnedTree],
) -> Result<VerifiedCommonProof, CommonProofVerifierError> {
    verify_common_proof(
        CommonProofVerificationInput {
            protocol_version: FOUNDATION_PROFILE.protocol_version,
            suite_identifier: AGGREGATE_THRESHOLD_SHARE_ENGINE_TEST_SUITE_IDENTIFIER,
            canonical_application_statement_bytes,
            relation_plan: &fixture.engine.relation_plan,
            relation_context: &fixture.engine.relation_context,
            schedule_position: None,
            top_count: None,
            statement_owned_trees,
            evaluator_auxiliary_roots: &[],
            proof_source: proof_bytes,
            declared_proof_byte_length: proof_bytes.len(),
            proof_byte_ceiling: VSS_ENGINE_TEST_MAXIMUM_PROOF_BYTE_LENGTH,
        },
        &mut NoVerifiedSequenceColumns,
    )
}

#[test]
fn authenticated_compact_aggregate_threshold_share_source_refuses_a_detached_canonical_message() {
    let material_profile = CommittedMaterialProfile::for_common_proof_evaluation_domain(
        VSS_ENGINE_TEST_RING_DEGREE,
        VSS_ENGINE_TEST_EVALUATION_DOMAIN_SIZE,
    )
    .expect("the bounded committed-material profile derives");
    let canonical_message = compact_aggregate_threshold_share_messages()
        .into_iter()
        .next()
        .expect("the first deterministic aggregate source message exists");
    let tree = CommittedMaterialTree::from_canonical_message(
        material_profile,
        [0x61; 64],
        [0x62; 64],
        &canonical_message,
        VSS_ENGINE_TEST_MODULUS,
    )
    .expect("the bounded aggregate committed-material tree derives");
    let mut detached_message = canonical_message;
    detached_message[0] = (detached_message[0] + 1) % VSS_ENGINE_TEST_MODULUS;
    assert_eq!(
        AuthenticatedCompactCommittedMaterialSource::from_recomputed_tree_and_canonical_message(
            tree,
            Zeroizing::new(detached_message.into_boxed_slice()),
            VSS_ENGINE_TEST_MODULUS,
        )
        .expect_err("a changed aggregate source message cannot inherit another source root"),
        CommittedMaterialError::InvalidInput,
    );
}

#[test]
#[ignore = "manual guarded compact aggregate-threshold-share proof evidence"]
fn heavy_rust_kernel_compact_aggregate_threshold_share_proof_verifies_and_refuses_each_bound_mutation()
 {
    let mut positive_fixture = compact_aggregate_threshold_share_proof_fixture(None);
    let (positive_result, proof_bytes) =
        attempt_compact_aggregate_threshold_share_proof_generation(&mut positive_fixture);
    positive_result
        .expect("the real compact aggregate-threshold-share adapter generates a bounded proof");
    assert!(!proof_bytes.is_empty());
    assert!(proof_bytes.len() <= VSS_ENGINE_TEST_MAXIMUM_PROOF_BYTE_LENGTH);
    let verified = verify_compact_aggregate_threshold_share_proof(
        &positive_fixture,
        &proof_bytes,
        &positive_fixture
            .engine
            .canonical_application_statement_bytes,
        &positive_fixture.statement_owned_trees,
    )
    .expect("the independently supplied aggregate roots verify the bounded proof");
    assert_eq!(
        verified.application_statement_schema_identifier(),
        ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
    );

    let mut wrong_root_trees = positive_fixture.statement_owned_trees.clone();
    let mut wrong_root = wrong_root_trees[0].expected_root();
    wrong_root[0] ^= 1;
    wrong_root_trees[0] = wrong_root_trees[0].with_test_expected_root(wrong_root);
    let wrong_root_error = match verify_compact_aggregate_threshold_share_proof(
        &positive_fixture,
        &proof_bytes,
        &positive_fixture
            .engine
            .canonical_application_statement_bytes,
        &wrong_root_trees,
    ) {
        Ok(_) => panic!("a changed aggregate statement-owned source root must refuse"),
        Err(error) => error,
    };
    assert_eq!(wrong_root_error, CommonProofVerifierError::InvalidBoundTree);

    let source_root_count = usize::from(FOUNDATION_PROFILE.participant_count);
    let statement_roots = positive_fixture
        .statement_owned_trees
        .iter()
        .map(VerifiedStatementOwnedTree::expected_root)
        .collect::<Vec<_>>();
    let changed_proof_binding = compact_aggregate_threshold_share_application_statement(
        &statement_roots[..source_root_count],
        &statement_roots[source_root_count..],
        0x46,
    );
    let changed_binding_error = match verify_compact_aggregate_threshold_share_proof(
        &positive_fixture,
        &proof_bytes,
        &changed_proof_binding,
        &positive_fixture.statement_owned_trees,
    ) {
        Ok(_) => panic!("a changed aggregate canonical application binding must refuse"),
        Err(error) => error,
    };
    assert_eq!(
        changed_binding_error,
        CommonProofVerifierError::InvalidProofHeader,
    );

    let mut projection_fault_fixture = compact_aggregate_threshold_share_proof_fixture(Some(
        AggregateThresholdShareColumnFault::BoundProjection,
    ));
    let (projection_fault_result, _) =
        attempt_compact_aggregate_threshold_share_proof_generation(&mut projection_fault_fixture);
    assert!(matches!(
        projection_fault_result,
        Err(CommonProofGenerationError::Prover(
            CommonProofProverError::InvalidTree
        )),
    ));

    let mut quotient_fault_fixture = compact_aggregate_threshold_share_proof_fixture(Some(
        AggregateThresholdShareColumnFault::AggregateQuotient,
    ));
    let (quotient_fault_result, _) =
        attempt_compact_aggregate_threshold_share_proof_generation(&mut quotient_fault_fixture);
    assert!(matches!(
        quotient_fault_result,
        Err(CommonProofGenerationError::Prover(
            CommonProofProverError::InvalidColumn
        )),
    ));
}

#[test]
fn every_public_aggregate_family_uses_the_generated_prover_and_capability_verifier() {
    let rkg_context = relation_context();
    let rkg_plan = compile_rkg_round_one_aggregate_relation_plan(
        &RkgRoundOneAggregatePlanInput {
            geometry: public_aggregate_geometry(),
            ordered_variants: vec![RkgRoundOneAggregateVariantInput {
                schedule_position: 7,
                ordered_left_component_moduli: vec![SuiteModulusReference::data(0)],
                ordered_right_component_moduli: vec![SuiteModulusReference::data(0)],
            }],
        },
        &rkg_context,
    )
    .expect("the round-one aggregate relation compiles");
    let mut rkg_fixture = public_aggregate_common_proof_fixture(
        rkg_context,
        rkg_plan,
        &[7, 11, 18, 13, 17, 30],
        canonical_rkg_round_one_aggregate_statement,
        Some(7),
        None,
    );
    let rkg_trees = verified_statement_trees(
        &rkg_fixture.relation_plan,
        &rkg_fixture.setup_polynomial_trees,
        None,
        rkg_fixture.schedule_position,
        rkg_fixture.top_count,
    );
    let rkg_proof = generate_fixture_proof(&mut rkg_fixture);
    let verified_rkg = verify_fixture_proof_capability(
        &rkg_fixture,
        &rkg_proof,
        &rkg_fixture.canonical_application_statement_bytes,
        &rkg_trees,
    )
    .expect("the round-one aggregate common proof verifies");
    assert_eq!(
        verified_rkg.application_statement_schema_identifier(),
        RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
    );
    assert_eq!(verified_rkg.schedule_position(), Some(7));
    assert_eq!(verified_rkg.top_count(), None);

    let evaluator_context = relation_context();
    let evaluator_plan = compile_evaluator_key_aggregate_relation_plan(
        &EvaluatorKeyAggregatePlanInput {
            geometry: public_aggregate_geometry(),
            ordered_variants: (1..=FOUNDATION_PROFILE.option_count)
                .map(|top_count| EvaluatorKeyAggregateVariantInput {
                    top_count,
                    ordered_entries: vec![EvaluatorKeyAggregateEntryPlanInput {
                        schedule_position: 3,
                        ordered_runtime_component_moduli: vec![SuiteModulusReference::data(0)],
                    }],
                })
                .collect(),
        },
        &evaluator_context,
    )
    .expect("the evaluator aggregate relation compiles");
    let mut evaluator_fixture = public_aggregate_common_proof_fixture(
        evaluator_context,
        evaluator_plan,
        &[5, 9, 14],
        canonical_evaluator_key_aggregate_statement,
        None,
        Some(FOUNDATION_PROFILE.option_count),
    );
    let evaluator_trees = verified_statement_trees(
        &evaluator_fixture.relation_plan,
        &evaluator_fixture.setup_polynomial_trees,
        None,
        evaluator_fixture.schedule_position,
        evaluator_fixture.top_count,
    );
    let evaluator_proof = generate_fixture_proof(&mut evaluator_fixture);
    let verified_evaluator = verify_fixture_proof_capability(
        &evaluator_fixture,
        &evaluator_proof,
        &evaluator_fixture.canonical_application_statement_bytes,
        &evaluator_trees,
    )
    .expect("the evaluator aggregate common proof verifies");
    assert_eq!(
        verified_evaluator.application_statement_schema_identifier(),
        EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
    );
    assert_eq!(verified_evaluator.schedule_position(), None);
    assert_eq!(
        verified_evaluator.top_count(),
        Some(FOUNDATION_PROFILE.option_count)
    );
    assert_ne!(
        verified_rkg.application_statement_hash(),
        verified_evaluator.application_statement_hash()
    );
}
