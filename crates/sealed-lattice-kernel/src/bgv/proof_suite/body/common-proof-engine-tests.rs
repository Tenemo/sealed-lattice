use std::collections::BTreeMap;

use crate::foundation::{CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple};

use super::super::relation_plan::RelationTreeDescriptor;
use super::super::{
    BoundedCommonProofByteSink, CollectivePublicKeyAggregatePlanInput,
    CommonProofBoundOpeningProvider, CommonProofEncodingError, CommonProofGenerationInput,
    CommonProofOpeningArtifact, CommonProofOpeningGeometry, CommonProofPrivateCoinSource,
    CommonProofQuerySectionWriter, CommonProofSourcePolynomial, CommonProofVerificationInput,
    CommonProofVerifierError, CompiledRelationPlan, PROOF_BASE_FIELD_MODULUS,
    PROOF_CHALLENGE_EXTENSION_DEGREE, PROOF_DEEP_POINT_COUNT, PROOF_EVALUATION_BLOWUP_FACTOR,
    PROOF_EVALUATION_COSET_OFFSET, PROOF_FINAL_POLYNOMIAL_DEGREE_BOUND_EXCLUSIVE,
    PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
    PROOF_NON_NATIVE_IDENTITY_CHALLENGE_COUNT, PROOF_UNIQUE_QUERY_COUNT, ProofBaseFieldElement,
    ProofEvaluationDomain, ProofExternalMemory, ProofExternalMemoryObject,
    ProofExternalMemoryProtection, ProofTreeCatalogEntry, PublicAggregateRelationGeometry,
    RelationPlanCheckContext, RelationProofTreeInput, ResolvedSuiteModulus,
    StatementOwnedProofTreeInput, SuiteModulusReference, VerifiedRelationColumnEvaluator,
    VerifiedStatementOwnedTree, canonical_proof_object_header_bytes,
    compile_collective_public_key_aggregate_relation_plan, generate_common_proof,
    verify_common_proof,
};
use super::{
    ProofTreeConstruction, SCHEMA_VERSION, SETUP_PUBLIC_POLYNOMIAL_LEAF_HASH_DOMAIN,
    SETUP_PUBLIC_POLYNOMIAL_PHASE_PAIR_LEAF_SCHEMA_IDENTIFIER, hash_canonical_leaf,
    statement_owned_node_digest,
};

const APPLICATION_STATEMENT_SCHEMA_IDENTIFIER: u16 = 0x1213;
const EVALUATION_DOMAIN_SIZE: u64 = 4_096;
const OPENING_DEGREE_BOUND_EXCLUSIVE: u64 = 258;
const MAXIMUM_PROOF_BYTE_LENGTH: usize = 16 * 1_024 * 1_024;
const MAXIMUM_EXTERNAL_MEMORY_BYTE_LENGTH: usize = 64 * 1_024 * 1_024;
const MAXIMUM_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH: u32 = 1_024 * 1_024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TestExternalMemoryError {
    DuplicateTransaction,
    MissingTransaction,
    DuplicateObject,
    MissingObject,
    UnsupportedProtection,
    OperationLimitExceeded,
    PayloadLimitExceeded,
    StorageLimitExceeded,
    WrongOffsetOrLength,
}

struct TestExternalMemoryObject {
    bytes: Vec<u8>,
    exact_byte_length: usize,
    sealed: bool,
}

enum TestExternalMemoryUndo {
    RemoveCreated(ProofExternalMemoryObject),
    TruncateAppended {
        object: ProofExternalMemoryObject,
        previous_byte_length: usize,
    },
    RestoreSeal {
        object: ProofExternalMemoryObject,
        previous_sealed: bool,
    },
    RestoreDeleted {
        object: ProofExternalMemoryObject,
        value: TestExternalMemoryObject,
    },
}

struct TestExternalMemoryTransaction {
    objects: BTreeMap<ProofExternalMemoryObject, TestExternalMemoryObject>,
    undo: Vec<TestExternalMemoryUndo>,
    remaining_payload_byte_length: usize,
    remaining_operation_count: u32,
}

struct BoundedInMemoryExternalMemory {
    maximum_byte_length: usize,
    committed: BTreeMap<ProofExternalMemoryObject, TestExternalMemoryObject>,
    transaction: Option<TestExternalMemoryTransaction>,
}

impl BoundedInMemoryExternalMemory {
    fn new(maximum_byte_length: usize) -> Self {
        Self {
            maximum_byte_length,
            committed: BTreeMap::new(),
            transaction: None,
        }
    }

    fn transaction_for_operation(
        &mut self,
        payload_byte_length: usize,
    ) -> Result<&mut TestExternalMemoryTransaction, TestExternalMemoryError> {
        let transaction = self
            .transaction
            .as_mut()
            .ok_or(TestExternalMemoryError::MissingTransaction)?;
        transaction.remaining_operation_count = transaction
            .remaining_operation_count
            .checked_sub(1)
            .ok_or(TestExternalMemoryError::OperationLimitExceeded)?;
        transaction.remaining_payload_byte_length = transaction
            .remaining_payload_byte_length
            .checked_sub(payload_byte_length)
            .ok_or(TestExternalMemoryError::PayloadLimitExceeded)?;
        Ok(transaction)
    }
}

impl ProofExternalMemory for BoundedInMemoryExternalMemory {
    type Error = TestExternalMemoryError;

    fn begin_transaction(
        &mut self,
        maximum_payload_byte_length: u64,
        maximum_operation_count: u32,
    ) -> Result<(), Self::Error> {
        if self.transaction.is_some() {
            return Err(TestExternalMemoryError::DuplicateTransaction);
        }
        let mut undo = Vec::new();
        undo.try_reserve_exact(
            usize::try_from(maximum_operation_count)
                .map_err(|_| TestExternalMemoryError::StorageLimitExceeded)?,
        )
        .map_err(|_| TestExternalMemoryError::StorageLimitExceeded)?;
        self.transaction = Some(TestExternalMemoryTransaction {
            objects: std::mem::take(&mut self.committed),
            undo,
            remaining_payload_byte_length: usize::try_from(maximum_payload_byte_length)
                .map_err(|_| TestExternalMemoryError::PayloadLimitExceeded)?,
            remaining_operation_count: maximum_operation_count,
        });
        Ok(())
    }

    fn create_object(
        &mut self,
        object: ProofExternalMemoryObject,
        protection: ProofExternalMemoryProtection,
        exact_byte_length: u64,
    ) -> Result<(), Self::Error> {
        if protection != ProofExternalMemoryProtection::PublicIntegrity {
            return Err(TestExternalMemoryError::UnsupportedProtection);
        }
        let maximum_byte_length = self.maximum_byte_length;
        let exact_byte_length = usize::try_from(exact_byte_length)
            .map_err(|_| TestExternalMemoryError::StorageLimitExceeded)?;
        let transaction = self.transaction_for_operation(0)?;
        if transaction.objects.contains_key(&object) {
            return Err(TestExternalMemoryError::DuplicateObject);
        }
        transaction
            .objects
            .values()
            .try_fold(0_usize, |total, object| {
                total.checked_add(object.exact_byte_length)
            })
            .and_then(|total| total.checked_add(exact_byte_length))
            .filter(|total| *total <= maximum_byte_length)
            .ok_or(TestExternalMemoryError::StorageLimitExceeded)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(exact_byte_length)
            .map_err(|_| TestExternalMemoryError::StorageLimitExceeded)?;
        transaction.objects.insert(
            object,
            TestExternalMemoryObject {
                bytes,
                exact_byte_length,
                sealed: false,
            },
        );
        transaction
            .undo
            .push(TestExternalMemoryUndo::RemoveCreated(object));
        Ok(())
    }

    fn append_object_bytes(
        &mut self,
        object: ProofExternalMemoryObject,
        expected_offset: u64,
        bytes: &[u8],
    ) -> Result<(), Self::Error> {
        let transaction = self.transaction_for_operation(bytes.len())?;
        let expected_offset = usize::try_from(expected_offset)
            .map_err(|_| TestExternalMemoryError::WrongOffsetOrLength)?;
        let previous_byte_length = {
            let stored = transaction
                .objects
                .get_mut(&object)
                .ok_or(TestExternalMemoryError::MissingObject)?;
            stored
                .bytes
                .len()
                .checked_add(bytes.len())
                .filter(|length| *length <= stored.exact_byte_length)
                .ok_or(TestExternalMemoryError::WrongOffsetOrLength)?;
            if stored.sealed || stored.bytes.len() != expected_offset {
                return Err(TestExternalMemoryError::WrongOffsetOrLength);
            }
            stored.bytes.len()
        };
        transaction
            .undo
            .push(TestExternalMemoryUndo::TruncateAppended {
                object,
                previous_byte_length,
            });
        transaction
            .objects
            .get_mut(&object)
            .ok_or(TestExternalMemoryError::MissingObject)?
            .bytes
            .extend_from_slice(bytes);
        Ok(())
    }

    fn seal_object(&mut self, object: ProofExternalMemoryObject) -> Result<(), Self::Error> {
        let transaction = self.transaction_for_operation(0)?;
        let previous_sealed = {
            let stored = transaction
                .objects
                .get(&object)
                .ok_or(TestExternalMemoryError::MissingObject)?;
            if stored.sealed || stored.bytes.len() != stored.exact_byte_length {
                return Err(TestExternalMemoryError::WrongOffsetOrLength);
            }
            stored.sealed
        };
        transaction.undo.push(TestExternalMemoryUndo::RestoreSeal {
            object,
            previous_sealed,
        });
        transaction
            .objects
            .get_mut(&object)
            .ok_or(TestExternalMemoryError::MissingObject)?
            .sealed = true;
        Ok(())
    }

    fn read_object_bytes(
        &mut self,
        object: ProofExternalMemoryObject,
        offset: u64,
        destination: &mut [u8],
    ) -> Result<(), Self::Error> {
        let stored = self
            .transaction_for_operation(destination.len())?
            .objects
            .get(&object)
            .ok_or(TestExternalMemoryError::MissingObject)?;
        let offset =
            usize::try_from(offset).map_err(|_| TestExternalMemoryError::WrongOffsetOrLength)?;
        let end = offset
            .checked_add(destination.len())
            .ok_or(TestExternalMemoryError::WrongOffsetOrLength)?;
        if !stored.sealed {
            return Err(TestExternalMemoryError::WrongOffsetOrLength);
        }
        destination.copy_from_slice(
            stored
                .bytes
                .get(offset..end)
                .ok_or(TestExternalMemoryError::WrongOffsetOrLength)?,
        );
        Ok(())
    }

    fn delete_object(&mut self, object: ProofExternalMemoryObject) -> Result<(), Self::Error> {
        let transaction = self.transaction_for_operation(0)?;
        let value = transaction
            .objects
            .remove(&object)
            .ok_or(TestExternalMemoryError::MissingObject)?;
        transaction
            .undo
            .push(TestExternalMemoryUndo::RestoreDeleted { object, value });
        Ok(())
    }

    fn commit_transaction(&mut self) -> Result<(), Self::Error> {
        let transaction = self
            .transaction
            .take()
            .ok_or(TestExternalMemoryError::MissingTransaction)?;
        self.committed = transaction.objects;
        Ok(())
    }

    fn abort_transaction(&mut self) -> Result<(), Self::Error> {
        let mut transaction = self
            .transaction
            .take()
            .ok_or(TestExternalMemoryError::MissingTransaction)?;
        while let Some(undo) = transaction.undo.pop() {
            match undo {
                TestExternalMemoryUndo::RemoveCreated(object) => {
                    transaction
                        .objects
                        .remove(&object)
                        .ok_or(TestExternalMemoryError::MissingObject)?;
                }
                TestExternalMemoryUndo::TruncateAppended {
                    object,
                    previous_byte_length,
                } => {
                    let stored = transaction
                        .objects
                        .get_mut(&object)
                        .ok_or(TestExternalMemoryError::MissingObject)?;
                    if previous_byte_length > stored.bytes.len() {
                        return Err(TestExternalMemoryError::WrongOffsetOrLength);
                    }
                    stored.bytes.truncate(previous_byte_length);
                }
                TestExternalMemoryUndo::RestoreSeal {
                    object,
                    previous_sealed,
                } => {
                    transaction
                        .objects
                        .get_mut(&object)
                        .ok_or(TestExternalMemoryError::MissingObject)?
                        .sealed = previous_sealed;
                }
                TestExternalMemoryUndo::RestoreDeleted { object, value } => {
                    if transaction.objects.insert(object, value).is_some() {
                        return Err(TestExternalMemoryError::DuplicateObject);
                    }
                }
            }
        }
        self.committed = transaction.objects;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TestPrivateCoinError {
    CallLimitExceeded,
    ByteLimitExceeded,
    InvalidModulus,
}

struct BoundedDeterministicTestPrivateCoins {
    next_value: u64,
    remaining_call_count: u32,
    remaining_byte_count: usize,
}

impl BoundedDeterministicTestPrivateCoins {
    fn new(maximum_call_count: u32, maximum_byte_count: usize) -> Self {
        Self {
            next_value: 1,
            remaining_call_count: maximum_call_count,
            remaining_byte_count: maximum_byte_count,
        }
    }

    fn consume_call(&mut self) -> Result<(), TestPrivateCoinError> {
        self.remaining_call_count = self
            .remaining_call_count
            .checked_sub(1)
            .ok_or(TestPrivateCoinError::CallLimitExceeded)?;
        Ok(())
    }
}

impl CommonProofPrivateCoinSource for BoundedDeterministicTestPrivateCoins {
    type Error = TestPrivateCoinError;

    fn sample_modulo(
        &mut self,
        _purpose: u16,
        modulus: u64,
        maximum_candidate_draws_per_output: u32,
    ) -> Result<u64, Self::Error> {
        self.consume_call()?;
        if modulus < 2 || maximum_candidate_draws_per_output == 0 {
            return Err(TestPrivateCoinError::InvalidModulus);
        }
        let value = self.next_value % modulus;
        self.next_value = self.next_value.wrapping_add(1);
        Ok(value)
    }

    fn fill_raw_bytes(&mut self, _purpose: u16, destination: &mut [u8]) -> Result<(), Self::Error> {
        self.consume_call()?;
        self.remaining_byte_count = self
            .remaining_byte_count
            .checked_sub(destination.len())
            .ok_or(TestPrivateCoinError::ByteLimitExceeded)?;
        for (offset, byte) in destination.iter_mut().enumerate() {
            *byte = self.next_value.wrapping_add(offset as u64) as u8;
        }
        self.next_value = self
            .next_value
            .wrapping_add(u64::try_from(destination.len()).unwrap_or(u64::MAX));
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct TestSetupPolynomialMetadata {
    public_polynomial_context_hash: [u8; 64],
    root: [u8; 64],
}

struct TestSetupPolynomialTree {
    tree_catalog_index: u16,
    public_polynomial_context_hash: [u8; 64],
    canonical_leaf_bytes: Vec<Vec<u8>>,
    digest_levels: Vec<Vec<[u8; 64]>>,
}

impl TestSetupPolynomialTree {
    fn new(
        tree_catalog_index: u16,
        public_polynomial_context_hash: [u8; 64],
        evaluation_domain_size: u64,
        constant_value: u64,
    ) -> Self {
        let leaf_count = usize::try_from(evaluation_domain_size / 2)
            .expect("the toy evaluation domain fits memory");
        let canonical_leaf_bytes = (0..leaf_count)
            .map(|leaf_index| {
                setup_polynomial_leaf_bytes(
                    public_polynomial_context_hash,
                    u64::try_from(leaf_index).expect("the toy leaf index fits u64"),
                    constant_value,
                )
            })
            .collect::<Vec<_>>();
        let leaf_digests = canonical_leaf_bytes
            .iter()
            .map(|bytes| {
                hash_canonical_leaf(SETUP_PUBLIC_POLYNOMIAL_LEAF_HASH_DOMAIN, bytes)
                    .expect("the canonical setup-polynomial leaf hashes")
            })
            .collect::<Vec<_>>();
        let construction = ProofTreeConstruction::SetupPolynomial {
            public_polynomial_context_hash,
            row_width: 1,
        };
        let mut digest_levels = vec![leaf_digests];
        while digest_levels.last().is_some_and(|level| level.len() > 1) {
            let child_level = digest_levels
                .last()
                .expect("the setup-polynomial tree has a child level");
            let parent_level_ordinal =
                u32::try_from(digest_levels.len()).expect("the toy tree height fits u32");
            let parents = child_level
                .chunks_exact(2)
                .enumerate()
                .map(|(parent_index, children)| {
                    statement_owned_node_digest(
                        &construction,
                        parent_level_ordinal,
                        u64::try_from(parent_index).expect("the toy node index fits u64"),
                        children[0],
                        children[1],
                    )
                    .expect("the setup-polynomial node hashes")
                })
                .collect::<Vec<_>>();
            digest_levels.push(parents);
        }
        Self {
            tree_catalog_index,
            public_polynomial_context_hash,
            canonical_leaf_bytes,
            digest_levels,
        }
    }

    fn root(&self) -> [u8; 64] {
        self.digest_levels
            .last()
            .and_then(|level| level.first())
            .copied()
            .expect("the validated toy tree has one root")
    }

    fn metadata(&self) -> TestSetupPolynomialMetadata {
        TestSetupPolynomialMetadata {
            public_polynomial_context_hash: self.public_polynomial_context_hash,
            root: self.root(),
        }
    }
}

fn canonical_base_value(value: u64) -> CanonicalItem {
    CanonicalItem::from_canonical_bytes(
        CanonicalItemType::FieldElement,
        value.to_le_bytes().to_vec(),
        &CanonicalDecodeLimits::default(),
    )
    .expect("the toy base-field value is canonical")
}

fn canonical_base_value_list(value: u64) -> CanonicalItem {
    CanonicalItem::homogeneous_list(
        CanonicalItemType::FieldElement,
        &[canonical_base_value(value)],
    )
    .expect("the toy setup-polynomial row encodes")
}

fn setup_polynomial_leaf_bytes(
    public_polynomial_context_hash: [u8; 64],
    leaf_index: u64,
    constant_value: u64,
) -> Vec<u8> {
    CanonicalTuple::new(
        SETUP_PUBLIC_POLYNOMIAL_PHASE_PAIR_LEAF_SCHEMA_IDENTIFIER,
        SCHEMA_VERSION,
        vec![
            CanonicalItem::hash512(public_polynomial_context_hash),
            CanonicalItem::unsigned64(leaf_index),
            canonical_base_value_list(constant_value),
            canonical_base_value_list(constant_value),
        ],
    )
    .encode()
    .expect("the toy setup-polynomial leaf encodes")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TestBoundOpeningError {
    MissingTree,
    WrongOffsetOrLength,
}

impl CommonProofOpeningArtifact for TestSetupPolynomialTree {
    type Error = TestBoundOpeningError;

    fn tree_catalog_index(&self) -> u16 {
        self.tree_catalog_index
    }

    fn leaf_count(&self) -> usize {
        self.canonical_leaf_bytes.len()
    }

    fn canonical_leaf_byte_length(&self) -> usize {
        self.canonical_leaf_bytes
            .first()
            .map(Vec::len)
            .expect("the toy tree has leaves")
    }

    fn read_canonical_leaf(
        &mut self,
        leaf_index: u64,
        destination: &mut [u8],
    ) -> Result<(), Self::Error> {
        let source = usize::try_from(leaf_index)
            .ok()
            .and_then(|index| self.canonical_leaf_bytes.get(index))
            .filter(|source| source.len() == destination.len())
            .ok_or(TestBoundOpeningError::WrongOffsetOrLength)?;
        destination.copy_from_slice(source);
        Ok(())
    }

    fn read_digest(&mut self, level: u32, node_index: u64) -> Result<[u8; 64], Self::Error> {
        self.digest_levels
            .get(usize::try_from(level).map_err(|_| TestBoundOpeningError::WrongOffsetOrLength)?)
            .and_then(|nodes| {
                usize::try_from(node_index)
                    .ok()
                    .and_then(|index| nodes.get(index))
            })
            .copied()
            .ok_or(TestBoundOpeningError::WrongOffsetOrLength)
    }
}

struct TestBoundOpeningProvider {
    trees: BTreeMap<u16, TestSetupPolynomialTree>,
}

impl TestBoundOpeningProvider {
    fn new(trees: Vec<TestSetupPolynomialTree>) -> Self {
        Self {
            trees: trees
                .into_iter()
                .map(|tree| (tree.tree_catalog_index, tree))
                .collect(),
        }
    }
}

impl CommonProofBoundOpeningProvider for TestBoundOpeningProvider {
    type Error = TestBoundOpeningError;

    fn opening_geometry(
        &self,
        catalog_entry: &ProofTreeCatalogEntry,
    ) -> Result<CommonProofOpeningGeometry, Self::Error> {
        let tree = self
            .trees
            .get(&catalog_entry.tree_catalog_index())
            .ok_or(TestBoundOpeningError::MissingTree)?;
        Ok(CommonProofOpeningGeometry {
            tree_catalog_index: tree.tree_catalog_index(),
            leaf_count: tree.leaf_count(),
            canonical_leaf_byte_length: tree.canonical_leaf_byte_length(),
        })
    }

    fn write_next_bound_opening<Sink>(
        &mut self,
        catalog_entry: &ProofTreeCatalogEntry,
        writer: &mut CommonProofQuerySectionWriter<'_, Sink>,
    ) -> Result<(), CommonProofEncodingError<Sink::Error, Self::Error>>
    where
        Sink: super::super::CommonProofByteSink,
    {
        let tree = self
            .trees
            .get_mut(&catalog_entry.tree_catalog_index())
            .ok_or(CommonProofEncodingError::Artifact(
                TestBoundOpeningError::MissingTree,
            ))?;
        writer.write_next_opening(tree)
    }
}

struct NoVerifiedSequenceColumns;

impl VerifiedRelationColumnEvaluator for NoVerifiedSequenceColumns {
    fn evaluate_at_extension_point(
        &mut self,
        _column_ordinal: u32,
        _point: super::super::ProofChallengeExtensionElement,
    ) -> Option<super::super::ProofChallengeExtensionElement> {
        None
    }
}

struct CommonProofEngineFixture {
    relation_context: RelationPlanCheckContext,
    relation_plan: CompiledRelationPlan,
    canonical_application_statement_bytes: Vec<u8>,
    relation_trees: Vec<RelationProofTreeInput>,
    provided_columns: BTreeMap<u32, CommonProofSourcePolynomial>,
    statement_tree_metadata: Vec<TestSetupPolynomialMetadata>,
    bound_openings: TestBoundOpeningProvider,
}

fn relation_context() -> RelationPlanCheckContext {
    let evaluation_domain = ProofEvaluationDomain::new(
        usize::try_from(EVALUATION_DOMAIN_SIZE).expect("the toy domain fits usize"),
        PROOF_EVALUATION_COSET_OFFSET,
    )
    .expect("the toy evaluation domain is valid");
    RelationPlanCheckContext {
        base_field_modulus: PROOF_BASE_FIELD_MODULUS,
        challenge_extension_degree: PROOF_CHALLENGE_EXTENSION_DEGREE as u16,
        evaluation_blowup_factor: PROOF_EVALUATION_BLOWUP_FACTOR,
        evaluation_domain_generator: evaluation_domain.generator().canonical(),
        evaluation_coset_offset: PROOF_EVALUATION_COSET_OFFSET,
        deep_point_count: PROOF_DEEP_POINT_COUNT,
        quotient_component_count: 2,
        quotient_component_degree_bound_exclusive: 2,
        fri_fold_count: 1,
        final_polynomial_degree_bound_exclusive: PROOF_FINAL_POLYNOMIAL_DEGREE_BOUND_EXCLUSIVE,
        unique_query_count: PROOF_UNIQUE_QUERY_COUNT,
        non_native_modular_identity_challenge_count: PROOF_NON_NATIVE_IDENTITY_CHALLENGE_COUNT,
        maximum_fiat_shamir_candidate_draws_per_output:
            PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
        resolved_moduli: vec![ResolvedSuiteModulus::new(
            SuiteModulusReference::data(0),
            97,
        )],
    }
}

fn canonical_application_statement(roots: &[[u8; 64]]) -> Vec<u8> {
    let source_roots = roots[..2]
        .iter()
        .copied()
        .map(CanonicalItem::hash512)
        .collect::<Vec<_>>();
    CanonicalTuple::new(
        APPLICATION_STATEMENT_SCHEMA_IDENTIFIER,
        SCHEMA_VERSION,
        vec![
            CanonicalItem::hash512([0x21; 64]),
            CanonicalItem::homogeneous_list(CanonicalItemType::Hash512, &source_roots)
                .expect("the source-root list encodes"),
            CanonicalItem::hash512(roots[2]),
        ],
    )
    .encode()
    .expect("the toy application statement encodes")
}

fn verified_statement_trees(
    relation_plan: &CompiledRelationPlan,
    metadata: &[TestSetupPolynomialMetadata],
    first_root_override: Option<[u8; 64]>,
) -> Vec<VerifiedStatementOwnedTree> {
    let variant = relation_plan
        .select_variant(None, None)
        .expect("the toy relation has one unselected variant");
    variant
        .ordered_trees()
        .iter()
        .enumerate()
        .map(|(tree_index, descriptor)| {
            let RelationTreeDescriptor::BoundPublic {
                expected_root_source_ordinal,
                ordered_column_ordinals,
                ..
            } = descriptor
            else {
                panic!("the public aggregate relation contains only bound trees");
            };
            let tree_metadata = metadata
                .get(tree_index)
                .copied()
                .expect("the toy bound tree metadata is complete");
            let expected_root = if tree_index == 0 {
                first_root_override.unwrap_or(tree_metadata.root)
            } else {
                tree_metadata.root
            };
            let ordered_canonical_residue_moduli = ordered_column_ordinals
                .iter()
                .map(|column_ordinal| {
                    variant
                        .ordered_columns()
                        .get(*column_ordinal as usize)
                        .expect("the checked tree column exists")
                        .canonical_residue_modulus()
                })
                .collect();
            VerifiedStatementOwnedTree::from_verified_canonical_source(
                u32::try_from(tree_index).expect("the toy tree index fits u32"),
                *expected_root_source_ordinal,
                StatementOwnedProofTreeInput::SetupPolynomial {
                    public_polynomial_context_hash: tree_metadata.public_polynomial_context_hash,
                    row_width: 1,
                    expected_root,
                },
                ordered_canonical_residue_moduli,
            )
        })
        .collect()
}

fn common_proof_engine_fixture() -> CommonProofEngineFixture {
    let relation_context = relation_context();
    let relation_plan = compile_collective_public_key_aggregate_relation_plan(
        &CollectivePublicKeyAggregatePlanInput {
            geometry: PublicAggregateRelationGeometry {
                ring_degree: 2,
                evaluation_domain_size: EVALUATION_DOMAIN_SIZE,
                opening_degree_bound_exclusive: OPENING_DEGREE_BOUND_EXCLUSIVE,
                public_polynomial_column_degree_bound_exclusive: 1,
                participant_count: 2,
            },
            ordered_component_moduli: vec![SuiteModulusReference::data(0)],
        },
        &relation_context,
    )
    .expect("the smallest production-schedule public aggregate plan compiles");
    let constant_values = [7_u64, 11, 18];
    let trees = constant_values
        .iter()
        .copied()
        .enumerate()
        .map(|(tree_index, constant_value)| {
            TestSetupPolynomialTree::new(
                u16::try_from(tree_index).expect("the toy tree index fits u16"),
                [0x31 + tree_index as u8; 64],
                EVALUATION_DOMAIN_SIZE,
                constant_value,
            )
        })
        .collect::<Vec<_>>();
    let statement_tree_metadata = trees
        .iter()
        .map(TestSetupPolynomialTree::metadata)
        .collect::<Vec<_>>();
    let roots = statement_tree_metadata
        .iter()
        .map(|metadata| metadata.root)
        .collect::<Vec<_>>();
    let relation_trees = statement_tree_metadata
        .iter()
        .map(|metadata| {
            RelationProofTreeInput::BoundPublic(StatementOwnedProofTreeInput::SetupPolynomial {
                public_polynomial_context_hash: metadata.public_polynomial_context_hash,
                row_width: 1,
                expected_root: metadata.root,
            })
        })
        .collect();
    let provided_columns = constant_values
        .iter()
        .copied()
        .enumerate()
        .map(|(column_index, value)| {
            (
                u32::try_from(column_index).expect("the toy column index fits u32"),
                CommonProofSourcePolynomial::Base(vec![
                    ProofBaseFieldElement::from_canonical(value)
                        .expect("the toy source coefficient is canonical"),
                ]),
            )
        })
        .collect();
    CommonProofEngineFixture {
        relation_context,
        relation_plan,
        canonical_application_statement_bytes: canonical_application_statement(&roots),
        relation_trees,
        provided_columns,
        statement_tree_metadata,
        bound_openings: TestBoundOpeningProvider::new(trees),
    }
}

fn verify_fixture_proof(
    fixture: &CommonProofEngineFixture,
    proof_bytes: &[u8],
    canonical_application_statement_bytes: &[u8],
    statement_owned_trees: &[VerifiedStatementOwnedTree],
) -> Result<(), CommonProofVerifierError> {
    verify_common_proof(
        CommonProofVerificationInput {
            protocol_version: 1,
            suite_identifier: [0x11; 64],
            canonical_application_statement_bytes,
            relation_plan: &fixture.relation_plan,
            relation_context: &fixture.relation_context,
            schedule_position: None,
            top_count: None,
            statement_owned_trees,
            proof_source: proof_bytes,
            declared_proof_byte_length: proof_bytes.len(),
            proof_byte_ceiling: MAXIMUM_PROOF_BYTE_LENGTH,
        },
        &mut NoVerifiedSequenceColumns,
    )
}

#[test]
fn complete_common_proof_engine_round_trip_binds_proof_statement_and_verified_source_root() {
    let mut fixture = common_proof_engine_fixture();
    let verified_trees = verified_statement_trees(
        &fixture.relation_plan,
        &fixture.statement_tree_metadata,
        None,
    );
    let mut external_memory =
        BoundedInMemoryExternalMemory::new(MAXIMUM_EXTERNAL_MEMORY_BYTE_LENGTH);
    let mut private_coins = BoundedDeterministicTestPrivateCoins::new(1_024, 1_024 * 1_024);
    let mut sink = BoundedCommonProofByteSink::new(MAXIMUM_PROOF_BYTE_LENGTH)
        .expect("the bounded proof sink initializes");
    generate_common_proof(
        CommonProofGenerationInput {
            protocol_version: 1,
            suite_identifier: [0x11; 64],
            canonical_application_statement_bytes: &fixture.canonical_application_statement_bytes,
            relation_plan: &fixture.relation_plan,
            relation_context: &fixture.relation_context,
            schedule_position: None,
            top_count: None,
            relation_trees: fixture.relation_trees.clone(),
            provided_pre_challenge_columns: fixture.provided_columns.clone(),
            provided_non_integer_lift_auxiliary_columns: BTreeMap::new(),
            maximum_external_memory_chunk_byte_length: MAXIMUM_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
            maximum_prefetched_query_byte_length: MAXIMUM_PROOF_BYTE_LENGTH as u64,
        },
        &mut external_memory,
        &mut private_coins,
        &mut sink,
        &mut fixture.bound_openings,
    )
    .expect("the checked toy relation produces one complete canonical proof");
    let proof_bytes = sink.finish();

    verify_fixture_proof(
        &fixture,
        &proof_bytes,
        &fixture.canonical_application_statement_bytes,
        &verified_trees,
    )
    .expect("the complete generated proof verifies");

    let header_byte_length =
        canonical_proof_object_header_bytes(&fixture.canonical_application_statement_bytes)
            .expect("the canonical proof header encodes")
            .len();
    let mut changed_proof_bytes = proof_bytes.clone();
    changed_proof_bytes[header_byte_length] ^= 1;
    assert!(
        verify_fixture_proof(
            &fixture,
            &changed_proof_bytes,
            &fixture.canonical_application_statement_bytes,
            &verified_trees,
        )
        .is_err(),
        "a changed proof-body root must fail closed",
    );

    let mut changed_statement_roots = fixture
        .statement_tree_metadata
        .iter()
        .map(|metadata| metadata.root)
        .collect::<Vec<_>>();
    changed_statement_roots[0][0] ^= 1;
    let changed_statement = canonical_application_statement(&changed_statement_roots);
    assert_eq!(
        verify_fixture_proof(&fixture, &proof_bytes, &changed_statement, &verified_trees,),
        Err(CommonProofVerifierError::InvalidProofHeader),
    );

    let changed_source_tree = TestSetupPolynomialTree::new(
        0,
        fixture.statement_tree_metadata[0].public_polynomial_context_hash,
        EVALUATION_DOMAIN_SIZE,
        8,
    );
    let changed_verified_trees = verified_statement_trees(
        &fixture.relation_plan,
        &fixture.statement_tree_metadata,
        Some(changed_source_tree.root()),
    );
    assert!(
        verify_fixture_proof(
            &fixture,
            &proof_bytes,
            &fixture.canonical_application_statement_bytes,
            &changed_verified_trees,
        )
        .is_err(),
        "a root recomputed from a changed verified source value must fail closed",
    );
}
