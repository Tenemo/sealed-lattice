//! Security-experiment extraction from a restored random-oracle state.
//!
//! This module is deliberately separate from production verification. The
//! verifier accepts only by recomputing the canonical transcript, Merkle
//! frontiers, opening identities, and FRI paths. It neither possesses nor
//! manufactures the adversary's random-oracle query table.
//!
//! The round-by-round knowledge experiment restores one opaque state that owns
//! the checked relation plan, the exact production tree catalog, relation-tree
//! roots, production-derived application challenges, canonical public inputs,
//! and one bounded snapshot of observed oracle preimage/output pairs. The
//! extractor never evaluates SHAKE. It walks the output-indexed query table
//! toward every root and compares each observed preimage with the exact
//! production framing derived from the checked catalog.
//!
//! This is a partial extractor in the standard sense. A missing query, an
//! ambiguous query table, or a committed source outside its checked degree
//! bound is an extractor failure charged to the commitment, collision, or
//! round-by-round low-degree bad event. None of those failures is converted
//! into a verifier result, simulator interface, runtime acceptance path, or
//! serialized proof field.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use zeroize::{Zeroize, Zeroizing};

use super::{
    ApplicationExtractionError, ApplicationExtractionInput, BoundTreeConstructionKind,
    CheckedApplicationExtractionPlan, ExtractedApplicationWitness,
    ExtractedLowDegreeApplicationTree, RelationApplicationChallengeAssignment,
    RelationColumnOrigin, RelationColumnValueType, RelationPlanError, RelationTreeDescriptor,
};
use crate::bgv::proof_suite::{
    COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH, CommonProofTranscript,
    CommonProofTranscriptSchedule, CompleteProofTreeCatalog, ProofBaseFieldElement, ProofBodyError,
    ProofChallengeExtensionElement, ProofEvaluationDomain, ProofLeafVisibility,
    ProofPolynomialError, ProofTreeCatalogEntry, ProofTreeCatalogInput, ProofTreeCatalogSource,
    ProofTreeOracleEquationNamespace, ProofTreeRole, ProofTreeValue, RelationProofTreeInput,
    StatementOwnedProofTreeInput, TranscriptError, build_complete_proof_tree_catalog,
    prover::CommonProofSourcePolynomial,
};

type ApplicationRoot = [u8; 64];

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum RoundByRoundApplicationExtractionError {
    Body(ProofBodyError),
    Polynomial(ProofPolynomialError),
    Relation(RelationPlanError),
    Transcript(TranscriptError),
    Application(ApplicationExtractionError),
    InvalidCatalog,
    InvalidCanonicalPublicInput,
    InvalidOracleQuery,
    InvalidQueryBound,
    QueryBoundExceeded,
    DuplicateOracleQuery,
    IncompleteOracleTranscript,
    AmbiguousOracleTranscript,
    OracleQueryKindMismatch,
    OracleQueryPreimageMismatch,
    RootMismatch,
    ColumnTypeMismatch,
    SourceDegreeExceeded,
    CountOverflow,
}

impl From<ProofBodyError> for RoundByRoundApplicationExtractionError {
    fn from(error: ProofBodyError) -> Self {
        Self::Body(error)
    }
}

impl From<ProofPolynomialError> for RoundByRoundApplicationExtractionError {
    fn from(error: ProofPolynomialError) -> Self {
        Self::Polynomial(error)
    }
}

impl From<RelationPlanError> for RoundByRoundApplicationExtractionError {
    fn from(error: RelationPlanError) -> Self {
        Self::Relation(error)
    }
}

impl From<TranscriptError> for RoundByRoundApplicationExtractionError {
    fn from(error: TranscriptError) -> Self {
        Self::Transcript(error)
    }
}

impl From<ApplicationExtractionError> for RoundByRoundApplicationExtractionError {
    fn from(error: ApplicationExtractionError) -> Self {
        Self::Application(error)
    }
}

/// One exact input/output pair observed in the experiment-owned oracle table.
/// The input is the complete canonical byte string absorbed by SHAKE256.
struct ObservedRandomOracleQueryPair {
    canonical_preimage: Zeroizing<Vec<u8>>,
    output_digest: ApplicationRoot,
}

impl ObservedRandomOracleQueryPair {
    fn new(
        canonical_preimage: Zeroizing<Vec<u8>>,
        output_digest: ApplicationRoot,
    ) -> Result<Self, RoundByRoundApplicationExtractionError> {
        if canonical_preimage.is_empty() {
            return Err(RoundByRoundApplicationExtractionError::InvalidOracleQuery);
        }
        Ok(Self {
            canonical_preimage,
            output_digest,
        })
    }
}

impl fmt::Debug for ObservedRandomOracleQueryPair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObservedRandomOracleQueryPair")
            .field(
                "canonical_preimage_byte_length",
                &self.canonical_preimage.len(),
            )
            .finish_non_exhaustive()
    }
}

/// One decoded leaf query. The semantic rows are retained only for
/// interpolation; their exact canonical hash preimage remains authoritative.
pub(super) struct RecordedOracleLeafQuery {
    observed_pair: ObservedRandomOracleQueryPair,
    leaf_index: u64,
    secret_salt: Option<Zeroizing<[u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]>>,
    first_point_values: Zeroizing<Vec<ProofTreeValue>>,
    opposite_point_values: Zeroizing<Vec<ProofTreeValue>>,
}

impl RecordedOracleLeafQuery {
    fn from_observed_pair(
        observed_pair: ObservedRandomOracleQueryPair,
        leaf_index: u64,
        secret_salt: Option<Zeroizing<[u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]>>,
        first_point_values: Zeroizing<Vec<ProofTreeValue>>,
        opposite_point_values: Zeroizing<Vec<ProofTreeValue>>,
    ) -> Result<Self, RoundByRoundApplicationExtractionError> {
        if first_point_values.is_empty() || first_point_values.len() != opposite_point_values.len()
        {
            return Err(RoundByRoundApplicationExtractionError::InvalidOracleQuery);
        }
        Ok(Self {
            observed_pair,
            leaf_index,
            secret_salt,
            first_point_values,
            opposite_point_values,
        })
    }
}

impl fmt::Debug for RecordedOracleLeafQuery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordedOracleLeafQuery")
            .field("leaf_index", &self.leaf_index)
            .field("has_secret_salt", &self.secret_salt.is_some())
            .field("row_width", &self.first_point_values.len())
            .finish_non_exhaustive()
    }
}

/// One decoded parent query. Coordinates are checked against the canonical
/// preimage during root-directed traversal and are never trusted as routing
/// metadata on their own.
pub(super) struct RecordedOracleNodeQuery {
    observed_pair: ObservedRandomOracleQueryPair,
    level: u32,
    node_index: u64,
    left_child_digest: ApplicationRoot,
    right_child_digest: ApplicationRoot,
}

impl RecordedOracleNodeQuery {
    fn from_observed_pair(
        observed_pair: ObservedRandomOracleQueryPair,
        level: u32,
        node_index: u64,
        left_child_digest: ApplicationRoot,
        right_child_digest: ApplicationRoot,
    ) -> Result<Self, RoundByRoundApplicationExtractionError> {
        if level == 0 {
            return Err(RoundByRoundApplicationExtractionError::InvalidOracleQuery);
        }
        Ok(Self {
            observed_pair,
            level,
            node_index,
            left_child_digest,
            right_child_digest,
        })
    }
}

impl fmt::Debug for RecordedOracleNodeQuery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordedOracleNodeQuery")
            .field("level", &self.level)
            .field("node_index", &self.node_index)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OracleQueryLocation {
    Leaf(usize),
    Node(usize),
}

/// One ambiguity-checked, output-indexed query-table snapshot. Construction is
/// `O(Q log Q)` and every traversal lookup is `O(log Q)` under the explicit
/// experiment query bound.
pub(super) struct RecordedRandomOracleQueryDatabase {
    leaf_queries: Vec<RecordedOracleLeafQuery>,
    node_queries: Vec<RecordedOracleNodeQuery>,
    query_location_by_output_digest: BTreeMap<ApplicationRoot, OracleQueryLocation>,
    maximum_observed_query_count: u128,
}

impl RecordedRandomOracleQueryDatabase {
    fn from_observed_queries(
        leaf_queries: Vec<RecordedOracleLeafQuery>,
        node_queries: Vec<RecordedOracleNodeQuery>,
        maximum_observed_query_count: u128,
    ) -> Result<Self, RoundByRoundApplicationExtractionError> {
        if maximum_observed_query_count == 0 {
            return Err(RoundByRoundApplicationExtractionError::InvalidQueryBound);
        }
        let query_count = leaf_queries
            .len()
            .checked_add(node_queries.len())
            .ok_or(RoundByRoundApplicationExtractionError::CountOverflow)?;
        if u128::try_from(query_count)
            .map_err(|_| RoundByRoundApplicationExtractionError::CountOverflow)?
            > maximum_observed_query_count
        {
            return Err(RoundByRoundApplicationExtractionError::QueryBoundExceeded);
        }
        let mut result = Self {
            leaf_queries,
            node_queries,
            query_location_by_output_digest: BTreeMap::new(),
            maximum_observed_query_count,
        };
        result.validate_and_index_queries()?;
        Ok(result)
    }

    fn validate_and_index_queries(&mut self) -> Result<(), RoundByRoundApplicationExtractionError> {
        let mut locations = Vec::new();
        locations
            .try_reserve_exact(
                self.leaf_queries
                    .len()
                    .checked_add(self.node_queries.len())
                    .ok_or(RoundByRoundApplicationExtractionError::CountOverflow)?,
            )
            .map_err(|_| RoundByRoundApplicationExtractionError::CountOverflow)?;
        locations.extend((0..self.leaf_queries.len()).map(OracleQueryLocation::Leaf));
        locations.extend((0..self.node_queries.len()).map(OracleQueryLocation::Node));

        locations.sort_by(|left, right| {
            let left_pair = self.query_pair(*left);
            let right_pair = self.query_pair(*right);
            left_pair
                .canonical_preimage
                .as_slice()
                .cmp(right_pair.canonical_preimage.as_slice())
                .then_with(|| left_pair.output_digest.cmp(&right_pair.output_digest))
        });
        for pair in locations.windows(2) {
            let left = self.query_pair(pair[0]);
            let right = self.query_pair(pair[1]);
            if left.canonical_preimage == right.canonical_preimage {
                return Err(if left.output_digest == right.output_digest {
                    RoundByRoundApplicationExtractionError::DuplicateOracleQuery
                } else {
                    RoundByRoundApplicationExtractionError::AmbiguousOracleTranscript
                });
            }
        }

        locations.sort_by(|left, right| {
            self.query_pair(*left)
                .output_digest
                .cmp(&self.query_pair(*right).output_digest)
        });
        for pair in locations.windows(2) {
            let left = self.query_pair(pair[0]);
            let right = self.query_pair(pair[1]);
            if left.output_digest == right.output_digest {
                return Err(RoundByRoundApplicationExtractionError::AmbiguousOracleTranscript);
            }
        }
        for location in locations {
            let output_digest = self.query_pair(location).output_digest;
            if self
                .query_location_by_output_digest
                .insert(output_digest, location)
                .is_some()
            {
                return Err(RoundByRoundApplicationExtractionError::AmbiguousOracleTranscript);
            }
        }
        Ok(())
    }

    fn query_pair(&self, location: OracleQueryLocation) -> &ObservedRandomOracleQueryPair {
        match location {
            OracleQueryLocation::Leaf(index) => &self.leaf_queries[index].observed_pair,
            OracleQueryLocation::Node(index) => &self.node_queries[index].observed_pair,
        }
    }

    fn extract_complete_tree<'a>(
        &'a self,
        catalog_entry: &ProofTreeCatalogEntry,
        expected_root: ApplicationRoot,
        leaf_count: usize,
    ) -> Result<Vec<&'a RecordedOracleLeafQuery>, RoundByRoundApplicationExtractionError> {
        if leaf_count < 1 || !leaf_count.is_power_of_two() {
            return Err(RoundByRoundApplicationExtractionError::InvalidCatalog);
        }
        if catalog_entry
            .bound_root()
            .is_some_and(|bound_root| bound_root != expected_root)
        {
            return Err(RoundByRoundApplicationExtractionError::RootMismatch);
        }

        let tree_height = leaf_count.trailing_zeros();
        let mut current_digests = vec![expected_root];
        for level in (1..=tree_height).rev() {
            let expected_node_count = leaf_count
                .checked_shr(level)
                .ok_or(RoundByRoundApplicationExtractionError::CountOverflow)?;
            if current_digests.len() != expected_node_count {
                return Err(RoundByRoundApplicationExtractionError::InvalidCatalog);
            }
            let mut child_digests = Vec::new();
            child_digests
                .try_reserve_exact(
                    current_digests
                        .len()
                        .checked_mul(2)
                        .ok_or(RoundByRoundApplicationExtractionError::CountOverflow)?,
                )
                .map_err(|_| RoundByRoundApplicationExtractionError::CountOverflow)?;
            for (expected_node_index, expected_digest) in
                current_digests.iter().copied().enumerate()
            {
                let location = self
                    .query_location_by_output_digest
                    .get(&expected_digest)
                    .copied()
                    .ok_or(RoundByRoundApplicationExtractionError::IncompleteOracleTranscript)?;
                let OracleQueryLocation::Node(query_index) = location else {
                    return Err(RoundByRoundApplicationExtractionError::OracleQueryKindMismatch);
                };
                let query = &self.node_queries[query_index];
                let expected_node_index = u64::try_from(expected_node_index)
                    .map_err(|_| RoundByRoundApplicationExtractionError::CountOverflow)?;
                if query.level != level || query.node_index != expected_node_index {
                    return Err(
                        RoundByRoundApplicationExtractionError::OracleQueryPreimageMismatch,
                    );
                }
                let expected_preimage = catalog_entry.materialized_parent_hash_preimage(
                    level,
                    expected_node_index,
                    query.left_child_digest,
                    query.right_child_digest,
                )?;
                if query.observed_pair.canonical_preimage != expected_preimage {
                    return Err(
                        RoundByRoundApplicationExtractionError::OracleQueryPreimageMismatch,
                    );
                }
                child_digests.push(query.left_child_digest);
                child_digests.push(query.right_child_digest);
            }
            current_digests = child_digests;
        }
        if current_digests.len() != leaf_count {
            return Err(RoundByRoundApplicationExtractionError::InvalidCatalog);
        }

        let mut extracted_leaves = Vec::new();
        extracted_leaves
            .try_reserve_exact(leaf_count)
            .map_err(|_| RoundByRoundApplicationExtractionError::CountOverflow)?;
        for (expected_leaf_index, expected_digest) in current_digests.into_iter().enumerate() {
            let location = self
                .query_location_by_output_digest
                .get(&expected_digest)
                .copied()
                .ok_or(RoundByRoundApplicationExtractionError::IncompleteOracleTranscript)?;
            let OracleQueryLocation::Leaf(query_index) = location else {
                return Err(RoundByRoundApplicationExtractionError::OracleQueryKindMismatch);
            };
            let query = &self.leaf_queries[query_index];
            let expected_leaf_index = u64::try_from(expected_leaf_index)
                .map_err(|_| RoundByRoundApplicationExtractionError::CountOverflow)?;
            if query.leaf_index != expected_leaf_index {
                return Err(RoundByRoundApplicationExtractionError::OracleQueryPreimageMismatch);
            }
            let mut salt = query.secret_salt.as_ref().map(|value| **value);
            let expected_preimage_result = catalog_entry.materialized_leaf_hash_preimage(
                expected_leaf_index,
                salt,
                Zeroizing::new(query.first_point_values.to_vec()),
                Zeroizing::new(query.opposite_point_values.to_vec()),
            );
            salt.zeroize();
            let expected_preimage = expected_preimage_result?;
            if query.observed_pair.canonical_preimage != expected_preimage {
                return Err(RoundByRoundApplicationExtractionError::OracleQueryPreimageMismatch);
            }
            extracted_leaves.push(query);
        }
        Ok(extracted_leaves)
    }
}

impl fmt::Debug for RecordedRandomOracleQueryDatabase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordedRandomOracleQueryDatabase")
            .field("leaf_query_count", &self.leaf_queries.len())
            .field("node_query_count", &self.node_queries.len())
            .field(
                "maximum_observed_query_count",
                &self.maximum_observed_query_count,
            )
            .finish_non_exhaustive()
    }
}

/// Raw material restored by the security experiment. The constructor consumes
/// this value and exposes only the sealed checked state below.
pub(super) struct RoundByRoundExperimentRestoreInput {
    checked_application_plan: CheckedApplicationExtractionPlan,
    protocol_version: u16,
    suite_identifier: [u8; 64],
    canonical_proof_object_header_bytes: Vec<u8>,
    proof_field_index: u16,
    relation_tree_inputs: Vec<RelationProofTreeInput>,
    ordered_relation_tree_roots: Vec<ApplicationRoot>,
    query_database: RecordedRandomOracleQueryDatabase,
    canonical_verifier_sequence_polynomials_by_column: BTreeMap<u32, CommonProofSourcePolynomial>,
    canonical_bound_roots_by_verifier_source: BTreeMap<u32, ApplicationRoot>,
}

/// One restored knowledge-experiment state. No field or constructor is
/// reachable from the verifier, runtime FFI, or proof decoder.
pub(super) struct RestoredRoundByRoundExperimentState {
    checked_application_plan: CheckedApplicationExtractionPlan,
    catalog: CompleteProofTreeCatalog,
    ordered_relation_tree_roots: Vec<ApplicationRoot>,
    query_database: RecordedRandomOracleQueryDatabase,
    canonical_verifier_sequence_polynomials_by_column: BTreeMap<u32, CommonProofSourcePolynomial>,
    canonical_bound_roots_by_verifier_source: BTreeMap<u32, ApplicationRoot>,
    application_challenges: Vec<RelationApplicationChallengeAssignment>,
}

impl RestoredRoundByRoundExperimentState {
    fn restore(
        input: RoundByRoundExperimentRestoreInput,
    ) -> Result<Self, RoundByRoundApplicationExtractionError> {
        let variant = input.checked_application_plan.variant();
        let context = input.checked_application_plan.context();
        let application_statement_schema_identifier = input
            .checked_application_plan
            .application_statement_schema_identifier();
        let transcript_schedule = variant.common_proof_transcript_schedule(context)?;

        validate_restored_relation_tree_inputs(
            variant,
            &input.relation_tree_inputs,
            &input.ordered_relation_tree_roots,
            &input.canonical_verifier_sequence_polynomials_by_column,
            &input.canonical_bound_roots_by_verifier_source,
        )?;
        let catalog = build_complete_proof_tree_catalog(
            ProofTreeCatalogInput {
                suite_identifier: input.suite_identifier,
                canonical_proof_object_header_bytes: input
                    .canonical_proof_object_header_bytes
                    .clone(),
                application_statement_schema_identifier,
                proof_field_index: input.proof_field_index,
                evaluation_domain_size: variant.evaluation_domain_size(),
                relation_trees: input.relation_tree_inputs.clone(),
            },
            &transcript_schedule,
        )?;
        validate_checked_catalog_matches_relation_plan(
            variant,
            &catalog,
            &input.relation_tree_inputs,
            &input.ordered_relation_tree_roots,
            input.suite_identifier,
            &input.canonical_proof_object_header_bytes,
            application_statement_schema_identifier,
            input.proof_field_index,
        )?;
        if !catalog.has_pairwise_distinct_oracle_equation_namespaces()? {
            return Err(RoundByRoundApplicationExtractionError::InvalidCatalog);
        }

        let application_challenges = derive_production_application_challenges(
            input.protocol_version,
            input.suite_identifier,
            application_statement_schema_identifier,
            &input.canonical_proof_object_header_bytes,
            &transcript_schedule,
            &catalog,
            &input.ordered_relation_tree_roots,
            variant.ordered_trees().len(),
        )?;
        variant.checked_application_challenges(context, &application_challenges)?;

        Ok(Self {
            checked_application_plan: input.checked_application_plan,
            catalog,
            ordered_relation_tree_roots: input.ordered_relation_tree_roots,
            query_database: input.query_database,
            canonical_verifier_sequence_polynomials_by_column: input
                .canonical_verifier_sequence_polynomials_by_column,
            canonical_bound_roots_by_verifier_source: input
                .canonical_bound_roots_by_verifier_source,
            application_challenges,
        })
    }

    fn extract(
        self,
    ) -> Result<ExtractedApplicationWitness, RoundByRoundApplicationExtractionError> {
        let variant = self.checked_application_plan.variant();
        let context = self.checked_application_plan.context();
        if self.catalog.evaluation_domain_size() != variant.evaluation_domain_size()
            || self.ordered_relation_tree_roots.len() != variant.ordered_trees().len()
        {
            return Err(RoundByRoundApplicationExtractionError::InvalidCatalog);
        }
        let evaluation_domain_size = usize::try_from(variant.evaluation_domain_size())
            .map_err(|_| RoundByRoundApplicationExtractionError::CountOverflow)?;
        let evaluation_domain =
            ProofEvaluationDomain::new(evaluation_domain_size, context.evaluation_coset_offset)?;
        if evaluation_domain.generator().canonical() != context.evaluation_domain_generator {
            return Err(RoundByRoundApplicationExtractionError::InvalidCatalog);
        }
        let leaf_count = evaluation_domain_size / 2;

        let mut ordered_trees = Vec::new();
        ordered_trees
            .try_reserve_exact(variant.ordered_trees().len())
            .map_err(|_| RoundByRoundApplicationExtractionError::CountOverflow)?;
        for (tree_index, ((tree_descriptor, catalog_entry), root)) in variant
            .ordered_trees()
            .iter()
            .zip(self.catalog.entries())
            .zip(&self.ordered_relation_tree_roots)
            .enumerate()
        {
            if usize::from(catalog_entry.tree_catalog_index()) != tree_index {
                return Err(RoundByRoundApplicationExtractionError::InvalidCatalog);
            }
            let leaves =
                self.query_database
                    .extract_complete_tree(catalog_entry, *root, leaf_count)?;
            let ordered_column_polynomials = extract_tree_source_polynomials(
                variant,
                tree_descriptor.ordered_column_ordinals(),
                evaluation_domain,
                &leaves,
            )?;
            ordered_trees.push(ExtractedLowDegreeApplicationTree::new(
                *root,
                ordered_column_polynomials,
            ));
        }

        let application_input = ApplicationExtractionInput::new(
            ordered_trees,
            self.canonical_verifier_sequence_polynomials_by_column,
            self.canonical_bound_roots_by_verifier_source,
            self.application_challenges,
        );
        self.checked_application_plan
            .extract(application_input)
            .map_err(Into::into)
    }
}

impl fmt::Debug for RestoredRoundByRoundExperimentState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RestoredRoundByRoundExperimentState")
            .field(
                "application_statement_schema_identifier",
                &self
                    .checked_application_plan
                    .application_statement_schema_identifier(),
            )
            .field(
                "relation_tree_count",
                &self.ordered_relation_tree_roots.len(),
            )
            .field("query_database", &self.query_database)
            .finish_non_exhaustive()
    }
}

fn validate_restored_relation_tree_inputs(
    variant: &super::RelationPlanVariant,
    relation_tree_inputs: &[RelationProofTreeInput],
    ordered_relation_tree_roots: &[ApplicationRoot],
    canonical_verifier_sequence_polynomials_by_column: &BTreeMap<u32, CommonProofSourcePolynomial>,
    canonical_bound_roots_by_verifier_source: &BTreeMap<u32, ApplicationRoot>,
) -> Result<(), RoundByRoundApplicationExtractionError> {
    if relation_tree_inputs.len() != variant.ordered_trees().len()
        || ordered_relation_tree_roots.len() != variant.ordered_trees().len()
    {
        return Err(RoundByRoundApplicationExtractionError::InvalidCatalog);
    }
    let expected_verifier_sequence_columns = variant
        .ordered_columns()
        .iter()
        .enumerate()
        .filter_map(|(column_index, column)| {
            matches!(
                column.origin(),
                RelationColumnOrigin::VerifierSequence { .. }
            )
            .then(|| u32::try_from(column_index).ok())
            .flatten()
        })
        .collect::<BTreeSet<_>>();
    if expected_verifier_sequence_columns
        != canonical_verifier_sequence_polynomials_by_column
            .keys()
            .copied()
            .collect()
    {
        return Err(RoundByRoundApplicationExtractionError::InvalidCanonicalPublicInput);
    }
    let expected_bound_root_sources = variant
        .ordered_trees()
        .iter()
        .filter_map(|tree| match tree {
            RelationTreeDescriptor::BoundPublic {
                expected_root_source_ordinal,
                ..
            } => Some(*expected_root_source_ordinal),
            RelationTreeDescriptor::ProofCreated { .. } => None,
        })
        .collect::<BTreeSet<_>>();
    if expected_bound_root_sources
        != canonical_bound_roots_by_verifier_source
            .keys()
            .copied()
            .collect()
    {
        return Err(RoundByRoundApplicationExtractionError::InvalidCanonicalPublicInput);
    }

    for ((descriptor, catalog_input), restored_root) in variant
        .ordered_trees()
        .iter()
        .zip(relation_tree_inputs)
        .zip(ordered_relation_tree_roots)
    {
        match (descriptor, catalog_input) {
            (
                RelationTreeDescriptor::ProofCreated {
                    proof_tree_role,
                    ordered_column_ordinals,
                },
                RelationProofTreeInput::ProofCreated {
                    tree_role,
                    row_width,
                    leaf_visibility,
                },
            ) => {
                let expected_role = relation_proof_tree_role(*proof_tree_role)?;
                let expected_row_width = u32::try_from(ordered_column_ordinals.len())
                    .map_err(|_| RoundByRoundApplicationExtractionError::CountOverflow)?;
                let expected_visibility =
                    relation_tree_leaf_visibility(variant, ordered_column_ordinals)?;
                if *tree_role != expected_role
                    || *row_width != expected_row_width
                    || *leaf_visibility != expected_visibility
                {
                    return Err(RoundByRoundApplicationExtractionError::InvalidCatalog);
                }
            }
            (
                RelationTreeDescriptor::BoundPublic {
                    construction_kind,
                    expected_root_source_ordinal,
                    ordered_column_ordinals,
                    ..
                },
                RelationProofTreeInput::BoundPublic(statement_tree),
            ) => {
                let expected_root = canonical_bound_roots_by_verifier_source
                    .get(expected_root_source_ordinal)
                    .ok_or(RoundByRoundApplicationExtractionError::InvalidCanonicalPublicInput)?;
                if expected_root != restored_root {
                    return Err(
                        RoundByRoundApplicationExtractionError::InvalidCanonicalPublicInput,
                    );
                }
                let construction_matches = match (construction_kind, statement_tree) {
                    (
                        BoundTreeConstructionKind::CommittedMaterial,
                        StatementOwnedProofTreeInput::CommittedMaterial {
                            expected_root: input_root,
                            ..
                        },
                    ) => input_root == expected_root,
                    (
                        BoundTreeConstructionKind::SetupPolynomial,
                        StatementOwnedProofTreeInput::SetupPolynomial {
                            row_width,
                            expected_root: input_root,
                            ..
                        },
                    ) => {
                        *row_width
                            == u32::try_from(ordered_column_ordinals.len()).map_err(|_| {
                                RoundByRoundApplicationExtractionError::CountOverflow
                            })?
                            && input_root == expected_root
                    }
                    _ => false,
                };
                if !construction_matches {
                    return Err(RoundByRoundApplicationExtractionError::InvalidCatalog);
                }
            }
            _ => return Err(RoundByRoundApplicationExtractionError::InvalidCatalog),
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_checked_catalog_matches_relation_plan(
    variant: &super::RelationPlanVariant,
    catalog: &CompleteProofTreeCatalog,
    relation_tree_inputs: &[RelationProofTreeInput],
    ordered_relation_tree_roots: &[ApplicationRoot],
    suite_identifier: [u8; 64],
    canonical_proof_object_header_bytes: &[u8],
    application_statement_schema_identifier: u16,
    proof_field_index: u16,
) -> Result<(), RoundByRoundApplicationExtractionError> {
    if catalog.evaluation_domain_size() != variant.evaluation_domain_size()
        || catalog.entries().len() < variant.ordered_trees().len()
    {
        return Err(RoundByRoundApplicationExtractionError::InvalidCatalog);
    }
    let mut next_base_ordinal = 0_u16;
    let mut next_auxiliary_ordinal = 0_u16;
    for (tree_index, (((descriptor, input), root), entry)) in variant
        .ordered_trees()
        .iter()
        .zip(relation_tree_inputs)
        .zip(ordered_relation_tree_roots)
        .zip(catalog.entries())
        .enumerate()
    {
        if usize::from(entry.tree_catalog_index()) != tree_index
            || entry.materialized_row_width()? != descriptor.ordered_column_ordinals().len()
        {
            return Err(RoundByRoundApplicationExtractionError::InvalidCatalog);
        }
        match (descriptor, input) {
            (
                RelationTreeDescriptor::ProofCreated {
                    proof_tree_role,
                    ordered_column_ordinals,
                },
                RelationProofTreeInput::ProofCreated {
                    tree_role,
                    row_width,
                    leaf_visibility,
                },
            ) => {
                let expected_role = relation_proof_tree_role(*proof_tree_role)?;
                let expected_ordinal = match expected_role {
                    ProofTreeRole::BaseOracle => {
                        let result = next_base_ordinal;
                        next_base_ordinal = next_base_ordinal
                            .checked_add(1)
                            .ok_or(RoundByRoundApplicationExtractionError::CountOverflow)?;
                        result
                    }
                    ProofTreeRole::AuxiliaryOracle => {
                        let result = next_auxiliary_ordinal;
                        next_auxiliary_ordinal = next_auxiliary_ordinal
                            .checked_add(1)
                            .ok_or(RoundByRoundApplicationExtractionError::CountOverflow)?;
                        result
                    }
                    ProofTreeRole::QuotientComponent
                    | ProofTreeRole::OpeningBatchMask
                    | ProofTreeRole::NonterminalFriLayer => {
                        return Err(RoundByRoundApplicationExtractionError::InvalidCatalog);
                    }
                };
                if *tree_role != expected_role
                    || entry.source()
                        != (ProofTreeCatalogSource::RelationProofCreated {
                            tree_role: expected_role,
                            tree_ordinal: expected_ordinal,
                        })
                    || entry.bound_root().is_some()
                    || entry.materialized_leaf_visibility() != *leaf_visibility
                    || !entry.common_catalog_identity_matches(
                        suite_identifier,
                        canonical_proof_object_header_bytes,
                        application_statement_schema_identifier,
                        proof_field_index,
                        expected_role,
                        expected_ordinal,
                        variant.evaluation_domain_size(),
                        *row_width,
                        *leaf_visibility,
                    )?
                    || relation_tree_leaf_visibility(variant, ordered_column_ordinals)?
                        != *leaf_visibility
                {
                    return Err(RoundByRoundApplicationExtractionError::InvalidCatalog);
                }
            }
            (
                RelationTreeDescriptor::BoundPublic { .. },
                RelationProofTreeInput::BoundPublic(statement_tree),
            ) => {
                let expected_namespace = match statement_tree {
                    StatementOwnedProofTreeInput::CommittedMaterial {
                        material_context_hash,
                        ..
                    } => ProofTreeOracleEquationNamespace::CommittedMaterial {
                        material_context_hash: *material_context_hash,
                    },
                    StatementOwnedProofTreeInput::SetupPolynomial {
                        public_polynomial_context_hash,
                        row_width,
                        ..
                    } => ProofTreeOracleEquationNamespace::SetupPolynomial {
                        public_polynomial_context_hash: *public_polynomial_context_hash,
                        row_width: *row_width,
                    },
                };
                if entry.source() != ProofTreeCatalogSource::RelationBoundPublic
                    || entry.uses_common_merkle_context()
                    || entry.bound_root() != Some(*root)
                    || entry.oracle_equation_namespace()? != expected_namespace
                {
                    return Err(RoundByRoundApplicationExtractionError::InvalidCatalog);
                }
            }
            _ => return Err(RoundByRoundApplicationExtractionError::InvalidCatalog),
        }
    }
    Ok(())
}

fn derive_production_application_challenges(
    protocol_version: u16,
    suite_identifier: [u8; 64],
    application_statement_schema_identifier: u16,
    canonical_proof_object_header_bytes: &[u8],
    transcript_schedule: &CommonProofTranscriptSchedule,
    catalog: &CompleteProofTreeCatalog,
    ordered_relation_tree_roots: &[ApplicationRoot],
    relation_tree_count: usize,
) -> Result<Vec<RelationApplicationChallengeAssignment>, RoundByRoundApplicationExtractionError> {
    let mut transcript = CommonProofTranscript::new(
        protocol_version,
        suite_identifier,
        application_statement_schema_identifier,
        canonical_proof_object_header_bytes,
        transcript_schedule.clone(),
    )?;
    for tree_ordinal in transcript_schedule.ordered_base_tree_ordinals() {
        let root = catalog
            .entries()
            .iter()
            .take(relation_tree_count)
            .zip(ordered_relation_tree_roots)
            .find_map(|(entry, root)| {
                (entry.source()
                    == ProofTreeCatalogSource::RelationProofCreated {
                        tree_role: ProofTreeRole::BaseOracle,
                        tree_ordinal: *tree_ordinal,
                    })
                .then_some(*root)
            })
            .ok_or(RoundByRoundApplicationExtractionError::InvalidCatalog)?;
        transcript.absorb_base_root(*tree_ordinal, root)?;
    }

    let challenge_count = transcript_schedule
        .ordered_application_challenge_groups()
        .iter()
        .try_fold(0_usize, |count, group| {
            count.checked_add(usize::from(group.coordinate_count()))
        })
        .ok_or(RoundByRoundApplicationExtractionError::CountOverflow)?;
    let mut application_challenges = Vec::new();
    application_challenges
        .try_reserve_exact(challenge_count)
        .map_err(|_| RoundByRoundApplicationExtractionError::CountOverflow)?;
    for group in transcript_schedule.ordered_application_challenge_groups() {
        let challenge = group.challenge();
        let values = transcript.sample_application_challenge_group(challenge)?;
        if values.len() != usize::from(group.coordinate_count()) {
            return Err(RoundByRoundApplicationExtractionError::InvalidCatalog);
        }
        for (repetition_ordinal, value) in values.into_iter().enumerate() {
            application_challenges.push(RelationApplicationChallengeAssignment::new(
                challenge,
                u16::try_from(repetition_ordinal)
                    .map_err(|_| RoundByRoundApplicationExtractionError::CountOverflow)?,
                value,
            )?);
        }
    }
    Ok(application_challenges)
}

fn relation_proof_tree_role(
    proof_tree_role: u16,
) -> Result<ProofTreeRole, RoundByRoundApplicationExtractionError> {
    match proof_tree_role {
        value if value == ProofTreeRole::BaseOracle as u16 => Ok(ProofTreeRole::BaseOracle),
        value if value == ProofTreeRole::AuxiliaryOracle as u16 => {
            Ok(ProofTreeRole::AuxiliaryOracle)
        }
        _ => Err(RoundByRoundApplicationExtractionError::InvalidCatalog),
    }
}

fn relation_tree_leaf_visibility(
    variant: &super::RelationPlanVariant,
    ordered_column_ordinals: &[u32],
) -> Result<ProofLeafVisibility, RoundByRoundApplicationExtractionError> {
    ordered_column_ordinals.iter().try_fold(
        ProofLeafVisibility::Public,
        |visibility, column_ordinal| {
            let column_index = usize::try_from(*column_ordinal)
                .map_err(|_| RoundByRoundApplicationExtractionError::CountOverflow)?;
            let column = variant
                .ordered_columns()
                .get(column_index)
                .ok_or(RoundByRoundApplicationExtractionError::InvalidCatalog)?;
            Ok(if matches!(column.origin(), RelationColumnOrigin::Prover) {
                ProofLeafVisibility::SecretBearing
            } else {
                visibility
            })
        },
    )
}

fn extract_tree_source_polynomials(
    variant: &super::RelationPlanVariant,
    ordered_column_ordinals: &[u32],
    evaluation_domain: ProofEvaluationDomain,
    leaves: &[&RecordedOracleLeafQuery],
) -> Result<Vec<CommonProofSourcePolynomial>, RoundByRoundApplicationExtractionError> {
    if leaves.len() != evaluation_domain.size() / 2 {
        return Err(RoundByRoundApplicationExtractionError::IncompleteOracleTranscript);
    }
    let row_width = ordered_column_ordinals.len();
    if row_width == 0
        || leaves.iter().any(|leaf| {
            leaf.first_point_values.len() != row_width
                || leaf.opposite_point_values.len() != row_width
        })
    {
        return Err(RoundByRoundApplicationExtractionError::InvalidCatalog);
    }

    let mut polynomials = Vec::new();
    polynomials
        .try_reserve_exact(row_width)
        .map_err(|_| RoundByRoundApplicationExtractionError::CountOverflow)?;
    for (column_position, column_ordinal) in ordered_column_ordinals.iter().copied().enumerate() {
        let descriptor = variant
            .ordered_columns()
            .get(
                usize::try_from(column_ordinal)
                    .map_err(|_| RoundByRoundApplicationExtractionError::CountOverflow)?,
            )
            .ok_or(RoundByRoundApplicationExtractionError::InvalidCatalog)?;
        let polynomial = match descriptor.value_type() {
            RelationColumnValueType::BaseField => {
                let mut evaluations = vec![ProofBaseFieldElement::ZERO; evaluation_domain.size()];
                let opposite_offset = leaves.len();
                for (leaf_position, leaf) in leaves.iter().enumerate() {
                    let ProofTreeValue::Base(first) = leaf.first_point_values[column_position]
                    else {
                        return Err(RoundByRoundApplicationExtractionError::ColumnTypeMismatch);
                    };
                    let ProofTreeValue::Base(opposite) =
                        leaf.opposite_point_values[column_position]
                    else {
                        return Err(RoundByRoundApplicationExtractionError::ColumnTypeMismatch);
                    };
                    evaluations[leaf_position] = first;
                    evaluations[opposite_offset + leaf_position] = opposite;
                }
                evaluation_domain.interpolate_base_polynomial_in_place(&mut evaluations)?;
                CommonProofSourcePolynomial::from_protected_base_coefficients(Zeroizing::new(
                    evaluations,
                ))
            }
            RelationColumnValueType::ChallengeExtension => {
                let mut evaluations =
                    vec![ProofChallengeExtensionElement::ZERO; evaluation_domain.size()];
                let opposite_offset = leaves.len();
                for (leaf_position, leaf) in leaves.iter().enumerate() {
                    let ProofTreeValue::Extension(first) = leaf.first_point_values[column_position]
                    else {
                        return Err(RoundByRoundApplicationExtractionError::ColumnTypeMismatch);
                    };
                    let ProofTreeValue::Extension(opposite) =
                        leaf.opposite_point_values[column_position]
                    else {
                        return Err(RoundByRoundApplicationExtractionError::ColumnTypeMismatch);
                    };
                    evaluations[leaf_position] = first;
                    evaluations[opposite_offset + leaf_position] = opposite;
                }
                evaluation_domain.interpolate_extension_polynomial_in_place(&mut evaluations)?;
                CommonProofSourcePolynomial::from_protected_extension_coefficients(Zeroizing::new(
                    evaluations,
                ))
            }
        };
        if u64::try_from(polynomial.coefficient_count())
            .map_err(|_| RoundByRoundApplicationExtractionError::CountOverflow)?
            > descriptor.source_degree_bound_exclusive()
        {
            return Err(RoundByRoundApplicationExtractionError::SourceDegreeExceeded);
        }
        polynomials.push(polynomial);
    }
    Ok(polynomials)
}

#[cfg(test)]
mod tests {
    use sha3::{
        Shake256,
        digest::{ExtendableOutput, Update, XofReader},
    };

    use super::super::{
        BoundTreeRootUse, CollectivePublicKeyAggregatePlanInput, PublicAggregateRelationGeometry,
        RelationPlanCheckContext, ResolvedSuiteModulus, SuiteModulusReference,
        compile_collective_public_key_aggregate_relation_plan, modular_power,
    };
    use super::*;
    use crate::{
        bgv::proof_suite::{
            CommonProofPrivacyMode, PROOF_BASE_FIELD_MAXIMUM_TWO_ADIC_GENERATOR,
            PROOF_BASE_FIELD_MODULUS, RelationRootEndpoint,
        },
        foundation::ProofApplicationSlotCeilings,
    };

    const EXPERIMENT_PROTOCOL_VERSION: u16 = 1;
    const EXPERIMENT_PROOF_FIELD_INDEX: u16 = 0;
    const EXPERIMENT_SUITE_IDENTIFIER: [u8; 64] = [0x5a; 64];
    const EXPERIMENT_PROOF_HEADER: &[u8] = b"sealed-lattice extractor experiment header";
    const EXPERIMENT_APPLICATION_FAMILY: u16 =
        ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER;

    /// Explicit fixed-oracle adapter for tests and replay only. The extractor
    /// proper receives observed pairs and never invokes this adapter.
    struct FixedShakeQueryReplayAdapter;

    impl FixedShakeQueryReplayAdapter {
        fn observe(
            canonical_preimage: Zeroizing<Vec<u8>>,
        ) -> Result<ObservedRandomOracleQueryPair, RoundByRoundApplicationExtractionError> {
            let mut hasher = Shake256::default();
            hasher.update(canonical_preimage.as_slice());
            let mut reader = hasher.finalize_xof();
            let mut output_digest = [0_u8; 64];
            reader.read(&mut output_digest);
            ObservedRandomOracleQueryPair::new(canonical_preimage, output_digest)
        }
    }

    struct RecordedTree {
        root: ApplicationRoot,
        leaf_queries: Vec<RecordedOracleLeafQuery>,
        node_queries: Vec<RecordedOracleNodeQuery>,
    }

    fn record_tree_queries(
        catalog_entry: &ProofTreeCatalogEntry,
        first_point_rows: &[Vec<ProofTreeValue>],
        opposite_point_rows: &[Vec<ProofTreeValue>],
        leaf_salts: &[Option<[u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]>],
    ) -> Result<RecordedTree, RoundByRoundApplicationExtractionError> {
        if first_point_rows.is_empty()
            || !first_point_rows.len().is_power_of_two()
            || first_point_rows.len() != opposite_point_rows.len()
            || first_point_rows.len() != leaf_salts.len()
        {
            return Err(RoundByRoundApplicationExtractionError::InvalidOracleQuery);
        }

        let mut leaf_queries = Vec::with_capacity(first_point_rows.len());
        let mut current_digests = Vec::with_capacity(first_point_rows.len());
        for (leaf_position, ((first_point_values, opposite_point_values), salt)) in first_point_rows
            .iter()
            .zip(opposite_point_rows)
            .zip(leaf_salts)
            .enumerate()
        {
            let leaf_index = u64::try_from(leaf_position)
                .map_err(|_| RoundByRoundApplicationExtractionError::CountOverflow)?;
            let canonical_preimage = catalog_entry.materialized_leaf_hash_preimage(
                leaf_index,
                *salt,
                Zeroizing::new(first_point_values.clone()),
                Zeroizing::new(opposite_point_values.clone()),
            )?;
            let observed_pair = FixedShakeQueryReplayAdapter::observe(canonical_preimage)?;
            let (_, production_digest) = catalog_entry.encode_materialized_leaf(
                leaf_index,
                *salt,
                Zeroizing::new(first_point_values.clone()),
                Zeroizing::new(opposite_point_values.clone()),
            )?;
            assert_eq!(observed_pair.output_digest, production_digest);
            current_digests.push(observed_pair.output_digest);
            leaf_queries.push(RecordedOracleLeafQuery::from_observed_pair(
                observed_pair,
                leaf_index,
                salt.map(Zeroizing::new),
                Zeroizing::new(first_point_values.clone()),
                Zeroizing::new(opposite_point_values.clone()),
            )?);
        }

        let tree_height = first_point_rows.len().trailing_zeros();
        let mut node_queries = Vec::with_capacity(first_point_rows.len() - 1);
        for level in 1..=tree_height {
            let mut parent_digests = Vec::with_capacity(current_digests.len() / 2);
            for (parent_position, children) in current_digests.chunks_exact(2).enumerate() {
                let parent_index = u64::try_from(parent_position)
                    .map_err(|_| RoundByRoundApplicationExtractionError::CountOverflow)?;
                let canonical_preimage = catalog_entry.materialized_parent_hash_preimage(
                    level,
                    parent_index,
                    children[0],
                    children[1],
                )?;
                let observed_pair = FixedShakeQueryReplayAdapter::observe(canonical_preimage)?;
                let production_digest = catalog_entry.materialized_parent_digest(
                    level,
                    parent_index,
                    children[0],
                    children[1],
                )?;
                assert_eq!(observed_pair.output_digest, production_digest);
                parent_digests.push(observed_pair.output_digest);
                node_queries.push(RecordedOracleNodeQuery::from_observed_pair(
                    observed_pair,
                    level,
                    parent_index,
                    children[0],
                    children[1],
                )?);
            }
            current_digests = parent_digests;
        }
        let [root] = current_digests.as_slice() else {
            return Err(RoundByRoundApplicationExtractionError::InvalidOracleQuery);
        };
        Ok(RecordedTree {
            root: *root,
            leaf_queries,
            node_queries,
        })
    }

    fn common_catalog(
        canonical_proof_header: &[u8],
        leaf_visibility: ProofLeafVisibility,
    ) -> CompleteProofTreeCatalog {
        let privacy_mode = match leaf_visibility {
            ProofLeafVisibility::Public => CommonProofPrivacyMode::PublicOnly,
            ProofLeafVisibility::SecretBearing => CommonProofPrivacyMode::SecretBearing,
        };
        let transcript_schedule = CommonProofTranscriptSchedule::new(
            vec![0],
            Vec::new(),
            Vec::new(),
            1,
            2,
            1,
            3,
            2,
            1,
            1,
            4,
            8,
            privacy_mode,
        )
        .expect("small common-proof transcript schedule");
        build_complete_proof_tree_catalog(
            ProofTreeCatalogInput {
                suite_identifier: EXPERIMENT_SUITE_IDENTIFIER,
                canonical_proof_object_header_bytes: canonical_proof_header.to_vec(),
                application_statement_schema_identifier: EXPERIMENT_APPLICATION_FAMILY,
                proof_field_index: EXPERIMENT_PROOF_FIELD_INDEX,
                evaluation_domain_size: 8,
                relation_trees: vec![RelationProofTreeInput::ProofCreated {
                    tree_role: ProofTreeRole::BaseOracle,
                    row_width: 1,
                    leaf_visibility,
                }],
            },
            &transcript_schedule,
        )
        .expect("small common tree catalog")
    }

    fn zero_rows(leaf_count: usize) -> Vec<Vec<ProofTreeValue>> {
        vec![vec![ProofTreeValue::Base(ProofBaseFieldElement::ZERO)]; leaf_count]
    }

    fn arbitrary_leaf_query(
        canonical_preimage: Vec<u8>,
        output_digest: ApplicationRoot,
        leaf_index: u64,
    ) -> RecordedOracleLeafQuery {
        RecordedOracleLeafQuery::from_observed_pair(
            ObservedRandomOracleQueryPair::new(Zeroizing::new(canonical_preimage), output_digest)
                .expect("nonempty arbitrary preimage"),
            leaf_index,
            None,
            Zeroizing::new(vec![ProofTreeValue::Base(ProofBaseFieldElement::ZERO)]),
            Zeroizing::new(vec![ProofTreeValue::Base(ProofBaseFieldElement::ZERO)]),
        )
        .expect("well-shaped arbitrary leaf")
    }

    fn arbitrary_node_query(
        canonical_preimage: Vec<u8>,
        output_digest: ApplicationRoot,
        node_index: u64,
    ) -> RecordedOracleNodeQuery {
        RecordedOracleNodeQuery::from_observed_pair(
            ObservedRandomOracleQueryPair::new(Zeroizing::new(canonical_preimage), output_digest)
                .expect("nonempty arbitrary preimage"),
            1,
            node_index,
            [0x11; 64],
            [0x22; 64],
        )
        .expect("well-shaped arbitrary node")
    }

    #[derive(Clone, Copy)]
    enum PublicAggregatePolynomialCase {
        ValidNonzero,
        InvalidRelation,
        SourceDegreeExceeded,
    }

    struct PreparedPublicAggregateExperiment {
        checked_application_plan: CheckedApplicationExtractionPlan,
        relation_tree_inputs: Vec<RelationProofTreeInput>,
        ordered_relation_tree_roots: Vec<ApplicationRoot>,
        leaf_queries: Vec<RecordedOracleLeafQuery>,
        node_queries: Vec<RecordedOracleNodeQuery>,
        canonical_bound_roots_by_verifier_source: BTreeMap<u32, ApplicationRoot>,
    }

    impl PreparedPublicAggregateExperiment {
        fn observed_query_count(&self) -> u128 {
            u128::try_from(self.leaf_queries.len() + self.node_queries.len())
                .expect("small test query count")
        }

        fn into_restore_input(
            self,
        ) -> Result<RoundByRoundExperimentRestoreInput, RoundByRoundApplicationExtractionError>
        {
            let maximum_observed_query_count = self.observed_query_count();
            let query_database = RecordedRandomOracleQueryDatabase::from_observed_queries(
                self.leaf_queries,
                self.node_queries,
                maximum_observed_query_count,
            )?;
            Ok(RoundByRoundExperimentRestoreInput {
                checked_application_plan: self.checked_application_plan,
                protocol_version: EXPERIMENT_PROTOCOL_VERSION,
                suite_identifier: EXPERIMENT_SUITE_IDENTIFIER,
                canonical_proof_object_header_bytes: EXPERIMENT_PROOF_HEADER.to_vec(),
                proof_field_index: EXPERIMENT_PROOF_FIELD_INDEX,
                relation_tree_inputs: self.relation_tree_inputs,
                ordered_relation_tree_roots: self.ordered_relation_tree_roots,
                query_database,
                canonical_verifier_sequence_polynomials_by_column: BTreeMap::new(),
                canonical_bound_roots_by_verifier_source: self
                    .canonical_bound_roots_by_verifier_source,
            })
        }
    }

    fn small_public_aggregate_context() -> RelationPlanCheckContext {
        RelationPlanCheckContext {
            base_field_modulus: PROOF_BASE_FIELD_MODULUS,
            challenge_extension_degree: 5,
            evaluation_blowup_factor: 2,
            evaluation_domain_generator: modular_power(
                PROOF_BASE_FIELD_MAXIMUM_TWO_ADIC_GENERATOR,
                (1_u64 << 32) / 8,
                PROOF_BASE_FIELD_MODULUS,
            ),
            evaluation_coset_offset: 7,
            deep_point_count: 1,
            quotient_component_count: 2,
            quotient_component_degree_bound_exclusive: 4,
            fri_fold_count: 2,
            final_polynomial_degree_bound_exclusive: 1,
            unique_query_count: 1,
            non_native_modular_identity_challenge_count: 1,
            maximum_fiat_shamir_candidate_draws_per_output: 8,
            resolved_moduli: vec![ResolvedSuiteModulus::new(
                SuiteModulusReference::data(0),
                97,
            )],
        }
    }

    fn prepare_public_aggregate_experiment(
        namespace_discriminator: u8,
        polynomial_case: PublicAggregatePolynomialCase,
    ) -> PreparedPublicAggregateExperiment {
        let context = small_public_aggregate_context();
        let compiled_plan = compile_collective_public_key_aggregate_relation_plan(
            &CollectivePublicKeyAggregatePlanInput {
                geometry: PublicAggregateRelationGeometry {
                    ring_degree: 4,
                    evaluation_domain_size: 8,
                    opening_degree_bound_exclusive: 4,
                    public_polynomial_column_degree_bound_exclusive: 2,
                    participant_count: 2,
                },
                ordered_component_moduli: vec![SuiteModulusReference::data(0)],
            },
            &context,
        )
        .expect("small checked public aggregate relation");
        let checked_application_plan =
            CheckedApplicationExtractionPlan::new(&compiled_plan, None, None, None, None, &context)
                .expect("small checked application extraction plan");
        let variant = checked_application_plan.variant().clone();
        let transcript_schedule = variant
            .common_proof_transcript_schedule(&context)
            .expect("small checked transcript schedule");

        let mut relation_tree_inputs = variant
            .ordered_trees()
            .iter()
            .enumerate()
            .map(|(tree_position, descriptor)| {
                let RelationTreeDescriptor::BoundPublic {
                    construction_kind: BoundTreeConstructionKind::SetupPolynomial,
                    ordered_column_ordinals,
                    ..
                } = descriptor
                else {
                    panic!("public aggregate uses only setup-polynomial trees")
                };
                RelationProofTreeInput::BoundPublic(StatementOwnedProofTreeInput::SetupPolynomial {
                    public_polynomial_context_hash: [namespace_discriminator.wrapping_add(
                        u8::try_from(tree_position + 1).expect("small tree position"),
                    ); 64],
                    row_width: u32::try_from(ordered_column_ordinals.len())
                        .expect("small row width"),
                    expected_root: [0_u8; 64],
                })
            })
            .collect::<Vec<_>>();
        let provisional_catalog = build_complete_proof_tree_catalog(
            ProofTreeCatalogInput {
                suite_identifier: EXPERIMENT_SUITE_IDENTIFIER,
                canonical_proof_object_header_bytes: EXPERIMENT_PROOF_HEADER.to_vec(),
                application_statement_schema_identifier: EXPERIMENT_APPLICATION_FAMILY,
                proof_field_index: EXPERIMENT_PROOF_FIELD_INDEX,
                evaluation_domain_size: variant.evaluation_domain_size(),
                relation_trees: relation_tree_inputs.clone(),
            },
            &transcript_schedule,
        )
        .expect("provisional relation tree catalog");
        let evaluation_domain = ProofEvaluationDomain::new(8, context.evaluation_coset_offset)
            .expect("small evaluation domain");
        assert_eq!(
            evaluation_domain.generator().canonical(),
            context.evaluation_domain_generator
        );

        let one = ProofBaseFieldElement::ONE;
        let two = ProofBaseFieldElement::from_canonical(2).expect("two is canonical");
        let mut ordered_relation_tree_roots = Vec::new();
        let mut leaf_queries = Vec::new();
        let mut node_queries = Vec::new();
        for (tree_position, (descriptor, catalog_entry)) in variant
            .ordered_trees()
            .iter()
            .zip(provisional_catalog.entries())
            .enumerate()
        {
            let RelationTreeDescriptor::BoundPublic { root_use, .. } = descriptor else {
                panic!("public aggregate uses only bound trees")
            };
            let mut coefficients = match root_use {
                BoundTreeRootUse::Input => vec![one],
                BoundTreeRootUse::Output => vec![two],
            };
            if tree_position == 0 {
                match polynomial_case {
                    PublicAggregatePolynomialCase::ValidNonzero => {}
                    PublicAggregatePolynomialCase::InvalidRelation => {
                        coefficients[0] = coefficients[0].add(one);
                    }
                    PublicAggregatePolynomialCase::SourceDegreeExceeded => {
                        coefficients.resize(3, ProofBaseFieldElement::ZERO);
                        coefficients[2] = one;
                    }
                }
            }
            let evaluations = evaluation_domain
                .evaluate_base_polynomial(&coefficients)
                .expect("small polynomial evaluations");
            let first_point_rows = evaluations[..4]
                .iter()
                .copied()
                .map(|value| vec![ProofTreeValue::Base(value)])
                .collect::<Vec<_>>();
            let opposite_point_rows = evaluations[4..]
                .iter()
                .copied()
                .map(|value| vec![ProofTreeValue::Base(value)])
                .collect::<Vec<_>>();
            let recorded_tree = record_tree_queries(
                catalog_entry,
                &first_point_rows,
                &opposite_point_rows,
                &[None; 4],
            )
            .expect("exact production tree queries");
            ordered_relation_tree_roots.push(recorded_tree.root);
            leaf_queries.extend(recorded_tree.leaf_queries);
            node_queries.extend(recorded_tree.node_queries);
        }

        for (tree_input, root) in relation_tree_inputs
            .iter_mut()
            .zip(&ordered_relation_tree_roots)
        {
            let RelationProofTreeInput::BoundPublic(
                StatementOwnedProofTreeInput::SetupPolynomial { expected_root, .. },
            ) = tree_input
            else {
                panic!("public aggregate uses only setup-polynomial trees")
            };
            *expected_root = *root;
        }
        let canonical_bound_roots_by_verifier_source = variant
            .ordered_trees()
            .iter()
            .zip(&ordered_relation_tree_roots)
            .map(|(descriptor, root)| {
                let RelationTreeDescriptor::BoundPublic {
                    expected_root_source_ordinal,
                    ..
                } = descriptor
                else {
                    panic!("public aggregate uses only bound trees")
                };
                (*expected_root_source_ordinal, *root)
            })
            .collect();

        PreparedPublicAggregateExperiment {
            checked_application_plan,
            relation_tree_inputs,
            ordered_relation_tree_roots,
            leaf_queries,
            node_queries,
            canonical_bound_roots_by_verifier_source,
        }
    }

    #[test]
    fn exact_recorded_queries_extract_and_verify_a_nonzero_application_witness() {
        let experiment =
            prepare_public_aggregate_experiment(0x10, PublicAggregatePolynomialCase::ValidNonzero);
        let expected_bound_roots = experiment.canonical_bound_roots_by_verifier_source.clone();
        let restored_state = RestoredRoundByRoundExperimentState::restore(
            experiment
                .into_restore_input()
                .expect("bounded global query table"),
        )
        .expect("opaque restored experiment state");
        let witness = restored_state
            .extract()
            .expect("nonzero public aggregate witness");
        assert!(witness.semantic_columns().is_empty());
        for (verifier_source_ordinal, expected_root) in expected_bound_roots {
            let endpoint = RelationRootEndpoint::new(
                EXPERIMENT_APPLICATION_FAMILY,
                None,
                None,
                None,
                None,
                verifier_source_ordinal,
            )
            .expect("collective aggregate root endpoint");
            assert_eq!(
                witness
                    .bind_root_endpoint(endpoint)
                    .expect("extracted root binding")
                    .root(),
                expected_root
            );
        }
    }

    #[test]
    fn extraction_rejects_a_low_degree_tree_that_violates_the_checked_relation() {
        let experiment = prepare_public_aggregate_experiment(
            0x20,
            PublicAggregatePolynomialCase::InvalidRelation,
        );
        let restored_state = RestoredRoundByRoundExperimentState::restore(
            experiment
                .into_restore_input()
                .expect("bounded global query table"),
        )
        .expect("opaque restored experiment state");
        assert!(matches!(
            restored_state.extract(),
            Err(RoundByRoundApplicationExtractionError::Application(
                ApplicationExtractionError::ConstraintViolation
            ))
        ));
    }

    #[test]
    fn extraction_rejects_a_polynomial_outside_the_checked_source_degree_bound() {
        let experiment = prepare_public_aggregate_experiment(
            0x30,
            PublicAggregatePolynomialCase::SourceDegreeExceeded,
        );
        let restored_state = RestoredRoundByRoundExperimentState::restore(
            experiment
                .into_restore_input()
                .expect("bounded global query table"),
        )
        .expect("opaque restored experiment state");
        assert!(matches!(
            restored_state.extract(),
            Err(RoundByRoundApplicationExtractionError::SourceDegreeExceeded)
        ));
    }

    #[test]
    fn extraction_fails_loudly_when_a_root_directed_node_or_leaf_query_is_missing() {
        let mut missing_node =
            prepare_public_aggregate_experiment(0x40, PublicAggregatePolynomialCase::ValidNonzero);
        missing_node.node_queries.pop().expect("root query");
        let restored_state = RestoredRoundByRoundExperimentState::restore(
            missing_node
                .into_restore_input()
                .expect("bounded incomplete node table"),
        )
        .expect("opaque restored state does not traverse yet");
        assert!(matches!(
            restored_state.extract(),
            Err(RoundByRoundApplicationExtractionError::IncompleteOracleTranscript)
        ));

        let mut missing_leaf =
            prepare_public_aggregate_experiment(0x41, PublicAggregatePolynomialCase::ValidNonzero);
        missing_leaf.leaf_queries.remove(0);
        let restored_state = RestoredRoundByRoundExperimentState::restore(
            missing_leaf
                .into_restore_input()
                .expect("bounded incomplete leaf table"),
        )
        .expect("opaque restored state does not traverse yet");
        assert!(matches!(
            restored_state.extract(),
            Err(RoundByRoundApplicationExtractionError::IncompleteOracleTranscript)
        ));
    }

    #[test]
    fn restored_state_rejects_role_substitution_and_noncanonical_public_roots() {
        let mut role_substitution =
            prepare_public_aggregate_experiment(0x50, PublicAggregatePolynomialCase::ValidNonzero);
        role_substitution.relation_tree_inputs[0] = RelationProofTreeInput::ProofCreated {
            tree_role: ProofTreeRole::BaseOracle,
            row_width: 1,
            leaf_visibility: ProofLeafVisibility::Public,
        };
        assert!(matches!(
            RestoredRoundByRoundExperimentState::restore(
                role_substitution
                    .into_restore_input()
                    .expect("bounded global query table")
            ),
            Err(RoundByRoundApplicationExtractionError::InvalidCatalog)
        ));

        let mut missing_public_root =
            prepare_public_aggregate_experiment(0x51, PublicAggregatePolynomialCase::ValidNonzero);
        let root_source = *missing_public_root
            .canonical_bound_roots_by_verifier_source
            .keys()
            .next()
            .expect("bound root source");
        missing_public_root
            .canonical_bound_roots_by_verifier_source
            .remove(&root_source);
        assert!(matches!(
            RestoredRoundByRoundExperimentState::restore(
                missing_public_root
                    .into_restore_input()
                    .expect("bounded global query table")
            ),
            Err(RoundByRoundApplicationExtractionError::InvalidCanonicalPublicInput)
        ));
    }

    #[test]
    fn namespace_mismatch_and_duplicate_namespaces_cannot_restore_one_state() {
        let mut namespace_mismatch =
            prepare_public_aggregate_experiment(0x60, PublicAggregatePolynomialCase::ValidNonzero);
        let RelationProofTreeInput::BoundPublic(StatementOwnedProofTreeInput::SetupPolynomial {
            public_polynomial_context_hash,
            ..
        }) = &mut namespace_mismatch.relation_tree_inputs[0]
        else {
            panic!("setup-polynomial tree")
        };
        public_polynomial_context_hash[0] ^= 1;
        let restored_state = RestoredRoundByRoundExperimentState::restore(
            namespace_mismatch
                .into_restore_input()
                .expect("bounded global query table"),
        )
        .expect("catalog is structurally valid before exact query matching");
        assert!(matches!(
            restored_state.extract(),
            Err(RoundByRoundApplicationExtractionError::OracleQueryPreimageMismatch)
        ));

        let mut duplicate_namespace =
            prepare_public_aggregate_experiment(0x61, PublicAggregatePolynomialCase::ValidNonzero);
        let first_namespace = match &duplicate_namespace.relation_tree_inputs[0] {
            RelationProofTreeInput::BoundPublic(
                StatementOwnedProofTreeInput::SetupPolynomial {
                    public_polynomial_context_hash,
                    ..
                },
            ) => *public_polynomial_context_hash,
            _ => panic!("setup-polynomial tree"),
        };
        let RelationProofTreeInput::BoundPublic(StatementOwnedProofTreeInput::SetupPolynomial {
            public_polynomial_context_hash,
            ..
        }) = &mut duplicate_namespace.relation_tree_inputs[1]
        else {
            panic!("setup-polynomial tree")
        };
        *public_polynomial_context_hash = first_namespace;
        assert!(matches!(
            RestoredRoundByRoundExperimentState::restore(
                duplicate_namespace
                    .into_restore_input()
                    .expect("bounded global query table")
            ),
            Err(RoundByRoundApplicationExtractionError::InvalidCatalog)
        ));
    }

    #[test]
    fn query_tables_from_distinct_restored_states_cannot_be_mixed() {
        let first_state =
            prepare_public_aggregate_experiment(0x70, PublicAggregatePolynomialCase::ValidNonzero);
        let mut second_state =
            prepare_public_aggregate_experiment(0x80, PublicAggregatePolynomialCase::ValidNonzero);
        second_state.leaf_queries = first_state.leaf_queries;
        second_state.node_queries = first_state.node_queries;
        let restored_state = RestoredRoundByRoundExperimentState::restore(
            second_state
                .into_restore_input()
                .expect("bounded mixed query table"),
        )
        .expect("opaque state restoration precedes root traversal");
        assert!(matches!(
            restored_state.extract(),
            Err(RoundByRoundApplicationExtractionError::IncompleteOracleTranscript)
        ));
    }

    #[test]
    fn common_catalog_identity_binds_header_role_ordinal_and_visibility() {
        let catalog = common_catalog(EXPERIMENT_PROOF_HEADER, ProofLeafVisibility::SecretBearing);
        let entry = &catalog.entries()[0];
        assert!(
            entry
                .common_catalog_identity_matches(
                    EXPERIMENT_SUITE_IDENTIFIER,
                    EXPERIMENT_PROOF_HEADER,
                    EXPERIMENT_APPLICATION_FAMILY,
                    EXPERIMENT_PROOF_FIELD_INDEX,
                    ProofTreeRole::BaseOracle,
                    0,
                    8,
                    1,
                    ProofLeafVisibility::SecretBearing,
                )
                .expect("exact common identity")
        );
        for (header, role, ordinal, visibility) in [
            (
                b"different proof header".as_slice(),
                ProofTreeRole::BaseOracle,
                0,
                ProofLeafVisibility::SecretBearing,
            ),
            (
                EXPERIMENT_PROOF_HEADER,
                ProofTreeRole::AuxiliaryOracle,
                0,
                ProofLeafVisibility::SecretBearing,
            ),
            (
                EXPERIMENT_PROOF_HEADER,
                ProofTreeRole::BaseOracle,
                1,
                ProofLeafVisibility::SecretBearing,
            ),
            (
                EXPERIMENT_PROOF_HEADER,
                ProofTreeRole::BaseOracle,
                0,
                ProofLeafVisibility::Public,
            ),
        ] {
            assert!(
                !entry
                    .common_catalog_identity_matches(
                        EXPERIMENT_SUITE_IDENTIFIER,
                        header,
                        EXPERIMENT_APPLICATION_FAMILY,
                        EXPERIMENT_PROOF_FIELD_INDEX,
                        role,
                        ordinal,
                        8,
                        1,
                        visibility,
                    )
                    .expect("well-formed mismatched identity")
            );
        }
    }

    #[test]
    fn proof_header_and_secret_salt_mismatches_break_exact_query_authentication() {
        let first_catalog =
            common_catalog(EXPERIMENT_PROOF_HEADER, ProofLeafVisibility::SecretBearing);
        let second_catalog = common_catalog(
            b"sealed-lattice extractor experiment second header",
            ProofLeafVisibility::SecretBearing,
        );
        let rows = zero_rows(4);
        let salts = [
            Some([0xa1; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]),
            Some([0xa2; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]),
            Some([0xa3; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]),
            Some([0xa4; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]),
        ];
        let recorded_tree = record_tree_queries(&first_catalog.entries()[0], &rows, &rows, &salts)
            .expect("secret-bearing exact queries");
        let query_database = RecordedRandomOracleQueryDatabase::from_observed_queries(
            recorded_tree.leaf_queries,
            recorded_tree.node_queries,
            7,
        )
        .expect("one complete secret tree table");
        assert!(matches!(
            query_database.extract_complete_tree(
                &second_catalog.entries()[0],
                recorded_tree.root,
                4,
            ),
            Err(RoundByRoundApplicationExtractionError::OracleQueryPreimageMismatch)
        ));

        let mut salt_mismatch =
            record_tree_queries(&first_catalog.entries()[0], &rows, &rows, &salts)
                .expect("secret-bearing exact queries");
        salt_mismatch.leaf_queries[0]
            .secret_salt
            .as_mut()
            .expect("secret leaf salt")[0] ^= 1;
        let query_database = RecordedRandomOracleQueryDatabase::from_observed_queries(
            salt_mismatch.leaf_queries,
            salt_mismatch.node_queries,
            7,
        )
        .expect("one complete tampered-salt table");
        assert!(matches!(
            query_database.extract_complete_tree(
                &first_catalog.entries()[0],
                salt_mismatch.root,
                4,
            ),
            Err(RoundByRoundApplicationExtractionError::OracleQueryPreimageMismatch)
        ));
    }

    #[test]
    fn decoded_query_kind_and_coordinates_are_not_trusted_for_routing() {
        let catalog = common_catalog(EXPERIMENT_PROOF_HEADER, ProofLeafVisibility::Public);
        let rows = zero_rows(4);
        let mut kind_mismatch =
            record_tree_queries(&catalog.entries()[0], &rows, &rows, &[None; 4])
                .expect("complete public tree");
        kind_mismatch.node_queries.pop().expect("root node query");
        kind_mismatch
            .leaf_queries
            .push(arbitrary_leaf_query(vec![0xf0], kind_mismatch.root, 0));
        let query_database = RecordedRandomOracleQueryDatabase::from_observed_queries(
            kind_mismatch.leaf_queries,
            kind_mismatch.node_queries,
            7,
        )
        .expect("type-substituted table indexes globally");
        assert!(matches!(
            query_database.extract_complete_tree(&catalog.entries()[0], kind_mismatch.root, 4),
            Err(RoundByRoundApplicationExtractionError::OracleQueryKindMismatch)
        ));

        let mut coordinate_mismatch =
            record_tree_queries(&catalog.entries()[0], &rows, &rows, &[None; 4])
                .expect("complete public tree");
        coordinate_mismatch
            .node_queries
            .last_mut()
            .expect("root node")
            .node_index = 1;
        let query_database = RecordedRandomOracleQueryDatabase::from_observed_queries(
            coordinate_mismatch.leaf_queries,
            coordinate_mismatch.node_queries,
            7,
        )
        .expect("coordinate-tampered table indexes globally");
        assert!(matches!(
            query_database.extract_complete_tree(
                &catalog.entries()[0],
                coordinate_mismatch.root,
                4,
            ),
            Err(RoundByRoundApplicationExtractionError::OracleQueryPreimageMismatch)
        ));
    }

    #[test]
    fn global_query_table_rejects_rewound_answers_collisions_duplicates_and_bound_overrun() {
        let shared_preimage = vec![0x01, 0x02];
        assert!(matches!(
            RecordedRandomOracleQueryDatabase::from_observed_queries(
                vec![
                    arbitrary_leaf_query(shared_preimage.clone(), [0x10; 64], 0),
                    arbitrary_leaf_query(shared_preimage, [0x20; 64], 1),
                ],
                Vec::new(),
                2,
            ),
            Err(RoundByRoundApplicationExtractionError::AmbiguousOracleTranscript)
        ));

        assert!(matches!(
            RecordedRandomOracleQueryDatabase::from_observed_queries(
                vec![
                    arbitrary_leaf_query(vec![0x03], [0x30; 64], 0),
                    arbitrary_leaf_query(vec![0x04], [0x30; 64], 1),
                ],
                Vec::new(),
                2,
            ),
            Err(RoundByRoundApplicationExtractionError::AmbiguousOracleTranscript)
        ));

        assert!(matches!(
            RecordedRandomOracleQueryDatabase::from_observed_queries(
                vec![
                    arbitrary_leaf_query(vec![0x05], [0x40; 64], 0),
                    arbitrary_leaf_query(vec![0x05], [0x40; 64], 0),
                ],
                Vec::new(),
                2,
            ),
            Err(RoundByRoundApplicationExtractionError::DuplicateOracleQuery)
        ));

        assert!(matches!(
            RecordedRandomOracleQueryDatabase::from_observed_queries(
                vec![arbitrary_leaf_query(vec![0x06], [0x50; 64], 0)],
                vec![arbitrary_node_query(vec![0x07], [0x60; 64], 0)],
                1,
            ),
            Err(RoundByRoundApplicationExtractionError::QueryBoundExceeded)
        ));
        assert!(matches!(
            RecordedRandomOracleQueryDatabase::from_observed_queries(Vec::new(), Vec::new(), 0,),
            Err(RoundByRoundApplicationExtractionError::InvalidQueryBound)
        ));
    }
}
