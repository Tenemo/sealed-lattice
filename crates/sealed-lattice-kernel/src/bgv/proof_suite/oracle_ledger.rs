//! Mechanical ideal-XOF accounting for the production common-proof
//! verification state machine.
//!
//! The ledger is derived from the checked transcript state machine, proof-tree
//! catalog, and exact opening/frontier geometry, from relation-plan validation
//! through construction of `VerifiedCommonProof`. Canonical-stream transport,
//! family-adapter preparation, and later protocol consumption are separate
//! scopes. The ledger is ordinary computation state: it is neither serialized
//! nor bound into a proof or verifier result.

use super::{
    COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH, CommonProofByteLengthCeiling,
    CommonProofTranscriptSchedule, CompleteProofTreeCatalog, ProofBodyError, ProofLeafVisibility,
    ProofQueryTreeByteLengthCeiling, ProofTreeCatalogEntry, ProofTreeCatalogSource,
    TranscriptError,
};

const BCS_IDEAL_XOF_OUTPUT_BYTE_LENGTH: usize = 64;
pub(crate) const BCS_MERKLE_STATISTICAL_PRIVACY_DENOMINATOR_EXPONENT: u16 = 126;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum VerifierHashEquationLedgerError {
    Transcript(TranscriptError),
    Catalog(ProofBodyError),
    CatalogMismatch,
    NonUniqueOracleEquationNamespace,
    InvalidSecretLeafSaltLength,
    InvalidOpeningGeometry,
    CountOverflow,
}

impl From<TranscriptError> for VerifierHashEquationLedgerError {
    fn from(error: TranscriptError) -> Self {
        Self::Transcript(error)
    }
}

impl From<ProofBodyError> for VerifierHashEquationLedgerError {
    fn from(error: ProofBodyError) -> Self {
        Self::Catalog(error)
    }
}

/// Exact accepted-path accounting for one query tree at its byte-ceiling
/// opening geometry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct VerifierQueryTreeHashEquationLedger {
    tree_catalog_index: u16,
    source: ProofTreeCatalogSource,
    opened_leaf_hash_query_count: u64,
    authentication_parent_hash_query_count: u64,
    common_context_hash_query_count: u64,
    secret_bearing_tree_root_count: u64,
    full_salted_leaf_count: u64,
    opened_salted_leaf_count: u64,
    hidden_salted_leaf_count: u64,
    full_secret_tree_hash_equation_count: u64,
    ideal_xof_query_count: u64,
    checked_oracle_equation_count: u64,
}

impl VerifierQueryTreeHashEquationLedger {
    pub(crate) const fn tree_catalog_index(self) -> u16 {
        self.tree_catalog_index
    }

    pub(crate) const fn source(self) -> ProofTreeCatalogSource {
        self.source
    }

    pub(crate) const fn opened_leaf_hash_query_count(self) -> u64 {
        self.opened_leaf_hash_query_count
    }

    pub(crate) const fn authentication_parent_hash_query_count(self) -> u64 {
        self.authentication_parent_hash_query_count
    }

    pub(crate) const fn common_context_hash_query_count(self) -> u64 {
        self.common_context_hash_query_count
    }

    /// Number of independently salted secret-bearing Merkle commitments in
    /// this tree row. It is either zero or one. Ceremony aggregation must
    /// count a reused statement-owned persistent root only once.
    pub(crate) const fn secret_bearing_tree_root_count(self) -> u64 {
        self.secret_bearing_tree_root_count
    }

    /// Full leaf population covered by the BCS16 statistical-privacy hybrid.
    /// Row width does not multiply this count: one independent 2-lambda salt
    /// hides the complete canonically framed row payload.
    pub(crate) const fn full_salted_leaf_count(self) -> u64 {
        self.full_salted_leaf_count
    }

    pub(crate) const fn opened_salted_leaf_count(self) -> u64 {
        self.opened_salted_leaf_count
    }

    pub(crate) const fn hidden_salted_leaf_count(self) -> u64 {
        self.hidden_salted_leaf_count
    }

    /// Full leaf-and-parent equation population, `2*n - 1`, for collision
    /// accounting across the shared ideal-XOF database.
    pub(crate) const fn full_secret_tree_hash_equation_count(self) -> u64 {
        self.full_secret_tree_hash_equation_count
    }

    pub(crate) const fn ideal_xof_query_count(self) -> u64 {
        self.ideal_xof_query_count
    }

    pub(crate) const fn checked_oracle_equation_count(self) -> u64 {
        self.checked_oracle_equation_count
    }
}

/// Exact accepted-path common-proof state-machine ledger at the supplied proof
/// ceiling after the caller proves that one shared query vector realizes it.
///
/// `ideal_xof_query_count` counts production invocations, including repeated
/// recomputation of the proof-header and common-tree context hashes.
/// `checked_oracle_equation_count` counts each repeated identical input once.
/// Typed transcript inputs, the application-statement, relation-plan, and
/// relation-plan-variant hashes, distinct opened leaves, and position-bound
/// authentication parents each contribute one equation per invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VerifierHashEquationLedger {
    transcript_hash_query_count: u64,
    maximum_transcript_xof_output_byte_length: u64,
    application_statement_hash_query_count: u64,
    proof_header_hash_query_count: u64,
    relation_plan_hash_query_count: u64,
    relation_plan_variant_hash_query_count: u64,
    fixed_checked_oracle_equation_count: u64,
    tree_hash_query_count: u64,
    secret_bearing_tree_root_count: u64,
    full_salted_leaf_count: u64,
    opened_salted_leaf_count: u64,
    hidden_salted_leaf_count: u64,
    full_secret_tree_hash_equation_count: u64,
    ideal_xof_query_count: u64,
    checked_oracle_equation_count: u64,
    query_trees: Vec<VerifierQueryTreeHashEquationLedger>,
}

impl VerifierHashEquationLedger {
    pub(crate) const fn transcript_hash_query_count(&self) -> u64 {
        self.transcript_hash_query_count
    }

    pub(crate) const fn maximum_transcript_xof_output_byte_length(&self) -> u64 {
        self.maximum_transcript_xof_output_byte_length
    }

    pub(crate) const fn application_statement_hash_query_count(&self) -> u64 {
        self.application_statement_hash_query_count
    }

    pub(crate) const fn proof_header_hash_query_count(&self) -> u64 {
        self.proof_header_hash_query_count
    }

    pub(crate) const fn relation_plan_hash_query_count(&self) -> u64 {
        self.relation_plan_hash_query_count
    }

    pub(crate) const fn relation_plan_variant_hash_query_count(&self) -> u64 {
        self.relation_plan_variant_hash_query_count
    }

    pub(crate) const fn fixed_checked_oracle_equation_count(&self) -> u64 {
        self.fixed_checked_oracle_equation_count
    }

    pub(crate) const fn tree_hash_query_count(&self) -> u64 {
        self.tree_hash_query_count
    }

    pub(crate) const fn secret_bearing_tree_root_count(&self) -> u64 {
        self.secret_bearing_tree_root_count
    }

    /// Per-proof BCS16 privacy numerator before ceremony-level persistent-root
    /// deduplication. The statistical term is this count times `2^-126`.
    pub(crate) const fn full_salted_leaf_count(&self) -> u64 {
        self.full_salted_leaf_count
    }

    pub(crate) const fn opened_salted_leaf_count(&self) -> u64 {
        self.opened_salted_leaf_count
    }

    pub(crate) const fn hidden_salted_leaf_count(&self) -> u64 {
        self.hidden_salted_leaf_count
    }

    pub(crate) const fn full_secret_tree_hash_equation_count(&self) -> u64 {
        self.full_secret_tree_hash_equation_count
    }

    pub(crate) const fn ideal_xof_query_count(&self) -> u64 {
        self.ideal_xof_query_count
    }

    pub(crate) const fn checked_oracle_equation_count(&self) -> u64 {
        self.checked_oracle_equation_count
    }

    pub(crate) fn query_trees(&self) -> &[VerifierQueryTreeHashEquationLedger] {
        &self.query_trees
    }
}

/// Derives the verifier ledger without adding it to the proof byte accounting
/// or any bound artifact. The generic byte ceiling is a simultaneous accepted
/// path only when the caller has separately established that one shared query
/// vector attains every per-tree maximum; selected-suite accounting performs
/// that constructive check.
pub(crate) fn verifier_hash_equation_ledger(
    transcript_schedule: &CommonProofTranscriptSchedule,
    byte_length_ceiling: &CommonProofByteLengthCeiling,
    tree_catalog: &CompleteProofTreeCatalog,
) -> Result<VerifierHashEquationLedger, VerifierHashEquationLedgerError> {
    if COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH
        != BCS_IDEAL_XOF_OUTPUT_BYTE_LENGTH
            .checked_mul(2)
            .ok_or(VerifierHashEquationLedgerError::CountOverflow)?
    {
        return Err(VerifierHashEquationLedgerError::InvalidSecretLeafSaltLength);
    }
    if byte_length_ceiling.query_trees().len() != tree_catalog.entries().len() {
        return Err(VerifierHashEquationLedgerError::CatalogMismatch);
    }
    if !tree_catalog.has_pairwise_distinct_oracle_equation_namespaces()? {
        return Err(VerifierHashEquationLedgerError::NonUniqueOracleEquationNamespace);
    }

    let mut query_trees = Vec::new();
    query_trees
        .try_reserve_exact(byte_length_ceiling.query_trees().len())
        .map_err(|_| VerifierHashEquationLedgerError::CountOverflow)?;
    for (tree_ceiling, catalog_entry) in byte_length_ceiling
        .query_trees()
        .iter()
        .zip(tree_catalog.entries())
    {
        if tree_ceiling.tree_catalog_index() != catalog_entry.tree_catalog_index()
            || tree_ceiling.source() != catalog_entry.source()
        {
            return Err(VerifierHashEquationLedgerError::CatalogMismatch);
        }
        query_trees.push(query_tree_hash_equation_ledger(
            tree_ceiling,
            catalog_entry,
        )?);
    }

    let transcript_hash_query_count = transcript_schedule.maximum_transcript_hash_query_count()?;
    let maximum_transcript_xof_output_byte_length =
        u64::try_from(transcript_schedule.maximum_transcript_xof_output_byte_length()?)
            .map_err(|_| VerifierHashEquationLedgerError::CountOverflow)?;
    // Building the production tree catalog hashes the canonical proof header
    // once before constructing the position-bound common tree contexts. The
    // state-machine constructor also hashes the checked relation plan. The
    // completed verifier hashes the same header again, then hashes the
    // application statement and selected relation-plan variant once each.
    let application_statement_hash_query_count = 1_u64;
    let proof_header_hash_query_count = 2_u64;
    let relation_plan_hash_query_count = 1_u64;
    let relation_plan_variant_hash_query_count = 1_u64;
    // The two proof-header invocations have identical framed inputs and check
    // one oracle equation. The statement, plan, and variant inputs are
    // distinct.
    let fixed_checked_oracle_equation_count = 4_u64;
    let tree_hash_query_count = query_trees.iter().try_fold(0_u64, |query_count, tree| {
        query_count
            .checked_add(tree.ideal_xof_query_count())
            .ok_or(VerifierHashEquationLedgerError::CountOverflow)
    })?;
    let tree_equation_count = query_trees.iter().try_fold(0_u64, |equation_count, tree| {
        equation_count
            .checked_add(tree.checked_oracle_equation_count())
            .ok_or(VerifierHashEquationLedgerError::CountOverflow)
    })?;
    let secret_bearing_tree_root_count = query_trees.iter().try_fold(0_u64, |count, tree| {
        count
            .checked_add(tree.secret_bearing_tree_root_count())
            .ok_or(VerifierHashEquationLedgerError::CountOverflow)
    })?;
    let full_salted_leaf_count = query_trees.iter().try_fold(0_u64, |count, tree| {
        count
            .checked_add(tree.full_salted_leaf_count())
            .ok_or(VerifierHashEquationLedgerError::CountOverflow)
    })?;
    let opened_salted_leaf_count = query_trees.iter().try_fold(0_u64, |count, tree| {
        count
            .checked_add(tree.opened_salted_leaf_count())
            .ok_or(VerifierHashEquationLedgerError::CountOverflow)
    })?;
    let hidden_salted_leaf_count = query_trees.iter().try_fold(0_u64, |count, tree| {
        count
            .checked_add(tree.hidden_salted_leaf_count())
            .ok_or(VerifierHashEquationLedgerError::CountOverflow)
    })?;
    let full_secret_tree_hash_equation_count =
        query_trees.iter().try_fold(0_u64, |count, tree| {
            count
                .checked_add(tree.full_secret_tree_hash_equation_count())
                .ok_or(VerifierHashEquationLedgerError::CountOverflow)
        })?;
    let ideal_xof_query_count = transcript_hash_query_count
        .checked_add(application_statement_hash_query_count)
        .and_then(|count| count.checked_add(proof_header_hash_query_count))
        .and_then(|count| count.checked_add(relation_plan_hash_query_count))
        .and_then(|count| count.checked_add(relation_plan_variant_hash_query_count))
        .and_then(|count| count.checked_add(tree_hash_query_count))
        .ok_or(VerifierHashEquationLedgerError::CountOverflow)?;
    let checked_oracle_equation_count = transcript_hash_query_count
        .checked_add(fixed_checked_oracle_equation_count)
        .and_then(|count| count.checked_add(tree_equation_count))
        .ok_or(VerifierHashEquationLedgerError::CountOverflow)?;

    Ok(VerifierHashEquationLedger {
        transcript_hash_query_count,
        maximum_transcript_xof_output_byte_length,
        application_statement_hash_query_count,
        proof_header_hash_query_count,
        relation_plan_hash_query_count,
        relation_plan_variant_hash_query_count,
        fixed_checked_oracle_equation_count,
        tree_hash_query_count,
        secret_bearing_tree_root_count,
        full_salted_leaf_count,
        opened_salted_leaf_count,
        hidden_salted_leaf_count,
        full_secret_tree_hash_equation_count,
        ideal_xof_query_count,
        checked_oracle_equation_count,
        query_trees,
    })
}

fn query_tree_hash_equation_ledger(
    tree_ceiling: &ProofQueryTreeByteLengthCeiling,
    catalog_entry: &ProofTreeCatalogEntry,
) -> Result<VerifierQueryTreeHashEquationLedger, VerifierHashEquationLedgerError> {
    if tree_ceiling.opened_leaf_count_at_ceiling() > tree_ceiling.leaf_count() {
        return Err(VerifierHashEquationLedgerError::InvalidOpeningGeometry);
    }
    derive_query_tree_hash_equation_ledger(
        tree_ceiling.tree_catalog_index(),
        tree_ceiling.source(),
        catalog_entry.uses_common_merkle_context(),
        catalog_entry.materialized_leaf_visibility(),
        u64::try_from(tree_ceiling.leaf_count())
            .map_err(|_| VerifierHashEquationLedgerError::CountOverflow)?,
        u64::try_from(tree_ceiling.opened_leaf_count_at_ceiling())
            .map_err(|_| VerifierHashEquationLedgerError::CountOverflow)?,
        u64::try_from(tree_ceiling.authentication_frontier_node_count_at_ceiling())
            .map_err(|_| VerifierHashEquationLedgerError::CountOverflow)?,
    )
}

fn derive_query_tree_hash_equation_ledger(
    tree_catalog_index: u16,
    source: ProofTreeCatalogSource,
    uses_common_merkle_context: bool,
    leaf_visibility: ProofLeafVisibility,
    leaf_count: u64,
    opened_leaf_hash_query_count: u64,
    authentication_frontier_node_count: u64,
) -> Result<VerifierQueryTreeHashEquationLedger, VerifierHashEquationLedgerError> {
    if opened_leaf_hash_query_count == 0 || opened_leaf_hash_query_count > leaf_count {
        return Err(VerifierHashEquationLedgerError::InvalidOpeningGeometry);
    }
    // Beginning with all opened-leaf and frontier digests, every parent hash
    // reduces the live node count by one until exactly the root remains.
    let authentication_parent_hash_query_count = opened_leaf_hash_query_count
        .checked_add(authentication_frontier_node_count)
        .and_then(|node_count| node_count.checked_sub(1))
        .ok_or(VerifierHashEquationLedgerError::CountOverflow)?;
    // A common leaf decoder recomputes its context hash while checking the
    // encoded context and again while reconstructing the canonical leaf. The
    // frontier verifier recomputes it once for the whole tree.
    let common_context_hash_query_count = if uses_common_merkle_context {
        opened_leaf_hash_query_count
            .checked_mul(2)
            .and_then(|count| count.checked_add(1))
            .ok_or(VerifierHashEquationLedgerError::CountOverflow)?
    } else {
        0
    };
    let ideal_xof_query_count = opened_leaf_hash_query_count
        .checked_add(authentication_parent_hash_query_count)
        .and_then(|count| count.checked_add(common_context_hash_query_count))
        .ok_or(VerifierHashEquationLedgerError::CountOverflow)?;
    let checked_context_equation_count = u64::from(uses_common_merkle_context);
    let checked_oracle_equation_count = opened_leaf_hash_query_count
        .checked_add(authentication_parent_hash_query_count)
        .and_then(|count| count.checked_add(checked_context_equation_count))
        .ok_or(VerifierHashEquationLedgerError::CountOverflow)?;
    let secret_bearing = leaf_visibility == ProofLeafVisibility::SecretBearing;
    let secret_bearing_tree_root_count = u64::from(secret_bearing);
    let full_salted_leaf_count = if secret_bearing { leaf_count } else { 0 };
    let opened_salted_leaf_count = if secret_bearing {
        opened_leaf_hash_query_count
    } else {
        0
    };
    let hidden_salted_leaf_count = full_salted_leaf_count
        .checked_sub(opened_salted_leaf_count)
        .ok_or(VerifierHashEquationLedgerError::InvalidOpeningGeometry)?;
    let full_secret_tree_hash_equation_count = if secret_bearing {
        leaf_count
            .checked_mul(2)
            .and_then(|count| count.checked_sub(1))
            .ok_or(VerifierHashEquationLedgerError::CountOverflow)?
    } else {
        0
    };

    Ok(VerifierQueryTreeHashEquationLedger {
        tree_catalog_index,
        source,
        opened_leaf_hash_query_count,
        authentication_parent_hash_query_count,
        common_context_hash_query_count,
        secret_bearing_tree_root_count,
        full_salted_leaf_count,
        opened_salted_leaf_count,
        hidden_salted_leaf_count,
        full_secret_tree_hash_equation_count,
        ideal_xof_query_count,
        checked_oracle_equation_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::ProofTreeRole;

    const SOURCE: ProofTreeCatalogSource = ProofTreeCatalogSource::RelationProofCreated {
        tree_role: ProofTreeRole::BaseOracle,
        tree_ordinal: 0,
    };

    #[test]
    fn sparse_common_tree_counts_frontier_parents_and_repeated_context_queries() {
        let ledger = derive_query_tree_hash_equation_ledger(
            0,
            SOURCE,
            true,
            ProofLeafVisibility::SecretBearing,
            16,
            3,
            5,
        )
        .expect("the sparse opening geometry is valid");

        assert_eq!(ledger.opened_leaf_hash_query_count(), 3);
        assert_eq!(ledger.authentication_parent_hash_query_count(), 7);
        assert_eq!(ledger.common_context_hash_query_count(), 7);
        assert_eq!(ledger.secret_bearing_tree_root_count(), 1);
        assert_eq!(ledger.full_salted_leaf_count(), 16);
        assert_eq!(ledger.opened_salted_leaf_count(), 3);
        assert_eq!(ledger.hidden_salted_leaf_count(), 13);
        assert_eq!(ledger.full_secret_tree_hash_equation_count(), 31);
        assert_eq!(ledger.ideal_xof_query_count(), 17);
        assert_eq!(ledger.checked_oracle_equation_count(), 11);
    }

    #[test]
    fn full_statement_owned_tree_has_no_frontier_or_context_hashes() {
        let ledger = derive_query_tree_hash_equation_ledger(
            4,
            ProofTreeCatalogSource::RelationBoundPublic,
            false,
            ProofLeafVisibility::Public,
            16,
            16,
            0,
        )
        .expect("the full tree opening geometry is valid");

        assert_eq!(ledger.tree_catalog_index(), 4);
        assert_eq!(ledger.source(), ProofTreeCatalogSource::RelationBoundPublic);
        assert_eq!(ledger.authentication_parent_hash_query_count(), 15);
        assert_eq!(ledger.common_context_hash_query_count(), 0);
        assert_eq!(ledger.secret_bearing_tree_root_count(), 0);
        assert_eq!(ledger.full_salted_leaf_count(), 0);
        assert_eq!(ledger.opened_salted_leaf_count(), 0);
        assert_eq!(ledger.hidden_salted_leaf_count(), 0);
        assert_eq!(ledger.full_secret_tree_hash_equation_count(), 0);
        assert_eq!(ledger.ideal_xof_query_count(), 31);
        assert_eq!(ledger.checked_oracle_equation_count(), 31);
    }

    #[test]
    fn empty_and_overflowing_tree_geometry_are_refused() {
        assert_eq!(
            derive_query_tree_hash_equation_ledger(
                0,
                SOURCE,
                true,
                ProofLeafVisibility::SecretBearing,
                16,
                0,
                0,
            ),
            Err(VerifierHashEquationLedgerError::InvalidOpeningGeometry)
        );
        assert_eq!(
            derive_query_tree_hash_equation_ledger(
                0,
                SOURCE,
                true,
                ProofLeafVisibility::SecretBearing,
                u64::MAX,
                u64::MAX,
                1,
            ),
            Err(VerifierHashEquationLedgerError::CountOverflow)
        );
        assert_eq!(
            derive_query_tree_hash_equation_ledger(
                0,
                SOURCE,
                true,
                ProofLeafVisibility::SecretBearing,
                8,
                9,
                1,
            ),
            Err(VerifierHashEquationLedgerError::InvalidOpeningGeometry)
        );
    }
}
