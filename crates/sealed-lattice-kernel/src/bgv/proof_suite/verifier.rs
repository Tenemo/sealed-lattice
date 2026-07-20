//! Bounded verifier for the suite-bound common transparent proof.
//!
//! The verifier derives every proof role, count, opening, and transcript round
//! from a checked relation plan.  It retains only the proof prefix, one
//! authenticated tree opening, and one small state per sampled query.  The
//! canonical query section is hashed while the same first read is decoded and
//! algebraically checked.

use crate::foundation::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple, FOUNDATION_PROFILE,
    PROOF_OBJECT_HEADER_SCHEMA_IDENTIFIER, PROOF_OBJECT_HEADER_SCHEMA_VERSION,
    ProofApplicationSlotCeilings, hash_foundation_tuple_512,
};
use crate::hashing::hash_framed_parts_512;

#[cfg(test)]
use super::CommittedMaterialTree;
#[cfg(test)]
use super::decode_proof_body_prefix;
use super::field::ProofChallengeExtensionElement;
use super::relation_plan::{
    BoundTreeConstructionKind, RelationColumnOrigin, RelationColumnValueType,
    RelationOpeningSourceClass, RelationPlanVariant, RelationSelectorPathStep,
    RelationTreeDescriptor, SelectorPathStepKind, SuiteModulusReference,
};
use super::{
    CommonProofPrivacyMode, CommonProofQueryOpeningAbsorber, CommonProofTranscript,
    CompiledRelationPlan, CompleteProofTreeCatalog, DecodedProofBodyPrefix,
    DeepCompositionVerificationInput, OpenedFriLayerPair, ProofBodyError, ProofBodyLayout,
    ProofByteSource, ProofDecodeError, ProofEvaluationDomain, ProofFriError, ProofFriQueryState,
    ProofFriQueryVerifier, ProofLeafVisibility, ProofOpeningClaimEvaluation, ProofOpeningError,
    ProofPolynomialError, ProofProfileError, ProofTreeCatalogInput, ProofTreeCatalogSource,
    ProofTreeOpening, ProofTreeRole, ProofTreeValue, RelationApplicationChallengeAssignment,
    RelationPlanCheckContext, RelationPlanError, RelationProofTreeInput,
    SelectedApplicationStatementContext, SelectedEvaluatorEntryKind,
    SelectedEvaluatorEntryPosition, SetupPublicPolynomialRootRole, SetupPublicPolynomialTree,
    StatementOwnedProofTreeInput, TranscriptError, ValidatedRelationPlanArtifact,
    build_complete_proof_tree_catalog, decode_proof_body_prefix_owned,
    decode_proof_query_section_header_at, decode_proof_query_tree_at,
    decode_selected_application_statement, evaluate_normalized_opening_claim_pair,
    proof_body_prefix_byte_length, proof_query_tree_byte_length,
    sample_relation_application_challenges, selected_evaluator_aggregate_entry_roots,
    selected_evaluator_aggregate_entry_roots_in_order, selected_evaluator_entry_positions,
    selected_relation_plan_check_context,
};

const PROOF_HEADER_HASH_DOMAIN: &str = "sealed-lattice/proof/header/v1";
const SELECTED_PROOF_FIELD_INDEX: u16 = 0;
const VERIFIED_COMMON_PROOF_STATEMENT_HASH_DOMAIN: &str =
    "sealed-lattice/common-proof/verified-application-statement/v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CommonProofVerifierError {
    CanonicalEncoding,
    Cancelled,
    InvalidApplicationStatement,
    InvalidProofHeader,
    InvalidBoundTree,
    InvalidTreeLayout,
    InvalidOpeningClaim,
    MissingVerifiedColumnValue,
    Profile(ProofProfileError),
    Relation(RelationPlanError),
    Body(ProofBodyError),
    Transcript(TranscriptError),
    Polynomial(ProofPolynomialError),
    Opening(ProofOpeningError),
    Fri(ProofFriError),
}

impl From<ProofProfileError> for CommonProofVerifierError {
    fn from(error: ProofProfileError) -> Self {
        Self::Profile(error)
    }
}

impl From<RelationPlanError> for CommonProofVerifierError {
    fn from(error: RelationPlanError) -> Self {
        Self::Relation(error)
    }
}

impl From<ProofBodyError> for CommonProofVerifierError {
    fn from(error: ProofBodyError) -> Self {
        Self::Body(error)
    }
}

impl From<TranscriptError> for CommonProofVerifierError {
    fn from(error: TranscriptError) -> Self {
        Self::Transcript(error)
    }
}

impl From<ProofPolynomialError> for CommonProofVerifierError {
    fn from(error: ProofPolynomialError) -> Self {
        Self::Polynomial(error)
    }
}

impl From<ProofOpeningError> for CommonProofVerifierError {
    fn from(error: ProofOpeningError) -> Self {
        Self::Opening(error)
    }
}

impl From<ProofFriError> for CommonProofVerifierError {
    fn from(error: ProofFriError) -> Self {
        Self::Fri(error)
    }
}

mod core_verification;
mod query_verification;
mod verification_state;
mod verified_values;

#[cfg(test)]
pub(crate) use core_verification::verify_common_proof;
pub(crate) use core_verification::{
    VerifiedRelationColumnEvaluator, VerifiedRelationColumnEvaluatorMemoryAccounting,
    verified_application_statement_hash,
};
#[cfg(test)]
pub(crate) use verification_state::CommonProofVerificationInput;
pub(crate) use verification_state::{
    CommonProofRequiredByteRange, CommonProofVerificationPoll,
    CommonProofVerificationResidentMemoryAccounting, CommonProofVerificationStateMachine,
    PollableCommonProofVerificationInput,
};
pub(crate) use verified_values::{
    VerifiedCommonProof, VerifiedEvaluatorAuxiliaryRoot, VerifiedEvaluatorKeyStore,
    VerifiedEvaluatorKeyStorePreflight, VerifiedEvaluatorRuntimeRoot, VerifiedStatementOwnedTree,
    VerifiedStreamedProofTreeTerminal, VerifiedStreamedProofTreeTerminalPreflight,
};

use core_verification::{
    absorb_relation_roots, catalog_root, decode_application_statement, derive_relation_tree_inputs,
    validate_evaluator_auxiliary_root_linkage, verified_proof_header_hash,
    verify_deep_composition_with_verified_sequences,
};
use query_verification::{QueryVerificationWorkspace, build_runtime_claim_groups};
#[cfg(test)]
use verification_state::verify_and_slice_proof_header;

#[cfg(test)]
mod tests;
