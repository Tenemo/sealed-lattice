//! Construction-driven common-proof verification support.

use super::{ProofBodyError, RelationPlanError};

const VERIFIED_COMMON_PROOF_STATEMENT_HASH_DOMAIN: &str =
    "sealed-lattice/common-proof/verified-application-statement/v1";

#[cfg(all(test, feature = "theorem-evidence"))]
pub(crate) const fn verified_common_proof_statement_hash_domain() -> &'static str {
    VERIFIED_COMMON_PROOF_STATEMENT_HASH_DOMAIN
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CommonProofVerifierError {
    CanonicalEncoding,
    InvalidApplicationStatement,
    InvalidProofHeader,
    InvalidBoundTree,
    InvalidTreeLayout,
    InvalidOpeningClaim,
    MissingVerifiedColumnValue,
    Relation(RelationPlanError),
    Body(ProofBodyError),
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

mod core_verification;
mod verification_state;
mod verified_values;

pub(crate) use core_verification::{
    VerifiedRelationColumnEvaluator, VerifiedRelationColumnEvaluatorMemoryAccounting,
    decode_application_statement, derive_relation_tree_inputs,
    validate_evaluator_auxiliary_root_linkage, verified_application_statement_hash,
    verify_out_of_domain_composition_with_verified_sequences,
};
pub(crate) use verification_state::{
    CommonProofRequiredByteRange, IncrementalExpectedProofObjectHeaderComparator,
};
pub(crate) use verified_values::{
    VerifiedCommonProof, VerifiedEvaluatorAuxiliaryRoot, VerifiedEvaluatorKeyStore,
    VerifiedEvaluatorKeyStorePreflight, VerifiedEvaluatorRuntimeRoot,
    VerifiedRowCodeWhirProofFacts, VerifiedStatementOwnedTree, VerifiedStreamedProofTreeTerminal,
    VerifiedStreamedProofTreeTerminalPreflight,
};
