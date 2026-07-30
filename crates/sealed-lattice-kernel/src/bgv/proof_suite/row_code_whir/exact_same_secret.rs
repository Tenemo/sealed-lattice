//! Exact production-authenticated same-secret construction.
//!
//! The prover enters the browser-owned setup authority, compiles the selected
//! same-secret relation, binds a persistent proof attempt to the canonical
//! witness, and consumes the production source adapter and private proof
//! coins. Synthetic columns are not accepted by this path.

use crate::{
    bgv::{
        proof_suite::{
            BorrowedVerifiedCommonProofCapability, CommonProofProverError,
            CommonProofRelationPlanCapability, CommonProofRuntimeError, CommonProofRuntimeLimits,
            CommonProofTranscript, IncrementalExpectedProofObjectHeaderComparator,
            MAXIMUM_COMMON_PROOF_BYTE_LENGTH, MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH,
            MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH, ProofTreeRole,
            SelectedApplicationStatementContext, VerifiedCommonProofStatementSource,
            VerifiedStatementOwnedTree, canonical_proof_object_header_bytes,
            compile_same_secret_relation_plan, decode_application_statement,
            decode_selected_same_secret_statement, derive_relation_tree_inputs,
            sample_relation_application_challenges,
            selected_committed_material_relation_plan_input, selected_relation_plan_check_context,
            selected_same_secret_relation_plan_input, verified_application_statement_hash,
        },
        setup::{
            SetupGenerationKeyRelationPreparationSource, SetupKeyRelationProofFamily,
            VerifiedVssShareLinkageTerminal,
        },
    },
    foundation::{
        CanonicalDecodeLimits, Hash512, ProofApplicationSlot, ProofApplicationSlotCeilings,
        ProofObjectHeader, RefusalReason,
    },
    hashing::hash_framed_parts_512,
};

#[cfg(all(test, not(target_arch = "wasm32")))]
use crate::hashing::StreamingHash512;

#[cfg(all(test, not(target_arch = "wasm32")))]
use crate::{
    bgv::{
        proof_suite::{
            CommonProofAuxiliaryColumnSynthesisCursor, CommonProofPreChallengeSourceCursor,
            CommonProofPreChallengeSourcePoll, CommonProofPrivateCoinCoordinate,
            CommonProofPrivateCoinSamplingCatalog, CommonProofPrivateCoinSamplingOperation,
            CommonProofPrivateCoinSource, CommonProofSourcePolynomial,
            PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
            RecordingCommonProofPrivateCoinSource, RelationProofTreeInput,
            common_proof_private_coin_coordinate_derivation_context_hash,
            construct_reversed_relation_column, encode_common_proof_checkpoint_cursor_manifest,
        },
        setup::{
            PreparedExactSameSecretGenerationSources, SetupGenerationAuthorityHandle,
            SetupGenerationKeyRelationApplication, populate_exact_same_secret_evidence_authority,
            release_setup_generation_authority,
            resolve_setup_generation_key_relation_preparation_source,
            with_setup_generation_key_relation,
        },
    },
    foundation::{
        PrivateRandomCursor, SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT,
        prepare_exact_same_secret_evidence_attempt,
    },
};

use std::collections::BTreeMap;

#[cfg(all(test, not(target_arch = "wasm32")))]
use super::NOMINAL_ROW_CODE_WHIR_PROOF_BYTE_LENGTH;
use super::{column_commitment::ColumnDigest, row_encoding::RowEncodingGeometry};
use crate::bgv::proof_suite::relation_plan::{RelationOpeningSourceClass, RelationTreeDescriptor};

mod aggregate_source;
mod exact_proof;
#[cfg(all(test, not(target_arch = "wasm32")))]
mod runtime_evidence_tests;

pub(in crate::bgv::proof_suite::row_code_whir) use aggregate_source::{
    ExactSameSecretAggregateMetadata, ExactSameSecretAggregateSource,
    ExactSameSecretAggregateSourceAction, ExactSameSecretAggregateSourceBatch,
    ExactSameSecretAggregateSourceTarget, ExactSameSecretAggregateWitness,
};
pub(in crate::bgv::proof_suite::row_code_whir) use exact_proof::{
    ExactBoundLeafOpening, ExactBoundTreeAuthentication, ExactSameSecretPhaseOpenings,
    ExactSameSecretProof, ExactSameSecretProofEncodingProgress, ExactSameSecretProofSinkEncoder,
    ExactSameSecretProofSinkEncodingError,
};
#[cfg(test)]
pub(in crate::bgv::proof_suite) use exact_proof::{
    ExactExtractorCorrespondenceFault, ExactPointConstraintExtractorCertificate,
    ExactPolynomialProtocolExtractorCertificate,
    canonical_row_code_whir_aggregate_opening_section_byte_ledger,
    canonical_row_code_whir_family_body_byte_length_ceiling,
    checked_exact_same_secret_extractor_correspondence,
    checked_exact_same_secret_extractor_correspondence_with_fault,
};
pub(crate) use exact_proof::{
    ExactSameSecretFinalProofVerification, ExactSameSecretIncrementalVerification,
};

#[cfg(all(test, not(target_arch = "wasm32")))]
const SOURCE_POLYNOMIAL_DIGEST_DOMAIN: &str =
    "sealed-lattice/exact-same-secret/source-polynomial/v1";
#[cfg(all(test, not(target_arch = "wasm32")))]
const SOURCE_CATALOG_DIGEST_DOMAIN: &str = "sealed-lattice/exact-same-secret/source-catalog/v1";
#[cfg(all(test, not(target_arch = "wasm32")))]
const EXACT_SAME_SECRET_EVIDENCE_REVISION: u8 = 4;
const EXACT_TRANSCRIPT_HEADER_DOMAIN: &[u8] =
    b"sealed-lattice/exact-same-secret/transcript-header/v2";
const LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT: usize =
    super::construction_plan::ROW_CODE_WHIR_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT;
const PHYSICAL_ROW_WITNESS_VARIABLE_COUNT: usize =
    super::construction_plan::ROW_CODE_WHIR_PHYSICAL_ROW_WITNESS_VARIABLE_COUNT;
const LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW: usize =
    super::construction_plan::ROW_CODE_WHIR_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW;
const EXACT_QUOTIENT_COMPONENT_COUNT: usize =
    super::super::selected_profile::SELECTED_QUOTIENT_COMPONENT_COUNT as usize;
const EXACT_ROW_CODE_LOG_INVERSE_RATE: usize =
    super::construction_plan::ROW_CODE_WHIR_LOG_INVERSE_RATE;
const VERIFIED_SAME_SECRET_LOW_DEGREE_PREREQUISITE_DOMAIN: &str =
    "sealed-lattice/same-secret/verified-low-degree-prerequisite/v2";
#[cfg(test)]
const TEST_VERIFIED_VSS_PROOF_RESULT_DIGEST: [u8; Hash512::BYTE_LENGTH] =
    [0x76; Hash512::BYTE_LENGTH];
#[cfg(test)]
const QUOTIENT_COMPONENT_CHUNK_COUNT: usize = 2;
#[cfg(all(test, not(target_arch = "wasm32")))]
const EXACT_ROW_PAD_SEED_BYTE_LENGTH: usize = core::mem::size_of::<[[u8; 32]; 3]>();

/// Opaque authority proving that the same-secret input roots already passed
/// the selected VSS low-degree verification.
///
/// There is no decoder or byte constructor. Production code can mint this
/// capability only from a positively verified VSS linkage terminal.
pub(in crate::bgv) struct VerifiedSameSecretLowDegreePrerequisite {
    protocol_version: u16,
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
    action_context_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    public_setup_seed: [u8; Hash512::BYTE_LENGTH],
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    roster_position: u16,
    ordered_input_roots: [[u8; Hash512::BYTE_LENGTH]; 8],
    binding_digest: [u8; Hash512::BYTE_LENGTH],
}

struct VerifiedVssLowDegreeEvidenceBinding {
    protocol_version: u16,
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
    action_context_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    public_setup_seed: [u8; Hash512::BYTE_LENGTH],
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    roster_position: u16,
    vss_application_statement_hash: [u8; Hash512::BYTE_LENGTH],
    vss_application_slot_hash: [u8; Hash512::BYTE_LENGTH],
    vss_canonical_application_binding_hash: [u8; Hash512::BYTE_LENGTH],
    vss_relation_plan_hash: [u8; Hash512::BYTE_LENGTH],
    vss_relation_plan_variant_hash: [u8; Hash512::BYTE_LENGTH],
    vss_construction_plan_identity_hash: [u8; Hash512::BYTE_LENGTH],
    vss_certificate_geometry_digest: [u8; Hash512::BYTE_LENGTH],
    owning_verification_binding_hash: [u8; Hash512::BYTE_LENGTH],
    owning_proof_header_hash: [u8; Hash512::BYTE_LENGTH],
    owning_proof_stream_digest: [u8; Hash512::BYTE_LENGTH],
    ordered_input_roots: [[u8; Hash512::BYTE_LENGTH]; 8],
}

#[derive(Clone)]
struct ExactSameSecretVerificationContext {
    protocol_version: u16,
    application_slot: ProofApplicationSlot,
    canonical_application_statement_bytes: Vec<u8>,
    statement_owned_trees: Vec<VerifiedStatementOwnedTree>,
    canonical_proof_object_header_bytes: Vec<u8>,
}

impl ExactSameSecretVerificationContext {
    fn new(
        protocol_version: u16,
        application_slot: ProofApplicationSlot,
        canonical_application_statement_bytes: Vec<u8>,
        statement_owned_trees: Vec<VerifiedStatementOwnedTree>,
    ) -> Result<Self, String> {
        if protocol_version == 0 || statement_owned_trees.is_empty() {
            return Err("exact same-secret verification context is incomplete".to_owned());
        }
        let canonical_proof_object_header_bytes =
            canonical_proof_object_header_bytes(&canonical_application_statement_bytes)
                .map_err(|error| format!("encode exact proof-object header: {error:?}"))?;
        Ok(Self {
            protocol_version,
            application_slot,
            canonical_application_statement_bytes,
            statement_owned_trees,
            canonical_proof_object_header_bytes,
        })
    }
}

pub(crate) struct PreparedExactSameSecretVerification {
    prerequisite: VerifiedSameSecretLowDegreePrerequisite,
    context: ExactSameSecretVerificationContext,
    header_comparator: IncrementalExpectedProofObjectHeaderComparator,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExactSameSecretVerificationResidentMemoryAccounting {
    maximum_resident_byte_length: u64,
}

impl ExactSameSecretVerificationResidentMemoryAccounting {
    pub(crate) const fn new(maximum_resident_byte_length: u64) -> Self {
        Self {
            maximum_resident_byte_length,
        }
    }

    pub(crate) const fn maximum_resident_byte_length(self) -> u64 {
        self.maximum_resident_byte_length
    }
}

impl PreparedExactSameSecretVerification {
    pub(crate) fn into_incremental(self) -> Result<ExactSameSecretIncrementalVerification, String> {
        ExactSameSecretIncrementalVerification::new(
            self.prerequisite,
            self.context,
            self.header_comparator,
        )
    }
}

/// Derives verifier limits from the selected exact construction and the proof
/// stream descriptor committed by the accepted package. Cryptographic
/// admission uses the common anti-exhaustion ceiling; the selected proof-size
/// target is enforced only by generation and evidence.
pub(crate) fn exact_same_secret_verification_runtime_limits(
    relation_plan: &CommonProofRelationPlanCapability,
    canonical_proof_byte_length: u64,
) -> Result<CommonProofRuntimeLimits, CommonProofRuntimeError> {
    exact_proof::validate_exact_same_secret_verification_construction(relation_plan)
        .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
    let canonical_proof_byte_length_usize = usize::try_from(canonical_proof_byte_length)
        .map_err(|_| CommonProofRuntimeError::InvalidLimits)?;
    if canonical_proof_byte_length_usize == 0
        || canonical_proof_byte_length_usize > MAXIMUM_COMMON_PROOF_BYTE_LENGTH
    {
        return Err(CommonProofRuntimeError::WrongVerificationBinding);
    }
    let prefetched_proof_byte_length =
        canonical_proof_byte_length_usize.min(MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH);
    CommonProofRuntimeLimits::new(
        MAXIMUM_COMMON_PROOF_BYTE_LENGTH,
        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
        u64::try_from(prefetched_proof_byte_length)
            .map_err(|_| CommonProofRuntimeError::InvalidLimits)?,
    )
}

pub(crate) fn exact_same_secret_verification_resident_memory_accounting(
    relation_plan: &CommonProofRelationPlanCapability,
    canonical_proof_byte_length: u64,
    canonical_application_statement_bytes: &[u8],
) -> Result<ExactSameSecretVerificationResidentMemoryAccounting, CommonProofRuntimeError> {
    exact_same_secret_verification_runtime_limits(relation_plan, canonical_proof_byte_length)?;
    if canonical_application_statement_bytes.is_empty() {
        return Err(CommonProofRuntimeError::WrongVerificationBinding);
    }
    let canonical_proof_byte_length = usize::try_from(canonical_proof_byte_length)
        .map_err(|_| CommonProofRuntimeError::InvalidLimits)?;
    let canonical_proof_object_header_byte_length =
        canonical_proof_object_header_bytes(canonical_application_statement_bytes)
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?
            .len();
    if canonical_proof_object_header_byte_length >= canonical_proof_byte_length {
        return Err(CommonProofRuntimeError::WrongVerificationBinding);
    }
    exact_proof::derive_exact_same_secret_verification_resident_memory_accounting(
        relation_plan,
        canonical_application_statement_bytes.len(),
        canonical_proof_object_header_byte_length,
        canonical_proof_byte_length,
    )
    .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)
}

pub(crate) fn prepare_exact_same_secret_verification(
    prerequisite: VerifiedSameSecretLowDegreePrerequisite,
    statement_source: &VerifiedCommonProofStatementSource,
    statement_trees: Vec<VerifiedStatementOwnedTree>,
) -> Result<PreparedExactSameSecretVerification, String> {
    let proof_application_binding = statement_source.proof_application_binding();
    let application_slot = proof_application_binding.application_slot();
    let context = ExactSameSecretVerificationContext::new(
        prerequisite.protocol_version(),
        application_slot,
        statement_source
            .canonical_application_statement_bytes()
            .to_vec(),
        statement_trees,
    )?;
    let expected_proof_header_hash = ProofObjectHeader::decode(
        &context.canonical_proof_object_header_bytes,
        &CanonicalDecodeLimits::default(),
    )
    .and_then(|header| header.proof_header_hash())
    .map_err(|error| format!("hash exact proof-object header: {error:?}"))?;
    if expected_proof_header_hash != proof_application_binding.proof_header_hash() {
        return Err(
            "exact proof-object header does not match the authenticated binding".to_owned(),
        );
    }
    exact_proof::validate_verification_context_bindings(&prerequisite, &context)?;
    let expected_canonical_proof_byte_length = usize::try_from(
        proof_application_binding
            .proof_stream_descriptor()
            .total_byte_length,
    )
    .map_err(|_| "exact same-secret proof byte length exceeds usize".to_owned())?;
    if expected_canonical_proof_byte_length == 0
        || expected_canonical_proof_byte_length > MAXIMUM_COMMON_PROOF_BYTE_LENGTH
    {
        return Err("exact same-secret proof byte length exceeds the common hard limit".to_owned());
    }
    let header_comparator = IncrementalExpectedProofObjectHeaderComparator::new(
        context.canonical_proof_object_header_bytes.clone(),
        expected_canonical_proof_byte_length,
        MAXIMUM_COMMON_PROOF_BYTE_LENGTH,
    )
    .map_err(|error| format!("validate exact proof-object framing: {error:?}"))?;
    Ok(PreparedExactSameSecretVerification {
        prerequisite,
        context,
        header_comparator,
    })
}

impl VerifiedSameSecretLowDegreePrerequisite {
    pub(in crate::bgv) fn from_positive_verified_vss_share_linkage(
        terminal: &VerifiedVssShareLinkageTerminal,
        verified_proof: BorrowedVerifiedCommonProofCapability<'_>,
        relation_plan: &CommonProofRelationPlanCapability,
    ) -> Result<Self, RefusalReason> {
        let ordered_input_roots = selected_vss_degree_zero_coefficient_roots(
            terminal.ordered_coefficient_material_roots(),
        )?;
        let vss_certificate_geometry_digest = relation_plan
            .row_code_whir_construction_plan()
            .selected_vss_low_degree_certificate_geometry_digest()
            .map_err(|_| RefusalReason::WrongTypeOrLength)?;
        let canonical_prior_proof_descriptor = terminal
            .proof_stream_descriptor()
            .encode()
            .map_err(|_| RefusalReason::WrongTypeOrLength)?;
        let vss_construction_plan_identity_hash =
            relation_plan.row_code_whir_construction_plan_identity_hash();
        if relation_plan.application_statement_schema_identifier()
            != ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER
            || relation_plan.relation_plan_hash() != verified_proof.relation_plan_hash()
            || relation_plan.relation_plan_variant_hash()
                != verified_proof.relation_plan_variant_hash()
            || verified_proof.schedule_position().is_some()
            || verified_proof.top_count().is_some()
            || verified_proof.protocol_version() != terminal.protocol_version()
            || verified_proof.suite_identifier() != terminal.suite_identifier()
            || verified_proof.ceremony_context_hash() != terminal.ceremony_context_hash()
            || verified_proof.action_context_hash() != terminal.action_context_hash()
            || verified_proof.board_object_hash() != terminal.board_object_hash()
            || verified_proof.proof_stream_descriptor() != terminal.proof_stream_descriptor()
            || verified_proof.proof_stream_full_object_digest()
                != terminal
                    .proof_stream_descriptor()
                    .full_object_digest
                    .into_bytes()
            || vss_construction_plan_identity_hash == [0_u8; Hash512::BYTE_LENGTH]
        {
            return Err(RefusalReason::WrongHashOrRoot);
        }
        Self::new(
            VerifiedVssLowDegreeEvidenceBinding {
                protocol_version: terminal.protocol_version(),
                suite_identifier: terminal.suite_identifier(),
                ceremony_context_hash: terminal.ceremony_context_hash(),
                action_context_hash: terminal.action_context_hash(),
                roster_hash: terminal.roster_hash(),
                public_setup_seed: terminal.public_setup_seed(),
                setup_proof_context_hash: terminal.setup_proof_context_hash(),
                participant_identity: terminal.participant_identity(),
                roster_position: terminal.roster_position(),
                vss_application_statement_hash: verified_proof.application_statement_hash(),
                vss_application_slot_hash: verified_proof.proof_application_slot_hash(),
                vss_canonical_application_binding_hash: verified_proof
                    .canonical_proof_application_binding_hash(),
                vss_relation_plan_hash: relation_plan.relation_plan_hash(),
                vss_relation_plan_variant_hash: relation_plan.relation_plan_variant_hash(),
                vss_construction_plan_identity_hash,
                vss_certificate_geometry_digest,
                owning_verification_binding_hash: verified_proof.verification_binding_hash(),
                owning_proof_header_hash: verified_proof.proof_header_hash(),
                owning_proof_stream_digest: verified_proof.proof_stream_full_object_digest(),
                ordered_input_roots,
            },
            ordered_input_roots,
            &canonical_prior_proof_descriptor,
        )
    }

    fn new(
        evidence: VerifiedVssLowDegreeEvidenceBinding,
        ordered_input_roots: [[u8; Hash512::BYTE_LENGTH]; 8],
        canonical_prior_proof_descriptor: &[u8],
    ) -> Result<Self, RefusalReason> {
        let zero_hash = [0_u8; Hash512::BYTE_LENGTH];
        if evidence.protocol_version == 0
            || evidence.suite_identifier == zero_hash
            || evidence.ceremony_context_hash == zero_hash
            || evidence.action_context_hash == zero_hash
            || evidence.roster_hash == zero_hash
            || evidence.public_setup_seed == zero_hash
            || evidence.setup_proof_context_hash == zero_hash
            || evidence.participant_identity == zero_hash
            || evidence.vss_application_statement_hash == zero_hash
            || evidence.vss_application_slot_hash == zero_hash
            || evidence.vss_canonical_application_binding_hash == zero_hash
            || evidence.vss_relation_plan_hash == zero_hash
            || evidence.vss_relation_plan_variant_hash == zero_hash
            || evidence.vss_construction_plan_identity_hash == zero_hash
            || evidence.vss_certificate_geometry_digest == zero_hash
            || evidence.owning_verification_binding_hash == zero_hash
            || evidence.owning_proof_header_hash == zero_hash
            || evidence.owning_proof_stream_digest == zero_hash
            || ordered_input_roots.contains(&[0_u8; Hash512::BYTE_LENGTH])
            || ordered_input_roots != evidence.ordered_input_roots
            || canonical_prior_proof_descriptor.is_empty()
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        let row_code_parameters = [
            LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT as u64,
            PHYSICAL_ROW_WITNESS_VARIABLE_COUNT as u64,
            LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW as u64,
            EXACT_ROW_CODE_LOG_INVERSE_RATE as u64,
        ]
        .into_iter()
        .flat_map(u64::to_le_bytes)
        .collect::<Vec<_>>();
        let input_root_bytes = ordered_input_roots
            .iter()
            .flat_map(|root| root.iter().copied())
            .collect::<Vec<_>>();
        let binding_digest = hash_framed_parts_512(
            VERIFIED_SAME_SECRET_LOW_DEGREE_PREREQUISITE_DOMAIN,
            &[
                &evidence.protocol_version.to_le_bytes(),
                &evidence.suite_identifier,
                &evidence.ceremony_context_hash,
                &evidence.action_context_hash,
                &evidence.roster_hash,
                &evidence.public_setup_seed,
                &evidence.setup_proof_context_hash,
                &evidence.participant_identity,
                &evidence.roster_position.to_le_bytes(),
                &input_root_bytes,
                &row_code_parameters,
                &evidence.vss_application_statement_hash,
                &evidence.vss_application_slot_hash,
                &evidence.vss_canonical_application_binding_hash,
                &evidence.vss_relation_plan_hash,
                &evidence.vss_relation_plan_variant_hash,
                &evidence.vss_construction_plan_identity_hash,
                &evidence.vss_certificate_geometry_digest,
                &evidence.owning_verification_binding_hash,
                &evidence.owning_proof_header_hash,
                &evidence.owning_proof_stream_digest,
                canonical_prior_proof_descriptor,
            ],
        );
        Ok(Self {
            protocol_version: evidence.protocol_version,
            suite_identifier: evidence.suite_identifier,
            ceremony_context_hash: evidence.ceremony_context_hash,
            action_context_hash: evidence.action_context_hash,
            roster_hash: evidence.roster_hash,
            public_setup_seed: evidence.public_setup_seed,
            setup_proof_context_hash: evidence.setup_proof_context_hash,
            participant_identity: evidence.participant_identity,
            roster_position: evidence.roster_position,
            ordered_input_roots,
            binding_digest,
        })
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn for_test(
        protocol_version: u16,
        suite_identifier: [u8; Hash512::BYTE_LENGTH],
        ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
        action_context_hash: [u8; Hash512::BYTE_LENGTH],
        public_setup_seed: [u8; Hash512::BYTE_LENGTH],
        setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
        participant_identity: [u8; Hash512::BYTE_LENGTH],
        roster_position: u16,
        ordered_input_roots: [[u8; Hash512::BYTE_LENGTH]; 8],
        prior_proof_result_digest: [u8; Hash512::BYTE_LENGTH],
    ) -> Result<Self, RefusalReason> {
        let nonzero_test_binding = prior_proof_result_digest;
        Self::new(
            VerifiedVssLowDegreeEvidenceBinding {
                protocol_version,
                suite_identifier,
                ceremony_context_hash,
                action_context_hash,
                roster_hash: nonzero_test_binding,
                public_setup_seed,
                setup_proof_context_hash,
                participant_identity,
                roster_position,
                vss_application_statement_hash: nonzero_test_binding,
                vss_application_slot_hash: nonzero_test_binding,
                vss_canonical_application_binding_hash: nonzero_test_binding,
                vss_relation_plan_hash: nonzero_test_binding,
                vss_relation_plan_variant_hash: nonzero_test_binding,
                vss_construction_plan_identity_hash: nonzero_test_binding,
                vss_certificate_geometry_digest: nonzero_test_binding,
                owning_verification_binding_hash: nonzero_test_binding,
                owning_proof_header_hash: nonzero_test_binding,
                owning_proof_stream_digest: nonzero_test_binding,
                ordered_input_roots,
            },
            ordered_input_roots,
            &prior_proof_result_digest,
        )
    }

    const fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    const fn suite_identifier(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.suite_identifier
    }

    const fn ceremony_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.ceremony_context_hash
    }

    const fn action_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.action_context_hash
    }

    const fn public_setup_seed(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.public_setup_seed
    }

    const fn setup_proof_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.setup_proof_context_hash
    }

    const fn participant_identity(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.participant_identity
    }

    const fn roster_position(&self) -> u16 {
        self.roster_position
    }

    const fn ordered_input_roots(&self) -> &[[u8; Hash512::BYTE_LENGTH]; 8] {
        &self.ordered_input_roots
    }

    const fn binding_digest(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.binding_digest
    }

    pub(in crate::bgv) fn matches_same_secret_generation_source(
        &self,
        source: &SetupGenerationKeyRelationPreparationSource,
        ordered_degree_zero_roots: &[[u8; Hash512::BYTE_LENGTH]],
    ) -> bool {
        source.family() == SetupKeyRelationProofFamily::SameSecret
            && self.protocol_version == source.protocol_version()
            && self.suite_identifier == source.suite_identifier()
            && self.ceremony_context_hash == source.ceremony_context_hash()
            && self.action_context_hash == source.action_context_hash()
            && self.roster_hash == source.roster_hash()
            && self.public_setup_seed == source.public_setup_seed()
            && self.setup_proof_context_hash == source.setup_proof_context_hash()
            && self.participant_identity == source.participant_identity()
            && self.roster_position == source.roster_position()
            && ordered_degree_zero_roots == self.ordered_input_roots
    }
}

/// Public Fiat-Shamir facts that a fresh exact verifier recomputes from the
/// canonical application, the checked relation, and the selected
/// construction. Attempt lineage, proof coins, checkpoint state, and proof
/// transport coordinates are deliberately absent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) struct ExactSameSecretFiatShamirBinding {
    protocol_version: u16,
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
    action_context_hash: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    roster_position: u16,
    proof_application_slot_hash: [u8; Hash512::BYTE_LENGTH],
    application_statement_schema_identifier: u16,
    application_statement_hash: [u8; Hash512::BYTE_LENGTH],
    proof_header_hash: [u8; Hash512::BYTE_LENGTH],
    relation_plan_hash: [u8; Hash512::BYTE_LENGTH],
    relation_plan_variant_hash: [u8; Hash512::BYTE_LENGTH],
    construction_plan_identity_hash: [u8; Hash512::BYTE_LENGTH],
    oracle_equation_catalog_hash: [u8; Hash512::BYTE_LENGTH],
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    ordered_source_roots: [[u8; Hash512::BYTE_LENGTH]; 11],
}

impl ExactSameSecretFiatShamirBinding {
    pub(in crate::bgv::proof_suite) fn derive(
        protocol_version: u16,
        suite_identifier: [u8; Hash512::BYTE_LENGTH],
        ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
        action_context_hash: [u8; Hash512::BYTE_LENGTH],
        canonical_application_statement_bytes: &[u8],
        relation_plan: &CommonProofRelationPlanCapability,
    ) -> Result<Self, String> {
        let application_statement_schema_identifier =
            SetupKeyRelationProofFamily::SameSecret.statement_schema_identifier();
        if protocol_version == 0
            || suite_identifier == [0_u8; Hash512::BYTE_LENGTH]
            || ceremony_context_hash == [0_u8; Hash512::BYTE_LENGTH]
            || action_context_hash == [0_u8; Hash512::BYTE_LENGTH]
            || relation_plan.application_statement_schema_identifier()
                != application_statement_schema_identifier
        {
            return Err("exact same-secret transcript authority has the wrong context".to_owned());
        }
        let statement = decode_selected_same_secret_statement(
            canonical_application_statement_bytes,
            SelectedApplicationStatementContext::new(
                protocol_version,
                suite_identifier,
                None,
                None,
            ),
        )
        .map_err(|error| format!("decode exact same-secret transcript statement: {error:?}"))?;
        let mut ordered_source_roots = statement.ordered_degree_zero_commitment_roots().to_vec();
        ordered_source_roots.extend_from_slice(&statement.anchor_commitment_roots());
        let ordered_source_roots: [[u8; Hash512::BYTE_LENGTH]; 11] = ordered_source_roots
            .try_into()
            .map_err(|_| "exact same-secret transcript source-root count is wrong".to_owned())?;
        if ordered_source_roots.contains(&[0_u8; Hash512::BYTE_LENGTH])
            || statement.setup_proof_context_hash() == [0_u8; Hash512::BYTE_LENGTH]
            || statement.participant_identity() == [0_u8; Hash512::BYTE_LENGTH]
        {
            return Err("exact same-secret transcript statement is empty".to_owned());
        }
        let proof_application_slot = ProofApplicationSlot::new(
            Hash512::from_bytes(suite_identifier),
            Hash512::from_bytes(ceremony_context_hash),
            Hash512::from_bytes(action_context_hash),
            application_statement_schema_identifier,
            Some(statement.roster_position()),
            None,
            None,
        )
        .map_err(|error| format!("construct exact same-secret application slot: {error:?}"))?;
        let proof_application_slot_hash = proof_application_slot
            .hash()
            .map_err(|error| format!("hash exact same-secret application slot: {error:?}"))?
            .into_bytes();
        let application_statement_hash = verified_application_statement_hash(
            protocol_version,
            suite_identifier,
            application_statement_schema_identifier,
            canonical_application_statement_bytes,
        );
        let proof_header_hash = ProofObjectHeader::from_canonical_application_statement(
            canonical_application_statement_bytes.to_vec(),
            &CanonicalDecodeLimits::default(),
        )
        .and_then(|header| header.proof_header_hash())
        .map_err(|error| format!("hash exact same-secret proof header: {error:?}"))?
        .into_bytes();
        let construction_plan = relation_plan.row_code_whir_construction_plan();
        let construction_plan_identity_hash = construction_plan
            .canonical_identity_hash()
            .map_err(|error| format!("hash exact same-secret construction: {error:?}"))?;
        let oracle_equation_catalog_hash = construction_plan
            .oracle_equation_catalog_hash()
            .map_err(|error| format!("hash exact same-secret oracle catalog: {error:?}"))?;
        if construction_plan_identity_hash
            != relation_plan.row_code_whir_construction_plan_identity_hash()
            || construction_plan.relation_plan_hash() != relation_plan.relation_plan_hash()
            || construction_plan.relation_plan_variant_hash()
                != relation_plan.relation_plan_variant_hash()
            || oracle_equation_catalog_hash == [0_u8; Hash512::BYTE_LENGTH]
        {
            return Err("exact same-secret transcript construction binding is wrong".to_owned());
        }
        Ok(Self {
            protocol_version,
            suite_identifier,
            ceremony_context_hash,
            action_context_hash,
            participant_identity: statement.participant_identity(),
            roster_position: statement.roster_position(),
            proof_application_slot_hash,
            application_statement_schema_identifier,
            application_statement_hash,
            proof_header_hash,
            relation_plan_hash: relation_plan.relation_plan_hash(),
            relation_plan_variant_hash: relation_plan.relation_plan_variant_hash(),
            construction_plan_identity_hash,
            oracle_equation_catalog_hash,
            setup_proof_context_hash: statement.setup_proof_context_hash(),
            ordered_source_roots,
        })
    }

    pub(in crate::bgv::proof_suite) const fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    pub(in crate::bgv::proof_suite) const fn suite_identifier(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.suite_identifier
    }

    pub(in crate::bgv::proof_suite) const fn ceremony_context_hash(
        &self,
    ) -> [u8; Hash512::BYTE_LENGTH] {
        self.ceremony_context_hash
    }

    pub(in crate::bgv::proof_suite) const fn action_context_hash(
        &self,
    ) -> [u8; Hash512::BYTE_LENGTH] {
        self.action_context_hash
    }

    pub(in crate::bgv::proof_suite) const fn participant_identity(
        &self,
    ) -> [u8; Hash512::BYTE_LENGTH] {
        self.participant_identity
    }

    pub(in crate::bgv::proof_suite) const fn roster_position(&self) -> u16 {
        self.roster_position
    }

    pub(in crate::bgv::proof_suite) const fn proof_application_slot_hash(
        &self,
    ) -> [u8; Hash512::BYTE_LENGTH] {
        self.proof_application_slot_hash
    }

    pub(in crate::bgv::proof_suite) const fn application_statement_schema_identifier(&self) -> u16 {
        self.application_statement_schema_identifier
    }

    pub(in crate::bgv::proof_suite) const fn application_statement_hash(
        &self,
    ) -> [u8; Hash512::BYTE_LENGTH] {
        self.application_statement_hash
    }

    pub(in crate::bgv::proof_suite) const fn proof_header_hash(
        &self,
    ) -> [u8; Hash512::BYTE_LENGTH] {
        self.proof_header_hash
    }

    pub(in crate::bgv::proof_suite) const fn relation_plan_hash(
        &self,
    ) -> [u8; Hash512::BYTE_LENGTH] {
        self.relation_plan_hash
    }

    pub(in crate::bgv::proof_suite) const fn relation_plan_variant_hash(
        &self,
    ) -> [u8; Hash512::BYTE_LENGTH] {
        self.relation_plan_variant_hash
    }

    pub(in crate::bgv::proof_suite) const fn construction_plan_identity_hash(
        &self,
    ) -> [u8; Hash512::BYTE_LENGTH] {
        self.construction_plan_identity_hash
    }

    pub(in crate::bgv::proof_suite) const fn oracle_equation_catalog_hash(
        &self,
    ) -> [u8; Hash512::BYTE_LENGTH] {
        self.oracle_equation_catalog_hash
    }

    pub(in crate::bgv::proof_suite) const fn ordered_source_roots(
        &self,
    ) -> &[[u8; Hash512::BYTE_LENGTH]; 11] {
        &self.ordered_source_roots
    }
}

/// Attempt-scoped authority retained only inside Rust. The private fields
/// prevent a prefix prepared for one attempt or checkpoint lineage from being
/// replayed into another operation, but they never enter Fiat-Shamir state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) struct ExactSameSecretTranscriptPrefixAuthorityBinding {
    fiat_shamir_binding: ExactSameSecretFiatShamirBinding,
    generation_binding_hash: [u8; Hash512::BYTE_LENGTH],
    attempt_identifier: [u8; 32],
}

impl ExactSameSecretTranscriptPrefixAuthorityBinding {
    pub(in crate::bgv::proof_suite) fn new(
        fiat_shamir_binding: ExactSameSecretFiatShamirBinding,
        generation_binding_hash: [u8; Hash512::BYTE_LENGTH],
        attempt_identifier: [u8; 32],
    ) -> Result<Self, CommonProofProverError> {
        if generation_binding_hash == [0_u8; Hash512::BYTE_LENGTH]
            || attempt_identifier == [0_u8; 32]
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        Ok(Self {
            fiat_shamir_binding,
            generation_binding_hash,
            attempt_identifier,
        })
    }

    pub(in crate::bgv::proof_suite) const fn fiat_shamir_binding(
        &self,
    ) -> &ExactSameSecretFiatShamirBinding {
        &self.fiat_shamir_binding
    }

    pub(in crate::bgv::proof_suite) const fn generation_binding_hash(
        &self,
    ) -> [u8; Hash512::BYTE_LENGTH] {
        self.generation_binding_hash
    }

    pub(in crate::bgv::proof_suite) const fn attempt_identifier(&self) -> [u8; 32] {
        self.attempt_identifier
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) struct ExactSameSecretAuthenticatedTranscriptPrefixRequest {
    authority_binding: ExactSameSecretTranscriptPrefixAuthorityBinding,
    source_replay_identity_digest: [u8; Hash512::BYTE_LENGTH],
    committed_base_root: [u8; Hash512::BYTE_LENGTH],
}

impl ExactSameSecretAuthenticatedTranscriptPrefixRequest {
    pub(in crate::bgv::proof_suite) fn new(
        authority_binding: ExactSameSecretTranscriptPrefixAuthorityBinding,
        source_replay_identity_digest: [u8; Hash512::BYTE_LENGTH],
        committed_base_root: [u8; Hash512::BYTE_LENGTH],
    ) -> Result<Self, CommonProofProverError> {
        if source_replay_identity_digest == [0_u8; Hash512::BYTE_LENGTH]
            || committed_base_root == [0_u8; Hash512::BYTE_LENGTH]
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        Ok(Self {
            authority_binding,
            source_replay_identity_digest,
            committed_base_root,
        })
    }

    pub(in crate::bgv::proof_suite) const fn authority_binding(
        &self,
    ) -> &ExactSameSecretTranscriptPrefixAuthorityBinding {
        &self.authority_binding
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) struct ExactSameSecretAuthenticatedTranscriptPrefixBinding {
    request: ExactSameSecretAuthenticatedTranscriptPrefixRequest,
    verified_prerequisite_binding: [u8; Hash512::BYTE_LENGTH],
}

pub(in crate::bgv::proof_suite) struct PreparedExactSameSecretTranscriptPrefix {
    binding: ExactSameSecretAuthenticatedTranscriptPrefixBinding,
    transcript: CommonProofTranscript,
}

impl PreparedExactSameSecretTranscriptPrefix {
    pub(in crate::bgv::proof_suite) fn prepare(
        request: ExactSameSecretAuthenticatedTranscriptPrefixRequest,
        prerequisite: &VerifiedSameSecretLowDegreePrerequisite,
        relation_plan: &CommonProofRelationPlanCapability,
    ) -> Result<Self, CommonProofProverError> {
        let fiat_shamir_binding = request.authority_binding.fiat_shamir_binding();
        let construction_plan = relation_plan.row_code_whir_construction_plan();
        if prerequisite.protocol_version() != fiat_shamir_binding.protocol_version
            || prerequisite.suite_identifier() != fiat_shamir_binding.suite_identifier
            || prerequisite.ceremony_context_hash() != fiat_shamir_binding.ceremony_context_hash
            || prerequisite.action_context_hash() != fiat_shamir_binding.action_context_hash
            || prerequisite.setup_proof_context_hash()
                != fiat_shamir_binding.setup_proof_context_hash
            || prerequisite.participant_identity() != fiat_shamir_binding.participant_identity
            || prerequisite.roster_position() != fiat_shamir_binding.roster_position
            || prerequisite.ordered_input_roots() != &fiat_shamir_binding.ordered_source_roots[..8]
            || relation_plan.relation_plan_hash() != fiat_shamir_binding.relation_plan_hash
            || relation_plan.relation_plan_variant_hash()
                != fiat_shamir_binding.relation_plan_variant_hash
            || relation_plan.row_code_whir_construction_plan_identity_hash()
                != fiat_shamir_binding.construction_plan_identity_hash
            || construction_plan
                .oracle_equation_catalog_hash()
                .map_err(|_| CommonProofProverError::InvalidInput)?
                != fiat_shamir_binding.oracle_equation_catalog_hash
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        let verified_prerequisite_binding = prerequisite.binding_digest();
        let header = exact_transcript_header(fiat_shamir_binding, verified_prerequisite_binding);
        let mut transcript = CommonProofTranscript::new_relation_prefix_for_construction_plan(
            fiat_shamir_binding.protocol_version,
            fiat_shamir_binding.suite_identifier,
            construction_plan,
            fiat_shamir_binding.application_statement_schema_identifier,
            &header,
            construction_plan.relation_prefix_schedule().clone(),
        )
        .map_err(|_| CommonProofProverError::InvalidInput)?;
        for tree_ordinal in construction_plan
            .relation_prefix_schedule()
            .ordered_base_tree_ordinals()
        {
            transcript
                .absorb_base_root(*tree_ordinal, request.committed_base_root)
                .map_err(|_| CommonProofProverError::InvalidInput)?;
        }
        Ok(Self {
            binding: ExactSameSecretAuthenticatedTranscriptPrefixBinding {
                request,
                verified_prerequisite_binding,
            },
            transcript,
        })
    }

    pub(in crate::bgv::proof_suite) const fn binding(
        &self,
    ) -> &ExactSameSecretAuthenticatedTranscriptPrefixBinding {
        &self.binding
    }

    pub(in crate::bgv::proof_suite) fn into_transcript(self) -> CommonProofTranscript {
        self.transcript
    }
}

impl ExactSameSecretAuthenticatedTranscriptPrefixBinding {
    pub(in crate::bgv::proof_suite) const fn request(
        &self,
    ) -> &ExactSameSecretAuthenticatedTranscriptPrefixRequest {
        &self.request
    }

    pub(in crate::bgv::proof_suite) const fn verified_prerequisite_binding(
        &self,
    ) -> [u8; Hash512::BYTE_LENGTH] {
        self.verified_prerequisite_binding
    }
}

fn selected_vss_degree_zero_coefficient_roots(
    ordered_coefficient_material_roots: &[[u8; Hash512::BYTE_LENGTH]],
) -> Result<[[u8; Hash512::BYTE_LENGTH]; 8], RefusalReason> {
    let relation_input = selected_committed_material_relation_plan_input()
        .map_err(|_| RefusalReason::WrongTypeOrLength)?;
    let sharing_limb_count = relation_input.sharing_data_modulus_indices.len();
    let reconstruction_threshold = usize::from(relation_input.threshold);
    let expected_root_count = sharing_limb_count
        .checked_mul(reconstruction_threshold)
        .ok_or(RefusalReason::WrongTypeOrLength)?;
    if sharing_limb_count != 8
        || reconstruction_threshold == 0
        || ordered_coefficient_material_roots.len() != expected_root_count
    {
        return Err(RefusalReason::WrongTypeOrLength);
    }

    (0..sharing_limb_count)
        .map(|sharing_limb_ordinal| {
            sharing_limb_ordinal
                .checked_mul(reconstruction_threshold)
                .and_then(|root_ordinal| ordered_coefficient_material_roots.get(root_ordinal))
                .copied()
                .ok_or(RefusalReason::WrongTypeOrLength)
        })
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| RefusalReason::WrongTypeOrLength)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ExactBasePhaseRow {
    column_ordinals: [Option<u32>; LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW],
    opening_point_ordinals: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ExactBasePhaseLayout {
    rows: Vec<ExactBasePhaseRow>,
}

impl ExactBasePhaseLayout {
    fn for_tree_role(
        variant: &crate::bgv::proof_suite::RelationPlanVariant,
        tree_role: ProofTreeRole,
    ) -> Result<Self, String> {
        let proof_tree_role = tree_role as u16;
        let mut opening_points_by_column = BTreeMap::<u32, Vec<u32>>::new();
        for tree in variant.ordered_trees() {
            let RelationTreeDescriptor::ProofCreated {
                proof_tree_role: descriptor_role,
                ordered_column_ordinals,
            } = tree
            else {
                continue;
            };
            if *descriptor_role != proof_tree_role {
                continue;
            }
            for column_ordinal in ordered_column_ordinals {
                if opening_points_by_column
                    .insert(*column_ordinal, Vec::new())
                    .is_some()
                {
                    return Err(format!(
                        "relation column {column_ordinal} occurs in more than one {tree_role:?} tree"
                    ));
                }
            }
        }
        if opening_points_by_column.is_empty() {
            return Err(format!("the relation has no {tree_role:?} columns"));
        }
        for claim in variant.ordered_opening_claims() {
            if claim.source_class() != RelationOpeningSourceClass::TreeColumn {
                continue;
            }
            let column_ordinal = claim
                .column_ordinal()
                .ok_or_else(|| "tree opening claim has no relation column".to_owned())?;
            if let Some(opening_points) = opening_points_by_column.get_mut(&column_ordinal) {
                opening_points.push(claim.opening_point_ordinal());
            }
        }
        if opening_points_by_column
            .values()
            .any(|opening_points| opening_points.is_empty())
        {
            return Err(format!(
                "a {tree_role:?} relation column has no opening claim"
            ));
        }
        for opening_points in opening_points_by_column.values_mut() {
            opening_points.sort_unstable();
            opening_points.dedup();
        }

        // A single encoded row can authenticate eight logical polynomials at
        // one rank-one block challenge only when all eight are opened at the
        // same point set. Grouping by this pattern is therefore a soundness
        // condition, not merely a storage optimization.
        let mut columns_by_opening_pattern = BTreeMap::<Vec<u32>, Vec<u32>>::new();
        for (column_ordinal, opening_points) in opening_points_by_column {
            columns_by_opening_pattern
                .entry(opening_points)
                .or_default()
                .push(column_ordinal);
        }
        let mut rows = Vec::new();
        for (opening_point_ordinals, columns) in columns_by_opening_pattern {
            for chunk in columns.chunks(LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW) {
                let mut column_ordinals = [None; LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW];
                for (block_index, column_ordinal) in chunk.iter().copied().enumerate() {
                    column_ordinals[block_index] = Some(column_ordinal);
                }
                rows.push(ExactBasePhaseRow {
                    column_ordinals,
                    opening_point_ordinals: opening_point_ordinals.clone(),
                });
            }
        }
        Ok(Self { rows })
    }

    fn geometry(&self) -> Result<RowEncodingGeometry, String> {
        RowEncodingGeometry::new_weighted_batch_with_log_inverse_rate(
            self.rows.len(),
            PHYSICAL_ROW_WITNESS_VARIABLE_COUNT,
            EXACT_ROW_CODE_LOG_INVERSE_RATE,
        )
    }
}

fn exact_transcript_header(
    binding: &ExactSameSecretFiatShamirBinding,
    verified_prerequisite_binding: [u8; Hash512::BYTE_LENGTH],
) -> Vec<u8> {
    let mut header = Vec::with_capacity(
        EXACT_TRANSCRIPT_HEADER_DOMAIN.len()
            + 2
            + 15 * Hash512::BYTE_LENGTH
            + 2
            + 2
            + 11 * Hash512::BYTE_LENGTH,
    );
    header.extend_from_slice(EXACT_TRANSCRIPT_HEADER_DOMAIN);
    header.extend_from_slice(&binding.protocol_version.to_le_bytes());
    header.extend_from_slice(&binding.suite_identifier);
    header.extend_from_slice(&binding.ceremony_context_hash);
    header.extend_from_slice(&binding.action_context_hash);
    header.extend_from_slice(&binding.participant_identity);
    header.extend_from_slice(&binding.roster_position.to_le_bytes());
    header.extend_from_slice(&binding.proof_application_slot_hash);
    header.extend_from_slice(
        &binding
            .application_statement_schema_identifier
            .to_le_bytes(),
    );
    header.extend_from_slice(&binding.application_statement_hash);
    header.extend_from_slice(&binding.proof_header_hash);
    header.extend_from_slice(&binding.relation_plan_hash);
    header.extend_from_slice(&binding.relation_plan_variant_hash);
    header.extend_from_slice(&binding.construction_plan_identity_hash);
    header.extend_from_slice(&binding.oracle_equation_catalog_hash);
    header.extend_from_slice(&binding.setup_proof_context_hash);
    header.extend_from_slice(&(binding.ordered_source_roots.len() as u16).to_le_bytes());
    for source_root in &binding.ordered_source_roots {
        header.extend_from_slice(source_root);
    }
    header.extend_from_slice(&verified_prerequisite_binding);
    header
}

#[cfg(all(test, not(target_arch = "wasm32")))]
fn absorb_exact_relation_roots(
    transcript: &mut CommonProofTranscript,
    tree_ordinals: &[u16],
    expected_role: ProofTreeRole,
    exact_phase_root: ColumnDigest,
    variant: &crate::bgv::proof_suite::RelationPlanVariant,
    relation_trees: &[RelationProofTreeInput],
) -> Result<(), String> {
    let root_bytes = exact_phase_root
        .into_iter()
        .flat_map(u64::to_le_bytes)
        .collect::<Vec<_>>()
        .try_into()
        .expect("eight digest words encode 64 bytes");
    let role_local_trees = variant
        .ordered_trees()
        .iter()
        .zip(relation_trees)
        .filter_map(|(descriptor, input)| match (descriptor, input) {
            (
                RelationTreeDescriptor::ProofCreated {
                    proof_tree_role, ..
                },
                RelationProofTreeInput::ProofCreated { tree_role, .. },
            ) if *proof_tree_role == expected_role as u16 && *tree_role == expected_role => {
                Some(Ok(()))
            }
            (
                RelationTreeDescriptor::ProofCreated {
                    proof_tree_role, ..
                },
                _,
            ) if *proof_tree_role == expected_role as u16 => Some(Err(format!(
                "a {expected_role:?} relation tree has a mismatched production input"
            ))),
            _ => None,
        })
        .collect::<Result<Vec<_>, _>>()?;
    for tree_ordinal in tree_ordinals {
        role_local_trees
            .get(usize::from(*tree_ordinal))
            .ok_or_else(|| {
                format!(
                    "{expected_role:?} relation tree {tree_ordinal} is absent from the production relation"
                )
            })?;
        match expected_role {
            ProofTreeRole::BaseOracle => transcript
                .absorb_base_root(*tree_ordinal, root_bytes)
                .map_err(|error| format!("absorb exact base root {tree_ordinal}: {error:?}"))?,
            ProofTreeRole::AuxiliaryOracle => transcript
                .absorb_auxiliary_root(*tree_ordinal, root_bytes)
                .map_err(|error| {
                    format!("absorb exact auxiliary root {tree_ordinal}: {error:?}")
                })?,
        }
    }
    Ok(())
}

#[cfg(test)]
fn production_same_secret_relation() -> Result<
    (
        CommonProofRelationPlanCapability,
        crate::bgv::proof_suite::RelationPlanVariant,
        crate::bgv::proof_suite::RelationPlanCheckContext,
    ),
    String,
> {
    let statement_schema_identifier =
        SetupKeyRelationProofFamily::SameSecret.statement_schema_identifier();
    let relation_context = selected_relation_plan_check_context(statement_schema_identifier)
        .ok_or_else(|| "selected same-secret relation context is unavailable".to_owned())?;
    let selected_plan = compile_same_secret_relation_plan(
        &selected_same_secret_relation_plan_input()
            .map_err(|error| format!("select same-secret relation input: {error:?}"))?,
        &relation_context,
    )
    .map_err(|error| format!("compile production same-secret relation plan: {error:?}"))?;
    let relation_plan_variant = selected_plan
        .select_variant(None, None)
        .map_err(|error| format!("select production same-secret relation variant: {error:?}"))?
        .clone();
    let relation_plan = CommonProofRelationPlanCapability::from_compiled_plan(
        &selected_plan,
        &relation_context,
        None,
        None,
    )
    .map_err(|error| format!("validate production same-secret relation plan: {error:?}"))?;
    Ok((relation_plan, relation_plan_variant, relation_context))
}

#[cfg(test)]
fn test_same_secret_low_degree_prerequisite(
    protocol_version: u16,
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
    action_context_hash: [u8; Hash512::BYTE_LENGTH],
    public_setup_seed: [u8; Hash512::BYTE_LENGTH],
    canonical_application_statement_bytes: &[u8],
) -> Result<VerifiedSameSecretLowDegreePrerequisite, String> {
    let statement = decode_selected_same_secret_statement(
        canonical_application_statement_bytes,
        SelectedApplicationStatementContext::new(protocol_version, suite_identifier, None, None),
    )
    .map_err(|error| format!("decode prerequisite same-secret statement: {error:?}"))?;
    let ordered_input_roots = statement
        .ordered_degree_zero_commitment_roots()
        .try_into()
        .map_err(|_| "same-secret prerequisite has the wrong input-root count".to_owned())?;
    VerifiedSameSecretLowDegreePrerequisite::for_test(
        protocol_version,
        suite_identifier,
        ceremony_context_hash,
        action_context_hash,
        public_setup_seed,
        statement.setup_proof_context_hash(),
        statement.participant_identity(),
        statement.roster_position(),
        ordered_input_roots,
        TEST_VERIFIED_VSS_PROOF_RESULT_DIGEST,
    )
    .map_err(|error| format!("construct verified VSS prerequisite: {error:?}"))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
fn production_same_secret_prerequisite(
    sources: &PreparedExactSameSecretGenerationSources,
) -> Result<VerifiedSameSecretLowDegreePrerequisite, String> {
    let request_context = sources
        .source_polynomials
        .exact_same_secret_evidence_request_context();
    test_same_secret_low_degree_prerequisite(
        request_context.protocol_version(),
        request_context.suite_identifier(),
        sources.authorization.ceremony_context_hash(),
        sources.action_context_hash,
        sources.public_setup_seed,
        &sources.canonical_application_statement_bytes,
    )
}

#[cfg(all(test, not(target_arch = "wasm32")))]
struct ProductionSameSecretEvidenceSources {
    sources: PreparedExactSameSecretGenerationSources,
    authority_handle: SetupGenerationAuthorityHandle,
}

#[cfg(all(test, not(target_arch = "wasm32")))]
fn release_production_same_secret_authority(
    authority_handle: SetupGenerationAuthorityHandle,
) -> Result<(), String> {
    release_setup_generation_authority(authority_handle)
        .map_err(|error| format!("release production setup authority: {error:?}"))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
fn production_same_secret_sources() -> Result<ProductionSameSecretEvidenceSources, String> {
    let (relation_plan, _, _) = production_same_secret_relation()?;
    let authority_population_started_at = std::time::Instant::now();
    println!("exact same-secret phase: populate browser-owned setup authority");
    let authority =
        populate_exact_same_secret_evidence_authority(EXACT_SAME_SECRET_EVIDENCE_REVISION)
            .map_err(|error| format!("populate production setup authority: {error:?}"))?;
    println!(
        "exact same-secret phase complete: browser-owned setup authority ({:?})",
        authority_population_started_at.elapsed(),
    );
    let sources = (|| {
        let preparation_source = resolve_setup_generation_key_relation_preparation_source(
            &authority.authority_handle,
            SetupKeyRelationProofFamily::SameSecret,
        )
        .map_err(|error| format!("resolve production same-secret statement: {error:?}"))?;
        let statement_schema_identifier =
            SetupKeyRelationProofFamily::SameSecret.statement_schema_identifier();
        let application_slot = ProofApplicationSlot::new(
            Hash512::from_bytes(preparation_source.suite_identifier()),
            Hash512::from_bytes(preparation_source.ceremony_context_hash()),
            Hash512::from_bytes(preparation_source.action_context_hash()),
            statement_schema_identifier,
            Some(preparation_source.roster_position()),
            None,
            None,
        )
        .map_err(|error| format!("construct production proof application slot: {error:?}"))?;
        let application_statement_hash = Hash512::from_bytes(verified_application_statement_hash(
            preparation_source.protocol_version(),
            preparation_source.suite_identifier(),
            statement_schema_identifier,
            preparation_source.canonical_application_statement_bytes(),
        ));
        let prepared_attempt = prepare_exact_same_secret_evidence_attempt(
            &authority.action_private_randomness,
            application_slot,
            application_statement_hash,
        )
        .map_err(|error| format!("bind production proof attempt: {error:?}"))?;
        let decoded_statement = decode_selected_same_secret_statement(
            preparation_source.canonical_application_statement_bytes(),
            SelectedApplicationStatementContext::new(
                preparation_source.protocol_version(),
                preparation_source.suite_identifier(),
                None,
                None,
            ),
        )
        .map_err(|error| format!("decode production same-secret statement: {error:?}"))?;
        let application = SetupGenerationKeyRelationApplication::from_runtime_binding(
            SetupKeyRelationProofFamily::SameSecret,
            prepared_attempt,
            preparation_source.canonical_application_statement_bytes(),
            decoded_statement.setup_proof_context_hash(),
            preparation_source.roster_hash(),
            preparation_source.participant_identity(),
            preparation_source.roster_position(),
        );
        with_setup_generation_key_relation(&authority.authority_handle, &application, |source| {
            source.prepare_exact_same_secret_generation_sources(relation_plan)
        })
        .map_err(|error| format!("prepare production same-secret sources: {error:?}"))
    })();
    match sources {
        Ok(sources) => Ok(ProductionSameSecretEvidenceSources {
            sources,
            authority_handle: authority.authority_handle,
        }),
        Err(error) => {
            release_production_same_secret_authority(authority.authority_handle)?;
            Err(error)
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
fn exact_private_coin_sampling_catalog(
    variant: &crate::bgv::proof_suite::RelationPlanVariant,
) -> Result<CommonProofPrivateCoinSamplingCatalog, String> {
    let mut catalog = CommonProofPrivateCoinSamplingCatalog::from_relation_plan_variant(
        variant,
        SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT,
    )
    .map_err(|error| format!("derive exact private-coin mask catalog: {error:?}"))?;
    catalog
        .record_raw_byte_fill(
            CommonProofPrivateCoinCoordinate::proof_salt(),
            EXACT_ROW_PAD_SEED_BYTE_LENGTH,
        )
        .map_err(|error| format!("add exact row-pad seed fill to catalog: {error:?}"))?;
    let hiding_configuration = super::hiding_whir::selected_hiding_whir_config(
        super::construction_plan::RowCodeWhirSelectedParameters::selected(),
    )
    .map_err(|error| format!("derive aggregate-wide hiding configuration: {error}"))?;
    let hiding_shape = super::aggregate_wide_hiding::AggregateWideHidingMaterialShape::derive(
        &hiding_configuration,
    )?;
    let base_field_sample_count = hiding_shape
        .total_extension_element_count()
        .checked_mul(crate::bgv::proof_suite::PROOF_CHALLENGE_EXTENSION_DEGREE)
        .ok_or_else(|| "aggregate-wide private-sample count overflowed".to_owned())?;
    catalog
        .record_modulo_samples(
            CommonProofPrivateCoinCoordinate::hiding_argument(),
            crate::bgv::proof_suite::PROOF_BASE_FIELD_MODULUS,
            SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT,
            base_field_sample_count,
        )
        .map_err(|error| format!("add aggregate-wide hiding samples to catalog: {error:?}"))?;
    Ok(catalog)
}

#[cfg(all(test, not(target_arch = "wasm32")))]
fn derive_exact_row_pad_seeds(
    sources: &mut PreparedExactSameSecretGenerationSources,
) -> Result<[[u8; 32]; 3], String> {
    let mut seed_bytes = zeroize::Zeroizing::new([0_u8; EXACT_ROW_PAD_SEED_BYTE_LENGTH]);
    sources
        .private_coins
        .fill_raw_bytes(
            CommonProofPrivateCoinCoordinate::proof_salt(),
            seed_bytes.as_mut(),
        )
        .map_err(|error| format!("derive production-private row-pad seeds: {error:?}"))?;
    Ok([
        seed_bytes[0..32]
            .try_into()
            .map_err(|_| "base row-pad seed has the wrong length".to_owned())?,
        seed_bytes[32..64]
            .try_into()
            .map_err(|_| "auxiliary row-pad seed has the wrong length".to_owned())?,
        seed_bytes[64..96]
            .try_into()
            .map_err(|_| "quotient row-pad seed has the wrong length".to_owned())?,
    ])
}

#[cfg(all(test, not(target_arch = "wasm32")))]
fn source_polynomial_digest(
    column_ordinal: u32,
    polynomial: &CommonProofSourcePolynomial,
) -> Result<[u8; 64], String> {
    let coefficient_byte_length = polynomial
        .coefficient_count()
        .checked_mul(core::mem::size_of::<u64>())
        .ok_or_else(|| "source polynomial byte length overflowed".to_owned())?;
    let mut hasher = StreamingHash512::new(SOURCE_POLYNOMIAL_DIGEST_DOMAIN, 2);
    hasher.absorb_part(&column_ordinal.to_le_bytes());
    hasher.begin_part(
        u64::try_from(coefficient_byte_length)
            .map_err(|_| "source polynomial byte length does not fit u64".to_owned())?,
    );
    match polynomial {
        CommonProofSourcePolynomial::Base(coefficients) => {
            for coefficient in coefficients.iter().copied() {
                hasher.absorb_raw(&coefficient.canonical().to_le_bytes());
            }
        }
        CommonProofSourcePolynomial::Extension(_) => {
            return Err(
                "the production pre-challenge source emitted an extension column".to_owned(),
            );
        }
    }
    Ok(hasher.finalize())
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod native_checkpoint {
    use std::{
        fs::{self, File, OpenOptions},
        io::{Read, Write},
        path::{Path, PathBuf},
    };

    use serde::{Deserialize, Serialize};

    use p3_field::PrimeCharacteristicRing;
    use p3_goldilocks::Goldilocks;

    use super::super::{column_commitment::StreamingColumnHasher, row_encoding::encode_row};
    use super::*;
    use crate::bgv::proof_suite::{
        PROOF_CHALLENGE_EXTENSION_DEGREE, ProofBaseFieldElement, ProofChallengeExtensionElement,
    };

    const POLYNOMIAL_MAGIC: &[u8; 8] = b"SLXPOL01";
    const EXTENSION_POLYNOMIAL_MAGIC: &[u8; 8] = b"SLXEXT01";
    const MANIFEST_SCHEMA: &str = "sealed-lattice/exact-same-secret-shifted-source/v1";
    const PHASE_MANIFEST_SCHEMA: &str =
        "sealed-lattice/exact-same-secret-row-code-phase-commitments/v1";
    const QUOTIENT_MANIFEST_SCHEMA: &str =
        "sealed-lattice/exact-same-secret-row-code-quotient-commitment/v1";
    pub(super) const QUOTIENT_ACCUMULATOR_CHECKPOINT_INTERVAL: usize = 64;
    type QuotientAccumulatorCheckpoint = (
        usize,
        zeroize::Zeroizing<Vec<ProofChallengeExtensionElement>>,
    );

    pub(super) trait RecomputableRowSource {
        fn read_row(&self, row_index: usize) -> Result<Vec<Goldilocks>, String>;
    }

    pub(super) fn commit_phase_rows<Source: RecomputableRowSource>(
        source: &Source,
        geometry: RowEncodingGeometry,
        secret_row_pad_seed: &[u8; 32],
    ) -> Result<ColumnDigest, String> {
        let mut column_hasher =
            StreamingColumnHasher::new(geometry.row_count, geometry.encoded_column_count)?;
        for row_index in 0..geometry.row_count {
            let mut witness_values = source.read_row(row_index)?;
            if witness_values.len() != geometry.witness_values_per_row {
                return Err(format!(
                    "row {row_index} has {} witness values, expected {}",
                    witness_values.len(),
                    geometry.witness_values_per_row
                ));
            }
            let mut encoded_row =
                encode_row(geometry, row_index, &witness_values, secret_row_pad_seed)?;
            column_hasher.absorb_row(&encoded_row)?;
            witness_values.fill(Goldilocks::ZERO);
            encoded_row.fill(Goldilocks::ZERO);
        }
        column_hasher.finalize_root()
    }

    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    pub(super) struct SourceCheckpointManifest {
        pub(super) schema: String,
        pub(super) relation_plan_hash: Vec<u8>,
        pub(super) relation_plan_variant_hash: Vec<u8>,
        pub(super) canonical_application_statement_bytes: Vec<u8>,
        pub(super) generation_binding_hash: Vec<u8>,
        pub(super) source_replay_identity_digest: Vec<u8>,
        pub(super) source_catalog_digest: Vec<u8>,
        pub(super) pre_challenge_polynomial_count: usize,
        pub(super) stored_relation_column_count: usize,
        pub(super) total_source_coefficient_count: u64,
        pub(super) maximum_source_coefficient_count: usize,
    }

    impl SourceCheckpointManifest {
        #[allow(clippy::too_many_arguments)]
        pub(super) fn new(
            relation_plan_hash: [u8; 64],
            relation_plan_variant_hash: [u8; 64],
            canonical_application_statement_bytes: Vec<u8>,
            generation_binding_hash: [u8; 64],
            source_replay_identity_digest: [u8; 64],
            source_catalog_digest: [u8; 64],
            pre_challenge_polynomial_count: usize,
            stored_relation_column_count: usize,
            total_source_coefficient_count: u64,
            maximum_source_coefficient_count: usize,
        ) -> Self {
            Self {
                schema: MANIFEST_SCHEMA.to_owned(),
                relation_plan_hash: relation_plan_hash.to_vec(),
                relation_plan_variant_hash: relation_plan_variant_hash.to_vec(),
                canonical_application_statement_bytes,
                generation_binding_hash: generation_binding_hash.to_vec(),
                source_replay_identity_digest: source_replay_identity_digest.to_vec(),
                source_catalog_digest: source_catalog_digest.to_vec(),
                pre_challenge_polynomial_count,
                stored_relation_column_count,
                total_source_coefficient_count,
                maximum_source_coefficient_count,
            }
        }
    }

    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    pub(super) struct ExactPhaseCommitmentManifest {
        pub(super) schema: String,
        pub(super) relation_plan_hash: Vec<u8>,
        pub(super) relation_plan_variant_hash: Vec<u8>,
        pub(super) source_catalog_digest: Vec<u8>,
        pub(super) encoded_column_count: usize,
        pub(super) base_row_count: usize,
        pub(super) auxiliary_row_count: usize,
        pub(super) base_root_words: Vec<u64>,
        pub(super) auxiliary_root_words: Vec<u64>,
    }

    impl ExactPhaseCommitmentManifest {
        pub(super) fn new(
            source: &SourceCheckpointManifest,
            encoded_column_count: usize,
            base_row_count: usize,
            auxiliary_row_count: usize,
            base_root: ColumnDigest,
            auxiliary_root: ColumnDigest,
        ) -> Self {
            Self {
                schema: PHASE_MANIFEST_SCHEMA.to_owned(),
                relation_plan_hash: source.relation_plan_hash.clone(),
                relation_plan_variant_hash: source.relation_plan_variant_hash.clone(),
                source_catalog_digest: source.source_catalog_digest.clone(),
                encoded_column_count,
                base_row_count,
                auxiliary_row_count,
                base_root_words: base_root.to_vec(),
                auxiliary_root_words: auxiliary_root.to_vec(),
            }
        }
    }

    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    pub(super) struct ExactQuotientCommitmentManifest {
        pub(super) schema: String,
        pub(super) relation_plan_hash: Vec<u8>,
        pub(super) relation_plan_variant_hash: Vec<u8>,
        pub(super) source_catalog_digest: Vec<u8>,
        pub(super) encoded_column_count: usize,
        pub(super) quotient_coefficient_count: usize,
        pub(super) maximum_live_transformed_column_count: usize,
        pub(super) quotient_phase_row_count: usize,
        pub(super) quotient_root_words: Vec<u64>,
    }

    impl ExactQuotientCommitmentManifest {
        pub(super) fn new(
            source: &SourceCheckpointManifest,
            encoded_column_count: usize,
            quotient_coefficient_count: usize,
            maximum_live_transformed_column_count: usize,
            quotient_phase_row_count: usize,
            quotient_root: ColumnDigest,
        ) -> Self {
            Self {
                schema: QUOTIENT_MANIFEST_SCHEMA.to_owned(),
                relation_plan_hash: source.relation_plan_hash.clone(),
                relation_plan_variant_hash: source.relation_plan_variant_hash.clone(),
                source_catalog_digest: source.source_catalog_digest.clone(),
                encoded_column_count,
                quotient_coefficient_count,
                maximum_live_transformed_column_count,
                quotient_phase_row_count,
                quotient_root_words: quotient_root.to_vec(),
            }
        }
    }

    pub(super) struct ExactPolynomialStore {
        root: PathBuf,
    }

    impl ExactPolynomialStore {
        pub(super) fn open() -> Result<Self, String> {
            let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .and_then(Path::parent)
                .ok_or_else(|| "resolve exact checkpoint workspace root".to_owned())?;
            let root = workspace_root
                .join("temp")
                .join("test-checkpoints")
                .join("exact-same-secret-row-code-whir-v1");
            fs::create_dir_all(&root)
                .map_err(|error| format!("create exact checkpoint directory: {error}"))?;
            Ok(Self { root })
        }

        fn polynomial_path(&self, column_ordinal: u32) -> PathBuf {
            self.root
                .join(format!("relation-column-{column_ordinal:04}.bin"))
        }

        fn phase_polynomial_path(&self, column_ordinal: u32) -> PathBuf {
            self.root
                .join(format!("phase-column-{column_ordinal:04}.bin"))
        }

        fn manifest_path(&self) -> PathBuf {
            self.root.join("source-manifest.json")
        }

        fn phase_manifest_path(&self) -> PathBuf {
            self.root.join("phase-commitments.json")
        }

        fn quotient_manifest_path(&self) -> PathBuf {
            self.root.join("quotient-commitment.json")
        }

        fn quotient_component_path(&self, component_ordinal: u16) -> PathBuf {
            self.root
                .join(format!("quotient-component-{component_ordinal:02}.bin"))
        }

        fn opening_batch_mask_path(&self) -> PathBuf {
            self.root.join("opening-batch-mask.bin")
        }

        fn quotient_accumulator_path(
            &self,
            binding: [u8; 64],
            next_constraint_ordinal: usize,
        ) -> PathBuf {
            let binding_hex = binding
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            self.root.join(format!(
                "quotient-accumulator-{binding_hex}-{next_constraint_ordinal:04}.bin"
            ))
        }

        pub(super) fn contains(&self, column_ordinal: u32) -> bool {
            self.phase_polynomial_path(column_ordinal).is_file()
                || self.polynomial_path(column_ordinal).is_file()
        }

        pub(super) fn write(
            &self,
            column_ordinal: u32,
            polynomial: &CommonProofSourcePolynomial,
        ) -> Result<(), String> {
            let path = self.polynomial_path(column_ordinal);
            self.write_polynomial_at(&path, column_ordinal, polynomial)
        }

        /// Phase output uses a separate namespace from the pre-challenge
        /// source checkpoint. An interrupted transcript attempt can therefore
        /// never be mistaken for authenticated source material on retry.
        pub(super) fn write_phase(
            &self,
            column_ordinal: u32,
            polynomial: &CommonProofSourcePolynomial,
        ) -> Result<(), String> {
            let path = self.phase_polynomial_path(column_ordinal);
            self.write_polynomial_at(&path, column_ordinal, polynomial)
        }

        fn write_polynomial_at(
            &self,
            path: &Path,
            column_ordinal: u32,
            polynomial: &CommonProofSourcePolynomial,
        ) -> Result<(), String> {
            if path.is_file() {
                let stored = self.read_polynomial_at(path, column_ordinal)?;
                if &stored == polynomial {
                    return Ok(());
                }
                return Err(format!(
                    "checkpoint phase column {column_ordinal} differs from the current construction"
                ));
            }
            let CommonProofSourcePolynomial::Base(coefficients) = polynomial else {
                return Err(format!(
                    "checkpoint phase column {column_ordinal} is not a base-field polynomial"
                ));
            };
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .map_err(|error| format!("create {}: {error}", path.display()))?;
            file.write_all(POLYNOMIAL_MAGIC)
                .and_then(|_| file.write_all(&column_ordinal.to_le_bytes()))
                .and_then(|_| {
                    file.write_all(
                        &u32::try_from(coefficients.len())
                            .map_err(|_| std::io::Error::other("coefficient count exceeds u32"))?
                            .to_le_bytes(),
                    )
                })
                .map_err(|error| format!("write {} header: {error}", path.display()))?;
            for coefficient in coefficients.iter().copied() {
                file.write_all(&coefficient.canonical().to_le_bytes())
                    .map_err(|error| format!("write {} coefficient: {error}", path.display()))?;
            }
            file.sync_all()
                .map_err(|error| format!("sync {}: {error}", path.display()))
        }

        pub(super) fn read(
            &self,
            column_ordinal: u32,
        ) -> Result<CommonProofSourcePolynomial, String> {
            let phase_path = self.phase_polynomial_path(column_ordinal);
            let path = if phase_path.is_file() {
                phase_path
            } else {
                self.polynomial_path(column_ordinal)
            };
            self.read_polynomial_at(&path, column_ordinal)
        }

        fn read_polynomial_at(
            &self,
            path: &Path,
            column_ordinal: u32,
        ) -> Result<CommonProofSourcePolynomial, String> {
            let mut file =
                File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
            let mut header = [0_u8; 16];
            file.read_exact(&mut header)
                .map_err(|error| format!("read {} header: {error}", path.display()))?;
            if &header[..8] != POLYNOMIAL_MAGIC
                || u32::from_le_bytes(header[8..12].try_into().expect("fixed header"))
                    != column_ordinal
            {
                return Err(format!(
                    "{} has the wrong checkpoint binding",
                    path.display()
                ));
            }
            let coefficient_count =
                u32::from_le_bytes(header[12..16].try_into().expect("fixed header")) as usize;
            if coefficient_count == 0 || coefficient_count > 262_144 {
                return Err(format!(
                    "{} has invalid coefficient count {coefficient_count}",
                    path.display()
                ));
            }
            let mut coefficients = Vec::with_capacity(coefficient_count);
            for coefficient_index in 0..coefficient_count {
                let mut canonical = [0_u8; 8];
                file.read_exact(&mut canonical).map_err(|error| {
                    format!(
                        "read {} coefficient {coefficient_index}: {error}",
                        path.display()
                    )
                })?;
                coefficients.push(
                    ProofBaseFieldElement::from_canonical(u64::from_le_bytes(canonical)).map_err(
                        |_| {
                            format!(
                                "{} coefficient {coefficient_index} is not canonical",
                                path.display()
                            )
                        },
                    )?,
                );
            }
            let mut trailing = [0_u8; 1];
            if file
                .read(&mut trailing)
                .map_err(|error| format!("finish reading {}: {error}", path.display()))?
                != 0
            {
                return Err(format!("{} contains trailing bytes", path.display()));
            }
            Ok(CommonProofSourcePolynomial::from_base_coefficients(
                coefficients,
            ))
        }

        fn write_extension_polynomial(
            &self,
            path: &Path,
            polynomial: &[ProofChallengeExtensionElement],
        ) -> Result<(), String> {
            if polynomial.is_empty() || polynomial.len() > 262_144 {
                return Err(format!(
                    "extension polynomial has invalid coefficient count {}",
                    polynomial.len()
                ));
            }
            if path.is_file() {
                let stored = self.read_extension_polynomial(path)?;
                if stored.as_slice() == polynomial {
                    return Ok(());
                }
                return Err(format!(
                    "checkpoint extension polynomial {} differs from the constructed polynomial",
                    path.display()
                ));
            }
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .map_err(|error| format!("create {}: {error}", path.display()))?;
            file.write_all(EXTENSION_POLYNOMIAL_MAGIC)
                .and_then(|_| {
                    file.write_all(
                        &u32::try_from(polynomial.len())
                            .map_err(|_| {
                                std::io::Error::other("extension coefficient count exceeds u32")
                            })?
                            .to_le_bytes(),
                    )
                })
                .map_err(|error| format!("write {} header: {error}", path.display()))?;
            for coefficient in polynomial {
                for coordinate in coefficient.canonical_coordinates() {
                    file.write_all(&coordinate.to_le_bytes()).map_err(|error| {
                        format!("write {} coefficient: {error}", path.display())
                    })?;
                }
            }
            file.sync_all()
                .map_err(|error| format!("sync {}: {error}", path.display()))
        }

        fn read_extension_polynomial(
            &self,
            path: &Path,
        ) -> Result<zeroize::Zeroizing<Vec<ProofChallengeExtensionElement>>, String> {
            let mut file =
                File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
            let mut header = [0_u8; 12];
            file.read_exact(&mut header)
                .map_err(|error| format!("read {} header: {error}", path.display()))?;
            if &header[..8] != EXTENSION_POLYNOMIAL_MAGIC {
                return Err(format!("{} has the wrong extension magic", path.display()));
            }
            let coefficient_count =
                u32::from_le_bytes(header[8..12].try_into().expect("fixed header")) as usize;
            if coefficient_count == 0 || coefficient_count > 262_144 {
                return Err(format!(
                    "{} has invalid coefficient count {coefficient_count}",
                    path.display()
                ));
            }
            let mut coefficients = Vec::with_capacity(coefficient_count);
            for _ in 0..coefficient_count {
                let mut coordinates = [0_u64; PROOF_CHALLENGE_EXTENSION_DEGREE];
                for coordinate in &mut coordinates {
                    let mut bytes = [0_u8; 8];
                    file.read_exact(&mut bytes).map_err(|error| {
                        format!("read {} extension coefficient: {error}", path.display())
                    })?;
                    *coordinate = u64::from_le_bytes(bytes);
                }
                coefficients.push(
                    ProofChallengeExtensionElement::from_canonical_coordinates(coordinates)
                        .map_err(|_| {
                            format!("{} contains a non-canonical coefficient", path.display())
                        })?,
                );
            }
            let mut trailing = [0_u8; 1];
            if file
                .read(&mut trailing)
                .map_err(|error| format!("read {} trailing byte: {error}", path.display()))?
                != 0
            {
                return Err(format!("{} contains trailing bytes", path.display()));
            }
            Ok(zeroize::Zeroizing::new(coefficients))
        }

        pub(super) fn write_quotient_component(
            &self,
            component_ordinal: u16,
            polynomial: &[ProofChallengeExtensionElement],
        ) -> Result<(), String> {
            self.write_extension_polynomial(
                &self.quotient_component_path(component_ordinal),
                polynomial,
            )
        }

        pub(super) fn read_quotient_component(
            &self,
            component_ordinal: u16,
        ) -> Result<zeroize::Zeroizing<Vec<ProofChallengeExtensionElement>>, String> {
            self.read_extension_polynomial(&self.quotient_component_path(component_ordinal))
        }

        pub(super) fn write_opening_batch_mask(
            &self,
            polynomial: &[ProofChallengeExtensionElement],
        ) -> Result<(), String> {
            self.write_extension_polynomial(&self.opening_batch_mask_path(), polynomial)
        }

        pub(super) fn read_opening_batch_mask(
            &self,
        ) -> Result<zeroize::Zeroizing<Vec<ProofChallengeExtensionElement>>, String> {
            self.read_extension_polynomial(&self.opening_batch_mask_path())
        }

        pub(super) fn write_quotient_accumulator(
            &self,
            binding: [u8; 64],
            next_constraint_ordinal: usize,
            evaluations: &[ProofChallengeExtensionElement],
        ) -> Result<(), String> {
            self.write_extension_polynomial(
                &self.quotient_accumulator_path(binding, next_constraint_ordinal),
                evaluations,
            )
        }

        pub(super) fn read_latest_quotient_accumulator(
            &self,
            binding: [u8; 64],
            constraint_count: usize,
            evaluation_count: usize,
        ) -> Result<Option<QuotientAccumulatorCheckpoint>, String> {
            for next_constraint_ordinal in (1..=constraint_count).rev() {
                if next_constraint_ordinal != constraint_count
                    && next_constraint_ordinal % QUOTIENT_ACCUMULATOR_CHECKPOINT_INTERVAL != 0
                {
                    continue;
                }
                let path = self.quotient_accumulator_path(binding, next_constraint_ordinal);
                if !path.is_file() {
                    continue;
                }
                let evaluations = self.read_extension_polynomial(&path)?;
                if evaluations.len() != evaluation_count {
                    return Err(format!(
                        "{} has {} evaluations instead of {evaluation_count}",
                        path.display(),
                        evaluations.len()
                    ));
                }
                return Ok(Some((next_constraint_ordinal, evaluations)));
            }
            Ok(None)
        }

        pub(super) fn write_manifest(
            &self,
            manifest: &SourceCheckpointManifest,
        ) -> Result<(), String> {
            let path = self.manifest_path();
            if path.is_file() {
                let stored = self.read_manifest()?.ok_or_else(|| {
                    "source checkpoint manifest disappeared during validation".to_owned()
                })?;
                if &stored == manifest {
                    return Ok(());
                }
                return Err("source checkpoint manifest differs from the current run".to_owned());
            }
            let canonical = serde_json::to_vec_pretty(manifest)
                .map_err(|error| format!("encode source checkpoint manifest: {error}"))?;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .map_err(|error| format!("create {}: {error}", path.display()))?;
            file.write_all(&canonical)
                .and_then(|_| file.sync_all())
                .map_err(|error| format!("write {}: {error}", path.display()))
        }

        pub(super) fn read_manifest(&self) -> Result<Option<SourceCheckpointManifest>, String> {
            let path = self.manifest_path();
            if !path.is_file() {
                return Ok(None);
            }
            let bytes =
                fs::read(&path).map_err(|error| format!("read {}: {error}", path.display()))?;
            let manifest: SourceCheckpointManifest = serde_json::from_slice(&bytes)
                .map_err(|error| format!("decode {}: {error}", path.display()))?;
            if manifest.schema != MANIFEST_SCHEMA {
                return Err(format!("{} has the wrong schema", path.display()));
            }
            Ok(Some(manifest))
        }

        pub(super) fn write_phase_manifest(
            &self,
            manifest: &ExactPhaseCommitmentManifest,
        ) -> Result<(), String> {
            let path = self.phase_manifest_path();
            if path.is_file() {
                let stored = self.read_phase_manifest()?.ok_or_else(|| {
                    "phase commitment manifest disappeared during validation".to_owned()
                })?;
                if &stored == manifest {
                    return Ok(());
                }
                return Err("phase commitment manifest differs from the current run".to_owned());
            }
            let canonical = serde_json::to_vec_pretty(manifest)
                .map_err(|error| format!("encode phase commitment manifest: {error}"))?;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .map_err(|error| format!("create {}: {error}", path.display()))?;
            file.write_all(&canonical)
                .and_then(|_| file.sync_all())
                .map_err(|error| format!("write {}: {error}", path.display()))
        }

        pub(super) fn read_phase_manifest(
            &self,
        ) -> Result<Option<ExactPhaseCommitmentManifest>, String> {
            let path = self.phase_manifest_path();
            if !path.is_file() {
                return Ok(None);
            }
            let bytes =
                fs::read(&path).map_err(|error| format!("read {}: {error}", path.display()))?;
            let manifest: ExactPhaseCommitmentManifest = serde_json::from_slice(&bytes)
                .map_err(|error| format!("decode {}: {error}", path.display()))?;
            if manifest.schema != PHASE_MANIFEST_SCHEMA {
                return Err(format!("{} has the wrong schema", path.display()));
            }
            Ok(Some(manifest))
        }

        pub(super) fn write_quotient_manifest(
            &self,
            manifest: &ExactQuotientCommitmentManifest,
        ) -> Result<(), String> {
            let path = self.quotient_manifest_path();
            if path.is_file() {
                let stored = self.read_quotient_manifest()?.ok_or_else(|| {
                    "quotient commitment manifest disappeared during validation".to_owned()
                })?;
                if &stored == manifest {
                    return Ok(());
                }
                return Err("quotient commitment manifest differs from the current run".to_owned());
            }
            let canonical = serde_json::to_vec_pretty(manifest)
                .map_err(|error| format!("encode quotient commitment manifest: {error}"))?;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .map_err(|error| format!("create {}: {error}", path.display()))?;
            file.write_all(&canonical)
                .and_then(|_| file.sync_all())
                .map_err(|error| format!("write {}: {error}", path.display()))
        }

        pub(super) fn read_quotient_manifest(
            &self,
        ) -> Result<Option<ExactQuotientCommitmentManifest>, String> {
            let path = self.quotient_manifest_path();
            if !path.is_file() {
                return Ok(None);
            }
            let bytes =
                fs::read(&path).map_err(|error| format!("read {}: {error}", path.display()))?;
            let manifest: ExactQuotientCommitmentManifest = serde_json::from_slice(&bytes)
                .map_err(|error| format!("decode {}: {error}", path.display()))?;
            if manifest.schema != QUOTIENT_MANIFEST_SCHEMA {
                return Err(format!("{} has the wrong schema", path.display()));
            }
            Ok(Some(manifest))
        }

        pub(super) fn root(&self) -> &Path {
            &self.root
        }
    }

    pub(super) struct CheckpointBasePhaseSource<'source> {
        store: &'source ExactPolynomialStore,
        layout: &'source ExactBasePhaseLayout,
    }

    impl<'source> CheckpointBasePhaseSource<'source> {
        pub(super) const fn new(
            store: &'source ExactPolynomialStore,
            layout: &'source ExactBasePhaseLayout,
        ) -> Self {
            Self { store, layout }
        }
    }

    impl RecomputableRowSource for CheckpointBasePhaseSource<'_> {
        fn read_row(&self, row_index: usize) -> Result<Vec<Goldilocks>, String> {
            let row = self
                .layout
                .rows
                .get(row_index)
                .ok_or_else(|| format!("phase row {row_index} is outside the layout"))?;
            let mut witness_values = vec![
                Goldilocks::ZERO;
                LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT
                    * LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW
            ];
            for (block_index, column_ordinal) in row.column_ordinals.iter().enumerate() {
                let Some(column_ordinal) = column_ordinal else {
                    continue;
                };
                let polynomial = self.store.read(*column_ordinal)?;
                let CommonProofSourcePolynomial::Base(coefficients) = polynomial else {
                    return Err(format!(
                        "phase relation column {column_ordinal} is not base-field valued"
                    ));
                };
                if coefficients.len() > LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT {
                    return Err(format!(
                        "phase relation column {column_ordinal} has {} coefficients, exceeding {}",
                        coefficients.len(),
                        LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT
                    ));
                }
                let block_start = block_index * LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT;
                for (destination, coefficient) in witness_values
                    [block_start..block_start + coefficients.len()]
                    .iter_mut()
                    .zip(coefficients.iter().copied())
                {
                    *destination = Goldilocks::new(coefficient.canonical());
                }
            }
            Ok(witness_values)
        }
    }

    pub(super) struct CheckpointQuotientPhaseSource<'source> {
        store: &'source ExactPolynomialStore,
        quotient_component_count: usize,
    }

    impl<'source> CheckpointQuotientPhaseSource<'source> {
        pub(super) fn new(
            store: &'source ExactPolynomialStore,
            quotient_component_count: usize,
        ) -> Result<Self, String> {
            if quotient_component_count != EXACT_QUOTIENT_COMPONENT_COUNT {
                return Err(format!(
                    "quotient component count {quotient_component_count} does not match the selected same-secret relation"
                ));
            }
            Ok(Self {
                store,
                quotient_component_count,
            })
        }

        pub(super) fn row_count(&self) -> usize {
            (QUOTIENT_COMPONENT_CHUNK_COUNT + 1) * PROOF_CHALLENGE_EXTENSION_DEGREE
        }
    }

    impl RecomputableRowSource for CheckpointQuotientPhaseSource<'_> {
        fn read_row(&self, row_index: usize) -> Result<Vec<Goldilocks>, String> {
            if row_index >= self.row_count() {
                return Err(format!(
                    "quotient phase row {row_index} is outside row count {}",
                    self.row_count()
                ));
            }
            let source_group_ordinal = row_index / PROOF_CHALLENGE_EXTENSION_DEGREE;
            let extension_coordinate_ordinal = row_index % PROOF_CHALLENGE_EXTENSION_DEGREE;
            let mut witness_values = vec![
                Goldilocks::ZERO;
                LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT
                    * LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW
            ];
            if source_group_ordinal < QUOTIENT_COMPONENT_CHUNK_COUNT {
                for component_ordinal in 0..self.quotient_component_count {
                    let polynomial =
                        self.store
                            .read_quotient_component(u16::try_from(component_ordinal).map_err(
                                |_| "quotient component ordinal exceeds u16".to_owned(),
                            )?)?;
                    let maximum_coefficient_count =
                        LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT * QUOTIENT_COMPONENT_CHUNK_COUNT;
                    if polynomial.len() > maximum_coefficient_count {
                        return Err(format!(
                            "quotient phase polynomial has {} coefficients, exceeding {}",
                            polynomial.len(),
                            maximum_coefficient_count
                        ));
                    }
                    let source_start = source_group_ordinal * LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT;
                    if source_start >= polynomial.len() {
                        continue;
                    }
                    let source_end = source_start
                        .checked_add(LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT)
                        .expect("quotient source chunk end fits usize")
                        .min(polynomial.len());
                    let destination_start =
                        component_ordinal * LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT;
                    for (destination, coefficient) in witness_values
                        [destination_start..destination_start + source_end - source_start]
                        .iter_mut()
                        .zip(polynomial[source_start..source_end].iter().copied())
                    {
                        *destination = Goldilocks::new(
                            coefficient.canonical_coordinates()[extension_coordinate_ordinal],
                        );
                    }
                }
            } else {
                let polynomial = self.store.read_opening_batch_mask()?;
                let maximum_coefficient_count =
                    LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT * LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW;
                if polynomial.len() > maximum_coefficient_count {
                    return Err(format!(
                        "quotient phase polynomial has {} coefficients, exceeding {}",
                        polynomial.len(),
                        maximum_coefficient_count
                    ));
                }
                for chunk_ordinal in 0..LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW {
                    let source_start = chunk_ordinal * LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT;
                    if source_start >= polynomial.len() {
                        continue;
                    }
                    let source_end = source_start
                        .checked_add(LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT)
                        .expect("quotient source chunk end fits usize")
                        .min(polynomial.len());
                    let destination_start = chunk_ordinal * LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT;
                    for (destination, coefficient) in witness_values
                        [destination_start..destination_start + source_end - source_start]
                        .iter_mut()
                        .zip(polynomial[source_start..source_end].iter().copied())
                    {
                        *destination = Goldilocks::new(
                            coefficient.canonical_coordinates()[extension_coordinate_ordinal],
                        );
                    }
                }
            }
            Ok(witness_values)
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use std::{
        collections::{BTreeMap, BTreeSet},
        time::Instant,
    };

    use zeroize::Zeroizing;

    use super::native_checkpoint::{
        CheckpointBasePhaseSource, CheckpointQuotientPhaseSource, ExactPhaseCommitmentManifest,
        ExactPolynomialStore, ExactQuotientCommitmentManifest, SourceCheckpointManifest,
        commit_phase_rows,
    };
    use super::*;
    use crate::bgv::proof_suite::relation_plan::RelationMaskKind;
    use crate::bgv::proof_suite::{
        CommonProofQuotientComponentCursor, PROOF_CHALLENGE_EXTENSION_DEGREE,
        ProofBaseFieldElement, ProofChallengeExtensionElement, ProofEvaluationDomain,
        RelationPlanError, common_proof_checkpoint_cursor_manifest_requirement_for_variant,
        construct_opening_batch_mask, selected_relation_plans,
    };
    use crate::transcript_core::encode_hex;

    fn selected_relation_plan_capability(
        family: SetupKeyRelationProofFamily,
    ) -> CommonProofRelationPlanCapability {
        let statement_schema_identifier = family.statement_schema_identifier();
        let relation_context = selected_relation_plan_check_context(statement_schema_identifier)
            .expect("the selected family has a relation context");
        let relation_plan_artifact = selected_relation_plans()
            .expect("selected relation plans compile")
            .into_iter()
            .find(|artifact| {
                artifact.application_statement_schema_identifier() == statement_schema_identifier
            })
            .expect("the selected family has a relation plan");
        CommonProofRelationPlanCapability::from_compiled_plan(
            relation_plan_artifact.compiled_plan(),
            &relation_context,
            None,
            None,
        )
        .expect("the selected family construction plan validates")
    }

    #[test]
    fn exact_verification_sizing_routes_validated_same_secret_construction() {
        let relation_plan =
            selected_relation_plan_capability(SetupKeyRelationProofFamily::SameSecret);
        let canonical_proof_byte_length =
            u64::try_from(NOMINAL_ROW_CODE_WHIR_PROOF_BYTE_LENGTH + 1)
                .expect("the selection proof-size target fits u64");

        let limits = exact_same_secret_verification_runtime_limits(
            &relation_plan,
            canonical_proof_byte_length,
        )
        .expect("a bounded exact proof routes to the WHIR verifier");

        assert_eq!(
            limits.maximum_proof_byte_length(),
            MAXIMUM_COMMON_PROOF_BYTE_LENGTH
        );
        assert_eq!(
            limits.prefetched_query_byte_length(),
            u64::try_from(MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH)
                .expect("the canonical proof chunk length fits u64")
        );
        assert_eq!(
            limits.external_memory_chunk_byte_length(),
            MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH
        );
    }

    #[test]
    fn exact_verification_sizing_refuses_oversized_proof_stream() {
        let relation_plan =
            selected_relation_plan_capability(SetupKeyRelationProofFamily::SameSecret);
        let oversized_proof_byte_length = u64::try_from(MAXIMUM_COMMON_PROOF_BYTE_LENGTH)
            .expect("the common proof hard limit fits u64")
            + 1;

        assert!(matches!(
            exact_same_secret_verification_runtime_limits(
                &relation_plan,
                oversized_proof_byte_length,
            ),
            Err(CommonProofRuntimeError::WrongVerificationBinding)
        ));
        assert!(matches!(
            exact_same_secret_verification_runtime_limits(&relation_plan, 0),
            Err(CommonProofRuntimeError::WrongVerificationBinding)
        ));
    }

    #[test]
    fn exact_verification_sizing_refuses_wrong_construction() {
        let wrong_relation_plan =
            selected_relation_plan_capability(SetupKeyRelationProofFamily::PublicKeyShare);
        let bounded_proof_byte_length = u64::try_from(NOMINAL_ROW_CODE_WHIR_PROOF_BYTE_LENGTH - 1)
            .expect("the selected proof-size target fits u64");

        assert!(matches!(
            exact_same_secret_verification_runtime_limits(
                &wrong_relation_plan,
                bounded_proof_byte_length,
            ),
            Err(CommonProofRuntimeError::WrongVerificationBinding)
        ));
    }

    #[test]
    fn verified_vss_prerequisite_selects_each_limb_degree_zero_root() {
        let relation_input = selected_committed_material_relation_plan_input()
            .expect("selected committed-material relation input");
        let sharing_limb_count = relation_input.sharing_data_modulus_indices.len();
        let reconstruction_threshold = usize::from(relation_input.threshold);
        assert_eq!(sharing_limb_count, 8);
        assert_eq!(reconstruction_threshold, 4);

        let coefficient_roots = (0..sharing_limb_count * reconstruction_threshold)
            .map(|root_ordinal| {
                [u8::try_from(root_ordinal + 1).expect("test root ordinal fits"); 64]
            })
            .collect::<Vec<_>>();
        let selected_roots = selected_vss_degree_zero_coefficient_roots(&coefficient_roots)
            .expect("select one degree-zero root per sharing limb");

        for (sharing_limb_ordinal, selected_root) in selected_roots.iter().enumerate() {
            let expected_root_ordinal = sharing_limb_ordinal * reconstruction_threshold;
            assert_eq!(*selected_root, coefficient_roots[expected_root_ordinal]);
        }
    }

    #[test]
    fn verified_vss_prerequisite_rejects_incomplete_or_extra_coefficient_roots() {
        let relation_input = selected_committed_material_relation_plan_input()
            .expect("selected committed-material relation input");
        let exact_root_count = relation_input
            .sharing_data_modulus_indices
            .len()
            .checked_mul(usize::from(relation_input.threshold))
            .expect("selected coefficient-root count fits");
        let exact_roots = vec![[0x5a; 64]; exact_root_count];

        assert!(
            selected_vss_degree_zero_coefficient_roots(&exact_roots[..exact_root_count - 1])
                .is_err()
        );
        let mut extra_roots = exact_roots;
        extra_roots.push([0xa5; 64]);
        assert!(selected_vss_degree_zero_coefficient_roots(&extra_roots).is_err());
    }

    #[test]
    fn authenticated_transcript_prefix_binds_prerequisite_construction_and_committed_root() {
        let relation_plan =
            selected_relation_plan_capability(SetupKeyRelationProofFamily::SameSecret);
        let construction_plan = relation_plan.row_code_whir_construction_plan();
        let mut ordered_source_roots = [[0_u8; Hash512::BYTE_LENGTH]; 11];
        for (source_ordinal, source_root) in ordered_source_roots.iter_mut().enumerate() {
            source_root.fill(
                u8::try_from(source_ordinal + 1).expect("source-root ordinal fits test byte"),
            );
        }
        let ordered_input_roots: [[u8; Hash512::BYTE_LENGTH]; 8] = ordered_source_roots[..8]
            .try_into()
            .expect("the exact source catalog starts with eight VSS roots");
        let protocol_version = 1;
        let suite_identifier = [0x11; Hash512::BYTE_LENGTH];
        let ceremony_context_hash = [0x22; Hash512::BYTE_LENGTH];
        let action_context_hash = [0x33; Hash512::BYTE_LENGTH];
        let setup_proof_context_hash = [0x44; Hash512::BYTE_LENGTH];
        let participant_identity = [0x55; Hash512::BYTE_LENGTH];
        let roster_position = 2;
        let fiat_shamir_binding = ExactSameSecretFiatShamirBinding {
            protocol_version,
            suite_identifier,
            ceremony_context_hash,
            action_context_hash,
            participant_identity,
            roster_position,
            proof_application_slot_hash: [0x66; Hash512::BYTE_LENGTH],
            application_statement_schema_identifier: SetupKeyRelationProofFamily::SameSecret
                .statement_schema_identifier(),
            application_statement_hash: [0x77; Hash512::BYTE_LENGTH],
            proof_header_hash: [0x88; Hash512::BYTE_LENGTH],
            relation_plan_hash: relation_plan.relation_plan_hash(),
            relation_plan_variant_hash: relation_plan.relation_plan_variant_hash(),
            construction_plan_identity_hash: relation_plan
                .row_code_whir_construction_plan_identity_hash(),
            oracle_equation_catalog_hash: construction_plan
                .oracle_equation_catalog_hash()
                .expect("the selected construction has a canonical oracle catalog"),
            setup_proof_context_hash,
            ordered_source_roots,
        };
        let prerequisite = VerifiedSameSecretLowDegreePrerequisite::for_test(
            protocol_version,
            suite_identifier,
            ceremony_context_hash,
            action_context_hash,
            [0x99; Hash512::BYTE_LENGTH],
            setup_proof_context_hash,
            participant_identity,
            roster_position,
            ordered_input_roots,
            [0xaa; Hash512::BYTE_LENGTH],
        )
        .expect("construct matching VSS prerequisite");
        let authority_binding = ExactSameSecretTranscriptPrefixAuthorityBinding::new(
            fiat_shamir_binding,
            [0xbb; Hash512::BYTE_LENGTH],
            [0xcc; 32],
        )
        .expect("construct attempt-scoped transcript authority");
        let first_request = ExactSameSecretAuthenticatedTranscriptPrefixRequest::new(
            authority_binding.clone(),
            [0xdd; Hash512::BYTE_LENGTH],
            [0xee; Hash512::BYTE_LENGTH],
        )
        .expect("construct first transcript-prefix request");
        let second_request = ExactSameSecretAuthenticatedTranscriptPrefixRequest::new(
            authority_binding,
            [0xdd; Hash512::BYTE_LENGTH],
            [0xef; Hash512::BYTE_LENGTH],
        )
        .expect("construct second transcript-prefix request");

        let first_prepared = PreparedExactSameSecretTranscriptPrefix::prepare(
            first_request.clone(),
            &prerequisite,
            &relation_plan,
        )
        .expect("prepare the authenticated transcript prefix");
        assert_eq!(first_prepared.binding().request(), &first_request);
        assert_eq!(
            first_prepared.binding().verified_prerequisite_binding(),
            prerequisite.binding_digest()
        );
        let schedule = construction_plan.relation_prefix_schedule().clone();
        let first_challenges = sample_relation_application_challenges(
            &mut first_prepared.into_transcript(),
            &schedule,
        )
        .expect("sample challenges from the first authenticated prefix");
        let second_challenges = sample_relation_application_challenges(
            &mut PreparedExactSameSecretTranscriptPrefix::prepare(
                second_request,
                &prerequisite,
                &relation_plan,
            )
            .expect("prepare a prefix for the changed committed root")
            .into_transcript(),
            &schedule,
        )
        .expect("sample challenges from the changed authenticated prefix");
        assert_ne!(first_challenges, second_challenges);

        let wrong_prerequisite = VerifiedSameSecretLowDegreePrerequisite::for_test(
            protocol_version,
            suite_identifier,
            ceremony_context_hash,
            [0xf0; Hash512::BYTE_LENGTH],
            [0x99; Hash512::BYTE_LENGTH],
            setup_proof_context_hash,
            participant_identity,
            roster_position,
            ordered_input_roots,
            [0xaa; Hash512::BYTE_LENGTH],
        )
        .expect("construct mismatched VSS prerequisite");
        assert!(
            PreparedExactSameSecretTranscriptPrefix::prepare(
                first_request.clone(),
                &wrong_prerequisite,
                &relation_plan,
            )
            .is_err()
        );
        let wrong_relation_plan =
            selected_relation_plan_capability(SetupKeyRelationProofFamily::PublicKeyShare);
        assert!(
            PreparedExactSameSecretTranscriptPrefix::prepare(
                first_request,
                &prerequisite,
                &wrong_relation_plan,
            )
            .is_err()
        );
    }

    fn fixed_hash(bytes: &[u8], label: &str) -> [u8; 64] {
        bytes
            .try_into()
            .unwrap_or_else(|_| panic!("{label} must contain exactly 64 bytes"))
    }

    fn column_digest_bytes(digest: ColumnDigest) -> [u8; 64] {
        digest
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect::<Vec<_>>()
            .try_into()
            .expect("eight digest words encode 64 bytes")
    }

    fn exact_trace_private_coin_catalog_for_tree_role(
        variant: &crate::bgv::proof_suite::RelationPlanVariant,
        tree_role: ProofTreeRole,
        include_row_pad_seed_fill: bool,
    ) -> CommonProofPrivateCoinSamplingCatalog {
        let layout = ExactBasePhaseLayout::for_tree_role(variant, tree_role)
            .expect("derive exact phase layout for private-coin reconciliation");
        let phase_column_ordinals = layout
            .rows
            .iter()
            .flat_map(|row| row.column_ordinals)
            .flatten()
            .collect::<BTreeSet<_>>();
        let phase_coordinates = variant
            .ordered_masks()
            .iter()
            .copied()
            .filter(|mask| {
                mask.mask_kind() == RelationMaskKind::Trace
                    && phase_column_ordinals.contains(&mask.target_ordinal())
            })
            .map(|mask| CommonProofPrivateCoinCoordinate::from_mask(mask.mask_coordinate()))
            .collect::<BTreeSet<_>>();
        let mut catalog = CommonProofPrivateCoinSamplingCatalog::from_relation_plan_variant(
            variant,
            SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT,
        )
        .expect("derive relation private-coin catalog");
        if include_row_pad_seed_fill {
            catalog
                .record_raw_byte_fill(
                    CommonProofPrivateCoinCoordinate::proof_salt(),
                    EXACT_ROW_PAD_SEED_BYTE_LENGTH,
                )
                .expect("add row-pad seeds to phase private-coin catalog");
        }
        catalog.retaining_coordinates(|coordinate| {
            phase_coordinates.contains(&coordinate)
                || (include_row_pad_seed_fill
                    && coordinate == CommonProofPrivateCoinCoordinate::proof_salt())
        })
    }

    fn exact_quotient_private_coin_catalog(
        variant: &crate::bgv::proof_suite::RelationPlanVariant,
    ) -> CommonProofPrivateCoinSamplingCatalog {
        let quotient_coordinates = variant
            .ordered_masks()
            .iter()
            .copied()
            .filter(|mask| mask.mask_kind() != RelationMaskKind::Trace)
            .map(|mask| CommonProofPrivateCoinCoordinate::from_mask(mask.mask_coordinate()))
            .collect::<BTreeSet<_>>();
        CommonProofPrivateCoinSamplingCatalog::from_relation_plan_variant(
            variant,
            SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT,
        )
        .expect("derive relation private-coin catalog")
        .retaining_coordinates(|coordinate| quotient_coordinates.contains(&coordinate))
    }

    fn validate_checkpoint_binding(
        sources: &PreparedExactSameSecretGenerationSources,
        manifest: &SourceCheckpointManifest,
    ) {
        assert_eq!(
            fixed_hash(&manifest.relation_plan_hash, "relation-plan hash"),
            sources.relation_plan.relation_plan_hash()
        );
        assert_eq!(
            fixed_hash(
                &manifest.relation_plan_variant_hash,
                "relation-plan variant hash"
            ),
            sources.relation_plan.relation_plan_variant_hash()
        );
        assert_eq!(
            manifest.canonical_application_statement_bytes,
            sources.canonical_application_statement_bytes
        );
        assert_eq!(
            fixed_hash(&manifest.generation_binding_hash, "generation binding"),
            sources.generation_binding_hash
        );
        assert_eq!(manifest.stored_relation_column_count, 2_030);
    }

    fn digest_from_words(words: &[u64], label: &str) -> ColumnDigest {
        words
            .try_into()
            .unwrap_or_else(|_| panic!("{label} must contain exactly eight digest words"))
    }

    fn exact_transcript_through_composition(
        sources: &PreparedExactSameSecretGenerationSources,
        phase_manifest: &ExactPhaseCommitmentManifest,
    ) -> (
        CommonProofTranscript,
        Vec<crate::bgv::proof_suite::RelationApplicationChallengeAssignment>,
        Vec<ProofChallengeExtensionElement>,
    ) {
        assert_eq!(
            fixed_hash(
                &phase_manifest.relation_plan_hash,
                "phase relation-plan hash"
            ),
            sources.relation_plan.relation_plan_hash()
        );
        assert_eq!(
            fixed_hash(
                &phase_manifest.relation_plan_variant_hash,
                "phase relation-plan variant hash"
            ),
            sources.relation_plan.relation_plan_variant_hash()
        );
        let request_context = sources
            .source_polynomials
            .exact_same_secret_evidence_request_context();
        let statement_schema_identifier =
            SetupKeyRelationProofFamily::SameSecret.statement_schema_identifier();
        let schedule = sources
            .relation_plan_variant
            .common_proof_relation_prefix_schedule(&sources.relation_context)
            .expect("derive production transcript schedule");
        let transcript_authority = sources
            .authorization
            .exact_same_secret_transcript_prefix_authority_binding(
                &sources.canonical_application_statement_bytes,
                &sources.relation_plan,
            )
            .expect("derive exact transcript authority");
        let header = exact_transcript_header(
            transcript_authority.fiat_shamir_binding(),
            production_same_secret_prerequisite(sources)
                .expect("construct verified VSS prerequisite")
                .binding_digest(),
        );
        let mut transcript = CommonProofTranscript::new_relation_prefix(
            request_context.protocol_version(),
            request_context.suite_identifier(),
            sources
                .relation_plan
                .row_code_whir_construction_plan_identity_hash(),
            statement_schema_identifier,
            &header,
            schedule.clone(),
        )
        .expect("construct exact relation transcript");
        absorb_exact_relation_roots(
            &mut transcript,
            schedule.ordered_base_tree_ordinals(),
            ProofTreeRole::BaseOracle,
            digest_from_words(&phase_manifest.base_root_words, "base root"),
            &sources.relation_plan_variant,
            &sources.relation_trees,
        )
        .expect("absorb exact base phase");
        let application_challenges =
            sample_relation_application_challenges(&mut transcript, &schedule)
                .expect("sample exact relation application challenges");
        absorb_exact_relation_roots(
            &mut transcript,
            schedule.ordered_auxiliary_tree_ordinals(),
            ProofTreeRole::AuxiliaryOracle,
            digest_from_words(&phase_manifest.auxiliary_root_words, "auxiliary root"),
            &sources.relation_plan_variant,
            &sources.relation_trees,
        )
        .expect("absorb exact auxiliary phase");
        let composition_challenges = (0..sources.relation_plan_variant.constraint_count())
            .map(|constraint_ordinal| {
                transcript
                    .sample_composition_challenge(
                        u32::try_from(constraint_ordinal)
                            .expect("constraint ordinal fits canonical u32"),
                    )
                    .expect("sample exact composition challenge")
            })
            .collect();
        (transcript, application_challenges, composition_challenges)
    }

    fn ensure_exact_verifier_sequence_columns(
        sources: &mut PreparedExactSameSecretGenerationSources,
        store: &ExactPolynomialStore,
    ) {
        for column_ordinal in 0..sources.relation_plan_variant.ordered_columns().len() {
            let column_ordinal =
                u32::try_from(column_ordinal).expect("relation column ordinal fits u32");
            if store.contains(column_ordinal) {
                continue;
            }
            let polynomial = sources
                .source_polynomials
                .exact_same_secret_evidence_verifier_sequence_polynomial(column_ordinal)
                .unwrap_or_else(|error| {
                    panic!(
                        "missing relation column {column_ordinal} is not an authority-derived verifier sequence: {error:?}"
                    )
                });
            store
                .write(column_ordinal, &polynomial)
                .expect("checkpoint authority-derived verifier sequence");
        }
        assert!(
            (0..sources.relation_plan_variant.ordered_columns().len()).all(|column_ordinal| store
                .contains(u32::try_from(column_ordinal).expect("column ordinal fits u32")))
        );
    }

    fn invert_nonzero_extension_elements_in_place(
        values: &mut [ProofChallengeExtensionElement],
    ) -> Result<(), String> {
        let mut prefix_products = Vec::with_capacity(values.len());
        let mut accumulated_product = ProofChallengeExtensionElement::ONE;
        for value in values.iter().copied() {
            if value.is_zero() {
                return Err("exact quotient zeroifier vanishes on the evaluation coset".to_owned());
            }
            prefix_products.push(accumulated_product);
            accumulated_product = accumulated_product.multiply(value);
        }
        let mut accumulated_inverse = accumulated_product
            .inverse()
            .map_err(|error| format!("invert exact quotient zeroifier product: {error:?}"))?;
        for value_ordinal in (0..values.len()).rev() {
            let value = values[value_ordinal];
            values[value_ordinal] = accumulated_inverse.multiply(prefix_products[value_ordinal]);
            accumulated_inverse = accumulated_inverse.multiply(value);
        }
        Ok(())
    }

    #[test]
    fn exact_private_coin_catalog_covers_relation_row_pad_and_aggregate_wide_hiding() {
        let (_, variant, _) =
            production_same_secret_relation().expect("compile exact same-secret relation");
        let catalog =
            exact_private_coin_sampling_catalog(&variant).expect("derive exact private coins");
        assert_eq!(
            EXACT_ROW_PAD_SEED_BYTE_LENGTH, 96,
            "the exact three row-pad seeds must consume one 96-byte raw fill"
        );

        let base_phase_catalog = exact_trace_private_coin_catalog_for_tree_role(
            &variant,
            ProofTreeRole::BaseOracle,
            true,
        );
        let auxiliary_phase_catalog = exact_trace_private_coin_catalog_for_tree_role(
            &variant,
            ProofTreeRole::AuxiliaryOracle,
            false,
        );
        let quotient_phase_catalog = exact_quotient_private_coin_catalog(&variant);
        let proof_salt_coordinate = CommonProofPrivateCoinCoordinate::proof_salt();
        assert_eq!(
            base_phase_catalog.entry(proof_salt_coordinate),
            Some(CommonProofPrivateCoinSamplingOperation::RawByteFill { byte_count: 96 })
        );
        assert_eq!(auxiliary_phase_catalog.entry(proof_salt_coordinate), None);
        assert_eq!(quotient_phase_catalog.entry(proof_salt_coordinate), None);

        let mut partitioned_entries = BTreeMap::new();
        for (phase_label, phase_catalog) in [
            ("base", &base_phase_catalog),
            ("auxiliary", &auxiliary_phase_catalog),
            ("quotient", &quotient_phase_catalog),
        ] {
            for (coordinate, operation) in phase_catalog.entries() {
                assert!(
                    partitioned_entries.insert(coordinate, operation).is_none(),
                    "the exact private-coin coordinate {coordinate:?} appears in more than one phase, including {phase_label}"
                );
            }
        }
        let mut relation_and_row_pad_catalog =
            CommonProofPrivateCoinSamplingCatalog::from_relation_plan_variant(
                &variant,
                SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT,
            )
            .expect("derive relation private-coin catalog");
        relation_and_row_pad_catalog
            .record_raw_byte_fill(proof_salt_coordinate, EXACT_ROW_PAD_SEED_BYTE_LENGTH)
            .expect("add exact row-pad seed fill");
        assert_eq!(
            partitioned_entries,
            relation_and_row_pad_catalog
                .entries()
                .collect::<BTreeMap<_, _>>(),
            "the pairwise-disjoint exact relation phases must partition the relation and row-pad actions"
        );

        assert_eq!(
            (
                SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT,
                PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
            ),
            (64, 128),
            "the exact private sampler remains authoritative at D=64; the generic transcript sampler still uses D=128"
        );
        let hiding_configuration = super::super::hiding_whir::selected_hiding_whir_config(
            super::super::construction_plan::RowCodeWhirSelectedParameters::selected(),
        )
        .expect("derive selected aggregate-wide hiding configuration");
        let hiding_shape =
            super::super::aggregate_wide_hiding::AggregateWideHidingMaterialShape::derive(
                &hiding_configuration,
            )
            .expect("derive selected aggregate-wide private-material shape");
        let hiding_base_field_sample_count =
            hiding_shape.total_extension_element_count() * PROOF_CHALLENGE_EXTENSION_DEGREE;
        assert_eq!(hiding_shape.total_extension_element_count(), 18_025);
        assert_eq!(hiding_base_field_sample_count, 90_125);
        assert_eq!(
            catalog.entry(CommonProofPrivateCoinCoordinate::hiding_argument()),
            Some(CommonProofPrivateCoinSamplingOperation::ModuloSamples {
                modulus: crate::bgv::proof_suite::PROOF_BASE_FIELD_MODULUS,
                maximum_candidate_draws_per_output:
                    SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT,
                output_count: 90_125,
            })
        );
        assert_eq!(catalog.entry_count(), variant.ordered_masks().len() + 2);
        let derivation_binding_hash = Hash512::from_bytes([0x8b_u8; Hash512::BYTE_LENGTH]);
        let stream_attempt_identifier = [0x4e_u8; 32];
        let checkpoint_cursors = catalog
            .entries()
            .enumerate()
            .map(|(catalog_ordinal, (coordinate, _))| {
                let cursor = PrivateRandomCursor::new(
                    ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
                    coordinate.purpose_class(),
                    common_proof_private_coin_coordinate_derivation_context_hash(
                        derivation_binding_hash,
                        coordinate,
                    ),
                    stream_attempt_identifier,
                    u64::try_from(catalog_ordinal + 1).expect("catalog ordinal fits u64"),
                    None,
                )
                .expect("exact private-coin catalog cursor is valid");
                (coordinate, cursor)
            })
            .collect::<Vec<_>>();
        let checkpoint_manifest = encode_common_proof_checkpoint_cursor_manifest(
            ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
            derivation_binding_hash,
            stream_attempt_identifier,
            checkpoint_cursors,
        )
        .expect("the complete exact private-coin catalog has a canonical checkpoint manifest");
        assert_eq!(
            u32::from_le_bytes(
                checkpoint_manifest[11..15]
                    .try_into()
                    .expect("checkpoint logical-cursor-count bytes")
            ),
            u32::try_from(catalog.entry_count()).expect("catalog entry count fits u32"),
            "the exact checkpoint commitment covers every relation-mask, aggregate-hiding, and row-pad cursor"
        );
        for (coordinate, operation) in catalog.entries() {
            if coordinate == CommonProofPrivateCoinCoordinate::proof_salt() {
                assert_eq!(
                    operation,
                    CommonProofPrivateCoinSamplingOperation::RawByteFill {
                        byte_count: u64::try_from(EXACT_ROW_PAD_SEED_BYTE_LENGTH)
                            .expect("row-pad byte count fits u64"),
                    }
                );
                assert_eq!(operation.maximum_candidate_draws_per_output(), None);
            } else {
                let CommonProofPrivateCoinSamplingOperation::ModuloSamples {
                    modulus,
                    maximum_candidate_draws_per_output,
                    output_count,
                } = operation
                else {
                    panic!("relation masks and aggregate-wide hiding must use modulo sampling")
                };
                assert_eq!(modulus, crate::bgv::proof_suite::PROOF_BASE_FIELD_MODULUS);
                assert_eq!(
                    maximum_candidate_draws_per_output,
                    SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT
                );
                assert!(output_count > 0);
            }
        }

        let application_slot_ceilings =
            crate::bgv::proof_suite::selected_profile::selected_proof_application_slot_ceilings()
                .expect("derive selected proof-application ceilings");
        let same_secret_application_multiplicity = application_slot_ceilings
            .family_ceiling(ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER)
            .expect("selected profile includes the same-secret family");
        assert_eq!(same_secret_application_multiplicity, 10);
        let complete_action_exhaustion = catalog
            .exhaustion_union_bound(same_secret_application_multiplicity)
            .expect("derive exact complete-action private-coin exhaustion");
        assert!(
            complete_action_exhaustion.is_at_most_inverse_power_of_two(128),
            "under the uniform-private-coin or ideal-PRF premise, the source-derived exact same-secret private-coin exhaustion union must be at most 2^-128"
        );
    }

    #[test]
    fn exact_checkpoint_private_coin_prefixes_encode_canonically() {
        let (_, variant, _) =
            production_same_secret_relation().expect("compile exact same-secret relation");
        let base_phase_catalog = exact_trace_private_coin_catalog_for_tree_role(
            &variant,
            ProofTreeRole::BaseOracle,
            false,
        );
        let auxiliary_phase_catalog = exact_trace_private_coin_catalog_for_tree_role(
            &variant,
            ProofTreeRole::AuxiliaryOracle,
            false,
        );
        let quotient_phase_catalog = exact_quotient_private_coin_catalog(&variant);
        let complete_catalog =
            exact_private_coin_sampling_catalog(&variant).expect("derive exact private coins");
        let family_schema_identifier =
            ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER;
        let derivation_binding_hash = Hash512::from_bytes([0x9a_u8; Hash512::BYTE_LENGTH]);
        let stream_attempt_identifier = [0xc3_u8; 32];
        let mut consumed_coordinates = BTreeSet::new();

        let assert_checkpoint_manifest = |checkpoint_label: &str,
                                          coordinates: &BTreeSet<
            CommonProofPrivateCoinCoordinate,
        >|
         -> Vec<u8> {
            let cursors = coordinates
                .iter()
                .copied()
                .enumerate()
                .map(|(coordinate_ordinal, coordinate)| {
                    let cursor = PrivateRandomCursor::new(
                        family_schema_identifier,
                        coordinate.purpose_class(),
                        common_proof_private_coin_coordinate_derivation_context_hash(
                            derivation_binding_hash,
                            coordinate,
                        ),
                        stream_attempt_identifier,
                        u64::try_from(coordinate_ordinal + 1)
                            .expect("checkpoint coordinate ordinal fits u64"),
                        None,
                    )
                    .expect("checkpoint cursor is valid");
                    (coordinate, cursor)
                })
                .collect::<Vec<_>>();
            encode_common_proof_checkpoint_cursor_manifest(
                family_schema_identifier,
                derivation_binding_hash,
                stream_attempt_identifier,
                cursors,
            )
            .unwrap_or_else(|error| {
                panic!(
                    "{checkpoint_label} private-coin checkpoint is not canonical: {error:?}; coordinate_count={}; first_coordinate={:?}; last_coordinate={:?}",
                    coordinates.len(),
                    coordinates.first(),
                    coordinates.last(),
                )
            })
        };
        let mut checkpoint_manifests = Vec::new();

        consumed_coordinates.extend(
            base_phase_catalog
                .entries()
                .map(|(coordinate, _)| coordinate),
        );
        checkpoint_manifests.push(assert_checkpoint_manifest(
            "sources and construction",
            &consumed_coordinates,
        ));
        consumed_coordinates.insert(CommonProofPrivateCoinCoordinate::proof_salt());
        checkpoint_manifests.push(assert_checkpoint_manifest(
            "base commitment",
            &consumed_coordinates,
        ));
        consumed_coordinates.extend(
            auxiliary_phase_catalog
                .entries()
                .map(|(coordinate, _)| coordinate),
        );
        checkpoint_manifests.push(assert_checkpoint_manifest(
            "auxiliary commitment",
            &consumed_coordinates,
        ));
        consumed_coordinates.extend(
            quotient_phase_catalog
                .entries()
                .map(|(coordinate, _)| coordinate),
        );
        checkpoint_manifests.push(assert_checkpoint_manifest(
            "quotient commitment",
            &consumed_coordinates,
        ));
        consumed_coordinates.insert(CommonProofPrivateCoinCoordinate::hiding_argument());
        assert_eq!(
            consumed_coordinates,
            complete_catalog
                .entries()
                .map(|(coordinate, _)| coordinate)
                .collect::<BTreeSet<_>>()
        );
        checkpoint_manifests.push(assert_checkpoint_manifest(
            "aggregate-wide hiding",
            &consumed_coordinates,
        ));

        let checkpoint_requirement =
            common_proof_checkpoint_cursor_manifest_requirement_for_variant(&variant)
                .expect("derive the exact checkpoint cursor requirement");
        let checkpoint_shapes = checkpoint_manifests
            .iter()
            .map(|manifest| {
                let logical_cursor_count = u32::from_le_bytes(
                    manifest[11..15]
                        .try_into()
                        .expect("checkpoint logical-cursor-count bytes"),
                );
                (manifest.len(), logical_cursor_count)
            })
            .collect::<Vec<_>>();
        assert_eq!(
            checkpoint_requirement.logical_cursor_count(),
            u32::try_from(consumed_coordinates.len()).expect("coordinate count fits u32")
        );
        assert_eq!(
            checkpoint_requirement.canonical_manifest_byte_ceiling(),
            u32::try_from(
                checkpoint_shapes
                    .iter()
                    .map(|(byte_length, _)| *byte_length)
                    .max()
                    .expect("the checkpoint schedule is nonempty")
            )
            .expect("checkpoint byte length fits u32")
        );
        assert!(
            checkpoint_manifests
                .windows(2)
                .all(|manifests| manifests[0] != manifests[1]),
            "each additional consumed cursor must change the exact checkpoint commitment"
        );
        assert_eq!(
            checkpoint_shapes
                .last()
                .map(|(_, logical_cursor_count)| *logical_cursor_count),
            Some(checkpoint_requirement.logical_cursor_count())
        );
        assert!(checkpoint_requirement.fits_absolute_bounds());
    }

    #[test]
    fn exact_quotient_batch_inversion_matches_individual_inversion() {
        let original_values = [
            ProofChallengeExtensionElement::from_canonical_coordinates([2, 0, 0, 0, 0])
                .expect("canonical base-field extension element"),
            ProofChallengeExtensionElement::from_canonical_coordinates([7, 11, 0, 5, 1])
                .expect("canonical mixed extension element"),
            ProofChallengeExtensionElement::from_canonical_coordinates([
                18_446_744_069_414_584_320,
                1,
                17,
                0,
                9,
            ])
            .expect("canonical near-modulus extension element"),
        ];
        let expected_inverses = original_values
            .iter()
            .copied()
            .map(|value| {
                value
                    .inverse()
                    .expect("nonzero extension element is invertible")
            })
            .collect::<Vec<_>>();
        let mut actual_inverses = original_values;
        invert_nonzero_extension_elements_in_place(&mut actual_inverses)
            .expect("batch inversion succeeds");
        assert_eq!(actual_inverses.as_slice(), expected_inverses);
        for (value, inverse) in original_values.into_iter().zip(actual_inverses) {
            assert_eq!(value.multiply(inverse), ProofChallengeExtensionElement::ONE);
        }

        let mut includes_zero = [
            ProofChallengeExtensionElement::ONE,
            ProofChallengeExtensionElement::ZERO,
        ];
        assert!(invert_nonzero_extension_elements_in_place(&mut includes_zero).is_err());
    }

    fn construct_exact_composed_quotient(
        sources: &PreparedExactSameSecretGenerationSources,
        store: &ExactPolynomialStore,
        phase_manifest: &ExactPhaseCommitmentManifest,
        application_challenges: &[crate::bgv::proof_suite::RelationApplicationChallengeAssignment],
        composition_challenges: &[ProofChallengeExtensionElement],
    ) -> (Zeroizing<Vec<ProofChallengeExtensionElement>>, usize) {
        const QUOTIENT_EVALUATION_DOMAIN_SIZE: usize = 65_536;

        let variant = &sources.relation_plan_variant;
        let context = &sources.relation_context;
        assert_eq!(composition_challenges.len(), variant.constraint_count());
        assert_eq!(QUOTIENT_EVALUATION_DOMAIN_SIZE % 16_384, 0);
        let domain = ProofEvaluationDomain::new(
            QUOTIENT_EVALUATION_DOMAIN_SIZE,
            context.evaluation_coset_offset,
        )
        .expect("construct exact quotient coset");
        let trace_domain_size =
            usize::try_from(variant.trace_domain_size()).expect("trace domain fits usize");
        let rotation_stride = QUOTIENT_EVALUATION_DOMAIN_SIZE / trace_domain_size;
        let checked_application_challenges = variant
            .checked_application_challenges(context, application_challenges)
            .expect("validate exact application challenges");

        let mut columns_by_constraint = Vec::with_capacity(variant.constraint_count());
        let mut last_constraint_by_column = vec![None; variant.ordered_columns().len()];
        for constraint_ordinal in 0..variant.constraint_count() {
            let mut columns = variant
                .constraint_column_queries(constraint_ordinal)
                .expect("derive exact constraint queries")
                .into_iter()
                .map(|query| query.column_ordinal())
                .collect::<Vec<_>>();
            columns.sort_unstable();
            columns.dedup();
            for column_ordinal in &columns {
                last_constraint_by_column
                    [usize::try_from(*column_ordinal).expect("column ordinal fits usize")] =
                    Some(constraint_ordinal);
            }
            columns_by_constraint.push(columns);
        }

        let mut scheduled_active_columns = vec![false; variant.ordered_columns().len()];
        let mut scheduled_active_column_count = 0_usize;
        let mut maximum_active_column_count = 0_usize;
        for (constraint_ordinal, constraint_columns) in columns_by_constraint.iter().enumerate() {
            for column_ordinal in constraint_columns {
                let column_index =
                    usize::try_from(*column_ordinal).expect("column ordinal fits usize");
                if !scheduled_active_columns[column_index] {
                    scheduled_active_columns[column_index] = true;
                    scheduled_active_column_count += 1;
                    maximum_active_column_count =
                        maximum_active_column_count.max(scheduled_active_column_count);
                }
            }
            for column_ordinal in constraint_columns {
                let column_index =
                    usize::try_from(*column_ordinal).expect("column ordinal fits usize");
                if last_constraint_by_column[column_index] == Some(constraint_ordinal) {
                    assert!(scheduled_active_columns[column_index]);
                    scheduled_active_columns[column_index] = false;
                    scheduled_active_column_count -= 1;
                }
            }
        }
        assert_eq!(scheduled_active_column_count, 0);
        assert!(scheduled_active_columns.iter().all(|active| !active));

        let evaluation_points = (0..domain.size())
            .map(|position| {
                domain
                    .point(position)
                    .map(ProofChallengeExtensionElement::from_base)
            })
            .collect::<Result<Vec<_>, _>>()
            .expect("materialize exact quotient evaluation points");
        let zeroifier_representative_ordinals =
            variant.constraint_zeroifier_representative_ordinals();
        assert_eq!(
            zeroifier_representative_ordinals.len(),
            variant.constraint_count()
        );
        let distinct_zeroifier_representatives = zeroifier_representative_ordinals
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let mut inverse_zeroifier_evaluations = BTreeMap::new();
        for representative_ordinal in distinct_zeroifier_representatives.iter().copied() {
            let mut zeroifier_evaluations = evaluation_points
                .iter()
                .copied()
                .enumerate()
                .map(|(evaluation_position, evaluation_point)| {
                    variant
                        .evaluate_constraint_zeroifier_at_point(
                            context,
                            representative_ordinal,
                            evaluation_point,
                            &checked_application_challenges,
                        )
                        .unwrap_or_else(|error| {
                            panic!(
                                "evaluate exact zeroifier class {representative_ordinal} at position {evaluation_position}: {error:?}"
                            )
                        })
                })
                .collect::<Vec<_>>();
            invert_nonzero_extension_elements_in_place(&mut zeroifier_evaluations)
                .expect("batch-invert exact quotient zeroifier class");
            assert!(
                inverse_zeroifier_evaluations
                    .insert(representative_ordinal, zeroifier_evaluations)
                    .is_none()
            );
        }
        let mut accumulator_binding_bytes = Vec::new();
        accumulator_binding_bytes.extend_from_slice(&sources.relation_plan.relation_plan_hash());
        accumulator_binding_bytes
            .extend_from_slice(&sources.relation_plan.relation_plan_variant_hash());
        accumulator_binding_bytes.extend_from_slice(&sources.generation_binding_hash);
        accumulator_binding_bytes.extend_from_slice(&sources.public_setup_seed);
        accumulator_binding_bytes.extend_from_slice(
            &u64::try_from(sources.canonical_application_statement_bytes.len())
                .expect("statement length fits u64")
                .to_le_bytes(),
        );
        accumulator_binding_bytes.extend_from_slice(&sources.canonical_application_statement_bytes);
        for root_word in phase_manifest
            .base_root_words
            .iter()
            .chain(&phase_manifest.auxiliary_root_words)
        {
            accumulator_binding_bytes.extend_from_slice(&root_word.to_le_bytes());
        }
        for assignment in application_challenges {
            accumulator_binding_bytes
                .extend_from_slice(&assignment.repetition_ordinal().to_le_bytes());
            accumulator_binding_bytes.extend_from_slice(&assignment.value().to_le_bytes());
        }
        for challenge in composition_challenges {
            for coordinate in challenge.canonical_coordinates() {
                accumulator_binding_bytes.extend_from_slice(&coordinate.to_le_bytes());
            }
        }
        accumulator_binding_bytes.extend_from_slice(
            &u64::try_from(domain.size())
                .expect("domain size fits u64")
                .to_le_bytes(),
        );
        let mut accumulator_binding_hasher = StreamingHash512::new(
            "sealed-lattice/exact-same-secret/quotient-accumulator/v1",
            1,
        );
        accumulator_binding_hasher.absorb_part(&accumulator_binding_bytes);
        let accumulator_binding = accumulator_binding_hasher.finalize();
        let (first_constraint_ordinal, mut quotient_evaluations) = store
            .read_latest_quotient_accumulator(
                accumulator_binding,
                variant.constraint_count(),
                domain.size(),
            )
            .expect("read exact quotient accumulator")
            .unwrap_or_else(|| {
                (
                    0,
                    Zeroizing::new(vec![ProofChallengeExtensionElement::ZERO; domain.size()]),
                )
            });
        let mut active_columns = std::iter::repeat_with(|| None)
            .take(variant.ordered_columns().len())
            .collect::<Vec<Option<Zeroizing<Vec<ProofBaseFieldElement>>>>>();
        let mut active_column_count = 0_usize;

        for (constraint_ordinal, constraint_columns) in columns_by_constraint
            .iter()
            .enumerate()
            .skip(first_constraint_ordinal)
        {
            let inverse_zeroifier_values = inverse_zeroifier_evaluations
                .get(&zeroifier_representative_ordinals[constraint_ordinal])
                .expect("exact quotient zeroifier class was precomputed");
            for column_ordinal in constraint_columns {
                let column_index =
                    usize::try_from(*column_ordinal).expect("column ordinal fits usize");
                if active_columns[column_index].is_some() {
                    continue;
                }
                let CommonProofSourcePolynomial::Base(mut coefficients) = store
                    .read(*column_ordinal)
                    .expect("read exact quotient input column")
                else {
                    panic!("exact relation column {column_ordinal} is not base-field valued")
                };
                domain
                    .evaluate_base_polynomial_in_place(&mut coefficients)
                    .expect("transform exact quotient input column");
                active_columns[column_index] = Some(coefficients);
                active_column_count += 1;
            }

            let composition_challenge = composition_challenges[constraint_ordinal];
            for (evaluation_position, evaluation_point) in
                evaluation_points.iter().copied().enumerate()
            {
                let numerator = variant
                    .evaluate_constraint_numerator_at_point(
                        context,
                        constraint_ordinal,
                        evaluation_point,
                        &checked_application_challenges,
                        &mut |column_ordinal, rotation_is_negative, rotation_magnitude| {
                            let reduced_rotation = usize::try_from(
                                rotation_magnitude
                                    % u64::try_from(trace_domain_size)
                                        .map_err(|_| RelationPlanError::CountOverflow)?,
                            )
                            .map_err(|_| RelationPlanError::CountOverflow)?;
                            let rotation_offset = reduced_rotation
                                .checked_mul(rotation_stride)
                                .ok_or(RelationPlanError::CountOverflow)?;
                            let rotated_position = if rotation_is_negative {
                                evaluation_position
                                    .checked_add(domain.size())
                                    .and_then(|position| position.checked_sub(rotation_offset))
                                    .ok_or(RelationPlanError::CountOverflow)?
                                    % domain.size()
                            } else {
                                evaluation_position
                                    .checked_add(rotation_offset)
                                    .ok_or(RelationPlanError::CountOverflow)?
                                    % domain.size()
                            };
                            active_columns
                                .get(
                                    usize::try_from(column_ordinal)
                                        .map_err(|_| RelationPlanError::CountOverflow)?,
                                )
                                .and_then(Option::as_ref)
                                .and_then(|values| values.get(rotated_position))
                                .copied()
                                .map(ProofChallengeExtensionElement::from_base)
                                .ok_or(RelationPlanError::InvalidConstraint)
                        },
                    )
                    .unwrap_or_else(|error| {
                        panic!(
                            "evaluate exact constraint {constraint_ordinal} at position {evaluation_position}: {error:?}"
                        )
                    });
                let normalized = numerator.multiply(inverse_zeroifier_values[evaluation_position]);
                quotient_evaluations[evaluation_position] = quotient_evaluations
                    [evaluation_position]
                    .add(normalized.multiply(composition_challenge));
            }

            for column_ordinal in constraint_columns {
                let column_index =
                    usize::try_from(*column_ordinal).expect("column ordinal fits usize");
                if last_constraint_by_column[column_index] == Some(constraint_ordinal) {
                    assert!(active_columns[column_index].take().is_some());
                    active_column_count -= 1;
                }
            }
            let next_constraint_ordinal = constraint_ordinal + 1;
            if next_constraint_ordinal == variant.constraint_count()
                || next_constraint_ordinal
                    .is_multiple_of(native_checkpoint::QUOTIENT_ACCUMULATOR_CHECKPOINT_INTERVAL)
            {
                store
                    .write_quotient_accumulator(
                        accumulator_binding,
                        next_constraint_ordinal,
                        &quotient_evaluations,
                    )
                    .expect("checkpoint exact quotient accumulator");
            }
        }
        assert_eq!(active_column_count, 0);
        assert!(active_columns.iter().all(Option::is_none));
        domain
            .interpolate_extension_polynomial_in_place(&mut quotient_evaluations)
            .expect("interpolate exact composed quotient");
        assert!(quotient_evaluations.len() <= QUOTIENT_EVALUATION_DOMAIN_SIZE);
        (quotient_evaluations, maximum_active_column_count)
    }

    #[test]
    #[ignore = "manual exact production-source gate"]
    fn heavy_rust_kernel_production_authenticated_same_secret_source() {
        let ProductionSameSecretEvidenceSources {
            mut sources,
            authority_handle,
        } = production_same_secret_sources().expect("production source fixture");
        let store = ExactPolynomialStore::open().expect("open exact polynomial checkpoint");
        assert_eq!(sources.relation_plan_variant.ordered_columns().len(), 2_930);
        assert_eq!(sources.relation_plan_variant.constraint_count(), 4_046);
        assert_eq!(sources.relation_plan_variant.trace_domain_size(), 16_384);
        let polynomial_commitment_variable_count = sources
            .relation_plan
            .row_code_whir_construction_plan()
            .selected_parameters()
            .polynomial_commitment_variable_count;
        let expected_evaluation_domain_size = 1_u64
            .checked_shl(
                u32::try_from(polynomial_commitment_variable_count)
                    .expect("the PCS variable count fits u32"),
            )
            .expect("the PCS evaluation domain size fits u64");
        assert_eq!(
            sources.relation_plan_variant.evaluation_domain_size(),
            expected_evaluation_domain_size
        );
        assert_eq!(sources.relation_trees.len(), 13);
        assert!(!sources.canonical_application_statement_bytes.is_empty());
        assert_ne!(sources.generation_binding_hash, [0_u8; 64]);
        assert_eq!(
            sources
                .relation_plan
                .application_statement_schema_identifier(),
            SetupKeyRelationProofFamily::SameSecret.statement_schema_identifier()
        );
        let expected_private_coin_catalog = exact_trace_private_coin_catalog_for_tree_role(
            &sources.relation_plan_variant,
            ProofTreeRole::BaseOracle,
            false,
        );
        let mut observed_private_coin_catalog = CommonProofPrivateCoinSamplingCatalog::default();
        let request_context = sources
            .source_polynomials
            .exact_same_secret_evidence_request_context();
        let reversed_column_bindings;
        let mut polynomial_digests = Vec::new();
        let mut total_coefficient_count = 0_u64;
        let mut maximum_coefficient_count = 0_usize;
        let source_replay_identity_digest;
        let catalog_digest;
        println!("exact same-secret phase: derive authenticated source polynomials");
        {
            let mut recording_private_coins = RecordingCommonProofPrivateCoinSource::new(
                &mut sources.private_coins,
                &mut observed_private_coin_catalog,
            );
            let mut cursor = CommonProofPreChallengeSourceCursor::new(
                &sources.relation_plan_variant,
                request_context,
            )
            .expect("construct production source cursor");
            reversed_column_bindings = cursor.reversed_column_bindings().to_vec();
            loop {
                let requested_column_ordinal = cursor.next_source_column_ordinal();
                match cursor
                    .next_source(
                        &sources.relation_plan_variant,
                        request_context,
                        &mut sources.source_polynomials,
                        &mut recording_private_coins,
                        SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT,
                    )
                    .unwrap_or_else(|error| {
                        panic!(
                            "derive exact production source polynomial {requested_column_ordinal:?}: {error:?}"
                        )
                    })
                {
                    CommonProofPreChallengeSourcePoll::Ready {
                        column_ordinal,
                        polynomial,
                    } => {
                        maximum_coefficient_count =
                            maximum_coefficient_count.max(polynomial.coefficient_count());
                        total_coefficient_count = total_coefficient_count
                            .checked_add(polynomial.coefficient_count() as u64)
                            .expect("source coefficient count fits u64");
                        polynomial_digests.push(
                            source_polynomial_digest(column_ordinal, &polynomial)
                                .expect("hash source polynomial"),
                        );
                        if polynomial_digests.len().is_multiple_of(128) {
                            println!(
                                "exact same-secret source progress: {} polynomials",
                                polynomial_digests.len(),
                            );
                        }
                        store
                            .write(column_ordinal, &polynomial)
                            .expect("checkpoint production source polynomial");
                    }
                    CommonProofPreChallengeSourcePoll::AuthenticatedSourceReadRequired => {
                        panic!(
                            "the browser-owned setup source unexpectedly requested host material"
                        )
                    }
                    CommonProofPreChallengeSourcePoll::Complete => break,
                }
            }
            source_replay_identity_digest = cursor
                .finish(&mut sources.source_polynomials)
                .expect("finish exact production source traversal");
            for (source_column_ordinal, reversed_column_ordinal) in &reversed_column_bindings {
                let source = store
                    .read(*source_column_ordinal)
                    .expect("replay reversed-column source");
                let reversed = construct_reversed_relation_column(
                    &sources.relation_plan_variant,
                    *source_column_ordinal,
                    *reversed_column_ordinal,
                    source,
                    &mut recording_private_coins,
                    SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT,
                )
                .expect("construct exact reversed relation column");
                store
                    .write(*reversed_column_ordinal, &reversed)
                    .expect("checkpoint reversed relation column");
            }
            let mut catalog_hasher = StreamingHash512::new(
                SOURCE_CATALOG_DIGEST_DOMAIN,
                u64::try_from(polynomial_digests.len()).expect("digest count fits u64"),
            );
            for digest in &polynomial_digests {
                catalog_hasher.absorb_part(digest);
            }
            catalog_digest = catalog_hasher.finalize();
        }
        assert_eq!(
            observed_private_coin_catalog, expected_private_coin_catalog,
            "the exact base-source generator must consume its source-derived private-coin catalog exactly"
        );
        let manifest = SourceCheckpointManifest::new(
            sources.relation_plan.relation_plan_hash(),
            sources.relation_plan.relation_plan_variant_hash(),
            sources.canonical_application_statement_bytes.clone(),
            sources.generation_binding_hash,
            source_replay_identity_digest,
            catalog_digest,
            polynomial_digests.len(),
            polynomial_digests.len() + reversed_column_bindings.len(),
            total_coefficient_count,
            maximum_coefficient_count,
        );
        store
            .write_manifest(&manifest)
            .expect("checkpoint production source manifest");
        assert_eq!(
            store
                .read_manifest()
                .expect("read production source manifest"),
            Some(manifest)
        );
        assert_ne!(catalog_digest, [0_u8; 64]);
        assert_ne!(source_replay_identity_digest, [0_u8; 64]);
        assert!(maximum_coefficient_count <= 32_768);
        println!(
            "production source polynomials: {}, coefficients: {}, maximum coefficients: {}, catalog digest: {}, replay digest: {}",
            polynomial_digests.len(),
            total_coefficient_count,
            maximum_coefficient_count,
            encode_hex(&catalog_digest),
            encode_hex(&source_replay_identity_digest),
        );
        println!("production source checkpoint: {}", store.root().display());
        release_production_same_secret_authority(authority_handle)
            .expect("release production setup authority");
    }

    #[test]
    #[ignore = "manual exact base and auxiliary phase commitment gate"]
    fn heavy_rust_kernel_exact_base_and_auxiliary_phase_commitments() {
        let ProductionSameSecretEvidenceSources {
            mut sources,
            authority_handle,
        } = production_same_secret_sources().expect("production source fixture");
        let store = ExactPolynomialStore::open().expect("open exact polynomial checkpoint");
        let source_manifest = store
            .read_manifest()
            .expect("read production source manifest")
            .expect("production source gate must run first");
        validate_checkpoint_binding(&sources, &source_manifest);
        let row_pad_seeds =
            derive_exact_row_pad_seeds(&mut sources).expect("derive exact row-pad seeds");

        let base_layout = ExactBasePhaseLayout::for_tree_role(
            &sources.relation_plan_variant,
            ProofTreeRole::BaseOracle,
        )
        .expect("derive exact base layout");
        let auxiliary_layout = ExactBasePhaseLayout::for_tree_role(
            &sources.relation_plan_variant,
            ProofTreeRole::AuxiliaryOracle,
        )
        .expect("derive exact auxiliary layout");
        assert_eq!(
            base_layout
                .rows
                .iter()
                .flat_map(|row| row.column_ordinals)
                .flatten()
                .count(),
            1_968
        );
        assert_eq!(
            auxiliary_layout
                .rows
                .iter()
                .flat_map(|row| row.column_ordinals)
                .flatten()
                .count(),
            900
        );
        assert!(base_layout.rows.iter().all(|row| {
            !row.opening_point_ordinals.is_empty()
                && row
                    .column_ordinals
                    .iter()
                    .flatten()
                    .all(|column_ordinal| store.contains(*column_ordinal))
        }));

        let base_source = CheckpointBasePhaseSource::new(&store, &base_layout);
        let base_geometry = base_layout.geometry().expect("derive base geometry");
        let base_root = commit_phase_rows(&base_source, base_geometry, &row_pad_seeds[0])
            .expect("commit exact base phase");

        let request_context = sources
            .source_polynomials
            .exact_same_secret_evidence_request_context();
        let statement_schema_identifier =
            SetupKeyRelationProofFamily::SameSecret.statement_schema_identifier();
        assert_eq!(
            request_context.application_statement_schema_identifier(),
            statement_schema_identifier
        );
        let schedule = sources
            .relation_plan_variant
            .common_proof_relation_prefix_schedule(&sources.relation_context)
            .expect("derive production transcript schedule");
        let transcript_authority = sources
            .authorization
            .exact_same_secret_transcript_prefix_authority_binding(
                &sources.canonical_application_statement_bytes,
                &sources.relation_plan,
            )
            .expect("derive exact transcript authority");
        let header = exact_transcript_header(
            transcript_authority.fiat_shamir_binding(),
            production_same_secret_prerequisite(&sources)
                .expect("construct verified VSS prerequisite")
                .binding_digest(),
        );
        let mut transcript = CommonProofTranscript::new_relation_prefix(
            request_context.protocol_version(),
            request_context.suite_identifier(),
            sources
                .relation_plan
                .row_code_whir_construction_plan_identity_hash(),
            statement_schema_identifier,
            &header,
            schedule.clone(),
        )
        .expect("construct exact relation transcript");
        absorb_exact_relation_roots(
            &mut transcript,
            schedule.ordered_base_tree_ordinals(),
            ProofTreeRole::BaseOracle,
            base_root,
            &sources.relation_plan_variant,
            &sources.relation_trees,
        )
        .expect("absorb exact base phase");
        let application_challenges =
            sample_relation_application_challenges(&mut transcript, &schedule)
                .expect("sample exact relation application challenges");

        let mut auxiliary_cursor = CommonProofAuxiliaryColumnSynthesisCursor::new(
            &sources.relation_plan_variant,
            &sources.relation_context,
            &application_challenges,
        )
        .expect("construct exact auxiliary synthesis cursor");
        let expected_private_coin_catalog = exact_trace_private_coin_catalog_for_tree_role(
            &sources.relation_plan_variant,
            ProofTreeRole::AuxiliaryOracle,
            false,
        );
        let mut observed_private_coin_catalog = CommonProofPrivateCoinSamplingCatalog::default();
        let mut auxiliary_output_count = 0_usize;
        {
            let mut recording_private_coins = RecordingCommonProofPrivateCoinSource::new(
                &mut sources.private_coins,
                &mut observed_private_coin_catalog,
            );
            while !auxiliary_cursor.is_complete() {
                if auxiliary_cursor.has_pending_output() {
                    let (column_ordinal, polynomial) = auxiliary_cursor
                        .take_next_output(
                            &sources.relation_plan_variant,
                            &mut recording_private_coins,
                            SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT,
                        )
                        .expect("construct masked exact auxiliary column")
                        .expect("pending exact auxiliary output exists");
                    store
                        .write_phase(column_ordinal, &polynomial)
                        .expect("checkpoint exact auxiliary polynomial");
                    auxiliary_output_count += 1;
                    continue;
                }
                if let Some(column_ordinal) = auxiliary_cursor.next_input_column_ordinal() {
                    auxiliary_cursor
                        .accept_input_column(
                            column_ordinal,
                            store
                                .read(column_ordinal)
                                .expect("read exact auxiliary input column"),
                        )
                        .expect("accept exact auxiliary input column");
                    continue;
                }
                assert!(
                    auxiliary_cursor
                        .advance_ready_task()
                        .expect("advance exact auxiliary synthesis task"),
                    "an incomplete exact auxiliary cursor must have a ready task"
                );
            }
        }
        assert_eq!(
            observed_private_coin_catalog, expected_private_coin_catalog,
            "the exact auxiliary generator must consume its source-derived private-coin catalog exactly"
        );
        assert_eq!(auxiliary_output_count, 900);
        assert!(auxiliary_layout.rows.iter().all(|row| {
            row.column_ordinals
                .iter()
                .flatten()
                .all(|column_ordinal| store.contains(*column_ordinal))
        }));

        let auxiliary_source = CheckpointBasePhaseSource::new(&store, &auxiliary_layout);
        let auxiliary_geometry = auxiliary_layout
            .geometry()
            .expect("derive auxiliary geometry");
        let auxiliary_root =
            commit_phase_rows(&auxiliary_source, auxiliary_geometry, &row_pad_seeds[1])
                .expect("commit exact auxiliary phase");
        absorb_exact_relation_roots(
            &mut transcript,
            schedule.ordered_auxiliary_tree_ordinals(),
            ProofTreeRole::AuxiliaryOracle,
            auxiliary_root,
            &sources.relation_plan_variant,
            &sources.relation_trees,
        )
        .expect("absorb exact auxiliary phase");

        let phase_manifest = ExactPhaseCommitmentManifest::new(
            &source_manifest,
            base_geometry.encoded_column_count,
            base_geometry.row_count,
            auxiliary_geometry.row_count,
            base_root,
            auxiliary_root,
        );
        store
            .write_phase_manifest(&phase_manifest)
            .expect("checkpoint exact phase commitments");
        assert_eq!(
            store
                .read_phase_manifest()
                .expect("read exact phase manifest"),
            Some(phase_manifest)
        );
        println!(
            "exact phase commitments: base rows {}, auxiliary rows {}, base root {}, auxiliary root {}",
            base_geometry.row_count,
            auxiliary_geometry.row_count,
            encode_hex(&column_digest_bytes(base_root)),
            encode_hex(&column_digest_bytes(auxiliary_root)),
        );
        release_production_same_secret_authority(authority_handle)
            .expect("release production setup authority");
    }

    #[test]
    #[ignore = "manual exact quotient phase gate"]
    fn heavy_rust_kernel_exact_masked_quotient_phase_commitment() {
        let started_at = Instant::now();
        let ProductionSameSecretEvidenceSources {
            mut sources,
            authority_handle,
        } = production_same_secret_sources().expect("production source fixture");
        let store = ExactPolynomialStore::open().expect("open exact polynomial checkpoint");
        let source_manifest = store
            .read_manifest()
            .expect("read production source manifest")
            .expect("production source gate must run first");
        validate_checkpoint_binding(&sources, &source_manifest);
        let phase_manifest = store
            .read_phase_manifest()
            .expect("read exact phase manifest")
            .expect("base and auxiliary phase gate must run first");
        ensure_exact_verifier_sequence_columns(&mut sources, &store);
        let (mut transcript, application_challenges, composition_challenges) =
            exact_transcript_through_composition(&sources, &phase_manifest);

        let quotient_started_at = Instant::now();
        let (composed_quotient, maximum_live_transformed_column_count) =
            construct_exact_composed_quotient(
                &sources,
                &store,
                &phase_manifest,
                &application_challenges,
                &composition_challenges,
            );
        let quotient_coefficient_count = composed_quotient.len();
        assert!(quotient_coefficient_count <= 34_813);
        assert!(maximum_live_transformed_column_count <= 117);

        let quotient_component_count =
            usize::try_from(sources.relation_context.quotient_component_count)
                .expect("quotient component count fits usize");
        assert_eq!(quotient_component_count, 8);
        let mut component_cursor = CommonProofQuotientComponentCursor::new(
            &sources.relation_plan_variant,
            &sources.relation_context,
            composed_quotient,
        )
        .expect("construct masked quotient component cursor");
        let expected_private_coin_catalog =
            exact_quotient_private_coin_catalog(&sources.relation_plan_variant);
        let mut observed_private_coin_catalog = CommonProofPrivateCoinSamplingCatalog::default();
        let mut produced_component_count = 0_usize;
        let opening_batch_mask;
        {
            let mut recording_private_coins = RecordingCommonProofPrivateCoinSource::new(
                &mut sources.private_coins,
                &mut observed_private_coin_catalog,
            );
            while let Some(component) = component_cursor
                .next_component(
                    &mut recording_private_coins,
                    SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT,
                )
                .expect("construct telescopically masked quotient component")
            {
                store
                    .write_quotient_component(
                        u16::try_from(produced_component_count)
                            .expect("quotient component ordinal fits u16"),
                        &component,
                    )
                    .expect("checkpoint masked quotient component");
                produced_component_count += 1;
            }
            opening_batch_mask = construct_opening_batch_mask(
                &sources.relation_plan_variant,
                &mut recording_private_coins,
                SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT,
            )
            .expect("construct production opening-batch mask")
            .expect("the secret-bearing exact relation requires an opening-batch mask");
        }
        assert_eq!(produced_component_count, quotient_component_count);
        assert_eq!(
            observed_private_coin_catalog, expected_private_coin_catalog,
            "the exact quotient generator must consume its source-derived private-coin catalog exactly"
        );
        store
            .write_opening_batch_mask(&opening_batch_mask)
            .expect("checkpoint production opening-batch mask");

        let quotient_source = CheckpointQuotientPhaseSource::new(&store, quotient_component_count)
            .expect("construct quotient phase source");
        assert_eq!(quotient_source.row_count(), 15);
        let quotient_geometry = RowEncodingGeometry::new_weighted_batch_with_log_inverse_rate(
            quotient_source.row_count(),
            PHYSICAL_ROW_WITNESS_VARIABLE_COUNT,
            EXACT_ROW_CODE_LOG_INVERSE_RATE,
        )
        .expect("derive quotient phase geometry");
        let quotient_root = commit_phase_rows(
            &quotient_source,
            quotient_geometry,
            &derive_exact_row_pad_seeds(&mut sources).expect("derive exact row-pad seeds")[2],
        )
        .expect("commit exact quotient phase");
        transcript
            .absorb_row_code_whir_quotient_phase_root(column_digest_bytes(quotient_root))
            .expect("absorb exact quotient phase root");

        let manifest = ExactQuotientCommitmentManifest::new(
            &source_manifest,
            quotient_geometry.encoded_column_count,
            quotient_coefficient_count,
            maximum_live_transformed_column_count,
            quotient_source.row_count(),
            quotient_root,
        );
        store
            .write_quotient_manifest(&manifest)
            .expect("checkpoint quotient commitment manifest");
        assert_eq!(
            store
                .read_quotient_manifest()
                .expect("read quotient commitment manifest"),
            Some(manifest)
        );
        println!(
            "exact quotient phase: coefficients {}, maximum live transformed columns {}, rows {}, root {}, quotient time {:?}, complete time {:?}",
            quotient_coefficient_count,
            maximum_live_transformed_column_count,
            quotient_source.row_count(),
            encode_hex(&column_digest_bytes(quotient_root)),
            quotient_started_at.elapsed(),
            started_at.elapsed(),
        );
        release_production_same_secret_authority(authority_handle)
            .expect("release production setup authority");
    }
}
