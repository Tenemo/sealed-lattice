//! Exact production-authenticated same-secret construction.
//!
//! The prover enters the browser-owned setup authority, compiles the selected
//! same-secret relation, binds a persistent proof attempt to the canonical
//! witness, and consumes the production source adapter and private proof
//! coins. Synthetic columns are not accepted by this path.

use crate::{
    bgv::{
        proof_suite::{
            CommonProofRelationPlanCapability, CommonProofTranscript, ProofTreeRole,
            SelectedApplicationStatementContext, VerifiedCommonProofStatementSource,
            VerifiedStatementOwnedTree, compile_same_secret_relation_plan,
            decode_selected_same_secret_statement, sample_relation_application_challenges,
            selected_relation_plan_check_context, selected_same_secret_relation_plan_input,
        },
        setup::{SetupKeyRelationProofFamily, VerifiedVssShareLinkageTerminal},
    },
    foundation::{Hash512, RefusalReason},
    hashing::StreamingHash512,
    hashing::hash_framed_parts_512,
};

#[cfg(all(test, not(target_arch = "wasm32")))]
use crate::{
    bgv::{
        proof_suite::{
            CommonProofAuxiliaryColumnSynthesisCursor, CommonProofPreChallengeSourceCursor,
            CommonProofPreChallengeSourcePoll, CommonProofPrivateCoinCoordinate,
            CommonProofPrivateCoinSource, CommonProofRuntimeLimits, CommonProofSourcePolynomial,
            MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH, RelationProofTreeInput,
            construct_reversed_relation_column, verified_application_statement_hash,
        },
        setup::{
            ExactSameSecretEvidenceSources, SetupGenerationKeyRelationApplication,
            populate_exact_same_secret_evidence_authority,
            resolve_setup_generation_key_relation_preparation_source,
            with_setup_generation_key_relation,
        },
    },
    foundation::{
        ProofApplicationSlot, SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT,
        prepare_exact_same_secret_evidence_attempt,
    },
};

use std::collections::BTreeMap;

#[cfg(all(test, not(target_arch = "wasm32")))]
use super::MAXIMUM_ROW_CODE_WHIR_PROOF_BYTE_LENGTH;
#[cfg(all(test, not(target_arch = "wasm32")))]
use super::protocol::{RecomputableRowSource, commit_streaming_witness};
use super::{column_commitment::ColumnDigest, row_encoding::RowEncodingGeometry};
use crate::bgv::proof_suite::relation_plan::{RelationOpeningSourceClass, RelationTreeDescriptor};

mod exact_proof;

pub(crate) use exact_proof::ExactSameSecretVerificationMetrics;
pub(super) use exact_proof::verify_exact_same_secret_proof_bytes;

#[cfg(all(test, not(target_arch = "wasm32")))]
const SOURCE_POLYNOMIAL_DIGEST_DOMAIN: &str =
    "sealed-lattice/exact-same-secret/source-polynomial/v1";
#[cfg(all(test, not(target_arch = "wasm32")))]
const SOURCE_CATALOG_DIGEST_DOMAIN: &str = "sealed-lattice/exact-same-secret/source-catalog/v1";
#[cfg(all(test, not(target_arch = "wasm32")))]
const EXACT_SAME_SECRET_EVIDENCE_REVISION: u8 = 1;
const EXACT_TRANSCRIPT_HEADER_DOMAIN: &[u8] =
    b"sealed-lattice/exact-same-secret/transcript-header/v1";
const LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT: usize = 32_768;
const PHYSICAL_ROW_WITNESS_VARIABLE_COUNT: usize = 18;
const LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW: usize = 8;
const EXACT_ROW_CODE_LOG_INVERSE_RATE: usize = 2;
const VERIFIED_SAME_SECRET_LOW_DEGREE_PREREQUISITE_DOMAIN: &str =
    "sealed-lattice/same-secret/verified-low-degree-prerequisite/v1";
#[cfg(test)]
const TEST_VERIFIED_VSS_PROOF_RESULT_DIGEST: [u8; Hash512::BYTE_LENGTH] =
    [0x76; Hash512::BYTE_LENGTH];
#[cfg(test)]
const QUOTIENT_COMPONENT_CHUNK_COUNT: usize = 2;
#[cfg(test)]
const OPENING_BATCH_MASK_CHUNK_COUNT: usize = 8;

/// Opaque authority proving that the same-secret input roots already passed
/// the selected VSS low-degree verification.
///
/// There is no decoder or byte constructor. Production code can mint this
/// capability only from a positively verified VSS linkage terminal.
pub(in crate::bgv) struct VerifiedSameSecretLowDegreePrerequisite {
    protocol_version: u16,
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    action_context_hash: [u8; Hash512::BYTE_LENGTH],
    public_setup_seed: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    roster_position: u16,
    ordered_input_roots: [[u8; Hash512::BYTE_LENGTH]; 8],
    binding_digest: [u8; Hash512::BYTE_LENGTH],
}

pub(crate) struct PreparedExactSameSecretVerification {
    prerequisite: VerifiedSameSecretLowDegreePrerequisite,
    canonical_public_input: Vec<u8>,
}

impl PreparedExactSameSecretVerification {
    pub(crate) fn verify(
        &self,
        canonical_proof: &[u8],
    ) -> Result<ExactSameSecretVerificationMetrics, String> {
        verify_exact_same_secret_proof_bytes(
            &self.prerequisite,
            &self.canonical_public_input,
            canonical_proof,
        )
    }
}

pub(crate) fn prepare_exact_same_secret_verification(
    prerequisite: VerifiedSameSecretLowDegreePrerequisite,
    statement_source: &VerifiedCommonProofStatementSource,
    statement_trees: &[VerifiedStatementOwnedTree],
) -> Result<PreparedExactSameSecretVerification, String> {
    let application_slot = statement_source
        .proof_application_binding()
        .application_slot();
    let public_input = exact_proof::ExactSameSecretPublicInput {
        protocol_version: prerequisite.protocol_version(),
        suite_identifier: application_slot.suite_identifier().into_bytes(),
        action_context_hash: application_slot.action_context_hash().into_bytes(),
        statement_schema_identifier: application_slot.application_statement_schema_identifier(),
        canonical_application_statement_bytes: statement_source
            .canonical_application_statement_bytes()
            .to_vec(),
        public_relation_trees: statement_trees
            .iter()
            .map(|tree| tree.statement_owned_tree_input().clone())
            .collect(),
    };
    let canonical_public_input = exact_proof::encode_exact_same_secret_public_input(&public_input)?;
    validate_prepared_same_secret_public_input(&prerequisite, &canonical_public_input)?;
    Ok(PreparedExactSameSecretVerification {
        prerequisite,
        canonical_public_input,
    })
}

fn validate_prepared_same_secret_public_input(
    prerequisite: &VerifiedSameSecretLowDegreePrerequisite,
    canonical_public_input: &[u8],
) -> Result<(), String> {
    let public_input = exact_proof::decode_exact_same_secret_public_input(canonical_public_input)?;
    exact_proof::validate_public_input_bindings(prerequisite, &public_input)
}

impl VerifiedSameSecretLowDegreePrerequisite {
    pub(in crate::bgv) fn from_verified_vss_share_linkage_terminal(
        terminal: &VerifiedVssShareLinkageTerminal,
    ) -> Result<Self, RefusalReason> {
        let ordered_input_roots: [[u8; Hash512::BYTE_LENGTH]; 8] = terminal
            .ordered_coefficient_material_roots()
            .try_into()
            .map_err(|_| RefusalReason::WrongTypeOrLength)?;
        let canonical_prior_proof_descriptor = terminal
            .proof_stream_descriptor()
            .encode()
            .map_err(|_| RefusalReason::WrongTypeOrLength)?;
        Self::new(
            terminal.protocol_version(),
            terminal.suite_identifier(),
            terminal.action_context_hash(),
            terminal.public_setup_seed(),
            terminal.participant_identity(),
            terminal.roster_position(),
            ordered_input_roots,
            terminal
                .proof_stream_descriptor()
                .full_object_digest
                .into_bytes(),
            &canonical_prior_proof_descriptor,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        protocol_version: u16,
        suite_identifier: [u8; Hash512::BYTE_LENGTH],
        action_context_hash: [u8; Hash512::BYTE_LENGTH],
        public_setup_seed: [u8; Hash512::BYTE_LENGTH],
        participant_identity: [u8; Hash512::BYTE_LENGTH],
        roster_position: u16,
        ordered_input_roots: [[u8; Hash512::BYTE_LENGTH]; 8],
        prior_proof_result_digest: [u8; Hash512::BYTE_LENGTH],
        canonical_prior_proof_descriptor: &[u8],
    ) -> Result<Self, RefusalReason> {
        if protocol_version == 0
            || suite_identifier == [0_u8; Hash512::BYTE_LENGTH]
            || action_context_hash == [0_u8; Hash512::BYTE_LENGTH]
            || public_setup_seed == [0_u8; Hash512::BYTE_LENGTH]
            || participant_identity == [0_u8; Hash512::BYTE_LENGTH]
            || ordered_input_roots.contains(&[0_u8; Hash512::BYTE_LENGTH])
            || prior_proof_result_digest == [0_u8; Hash512::BYTE_LENGTH]
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
                &protocol_version.to_le_bytes(),
                &suite_identifier,
                &action_context_hash,
                &public_setup_seed,
                &participant_identity,
                &roster_position.to_le_bytes(),
                &input_root_bytes,
                &row_code_parameters,
                &prior_proof_result_digest,
                canonical_prior_proof_descriptor,
            ],
        );
        Ok(Self {
            protocol_version,
            suite_identifier,
            action_context_hash,
            public_setup_seed,
            participant_identity,
            roster_position,
            ordered_input_roots,
            binding_digest,
        })
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn for_test(
        protocol_version: u16,
        suite_identifier: [u8; Hash512::BYTE_LENGTH],
        action_context_hash: [u8; Hash512::BYTE_LENGTH],
        public_setup_seed: [u8; Hash512::BYTE_LENGTH],
        participant_identity: [u8; Hash512::BYTE_LENGTH],
        roster_position: u16,
        ordered_input_roots: [[u8; Hash512::BYTE_LENGTH]; 8],
        prior_proof_result_digest: [u8; Hash512::BYTE_LENGTH],
    ) -> Result<Self, RefusalReason> {
        Self::new(
            protocol_version,
            suite_identifier,
            action_context_hash,
            public_setup_seed,
            participant_identity,
            roster_position,
            ordered_input_roots,
            prior_proof_result_digest,
            &prior_proof_result_digest,
        )
    }

    const fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    const fn suite_identifier(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.suite_identifier
    }

    const fn action_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.action_context_hash
    }

    const fn public_setup_seed(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.public_setup_seed
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
    protocol_version: u16,
    suite_identifier: [u8; 64],
    statement_schema_identifier: u16,
    relation_plan_hash: [u8; 64],
    relation_plan_variant_hash: [u8; 64],
    verified_prerequisite_binding: [u8; 64],
    canonical_application_statement_bytes: &[u8],
) -> Result<Vec<u8>, String> {
    let statement_byte_length = u64::try_from(canonical_application_statement_bytes.len())
        .map_err(|_| "application statement byte length exceeds u64".to_owned())?;
    let mut header = Vec::with_capacity(
        EXACT_TRANSCRIPT_HEADER_DOMAIN.len()
            + 2
            + 64
            + 2
            + 64
            + 64
            + 64
            + 8
            + canonical_application_statement_bytes.len(),
    );
    header.extend_from_slice(EXACT_TRANSCRIPT_HEADER_DOMAIN);
    header.extend_from_slice(&protocol_version.to_le_bytes());
    header.extend_from_slice(&suite_identifier);
    header.extend_from_slice(&statement_schema_identifier.to_le_bytes());
    header.extend_from_slice(&relation_plan_hash);
    header.extend_from_slice(&relation_plan_variant_hash);
    header.extend_from_slice(&verified_prerequisite_binding);
    header.extend_from_slice(&statement_byte_length.to_le_bytes());
    header.extend_from_slice(canonical_application_statement_bytes);
    Ok(header)
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
            _ => return Err("an unsupported relation phase root was requested".to_owned()),
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
        action_context_hash,
        public_setup_seed,
        statement.participant_identity(),
        statement.roster_position(),
        ordered_input_roots,
        TEST_VERIFIED_VSS_PROOF_RESULT_DIGEST,
    )
    .map_err(|error| format!("construct verified VSS prerequisite: {error:?}"))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
fn production_same_secret_prerequisite(
    sources: &ExactSameSecretEvidenceSources,
) -> Result<VerifiedSameSecretLowDegreePrerequisite, String> {
    let request_context = sources
        .source_polynomials
        .exact_same_secret_evidence_request_context();
    test_same_secret_low_degree_prerequisite(
        request_context.protocol_version(),
        request_context.suite_identifier(),
        sources.action_context_hash,
        sources.public_setup_seed,
        &sources.canonical_application_statement_bytes,
    )
}

#[cfg(all(test, not(target_arch = "wasm32")))]
fn production_same_secret_sources() -> Result<ExactSameSecretEvidenceSources, String> {
    let (relation_plan, _, _) = production_same_secret_relation()?;
    let authority =
        populate_exact_same_secret_evidence_authority(EXACT_SAME_SECRET_EVIDENCE_REVISION)
            .map_err(|error| format!("populate production setup authority: {error:?}"))?;
    let preparation_source = resolve_setup_generation_key_relation_preparation_source(
        &authority.authority_handle,
        SetupKeyRelationProofFamily::SameSecret,
    )
    .map_err(|error| format!("resolve production same-secret statement: {error:?}"))?;
    let statement_schema_identifier =
        SetupKeyRelationProofFamily::SameSecret.statement_schema_identifier();
    let expected_query_count = relation_plan
        .proof_query_count()
        .map_err(|error| format!("derive production relation query count: {error:?}"))?;
    let limits = CommonProofRuntimeLimits::new(
        MAXIMUM_ROW_CODE_WHIR_PROOF_BYTE_LENGTH,
        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
        MAXIMUM_ROW_CODE_WHIR_PROOF_BYTE_LENGTH as u64,
    )
    .map_err(|error| format!("construct exact backend runtime limits: {error:?}"))?;
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
        MAXIMUM_ROW_CODE_WHIR_PROOF_BYTE_LENGTH as u64,
        expected_query_count,
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
        source.prepare_exact_same_secret_evidence_sources(relation_plan, limits)
    })
    .map_err(|error| format!("prepare production same-secret sources: {error:?}"))
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
        pub(super) base_row_pad_seed: Vec<u8>,
        pub(super) auxiliary_row_pad_seed: Vec<u8>,
        pub(super) quotient_row_pad_seed: Vec<u8>,
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
            row_pad_seeds: [[u8; 32]; 3],
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
                base_row_pad_seed: row_pad_seeds[0].to_vec(),
                auxiliary_row_pad_seed: row_pad_seeds[1].to_vec(),
                quotient_row_pad_seed: row_pad_seeds[2].to_vec(),
            }
        }

        pub(super) fn row_pad_seeds(&self) -> Result<[[u8; 32]; 3], String> {
            Ok([
                self.base_row_pad_seed
                    .as_slice()
                    .try_into()
                    .map_err(|_| "base row-pad seed has the wrong length".to_owned())?,
                self.auxiliary_row_pad_seed
                    .as_slice()
                    .try_into()
                    .map_err(|_| "auxiliary row-pad seed has the wrong length".to_owned())?,
                self.quotient_row_pad_seed
                    .as_slice()
                    .try_into()
                    .map_err(|_| "quotient row-pad seed has the wrong length".to_owned())?,
            ])
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
            let root = PathBuf::from("temp")
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
            if quotient_component_count != LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW {
                return Err(format!(
                    "quotient component count {quotient_component_count} does not fill the exact eight-block row"
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
                    LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT * OPENING_BATCH_MASK_CHUNK_COUNT;
                if polynomial.len() > maximum_coefficient_count {
                    return Err(format!(
                        "quotient phase polynomial has {} coefficients, exceeding {}",
                        polynomial.len(),
                        maximum_coefficient_count
                    ));
                }
                for chunk_ordinal in 0..OPENING_BATCH_MASK_CHUNK_COUNT {
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
    };
    use super::*;
    use crate::bgv::proof_suite::{
        CommonProofQuotientComponentCursor, ProofBaseFieldElement, ProofChallengeExtensionElement,
        ProofEvaluationDomain, RelationPlanError, construct_opening_batch_mask,
    };
    use crate::transcript_core::encode_hex;

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

    fn validate_checkpoint_binding(
        sources: &ExactSameSecretEvidenceSources,
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
        sources: &ExactSameSecretEvidenceSources,
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
            .common_proof_transcript_schedule(&sources.relation_context)
            .expect("derive production transcript schedule");
        let header = exact_transcript_header(
            request_context.protocol_version(),
            request_context.suite_identifier(),
            statement_schema_identifier,
            sources.relation_plan.relation_plan_hash(),
            sources.relation_plan.relation_plan_variant_hash(),
            production_same_secret_prerequisite(sources)
                .expect("construct verified VSS prerequisite")
                .binding_digest(),
            &sources.canonical_application_statement_bytes,
        )
        .expect("derive exact transcript header");
        let mut transcript = CommonProofTranscript::new(
            request_context.protocol_version(),
            request_context.suite_identifier(),
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
        sources: &mut ExactSameSecretEvidenceSources,
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
        sources: &ExactSameSecretEvidenceSources,
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
        eprintln!(
            "exact quotient zeroifier classes: {} for {} constraints",
            inverse_zeroifier_evaluations.len(),
            variant.constraint_count()
        );
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
        eprintln!(
            "exact quotient resumes at constraint {first_constraint_ordinal}/{}",
            variant.constraint_count()
        );
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
                eprintln!(
                    "exact quotient checkpoint: constraints {next_constraint_ordinal}/{}",
                    variant.constraint_count()
                );
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
        let mut sources = production_same_secret_sources().expect("production source fixture");
        let store = ExactPolynomialStore::open().expect("open exact polynomial checkpoint");
        assert_eq!(sources.relation_plan_variant.ordered_columns().len(), 3_110);
        assert_eq!(sources.relation_plan_variant.constraint_count(), 4_406);
        assert_eq!(sources.relation_plan_variant.trace_domain_size(), 16_384);
        assert_eq!(
            sources.relation_plan_variant.evaluation_domain_size(),
            2_097_152
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

        let request_context = sources
            .source_polynomials
            .exact_same_secret_evidence_request_context();
        let mut cursor = CommonProofPreChallengeSourceCursor::new(
            &sources.relation_plan_variant,
            request_context,
        )
        .expect("construct production source cursor");
        let reversed_column_bindings = cursor.reversed_column_bindings().to_vec();
        let mut polynomial_digests = Vec::new();
        let mut total_coefficient_count = 0_u64;
        let mut maximum_coefficient_count = 0_usize;
        loop {
            let requested_column_ordinal = cursor.next_source_column_ordinal();
            match cursor
                .next_source(
                    &sources.relation_plan_variant,
                    request_context,
                    &mut sources.source_polynomials,
                    &mut sources.private_coins,
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
                    store
                        .write(column_ordinal, &polynomial)
                        .expect("checkpoint production source polynomial");
                }
                CommonProofPreChallengeSourcePoll::AuthenticatedSourceReadRequired => {
                    panic!("the browser-owned setup source unexpectedly requested host material")
                }
                CommonProofPreChallengeSourcePoll::Complete => break,
            }
        }
        let source_replay_identity_digest = cursor
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
                &mut sources.private_coins,
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
        let catalog_digest = catalog_hasher.finalize();
        let mut row_pad_seed_bytes = [0_u8; 96];
        sources
            .private_coins
            .fill_raw_bytes(
                CommonProofPrivateCoinCoordinate::proof_salt(),
                &mut row_pad_seed_bytes,
            )
            .expect("derive production-private row-pad seeds");
        let row_pad_seeds = [
            row_pad_seed_bytes[0..32]
                .try_into()
                .expect("fixed seed slice"),
            row_pad_seed_bytes[32..64]
                .try_into()
                .expect("fixed seed slice"),
            row_pad_seed_bytes[64..96]
                .try_into()
                .expect("fixed seed slice"),
        ];
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
            row_pad_seeds,
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
    }

    #[test]
    #[ignore = "manual exact base and auxiliary phase commitment gate"]
    fn heavy_rust_kernel_exact_base_and_auxiliary_phase_commitments() {
        let mut sources = production_same_secret_sources().expect("production source fixture");
        let store = ExactPolynomialStore::open().expect("open exact polynomial checkpoint");
        let source_manifest = store
            .read_manifest()
            .expect("read production source manifest")
            .expect("production source gate must run first");
        validate_checkpoint_binding(&sources, &source_manifest);
        let row_pad_seeds = source_manifest
            .row_pad_seeds()
            .expect("read exact row-pad seeds");

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
            1_080
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
        let base_root = commit_streaming_witness(&base_source, base_geometry, &row_pad_seeds[0])
            .expect("commit exact base phase")
            .column_root;

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
            .common_proof_transcript_schedule(&sources.relation_context)
            .expect("derive production transcript schedule");
        let header = exact_transcript_header(
            request_context.protocol_version(),
            request_context.suite_identifier(),
            statement_schema_identifier,
            sources.relation_plan.relation_plan_hash(),
            sources.relation_plan.relation_plan_variant_hash(),
            production_same_secret_prerequisite(&sources)
                .expect("construct verified VSS prerequisite")
                .binding_digest(),
            &sources.canonical_application_statement_bytes,
        )
        .expect("derive exact transcript header");
        let mut transcript = CommonProofTranscript::new(
            request_context.protocol_version(),
            request_context.suite_identifier(),
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
        let mut auxiliary_output_count = 0_usize;
        while !auxiliary_cursor.is_complete() {
            if auxiliary_cursor.has_pending_output() {
                let (column_ordinal, polynomial) = auxiliary_cursor
                    .take_next_output(
                        &sources.relation_plan_variant,
                        &mut sources.private_coins,
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
        assert_eq!(auxiliary_output_count, 1_080);
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
            commit_streaming_witness(&auxiliary_source, auxiliary_geometry, &row_pad_seeds[1])
                .expect("commit exact auxiliary phase")
                .column_root;
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
    }

    #[test]
    #[ignore = "manual exact quotient phase gate"]
    fn heavy_rust_kernel_exact_masked_quotient_phase_commitment() {
        let started_at = Instant::now();
        let mut sources = production_same_secret_sources().expect("production source fixture");
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
        let mut produced_component_count = 0_usize;
        while let Some(component) = component_cursor
            .next_component(
                &mut sources.private_coins,
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
        assert_eq!(produced_component_count, quotient_component_count);
        let opening_batch_mask = construct_opening_batch_mask(
            &sources.relation_plan_variant,
            &mut sources.private_coins,
            SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT,
        )
        .expect("construct production opening-batch mask")
        .expect("the secret-bearing exact relation requires an opening-batch mask");
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
        let quotient_root = commit_streaming_witness(
            &quotient_source,
            quotient_geometry,
            &source_manifest
                .row_pad_seeds()
                .expect("read exact row-pad seeds")[2],
        )
        .expect("commit exact quotient phase")
        .column_root;
        for component_ordinal in 0..sources.relation_context.quotient_component_count {
            transcript
                .absorb_quotient_root(
                    u16::try_from(component_ordinal).expect("quotient component ordinal fits u16"),
                    column_digest_bytes(quotient_root),
                )
                .expect("absorb exact quotient root");
        }

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
    }
}
