//! Independent native evidence for production setup sources and witnesses.
//!
//! This module deliberately does not call a proof generator, proof verifier,
//! relation column evaluator, or compact assignment builder. It snapshots the
//! canonical production authorities and recomputes their complete arithmetic
//! with small, direct test-only routines. The resulting certificate is
//! development evidence only and cannot mint a runtime capability.

use crate::{
    bgv::{
        proof_suite::{
            CommittedMaterialContext, CommittedMaterialProfile, CommittedMaterialRole,
            PROOF_BASE_FIELD_MODULUS, ProofBaseFieldElement, ProofEvaluationDomain,
            SelectedApplicationStatementContext, SetupPublicPolynomialContext,
            SetupPublicPolynomialTree, SuiteModulusReference, compile_same_secret_relation_plan,
            compile_vss_share_linkage_relation_plan, decode_selected_same_secret_statement,
            decode_selected_vss_share_linkage_statement, selected_committed_material_profile,
            selected_committed_material_relation_plan_input, selected_proof_profile_set,
            selected_relation_plan_check_context, selected_same_secret_relation_plan_input,
            verified_application_statement_hash,
        },
        setup::{
            SetupGeneratedCommittedMaterial, SetupGenerationAnchorOpening,
            SetupGenerationKeyRelationApplication, SetupGenerationKeyRelationSource,
            SetupGenerationVssApplication, SetupGenerationVssSource, SetupKeyRelationProofFamily,
            populate_exact_same_secret_evidence_authority, release_setup_generation_authority,
            resolve_setup_generation_key_relation_preparation_source,
            resolve_setup_generation_vss_preparation_source, setup_commitment_matrix_polynomial,
            with_setup_generation_key_relation,
            with_setup_generation_vss_material_for_exact_same_secret_evidence,
        },
    },
    foundation::{
        Hash512, ProofApplicationSlot, ProofApplicationSlotCeilings,
        SELECTED_MAXIMUM_BALLOT_ATTEMPTS_PER_PARTICIPANT,
        prepare_exact_same_secret_evidence_attempt,
    },
    transcript_core::encode_hex,
};

use super::interpreter::checked_relation_compiler_interpreter_semantics;
use super::{RelationPlanCheckContext, RelationPlanVariant};

const SELECTED_SOURCE_ORACLE_EVIDENCE_REVISION: u8 = 4;
const VSS_SOURCE_ORACLE_LINEAGE_IDENTIFIER: [u8; 32] = [0x51; 32];
const SAME_SECRET_SOURCE_ORACLE_LINEAGE_IDENTIFIER: [u8; 32] = [0x52; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OracleRelation {
    VssShareLinkage,
    SameSecret,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OracleSourceCategory {
    CoefficientMaterial,
    RecipientShareMaterial,
    DegreeZeroMaterial,
    AnchorCommitment,
    AnchorHidingSecret,
    AnchorHidingError,
    PublicMatrix,
    CommonSecret,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OracleBindingField {
    CanonicalStatement,
    ProtocolVersion,
    SuiteIdentifier,
    CeremonyContext,
    ActionContext,
    Roster,
    SetupProofContext,
    PublicSetupSeed,
    ParticipantIdentity,
    RosterPosition,
    ApplicationSlot,
    ApplicationStatementHash,
    AttemptIdentifier,
    ProofProfile,
    RelationVariant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OracleSourceField {
    CatalogLength,
    CatalogOrder,
    Profile,
    ContextHash,
    Root,
    CanonicalModulus,
    CanonicalLength,
    CanonicalValue,
    PublicPolynomialContext,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum OracleDivergence {
    Binding {
        relation: OracleRelation,
        field: OracleBindingField,
    },
    CompilerSegment {
        relation: OracleRelation,
        segment_ordinal: usize,
    },
    Source {
        relation: OracleRelation,
        category: OracleSourceCategory,
        source_ordinal: usize,
        field: OracleSourceField,
    },
    Coefficient {
        relation: OracleRelation,
        category: OracleSourceCategory,
        source_ordinal: usize,
        coefficient_ordinal: usize,
    },
}

#[derive(Clone)]
struct MaterialSnapshot {
    profile: CommittedMaterialProfile,
    material_context_hash: [u8; 64],
    root: [u8; 64],
    canonical_modulus: u64,
    canonical_message: Vec<u64>,
}

impl MaterialSnapshot {
    fn from_production(material: &SetupGeneratedCommittedMaterial) -> Self {
        let authenticated = material.owned_authenticated_source();
        let compact = authenticated.compact_source();
        Self {
            profile: compact.profile(),
            material_context_hash: compact.material_context_hash(),
            root: compact.root(),
            canonical_modulus: authenticated.canonical_modulus(),
            canonical_message: authenticated.canonical_message().to_vec(),
        }
    }
}

#[derive(Clone)]
struct AnchorSnapshot {
    commitment_data_prime_index: u16,
    canonical_commitment_bytes: Vec<u8>,
    public_polynomial_context_hash: [u8; 64],
    root: [u8; 64],
    source_polynomial_degree_bound_exclusive: usize,
    commitment_rows: Vec<Vec<i128>>,
    hiding_secret_polynomials: Vec<Vec<i8>>,
    hiding_error_polynomials: Vec<Vec<i8>>,
}

impl AnchorSnapshot {
    fn from_production(
        anchor: &SetupGenerationAnchorOpening,
        commitment_module_rank: usize,
    ) -> Result<Self, String> {
        let commitment_rows = (0..=commitment_module_rank)
            .map(|row_ordinal| {
                anchor
                    .commitment_row(row_ordinal)
                    .map_err(|error| format!("decode anchor row {row_ordinal}: {error:?}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            commitment_data_prime_index: anchor.commitment_data_prime_index(),
            canonical_commitment_bytes: anchor.canonical_commitment_bytes().to_vec(),
            public_polynomial_context_hash: anchor.public_polynomial_context_hash(),
            root: anchor.root(),
            source_polynomial_degree_bound_exclusive: anchor
                .source_polynomial_degree_bound_exclusive(),
            commitment_rows,
            hiding_secret_polynomials: anchor
                .hiding_secret_polynomials()
                .iter()
                .map(|polynomial| polynomial.to_vec())
                .collect(),
            hiding_error_polynomials: anchor
                .hiding_error_polynomials()
                .iter()
                .map(|polynomial| polynomial.to_vec())
                .collect(),
        })
    }
}

#[derive(Clone)]
struct CompilerSnapshot {
    expected_variant_hash: [u8; 64],
    observed_variant_hash: [u8; 64],
    expected_segments: Vec<Vec<u8>>,
    observed_segments: Vec<Vec<u8>>,
}

impl CompilerSnapshot {
    fn from_variant(variant: &RelationPlanVariant) -> Result<Self, String> {
        let expected_variant_hash = variant
            .canonical_hash()
            .map_err(|error| format!("hash selected relation variant: {error:?}"))?;
        let expected_segments = variant
            .ordered_constraints
            .iter()
            .enumerate()
            .map(|(segment_ordinal, constraint)| {
                constraint
                    .canonical_tuple()
                    .and_then(|tuple| {
                        tuple
                            .encode()
                            .map_err(|_| super::RelationPlanError::CanonicalEncoding)
                    })
                    .map_err(|error| {
                        format!("encode compiler segment {segment_ordinal}: {error:?}")
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            expected_variant_hash,
            observed_variant_hash: expected_variant_hash,
            observed_segments: expected_segments.clone(),
            expected_segments,
        })
    }

    fn validate(&self, relation: OracleRelation) -> Result<(), OracleDivergence> {
        if self.observed_variant_hash != self.expected_variant_hash {
            return Err(OracleDivergence::Binding {
                relation,
                field: OracleBindingField::RelationVariant,
            });
        }
        if self.observed_segments.len() != self.expected_segments.len() {
            return Err(OracleDivergence::CompilerSegment {
                relation,
                segment_ordinal: self
                    .observed_segments
                    .len()
                    .min(self.expected_segments.len()),
            });
        }
        for (segment_ordinal, (observed, expected)) in self
            .observed_segments
            .iter()
            .zip(&self.expected_segments)
            .enumerate()
        {
            if observed != expected {
                return Err(OracleDivergence::CompilerSegment {
                    relation,
                    segment_ordinal,
                });
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
struct AttemptBindingSnapshot {
    expected_application_slot: ProofApplicationSlot,
    observed_application_slot: ProofApplicationSlot,
    expected_application_statement_hash: [u8; 64],
    observed_application_statement_hash: [u8; 64],
    expected_attempt_identifier: [u8; 32],
    observed_attempt_identifier: [u8; 32],
}

#[derive(Clone, Copy)]
struct ExpectedAttemptBinding {
    application_slot: ProofApplicationSlot,
    application_statement_hash: [u8; 64],
    attempt_identifier: [u8; 32],
}

#[derive(Clone, Copy)]
struct ExpectedMaterialShape {
    profile: CommittedMaterialProfile,
    context_hash: [u8; 64],
    root: [u8; 64],
    canonical_modulus: u64,
    ring_degree: usize,
}

#[derive(Clone)]
struct VssSnapshot {
    protocol_version: u16,
    observed_protocol_version: u16,
    suite_identifier: [u8; 64],
    observed_suite_identifier: [u8; 64],
    ceremony_context_hash: [u8; 64],
    action_context_hash: [u8; 64],
    roster_hash: [u8; 64],
    public_setup_seed: [u8; 64],
    participant_identity: [u8; 64],
    roster_position: u16,
    expected_canonical_statement_bytes: Vec<u8>,
    observed_canonical_statement_bytes: Vec<u8>,
    proof_profile_bytes: Vec<u8>,
    observed_proof_profile_bytes: Vec<u8>,
    attempt: AttemptBindingSnapshot,
    compiler: CompilerSnapshot,
    coefficient_materials: Vec<MaterialSnapshot>,
    recipient_share_materials: Vec<MaterialSnapshot>,
}

#[derive(Clone)]
struct SameSecretSnapshot {
    protocol_version: u16,
    observed_protocol_version: u16,
    suite_identifier: [u8; 64],
    observed_suite_identifier: [u8; 64],
    ceremony_context_hash: [u8; 64],
    observed_ceremony_context_hash: [u8; 64],
    action_context_hash: [u8; 64],
    observed_action_context_hash: [u8; 64],
    roster_hash: [u8; 64],
    observed_roster_hash: [u8; 64],
    setup_proof_context_hash: [u8; 64],
    observed_setup_proof_context_hash: [u8; 64],
    participant_identity: [u8; 64],
    observed_participant_identity: [u8; 64],
    roster_position: u16,
    observed_roster_position: u16,
    public_setup_seed: [u8; 64],
    observed_public_setup_seed: [u8; 64],
    public_matrix_seed: [u8; 64],
    expected_canonical_statement_bytes: Vec<u8>,
    observed_canonical_statement_bytes: Vec<u8>,
    proof_profile_bytes: Vec<u8>,
    observed_proof_profile_bytes: Vec<u8>,
    attempt: AttemptBindingSnapshot,
    compiler: CompilerSnapshot,
    common_secret_coefficients: Vec<i8>,
    degree_zero_materials: Vec<MaterialSnapshot>,
    anchor_openings: Vec<AnchorSnapshot>,
}

#[derive(Clone)]
struct ProductionSourceWitnessSnapshot {
    vss: VssSnapshot,
    same_secret: SameSecretSnapshot,
    vss_context: RelationPlanCheckContext,
    same_secret_context: RelationPlanCheckContext,
}

#[derive(Debug)]
enum SnapshotCollectionError {
    Refusal(crate::foundation::RefusalReason),
    Message(String),
}

impl From<crate::foundation::RefusalReason> for SnapshotCollectionError {
    fn from(error: crate::foundation::RefusalReason) -> Self {
        Self::Refusal(error)
    }
}

impl core::fmt::Display for SnapshotCollectionError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Refusal(reason) => write!(formatter, "production authority refused: {reason:?}"),
            Self::Message(message) => formatter.write_str(message),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProductionSourceWitnessOracleCertificate {
    vss_compiler_constraint_count: usize,
    same_secret_compiler_constraint_count: usize,
    coefficient_material_count: usize,
    recipient_share_material_count: usize,
    degree_zero_material_count: usize,
    anchor_count: usize,
    vss_coefficient_evaluation_count: u64,
    degree_zero_coefficient_evaluation_count: u64,
    anchor_coefficient_evaluation_count: u64,
}

fn proof_profile_bytes() -> Result<Vec<u8>, String> {
    selected_proof_profile_set(SELECTED_MAXIMUM_BALLOT_ATTEMPTS_PER_PARTICIPANT)
        .map_err(|error| format!("derive selected proof profile: {error:?}"))?
        .canonical_bytes()
        .map_err(|error| format!("encode selected proof profile: {error:?}"))
}

fn application_slot(
    suite_identifier: [u8; 64],
    ceremony_context_hash: [u8; 64],
    action_context_hash: [u8; 64],
    statement_schema_identifier: u16,
    roster_position: u16,
) -> Result<ProofApplicationSlot, String> {
    ProofApplicationSlot::new(
        Hash512::from_bytes(suite_identifier),
        Hash512::from_bytes(ceremony_context_hash),
        Hash512::from_bytes(action_context_hash),
        statement_schema_identifier,
        Some(roster_position),
        None,
        None,
    )
    .map_err(|error| format!("construct source-oracle application slot: {error:?}"))
}

fn collect_production_snapshot() -> Result<ProductionSourceWitnessSnapshot, String> {
    let authority = populate_exact_same_secret_evidence_authority(
        SELECTED_SOURCE_ORACLE_EVIDENCE_REVISION,
        true,
    )?;
    let result = collect_production_snapshot_from_authority(
        &authority.authority_handle,
        &authority.action_private_randomness,
    );
    let release_result = release_setup_generation_authority(authority.authority_handle)
        .map_err(|error| format!("release source-oracle setup authority: {error:?}"));
    match (result, release_result) {
        (Ok(snapshot), Ok(())) => Ok(snapshot),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(collection_error), Err(release_error)) => Err(format!(
            "{collection_error}; additionally failed to release authority: {release_error}"
        )),
    }
}

fn collect_production_snapshot_from_authority(
    authority_handle: &crate::bgv::setup::SetupGenerationAuthorityHandle,
    action_private_randomness: &crate::foundation::ActionPrivateRandomness,
) -> Result<ProductionSourceWitnessSnapshot, String> {
    let proof_profile_bytes = proof_profile_bytes()?;
    let vss_input = selected_committed_material_relation_plan_input()
        .map_err(|error| format!("derive selected VSS relation input: {error:?}"))?;
    let vss_context = selected_relation_plan_check_context(
        ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
    )
    .ok_or_else(|| "selected VSS relation context is unavailable".to_owned())?;
    let compiled_vss = compile_vss_share_linkage_relation_plan(&vss_input, &vss_context)
        .map_err(|error| format!("compile selected VSS relation: {error:?}"))?;
    let vss_variant = compiled_vss
        .select_variant(None, None)
        .map_err(|error| format!("select VSS relation variant: {error:?}"))?;
    let vss_compiler = CompilerSnapshot::from_variant(vss_variant)?;
    checked_relation_compiler_interpreter_semantics(vss_variant, &vss_context)
        .map_err(|error| format!("independently interpret selected VSS compiler: {error:?}"))?;

    let vss_preparation = resolve_setup_generation_vss_preparation_source(authority_handle)
        .map_err(|error| format!("resolve production VSS source: {error:?}"))?;
    let vss_statement_bytes = vss_preparation
        .canonical_application_statement_bytes()
        .to_vec();
    let vss_statement_hash = verified_application_statement_hash(
        vss_preparation.protocol_version(),
        vss_preparation.suite_identifier(),
        ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
        &vss_statement_bytes,
    );
    let vss_slot = application_slot(
        vss_preparation.suite_identifier(),
        vss_preparation.ceremony_context_hash(),
        vss_preparation.action_context_hash(),
        ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
        vss_preparation.roster_position(),
    )?;
    let vss_attempt = prepare_exact_same_secret_evidence_attempt(
        action_private_randomness,
        vss_slot,
        Hash512::from_bytes(vss_statement_hash),
        VSS_SOURCE_ORACLE_LINEAGE_IDENTIFIER,
        Hash512::from_bytes(vss_compiler.expected_variant_hash),
    )
    .map_err(|error| format!("bind source-oracle VSS attempt: {error:?}"))?;
    let expected_vss_attempt = ExpectedAttemptBinding {
        application_slot: vss_slot,
        application_statement_hash: vss_statement_hash,
        attempt_identifier: vss_attempt.attempt_identifier(),
    };
    let decoded_vss = decode_selected_vss_share_linkage_statement(
        &vss_statement_bytes,
        SelectedApplicationStatementContext::new(
            vss_preparation.protocol_version(),
            vss_preparation.suite_identifier(),
            None,
            None,
        ),
    )
    .map_err(|error| format!("decode production VSS statement: {error:?}"))?;
    let vss_application = SetupGenerationVssApplication::from_decoded_statement(
        vss_attempt,
        &vss_statement_bytes,
        &decoded_vss,
    );
    let vss = with_setup_generation_vss_material_for_exact_same_secret_evidence(
        authority_handle,
        &vss_application,
        |source| {
            collect_vss_snapshot(
                source,
                &vss_preparation,
                vss_compiler,
                proof_profile_bytes.clone(),
                expected_vss_attempt,
            )
            .map_err(SnapshotCollectionError::Message)
        },
    )
    .map_err(|error| format!("snapshot production VSS source: {error}"))?;

    let same_secret_input = selected_same_secret_relation_plan_input()
        .map_err(|error| format!("derive selected same-secret relation input: {error:?}"))?;
    let statement_schema_identifier =
        SetupKeyRelationProofFamily::SameSecret.statement_schema_identifier();
    let same_secret_context = selected_relation_plan_check_context(statement_schema_identifier)
        .ok_or_else(|| "selected same-secret relation context is unavailable".to_owned())?;
    let compiled_same_secret =
        compile_same_secret_relation_plan(&same_secret_input, &same_secret_context)
            .map_err(|error| format!("compile selected same-secret relation: {error:?}"))?;
    let same_secret_variant = compiled_same_secret
        .select_variant(None, None)
        .map_err(|error| format!("select same-secret relation variant: {error:?}"))?;
    let same_secret_compiler = CompilerSnapshot::from_variant(same_secret_variant)?;
    checked_relation_compiler_interpreter_semantics(same_secret_variant, &same_secret_context)
        .map_err(|error| {
            format!("independently interpret selected same-secret compiler: {error:?}")
        })?;

    let same_secret_preparation = resolve_setup_generation_key_relation_preparation_source(
        authority_handle,
        SetupKeyRelationProofFamily::SameSecret,
    )
    .map_err(|error| format!("resolve production same-secret source: {error:?}"))?;
    let same_secret_statement_bytes = same_secret_preparation
        .canonical_application_statement_bytes()
        .to_vec();
    let same_secret_statement_hash = verified_application_statement_hash(
        same_secret_preparation.protocol_version(),
        same_secret_preparation.suite_identifier(),
        statement_schema_identifier,
        &same_secret_statement_bytes,
    );
    let same_secret_slot = application_slot(
        same_secret_preparation.suite_identifier(),
        same_secret_preparation.ceremony_context_hash(),
        same_secret_preparation.action_context_hash(),
        statement_schema_identifier,
        same_secret_preparation.roster_position(),
    )?;
    let same_secret_attempt = prepare_exact_same_secret_evidence_attempt(
        action_private_randomness,
        same_secret_slot,
        Hash512::from_bytes(same_secret_statement_hash),
        SAME_SECRET_SOURCE_ORACLE_LINEAGE_IDENTIFIER,
        Hash512::from_bytes(same_secret_compiler.expected_variant_hash),
    )
    .map_err(|error| format!("bind source-oracle same-secret attempt: {error:?}"))?;
    let expected_same_secret_attempt = ExpectedAttemptBinding {
        application_slot: same_secret_slot,
        application_statement_hash: same_secret_statement_hash,
        attempt_identifier: same_secret_attempt.attempt_identifier(),
    };
    let decoded_same_secret = decode_selected_same_secret_statement(
        &same_secret_statement_bytes,
        SelectedApplicationStatementContext::new(
            same_secret_preparation.protocol_version(),
            same_secret_preparation.suite_identifier(),
            None,
            None,
        ),
    )
    .map_err(|error| format!("decode production same-secret statement: {error:?}"))?;
    let same_secret_application = SetupGenerationKeyRelationApplication::from_runtime_binding(
        SetupKeyRelationProofFamily::SameSecret,
        same_secret_attempt,
        &same_secret_statement_bytes,
        decoded_same_secret.setup_proof_context_hash(),
        same_secret_preparation.roster_hash(),
        same_secret_preparation.participant_identity(),
        same_secret_preparation.roster_position(),
    );
    let same_secret =
        with_setup_generation_key_relation(authority_handle, &same_secret_application, |source| {
            collect_same_secret_snapshot(
                source,
                &same_secret_preparation,
                same_secret_compiler,
                proof_profile_bytes,
                usize::from(same_secret_input.commitment_module_rank),
                expected_same_secret_attempt,
            )
            .map_err(SnapshotCollectionError::Message)
        })
        .map_err(|error| format!("snapshot production same-secret source: {error}"))?;

    Ok(ProductionSourceWitnessSnapshot {
        vss,
        same_secret,
        vss_context,
        same_secret_context,
    })
}

fn collect_vss_snapshot(
    source: SetupGenerationVssSource<'_, '_>,
    preparation: &crate::bgv::setup::SetupGenerationVssPreparationSource,
    compiler: CompilerSnapshot,
    proof_profile_bytes: Vec<u8>,
    expected_attempt: ExpectedAttemptBinding,
) -> Result<VssSnapshot, String> {
    let prepared_attempt = source.prepared_attempt();
    Ok(VssSnapshot {
        protocol_version: preparation.protocol_version(),
        observed_protocol_version: source.protocol_version(),
        suite_identifier: preparation.suite_identifier(),
        observed_suite_identifier: source.suite_identifier(),
        ceremony_context_hash: preparation.ceremony_context_hash(),
        action_context_hash: preparation.action_context_hash(),
        roster_hash: preparation.roster_hash(),
        public_setup_seed: preparation.public_setup_seed(),
        participant_identity: preparation.participant_identity(),
        roster_position: preparation.roster_position(),
        expected_canonical_statement_bytes: preparation
            .canonical_application_statement_bytes()
            .to_vec(),
        observed_canonical_statement_bytes: source.canonical_application_statement_bytes().to_vec(),
        observed_proof_profile_bytes: proof_profile_bytes.clone(),
        proof_profile_bytes,
        attempt: AttemptBindingSnapshot {
            expected_application_slot: expected_attempt.application_slot,
            observed_application_slot: prepared_attempt.application_slot(),
            expected_application_statement_hash: expected_attempt.application_statement_hash,
            observed_application_statement_hash: prepared_attempt
                .application_statement_hash()
                .into_bytes(),
            expected_attempt_identifier: expected_attempt.attempt_identifier,
            observed_attempt_identifier: prepared_attempt.attempt_identifier(),
        },
        compiler,
        coefficient_materials: source
            .ordered_coefficient_materials()
            .iter()
            .map(MaterialSnapshot::from_production)
            .collect(),
        recipient_share_materials: source
            .ordered_recipient_share_materials()
            .iter()
            .map(MaterialSnapshot::from_production)
            .collect(),
    })
}

fn collect_same_secret_snapshot(
    source: SetupGenerationKeyRelationSource<'_, '_>,
    preparation: &crate::bgv::setup::SetupGenerationKeyRelationPreparationSource,
    compiler: CompilerSnapshot,
    proof_profile_bytes: Vec<u8>,
    commitment_module_rank: usize,
    expected_attempt: ExpectedAttemptBinding,
) -> Result<SameSecretSnapshot, String> {
    let prepared_attempt = source.prepared_attempt();
    let degree_zero_materials = (0..selected_same_secret_relation_plan_input()
        .map_err(|error| format!("derive degree-zero source count: {error:?}"))?
        .sharing_data_modulus_indices
        .len())
        .map(|material_ordinal| {
            source
                .degree_zero_material(material_ordinal)
                .map(MaterialSnapshot::from_production)
                .map_err(|error| {
                    format!("snapshot degree-zero source {material_ordinal}: {error:?}")
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let anchor_openings = source
        .anchor_openings()
        .iter()
        .map(|anchor| AnchorSnapshot::from_production(anchor, commitment_module_rank))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(SameSecretSnapshot {
        protocol_version: preparation.protocol_version(),
        observed_protocol_version: source.protocol_version(),
        suite_identifier: preparation.suite_identifier(),
        observed_suite_identifier: source.suite_identifier(),
        ceremony_context_hash: preparation.ceremony_context_hash(),
        observed_ceremony_context_hash: preparation.ceremony_context_hash(),
        action_context_hash: preparation.action_context_hash(),
        observed_action_context_hash: source.action_context_hash(),
        roster_hash: preparation.roster_hash(),
        observed_roster_hash: source.roster_hash(),
        setup_proof_context_hash: preparation.setup_proof_context_hash(),
        observed_setup_proof_context_hash: source.setup_proof_context_hash(),
        participant_identity: preparation.participant_identity(),
        observed_participant_identity: source.participant_identity(),
        roster_position: preparation.roster_position(),
        observed_roster_position: source.roster_position(),
        public_setup_seed: preparation.public_setup_seed(),
        observed_public_setup_seed: source.public_setup_seed(),
        public_matrix_seed: source.public_setup_seed(),
        expected_canonical_statement_bytes: preparation
            .canonical_application_statement_bytes()
            .to_vec(),
        observed_canonical_statement_bytes: source.canonical_application_statement_bytes().to_vec(),
        observed_proof_profile_bytes: proof_profile_bytes.clone(),
        proof_profile_bytes,
        attempt: AttemptBindingSnapshot {
            expected_application_slot: expected_attempt.application_slot,
            observed_application_slot: prepared_attempt.application_slot(),
            expected_application_statement_hash: expected_attempt.application_statement_hash,
            observed_application_statement_hash: prepared_attempt
                .application_statement_hash()
                .into_bytes(),
            expected_attempt_identifier: expected_attempt.attempt_identifier,
            observed_attempt_identifier: prepared_attempt.attempt_identifier(),
        },
        compiler,
        common_secret_coefficients: source.common_secret_coefficients().to_vec(),
        degree_zero_materials,
        anchor_openings,
    })
}

fn validate_attempt_binding(
    relation: OracleRelation,
    attempt: &AttemptBindingSnapshot,
    protocol_version: u16,
    suite_identifier: [u8; 64],
    statement_schema_identifier: u16,
    canonical_statement_bytes: &[u8],
) -> Result<(), OracleDivergence> {
    if attempt.observed_application_slot != attempt.expected_application_slot {
        return Err(OracleDivergence::Binding {
            relation,
            field: OracleBindingField::ApplicationSlot,
        });
    }
    let expected_statement_hash = verified_application_statement_hash(
        protocol_version,
        suite_identifier,
        statement_schema_identifier,
        canonical_statement_bytes,
    );
    if attempt.expected_application_statement_hash != expected_statement_hash
        || attempt.observed_application_statement_hash != expected_statement_hash
    {
        return Err(OracleDivergence::Binding {
            relation,
            field: OracleBindingField::ApplicationStatementHash,
        });
    }
    if attempt.observed_attempt_identifier != attempt.expected_attempt_identifier {
        return Err(OracleDivergence::Binding {
            relation,
            field: OracleBindingField::AttemptIdentifier,
        });
    }
    Ok(())
}

fn validate_material_shape(
    relation: OracleRelation,
    category: OracleSourceCategory,
    source_ordinal: usize,
    material: &MaterialSnapshot,
    expected: ExpectedMaterialShape,
) -> Result<(), OracleDivergence> {
    let source_error = |field| OracleDivergence::Source {
        relation,
        category,
        source_ordinal,
        field,
    };
    if material.profile != expected.profile {
        return Err(source_error(OracleSourceField::Profile));
    }
    if material.material_context_hash != expected.context_hash {
        return Err(source_error(OracleSourceField::ContextHash));
    }
    if material.root != expected.root {
        return Err(source_error(OracleSourceField::Root));
    }
    if material.canonical_modulus != expected.canonical_modulus {
        return Err(source_error(OracleSourceField::CanonicalModulus));
    }
    if material.canonical_message.len() != expected.ring_degree {
        return Err(source_error(OracleSourceField::CanonicalLength));
    }
    if material
        .canonical_message
        .iter()
        .any(|coefficient| *coefficient >= expected.canonical_modulus)
    {
        return Err(source_error(OracleSourceField::CanonicalValue));
    }
    Ok(())
}

fn expected_material_context_hash(
    suite_identifier: [u8; 64],
    ceremony_context_hash: [u8; 64],
    action_context_hash: [u8; 64],
    participant_identity: [u8; 64],
    role: CommittedMaterialRole,
    sharing_limb_index: u16,
    object_index: u16,
) -> Result<[u8; 64], OracleDivergence> {
    CommittedMaterialContext::new(
        suite_identifier,
        ceremony_context_hash,
        action_context_hash,
        participant_identity,
        role,
        sharing_limb_index,
        object_index,
    )
    .context_hash()
    .map_err(|_| OracleDivergence::Source {
        relation: OracleRelation::VssShareLinkage,
        category: match role {
            CommittedMaterialRole::Coefficient => OracleSourceCategory::CoefficientMaterial,
            CommittedMaterialRole::RecipientShare => OracleSourceCategory::RecipientShareMaterial,
            CommittedMaterialRole::AggregateThresholdShare => {
                OracleSourceCategory::RecipientShareMaterial
            }
        },
        source_ordinal: 0,
        field: OracleSourceField::ContextHash,
    })
}

fn add_negacyclic_monomial_action_independently(
    accumulator: &mut [u64],
    source: &[u64],
    exponent: u64,
    modulus: u64,
) -> Result<(), ()> {
    if accumulator.len() != source.len() || source.is_empty() || modulus <= 1 {
        return Err(());
    }
    let ring_degree = u64::try_from(source.len()).map_err(|_| ())?;
    let doubled_degree = ring_degree.checked_mul(2).ok_or(())?;
    let normalized_exponent = exponent % doubled_degree;
    for (source_ordinal, source_value) in source.iter().copied().enumerate() {
        if source_value >= modulus {
            return Err(());
        }
        let displaced = u64::try_from(source_ordinal)
            .map_err(|_| ())?
            .checked_add(normalized_exponent)
            .ok_or(())?;
        let destination = usize::try_from(displaced % ring_degree).map_err(|_| ())?;
        let wrap_is_negative = (displaced / ring_degree) % 2 == 1;
        let signed_value = if wrap_is_negative && source_value != 0 {
            modulus - source_value
        } else {
            source_value
        };
        accumulator[destination] = ((u128::from(accumulator[destination])
            + u128::from(signed_value))
            % u128::from(modulus)) as u64;
    }
    Ok(())
}

fn validate_vss(snapshot: &ProductionSourceWitnessSnapshot) -> Result<u64, OracleDivergence> {
    let vss = &snapshot.vss;
    let relation = OracleRelation::VssShareLinkage;
    if vss.observed_protocol_version != vss.protocol_version {
        return Err(OracleDivergence::Binding {
            relation,
            field: OracleBindingField::ProtocolVersion,
        });
    }
    if vss.observed_suite_identifier != vss.suite_identifier {
        return Err(OracleDivergence::Binding {
            relation,
            field: OracleBindingField::SuiteIdentifier,
        });
    }
    if vss.observed_proof_profile_bytes != vss.proof_profile_bytes {
        return Err(OracleDivergence::Binding {
            relation,
            field: OracleBindingField::ProofProfile,
        });
    }
    if vss.observed_canonical_statement_bytes != vss.expected_canonical_statement_bytes {
        return Err(OracleDivergence::Binding {
            relation,
            field: OracleBindingField::CanonicalStatement,
        });
    }
    vss.compiler.validate(relation)?;
    let statement = decode_selected_vss_share_linkage_statement(
        &vss.observed_canonical_statement_bytes,
        SelectedApplicationStatementContext::new(
            vss.protocol_version,
            vss.suite_identifier,
            None,
            None,
        ),
    )
    .map_err(|_| OracleDivergence::Binding {
        relation,
        field: OracleBindingField::CanonicalStatement,
    })?;
    for (matches, field) in [
        (
            statement.ceremony_context_hash() == vss.ceremony_context_hash,
            OracleBindingField::CeremonyContext,
        ),
        (
            statement.action_context_hash() == vss.action_context_hash,
            OracleBindingField::ActionContext,
        ),
        (
            statement.roster_hash() == vss.roster_hash,
            OracleBindingField::Roster,
        ),
        (
            statement.public_setup_seed() == vss.public_setup_seed,
            OracleBindingField::PublicSetupSeed,
        ),
        (
            statement.participant_identity() == vss.participant_identity,
            OracleBindingField::ParticipantIdentity,
        ),
        (
            statement.roster_position() == vss.roster_position,
            OracleBindingField::RosterPosition,
        ),
    ] {
        if !matches {
            return Err(OracleDivergence::Binding { relation, field });
        }
    }
    validate_attempt_binding(
        relation,
        &vss.attempt,
        vss.protocol_version,
        vss.suite_identifier,
        ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
        &vss.observed_canonical_statement_bytes,
    )?;

    let input = selected_committed_material_relation_plan_input().map_err(|_| {
        OracleDivergence::Binding {
            relation,
            field: OracleBindingField::RelationVariant,
        }
    })?;
    let selected_profile =
        selected_committed_material_profile().map_err(|_| OracleDivergence::Binding {
            relation,
            field: OracleBindingField::ProofProfile,
        })?;
    let ring_degree = usize::try_from(input.ring_degree).map_err(|_| OracleDivergence::Source {
        relation,
        category: OracleSourceCategory::CoefficientMaterial,
        source_ordinal: 0,
        field: OracleSourceField::CanonicalLength,
    })?;
    let threshold = usize::from(input.threshold);
    let participant_count = usize::from(input.participant_count);
    let sharing_limb_count = input.sharing_data_modulus_indices.len();
    if vss.coefficient_materials.len() != sharing_limb_count * threshold
        || statement.ordered_coefficient_material_roots().len() != vss.coefficient_materials.len()
    {
        return Err(OracleDivergence::Source {
            relation,
            category: OracleSourceCategory::CoefficientMaterial,
            source_ordinal: vss.coefficient_materials.len(),
            field: OracleSourceField::CatalogLength,
        });
    }
    if vss.recipient_share_materials.len() != sharing_limb_count * participant_count
        || statement.ordered_recipient_share_material_roots().len()
            != vss.recipient_share_materials.len()
    {
        return Err(OracleDivergence::Source {
            relation,
            category: OracleSourceCategory::RecipientShareMaterial,
            source_ordinal: vss.recipient_share_materials.len(),
            field: OracleSourceField::CatalogLength,
        });
    }
    let point_stride = input
        .point_stride()
        .map_err(|_| OracleDivergence::Binding {
            relation,
            field: OracleBindingField::RelationVariant,
        })?;
    let mut evaluated_coefficient_count = 0_u64;
    for (sharing_limb_ordinal, sharing_limb_index) in input
        .sharing_data_modulus_indices
        .iter()
        .copied()
        .enumerate()
    {
        let modulus = snapshot
            .vss_context
            .resolved_modulus(SuiteModulusReference::data(sharing_limb_index))
            .map_err(|_| OracleDivergence::Binding {
                relation,
                field: OracleBindingField::RelationVariant,
            })?;
        let coefficient_start = sharing_limb_ordinal * threshold;
        let coefficient_end = coefficient_start + threshold;
        for (local_coefficient_ordinal, material) in vss.coefficient_materials
            [coefficient_start..coefficient_end]
            .iter()
            .enumerate()
        {
            let source_ordinal = coefficient_start + local_coefficient_ordinal;
            let context_hash = expected_material_context_hash(
                vss.suite_identifier,
                vss.ceremony_context_hash,
                vss.action_context_hash,
                vss.participant_identity,
                CommittedMaterialRole::Coefficient,
                sharing_limb_index,
                u16::try_from(local_coefficient_ordinal).map_err(|_| OracleDivergence::Source {
                    relation,
                    category: OracleSourceCategory::CoefficientMaterial,
                    source_ordinal,
                    field: OracleSourceField::ContextHash,
                })?,
            )?;
            validate_material_shape(
                relation,
                OracleSourceCategory::CoefficientMaterial,
                source_ordinal,
                material,
                ExpectedMaterialShape {
                    profile: selected_profile,
                    context_hash,
                    root: statement.ordered_coefficient_material_roots()[source_ordinal],
                    canonical_modulus: modulus,
                    ring_degree,
                },
            )?;
        }
        for recipient_ordinal in 0..participant_count {
            let source_ordinal = sharing_limb_ordinal * participant_count + recipient_ordinal;
            let material = &vss.recipient_share_materials[source_ordinal];
            let context_hash = expected_material_context_hash(
                vss.suite_identifier,
                vss.ceremony_context_hash,
                vss.action_context_hash,
                vss.participant_identity,
                CommittedMaterialRole::RecipientShare,
                sharing_limb_index,
                u16::try_from(recipient_ordinal).map_err(|_| OracleDivergence::Source {
                    relation,
                    category: OracleSourceCategory::RecipientShareMaterial,
                    source_ordinal,
                    field: OracleSourceField::ContextHash,
                })?,
            )?;
            validate_material_shape(
                relation,
                OracleSourceCategory::RecipientShareMaterial,
                source_ordinal,
                material,
                ExpectedMaterialShape {
                    profile: selected_profile,
                    context_hash,
                    root: statement.ordered_recipient_share_material_roots()[source_ordinal],
                    canonical_modulus: modulus,
                    ring_degree,
                },
            )?;
            let mut independently_evaluated_share = vec![0_u64; ring_degree];
            for (coefficient_ordinal, coefficient_material) in vss.coefficient_materials
                [coefficient_start..coefficient_end]
                .iter()
                .enumerate()
            {
                let exponent = u64::try_from(coefficient_ordinal)
                    .ok()
                    .and_then(|coefficient| {
                        coefficient.checked_mul(u64::try_from(recipient_ordinal).ok()?)
                    })
                    .and_then(|product| product.checked_mul(point_stride))
                    .ok_or(OracleDivergence::Coefficient {
                        relation,
                        category: OracleSourceCategory::RecipientShareMaterial,
                        source_ordinal,
                        coefficient_ordinal: 0,
                    })?;
                add_negacyclic_monomial_action_independently(
                    &mut independently_evaluated_share,
                    &coefficient_material.canonical_message,
                    exponent,
                    modulus,
                )
                .map_err(|_| OracleDivergence::Coefficient {
                    relation,
                    category: OracleSourceCategory::CoefficientMaterial,
                    source_ordinal: coefficient_start + coefficient_ordinal,
                    coefficient_ordinal: 0,
                })?;
            }
            for (coefficient_ordinal, (expected, observed)) in independently_evaluated_share
                .iter()
                .zip(&material.canonical_message)
                .enumerate()
            {
                evaluated_coefficient_count = evaluated_coefficient_count.saturating_add(1);
                if expected != observed {
                    return Err(OracleDivergence::Coefficient {
                        relation,
                        category: OracleSourceCategory::RecipientShareMaterial,
                        source_ordinal,
                        coefficient_ordinal,
                    });
                }
            }
        }
    }
    Ok(evaluated_coefficient_count)
}

fn centered_i8_residue_independently(value: i8, modulus: u64) -> Option<u64> {
    match value {
        -1 => Some(modulus.checked_sub(1)?),
        0 => Some(0),
        1 => Some(1),
        _ => None,
    }
}

fn negacyclic_product_independently(
    left: &[u64],
    right: &[i8],
    modulus: u64,
) -> Result<Vec<u64>, ()> {
    if left.len() != right.len()
        || left.is_empty()
        || left.iter().any(|value| *value >= modulus)
        || right.iter().any(|value| !(-1..=1).contains(value))
    {
        return Err(());
    }
    let ring_degree = left.len();
    let transform_size = ring_degree.checked_mul(2).ok_or(())?;
    let domain = ProofEvaluationDomain::new_subgroup(transform_size).map_err(|_| ())?;
    let mut left_evaluations = vec![ProofBaseFieldElement::ZERO; transform_size];
    for (destination, value) in left_evaluations.iter_mut().zip(left.iter().copied()) {
        *destination = ProofBaseFieldElement::from_canonical(value).map_err(|_| ())?;
    }
    let mut right_evaluations = vec![ProofBaseFieldElement::ZERO; transform_size];
    for (destination, value) in right_evaluations.iter_mut().zip(right.iter().copied()) {
        *destination = match value {
            -1 => ProofBaseFieldElement::ONE.negate(),
            0 => ProofBaseFieldElement::ZERO,
            1 => ProofBaseFieldElement::ONE,
            _ => return Err(()),
        };
    }
    domain
        .evaluate_base_polynomial_in_place(&mut left_evaluations)
        .map_err(|_| ())?;
    domain
        .evaluate_base_polynomial_in_place(&mut right_evaluations)
        .map_err(|_| ())?;
    for (left_value, right_value) in left_evaluations.iter_mut().zip(&right_evaluations) {
        *left_value = left_value.multiply(*right_value);
    }
    domain
        .interpolate_base_polynomial_in_place(&mut left_evaluations)
        .map_err(|_| ())?;
    left_evaluations.resize(transform_size, ProofBaseFieldElement::ZERO);
    let proof_modulus = i128::from(PROOF_BASE_FIELD_MODULUS);
    let commitment_modulus = i128::from(modulus);
    (0..ring_degree)
        .map(|coefficient_ordinal| {
            let difference = left_evaluations[coefficient_ordinal]
                .subtract(left_evaluations[coefficient_ordinal + ring_degree])
                .canonical();
            let centered = if difference <= PROOF_BASE_FIELD_MODULUS / 2 {
                i128::from(difference)
            } else {
                i128::from(difference) - proof_modulus
            };
            u64::try_from(centered.rem_euclid(commitment_modulus)).map_err(|_| ())
        })
        .collect()
}

fn validate_same_secret(
    snapshot: &ProductionSourceWitnessSnapshot,
) -> Result<(u64, u64), OracleDivergence> {
    let same_secret = &snapshot.same_secret;
    let relation = OracleRelation::SameSecret;
    for (matches, field) in [
        (
            same_secret.observed_protocol_version == same_secret.protocol_version,
            OracleBindingField::ProtocolVersion,
        ),
        (
            same_secret.observed_suite_identifier == same_secret.suite_identifier,
            OracleBindingField::SuiteIdentifier,
        ),
        (
            same_secret.observed_ceremony_context_hash == same_secret.ceremony_context_hash,
            OracleBindingField::CeremonyContext,
        ),
        (
            same_secret.observed_action_context_hash == same_secret.action_context_hash,
            OracleBindingField::ActionContext,
        ),
        (
            same_secret.observed_roster_hash == same_secret.roster_hash,
            OracleBindingField::Roster,
        ),
        (
            same_secret.observed_setup_proof_context_hash == same_secret.setup_proof_context_hash,
            OracleBindingField::SetupProofContext,
        ),
        (
            same_secret.observed_participant_identity == same_secret.participant_identity,
            OracleBindingField::ParticipantIdentity,
        ),
        (
            same_secret.observed_roster_position == same_secret.roster_position,
            OracleBindingField::RosterPosition,
        ),
        (
            same_secret.observed_public_setup_seed == same_secret.public_setup_seed,
            OracleBindingField::PublicSetupSeed,
        ),
        (
            same_secret.observed_proof_profile_bytes == same_secret.proof_profile_bytes,
            OracleBindingField::ProofProfile,
        ),
    ] {
        if !matches {
            return Err(OracleDivergence::Binding { relation, field });
        }
    }
    if same_secret.observed_canonical_statement_bytes
        != same_secret.expected_canonical_statement_bytes
    {
        return Err(OracleDivergence::Binding {
            relation,
            field: OracleBindingField::CanonicalStatement,
        });
    }
    same_secret.compiler.validate(relation)?;
    let statement_schema_identifier =
        SetupKeyRelationProofFamily::SameSecret.statement_schema_identifier();
    let statement = decode_selected_same_secret_statement(
        &same_secret.observed_canonical_statement_bytes,
        SelectedApplicationStatementContext::new(
            same_secret.protocol_version,
            same_secret.suite_identifier,
            None,
            None,
        ),
    )
    .map_err(|_| OracleDivergence::Binding {
        relation,
        field: OracleBindingField::CanonicalStatement,
    })?;
    for (matches, field) in [
        (
            statement.setup_proof_context_hash() == same_secret.setup_proof_context_hash,
            OracleBindingField::SetupProofContext,
        ),
        (
            statement.participant_identity() == same_secret.participant_identity,
            OracleBindingField::ParticipantIdentity,
        ),
        (
            statement.roster_position() == same_secret.roster_position,
            OracleBindingField::RosterPosition,
        ),
    ] {
        if !matches {
            return Err(OracleDivergence::Binding { relation, field });
        }
    }
    validate_attempt_binding(
        relation,
        &same_secret.attempt,
        same_secret.protocol_version,
        same_secret.suite_identifier,
        statement_schema_identifier,
        &same_secret.observed_canonical_statement_bytes,
    )?;

    let input =
        selected_same_secret_relation_plan_input().map_err(|_| OracleDivergence::Binding {
            relation,
            field: OracleBindingField::RelationVariant,
        })?;
    let selected_profile =
        selected_committed_material_profile().map_err(|_| OracleDivergence::Binding {
            relation,
            field: OracleBindingField::ProofProfile,
        })?;
    let ring_degree = usize::try_from(input.ring_degree).map_err(|_| OracleDivergence::Source {
        relation,
        category: OracleSourceCategory::CommonSecret,
        source_ordinal: 0,
        field: OracleSourceField::CanonicalLength,
    })?;
    if same_secret.common_secret_coefficients.len() != ring_degree
        || same_secret
            .common_secret_coefficients
            .iter()
            .any(|coefficient| !(-1..=1).contains(coefficient))
    {
        return Err(OracleDivergence::Source {
            relation,
            category: OracleSourceCategory::CommonSecret,
            source_ordinal: 0,
            field: OracleSourceField::CanonicalValue,
        });
    }
    if same_secret.degree_zero_materials.len() != input.sharing_data_modulus_indices.len()
        || statement.ordered_degree_zero_commitment_roots().len()
            != same_secret.degree_zero_materials.len()
    {
        return Err(OracleDivergence::Source {
            relation,
            category: OracleSourceCategory::DegreeZeroMaterial,
            source_ordinal: same_secret.degree_zero_materials.len(),
            field: OracleSourceField::CatalogLength,
        });
    }
    let threshold = usize::from(
        selected_committed_material_relation_plan_input()
            .map_err(|_| OracleDivergence::Binding {
                relation,
                field: OracleBindingField::RelationVariant,
            })?
            .threshold,
    );
    let mut degree_zero_coefficient_evaluation_count = 0_u64;
    for (sharing_limb_ordinal, sharing_limb_index) in input
        .sharing_data_modulus_indices
        .iter()
        .copied()
        .enumerate()
    {
        let material = &same_secret.degree_zero_materials[sharing_limb_ordinal];
        let modulus = snapshot
            .same_secret_context
            .resolved_modulus(SuiteModulusReference::data(sharing_limb_index))
            .map_err(|_| OracleDivergence::Binding {
                relation,
                field: OracleBindingField::RelationVariant,
            })?;
        let context_hash = CommittedMaterialContext::new(
            same_secret.suite_identifier,
            same_secret.ceremony_context_hash,
            same_secret.action_context_hash,
            same_secret.participant_identity,
            CommittedMaterialRole::Coefficient,
            sharing_limb_index,
            0,
        )
        .context_hash()
        .map_err(|_| OracleDivergence::Source {
            relation,
            category: OracleSourceCategory::DegreeZeroMaterial,
            source_ordinal: sharing_limb_ordinal,
            field: OracleSourceField::ContextHash,
        })?;
        validate_material_shape(
            relation,
            OracleSourceCategory::DegreeZeroMaterial,
            sharing_limb_ordinal,
            material,
            ExpectedMaterialShape {
                profile: selected_profile,
                context_hash,
                root: statement.ordered_degree_zero_commitment_roots()[sharing_limb_ordinal],
                canonical_modulus: modulus,
                ring_degree,
            },
        )?;
        let vss_source_ordinal = sharing_limb_ordinal * threshold;
        let vss_degree_zero = snapshot
            .vss
            .coefficient_materials
            .get(vss_source_ordinal)
            .ok_or(OracleDivergence::Source {
                relation,
                category: OracleSourceCategory::DegreeZeroMaterial,
                source_ordinal: sharing_limb_ordinal,
                field: OracleSourceField::CatalogOrder,
            })?;
        if material.root != vss_degree_zero.root
            || material.material_context_hash != vss_degree_zero.material_context_hash
            || material.canonical_message != vss_degree_zero.canonical_message
        {
            return Err(OracleDivergence::Source {
                relation,
                category: OracleSourceCategory::DegreeZeroMaterial,
                source_ordinal: sharing_limb_ordinal,
                field: OracleSourceField::CatalogOrder,
            });
        }
        for (coefficient_ordinal, (secret, observed)) in same_secret
            .common_secret_coefficients
            .iter()
            .zip(&material.canonical_message)
            .enumerate()
        {
            degree_zero_coefficient_evaluation_count =
                degree_zero_coefficient_evaluation_count.saturating_add(1);
            let expected = centered_i8_residue_independently(*secret, modulus).ok_or(
                OracleDivergence::Coefficient {
                    relation,
                    category: OracleSourceCategory::CommonSecret,
                    source_ordinal: 0,
                    coefficient_ordinal,
                },
            )?;
            if expected != *observed {
                return Err(OracleDivergence::Coefficient {
                    relation,
                    category: OracleSourceCategory::DegreeZeroMaterial,
                    source_ordinal: sharing_limb_ordinal,
                    coefficient_ordinal,
                });
            }
        }
    }

    if same_secret.anchor_openings.len() != input.commitment_data_modulus_indices.len()
        || same_secret.anchor_openings.len() != statement.anchor_commitment_roots().len()
    {
        return Err(OracleDivergence::Source {
            relation,
            category: OracleSourceCategory::AnchorCommitment,
            source_ordinal: same_secret.anchor_openings.len(),
            field: OracleSourceField::CatalogLength,
        });
    }
    if same_secret.public_matrix_seed != same_secret.public_setup_seed {
        return Err(OracleDivergence::Source {
            relation,
            category: OracleSourceCategory::PublicMatrix,
            source_ordinal: 0,
            field: OracleSourceField::ContextHash,
        });
    }
    let public_setup_seed_hex = encode_hex(&same_secret.public_matrix_seed);
    let module_rank = usize::from(input.commitment_module_rank);
    let mut anchor_coefficient_evaluation_count = 0_u64;
    for (anchor_ordinal, anchor) in same_secret.anchor_openings.iter().enumerate() {
        let expected_modulus_index = input.commitment_data_modulus_indices[anchor_ordinal];
        if anchor.commitment_data_prime_index != expected_modulus_index {
            return Err(OracleDivergence::Source {
                relation,
                category: OracleSourceCategory::AnchorCommitment,
                source_ordinal: anchor_ordinal,
                field: OracleSourceField::CatalogOrder,
            });
        }
        let modulus = snapshot
            .same_secret_context
            .resolved_modulus(SuiteModulusReference::data(expected_modulus_index))
            .map_err(|_| OracleDivergence::Binding {
                relation,
                field: OracleBindingField::RelationVariant,
            })?;
        if anchor.root != statement.anchor_commitment_roots()[anchor_ordinal] {
            return Err(OracleDivergence::Source {
                relation,
                category: OracleSourceCategory::AnchorCommitment,
                source_ordinal: anchor_ordinal,
                field: OracleSourceField::Root,
            });
        }
        let public_context = SetupPublicPolynomialContext::lattice_anchor(
            same_secret.setup_proof_context_hash,
            same_secret.participant_identity,
            same_secret.roster_position,
            expected_modulus_index,
        )
        .map_err(|_| OracleDivergence::Source {
            relation,
            category: OracleSourceCategory::AnchorCommitment,
            source_ordinal: anchor_ordinal,
            field: OracleSourceField::PublicPolynomialContext,
        })?;
        let (context_hash, root, degree_bound, row_width) =
            SetupPublicPolynomialTree::construct_lattice_anchor_root_from_canonical_bytes(
                &public_context,
                usize::try_from(input.evaluation_domain_size).map_err(|_| {
                    OracleDivergence::Source {
                        relation,
                        category: OracleSourceCategory::AnchorCommitment,
                        source_ordinal: anchor_ordinal,
                        field: OracleSourceField::CanonicalLength,
                    }
                })?,
                &anchor.canonical_commitment_bytes,
            )
            .map_err(|_| OracleDivergence::Source {
                relation,
                category: OracleSourceCategory::AnchorCommitment,
                source_ordinal: anchor_ordinal,
                field: OracleSourceField::CanonicalValue,
            })?;
        if context_hash != anchor.public_polynomial_context_hash
            || degree_bound != anchor.source_polynomial_degree_bound_exclusive
            || usize::try_from(row_width).ok() != Some((module_rank + 1) * 2)
        {
            return Err(OracleDivergence::Source {
                relation,
                category: OracleSourceCategory::AnchorCommitment,
                source_ordinal: anchor_ordinal,
                field: OracleSourceField::PublicPolynomialContext,
            });
        }
        if root != anchor.root {
            return Err(OracleDivergence::Source {
                relation,
                category: OracleSourceCategory::AnchorCommitment,
                source_ordinal: anchor_ordinal,
                field: OracleSourceField::Root,
            });
        }
        if anchor.commitment_rows.len() != module_rank + 1
            || anchor.hiding_secret_polynomials.len() != module_rank + 1
            || anchor.hiding_error_polynomials.len() != module_rank
        {
            return Err(OracleDivergence::Source {
                relation,
                category: OracleSourceCategory::AnchorCommitment,
                source_ordinal: anchor_ordinal,
                field: OracleSourceField::CanonicalLength,
            });
        }
        for row_ordinal in 0..=module_rank {
            let mut expected_row = vec![0_u64; ring_degree];
            let sampled_column_count = if row_ordinal < module_rank {
                module_rank + 1
            } else {
                module_rank
            };
            for randomness_column_ordinal in 0..sampled_column_count {
                let matrix = setup_commitment_matrix_polynomial(
                    &public_setup_seed_hex,
                    usize::from(expected_modulus_index),
                    row_ordinal,
                    randomness_column_ordinal,
                    ring_degree,
                    modulus,
                )
                .map_err(|_| OracleDivergence::Source {
                    relation,
                    category: OracleSourceCategory::PublicMatrix,
                    source_ordinal: anchor_ordinal,
                    field: OracleSourceField::CanonicalValue,
                })?;
                let product = negacyclic_product_independently(
                    &matrix,
                    &anchor.hiding_secret_polynomials[randomness_column_ordinal],
                    modulus,
                )
                .map_err(|_| OracleDivergence::Coefficient {
                    relation,
                    category: OracleSourceCategory::AnchorHidingSecret,
                    source_ordinal: anchor_ordinal,
                    coefficient_ordinal: 0,
                })?;
                for (accumulator, value) in expected_row.iter_mut().zip(product) {
                    *accumulator = ((u128::from(*accumulator) + u128::from(value))
                        % u128::from(modulus)) as u64;
                }
            }
            if row_ordinal < module_rank {
                for (accumulator, error) in expected_row
                    .iter_mut()
                    .zip(&anchor.hiding_error_polynomials[row_ordinal])
                {
                    let error_residue = centered_i8_residue_independently(*error, modulus).ok_or(
                        OracleDivergence::Coefficient {
                            relation,
                            category: OracleSourceCategory::AnchorHidingError,
                            source_ordinal: anchor_ordinal,
                            coefficient_ordinal: 0,
                        },
                    )?;
                    *accumulator = ((u128::from(*accumulator) + u128::from(error_residue))
                        % u128::from(modulus)) as u64;
                }
            } else {
                for (coefficient_ordinal, accumulator) in expected_row.iter_mut().enumerate() {
                    let blinding_residue = centered_i8_residue_independently(
                        anchor.hiding_secret_polynomials[module_rank][coefficient_ordinal],
                        modulus,
                    )
                    .ok_or(OracleDivergence::Coefficient {
                        relation,
                        category: OracleSourceCategory::AnchorHidingSecret,
                        source_ordinal: anchor_ordinal,
                        coefficient_ordinal,
                    })?;
                    let secret_residue = centered_i8_residue_independently(
                        same_secret.common_secret_coefficients[coefficient_ordinal],
                        modulus,
                    )
                    .ok_or(OracleDivergence::Coefficient {
                        relation,
                        category: OracleSourceCategory::CommonSecret,
                        source_ordinal: 0,
                        coefficient_ordinal,
                    })?;
                    *accumulator = ((u128::from(*accumulator)
                        + u128::from(blinding_residue)
                        + u128::from(secret_residue))
                        % u128::from(modulus)) as u64;
                }
            }
            let observed_row = &anchor.commitment_rows[row_ordinal];
            if observed_row.len() != ring_degree {
                return Err(OracleDivergence::Source {
                    relation,
                    category: OracleSourceCategory::AnchorCommitment,
                    source_ordinal: anchor_ordinal,
                    field: OracleSourceField::CanonicalLength,
                });
            }
            for (coefficient_ordinal, (expected, observed)) in
                expected_row.iter().zip(observed_row).enumerate()
            {
                anchor_coefficient_evaluation_count =
                    anchor_coefficient_evaluation_count.saturating_add(1);
                if i128::from(*expected) != *observed {
                    return Err(OracleDivergence::Coefficient {
                        relation,
                        category: OracleSourceCategory::AnchorCommitment,
                        source_ordinal: anchor_ordinal,
                        coefficient_ordinal: row_ordinal * ring_degree + coefficient_ordinal,
                    });
                }
            }
        }
    }
    Ok((
        degree_zero_coefficient_evaluation_count,
        anchor_coefficient_evaluation_count,
    ))
}

fn validate_production_snapshot(
    snapshot: &ProductionSourceWitnessSnapshot,
) -> Result<ProductionSourceWitnessOracleCertificate, OracleDivergence> {
    let vss_coefficient_evaluation_count = validate_vss(snapshot)?;
    let (degree_zero_coefficient_evaluation_count, anchor_coefficient_evaluation_count) =
        validate_same_secret(snapshot)?;
    Ok(ProductionSourceWitnessOracleCertificate {
        vss_compiler_constraint_count: snapshot.vss.compiler.expected_segments.len(),
        same_secret_compiler_constraint_count: snapshot
            .same_secret
            .compiler
            .expected_segments
            .len(),
        coefficient_material_count: snapshot.vss.coefficient_materials.len(),
        recipient_share_material_count: snapshot.vss.recipient_share_materials.len(),
        degree_zero_material_count: snapshot.same_secret.degree_zero_materials.len(),
        anchor_count: snapshot.same_secret.anchor_openings.len(),
        vss_coefficient_evaluation_count,
        degree_zero_coefficient_evaluation_count,
        anchor_coefficient_evaluation_count,
    })
}

fn changed_hash(mut value: [u8; 64]) -> [u8; 64] {
    value[0] ^= 0x80;
    value
}

fn expect_binding_fault(
    snapshot: &ProductionSourceWitnessSnapshot,
    relation: OracleRelation,
    field: OracleBindingField,
) {
    let divergence = match relation {
        OracleRelation::VssShareLinkage => validate_vss(snapshot)
            .map(|_| ())
            .expect_err("the hostile VSS binding must diverge"),
        OracleRelation::SameSecret => validate_same_secret(snapshot)
            .map(|_| ())
            .expect_err("the hostile same-secret binding must diverge"),
    };
    assert_eq!(divergence, OracleDivergence::Binding { relation, field });
}

fn relation_divergence(
    snapshot: &ProductionSourceWitnessSnapshot,
    relation: OracleRelation,
) -> OracleDivergence {
    match relation {
        OracleRelation::VssShareLinkage => validate_vss(snapshot)
            .map(|_| ())
            .expect_err("the hostile VSS source or witness must diverge"),
        OracleRelation::SameSecret => validate_same_secret(snapshot)
            .map(|_| ())
            .expect_err("the hostile same-secret source or witness must diverge"),
    }
}

fn negacyclic_product_schoolbook_for_test(left: &[u64], right: &[i8], modulus: u64) -> Vec<u64> {
    let ring_degree = left.len();
    let mut coefficients = vec![0_i128; ring_degree];
    for (left_ordinal, left_value) in left.iter().copied().enumerate() {
        for (right_ordinal, right_value) in right.iter().copied().enumerate() {
            let combined_ordinal = left_ordinal + right_ordinal;
            let destination = combined_ordinal % ring_degree;
            let product = i128::from(left_value) * i128::from(right_value);
            coefficients[destination] += if combined_ordinal >= ring_degree {
                -product
            } else {
                product
            };
        }
    }
    coefficients
        .into_iter()
        .map(|coefficient| coefficient.rem_euclid(i128::from(modulus)) as u64)
        .collect()
}

#[test]
fn independent_anchor_convolution_matches_small_schoolbook_cases() {
    let cases = [
        (vec![0, 0], vec![0, 0]),
        (vec![16, 0], vec![1, 0]),
        (vec![1, 2, 3, 4], vec![-1, 0, 1, -1]),
        (
            vec![16, 15, 14, 13, 12, 11, 10, 9],
            vec![1, -1, 1, -1, -1, 0, 1, 0],
        ),
    ];
    for (left, right) in cases {
        assert_eq!(
            negacyclic_product_independently(&left, &right, 17),
            Ok(negacyclic_product_schoolbook_for_test(&left, &right, 17))
        );
    }
    assert_eq!(
        negacyclic_product_independently(&[1, 2, 3, 4], &[1, 0, 1], 17),
        Err(())
    );
    assert_eq!(
        negacyclic_product_independently(&[1, 2, 3, 17], &[1, 0, 1, 0], 17),
        Err(())
    );
    assert_eq!(
        negacyclic_product_independently(&[1, 2, 3, 4], &[1, 0, 2, 0], 17),
        Err(())
    );
}

#[test]
#[ignore = "manual selected production source-and-witness correspondence evidence"]
fn heavy_rust_kernel_selected_production_source_and_witness_oracle() {
    let snapshot = collect_production_snapshot().expect("production setup sources populate");
    let certificate = validate_production_snapshot(&snapshot)
        .expect("every production source and witness matches independent arithmetic");
    assert_eq!(certificate.vss_compiler_constraint_count, 3_767);
    assert_eq!(certificate.same_secret_compiler_constraint_count, 4_046);
    assert_eq!(certificate.coefficient_material_count, 32);
    assert_eq!(certificate.recipient_share_material_count, 80);
    assert_eq!(certificate.degree_zero_material_count, 8);
    assert_eq!(certificate.anchor_count, 3);
    assert_eq!(certificate.vss_coefficient_evaluation_count, 2_621_440);
    assert_eq!(
        certificate.degree_zero_coefficient_evaluation_count,
        262_144
    );
    assert_eq!(certificate.anchor_coefficient_evaluation_count, 196_608);

    let mut hostile = snapshot.clone();
    hostile.vss.observed_canonical_statement_bytes.pop();
    expect_binding_fault(
        &hostile,
        OracleRelation::VssShareLinkage,
        OracleBindingField::CanonicalStatement,
    );

    let mut hostile = snapshot.clone();
    hostile.vss.observed_protocol_version ^= 1;
    expect_binding_fault(
        &hostile,
        OracleRelation::VssShareLinkage,
        OracleBindingField::ProtocolVersion,
    );

    let mut hostile = snapshot.clone();
    hostile.vss.observed_suite_identifier = changed_hash(hostile.vss.observed_suite_identifier);
    expect_binding_fault(
        &hostile,
        OracleRelation::VssShareLinkage,
        OracleBindingField::SuiteIdentifier,
    );

    let mut hostile = snapshot.clone();
    hostile.same_secret.observed_ceremony_context_hash =
        changed_hash(hostile.same_secret.observed_ceremony_context_hash);
    expect_binding_fault(
        &hostile,
        OracleRelation::SameSecret,
        OracleBindingField::CeremonyContext,
    );

    let mut hostile = snapshot.clone();
    hostile.same_secret.observed_action_context_hash =
        changed_hash(hostile.same_secret.observed_action_context_hash);
    expect_binding_fault(
        &hostile,
        OracleRelation::SameSecret,
        OracleBindingField::ActionContext,
    );

    let mut hostile = snapshot.clone();
    hostile.same_secret.observed_roster_hash =
        changed_hash(hostile.same_secret.observed_roster_hash);
    expect_binding_fault(
        &hostile,
        OracleRelation::SameSecret,
        OracleBindingField::Roster,
    );

    let mut hostile = snapshot.clone();
    hostile.same_secret.observed_setup_proof_context_hash =
        changed_hash(hostile.same_secret.observed_setup_proof_context_hash);
    expect_binding_fault(
        &hostile,
        OracleRelation::SameSecret,
        OracleBindingField::SetupProofContext,
    );

    let mut hostile = snapshot.clone();
    hostile.same_secret.observed_public_setup_seed =
        changed_hash(hostile.same_secret.observed_public_setup_seed);
    expect_binding_fault(
        &hostile,
        OracleRelation::SameSecret,
        OracleBindingField::PublicSetupSeed,
    );

    let mut hostile = snapshot.clone();
    hostile.same_secret.observed_participant_identity =
        changed_hash(hostile.same_secret.observed_participant_identity);
    expect_binding_fault(
        &hostile,
        OracleRelation::SameSecret,
        OracleBindingField::ParticipantIdentity,
    );

    let mut hostile = snapshot.clone();
    hostile.same_secret.observed_roster_position ^= 1;
    expect_binding_fault(
        &hostile,
        OracleRelation::SameSecret,
        OracleBindingField::RosterPosition,
    );

    let mut hostile = snapshot.clone();
    hostile.same_secret.attempt.observed_application_slot = application_slot(
        hostile.same_secret.suite_identifier,
        hostile.same_secret.ceremony_context_hash,
        hostile.same_secret.action_context_hash,
        SetupKeyRelationProofFamily::SameSecret.statement_schema_identifier(),
        hostile.same_secret.roster_position ^ 1,
    )
    .expect("hostile application slot remains structurally valid");
    expect_binding_fault(
        &hostile,
        OracleRelation::SameSecret,
        OracleBindingField::ApplicationSlot,
    );

    let mut hostile = snapshot.clone();
    hostile
        .same_secret
        .attempt
        .observed_application_statement_hash = changed_hash(
        hostile
            .same_secret
            .attempt
            .observed_application_statement_hash,
    );
    expect_binding_fault(
        &hostile,
        OracleRelation::SameSecret,
        OracleBindingField::ApplicationStatementHash,
    );

    let mut hostile = snapshot.clone();
    hostile.same_secret.attempt.observed_attempt_identifier[0] ^= 1;
    expect_binding_fault(
        &hostile,
        OracleRelation::SameSecret,
        OracleBindingField::AttemptIdentifier,
    );

    let mut hostile = snapshot.clone();
    hostile.vss.compiler.observed_variant_hash =
        changed_hash(hostile.vss.compiler.observed_variant_hash);
    expect_binding_fault(
        &hostile,
        OracleRelation::VssShareLinkage,
        OracleBindingField::RelationVariant,
    );

    let mut hostile = snapshot.clone();
    hostile.same_secret.observed_proof_profile_bytes[0] ^= 1;
    expect_binding_fault(
        &hostile,
        OracleRelation::SameSecret,
        OracleBindingField::ProofProfile,
    );

    let mut hostile = snapshot.clone();
    hostile.vss.coefficient_materials.swap(0, 1);
    assert!(matches!(
        relation_divergence(&hostile, OracleRelation::VssShareLinkage),
        OracleDivergence::Source {
            relation: OracleRelation::VssShareLinkage,
            category: OracleSourceCategory::CoefficientMaterial,
            source_ordinal: 0,
            field: OracleSourceField::ContextHash | OracleSourceField::Root,
        }
    ));

    let mut hostile = snapshot.clone();
    hostile.vss.recipient_share_materials[0].root =
        changed_hash(hostile.vss.recipient_share_materials[0].root);
    assert_eq!(
        relation_divergence(&hostile, OracleRelation::VssShareLinkage),
        OracleDivergence::Source {
            relation: OracleRelation::VssShareLinkage,
            category: OracleSourceCategory::RecipientShareMaterial,
            source_ordinal: 0,
            field: OracleSourceField::Root,
        }
    );

    let mut hostile = snapshot.clone();
    hostile.vss.coefficient_materials[0].material_context_hash =
        changed_hash(hostile.vss.coefficient_materials[0].material_context_hash);
    assert_eq!(
        relation_divergence(&hostile, OracleRelation::VssShareLinkage),
        OracleDivergence::Source {
            relation: OracleRelation::VssShareLinkage,
            category: OracleSourceCategory::CoefficientMaterial,
            source_ordinal: 0,
            field: OracleSourceField::ContextHash,
        }
    );

    let mut hostile = snapshot.clone();
    hostile.vss.recipient_share_materials[0].canonical_message[0] ^= 1;
    assert_eq!(
        relation_divergence(&hostile, OracleRelation::VssShareLinkage),
        OracleDivergence::Coefficient {
            relation: OracleRelation::VssShareLinkage,
            category: OracleSourceCategory::RecipientShareMaterial,
            source_ordinal: 0,
            coefficient_ordinal: 0,
        }
    );

    let mut hostile = snapshot.clone();
    hostile.same_secret.degree_zero_materials[0].root =
        changed_hash(hostile.same_secret.degree_zero_materials[0].root);
    assert_eq!(
        relation_divergence(&hostile, OracleRelation::SameSecret),
        OracleDivergence::Source {
            relation: OracleRelation::SameSecret,
            category: OracleSourceCategory::DegreeZeroMaterial,
            source_ordinal: 0,
            field: OracleSourceField::Root,
        }
    );

    let mut hostile = snapshot.clone();
    hostile.same_secret.anchor_openings[0].canonical_commitment_bytes[0] ^= 1;
    assert!(matches!(
        relation_divergence(&hostile, OracleRelation::SameSecret),
        OracleDivergence::Source {
            relation: OracleRelation::SameSecret,
            category: OracleSourceCategory::AnchorCommitment,
            source_ordinal: 0,
            field: OracleSourceField::CanonicalValue | OracleSourceField::Root,
        }
    ));

    let mut hostile = snapshot.clone();
    hostile.same_secret.public_matrix_seed = changed_hash(hostile.same_secret.public_matrix_seed);
    assert_eq!(
        relation_divergence(&hostile, OracleRelation::SameSecret),
        OracleDivergence::Source {
            relation: OracleRelation::SameSecret,
            category: OracleSourceCategory::PublicMatrix,
            source_ordinal: 0,
            field: OracleSourceField::ContextHash,
        }
    );

    let mut hostile = snapshot.clone();
    hostile.same_secret.common_secret_coefficients[0] = 2;
    assert_eq!(
        relation_divergence(&hostile, OracleRelation::SameSecret),
        OracleDivergence::Source {
            relation: OracleRelation::SameSecret,
            category: OracleSourceCategory::CommonSecret,
            source_ordinal: 0,
            field: OracleSourceField::CanonicalValue,
        }
    );

    let mut hostile = snapshot.clone();
    hostile.same_secret.anchor_openings[0].hiding_secret_polynomials[0][0] = 2;
    assert!(matches!(
        relation_divergence(&hostile, OracleRelation::SameSecret),
        OracleDivergence::Coefficient {
            relation: OracleRelation::SameSecret,
            category: OracleSourceCategory::AnchorHidingSecret,
            source_ordinal: 0,
            ..
        }
    ));

    let mut hostile = snapshot.clone();
    hostile.same_secret.anchor_openings[0].hiding_error_polynomials[0][0] = 2;
    assert!(matches!(
        relation_divergence(&hostile, OracleRelation::SameSecret),
        OracleDivergence::Coefficient {
            relation: OracleRelation::SameSecret,
            category: OracleSourceCategory::AnchorHidingError,
            source_ordinal: 0,
            ..
        }
    ));

    for (relation, mut compiler) in [
        (
            OracleRelation::VssShareLinkage,
            snapshot.vss.compiler.clone(),
        ),
        (
            OracleRelation::SameSecret,
            snapshot.same_secret.compiler.clone(),
        ),
    ] {
        for segment_ordinal in 0..compiler.observed_segments.len() {
            compiler.observed_segments[segment_ordinal][0] ^= 1;
            assert_eq!(
                compiler.validate(relation),
                Err(OracleDivergence::CompilerSegment {
                    relation,
                    segment_ordinal,
                })
            );
            compiler.observed_segments[segment_ordinal][0] ^= 1;
        }
    }

    println!(
        "selected production source-and-witness oracle complete: vss_compiler_constraint_count={} same_secret_compiler_constraint_count={} coefficient_material_count={} recipient_share_material_count={} degree_zero_material_count={} anchor_count={} vss_coefficient_evaluation_count={} degree_zero_coefficient_evaluation_count={} anchor_coefficient_evaluation_count={}",
        certificate.vss_compiler_constraint_count,
        certificate.same_secret_compiler_constraint_count,
        certificate.coefficient_material_count,
        certificate.recipient_share_material_count,
        certificate.degree_zero_material_count,
        certificate.anchor_count,
        certificate.vss_coefficient_evaluation_count,
        certificate.degree_zero_coefficient_evaluation_count,
        certificate.anchor_coefficient_evaluation_count,
    );
}
