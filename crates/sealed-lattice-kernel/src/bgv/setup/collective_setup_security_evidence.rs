//! Test-owned extraction of the exact collective-setup security-game catalog.
//!
//! This module does not participate in protocol acceptance and cannot mint a
//! setup capability. It makes the production roster, proof inventory,
//! relation-plan identities, evaluator topology, and public-sample census
//! available to the checked security-evidence record without maintaining a
//! second hand-written catalog.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    sync::OnceLock,
};

use num_bigint::{BigInt, BigUint};
use num_traits::{Signed, Zero};
use serde::Serialize;

use crate::{
    bgv::{
        evaluator::{
            candidate_evidence::EvaluatorCandidateInput,
            noise_recurrence::direct_ballot_target_noise_bounds,
        },
        key_switch_topology::{
            KEY_SWITCH_DATA_PRIMES_PER_BLOCK, KeySwitchDecompositionTopology,
            key_switch_special_basis_modulus_product,
        },
        parameters::{DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE, SPECIAL_PRIMES},
        proof_suite::{
            SelectedEvaluatorEntryKind, selected_evaluator_entry_positions,
            selected_evaluator_galois_entry_positions,
            selected_evaluator_relinearization_entry_positions, selected_relation_plans,
        },
    },
    foundation::{
        FOUNDATION_PROFILE, ProofApplicationSlotCeilings,
        SELECTED_MAXIMUM_CANDIDATE_PACKAGES_PER_ACTION,
        SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT,
        SELECTED_MAXIMUM_PUBLIC_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT,
        selected_sharing_data_prime_coordinates,
    },
    transcript_core::encode_hex,
};

use super::{
    SETUP_COMMITMENT_HIDING_ERROR_WIDTH, SETUP_COMMITMENT_HIDING_SECRET_WIDTH,
    SETUP_COMMITMENT_MODULE_RANK, SETUP_COMMITMENT_MODULUS_LIMB_INDICES,
};

const SETUP_FAMILY_SCHEMA_IDENTIFIERS: [u16; 10] = [
    ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
    ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
    ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
    ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
    ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
    ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER,
    ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
    ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER,
    ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
    ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
];

const PRODUCTION_AUTHORITY_EXPORT_PATH_ENVIRONMENT_VARIABLE: &str =
    "SEALED_LATTICE_COLLECTIVE_SETUP_AUTHORITY_EXPORT_PATH";

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct CollectiveSetupSecurityAuthority {
    profile: SelectedRosterProfile,
    corruption_classes: Vec<CorruptionClass>,
    proof_inventory: Vec<ProofInventoryEntry>,
    proof_inventory_totals: ProofInventoryTotals,
    relation_plan_bindings: Vec<RelationPlanBinding>,
    evaluator_topology: EvaluatorTopology,
    sample_census: SampleCensus,
    witness_commitment_topology: WitnessCommitmentTopology,
    setup_correctness: SetupCorrectnessAuthority,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct SelectedRosterProfile {
    participant_count: u16,
    active_fault_bound: u16,
    reconstruction_threshold: u16,
    finality_quorum: u16,
    state_witness_quorum: u16,
    option_count: u16,
    polynomial_degree: usize,
    plaintext_modulus: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct CorruptionClass {
    corruption_count: u16,
    honest_participant_count: u16,
    honest_secret_support_before_known_shift: [i16; 2],
    honest_error_support: [i16; 2],
    corruption_subsets: Vec<Vec<u16>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProofInventoryEntry {
    family: &'static str,
    application_statement_schema_identifier: u16,
    physical_proof_application_count: u32,
    logical_relation_instance_count: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProofInventoryTotals {
    physical_proof_application_count: u32,
    logical_relation_instance_count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct RelationPlanBinding {
    family: &'static str,
    application_statement_schema_identifier: u16,
    canonical_plan_byte_length: usize,
    canonical_plan_hash: String,
    variants: Vec<RelationPlanVariantBinding>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct RelationPlanVariantBinding {
    schedule_position: Option<u32>,
    top_count: Option<u16>,
    canonical_variant_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct EvaluatorTopology {
    ordered_relinearization_entries: Vec<EvaluatorEntry>,
    ordered_galois_entries: Vec<EvaluatorEntry>,
    complete_action_entries: Vec<EvaluatorEntry>,
    ordered_data_primes: Vec<u64>,
    ordered_special_primes: Vec<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct EvaluatorEntry {
    kind: &'static str,
    schedule_position: u32,
    catalog_level: usize,
    galois_element: Option<usize>,
    data_prime_count: usize,
    special_prime_count: usize,
    decomposition_block_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct SampleCensus {
    rows: Vec<SampleCensusRow>,
    summary: SampleCensusSummary,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct SampleCensusRow {
    family: &'static str,
    catalog_level: usize,
    key_count: usize,
    decomposition_block_count: usize,
    source_relation_count: usize,
    deterministic_derived_relation_count: usize,
    public_relation_count: usize,
    common_uniform_polynomial_count: usize,
    generated_component_view_count: usize,
    distinct_public_polynomial_count: usize,
    duplicate_component_view_count: usize,
    relation_class: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct SampleCensusSummary {
    source_relation_count_per_participant: usize,
    source_relation_count_for_roster: usize,
    deterministic_derived_relation_count: usize,
    complete_public_relation_count: usize,
    final_runtime_key_relation_count: usize,
    common_uniform_polynomial_count: usize,
    generated_component_view_count: usize,
    distinct_public_polynomial_count: usize,
    duplicate_component_view_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct WitnessCommitmentTopology {
    ordered_vss_sharing_data_prime_coordinates: Vec<ModulusCoordinate>,
    anchor_commitment_data_prime_indices: Vec<usize>,
    anchor_commitment_module_rank: usize,
    anchor_hiding_secret_width: usize,
    anchor_hiding_error_width: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ModulusCoordinate {
    data_prime_index: u16,
    modulus: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct SetupCorrectnessAuthority {
    participant_secret_coefficient_bound: u64,
    participant_error_coefficient_bound: u64,
    collective_secret_coefficient_bound: u64,
    collective_error_coefficient_bound: u64,
    collective_public_key_scaled_error_coefficient_bound: u64,
    collective_public_key_minimum_centered_margins: Vec<u64>,
    key_switch_data_primes_per_block: usize,
    special_basis_modulus_product_decimal: String,
    special_basis_is_coprime_to_plaintext_modulus: bool,
    accepted_ballot_count_cases: usize,
    evaluator_target_trace_count: usize,
    maximum_evaluator_error_coefficient_bound_decimal: String,
    minimum_evaluator_decryption_margin_decimal: String,
    maximum_private_sampler_candidate_draws_per_output: u32,
    maximum_public_sampler_candidate_draws_per_output: u32,
}

fn family_name(application_statement_schema_identifier: u16) -> &'static str {
    match application_statement_schema_identifier {
        ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER => {
            "vssShareLinkage"
        }
        ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER => {
            "aggregateThresholdShare"
        }
        ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER => "sameSecret",
        ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER => {
            "publicKeyShare"
        }
        ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER => {
            "collectivePublicKeyAggregate"
        }
        ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER => {
            "relinearizationRoundOne"
        }
        ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER => {
            "relinearizationRoundOneAggregate"
        }
        ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER => {
            "relinearizationRoundTwo"
        }
        ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER => {
            "galoisKeyShareBatch"
        }
        ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER => {
            "evaluatorKeyAggregate"
        }
        _ => "outsideCollectiveSetup",
    }
}

fn combinations(
    participant_count: u16,
    corruption_count: u16,
    next_roster_position: u16,
    current: &mut Vec<u16>,
    output: &mut Vec<Vec<u16>>,
) {
    if current.len() == usize::from(corruption_count) {
        output.push(current.clone());
        return;
    }
    let remaining = corruption_count - u16::try_from(current.len()).expect("small roster subset");
    let last_start = participant_count - remaining;
    for roster_position in next_roster_position..=last_start {
        current.push(roster_position);
        combinations(
            participant_count,
            corruption_count,
            roster_position + 1,
            current,
            output,
        );
        current.pop();
    }
}

fn corruption_classes() -> Vec<CorruptionClass> {
    (0..=FOUNDATION_PROFILE.active_fault_bound)
        .map(|corruption_count| {
            let honest_participant_count = FOUNDATION_PROFILE.participant_count - corruption_count;
            let mut corruption_subsets = Vec::new();
            combinations(
                FOUNDATION_PROFILE.participant_count,
                corruption_count,
                0,
                &mut Vec::new(),
                &mut corruption_subsets,
            );
            let secret_bound = i16::try_from(honest_participant_count).expect("small roster bound");
            let error_bound = secret_bound * 2;
            CorruptionClass {
                corruption_count,
                honest_participant_count,
                honest_secret_support_before_known_shift: [-secret_bound, secret_bound],
                honest_error_support: [-error_bound, error_bound],
                corruption_subsets,
            }
        })
        .collect()
}

fn evaluator_entry(
    position: crate::bgv::proof_suite::SelectedEvaluatorEntryPosition,
) -> Result<EvaluatorEntry, String> {
    let (kind, catalog_level, galois_element) = match position.key_kind() {
        SelectedEvaluatorEntryKind::Relinearization { catalog_level } => {
            ("relinearization", catalog_level, None)
        }
        SelectedEvaluatorEntryKind::Galois {
            galois_element,
            catalog_level,
        } => ("galois", catalog_level, Some(galois_element)),
    };
    let topology = KeySwitchDecompositionTopology::for_level(catalog_level)
        .map_err(|error| format!("key-switch topology failed: {error}"))?;
    Ok(EvaluatorEntry {
        kind,
        schedule_position: position.schedule_position(),
        catalog_level,
        galois_element,
        data_prime_count: topology.data_prime_count(),
        special_prime_count: SPECIAL_PRIMES.len(),
        decomposition_block_count: topology.data_block_count(),
    })
}

fn derive_proof_inventory() -> Result<(Vec<ProofInventoryEntry>, ProofInventoryTotals), String> {
    let relinearization_positions = selected_evaluator_relinearization_entry_positions()
        .map_err(|error| format!("relinearization catalog failed: {error:?}"))?;
    let galois_positions = selected_evaluator_galois_entry_positions()
        .map_err(|error| format!("Galois catalog failed: {error:?}"))?;
    let complete_action_positions =
        selected_evaluator_entry_positions(FOUNDATION_PROFILE.option_count)
            .map_err(|error| format!("evaluator catalog failed: {error:?}"))?;
    let ceilings = ProofApplicationSlotCeilings::derive(
        FOUNDATION_PROFILE.participant_count,
        u32::try_from(relinearization_positions.len())
            .map_err(|_| "relinearization position count overflowed")?,
        if galois_positions.is_empty() { 0 } else { 1 },
        SELECTED_MAXIMUM_CANDIDATE_PACKAGES_PER_ACTION,
    )
    .map_err(|error| format!("proof application ceilings failed: {error:?}"))?;
    let inventory = ceilings
        .derive_proof_family_application_inventory(
            u32::try_from(galois_positions.len())
                .map_err(|_| "Galois position count overflowed")?,
            u32::try_from(complete_action_positions.len())
                .map_err(|_| "evaluator position count overflowed")?,
        )
        .map_err(|error| format!("proof application inventory failed: {error:?}"))?;
    let setup_inventory = inventory
        .ordered_family_entries()
        .iter()
        .filter(|entry| {
            SETUP_FAMILY_SCHEMA_IDENTIFIERS
                .contains(&entry.application_statement_schema_identifier())
        })
        .map(|entry| ProofInventoryEntry {
            family: family_name(entry.application_statement_schema_identifier()),
            application_statement_schema_identifier: entry
                .application_statement_schema_identifier(),
            physical_proof_application_count: entry.physical_proof_application_count(),
            logical_relation_instance_count: entry.logical_relation_instance_count(),
        })
        .collect::<Vec<_>>();
    let totals = setup_inventory
        .iter()
        .try_fold(
            ProofInventoryTotals {
                physical_proof_application_count: 0,
                logical_relation_instance_count: 0,
            },
            |totals, entry| {
                Some(ProofInventoryTotals {
                    physical_proof_application_count: totals
                        .physical_proof_application_count
                        .checked_add(entry.physical_proof_application_count)?,
                    logical_relation_instance_count: totals
                        .logical_relation_instance_count
                        .checked_add(entry.logical_relation_instance_count)?,
                })
            },
        )
        .ok_or_else(|| "setup proof inventory overflowed".to_owned())?;
    Ok((setup_inventory, totals))
}

fn derive_relation_plan_bindings() -> Result<Vec<RelationPlanBinding>, String> {
    let artifacts = selected_relation_plans()
        .map_err(|error| format!("selected relation plans failed: {error:?}"))?;
    let mut artifacts_by_family = artifacts
        .into_iter()
        .filter(|artifact| {
            SETUP_FAMILY_SCHEMA_IDENTIFIERS
                .contains(&artifact.application_statement_schema_identifier())
        })
        .map(|artifact| (artifact.application_statement_schema_identifier(), artifact))
        .collect::<BTreeMap<_, _>>();
    SETUP_FAMILY_SCHEMA_IDENTIFIERS
        .into_iter()
        .map(|application_statement_schema_identifier| {
            let artifact = artifacts_by_family
                .remove(&application_statement_schema_identifier)
                .ok_or_else(|| {
                    format!(
                        "setup family {application_statement_schema_identifier:#06x} has no relation plan"
                    )
                })?;
            let canonical_plan_bytes = artifact
                .compiled_plan()
                .canonical_bytes()
                .map_err(|error| format!("relation-plan encoding failed: {error:?}"))?;
            let canonical_plan_hash = artifact.canonical_plan_hash();
            if artifact
                .compiled_plan()
                .canonical_hash()
                .map_err(|error| format!("relation-plan hashing failed: {error:?}"))?
                != canonical_plan_hash
            {
                return Err("validated relation-plan hash disagrees with canonical bytes".to_owned());
            }
            let variants = artifact
                .compiled_plan()
                .variants()
                .iter()
                .map(|variant| {
                    Ok(RelationPlanVariantBinding {
                        schedule_position: variant.schedule_position(),
                        top_count: variant.top_count(),
                        canonical_variant_hash: encode_hex(&variant.canonical_hash().map_err(
                            |error| format!("relation-plan variant hashing failed: {error:?}"),
                        )?),
                    })
                })
                .collect::<Result<Vec<_>, String>>()?;
            Ok(RelationPlanBinding {
                family: family_name(application_statement_schema_identifier),
                application_statement_schema_identifier,
                canonical_plan_byte_length: canonical_plan_bytes.len(),
                canonical_plan_hash: encode_hex(&canonical_plan_hash),
                variants,
            })
        })
        .collect()
}

fn sample_census(evaluator_candidate: &EvaluatorCandidateInput) -> Result<SampleCensus, String> {
    let participant_count = usize::from(FOUNDATION_PROFILE.participant_count);
    let mut rows = vec![SampleCensusRow {
        family: "collectivePublicKey",
        catalog_level: evaluator_candidate.evaluator_working_level,
        key_count: 1,
        decomposition_block_count: 0,
        source_relation_count: participant_count,
        deterministic_derived_relation_count: 1,
        public_relation_count: participant_count + 1,
        common_uniform_polynomial_count: 1,
        generated_component_view_count: participant_count + 2,
        distinct_public_polynomial_count: participant_count + 2,
        duplicate_component_view_count: 0,
        relation_class: "ordinary marginal plus deterministic aggregate",
    }];
    for catalog_level in &evaluator_candidate.relinearization_levels {
        let block_count = KeySwitchDecompositionTopology::for_level(*catalog_level)
            .map_err(|error| format!("relinearization topology failed: {error}"))?
            .data_block_count();
        rows.push(SampleCensusRow {
            family: "relinearization",
            catalog_level: *catalog_level,
            key_count: 1,
            decomposition_block_count: block_count,
            source_relation_count: 3 * participant_count * block_count,
            deterministic_derived_relation_count: 3 * block_count,
            public_relation_count: 3 * (participant_count + 1) * block_count,
            common_uniform_polynomial_count: block_count,
            generated_component_view_count: 35 * block_count,
            distinct_public_polynomial_count: 34 * block_count,
            duplicate_component_view_count: block_count,
            relation_class: "joint secret-square circular or KDM exposure",
        });
    }
    let mut galois_key_count_by_level = BTreeMap::<usize, usize>::new();
    for (_, catalog_level) in &evaluator_candidate.galois_key_schedule {
        *galois_key_count_by_level.entry(*catalog_level).or_default() += 1;
    }
    for (catalog_level, key_count) in galois_key_count_by_level {
        let block_count = KeySwitchDecompositionTopology::for_level(catalog_level)
            .map_err(|error| format!("Galois topology failed: {error}"))?
            .data_block_count();
        let common_uniform_polynomial_count = key_count * block_count;
        let source_relation_count = participant_count * common_uniform_polynomial_count;
        let deterministic_derived_relation_count = common_uniform_polynomial_count;
        rows.push(SampleCensusRow {
            family: "galois",
            catalog_level,
            key_count,
            decomposition_block_count: block_count,
            source_relation_count,
            deterministic_derived_relation_count,
            public_relation_count: source_relation_count + deterministic_derived_relation_count,
            common_uniform_polynomial_count,
            generated_component_view_count: source_relation_count
                + 2 * common_uniform_polynomial_count,
            distinct_public_polynomial_count: source_relation_count
                + 2 * common_uniform_polynomial_count,
            duplicate_component_view_count: 0,
            relation_class: "transformed-secret circular or KDM exposure",
        });
    }
    let sum = |selector: fn(&SampleCensusRow) -> usize| rows.iter().map(selector).sum();
    let source_relation_count_for_roster = sum(|row| row.source_relation_count);
    let deterministic_derived_relation_count = sum(|row| row.deterministic_derived_relation_count);
    let common_uniform_polynomial_count = sum(|row| row.common_uniform_polynomial_count);
    let generated_component_view_count = sum(|row| row.generated_component_view_count);
    let distinct_public_polynomial_count = sum(|row| row.distinct_public_polynomial_count);
    let summary = SampleCensusSummary {
        source_relation_count_per_participant: source_relation_count_for_roster / participant_count,
        source_relation_count_for_roster,
        deterministic_derived_relation_count,
        complete_public_relation_count: source_relation_count_for_roster
            + deterministic_derived_relation_count,
        final_runtime_key_relation_count: 1 + rows
            .iter()
            .filter(|row| row.family != "collectivePublicKey")
            .map(|row| row.key_count * row.decomposition_block_count)
            .sum::<usize>(),
        common_uniform_polynomial_count,
        generated_component_view_count,
        distinct_public_polynomial_count,
        duplicate_component_view_count: generated_component_view_count
            - distinct_public_polynomial_count,
    };
    Ok(SampleCensus { rows, summary })
}

fn derive_setup_correctness_authority() -> Result<SetupCorrectnessAuthority, String> {
    let participant_secret_coefficient_bound = 1_u64;
    let participant_error_coefficient_bound = 2_u64;
    let participant_count = u64::from(FOUNDATION_PROFILE.participant_count);
    let collective_secret_coefficient_bound = participant_count
        .checked_mul(participant_secret_coefficient_bound)
        .ok_or_else(|| "collective secret bound overflowed".to_owned())?;
    let collective_error_coefficient_bound = participant_count
        .checked_mul(participant_error_coefficient_bound)
        .ok_or_else(|| "collective error bound overflowed".to_owned())?;
    let collective_public_key_scaled_error_coefficient_bound = PLAINTEXT_MODULUS
        .checked_mul(collective_error_coefficient_bound)
        .ok_or_else(|| "collective public-key error bound overflowed".to_owned())?;
    let collective_public_key_minimum_centered_margins = DATA_PRIMES
        .iter()
        .copied()
        .map(|modulus| {
            modulus
                .checked_div(2)
                .and_then(|half_modulus| {
                    half_modulus.checked_sub(collective_public_key_scaled_error_coefficient_bound)
                })
                .filter(|margin| *margin > 0)
                .ok_or_else(|| {
                    "collective public-key error exhausted a selected data-prime margin".to_owned()
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let special_basis_modulus_product = key_switch_special_basis_modulus_product();
    let special_basis_is_coprime_to_plaintext_modulus =
        (&special_basis_modulus_product % BigUint::from(PLAINTEXT_MODULUS)) != BigUint::zero();
    if PLAINTEXT_MODULUS != 257 || !special_basis_is_coprime_to_plaintext_modulus {
        return Err(
            "the selected special basis does not admit the plaintext correction".to_owned(),
        );
    }

    let mut evaluator_target_trace_count = 0_usize;
    let mut maximum_evaluator_error_coefficient_bound = BigUint::zero();
    let mut minimum_evaluator_decryption_margin: Option<BigInt> = None;
    for ballot_count in 1..=usize::from(FOUNDATION_PROFILE.participant_count) {
        let target_bounds = direct_ballot_target_noise_bounds(
            participant_count,
            ballot_count,
            usize::from(FOUNDATION_PROFILE.option_count),
            u64::from(FOUNDATION_PROFILE.minimum_score),
            u64::from(FOUNDATION_PROFILE.maximum_score),
        )
        .map_err(|error| format!("selected evaluator recurrence failed: {error:?}"))?;
        if target_bounds.len() != usize::from(FOUNDATION_PROFILE.option_count)
            || target_bounds
                .iter()
                .any(|bound| !bound.every_decryption_margin_is_positive())
        {
            return Err("selected evaluator recurrence has a non-positive margin".to_owned());
        }
        evaluator_target_trace_count = evaluator_target_trace_count
            .checked_add(target_bounds.len())
            .ok_or_else(|| "evaluator target trace count overflowed".to_owned())?;
        for bound in target_bounds {
            maximum_evaluator_error_coefficient_bound = maximum_evaluator_error_coefficient_bound
                .max(
                    bound
                        .target_identifier
                        .error_coefficient_bound
                        .clone()
                        .max(bound.target_order.error_coefficient_bound.clone()),
                );
            for margin in [
                bound.target_identifier.minimum_decryption_margin,
                bound.target_order.minimum_decryption_margin,
            ] {
                if !margin.is_positive() {
                    return Err(
                        "selected evaluator recurrence reached a non-positive margin".to_owned(),
                    );
                }
                minimum_evaluator_decryption_margin = Some(
                    minimum_evaluator_decryption_margin
                        .take()
                        .map_or(margin.clone(), |current| current.min(margin)),
                );
            }
        }
    }
    let minimum_evaluator_decryption_margin = minimum_evaluator_decryption_margin
        .ok_or_else(|| "selected evaluator recurrence produced no target margin".to_owned())?;

    Ok(SetupCorrectnessAuthority {
        participant_secret_coefficient_bound,
        participant_error_coefficient_bound,
        collective_secret_coefficient_bound,
        collective_error_coefficient_bound,
        collective_public_key_scaled_error_coefficient_bound,
        collective_public_key_minimum_centered_margins,
        key_switch_data_primes_per_block: KEY_SWITCH_DATA_PRIMES_PER_BLOCK,
        special_basis_modulus_product_decimal: special_basis_modulus_product.to_str_radix(10),
        special_basis_is_coprime_to_plaintext_modulus,
        accepted_ballot_count_cases: usize::from(FOUNDATION_PROFILE.participant_count),
        evaluator_target_trace_count,
        maximum_evaluator_error_coefficient_bound_decimal:
            maximum_evaluator_error_coefficient_bound.to_str_radix(10),
        minimum_evaluator_decryption_margin_decimal: minimum_evaluator_decryption_margin
            .to_str_radix(10),
        maximum_private_sampler_candidate_draws_per_output:
            SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT,
        maximum_public_sampler_candidate_draws_per_output:
            SELECTED_MAXIMUM_PUBLIC_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT,
    })
}

fn derive_production_authority() -> Result<CollectiveSetupSecurityAuthority, String> {
    let evaluator_candidate = EvaluatorCandidateInput::implemented()
        .map_err(|error| format!("evaluator candidate failed: {error}"))?;
    let ordered_relinearization_entries = selected_evaluator_relinearization_entry_positions()
        .map_err(|error| format!("relinearization entries failed: {error:?}"))?
        .into_iter()
        .map(evaluator_entry)
        .collect::<Result<Vec<_>, _>>()?;
    let ordered_galois_entries = selected_evaluator_galois_entry_positions()
        .map_err(|error| format!("Galois entries failed: {error:?}"))?
        .into_iter()
        .map(evaluator_entry)
        .collect::<Result<Vec<_>, _>>()?;
    let complete_action_entries =
        selected_evaluator_entry_positions(FOUNDATION_PROFILE.option_count)
            .map_err(|error| format!("complete evaluator entries failed: {error:?}"))?
            .into_iter()
            .map(evaluator_entry)
            .collect::<Result<Vec<_>, _>>()?;
    let (proof_inventory, proof_inventory_totals) = derive_proof_inventory()?;
    Ok(CollectiveSetupSecurityAuthority {
        profile: SelectedRosterProfile {
            participant_count: FOUNDATION_PROFILE.participant_count,
            active_fault_bound: FOUNDATION_PROFILE.active_fault_bound,
            reconstruction_threshold: FOUNDATION_PROFILE.reconstruction_threshold,
            finality_quorum: FOUNDATION_PROFILE.finality_quorum,
            state_witness_quorum: FOUNDATION_PROFILE.state_witness_quorum,
            option_count: FOUNDATION_PROFILE.option_count,
            polynomial_degree: POLYNOMIAL_DEGREE,
            plaintext_modulus: PLAINTEXT_MODULUS,
        },
        corruption_classes: corruption_classes(),
        proof_inventory,
        proof_inventory_totals,
        relation_plan_bindings: derive_relation_plan_bindings()?,
        evaluator_topology: EvaluatorTopology {
            ordered_relinearization_entries,
            ordered_galois_entries,
            complete_action_entries,
            ordered_data_primes: DATA_PRIMES.to_vec(),
            ordered_special_primes: SPECIAL_PRIMES.to_vec(),
        },
        sample_census: sample_census(&evaluator_candidate)?,
        witness_commitment_topology: WitnessCommitmentTopology {
            ordered_vss_sharing_data_prime_coordinates: selected_sharing_data_prime_coordinates()
                .map_err(|error| format!("sharing coordinates failed: {error:?}"))?
                .iter()
                .map(|(data_prime_index, modulus)| ModulusCoordinate {
                    data_prime_index: *data_prime_index,
                    modulus: *modulus,
                })
                .collect(),
            anchor_commitment_data_prime_indices: SETUP_COMMITMENT_MODULUS_LIMB_INDICES.to_vec(),
            anchor_commitment_module_rank: SETUP_COMMITMENT_MODULE_RANK,
            anchor_hiding_secret_width: SETUP_COMMITMENT_HIDING_SECRET_WIDTH,
            anchor_hiding_error_width: SETUP_COMMITMENT_HIDING_ERROR_WIDTH,
        },
        setup_correctness: derive_setup_correctness_authority()?,
    })
}

fn production_authority() -> &'static CollectiveSetupSecurityAuthority {
    static PRODUCTION_AUTHORITY: OnceLock<CollectiveSetupSecurityAuthority> = OnceLock::new();
    PRODUCTION_AUTHORITY.get_or_init(|| {
        derive_production_authority().expect("collective-setup production authority must derive")
    })
}

fn validate_production_authority(
    candidate: &CollectiveSetupSecurityAuthority,
) -> Result<(), &'static str> {
    if candidate != production_authority() {
        return Err("collective-setup security authority is stale or mismatched");
    }
    Ok(())
}

fn assert_collective_setup_security_authority_derives_exact_roster_inventory_and_samples() {
    let authority = production_authority();
    assert_eq!(authority.profile.participant_count, 10);
    assert_eq!(authority.profile.active_fault_bound, 3);
    assert_eq!(authority.profile.reconstruction_threshold, 4);
    assert_eq!(authority.profile.finality_quorum, 7);
    assert_eq!(authority.profile.state_witness_quorum, 7);
    assert_eq!(
        authority.profile.option_count,
        FOUNDATION_PROFILE.option_count
    );
    assert_eq!(authority.profile.polynomial_degree, 32_768);
    assert_eq!(authority.profile.plaintext_modulus, 257);
    assert_eq!(authority.proof_inventory.len(), 10);
    assert_eq!(
        authority.proof_inventory_totals,
        authority.proof_inventory.iter().fold(
            ProofInventoryTotals {
                physical_proof_application_count: 0,
                logical_relation_instance_count: 0,
            },
            |totals, entry| ProofInventoryTotals {
                physical_proof_application_count: totals.physical_proof_application_count
                    + entry.physical_proof_application_count,
                logical_relation_instance_count: totals.logical_relation_instance_count
                    + entry.logical_relation_instance_count,
            },
        )
    );
    assert_eq!(authority.relation_plan_bindings.len(), 10);
    assert_eq!(
        authority
            .relation_plan_bindings
            .iter()
            .map(|binding| binding.variants.len())
            .sum::<usize>(),
        authority.relation_plan_bindings.len() - 1 + usize::from(FOUNDATION_PROFILE.option_count)
    );
    assert_eq!(
        authority
            .evaluator_topology
            .ordered_relinearization_entries
            .len(),
        1
    );
    assert_eq!(authority.evaluator_topology.ordered_galois_entries.len(), 6);
    assert_eq!(
        authority.evaluator_topology.complete_action_entries.len(),
        authority
            .evaluator_topology
            .ordered_relinearization_entries
            .len()
            + authority.evaluator_topology.ordered_galois_entries.len()
    );
    assert_eq!(
        authority.sample_census.summary,
        SampleCensusSummary {
            source_relation_count_per_participant: 61,
            source_relation_count_for_roster: 610,
            deterministic_derived_relation_count: 61,
            complete_public_relation_count: 671,
            final_runtime_key_relation_count: 45,
            common_uniform_polynomial_count: 45,
            generated_component_view_count: 724,
            distinct_public_polynomial_count: 716,
            duplicate_component_view_count: 8,
        }
    );
    assert_eq!(
        authority
            .witness_commitment_topology
            .ordered_vss_sharing_data_prime_coordinates
            .iter()
            .map(|coordinate| coordinate.data_prime_index)
            .collect::<Vec<_>>(),
        (0_u16..8).collect::<Vec<_>>()
    );
    assert_eq!(
        authority
            .witness_commitment_topology
            .anchor_commitment_data_prime_indices,
        [0, 1, 2]
    );
    assert_eq!(
        authority
            .setup_correctness
            .collective_secret_coefficient_bound,
        10
    );
    assert_eq!(
        authority
            .setup_correctness
            .collective_error_coefficient_bound,
        20
    );
    assert_eq!(
        authority
            .setup_correctness
            .collective_public_key_scaled_error_coefficient_bound,
        5_140
    );
    assert_eq!(
        authority
            .setup_correctness
            .collective_public_key_minimum_centered_margins
            .len(),
        DATA_PRIMES.len()
    );
    assert!(
        authority
            .setup_correctness
            .collective_public_key_minimum_centered_margins
            .iter()
            .all(|margin| *margin > 0)
    );
    assert_eq!(
        authority.setup_correctness.key_switch_data_primes_per_block,
        3
    );
    assert!(
        authority
            .setup_correctness
            .special_basis_is_coprime_to_plaintext_modulus
    );
    assert_eq!(
        authority.setup_correctness.accepted_ballot_count_cases,
        usize::from(FOUNDATION_PROFILE.participant_count)
    );
    assert_eq!(
        authority.setup_correctness.evaluator_target_trace_count,
        usize::from(FOUNDATION_PROFILE.participant_count)
            * usize::from(FOUNDATION_PROFILE.option_count)
    );
    assert_eq!(
        authority
            .setup_correctness
            .maximum_private_sampler_candidate_draws_per_output,
        64
    );
    assert_eq!(
        authority
            .setup_correctness
            .maximum_public_sampler_candidate_draws_per_output,
        128
    );
}

fn assert_collective_setup_security_authority_enumerates_every_static_corruption_subset() {
    let authority = production_authority();
    let all_subsets = authority
        .corruption_classes
        .iter()
        .flat_map(|corruption_class| corruption_class.corruption_subsets.iter())
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(all_subsets.len(), 176);
    assert_eq!(
        all_subsets.iter().cloned().collect::<BTreeSet<_>>().len(),
        176
    );
    for corruption_class in &authority.corruption_classes {
        assert!(corruption_class.corruption_subsets.iter().all(|subset| {
            subset.len() == usize::from(corruption_class.corruption_count)
                && subset.windows(2).all(|pair| pair[0] < pair[1])
                && subset
                    .iter()
                    .all(|position| *position < FOUNDATION_PROFILE.participant_count)
        }));
    }
}

fn assert_collective_setup_security_authority_binds_every_plan_and_variant() {
    let authority = production_authority();
    assert_eq!(
        authority
            .relation_plan_bindings
            .iter()
            .map(|binding| binding.application_statement_schema_identifier)
            .collect::<Vec<_>>(),
        SETUP_FAMILY_SCHEMA_IDENTIFIERS
    );
    for binding in &authority.relation_plan_bindings {
        assert!(binding.canonical_plan_byte_length > 0);
        assert_eq!(binding.canonical_plan_hash.len(), 128);
        assert!(!binding.variants.is_empty());
        assert_eq!(
            binding
                .variants
                .iter()
                .map(|variant| (variant.schedule_position, variant.top_count))
                .collect::<BTreeSet<_>>()
                .len(),
            binding.variants.len()
        );
        assert!(
            binding
                .variants
                .iter()
                .all(|variant| variant.canonical_variant_hash.len() == 128)
        );
    }
    let evaluator_binding = authority
        .relation_plan_bindings
        .iter()
        .find(|binding| binding.family == "evaluatorKeyAggregate")
        .expect("evaluator aggregate relation plan");
    assert_eq!(
        evaluator_binding
            .variants
            .iter()
            .map(|variant| variant.top_count)
            .collect::<Vec<_>>(),
        (1..=FOUNDATION_PROFILE.option_count)
            .map(Some)
            .collect::<Vec<_>>()
    );
}

fn assert_collective_setup_security_authority_refuses_mutated_production_facts() {
    let authority = production_authority();
    validate_production_authority(authority).expect("fresh authority validates");

    let mut changed_plan_hash = (*authority).clone();
    let replacement = if changed_plan_hash.relation_plan_bindings[0]
        .canonical_plan_hash
        .starts_with("00")
    {
        "01"
    } else {
        "00"
    };
    changed_plan_hash.relation_plan_bindings[0]
        .canonical_plan_hash
        .replace_range(0..2, replacement);
    assert!(validate_production_authority(&changed_plan_hash).is_err());

    let mut missing_corruption_subset = (*authority).clone();
    missing_corruption_subset.corruption_classes[3]
        .corruption_subsets
        .pop();
    assert!(validate_production_authority(&missing_corruption_subset).is_err());

    let mut changed_multiplicity = (*authority).clone();
    changed_multiplicity.proof_inventory[0].physical_proof_application_count -= 1;
    assert!(validate_production_authority(&changed_multiplicity).is_err());

    let mut changed_sample_correlation = (*authority).clone();
    changed_sample_correlation
        .sample_census
        .rows
        .iter_mut()
        .find(|row| row.family == "relinearization")
        .expect("relinearization sample row")
        .duplicate_component_view_count = 0;
    assert!(validate_production_authority(&changed_sample_correlation).is_err());

    let mut changed_correctness_margin = (*authority).clone();
    changed_correctness_margin
        .setup_correctness
        .collective_public_key_minimum_centered_margins[0] = 0;
    assert!(validate_production_authority(&changed_correctness_margin).is_err());
}

fn assert_checked_collective_setup_security_record_uses_the_live_production_authority() {
    let checked_record: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/selected-collective-setup-security-evidence.json"
    )))
    .expect("checked collective-setup security record parses");
    assert_eq!(
        checked_record
            .get("productionAuthority")
            .expect("checked record has production authority"),
        &serde_json::to_value(production_authority()).expect("production authority serializes")
    );
}

#[test]
#[ignore = "guarded collective-setup production-authority export"]
fn collective_setup_security_production_authority_exports_for_refresh() {
    assert_collective_setup_security_authority_derives_exact_roster_inventory_and_samples();
    assert_collective_setup_security_authority_enumerates_every_static_corruption_subset();
    assert_collective_setup_security_authority_binds_every_plan_and_variant();
    assert_collective_setup_security_authority_refuses_mutated_production_facts();

    let output_path = std::env::var_os(PRODUCTION_AUTHORITY_EXPORT_PATH_ENVIRONMENT_VARIABLE)
        .map(std::path::PathBuf::from)
        .expect("the production-authority export path must be provided");
    let parent_path = output_path
        .parent()
        .expect("the production-authority export path must have a parent");
    fs::create_dir_all(parent_path).expect("the production-authority export directory is created");
    let serialized_authority = serde_json::to_string_pretty(production_authority())
        .expect("production authority serializes");
    fs::write(output_path, format!("{serialized_authority}\n"))
        .expect("the production authority is exported by the focused owner");
}

#[test]
#[ignore = "guarded complete collective-setup construction-authority evidence"]
fn collective_setup_security_production_authority_closes_complete_evidence() {
    assert_collective_setup_security_authority_derives_exact_roster_inventory_and_samples();
    assert_collective_setup_security_authority_enumerates_every_static_corruption_subset();
    assert_collective_setup_security_authority_binds_every_plan_and_variant();
    assert_collective_setup_security_authority_refuses_mutated_production_facts();
    assert_checked_collective_setup_security_record_uses_the_live_production_authority();

    println!(
        "{}",
        serde_json::to_string_pretty(production_authority())
            .expect("production authority serializes")
    );
}
