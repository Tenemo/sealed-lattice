//! Bounded, opt-in measurements of exact production primitive owners.
//!
//! The feature is absent from the ordinary kernel. It exposes no proof,
//! verification, source-authentication, or capability surface; only a small
//! deterministic result record crosses the Wasm boundary.

use core::{
    hint::black_box,
    mem::{size_of, size_of_val},
};
use std::collections::{BTreeMap, BTreeSet};

use p3_goldilocks::Goldilocks;
use serde::Serialize;
use sha3::Shake256;
use zeroize::Zeroizing;

use super::super::relation_plan::{
    COMMITTED_MATERIAL_TRACE_PACKING_FACTOR, derive_vss_relation_packing_candidate_geometry,
};
use super::{
    bounded_dft::{
        BoundedBaseCosetLaneDft, BoundedSelectedBaseCosetLaneDft, SelectedBaseCosetLaneDftSchedule,
    },
    column_commitment::{
        ColumnDigest, hash_merkle_parent, hash_opened_column_with_salt,
        salted_phase_column_leaf_keccak_permutation_count,
    },
    commitment_liveness::{
        ROOT_AND_OPENING_PASS_COUNT, derive_phase_commitment_geometry_accounting,
    },
    construction_plan::{
        ROW_CODE_WHIR_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT,
        ROW_CODE_WHIR_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW, ROW_CODE_WHIR_OUTER_QUERY_COUNT,
        RowCodeWhirAggregateColumnRole, RowCodeWhirConstructionPlan,
        RowCodeWhirConstructionPlanError,
    },
    hiding_whir::selected_hiding_whir_config,
    opening_claim_reduction::OpeningClaimQuotientBatchGeometry,
    private_leaf_salt::{
        PRIVATE_LEAF_SALT_BYTE_LENGTH, derive_private_leaf_salt,
        private_leaf_salt_derivation_workspace_byte_length,
    },
    row_encoding::{
        PRIVATE_ROW_PAD_SEED_BYTE_LENGTH, RowCodeHighHalfSource, RowEncodingGeometry,
        padded_base_row_coefficients,
    },
};
use crate::bgv::proof_suite::{
    PROOF_BASE_FIELD_MODULUS, PROOF_EVALUATION_COSET_OFFSET, ProofBaseFieldElement,
    ProofEvaluationDomain, ProofProfileError, RelationTreeDescriptor,
    SelectedVssSourceReplayMeasurement, ValidatedRelationPlanArtifact,
    compile_vss_share_linkage_relation_plan,
    prover::relation_reversed_column_bindings,
    relation_plan::{BoundTreeConstructionKind, ProofPrivacyMode, RelationColumnOrigin},
    selected_committed_material_relation_plan_input, selected_relation_plan_check_context,
};
use crate::foundation::{
    MAXIMUM_LOCAL_RECORD_PLAINTEXT_BYTE_LENGTH, ProofApplicationSlotCeilings,
    measure_common_proof_scratch_record_codec,
};

const MEASUREMENT_SCHEMA_VERSION: u16 = 2;
const PHASE_ENCODED_COLUMN_COUNT: usize = 1 << 24;
const PHASE_LANE_COLUMN_COUNT: usize = 1 << 19;
const PHASE_LOGICAL_LEAF_WIDTH: usize = 1_128;
const DFT_BUTTERFLY_COUNT: u64 = 4_980_736;
const SALTED_LEAF_ITERATION_COUNT: usize = 512;
const PRIVATE_SALT_ITERATION_COUNT: usize = 4_096;
const FIVE_LEVEL_CARRY_ITERATION_COUNT: usize = 32_768;
const SOURCE_REPLAY_ITERATION_COUNT: usize = 4;
const PRODUCTION_WEIGHTED_SOURCE_REPLAY_ITERATION_COUNT: usize = 1;
const VSS_RELATION_REPLAY_CANDIDATE_RETAINED_GROUP_WIDTH: usize = 64;
const VSS_RELATION_REPLAY_CANDIDATE_TRACE_PACKING_FACTOR: u64 = 16;
const VSS_RELATION_REPLAY_CANDIDATE_LANE_ORDINAL: usize = 0;
const AUTHENTICATED_SCRATCH_RECORD_ITERATION_COUNT: usize = 8;
const SELECTED_CHECKPOINT_LEVEL: u32 = 2;

#[cfg(target_arch = "wasm32")]
#[link(wasm_import_module = "env")]
unsafe extern "C" {
    fn sealed_lattice_primitive_measurement_now_milliseconds() -> f64;
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PrimitiveMeasurementDimension {
    name: &'static str,
    value: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PrimitiveMeasurementRecord {
    schema_version: u16,
    case_identifier: u32,
    case_name: &'static str,
    execution_target: &'static str,
    iteration_count: u64,
    elapsed_nanoseconds: u64,
    modeled_peak_live_byte_length: u64,
    checksum_hex: String,
    dimensions: Vec<PrimitiveMeasurementDimension>,
}

fn dimension(name: &'static str, value: usize) -> Result<PrimitiveMeasurementDimension, String> {
    Ok(PrimitiveMeasurementDimension {
        name,
        value: u64::try_from(value)
            .map_err(|_| format!("primitive measurement dimension {name} exceeds u64"))?,
    })
}

const fn dimension_u64(name: &'static str, value: u64) -> PrimitiveMeasurementDimension {
    PrimitiveMeasurementDimension { name, value }
}

fn execution_target() -> &'static str {
    if cfg!(target_arch = "wasm32") {
        "wasm32-unknown-unknown"
    } else {
        "release-native"
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn measure_elapsed_nanoseconds<ResultValue>(
    operation: impl FnOnce() -> Result<ResultValue, String>,
) -> Result<(ResultValue, u64), String> {
    let started_at = std::time::Instant::now();
    let result = operation()?;
    let elapsed = u64::try_from(started_at.elapsed().as_nanos())
        .map_err(|_| "primitive measurement duration exceeds u64 nanoseconds".to_owned())?;
    if elapsed == 0 {
        return Err("primitive measurement clock did not advance".to_owned());
    }
    Ok((result, elapsed))
}

#[cfg(target_arch = "wasm32")]
fn measure_elapsed_nanoseconds<ResultValue>(
    operation: impl FnOnce() -> Result<ResultValue, String>,
) -> Result<(ResultValue, u64), String> {
    let started_at = unsafe { sealed_lattice_primitive_measurement_now_milliseconds() };
    let result = operation()?;
    let finished_at = unsafe { sealed_lattice_primitive_measurement_now_milliseconds() };
    let elapsed_nanoseconds = (finished_at - started_at) * 1_000_000.0;
    if !started_at.is_finite()
        || !finished_at.is_finite()
        || elapsed_nanoseconds <= 0.0
        || elapsed_nanoseconds > u64::MAX as f64
    {
        return Err("primitive measurement clock returned an invalid duration".to_owned());
    }
    Ok((result, elapsed_nanoseconds.round() as u64))
}

fn measurement_lane_coefficients() -> Result<Vec<ProofBaseFieldElement>, String> {
    let mut coefficients = Vec::new();
    coefficients
        .try_reserve_exact(PHASE_LANE_COLUMN_COUNT)
        .map_err(|_| "lane DFT coefficient allocation failed".to_owned())?;
    for coefficient_ordinal in 0..PHASE_LANE_COLUMN_COUNT {
        let ordinal = u64::try_from(coefficient_ordinal)
            .map_err(|_| "lane DFT coefficient ordinal exceeds u64".to_owned())?;
        coefficients.push(
            ProofBaseFieldElement::from_canonical(
                ordinal.wrapping_mul(65_537).wrapping_add(17) % PROOF_BASE_FIELD_MODULUS,
            )
            .map_err(|_| "lane DFT coefficient is noncanonical".to_owned())?,
        );
    }
    Ok(coefficients)
}

fn measure_lane_dft() -> Result<PrimitiveMeasurementRecord, String> {
    let coefficients = measurement_lane_coefficients()?;
    let full_domain =
        ProofEvaluationDomain::new(PHASE_ENCODED_COLUMN_COUNT, PROOF_EVALUATION_COSET_OFFSET)
            .map_err(|_| "lane DFT domain is invalid".to_owned())?;
    let mut transform = BoundedBaseCosetLaneDft::new(
        Zeroizing::new(coefficients),
        full_domain,
        PHASE_LANE_COLUMN_COUNT,
        0,
    )?;
    let ((values, poll_count), elapsed_nanoseconds) = measure_elapsed_nanoseconds(|| {
        let mut poll_count = 0_usize;
        loop {
            poll_count = poll_count
                .checked_add(1)
                .ok_or_else(|| "lane DFT poll count overflowed".to_owned())?;
            if transform.poll()? {
                break;
            }
        }
        Ok((transform.into_values()?, poll_count))
    })?;
    if values.len() != PHASE_LANE_COLUMN_COUNT {
        return Err("lane DFT returned the wrong value count".to_owned());
    }
    let checksum = values
        .iter()
        .fold(0_u64, |accumulated, value| accumulated ^ value.canonical());
    black_box(checksum);
    Ok(PrimitiveMeasurementRecord {
        schema_version: MEASUREMENT_SCHEMA_VERSION,
        case_identifier: 1,
        case_name: "bounded-phase-lane-dft",
        execution_target: execution_target(),
        iteration_count: 1,
        elapsed_nanoseconds,
        modeled_peak_live_byte_length: u64::try_from(
            PHASE_LANE_COLUMN_COUNT
                .checked_mul(size_of::<ProofBaseFieldElement>())
                .and_then(|length| length.checked_add(size_of::<BoundedBaseCosetLaneDft>()))
                .ok_or_else(|| "lane DFT live-set size overflowed".to_owned())?,
        )
        .map_err(|_| "lane DFT live-set size exceeds u64".to_owned())?,
        checksum_hex: format!("{checksum:016x}"),
        dimensions: vec![
            dimension("fullDomainSize", PHASE_ENCODED_COLUMN_COUNT)?,
            dimension("laneColumnCount", PHASE_LANE_COLUMN_COUNT)?,
            dimension("butterflyCount", DFT_BUTTERFLY_COUNT as usize)?,
            dimension("pollCount", poll_count)?,
        ],
    })
}

fn measure_selected_vss_checkpoint_opening_lane_dfts() -> Result<PrimitiveMeasurementRecord, String>
{
    let work_ledger = derive_selected_vss_base_phase_work_ledger()?;
    let checkpoint_leaf_count = 1_u64
        .checked_shl(SELECTED_CHECKPOINT_LEVEL)
        .ok_or_else(|| "selected checkpoint leaf count overflowed".to_owned())?;
    let maximum_recomputed_leaf_count = work_ledger
        .opening_query_count
        .checked_mul(checkpoint_leaf_count)
        .ok_or_else(|| "selected checkpoint recomputed-leaf count overflowed".to_owned())?;
    let lane_count = usize::try_from(work_ledger.lane_count)
        .map_err(|_| "selected checkpoint lane count exceeds usize".to_owned())?;
    let maximum_recomputed_leaf_count = usize::try_from(maximum_recomputed_leaf_count)
        .map_err(|_| "selected checkpoint recomputed-leaf count exceeds usize".to_owned())?;
    if lane_count != PHASE_ENCODED_COLUMN_COUNT / PHASE_LANE_COLUMN_COUNT
        || maximum_recomputed_leaf_count == 0
    {
        return Err("selected checkpoint opening geometry is inconsistent".to_owned());
    }
    let lower_selected_output_count = maximum_recomputed_leaf_count / lane_count;
    let higher_selected_output_count = maximum_recomputed_leaf_count.div_ceil(lane_count);
    let higher_output_lane_count = maximum_recomputed_leaf_count % lane_count;
    let lower_output_lane_count = lane_count
        .checked_sub(higher_output_lane_count)
        .ok_or_else(|| "selected checkpoint balanced-lane count underflowed".to_owned())?;
    if lower_selected_output_count == 0
        || higher_selected_output_count != lower_selected_output_count + 1
        || higher_output_lane_count == 0
    {
        return Err("selected checkpoint balanced-lane geometry is degenerate".to_owned());
    }

    // The first 387 distinct four-leaf checkpoint blocks induce exactly 49
    // consecutive within-lane coordinates in twelve lanes and 48 in the
    // remaining twenty. Consecutive coordinates attain the dependency-count
    // upper bound at every DFT layer, so this is an executable conservative
    // projection rather than a favorable sampled schedule.
    let lower_selected_indices = (0..lower_selected_output_count).collect::<Vec<_>>();
    let higher_selected_indices = (0..higher_selected_output_count).collect::<Vec<_>>();
    let lower_schedule =
        SelectedBaseCosetLaneDftSchedule::new(PHASE_LANE_COLUMN_COUNT, &lower_selected_indices)?;
    let higher_schedule =
        SelectedBaseCosetLaneDftSchedule::new(PHASE_LANE_COLUMN_COUNT, &higher_selected_indices)?;
    if lower_schedule.butterfly_count() != lower_schedule.maximum_butterfly_count_upper_bound()
        || higher_schedule.butterfly_count()
            != higher_schedule.maximum_butterfly_count_upper_bound()
    {
        return Err("selected checkpoint benchmark does not attain its DFT work bound".to_owned());
    }
    let full_domain =
        ProofEvaluationDomain::new(PHASE_ENCODED_COLUMN_COUNT, PROOF_EVALUATION_COSET_OFFSET)
            .map_err(|_| "selected checkpoint DFT domain is invalid".to_owned())?;
    let coefficients = Zeroizing::new(measurement_lane_coefficients()?);
    let ((checksum, poll_count, selected_value_count), elapsed_nanoseconds) =
        measure_elapsed_nanoseconds(|| {
            let mut checksum = 0xcbf2_9ce4_8422_2325_u64;
            let mut poll_count = 0_usize;
            let mut selected_value_count = 0_usize;
            for lane_ordinal in 0..lane_count {
                let schedule = if lane_ordinal < higher_output_lane_count {
                    higher_schedule.clone()
                } else {
                    lower_schedule.clone()
                };
                let mut transform = BoundedSelectedBaseCosetLaneDft::new(
                    Zeroizing::new(coefficients.as_slice().to_vec()),
                    full_domain,
                    lane_ordinal,
                    schedule,
                )?;
                loop {
                    poll_count = poll_count.checked_add(1).ok_or_else(|| {
                        "selected checkpoint DFT poll count overflowed".to_owned()
                    })?;
                    if transform.poll()? {
                        break;
                    }
                }
                let selected_values = transform.into_selected_values()?;
                selected_value_count = selected_value_count
                    .checked_add(selected_values.len())
                    .ok_or_else(|| "selected checkpoint DFT output count overflowed".to_owned())?;
                for (within_lane_index, value) in selected_values {
                    checksum = checksum
                        .rotate_left(17)
                        .wrapping_add(value.canonical())
                        .wrapping_add(
                            u64::try_from(lane_ordinal)
                                .map_err(|_| "selected lane ordinal exceeds u64".to_owned())?
                                .rotate_left(11),
                        )
                        .wrapping_add(
                            u64::try_from(within_lane_index)
                                .map_err(|_| "selected output index exceeds u64".to_owned())?
                                .rotate_left(37),
                        )
                        .wrapping_mul(0x1000_0000_01b3);
                }
            }
            Ok((checksum, poll_count, selected_value_count))
        })?;
    if selected_value_count != maximum_recomputed_leaf_count {
        return Err("selected checkpoint DFT returned the wrong value count".to_owned());
    }
    black_box(checksum);

    let lower_schedule_byte_length = lower_schedule.exact_heap_byte_length()?;
    let higher_schedule_byte_length = higher_schedule.exact_heap_byte_length()?;
    let active_schedule_byte_length = lower_schedule_byte_length.max(higher_schedule_byte_length);
    let coefficient_buffer_byte_length = PHASE_LANE_COLUMN_COUNT
        .checked_mul(size_of::<ProofBaseFieldElement>())
        .ok_or_else(|| "selected checkpoint coefficient-buffer size overflowed".to_owned())?;
    let maximum_selected_output_byte_length = higher_selected_output_count
        .checked_mul(size_of::<(usize, ProofBaseFieldElement)>())
        .ok_or_else(|| "selected checkpoint output size overflowed".to_owned())?;
    let runtime_peak = coefficient_buffer_byte_length
        .checked_mul(2)
        .and_then(|total| total.checked_add(lower_schedule_byte_length))
        .and_then(|total| total.checked_add(higher_schedule_byte_length))
        .and_then(|total| total.checked_add(active_schedule_byte_length))
        .and_then(|total| total.checked_add(maximum_selected_output_byte_length))
        .and_then(|total| total.checked_add(size_of::<BoundedSelectedBaseCosetLaneDft>()))
        .ok_or_else(|| "selected checkpoint DFT live set overflowed".to_owned())?;
    let schedule_construction_peak = lower_schedule_byte_length
        .checked_add(higher_schedule.maximum_construction_workspace_byte_length()?)
        .and_then(|total| total.checked_add(coefficient_buffer_byte_length))
        .ok_or_else(|| "selected checkpoint schedule live set overflowed".to_owned())?;
    let modeled_peak_live_byte_length = runtime_peak.max(schedule_construction_peak);
    let executed_butterfly_count = higher_schedule
        .butterfly_count()
        .checked_mul(higher_output_lane_count)
        .and_then(|total| {
            lower_schedule
                .butterfly_count()
                .checked_mul(lower_output_lane_count)
                .and_then(|lower| total.checked_add(lower))
        })
        .ok_or_else(|| "selected checkpoint butterfly count overflowed".to_owned())?;
    let full_lane_butterfly_count = usize::try_from(DFT_BUTTERFLY_COUNT)
        .map_err(|_| "full lane butterfly count exceeds usize".to_owned())?;
    let full_butterfly_count = full_lane_butterfly_count
        .checked_mul(lane_count)
        .ok_or_else(|| "full checkpoint opening butterfly count overflowed".to_owned())?;

    Ok(PrimitiveMeasurementRecord {
        schema_version: MEASUREMENT_SCHEMA_VERSION,
        case_identifier: 7,
        case_name: "selected-vss-checkpoint-opening-lane-dfts",
        execution_target: execution_target(),
        iteration_count: u64::try_from(lane_count)
            .map_err(|_| "selected checkpoint iteration count exceeds u64".to_owned())?,
        elapsed_nanoseconds,
        modeled_peak_live_byte_length: u64::try_from(modeled_peak_live_byte_length)
            .map_err(|_| "selected checkpoint DFT live set exceeds u64".to_owned())?,
        checksum_hex: format!("{checksum:016x}"),
        dimensions: vec![
            dimension("fullDomainSize", PHASE_ENCODED_COLUMN_COUNT)?,
            dimension("laneColumnCount", PHASE_LANE_COLUMN_COUNT)?,
            dimension("laneCount", lane_count)?,
            dimension_u64("checkpointLevel", u64::from(SELECTED_CHECKPOINT_LEVEL)),
            dimension_u64("checkpointLeafCount", checkpoint_leaf_count),
            dimension("maximumRecomputedLeafCount", maximum_recomputed_leaf_count)?,
            dimension("higherOutputLaneCount", higher_output_lane_count)?,
            dimension("higherSelectedOutputCount", higher_selected_output_count)?,
            dimension("lowerOutputLaneCount", lower_output_lane_count)?,
            dimension("lowerSelectedOutputCount", lower_selected_output_count)?,
            dimension("selectedValueCount", selected_value_count)?,
            dimension("executedButterflyCount", executed_butterfly_count)?,
            dimension("fullButterflyCount", full_butterfly_count)?,
            dimension("pollCount", poll_count)?,
            dimension("lowerScheduleHeapByteLength", lower_schedule_byte_length)?,
            dimension("higherScheduleHeapByteLength", higher_schedule_byte_length)?,
            dimension(
                "scheduleConstructionWorkspaceByteLength",
                higher_schedule.maximum_construction_workspace_byte_length()?,
            )?,
        ],
    })
}

fn measurement_leaf_values() -> Result<Vec<Goldilocks>, String> {
    (0..PHASE_LOGICAL_LEAF_WIDTH)
        .map(|value_ordinal| {
            let canonical = u64::try_from(value_ordinal)
                .map_err(|_| "phase-leaf value ordinal exceeds u64".to_owned())?
                .wrapping_mul(1_000_003)
                .wrapping_add(29)
                % PROOF_BASE_FIELD_MODULUS;
            Ok(Goldilocks::new(canonical))
        })
        .collect()
}

fn measure_salted_phase_leaf() -> Result<PrimitiveMeasurementRecord, String> {
    let values = measurement_leaf_values()?;
    let per_leaf_keccak_permutation_count =
        salted_phase_column_leaf_keccak_permutation_count(PHASE_LOGICAL_LEAF_WIDTH)?;
    let salt = derive_private_leaf_salt(
        &[0x63_u8; 64],
        b"relation-phase/base",
        PHASE_ENCODED_COLUMN_COUNT,
        PHASE_LOGICAL_LEAF_WIDTH,
        0,
        17,
    )?;
    let (checksum, elapsed_nanoseconds) = measure_elapsed_nanoseconds(|| {
        let mut checksum = 0xcbf2_9ce4_8422_2325_u64;
        for iteration_ordinal in 0..SALTED_LEAF_ITERATION_COUNT {
            let digest = hash_opened_column_with_salt(
                black_box(&values),
                PHASE_ENCODED_COLUMN_COUNT,
                Some(black_box(&salt)),
            );
            let ordinal = u64::try_from(iteration_ordinal)
                .map_err(|_| "salted phase-leaf iteration ordinal exceeds u64".to_owned())?;
            checksum = checksum
                .rotate_left(17)
                .wrapping_add(digest[iteration_ordinal % digest.len()])
                .wrapping_add(ordinal.wrapping_mul(0x9e37_79b1_85eb_ca87))
                .wrapping_mul(0x1000_0000_01b3);
        }
        Ok(checksum)
    })?;
    black_box(checksum);
    let modeled_peak_live_byte_length = values
        .len()
        .checked_mul(size_of::<Goldilocks>())
        .and_then(|length| length.checked_add(PRIVATE_LEAF_SALT_BYTE_LENGTH))
        .and_then(|length| length.checked_add(size_of::<Shake256>()))
        .and_then(|length| length.checked_add(size_of::<ColumnDigest>()))
        .ok_or_else(|| "salted phase-leaf live-set size overflowed".to_owned())?;
    Ok(PrimitiveMeasurementRecord {
        schema_version: MEASUREMENT_SCHEMA_VERSION,
        case_identifier: 2,
        case_name: "salted-phase-column-leaf",
        execution_target: execution_target(),
        iteration_count: SALTED_LEAF_ITERATION_COUNT as u64,
        elapsed_nanoseconds,
        modeled_peak_live_byte_length: modeled_peak_live_byte_length as u64,
        checksum_hex: format!("{checksum:016x}"),
        dimensions: vec![
            dimension("logicalLeafWidth", PHASE_LOGICAL_LEAF_WIDTH)?,
            dimension("saltByteLength", PRIVATE_LEAF_SALT_BYTE_LENGTH)?,
            dimension(
                "keccakPermutationCount",
                SALTED_LEAF_ITERATION_COUNT
                    .checked_mul(usize::try_from(per_leaf_keccak_permutation_count).map_err(
                        |_| "salted phase-leaf permutation count exceeds usize".to_owned(),
                    )?)
                    .ok_or_else(|| {
                        "salted phase-leaf measured permutation count overflowed".to_owned()
                    })?,
            )?,
        ],
    })
}

fn measure_private_leaf_salt_derivation() -> Result<PrimitiveMeasurementRecord, String> {
    let (checksum, elapsed_nanoseconds) = measure_elapsed_nanoseconds(|| {
        let mut checksum = 0_u64;
        for leaf_index in 0..PRIVATE_SALT_ITERATION_COUNT {
            let salt = derive_private_leaf_salt(
                &[0x7d_u8; 64],
                b"relation-phase/base",
                PHASE_ENCODED_COLUMN_COUNT,
                PHASE_LOGICAL_LEAF_WIDTH,
                0,
                leaf_index,
            )?;
            checksum ^= u64::from_le_bytes(
                salt[..8]
                    .try_into()
                    .map_err(|_| "private leaf salt prefix has the wrong size".to_owned())?,
            );
            checksum = checksum.rotate_left(1);
        }
        Ok(checksum)
    })?;
    black_box(checksum);
    Ok(PrimitiveMeasurementRecord {
        schema_version: MEASUREMENT_SCHEMA_VERSION,
        case_identifier: 3,
        case_name: "private-leaf-salt-kmac",
        execution_target: execution_target(),
        iteration_count: PRIVATE_SALT_ITERATION_COUNT as u64,
        elapsed_nanoseconds,
        modeled_peak_live_byte_length: private_leaf_salt_derivation_workspace_byte_length() as u64,
        checksum_hex: format!("{checksum:016x}"),
        dimensions: vec![
            dimension("leafCount", PHASE_ENCODED_COLUMN_COUNT)?,
            dimension("logicalLeafWidth", PHASE_LOGICAL_LEAF_WIDTH)?,
            dimension("saltByteLength", PRIVATE_LEAF_SALT_BYTE_LENGTH)?,
        ],
    })
}

fn measure_five_level_digest_carry() -> Result<PrimitiveMeasurementRecord, String> {
    let left_digests: [ColumnDigest; 5] = core::array::from_fn(|level| {
        core::array::from_fn(|word| ((level + 1) as u64) << 32 | (word + 1) as u64)
    });
    let (checksum, elapsed_nanoseconds) = measure_elapsed_nanoseconds(|| {
        let mut carried = [0x9a5b_c31d_e742_816f_u64; 8];
        for _ in 0..FIVE_LEVEL_CARRY_ITERATION_COUNT {
            for left in &left_digests {
                carried = hash_merkle_parent(left, &carried);
            }
        }
        Ok(carried[0])
    })?;
    black_box(checksum);
    Ok(PrimitiveMeasurementRecord {
        schema_version: MEASUREMENT_SCHEMA_VERSION,
        case_identifier: 4,
        case_name: "five-level-digest-carry",
        execution_target: execution_target(),
        iteration_count: FIVE_LEVEL_CARRY_ITERATION_COUNT as u64,
        elapsed_nanoseconds,
        modeled_peak_live_byte_length: (size_of::<[ColumnDigest; 5]>()
            + size_of::<ColumnDigest>()
            + size_of::<Shake256>()) as u64,
        checksum_hex: format!("{checksum:016x}"),
        dimensions: vec![dimension(
            "merkleParentHashCount",
            FIVE_LEVEL_CARRY_ITERATION_COUNT * 5,
        )?],
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SelectedVssBasePhaseWorkLedger {
    materialization_pass_count: u64,
    logical_polynomials_per_physical_row: u64,
    row_count: u64,
    lane_count: u64,
    opening_query_count: u64,
    aggregate_wide_pad_query_count: u64,
    logical_chunk_count_per_lane: u64,
    direct_source_column_count_per_lane: u64,
    coefficient_chunk_count_per_source: u64,
    direct_source_chunk_count_per_lane: u64,
    reversed_source_chunk_count_per_lane: u64,
    source_replay_count: u64,
    reversed_polynomial_reconstruction_count: u64,
    bound_source_replay_count: u64,
    prover_source_replay_count: u64,
    lane_dft_count: u64,
    butterfly_count: u64,
    coset_multiplication_count: u64,
    column_value_delivery_count: u64,
    transported_value_byte_length: u64,
    leaf_hash_query_count: u64,
    salted_leaf_keccak_permutation_count: u64,
    merkle_parent_hash_query_count: u64,
    private_leaf_salt_derivation_count: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct VssRelationReplayCandidateLedger {
    trace_packing_factor: u64,
    logical_polynomials_per_physical_row: u64,
    relation_trace_domain_size: u64,
    material_group_count: u64,
    material_prover_column_count: u64,
    quotient_group_count: u64,
    quotient_prover_column_count: u64,
    shift_selector_column_count: u64,
    prover_column_count: u64,
    prover_column_degree_bound_exclusive: u64,
    maximum_range_constraint_numerator_degree: u64,
    opening_degree_bound_exclusive: u64,
    row_code_inverse_rate: u64,
    opening_point_count: u64,
    bound_reduction_aggregate_column_count: u64,
    aggregate_column_role_count: u64,
    aggregate_table_width: u64,
    coefficient_chunk_count_per_source: u64,
    physical_row_count: u64,
    lane_dft_count: u64,
    butterfly_count: u64,
    coefficient_fold_count: u64,
    coset_multiplication_count: u64,
    private_high_half_value_generation_count: u64,
    column_value_delivery_count: u64,
    transported_value_byte_length: u64,
    leaf_hash_query_count: u64,
    salted_leaf_keccak_permutation_count: u64,
    merkle_parent_hash_query_count: u64,
    private_leaf_salt_derivation_count: u64,
    retained_source_materialization_count: u64,
    source_trace_value_generation_count: u64,
    retained_coefficient_group_byte_length: u64,
    logical_row_chunk_byte_length: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct VssOpeningClaimQuotientCandidateLedger {
    direct_aggregate_column_role_count: u64,
    quotient_aggregate_column_role_count: u64,
    aggregate_table_width: u64,
    source_degree_bound_exclusive: u64,
    opening_claim_count: u64,
    batched_quotient_degree_bound_exclusive: u64,
    discrepancy_numerator_degree_bound_inclusive: u64,
    query_domain_size: u64,
    query_count: u64,
    agreement_ceiling: u64,
}

fn derive_vss_opening_claim_quotient_candidate_ledger(
    candidate: VssRelationReplayCandidateLedger,
) -> Result<VssOpeningClaimQuotientCandidateLedger, String> {
    let source_degree_bound_exclusive = candidate
        .opening_degree_bound_exclusive
        .checked_mul(2)
        .ok_or_else(|| "VSS quotient-batch source degree overflowed".to_owned())?;
    let geometry = OpeningClaimQuotientBatchGeometry::derive(
        usize::try_from(source_degree_bound_exclusive)
            .map_err(|_| "VSS quotient-batch source degree exceeds usize".to_owned())?,
        usize::try_from(candidate.opening_point_count)
            .map_err(|_| "VSS quotient-batch claim count exceeds usize".to_owned())?,
        PHASE_ENCODED_COLUMN_COUNT,
        ROW_CODE_WHIR_OUTER_QUERY_COUNT,
    )?;
    let quotient_aggregate_column_role_count = 1_u64
        .checked_add(candidate.bound_reduction_aggregate_column_count)
        .ok_or_else(|| "VSS quotient-batch aggregate role count overflowed".to_owned())?;
    if geometry.source_degree_bound_exclusive()
        != usize::try_from(source_degree_bound_exclusive)
            .map_err(|_| "VSS quotient-batch source degree exceeds usize".to_owned())?
        || geometry.opening_claim_count()
            != usize::try_from(candidate.opening_point_count)
                .map_err(|_| "VSS quotient-batch claim count exceeds usize".to_owned())?
        || quotient_aggregate_column_role_count > candidate.aggregate_table_width
    {
        return Err("VSS quotient-batch geometry does not fit its aggregate table".to_owned());
    }
    Ok(VssOpeningClaimQuotientCandidateLedger {
        direct_aggregate_column_role_count: candidate.aggregate_column_role_count,
        quotient_aggregate_column_role_count,
        aggregate_table_width: candidate.aggregate_table_width,
        source_degree_bound_exclusive,
        opening_claim_count: candidate.opening_point_count,
        batched_quotient_degree_bound_exclusive: u64::try_from(
            geometry.batched_quotient_degree_bound_exclusive(),
        )
        .map_err(|_| "VSS quotient-batch degree exceeds u64".to_owned())?,
        discrepancy_numerator_degree_bound_inclusive: u64::try_from(
            geometry.discrepancy_numerator_degree_bound_inclusive(),
        )
        .map_err(|_| "VSS quotient-batch discrepancy degree exceeds u64".to_owned())?,
        query_domain_size: u64::try_from(geometry.query_domain_size())
            .map_err(|_| "VSS quotient-batch query domain exceeds u64".to_owned())?,
        query_count: u64::try_from(geometry.query_count())
            .map_err(|_| "VSS quotient-batch query count exceeds u64".to_owned())?,
        agreement_ceiling: u64::try_from(geometry.agreement_ceiling())
            .map_err(|_| "VSS quotient-batch agreement ceiling exceeds u64".to_owned())?,
    })
}

fn derive_vss_relation_replay_candidate_ledger(
    trace_packing_factor: u64,
    logical_polynomials_per_physical_row: u64,
) -> Result<Option<VssRelationReplayCandidateLedger>, String> {
    if logical_polynomials_per_physical_row == 0
        || !logical_polynomials_per_physical_row.is_power_of_two()
        || logical_polynomials_per_physical_row
            > u64::try_from(ROW_CODE_WHIR_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW)
                .map_err(|_| "VSS candidate maximum row width exceeds u64".to_owned())?
    {
        return Err("VSS candidate physical row width is unsupported".to_owned());
    }
    let schema_identifier =
        ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER;
    let relation_context = selected_relation_plan_check_context(schema_identifier)
        .ok_or_else(|| "VSS candidate relation context is absent".to_owned())?;
    let relation_input = selected_committed_material_relation_plan_input()
        .map_err(|_| "VSS candidate relation input is invalid".to_owned())?;
    let logical_polynomial_coefficient_count =
        u64::try_from(ROW_CODE_WHIR_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT)
            .map_err(|_| "VSS candidate coefficient count exceeds u64".to_owned())?;
    let opening_degree_bound_exclusive = logical_polynomial_coefficient_count
        .checked_mul(logical_polynomials_per_physical_row)
        .ok_or_else(|| "VSS candidate opening degree bound overflowed".to_owned())?;
    let relation = derive_vss_relation_packing_candidate_geometry(
        &relation_input,
        &relation_context,
        trace_packing_factor,
    )
    .map_err(|_| "VSS candidate relation packing does not derive".to_owned())?;
    if relation.prover_column_degree_bound_exclusive > opening_degree_bound_exclusive
        || relation.maximum_range_constraint_numerator_degree >= opening_degree_bound_exclusive
        || relation_input.material_column_degree_bound_exclusive > opening_degree_bound_exclusive
    {
        return Ok(None);
    }
    let prefix_stacking_factor = 2_u64;
    let row_encoding_denominator = opening_degree_bound_exclusive
        .checked_mul(prefix_stacking_factor)
        .ok_or_else(|| "VSS candidate row-encoding denominator overflowed".to_owned())?;
    let row_code_inverse_rate = relation_input
        .evaluation_domain_size
        .checked_div(row_encoding_denominator)
        .filter(|inverse_rate| {
            *inverse_rate >= 4
                && inverse_rate.is_power_of_two()
                && row_encoding_denominator.checked_mul(*inverse_rate)
                    == Some(relation_input.evaluation_domain_size)
        })
        .ok_or_else(|| "VSS candidate row-code inverse rate is unsupported".to_owned())?;
    let coefficient_chunk_count_per_source = relation
        .prover_column_degree_bound_exclusive
        .div_ceil(logical_polynomial_coefficient_count);
    let opening_point_count = relation.opening_point_count;
    let bound_reduction_aggregate_column_count = 1_u64;
    let aggregate_column_role_count = opening_point_count
        .checked_add(bound_reduction_aggregate_column_count)
        .ok_or_else(|| "VSS candidate aggregate-column count overflowed".to_owned())?;
    let aggregate_table_width = row_code_inverse_rate;
    let physical_column_group_count = relation
        .prover_column_count
        .div_ceil(logical_polynomials_per_physical_row);
    let physical_row_count = physical_column_group_count
        .checked_mul(coefficient_chunk_count_per_source)
        .ok_or_else(|| "VSS candidate physical row count overflowed".to_owned())?;
    let lane_count = u64::try_from(PHASE_ENCODED_COLUMN_COUNT / PHASE_LANE_COLUMN_COUNT)
        .map_err(|_| "VSS candidate lane count exceeds u64".to_owned())?;
    let materialization_pass_count = ROOT_AND_OPENING_PASS_COUNT;
    let lane_dft_count = physical_row_count
        .checked_mul(lane_count)
        .and_then(|count| count.checked_mul(materialization_pass_count))
        .ok_or_else(|| "VSS candidate lane DFT count overflowed".to_owned())?;
    let butterfly_count = lane_dft_count
        .checked_mul(DFT_BUTTERFLY_COUNT)
        .ok_or_else(|| "VSS candidate butterfly count overflowed".to_owned())?;
    let padded_coefficient_count = opening_degree_bound_exclusive
        .checked_mul(prefix_stacking_factor)
        .ok_or_else(|| "VSS candidate padded coefficient count overflowed".to_owned())?;
    let lane_column_count = u64::try_from(PHASE_LANE_COLUMN_COUNT)
        .map_err(|_| "VSS candidate lane width exceeds u64".to_owned())?;
    let coefficient_fold_count_per_lane =
        padded_coefficient_count
            .checked_sub(lane_column_count)
            .ok_or_else(|| "VSS candidate lane exceeds its coefficient message".to_owned())?;
    let coefficient_fold_count = lane_dft_count
        .checked_mul(coefficient_fold_count_per_lane)
        .ok_or_else(|| "VSS candidate coefficient-fold count overflowed".to_owned())?;
    let coset_multiplication_count = lane_dft_count
        .checked_mul(lane_column_count)
        .ok_or_else(|| "VSS candidate coset multiplication count overflowed".to_owned())?;
    let private_high_half_value_generation_count = lane_dft_count
        .checked_mul(opening_degree_bound_exclusive)
        .ok_or_else(|| "VSS candidate private high-half count overflowed".to_owned())?;
    let evaluation_domain_size = u64::try_from(PHASE_ENCODED_COLUMN_COUNT)
        .map_err(|_| "VSS candidate evaluation domain exceeds u64".to_owned())?;
    if evaluation_domain_size != relation_input.evaluation_domain_size {
        return Err("VSS candidate evaluation domains disagree".to_owned());
    }
    let column_value_delivery_count = physical_row_count
        .checked_mul(evaluation_domain_size)
        .and_then(|count| count.checked_mul(materialization_pass_count))
        .ok_or_else(|| "VSS candidate column-value count overflowed".to_owned())?;
    let transported_value_byte_length = column_value_delivery_count
        .checked_mul(size_of::<ProofBaseFieldElement>() as u64)
        .ok_or_else(|| "VSS candidate transported-value size overflowed".to_owned())?;
    let leaf_hash_query_count = evaluation_domain_size
        .checked_mul(materialization_pass_count)
        .ok_or_else(|| "VSS candidate leaf-hash count overflowed".to_owned())?;
    let per_leaf_keccak_permutation_count = salted_phase_column_leaf_keccak_permutation_count(
        usize::try_from(physical_row_count)
            .map_err(|_| "VSS candidate row count exceeds usize".to_owned())?,
    )?;
    let salted_leaf_keccak_permutation_count = leaf_hash_query_count
        .checked_mul(per_leaf_keccak_permutation_count)
        .ok_or_else(|| "VSS candidate leaf permutation count overflowed".to_owned())?;
    let merkle_parent_hash_query_count = evaluation_domain_size
        .checked_sub(1)
        .and_then(|count| count.checked_mul(materialization_pass_count))
        .ok_or_else(|| "VSS candidate Merkle-parent count overflowed".to_owned())?;
    let retained_source_materialization_count = relation
        .prover_column_count
        .checked_mul(materialization_pass_count)
        .ok_or_else(|| "VSS candidate source-materialization count overflowed".to_owned())?;
    let source_trace_value_generation_count = retained_source_materialization_count
        .checked_mul(relation.relation_trace_domain_size)
        .ok_or_else(|| "VSS candidate source-value count overflowed".to_owned())?;
    let retained_group_width = relation
        .prover_column_count
        .min(logical_polynomials_per_physical_row);
    let retained_coefficient_group_byte_length = retained_group_width
        .checked_mul(relation.prover_column_degree_bound_exclusive)
        .and_then(|count| count.checked_mul(size_of::<ProofBaseFieldElement>() as u64))
        .ok_or_else(|| "VSS candidate retained coefficient group overflowed".to_owned())?;
    let logical_row_chunk_byte_length = opening_degree_bound_exclusive
        .checked_mul(size_of::<ProofBaseFieldElement>() as u64)
        .ok_or_else(|| "VSS candidate logical-row chunk size overflowed".to_owned())?;

    Ok(Some(VssRelationReplayCandidateLedger {
        trace_packing_factor: relation.trace_packing_factor,
        logical_polynomials_per_physical_row,
        relation_trace_domain_size: relation.relation_trace_domain_size,
        material_group_count: relation.material_group_count,
        material_prover_column_count: relation.material_prover_column_count,
        quotient_group_count: relation.quotient_group_count,
        quotient_prover_column_count: relation.quotient_prover_column_count,
        shift_selector_column_count: relation.shift_selector_column_count,
        prover_column_count: relation.prover_column_count,
        prover_column_degree_bound_exclusive: relation.prover_column_degree_bound_exclusive,
        maximum_range_constraint_numerator_degree: relation
            .maximum_range_constraint_numerator_degree,
        opening_degree_bound_exclusive,
        row_code_inverse_rate,
        opening_point_count,
        bound_reduction_aggregate_column_count,
        aggregate_column_role_count,
        aggregate_table_width,
        coefficient_chunk_count_per_source,
        physical_row_count,
        lane_dft_count,
        butterfly_count,
        coefficient_fold_count,
        coset_multiplication_count,
        private_high_half_value_generation_count,
        column_value_delivery_count,
        transported_value_byte_length,
        leaf_hash_query_count,
        salted_leaf_keccak_permutation_count,
        merkle_parent_hash_query_count,
        private_leaf_salt_derivation_count: leaf_hash_query_count,
        retained_source_materialization_count,
        source_trace_value_generation_count,
        retained_coefficient_group_byte_length,
        logical_row_chunk_byte_length,
    }))
}

fn derive_vss_relation_replay_candidate_grid()
-> Result<Vec<VssRelationReplayCandidateLedger>, String> {
    let mut candidates = Vec::new();
    for trace_packing_factor in [1_u64, 2, 4, 8, 16, 32, 64] {
        for logical_polynomials_per_physical_row in [8_u64, 16, 32, 64] {
            if let Some(candidate) = derive_vss_relation_replay_candidate_ledger(
                trace_packing_factor,
                logical_polynomials_per_physical_row,
            )? {
                candidates.push(candidate);
            }
        }
    }
    if candidates.is_empty() {
        return Err("VSS relation-replay candidate grid is empty".to_owned());
    }
    Ok(candidates)
}

fn derive_vss_relation_replay_candidate_construction_plan(
    candidate: VssRelationReplayCandidateLedger,
) -> Result<RowCodeWhirConstructionPlan, String> {
    let (artifact, context) =
        SelectedVssSourceReplayMeasurement::validated_relation_replay_candidate(
            candidate.trace_packing_factor,
            candidate.opening_degree_bound_exclusive,
        )?;
    let variant = artifact
        .compiled_plan()
        .variants()
        .first()
        .ok_or_else(|| "VSS relation-replay candidate variant is absent".to_owned())?;
    RowCodeWhirConstructionPlan::for_primitive_measurement_candidate_variant(
        &artifact,
        &context,
        variant.schedule_position(),
        variant.top_count(),
        vss_relation_replay_candidate_bound_root_source_trace_domain_size,
    )
    .map_err(|error| {
        format!("VSS relation-replay candidate construction does not derive: {error:?}")
    })
}

fn derive_vss_relation_replay_opening_claim_quotient_candidate_construction_plan(
    candidate: VssRelationReplayCandidateLedger,
) -> Result<RowCodeWhirConstructionPlan, String> {
    let (artifact, context) =
        SelectedVssSourceReplayMeasurement::validated_relation_replay_candidate(
            candidate.trace_packing_factor,
            candidate.opening_degree_bound_exclusive,
        )?;
    let variant = artifact
        .compiled_plan()
        .variants()
        .first()
        .ok_or_else(|| "VSS relation-replay candidate variant is absent".to_owned())?;
    RowCodeWhirConstructionPlan::for_primitive_measurement_opening_claim_quotient_candidate_variant(
        &artifact,
        &context,
        variant.schedule_position(),
        variant.top_count(),
        vss_relation_replay_candidate_bound_root_source_trace_domain_size,
    )
    .map_err(|error| {
        format!("VSS opening-claim quotient candidate construction does not derive: {error:?}")
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct VssRelationReplayCandidateCapacityRefusal {
    opening_point_count: u64,
    bound_reduction_aggregate_column_count: u64,
    aggregate_column_role_count: u64,
    aggregate_table_width: u64,
}

fn derive_vss_relation_replay_candidate_capacity_refusal(
    candidate: VssRelationReplayCandidateLedger,
) -> Result<VssRelationReplayCandidateCapacityRefusal, String> {
    let (artifact, context) =
        SelectedVssSourceReplayMeasurement::validated_relation_replay_candidate(
            candidate.trace_packing_factor,
            candidate.opening_degree_bound_exclusive,
        )?;
    let variant = artifact
        .compiled_plan()
        .variants()
        .first()
        .ok_or_else(|| "VSS relation-replay candidate variant is absent".to_owned())?;
    let opening_point_count = u64::try_from(variant.ordered_opening_points().len())
        .map_err(|_| "VSS candidate opening-point count exceeds u64".to_owned())?;
    let bound_reduction_aggregate_column_count = u64::from(
        variant
            .ordered_trees()
            .iter()
            .any(|tree| matches!(tree, RelationTreeDescriptor::BoundPublic { .. })),
    );
    let refusal = match RowCodeWhirConstructionPlan::for_primitive_measurement_candidate_variant(
        &artifact,
        &context,
        variant.schedule_position(),
        variant.top_count(),
        vss_relation_replay_candidate_bound_root_source_trace_domain_size,
    ) {
        Ok(_) => {
            return Err(
                "the capacity-refused VSS candidate unexpectedly derived a construction".to_owned(),
            );
        }
        Err(error) => error,
    };
    let RowCodeWhirConstructionPlanError::InsufficientAggregateTableWidth {
        aggregate_column_role_count,
        aggregate_table_width,
    } = refusal
    else {
        return Err(format!(
            "VSS relation-replay candidate has an unexpected construction refusal: {refusal:?}"
        ));
    };
    let refusal = VssRelationReplayCandidateCapacityRefusal {
        opening_point_count,
        bound_reduction_aggregate_column_count,
        aggregate_column_role_count: u64::try_from(aggregate_column_role_count)
            .map_err(|_| "VSS candidate aggregate-column count exceeds u64".to_owned())?,
        aggregate_table_width: u64::try_from(aggregate_table_width)
            .map_err(|_| "VSS candidate aggregate-table width exceeds u64".to_owned())?,
    };
    if refusal.opening_point_count != candidate.opening_point_count
        || refusal.bound_reduction_aggregate_column_count
            != candidate.bound_reduction_aggregate_column_count
        || refusal.aggregate_column_role_count != candidate.aggregate_column_role_count
        || refusal.aggregate_table_width != candidate.aggregate_table_width
    {
        return Err("VSS candidate capacity model and construction refusal disagree".to_owned());
    }
    Ok(refusal)
}

fn vss_relation_replay_candidate_bound_root_source_trace_domain_size(
    application_statement_schema_identifier: u16,
    construction_kind: BoundTreeConstructionKind,
    relation_trace_domain_size: u64,
    evaluation_domain_size: u64,
) -> Result<u64, ProofProfileError> {
    if application_statement_schema_identifier
        != ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER
        || construction_kind != BoundTreeConstructionKind::CommittedMaterial
        || evaluation_domain_size
            != u64::try_from(PHASE_ENCODED_COLUMN_COUNT)
                .map_err(|_| ProofProfileError::CountOverflow)?
    {
        return Err(ProofProfileError::InvalidRootTopology);
    }
    let selected_relation_trace_domain_size =
        selected_committed_material_relation_plan_input()?.relation_trace_domain_size()?;
    let physical_trace_domain_size = selected_relation_trace_domain_size
        .checked_div(COMMITTED_MATERIAL_TRACE_PACKING_FACTOR)
        .filter(|physical_domain_size| {
            physical_domain_size.checked_mul(COMMITTED_MATERIAL_TRACE_PACKING_FACTOR)
                == Some(selected_relation_trace_domain_size)
        })
        .ok_or(ProofProfileError::InvalidRelationPlan)?;
    let candidate_trace_packing_factor = relation_trace_domain_size
        .checked_div(physical_trace_domain_size)
        .filter(|packing_factor| {
            packing_factor.is_power_of_two()
                && *packing_factor <= 64
                && physical_trace_domain_size.checked_mul(*packing_factor)
                    == Some(relation_trace_domain_size)
        })
        .ok_or(ProofProfileError::InvalidRelationPlan)?;
    if candidate_trace_packing_factor == 0
        || physical_trace_domain_size == 0
        || !physical_trace_domain_size.is_power_of_two()
        || !evaluation_domain_size.is_multiple_of(physical_trace_domain_size)
    {
        return Err(ProofProfileError::InvalidRelationPlan);
    }
    Ok(physical_trace_domain_size)
}

fn derive_selected_vss_base_phase_work_ledger() -> Result<SelectedVssBasePhaseWorkLedger, String> {
    let schema_identifier =
        ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER;
    let relation_context = selected_relation_plan_check_context(schema_identifier)
        .ok_or_else(|| "selected VSS work-ledger context is absent".to_owned())?;
    let relation_input = selected_committed_material_relation_plan_input()
        .map_err(|_| "selected VSS work-ledger input is invalid".to_owned())?;
    let compiled_plan = compile_vss_share_linkage_relation_plan(&relation_input, &relation_context)
        .map_err(|_| "selected VSS work-ledger relation does not compile".to_owned())?;
    let artifact =
        ValidatedRelationPlanArtifact::from_owned_compiled_plan(compiled_plan, &relation_context)
            .map_err(|_| "selected VSS work-ledger relation does not validate".to_owned())?;
    let relation_variant = artifact
        .compiled_plan()
        .variants()
        .first()
        .ok_or_else(|| "selected VSS work-ledger relation variant is absent".to_owned())?;
    let construction_plan = RowCodeWhirConstructionPlan::for_selected_variant(
        &artifact,
        relation_variant.schedule_position(),
        relation_variant.top_count(),
    )
    .map_err(|_| "selected VSS work-ledger construction does not derive".to_owned())?;
    let base_phase = construction_plan
        .base_phase
        .as_ref()
        .ok_or_else(|| "selected VSS work-ledger base phase is absent".to_owned())?;
    let commitment = derive_phase_commitment_geometry_accounting(base_phase.geometry)?;
    let requested_source_columns = construction_plan
        .requested_source_column_ordinals
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let reversed_source_by_column = relation_reversed_column_bindings(relation_variant)
        .map_err(|_| "selected VSS reversed-column bindings do not derive".to_owned())?
        .into_iter()
        .map(|(source_column_ordinal, reversed_column_ordinal)| {
            (reversed_column_ordinal, source_column_ordinal)
        })
        .collect::<BTreeMap<_, _>>();

    let mut logical_chunk_count_per_lane = 0_u64;
    let mut direct_source_chunk_count_per_lane = 0_u64;
    let mut reversed_source_chunk_count_per_lane = 0_u64;
    let mut direct_chunks_by_source_column = BTreeMap::<u32, BTreeSet<u32>>::new();
    let mut bound_source_count_per_lane = 0_u64;
    let mut prover_source_count_per_lane = 0_u64;
    for chunk in base_phase
        .rows
        .iter()
        .flat_map(|row| row.logical_polynomial_chunks.iter().flatten())
    {
        logical_chunk_count_per_lane = logical_chunk_count_per_lane
            .checked_add(1)
            .ok_or_else(|| "selected VSS logical-chunk count overflowed".to_owned())?;
        let source_column_ordinal = if requested_source_columns.contains(&chunk.column_ordinal) {
            direct_source_chunk_count_per_lane = direct_source_chunk_count_per_lane
                .checked_add(1)
                .ok_or_else(|| "selected VSS direct-source count overflowed".to_owned())?;
            if !direct_chunks_by_source_column
                .entry(chunk.column_ordinal)
                .or_default()
                .insert(chunk.coefficient_chunk_ordinal)
            {
                return Err("selected VSS direct-source chunk is duplicated".to_owned());
            }
            chunk.column_ordinal
        } else {
            reversed_source_chunk_count_per_lane = reversed_source_chunk_count_per_lane
                .checked_add(1)
                .ok_or_else(|| "selected VSS reversed-source count overflowed".to_owned())?;
            *reversed_source_by_column
                .get(&chunk.column_ordinal)
                .ok_or_else(|| {
                    "selected VSS base chunk is neither a source nor its reversal".to_owned()
                })?
        };
        let descriptor = relation_variant
            .ordered_columns()
            .get(
                usize::try_from(source_column_ordinal)
                    .map_err(|_| "selected VSS source column exceeds usize".to_owned())?,
            )
            .ok_or_else(|| "selected VSS source column is absent".to_owned())?;
        match descriptor.origin() {
            RelationColumnOrigin::BoundTree { .. } => {
                bound_source_count_per_lane = bound_source_count_per_lane
                    .checked_add(1)
                    .ok_or_else(|| "selected VSS bound-source count overflowed".to_owned())?;
            }
            RelationColumnOrigin::Prover => {
                prover_source_count_per_lane = prover_source_count_per_lane
                    .checked_add(1)
                    .ok_or_else(|| "selected VSS prover-source count overflowed".to_owned())?;
            }
            RelationColumnOrigin::VerifierSequence { .. } => {
                return Err("selected VSS base chunk depends on a verifier sequence".to_owned());
            }
        }
    }

    let direct_source_column_count_per_lane =
        u64::try_from(direct_chunks_by_source_column.len())
            .map_err(|_| "selected VSS direct-source column count exceeds u64".to_owned())?;
    let coefficient_chunk_count_per_source = direct_chunks_by_source_column
        .values()
        .next()
        .map(BTreeSet::len)
        .filter(|chunk_count| *chunk_count > 0)
        .ok_or_else(|| "selected VSS direct-source chunk catalog is empty".to_owned())?;
    if direct_chunks_by_source_column
        .values()
        .any(|chunk_ordinals| {
            chunk_ordinals.len() != coefficient_chunk_count_per_source
                || chunk_ordinals
                    .iter()
                    .copied()
                    .enumerate()
                    .any(|(expected_ordinal, ordinal)| {
                        u32::try_from(expected_ordinal).ok() != Some(ordinal)
                    })
        })
    {
        return Err("selected VSS direct-source chunk geometry is nonuniform".to_owned());
    }
    let coefficient_chunk_count_per_source = u64::try_from(coefficient_chunk_count_per_source)
        .map_err(|_| "selected VSS coefficient chunk count exceeds u64".to_owned())?;

    let scale_per_materialization = |count: u64, role: &str| {
        count
            .checked_mul(commitment.lane_count)
            .and_then(|value| value.checked_mul(ROOT_AND_OPENING_PASS_COUNT))
            .ok_or_else(|| format!("selected VSS {role} count overflowed"))
    };
    let scale_per_pass = |count: u64, role: &str| {
        count
            .checked_mul(ROOT_AND_OPENING_PASS_COUNT)
            .ok_or_else(|| format!("selected VSS {role} count overflowed"))
    };
    let bound_source_replay_count =
        scale_per_materialization(bound_source_count_per_lane, "bound-source replay")?;
    let prover_source_replay_count =
        scale_per_materialization(prover_source_count_per_lane, "prover-source replay")?;
    let source_replay_count = bound_source_replay_count
        .checked_add(prover_source_replay_count)
        .ok_or_else(|| "selected VSS source-replay count overflowed".to_owned())?;
    let reversed_polynomial_reconstruction_count = scale_per_materialization(
        reversed_source_chunk_count_per_lane,
        "reversed-polynomial reconstruction",
    )?;
    let lane_dft_count = scale_per_pass(commitment.lane_dft_count_per_pass, "lane DFT")?;
    let leaf_hash_query_count =
        scale_per_pass(commitment.leaf_hash_query_count_per_pass, "leaf hash")?;
    let private_leaf_salt_derivation_count = match construction_plan.proof_privacy_mode {
        ProofPrivacyMode::SecretBearing => leaf_hash_query_count,
        ProofPrivacyMode::PublicOnly => 0,
    };
    let column_value_delivery_count = scale_per_pass(
        commitment.column_value_delivery_count_per_pass,
        "column value delivery",
    )?;

    if direct_source_chunk_count_per_lane.checked_add(reversed_source_chunk_count_per_lane)
        != Some(logical_chunk_count_per_lane)
        || source_replay_count
            != logical_chunk_count_per_lane
                .checked_mul(commitment.lane_count)
                .and_then(|value| value.checked_mul(ROOT_AND_OPENING_PASS_COUNT))
                .ok_or_else(|| "selected VSS source-replay identity overflowed".to_owned())?
        || lane_dft_count
            != commitment
                .row_count
                .checked_mul(commitment.lane_count)
                .and_then(|value| value.checked_mul(ROOT_AND_OPENING_PASS_COUNT))
                .ok_or_else(|| "selected VSS lane-DFT identity overflowed".to_owned())?
    {
        return Err("selected VSS work-ledger identities are inconsistent".to_owned());
    }

    let aggregate_wide_pad_query_count = selected_hiding_whir_config(construction_plan.parameters)
        .map_err(|_| "selected VSS aggregate-wide hiding configuration does not derive".to_owned())?
        .mask_queries;
    if aggregate_wide_pad_query_count == construction_plan.parameters.outer_query_count {
        return Err(
            "selected VSS outer and aggregate-wide pad query schedules were conflated".to_owned(),
        );
    }

    Ok(SelectedVssBasePhaseWorkLedger {
        materialization_pass_count: ROOT_AND_OPENING_PASS_COUNT,
        logical_polynomials_per_physical_row: u64::try_from(
            construction_plan
                .parameters
                .logical_polynomials_per_physical_row,
        )
        .map_err(|_| "selected VSS physical row width exceeds u64".to_owned())?,
        row_count: commitment.row_count,
        lane_count: commitment.lane_count,
        opening_query_count: u64::try_from(construction_plan.parameters.outer_query_count)
            .map_err(|_| "selected VSS opening-query count exceeds u64".to_owned())?,
        aggregate_wide_pad_query_count: u64::try_from(aggregate_wide_pad_query_count)
            .map_err(|_| "selected VSS aggregate-wide pad query count exceeds u64".to_owned())?,
        logical_chunk_count_per_lane,
        direct_source_column_count_per_lane,
        coefficient_chunk_count_per_source,
        direct_source_chunk_count_per_lane,
        reversed_source_chunk_count_per_lane,
        source_replay_count,
        reversed_polynomial_reconstruction_count,
        bound_source_replay_count,
        prover_source_replay_count,
        lane_dft_count,
        butterfly_count: scale_per_pass(commitment.butterfly_count_per_pass, "butterfly")?,
        coset_multiplication_count: scale_per_pass(
            commitment.coset_multiplication_count_per_pass,
            "coset multiplication",
        )?,
        column_value_delivery_count,
        transported_value_byte_length: column_value_delivery_count
            .checked_mul(size_of::<ProofBaseFieldElement>() as u64)
            .ok_or_else(|| "selected VSS transported-value size overflowed".to_owned())?,
        leaf_hash_query_count,
        salted_leaf_keccak_permutation_count: leaf_hash_query_count
            .checked_mul(salted_phase_column_leaf_keccak_permutation_count(
                usize::try_from(commitment.row_count)
                    .map_err(|_| "selected VSS row count exceeds usize".to_owned())?,
            )?)
            .ok_or_else(|| "selected VSS leaf permutation count overflowed".to_owned())?,
        merkle_parent_hash_query_count: scale_per_pass(
            commitment.merkle_parent_hash_query_count_per_pass,
            "Merkle parent hash",
        )?,
        private_leaf_salt_derivation_count,
    })
}

fn measure_selected_vss_source_replay() -> Result<PrimitiveMeasurementRecord, String> {
    let measurement = SelectedVssSourceReplayMeasurement::prepare()?;
    let work_ledger = derive_selected_vss_base_phase_work_ledger()?;
    let candidate_grid = derive_vss_relation_replay_candidate_grid()?;
    let current_geometry = candidate_grid
        .iter()
        .copied()
        .find(|candidate| {
            candidate.trace_packing_factor == COMMITTED_MATERIAL_TRACE_PACKING_FACTOR
                && candidate.logical_polynomials_per_physical_row
                    == work_ledger.logical_polynomials_per_physical_row
        })
        .ok_or_else(|| "current VSS relation-replay geometry is absent".to_owned())?;
    let modeled_candidate = candidate_grid
        .iter()
        .copied()
        .find(|candidate| {
            candidate.trace_packing_factor == 16
                && candidate.logical_polynomials_per_physical_row == 64
        })
        .ok_or_else(|| "modeled VSS relation-replay candidate is absent".to_owned())?;
    let modeled_candidate_capacity_refusal =
        derive_vss_relation_replay_candidate_capacity_refusal(modeled_candidate)?;
    let modeled_candidate_quotient_batch =
        derive_vss_opening_claim_quotient_candidate_ledger(modeled_candidate)?;
    let modeled_candidate_quotient_construction =
        derive_vss_relation_replay_opening_claim_quotient_candidate_construction_plan(
            modeled_candidate,
        )?;
    let modeled_candidate_quotient_parameters =
        modeled_candidate_quotient_construction.selected_parameters();
    let modeled_candidate_quotient_identity_bytes = modeled_candidate_quotient_construction
        .canonical_identity_bytes()
        .map_err(|_| "modeled VSS quotient construction identity does not encode".to_owned())?;
    let modeled_candidate_quotient_identity_hash = modeled_candidate_quotient_construction
        .canonical_identity_hash()
        .map_err(|_| "modeled VSS quotient construction identity does not hash".to_owned())?;
    let modeled_candidate_quotient_oracle_catalog = modeled_candidate_quotient_construction
        .oracle_equation_catalog()
        .map_err(|_| "modeled VSS quotient oracle catalog does not derive".to_owned())?;
    let modeled_candidate_quotient_oracle_catalog_hash = modeled_candidate_quotient_construction
        .oracle_equation_catalog_hash()
        .map_err(|_| "modeled VSS quotient oracle catalog does not hash".to_owned())?;
    let (
        modeled_candidate_quotient_bound_query_count,
        modeled_candidate_quotient_bound_degree_test_count,
    ) = modeled_candidate_quotient_construction
        .bound_reduction_blocks
        .iter()
        .try_fold((0_usize, 0_usize), |(query_total, degree_total), block| {
            let degree_test_count = 1_usize
                .checked_add(block.degree_suffix_prefixes.len())
                .ok_or_else(|| {
                    "modeled VSS quotient bound degree-test count overflowed".to_owned()
                })?;
            Ok::<_, String>((
                query_total.checked_add(block.query_count).ok_or_else(|| {
                    "modeled VSS quotient bound-query count overflowed".to_owned()
                })?,
                degree_total.checked_add(degree_test_count).ok_or_else(|| {
                    "modeled VSS quotient bound degree-test count overflowed".to_owned()
                })?,
            ))
        })?;
    let modeled_candidate_quotient_bound_batch_count = modeled_candidate_quotient_bound_query_count
        .checked_mul(2)
        .and_then(|count| count.checked_add(modeled_candidate_quotient_bound_degree_test_count))
        .ok_or_else(|| "modeled VSS quotient bound-batch count overflowed".to_owned())?;
    let modeled_candidate_quotient_opening_batches =
        modeled_candidate_quotient_construction.opening_batches();
    let modeled_candidate_quotient_outer_query_count =
        modeled_candidate_quotient_construction.outer_query_count();
    let single_aggregate_candidate = candidate_grid
        .iter()
        .copied()
        .filter(|candidate| {
            candidate.aggregate_column_role_count <= candidate.aggregate_table_width
        })
        .min_by_key(|candidate| candidate.physical_row_count)
        .ok_or_else(|| "single-aggregate VSS relation-replay candidate is absent".to_owned())?;
    let single_aggregate_construction =
        derive_vss_relation_replay_candidate_construction_plan(single_aggregate_candidate)?;
    let single_aggregate_parameters = single_aggregate_construction.selected_parameters();
    let single_aggregate_base_phase = single_aggregate_construction
        .base_phase
        .as_ref()
        .ok_or_else(|| "single-aggregate VSS relation-replay base phase is absent".to_owned())?;
    let single_aggregate_commitment =
        derive_phase_commitment_geometry_accounting(single_aggregate_base_phase.geometry)?;
    let single_aggregate_identity_bytes = single_aggregate_construction
        .canonical_identity_bytes()
        .map_err(|_| "single-aggregate VSS construction identity does not encode".to_owned())?;
    let single_aggregate_identity_hash = single_aggregate_construction
        .canonical_identity_hash()
        .map_err(|_| "single-aggregate VSS construction identity does not hash".to_owned())?;
    let single_aggregate_oracle_catalog =
        single_aggregate_construction
            .oracle_equation_catalog()
            .map_err(|_| "single-aggregate VSS oracle catalog does not derive".to_owned())?;
    let single_aggregate_oracle_catalog_hash = single_aggregate_construction
        .oracle_equation_catalog_hash()
        .map_err(|_| "single-aggregate VSS oracle catalog does not hash".to_owned())?;
    let modeled_candidate_quotient_source_degree_bound_exclusive = 1_u64
        .checked_shl(
            u32::try_from(modeled_candidate_quotient_parameters.table_variable_count)
                .map_err(|_| "modeled VSS quotient table width exceeds u32".to_owned())?,
        )
        .ok_or_else(|| "modeled VSS quotient source degree overflowed".to_owned())?;
    if candidate_grid
        .iter()
        .any(|candidate| candidate.physical_row_count < modeled_candidate.physical_row_count)
        || current_geometry.relation_trace_domain_size
            != u64::try_from(measurement.trace_value_count())
                .map_err(|_| "current VSS trace size exceeds u64".to_owned())?
        || current_geometry.prover_column_count != work_ledger.direct_source_column_count_per_lane
        || current_geometry.coefficient_chunk_count_per_source
            != work_ledger.coefficient_chunk_count_per_source
        || current_geometry.physical_row_count != work_ledger.row_count
        || current_geometry.lane_dft_count != work_ledger.lane_dft_count
        || current_geometry.butterfly_count != work_ledger.butterfly_count
        || current_geometry.column_value_delivery_count != work_ledger.column_value_delivery_count
        || current_geometry.salted_leaf_keccak_permutation_count
            != work_ledger.salted_leaf_keccak_permutation_count
        || modeled_candidate_capacity_refusal.aggregate_column_role_count
            <= modeled_candidate_capacity_refusal.aggregate_table_width
        || modeled_candidate_quotient_batch.direct_aggregate_column_role_count
            != modeled_candidate.aggregate_column_role_count
        || modeled_candidate_quotient_batch.quotient_aggregate_column_role_count
            > modeled_candidate_quotient_batch.aggregate_table_width
        || modeled_candidate_quotient_batch.opening_claim_count
            != modeled_candidate.opening_point_count
        || modeled_candidate_quotient_batch.query_count != work_ledger.opening_query_count
        || modeled_candidate_quotient_batch.agreement_ceiling
            >= modeled_candidate_quotient_batch.query_domain_size
        || modeled_candidate_quotient_construction.application_statement_schema_identifier()
            != ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER
        || modeled_candidate_quotient_construction.trace_domain_size
            != modeled_candidate.relation_trace_domain_size
        || modeled_candidate_quotient_construction.evaluation_domain_size
            != modeled_candidate_quotient_batch.query_domain_size
        || modeled_candidate_quotient_construction.opening_degree_bound_exclusive
            != modeled_candidate.opening_degree_bound_exclusive
        || modeled_candidate_quotient_parameters.logical_polynomial_coefficient_count
            != ROW_CODE_WHIR_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT
        || u64::try_from(modeled_candidate_quotient_parameters.logical_polynomials_per_physical_row)
            .ok()
            != Some(modeled_candidate.logical_polynomials_per_physical_row)
        || modeled_candidate_quotient_parameters.physical_row_witness_variable_count != 21
        || modeled_candidate_quotient_parameters.table_variable_count != 22
        || modeled_candidate_quotient_parameters.polynomial_commitment_variable_count != 24
        || modeled_candidate_quotient_parameters.row_code_log_inverse_rate != 2
        || modeled_candidate_quotient_source_degree_bound_exclusive
            != modeled_candidate_quotient_batch.source_degree_bound_exclusive
        || modeled_candidate_quotient_construction.aggregate_column_roles
            != [
                RowCodeWhirAggregateColumnRole::OpeningClaimQuotientBatch {
                    opening_point_count: 24,
                },
                RowCodeWhirAggregateColumnRole::BoundReduction,
            ]
        || modeled_candidate_quotient_construction.aggregate_logical_column_count() != 2
        || modeled_candidate_quotient_construction.aggregate_table_width() != 4
        || modeled_candidate_quotient_construction
            .aggregate_opening_point_count()
            .ok()
            != Some(24)
        || modeled_candidate_quotient_construction
            .uses_opening_claim_quotient_batch()
            .ok()
            != Some(true)
        || modeled_candidate_quotient_outer_query_count
            != usize::try_from(modeled_candidate_quotient_batch.query_count)
                .map_err(|_| "modeled VSS quotient query count exceeds usize".to_owned())?
        || modeled_candidate_quotient_opening_batches.len()
            != modeled_candidate_quotient_outer_query_count
                .checked_add(modeled_candidate_quotient_bound_batch_count)
                .ok_or_else(|| "modeled VSS quotient opening-batch count overflowed".to_owned())?
        || modeled_candidate_quotient_opening_batches
            [..modeled_candidate_quotient_outer_query_count]
            .iter()
            .any(|batch| batch.requested_aggregate_column_ordinals != [0])
        || modeled_candidate_quotient_opening_batches
            [modeled_candidate_quotient_outer_query_count..]
            .iter()
            .any(|batch| batch.requested_aggregate_column_ordinals != [1])
        || single_aggregate_candidate.trace_packing_factor != 1
        || single_aggregate_candidate.logical_polynomials_per_physical_row != 32
        || single_aggregate_candidate.physical_row_count != 331
        || single_aggregate_candidate.aggregate_column_role_count
            > single_aggregate_candidate.aggregate_table_width
        || single_aggregate_candidate
            .physical_row_count
            .checked_mul(10)
            .is_none_or(|tenfold_candidate_rows| {
                current_geometry.physical_row_count >= tenfold_candidate_rows
            })
        || single_aggregate_construction.application_statement_schema_identifier()
            != ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER
        || single_aggregate_construction.trace_domain_size
            != single_aggregate_candidate.relation_trace_domain_size
        || single_aggregate_construction.evaluation_domain_size
            != u64::try_from(PHASE_ENCODED_COLUMN_COUNT)
                .map_err(|_| "single-aggregate VSS evaluation domain exceeds u64".to_owned())?
        || single_aggregate_construction.opening_degree_bound_exclusive
            != single_aggregate_candidate.opening_degree_bound_exclusive
        || single_aggregate_parameters.logical_polynomial_coefficient_count
            != ROW_CODE_WHIR_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT
        || u64::try_from(single_aggregate_parameters.logical_polynomials_per_physical_row).ok()
            != Some(single_aggregate_candidate.logical_polynomials_per_physical_row)
        || single_aggregate_parameters.physical_row_witness_variable_count != 20
        || single_aggregate_parameters.table_variable_count != 21
        || single_aggregate_parameters.polynomial_commitment_variable_count != 24
        || single_aggregate_parameters.row_code_log_inverse_rate != 3
        || single_aggregate_commitment.row_count != single_aggregate_candidate.physical_row_count
        || single_aggregate_commitment.encoded_column_count
            != u64::try_from(PHASE_ENCODED_COLUMN_COUNT)
                .map_err(|_| "single-aggregate VSS encoded domain exceeds u64".to_owned())?
        || single_aggregate_commitment.lane_count != 32
        || single_aggregate_commitment
            .lane_dft_count_per_pass
            .checked_mul(ROOT_AND_OPENING_PASS_COUNT)
            != Some(single_aggregate_candidate.lane_dft_count)
        || single_aggregate_commitment
            .butterfly_count_per_pass
            .checked_mul(ROOT_AND_OPENING_PASS_COUNT)
            != Some(single_aggregate_candidate.butterfly_count)
        || single_aggregate_commitment
            .coefficient_fold_count_per_pass
            .checked_mul(ROOT_AND_OPENING_PASS_COUNT)
            != Some(single_aggregate_candidate.coefficient_fold_count)
        || single_aggregate_commitment
            .coset_multiplication_count_per_pass
            .checked_mul(ROOT_AND_OPENING_PASS_COUNT)
            != Some(single_aggregate_candidate.coset_multiplication_count)
        || single_aggregate_commitment
            .column_value_delivery_count_per_pass
            .checked_mul(ROOT_AND_OPENING_PASS_COUNT)
            != Some(single_aggregate_candidate.column_value_delivery_count)
        || single_aggregate_commitment
            .leaf_hash_query_count_per_pass
            .checked_mul(ROOT_AND_OPENING_PASS_COUNT)
            != Some(single_aggregate_candidate.leaf_hash_query_count)
        || single_aggregate_commitment
            .merkle_parent_hash_query_count_per_pass
            .checked_mul(ROOT_AND_OPENING_PASS_COUNT)
            != Some(single_aggregate_candidate.merkle_parent_hash_query_count)
    {
        return Err("VSS relation-replay model does not reproduce production geometry".to_owned());
    }
    let retained_input_byte_length = measurement.retained_input_byte_length()?;
    let nonzero_source_coefficient_count = measurement.nonzero_source_coefficient_count()?;
    if measurement.logical_root_count() != 112 || nonzero_source_coefficient_count == 0 {
        return Err("selected VSS measurement source geometry is incomplete".to_owned());
    }
    let (mut checksum, elapsed_nanoseconds) = measure_elapsed_nanoseconds(|| {
        let mut checksum = 0xcbf2_9ce4_8422_2325_u64;
        for iteration_ordinal in 0..SOURCE_REPLAY_ITERATION_COUNT {
            let coefficients = measurement.replay_once()?;
            black_box(&coefficients);
            let middle_ordinal = coefficients.len() / 2;
            let sampled_value = coefficients
                .first()
                .ok_or_else(|| "selected VSS source replay is empty".to_owned())?
                .canonical()
                ^ coefficients[middle_ordinal].canonical().rotate_left(21)
                ^ coefficients
                    .last()
                    .ok_or_else(|| "selected VSS source replay is empty".to_owned())?
                    .canonical()
                    .rotate_left(42)
                ^ u64::try_from(coefficients.len())
                    .map_err(|_| "source-replay value count exceeds u64".to_owned())?;
            let ordinal = u64::try_from(iteration_ordinal)
                .map_err(|_| "source-replay iteration ordinal exceeds u64".to_owned())?;
            checksum = checksum
                .rotate_left(17)
                .wrapping_add(sampled_value)
                .wrapping_add(ordinal.wrapping_mul(0x9e37_79b1_85eb_ca87))
                .wrapping_mul(0x1000_0000_01b3);
        }
        Ok(checksum)
    })?;
    for hash in [
        modeled_candidate_quotient_identity_hash,
        modeled_candidate_quotient_oracle_catalog_hash,
        single_aggregate_identity_hash,
        single_aggregate_oracle_catalog_hash,
    ] {
        for hash_word in hash.chunks_exact(size_of::<u64>()) {
            checksum = checksum
                .rotate_left(17)
                .wrapping_add(u64::from_le_bytes(
                    hash_word
                        .try_into()
                        .map_err(|_| "VSS candidate identity hash is malformed".to_owned())?,
                ))
                .wrapping_mul(0x1000_0000_01b3);
        }
    }
    black_box(checksum);
    let replay_buffer_byte_length = u64::try_from(measurement.trace_value_count())
        .ok()
        .and_then(|count| count.checked_mul(size_of::<ProofBaseFieldElement>() as u64))
        .ok_or_else(|| "selected VSS replay buffer size overflowed".to_owned())?;
    Ok(PrimitiveMeasurementRecord {
        schema_version: MEASUREMENT_SCHEMA_VERSION,
        case_identifier: 5,
        case_name: "selected-vss-source-replay",
        execution_target: execution_target(),
        iteration_count: SOURCE_REPLAY_ITERATION_COUNT as u64,
        elapsed_nanoseconds,
        modeled_peak_live_byte_length: retained_input_byte_length
            .checked_add(replay_buffer_byte_length)
            .ok_or_else(|| "selected VSS source-replay live set overflowed".to_owned())?,
        checksum_hex: format!("{checksum:016x}"),
        dimensions: vec![
            dimension("logicalRootCount", measurement.logical_root_count())?,
            dimension("traceValueCount", measurement.trace_value_count())?,
            dimension("columnOrdinal", measurement.column_ordinal() as usize)?,
            PrimitiveMeasurementDimension {
                name: "nonzeroSourceCoefficientCount",
                value: nonzero_source_coefficient_count,
            },
            PrimitiveMeasurementDimension {
                name: "retainedInputByteLength",
                value: retained_input_byte_length,
            },
            dimension_u64(
                "basePhaseMaterializationPassCount",
                work_ledger.materialization_pass_count,
            ),
            dimension_u64(
                "basePhaseTracePackingFactor",
                current_geometry.trace_packing_factor,
            ),
            dimension_u64(
                "basePhasePhysicalRowWidth",
                work_ledger.logical_polynomials_per_physical_row,
            ),
            dimension_u64(
                "basePhaseLogicalPolynomialCoefficientCount",
                u64::try_from(ROW_CODE_WHIR_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT)
                    .map_err(|_| "selected VSS coefficient count exceeds u64".to_owned())?,
            ),
            dimension_u64(
                "basePhaseTraceMaskDegreeBoundExclusive",
                current_geometry
                    .prover_column_degree_bound_exclusive
                    .checked_sub(current_geometry.relation_trace_domain_size)
                    .ok_or_else(|| "selected VSS trace-mask degree underflowed".to_owned())?,
            ),
            dimension_u64(
                "basePhaseProverColumnDegreeBoundExclusive",
                current_geometry.prover_column_degree_bound_exclusive,
            ),
            dimension_u64(
                "basePhaseMaximumRangeConstraintNumeratorDegree",
                current_geometry.maximum_range_constraint_numerator_degree,
            ),
            dimension_u64("basePhaseRowCount", work_ledger.row_count),
            dimension_u64("basePhaseLaneCount", work_ledger.lane_count),
            dimension_u64(
                "basePhaseOpeningQueryCount",
                work_ledger.opening_query_count,
            ),
            dimension_u64(
                "aggregateWidePadQueryCount",
                work_ledger.aggregate_wide_pad_query_count,
            ),
            dimension_u64(
                "basePhaseLogicalChunkCountPerLane",
                work_ledger.logical_chunk_count_per_lane,
            ),
            dimension_u64(
                "basePhaseDirectSourceChunkCountPerLane",
                work_ledger.direct_source_chunk_count_per_lane,
            ),
            dimension_u64(
                "basePhaseDirectSourceColumnCountPerLane",
                work_ledger.direct_source_column_count_per_lane,
            ),
            dimension_u64(
                "basePhaseCoefficientChunkCountPerSource",
                work_ledger.coefficient_chunk_count_per_source,
            ),
            dimension_u64(
                "basePhaseReversedSourceChunkCountPerLane",
                work_ledger.reversed_source_chunk_count_per_lane,
            ),
            dimension_u64(
                "basePhaseSourceReplayCount",
                work_ledger.source_replay_count,
            ),
            dimension_u64(
                "basePhaseBoundSourceReplayCount",
                work_ledger.bound_source_replay_count,
            ),
            dimension_u64(
                "basePhaseProverSourceReplayCount",
                work_ledger.prover_source_replay_count,
            ),
            dimension_u64(
                "basePhaseReversedPolynomialReconstructionCount",
                work_ledger.reversed_polynomial_reconstruction_count,
            ),
            dimension_u64("basePhaseLaneDftCount", work_ledger.lane_dft_count),
            dimension_u64("basePhaseButterflyCount", work_ledger.butterfly_count),
            dimension_u64(
                "basePhaseCosetMultiplicationCount",
                work_ledger.coset_multiplication_count,
            ),
            dimension_u64(
                "basePhaseColumnValueDeliveryCount",
                work_ledger.column_value_delivery_count,
            ),
            dimension_u64(
                "basePhaseTransportedValueByteLength",
                work_ledger.transported_value_byte_length,
            ),
            dimension_u64(
                "basePhaseLeafHashQueryCount",
                work_ledger.leaf_hash_query_count,
            ),
            dimension_u64(
                "basePhaseSaltedLeafKeccakPermutationCount",
                work_ledger.salted_leaf_keccak_permutation_count,
            ),
            dimension_u64(
                "basePhaseMerkleParentHashQueryCount",
                work_ledger.merkle_parent_hash_query_count,
            ),
            dimension_u64(
                "basePhasePrivateLeafSaltDerivationCount",
                work_ledger.private_leaf_salt_derivation_count,
            ),
            dimension_u64(
                "modeledCandidateTracePackingFactor",
                modeled_candidate.trace_packing_factor,
            ),
            dimension_u64(
                "modeledCandidatePhysicalRowWidth",
                modeled_candidate.logical_polynomials_per_physical_row,
            ),
            dimension_u64(
                "modeledCandidateRelationTraceValueCount",
                modeled_candidate.relation_trace_domain_size,
            ),
            dimension_u64(
                "modeledCandidateMaterialGroupCount",
                modeled_candidate.material_group_count,
            ),
            dimension_u64(
                "modeledCandidateMaterialProverColumnCount",
                modeled_candidate.material_prover_column_count,
            ),
            dimension_u64(
                "modeledCandidateQuotientGroupCount",
                modeled_candidate.quotient_group_count,
            ),
            dimension_u64(
                "modeledCandidateQuotientProverColumnCount",
                modeled_candidate.quotient_prover_column_count,
            ),
            dimension_u64(
                "modeledCandidateShiftSelectorColumnCount",
                modeled_candidate.shift_selector_column_count,
            ),
            dimension_u64(
                "modeledCandidateProverColumnCount",
                modeled_candidate.prover_column_count,
            ),
            dimension_u64(
                "modeledCandidateProverColumnDegreeBoundExclusive",
                modeled_candidate.prover_column_degree_bound_exclusive,
            ),
            dimension_u64(
                "modeledCandidateMaximumRangeConstraintNumeratorDegree",
                modeled_candidate.maximum_range_constraint_numerator_degree,
            ),
            dimension_u64(
                "modeledCandidateOpeningDegreeBoundExclusive",
                modeled_candidate.opening_degree_bound_exclusive,
            ),
            dimension_u64(
                "modeledCandidateRowCodeInverseRate",
                modeled_candidate.row_code_inverse_rate,
            ),
            dimension_u64(
                "modeledCandidateOpeningPointCount",
                modeled_candidate_capacity_refusal.opening_point_count,
            ),
            dimension_u64(
                "modeledCandidateBoundReductionAggregateColumnCount",
                modeled_candidate_capacity_refusal.bound_reduction_aggregate_column_count,
            ),
            dimension_u64(
                "modeledCandidateAggregateColumnRoleCount",
                modeled_candidate_capacity_refusal.aggregate_column_role_count,
            ),
            dimension_u64(
                "modeledCandidateAggregateTableWidth",
                modeled_candidate_capacity_refusal.aggregate_table_width,
            ),
            dimension_u64(
                "modeledCandidateCoefficientChunkCountPerSource",
                modeled_candidate.coefficient_chunk_count_per_source,
            ),
            dimension_u64(
                "modeledCandidateRowCount",
                modeled_candidate.physical_row_count,
            ),
            dimension_u64(
                "modeledCandidateLaneDftCount",
                modeled_candidate.lane_dft_count,
            ),
            dimension_u64(
                "modeledCandidateButterflyCount",
                modeled_candidate.butterfly_count,
            ),
            dimension_u64(
                "modeledCandidateCoefficientFoldCount",
                modeled_candidate.coefficient_fold_count,
            ),
            dimension_u64(
                "modeledCandidateCosetMultiplicationCount",
                modeled_candidate.coset_multiplication_count,
            ),
            dimension_u64(
                "modeledCandidatePrivateHighHalfValueGenerationCount",
                modeled_candidate.private_high_half_value_generation_count,
            ),
            dimension_u64(
                "modeledCandidateColumnValueDeliveryCount",
                modeled_candidate.column_value_delivery_count,
            ),
            dimension_u64(
                "modeledCandidateTransportedValueByteLength",
                modeled_candidate.transported_value_byte_length,
            ),
            dimension_u64(
                "modeledCandidateLeafHashQueryCount",
                modeled_candidate.leaf_hash_query_count,
            ),
            dimension_u64(
                "modeledCandidateSaltedLeafKeccakPermutationCount",
                modeled_candidate.salted_leaf_keccak_permutation_count,
            ),
            dimension_u64(
                "modeledCandidateMerkleParentHashQueryCount",
                modeled_candidate.merkle_parent_hash_query_count,
            ),
            dimension_u64(
                "modeledCandidatePrivateLeafSaltDerivationCount",
                modeled_candidate.private_leaf_salt_derivation_count,
            ),
            dimension_u64(
                "modeledCandidateRetainedSourceMaterializationCount",
                modeled_candidate.retained_source_materialization_count,
            ),
            dimension_u64(
                "modeledCandidateSourceTraceValueGenerationCount",
                modeled_candidate.source_trace_value_generation_count,
            ),
            dimension_u64(
                "modeledCandidateRetainedCoefficientGroupByteLength",
                modeled_candidate.retained_coefficient_group_byte_length,
            ),
            dimension_u64(
                "modeledCandidateLogicalRowChunkByteLength",
                modeled_candidate.logical_row_chunk_byte_length,
            ),
            dimension_u64(
                "modeledCandidateDirectAggregateColumnRoleCount",
                modeled_candidate_quotient_batch.direct_aggregate_column_role_count,
            ),
            dimension_u64(
                "modeledCandidateQuotientAggregateColumnRoleCount",
                modeled_candidate_quotient_batch.quotient_aggregate_column_role_count,
            ),
            dimension_u64(
                "modeledCandidateQuotientSourceDegreeBoundExclusive",
                modeled_candidate_quotient_batch.source_degree_bound_exclusive,
            ),
            dimension_u64(
                "modeledCandidateQuotientOpeningClaimCount",
                modeled_candidate_quotient_batch.opening_claim_count,
            ),
            dimension_u64(
                "modeledCandidateBatchedQuotientDegreeBoundExclusive",
                modeled_candidate_quotient_batch.batched_quotient_degree_bound_exclusive,
            ),
            dimension_u64(
                "modeledCandidateQuotientDiscrepancyNumeratorDegreeBoundInclusive",
                modeled_candidate_quotient_batch.discrepancy_numerator_degree_bound_inclusive,
            ),
            dimension_u64(
                "modeledCandidateQuotientQueryDomainSize",
                modeled_candidate_quotient_batch.query_domain_size,
            ),
            dimension_u64(
                "modeledCandidateQuotientQueryCount",
                modeled_candidate_quotient_batch.query_count,
            ),
            dimension_u64(
                "modeledCandidateQuotientAgreementCeiling",
                modeled_candidate_quotient_batch.agreement_ceiling,
            ),
            dimension(
                "modeledCandidateQuotientConstructionIdentityByteLength",
                modeled_candidate_quotient_identity_bytes.len(),
            )?,
            dimension(
                "modeledCandidateQuotientConstructionIdentityHashByteLength",
                modeled_candidate_quotient_identity_hash.len(),
            )?,
            dimension(
                "modeledCandidateQuotientOracleEquationCatalogHashByteLength",
                modeled_candidate_quotient_oracle_catalog_hash.len(),
            )?,
            dimension(
                "modeledCandidateQuotientPhysicalRowWitnessVariableCount",
                modeled_candidate_quotient_parameters.physical_row_witness_variable_count,
            )?,
            dimension(
                "modeledCandidateQuotientTableVariableCount",
                modeled_candidate_quotient_parameters.table_variable_count,
            )?,
            dimension(
                "modeledCandidateQuotientPolynomialCommitmentVariableCount",
                modeled_candidate_quotient_parameters.polynomial_commitment_variable_count,
            )?,
            dimension(
                "modeledCandidateQuotientRowCodeLogInverseRate",
                modeled_candidate_quotient_parameters.row_code_log_inverse_rate,
            )?,
            dimension(
                "modeledCandidateQuotientAggregateLogicalColumnCount",
                modeled_candidate_quotient_construction.aggregate_logical_column_count(),
            )?,
            dimension(
                "modeledCandidateQuotientAggregateTableWidth",
                modeled_candidate_quotient_construction.aggregate_table_width(),
            )?,
            dimension(
                "modeledCandidateQuotientPhaseOrderCount",
                modeled_candidate_quotient_construction.phase_order.len(),
            )?,
            dimension(
                "modeledCandidateQuotientTranscriptOperationCount",
                modeled_candidate_quotient_construction
                    .transcript_operations()
                    .len(),
            )?,
            dimension(
                "modeledCandidateQuotientOpeningBatchCount",
                modeled_candidate_quotient_opening_batches.len(),
            )?,
            dimension(
                "modeledCandidateQuotientOuterOpeningBatchCount",
                modeled_candidate_quotient_outer_query_count,
            )?,
            dimension(
                "modeledCandidateQuotientBoundOpeningBatchCount",
                modeled_candidate_quotient_bound_batch_count,
            )?,
            dimension(
                "modeledCandidateQuotientBoundReductionBlockCount",
                modeled_candidate_quotient_construction
                    .bound_reduction_blocks
                    .len(),
            )?,
            dimension(
                "modeledCandidateQuotientBoundQueryCount",
                modeled_candidate_quotient_bound_query_count,
            )?,
            dimension(
                "modeledCandidateQuotientBoundDegreeTestCount",
                modeled_candidate_quotient_bound_degree_test_count,
            )?,
            dimension(
                "modeledCandidateQuotientProofSectionCount",
                modeled_candidate_quotient_construction
                    .proof_sections()
                    .len(),
            )?,
            dimension(
                "modeledCandidateQuotientCheckpointCount",
                modeled_candidate_quotient_construction.checkpoints().len(),
            )?,
            dimension_u64(
                "modeledCandidateQuotientMaximumTranscriptHashQueryCount",
                modeled_candidate_quotient_oracle_catalog
                    .maximum_transcript_hash_query_count()
                    .map_err(|_| {
                        "modeled VSS quotient transcript query count does not derive".to_owned()
                    })?,
            ),
            dimension_u64(
                "modeledCandidateQuotientLogicalVerifierMessageCount",
                modeled_candidate_quotient_oracle_catalog
                    .logical_verifier_message_count()
                    .map_err(|_| {
                        "modeled VSS quotient verifier message count does not derive".to_owned()
                    })?,
            ),
            dimension_u64(
                "singleAggregateCandidateTracePackingFactor",
                single_aggregate_candidate.trace_packing_factor,
            ),
            dimension_u64(
                "singleAggregateCandidatePhysicalRowWidth",
                single_aggregate_candidate.logical_polynomials_per_physical_row,
            ),
            dimension_u64(
                "singleAggregateCandidateOpeningDegreeBoundExclusive",
                single_aggregate_candidate.opening_degree_bound_exclusive,
            ),
            dimension_u64(
                "singleAggregateCandidateRowCount",
                single_aggregate_candidate.physical_row_count,
            ),
            dimension_u64(
                "singleAggregateCandidateLaneDftCount",
                single_aggregate_candidate.lane_dft_count,
            ),
            dimension_u64(
                "singleAggregateCandidateSaltedLeafKeccakPermutationCount",
                single_aggregate_candidate.salted_leaf_keccak_permutation_count,
            ),
            dimension_u64(
                "singleAggregateCandidateAggregateColumnRoleCount",
                single_aggregate_candidate.aggregate_column_role_count,
            ),
            dimension_u64(
                "singleAggregateCandidateAggregateTableWidth",
                single_aggregate_candidate.aggregate_table_width,
            ),
            dimension(
                "singleAggregateCandidateConstructionIdentityByteLength",
                single_aggregate_identity_bytes.len(),
            )?,
            dimension(
                "singleAggregateCandidateConstructionIdentityHashByteLength",
                single_aggregate_identity_hash.len(),
            )?,
            dimension(
                "singleAggregateCandidateOracleEquationCatalogHashByteLength",
                single_aggregate_oracle_catalog_hash.len(),
            )?,
            dimension(
                "singleAggregateCandidatePhysicalRowWitnessVariableCount",
                single_aggregate_parameters.physical_row_witness_variable_count,
            )?,
            dimension(
                "singleAggregateCandidateTableVariableCount",
                single_aggregate_parameters.table_variable_count,
            )?,
            dimension(
                "singleAggregateCandidatePolynomialCommitmentVariableCount",
                single_aggregate_parameters.polynomial_commitment_variable_count,
            )?,
            dimension(
                "singleAggregateCandidateRowCodeLogInverseRate",
                single_aggregate_parameters.row_code_log_inverse_rate,
            )?,
            dimension(
                "singleAggregateCandidatePhaseOrderCount",
                single_aggregate_construction.phase_order.len(),
            )?,
            dimension(
                "singleAggregateCandidateTranscriptOperationCount",
                single_aggregate_construction.transcript_operations().len(),
            )?,
            dimension(
                "singleAggregateCandidateOpeningBatchCount",
                single_aggregate_construction.opening_batches().len(),
            )?,
            dimension(
                "singleAggregateCandidateProofSectionCount",
                single_aggregate_construction.proof_sections().len(),
            )?,
            dimension(
                "singleAggregateCandidateCheckpointCount",
                single_aggregate_construction.checkpoints().len(),
            )?,
            dimension_u64(
                "singleAggregateCandidateMaximumTranscriptHashQueryCount",
                single_aggregate_oracle_catalog
                    .maximum_transcript_hash_query_count()
                    .map_err(|_| {
                        "single-aggregate VSS transcript query count does not derive".to_owned()
                    })?,
            ),
            dimension_u64(
                "singleAggregateCandidateLogicalVerifierMessageCount",
                single_aggregate_oracle_catalog
                    .logical_verifier_message_count()
                    .map_err(|_| {
                        "single-aggregate VSS verifier message count does not derive".to_owned()
                    })?,
            ),
            dimension_u64(
                "singleAggregateCandidateBasePhaseWorkingBufferByteLength",
                single_aggregate_commitment.working_buffer_byte_length,
            ),
            dimension_u64(
                "singleAggregateCandidateBasePhaseHashStateByteLength",
                single_aggregate_commitment.hash_state_byte_length,
            ),
            dimension_u64(
                "singleAggregateCandidateBasePhaseDigestPlaneByteLength",
                single_aggregate_commitment.digest_plane_byte_length,
            ),
            dimension_u64(
                "singleAggregateCandidateBasePhaseAlgorithmLiveSetByteLength",
                single_aggregate_commitment.algorithm_live_set_byte_length,
            ),
        ],
    })
}

fn measure_selected_vss_production_weighted_source_replay()
-> Result<PrimitiveMeasurementRecord, String> {
    let measurement = SelectedVssSourceReplayMeasurement::prepare()?;
    let work_ledger = derive_selected_vss_base_phase_work_ledger()?;
    let retained_input_byte_length = measurement.retained_input_byte_length()?;
    let production_recipe_count = measurement.production_recipe_count();
    if u64::try_from(production_recipe_count).ok()
        != Some(work_ledger.direct_source_column_count_per_lane)
        || work_ledger.reversed_source_chunk_count_per_lane != 0
        || work_ledger.reversed_polynomial_reconstruction_count != 0
    {
        return Err(format!(
            "selected VSS production replay catalog does not match the base phase: recipes={production_recipe_count}, columns={}, chunks={}, reversed={}, reconstructions={}",
            work_ledger.direct_source_column_count_per_lane,
            work_ledger.direct_source_chunk_count_per_lane,
            work_ledger.reversed_source_chunk_count_per_lane,
            work_ledger.reversed_polynomial_reconstruction_count,
        ));
    }
    let (checksum, elapsed_nanoseconds) =
        measure_elapsed_nanoseconds(|| measurement.replay_production_recipe_catalog_once())?;
    black_box(checksum);
    let replay_buffer_byte_length = u64::try_from(measurement.trace_value_count())
        .ok()
        .and_then(|count| count.checked_mul(size_of::<ProofBaseFieldElement>() as u64))
        .ok_or_else(|| "selected VSS production replay buffer size overflowed".to_owned())?;
    let root_pass_source_catalog_pass_count = work_ledger
        .lane_count
        .checked_mul(work_ledger.coefficient_chunk_count_per_source)
        .ok_or_else(|| "selected VSS root source-catalog pass count overflowed".to_owned())?;
    let current_two_pass_source_catalog_pass_count = root_pass_source_catalog_pass_count
        .checked_mul(work_ledger.materialization_pass_count)
        .ok_or_else(|| "selected VSS source-catalog pass count overflowed".to_owned())?;
    Ok(PrimitiveMeasurementRecord {
        schema_version: MEASUREMENT_SCHEMA_VERSION,
        case_identifier: 8,
        case_name: "selected-vss-production-weighted-source-replay",
        execution_target: execution_target(),
        iteration_count: PRODUCTION_WEIGHTED_SOURCE_REPLAY_ITERATION_COUNT as u64,
        elapsed_nanoseconds,
        modeled_peak_live_byte_length: retained_input_byte_length
            .checked_add(replay_buffer_byte_length)
            .ok_or_else(|| "selected VSS production replay live set overflowed".to_owned())?,
        checksum_hex: format!("{checksum:016x}"),
        dimensions: vec![
            dimension("logicalRootCount", measurement.logical_root_count())?,
            dimension("traceValueCount", measurement.trace_value_count())?,
            dimension("productionRecipeCount", production_recipe_count)?,
            PrimitiveMeasurementDimension {
                name: "retainedInputByteLength",
                value: retained_input_byte_length,
            },
            dimension_u64(
                "basePhaseDirectSourceChunkCountPerLane",
                work_ledger.direct_source_chunk_count_per_lane,
            ),
            dimension_u64(
                "basePhaseDirectSourceColumnCountPerLane",
                work_ledger.direct_source_column_count_per_lane,
            ),
            dimension_u64(
                "basePhaseCoefficientChunkCountPerSource",
                work_ledger.coefficient_chunk_count_per_source,
            ),
            dimension_u64(
                "basePhaseReversedSourceChunkCountPerLane",
                work_ledger.reversed_source_chunk_count_per_lane,
            ),
            dimension_u64(
                "basePhaseRootPassSourceCatalogPassCount",
                root_pass_source_catalog_pass_count,
            ),
            dimension_u64(
                "basePhaseCurrentTwoPassSourceCatalogPassCount",
                current_two_pass_source_catalog_pass_count,
            ),
        ],
    })
}

fn measure_vss_relation_replay_candidate_retained_group()
-> Result<PrimitiveMeasurementRecord, String> {
    let candidate = derive_vss_relation_replay_candidate_ledger(
        VSS_RELATION_REPLAY_CANDIDATE_TRACE_PACKING_FACTOR,
        VSS_RELATION_REPLAY_CANDIDATE_RETAINED_GROUP_WIDTH as u64,
    )?
    .ok_or_else(|| "VSS retained-group candidate does not fit its opening bound".to_owned())?;
    let measurement = SelectedVssSourceReplayMeasurement::prepare_relation_replay_candidate(
        candidate.trace_packing_factor,
        candidate.opening_degree_bound_exclusive,
    )?;
    let retained_recipe_count = VSS_RELATION_REPLAY_CANDIDATE_RETAINED_GROUP_WIDTH;
    let retained_input_byte_length = measurement.retained_input_byte_length()?;
    let prover_column_degree_bound_exclusive =
        u64::try_from(measurement.prover_column_degree_bound_exclusive())
            .map_err(|_| "VSS retained-group degree bound exceeds u64".to_owned())?;
    let replay_buffer_byte_length = u64::try_from(measurement.trace_value_count())
        .ok()
        .and_then(|count| count.checked_mul(size_of::<ProofBaseFieldElement>() as u64))
        .ok_or_else(|| "VSS retained-group replay buffer size overflowed".to_owned())?;
    let retained_group_header_byte_length = u64::try_from(retained_recipe_count)
        .ok()
        .and_then(|count| {
            count.checked_mul(size_of::<Zeroizing<Vec<ProofBaseFieldElement>>>() as u64)
        })
        .ok_or_else(|| "VSS retained-group header size overflowed".to_owned())?;
    if measurement.trace_packing_factor() != candidate.trace_packing_factor
        || measurement.trace_value_count()
            != usize::try_from(candidate.relation_trace_domain_size)
                .map_err(|_| "VSS retained-group trace size exceeds usize".to_owned())?
        || measurement.production_recipe_count()
            != usize::try_from(candidate.prover_column_count)
                .map_err(|_| "VSS retained-group recipe count exceeds usize".to_owned())?
        || prover_column_degree_bound_exclusive != candidate.prover_column_degree_bound_exclusive
        || u64::try_from(retained_recipe_count).ok().and_then(|width| {
            width
                .checked_mul(prover_column_degree_bound_exclusive)
                .and_then(|count| count.checked_mul(size_of::<ProofBaseFieldElement>() as u64))
        }) != Some(candidate.retained_coefficient_group_byte_length)
    {
        return Err("VSS retained-group candidate disagrees with the compiler".to_owned());
    }
    let (checksum, elapsed_nanoseconds) = measure_elapsed_nanoseconds(|| {
        measurement.materialize_retained_recipe_group_once(retained_recipe_count)
    })?;
    black_box(checksum);
    let modeled_peak_live_byte_length = retained_input_byte_length
        .checked_add(candidate.retained_coefficient_group_byte_length)
        .and_then(|value| value.checked_add(replay_buffer_byte_length))
        .and_then(|value| value.checked_add(retained_group_header_byte_length))
        .ok_or_else(|| "VSS retained-group owned live set overflowed".to_owned())?;
    Ok(PrimitiveMeasurementRecord {
        schema_version: MEASUREMENT_SCHEMA_VERSION,
        case_identifier: 9,
        case_name: "vss-relation-replay-candidate-retained-group",
        execution_target: execution_target(),
        iteration_count: 1,
        elapsed_nanoseconds,
        modeled_peak_live_byte_length,
        checksum_hex: format!("{checksum:016x}"),
        dimensions: vec![
            dimension_u64("tracePackingFactor", candidate.trace_packing_factor),
            dimension_u64("physicalRowWidth", 64),
            dimension_u64("traceValueCount", candidate.relation_trace_domain_size),
            dimension_u64(
                "proverColumnDegreeBoundExclusive",
                candidate.prover_column_degree_bound_exclusive,
            ),
            dimension_u64("productionRecipeCount", candidate.prover_column_count),
            dimension("retainedRecipeCount", retained_recipe_count)?,
            dimension_u64(
                "retainedCoefficientPayloadByteLength",
                candidate.retained_coefficient_group_byte_length,
            ),
            dimension_u64("replayBufferByteLength", replay_buffer_byte_length),
            dimension_u64(
                "retainedGroupHeaderByteLength",
                retained_group_header_byte_length,
            ),
            PrimitiveMeasurementDimension {
                name: "retainedInputByteLength",
                value: retained_input_byte_length,
            },
            dimension_u64(
                "logicalRowChunkByteLength",
                candidate.logical_row_chunk_byte_length,
            ),
            dimension(
                "relationPlanHashByteLength",
                measurement.relation_plan_hash().len(),
            )?,
        ],
    })
}

fn assemble_vss_relation_replay_candidate_row_chunk(
    retained_coefficients: &[Zeroizing<Vec<ProofBaseFieldElement>>],
    logical_polynomial_coefficient_count: usize,
    coefficient_chunk_ordinal: usize,
    geometry: RowEncodingGeometry,
) -> Result<Zeroizing<Vec<ProofBaseFieldElement>>, String> {
    if retained_coefficients.is_empty() || logical_polynomial_coefficient_count == 0 {
        return Err("VSS candidate row chunk source is empty".to_owned());
    }
    let prover_column_degree_bound_exclusive = retained_coefficients[0].len();
    if prover_column_degree_bound_exclusive == 0
        || retained_coefficients
            .iter()
            .any(|coefficients| coefficients.len() != prover_column_degree_bound_exclusive)
    {
        return Err("VSS candidate row chunk source widths disagree".to_owned());
    }
    let expected_witness_value_count = retained_coefficients
        .len()
        .checked_mul(logical_polynomial_coefficient_count)
        .ok_or_else(|| "VSS candidate row witness size overflowed".to_owned())?;
    if geometry.witness_values_per_row != expected_witness_value_count {
        return Err("VSS candidate row width disagrees with its geometry".to_owned());
    }
    let coefficient_chunk_count =
        prover_column_degree_bound_exclusive.div_ceil(logical_polynomial_coefficient_count);
    if coefficient_chunk_ordinal >= coefficient_chunk_count {
        return Err("VSS candidate coefficient chunk is outside the source".to_owned());
    }
    let source_start = coefficient_chunk_ordinal
        .checked_mul(logical_polynomial_coefficient_count)
        .ok_or_else(|| "VSS candidate coefficient chunk offset overflowed".to_owned())?;
    let source_end = source_start
        .checked_add(logical_polynomial_coefficient_count)
        .map(|end| end.min(prover_column_degree_bound_exclusive))
        .ok_or_else(|| "VSS candidate coefficient chunk end overflowed".to_owned())?;
    let copied_coefficient_count = source_end
        .checked_sub(source_start)
        .ok_or_else(|| "VSS candidate coefficient chunk is reversed".to_owned())?;
    let mut row_witness = Vec::new();
    row_witness
        .try_reserve_exact(geometry.padded_coefficient_count)
        .map_err(|_| "VSS candidate row allocation failed".to_owned())?;
    row_witness.resize(geometry.witness_values_per_row, ProofBaseFieldElement::ZERO);
    for (recipe_ordinal, coefficients) in retained_coefficients.iter().enumerate() {
        let destination_start = recipe_ordinal
            .checked_mul(logical_polynomial_coefficient_count)
            .ok_or_else(|| "VSS candidate row destination offset overflowed".to_owned())?;
        let destination_end = destination_start
            .checked_add(copied_coefficient_count)
            .ok_or_else(|| "VSS candidate row destination end overflowed".to_owned())?;
        row_witness[destination_start..destination_end]
            .copy_from_slice(&coefficients[source_start..source_end]);
    }
    Ok(Zeroizing::new(row_witness))
}

fn measure_vss_relation_replay_candidate_row_lane_stripe()
-> Result<PrimitiveMeasurementRecord, String> {
    let candidate = derive_vss_relation_replay_candidate_ledger(
        VSS_RELATION_REPLAY_CANDIDATE_TRACE_PACKING_FACTOR,
        VSS_RELATION_REPLAY_CANDIDATE_RETAINED_GROUP_WIDTH as u64,
    )?
    .ok_or_else(|| "VSS row-lane candidate does not fit its opening bound".to_owned())?;
    let measurement = SelectedVssSourceReplayMeasurement::prepare_relation_replay_candidate(
        candidate.trace_packing_factor,
        candidate.opening_degree_bound_exclusive,
    )?;
    let retained_group = measurement
        .materialize_retained_recipe_group(VSS_RELATION_REPLAY_CANDIDATE_RETAINED_GROUP_WIDTH)?;
    let logical_polynomial_coefficient_count = ROW_CODE_WHIR_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT;
    let witness_value_count = usize::try_from(candidate.opening_degree_bound_exclusive)
        .map_err(|_| "VSS row-lane witness size exceeds usize".to_owned())?;
    if !witness_value_count.is_power_of_two() || !candidate.row_code_inverse_rate.is_power_of_two()
    {
        return Err("VSS row-lane geometry is not power-of-two".to_owned());
    }
    let geometry = RowEncodingGeometry::new_weighted_batch_with_log_inverse_rate(
        usize::try_from(candidate.physical_row_count)
            .map_err(|_| "VSS row-lane row count exceeds usize".to_owned())?,
        witness_value_count.ilog2() as usize,
        candidate.row_code_inverse_rate.ilog2() as usize,
    )?;
    let coefficient_chunk_count = usize::try_from(candidate.coefficient_chunk_count_per_source)
        .map_err(|_| "VSS row-lane chunk count exceeds usize".to_owned())?;
    let retained_recipe_count = retained_group.coefficients.len();
    let expected_retained_payload_byte_length = u64::try_from(retained_recipe_count)
        .ok()
        .and_then(|count| {
            count
                .checked_mul(candidate.prover_column_degree_bound_exclusive)
                .and_then(|value_count| {
                    value_count.checked_mul(size_of::<ProofBaseFieldElement>() as u64)
                })
        })
        .ok_or_else(|| "VSS row-lane retained payload size overflowed".to_owned())?;
    let expected_chunk_count = measurement
        .prover_column_degree_bound_exclusive()
        .div_ceil(logical_polynomial_coefficient_count);
    let lane_count = geometry
        .encoded_column_count
        .checked_div(PHASE_LANE_COLUMN_COUNT)
        .filter(|count| count.is_power_of_two())
        .ok_or_else(|| "VSS row-lane count is invalid".to_owned())?;
    if retained_recipe_count != VSS_RELATION_REPLAY_CANDIDATE_RETAINED_GROUP_WIDTH
        || measurement.prover_column_degree_bound_exclusive()
            != usize::try_from(candidate.prover_column_degree_bound_exclusive)
                .map_err(|_| "VSS row-lane degree bound exceeds usize".to_owned())?
        || expected_retained_payload_byte_length != candidate.retained_coefficient_group_byte_length
        || geometry.witness_values_per_row != witness_value_count
        || geometry.padded_coefficient_count != witness_value_count * 2
        || geometry.encoded_column_count != PHASE_ENCODED_COLUMN_COUNT
        || coefficient_chunk_count != expected_chunk_count
        || lane_count != PHASE_ENCODED_COLUMN_COUNT / PHASE_LANE_COLUMN_COUNT
    {
        return Err("VSS row-lane candidate disagrees with production geometry".to_owned());
    }

    let full_domain =
        ProofEvaluationDomain::new(PHASE_ENCODED_COLUMN_COUNT, PROOF_EVALUATION_COSET_OFFSET)
            .map_err(|_| "VSS row-lane domain is invalid".to_owned())?;
    let private_row_pad_seed = [0x6d_u8; PRIVATE_ROW_PAD_SEED_BYTE_LENGTH];
    let ((checksum, poll_count), elapsed_nanoseconds) = measure_elapsed_nanoseconds(|| {
        let mut checksum = retained_group.checksum;
        let mut poll_count = 0_usize;
        for coefficient_chunk_ordinal in 0..coefficient_chunk_count {
            let row_witness = assemble_vss_relation_replay_candidate_row_chunk(
                &retained_group.coefficients,
                logical_polynomial_coefficient_count,
                coefficient_chunk_ordinal,
                geometry,
            )?;
            let padded_coefficients = padded_base_row_coefficients(
                geometry,
                coefficient_chunk_ordinal,
                row_witness,
                RowCodeHighHalfSource::PrivateMaskSeed(&private_row_pad_seed),
            )?;
            let mut transform = BoundedBaseCosetLaneDft::new(
                padded_coefficients,
                full_domain,
                PHASE_LANE_COLUMN_COUNT,
                VSS_RELATION_REPLAY_CANDIDATE_LANE_ORDINAL,
            )?;
            loop {
                poll_count = poll_count
                    .checked_add(1)
                    .ok_or_else(|| "VSS row-lane poll count overflowed".to_owned())?;
                if transform.poll()? {
                    break;
                }
            }
            let values = transform.into_values()?;
            if values.len() != PHASE_LANE_COLUMN_COUNT {
                return Err("VSS row-lane output width is inconsistent".to_owned());
            }
            let middle_ordinal = values.len() / 2;
            let sampled_value = values[0].canonical()
                ^ values[middle_ordinal].canonical().rotate_left(21)
                ^ values[values.len() - 1].canonical().rotate_left(42)
                ^ u64::try_from(coefficient_chunk_ordinal)
                    .map_err(|_| "VSS row-lane chunk ordinal exceeds u64".to_owned())?
                    .rotate_left(7);
            checksum = checksum
                .rotate_left(17)
                .wrapping_add(sampled_value)
                .wrapping_mul(0x1000_0000_01b3);
            black_box(&values);
        }
        Ok((checksum, poll_count))
    })?;
    black_box(checksum);

    let retained_input_byte_length = measurement.retained_input_byte_length()?;
    let replay_buffer_byte_length = u64::try_from(measurement.trace_value_count())
        .ok()
        .and_then(|count| count.checked_mul(size_of::<ProofBaseFieldElement>() as u64))
        .ok_or_else(|| "VSS row-lane replay buffer size overflowed".to_owned())?;
    let retained_group_header_byte_length = u64::try_from(retained_recipe_count)
        .ok()
        .and_then(|count| {
            count.checked_mul(size_of::<Zeroizing<Vec<ProofBaseFieldElement>>>() as u64)
        })
        .ok_or_else(|| "VSS row-lane group header size overflowed".to_owned())?;
    let row_working_buffer_byte_length = u64::try_from(geometry.padded_coefficient_count)
        .ok()
        .and_then(|count| count.checked_mul(size_of::<ProofBaseFieldElement>() as u64))
        .ok_or_else(|| "VSS row-lane working buffer size overflowed".to_owned())?;
    let retained_group_container_byte_length = u64::try_from(size_of_val(&retained_group))
        .map_err(|_| "VSS row-lane group container exceeds u64".to_owned())?;
    let owned_fixed_state_byte_length = u64::try_from(
        size_of_val(&retained_group)
            + size_of::<BoundedBaseCosetLaneDft>()
            + size_of::<RowEncodingGeometry>()
            + size_of::<ProofEvaluationDomain>()
            + size_of_val(&private_row_pad_seed),
    )
    .map_err(|_| "VSS row-lane fixed state exceeds u64".to_owned())?;
    let materialization_peak_live_byte_length = retained_input_byte_length
        .checked_add(expected_retained_payload_byte_length)
        .and_then(|value| value.checked_add(replay_buffer_byte_length))
        .and_then(|value| value.checked_add(retained_group_header_byte_length))
        .and_then(|value| value.checked_add(retained_group_container_byte_length))
        .ok_or_else(|| "VSS row-lane materialization live set overflowed".to_owned())?;
    let stripe_peak_live_byte_length = retained_input_byte_length
        .checked_add(expected_retained_payload_byte_length)
        .and_then(|value| value.checked_add(retained_group_header_byte_length))
        .and_then(|value| value.checked_add(row_working_buffer_byte_length))
        .and_then(|value| value.checked_add(owned_fixed_state_byte_length))
        .ok_or_else(|| "VSS row-lane stripe live set overflowed".to_owned())?;
    let modeled_peak_live_byte_length =
        materialization_peak_live_byte_length.max(stripe_peak_live_byte_length);
    let copied_coefficient_value_count = u64::try_from(retained_recipe_count)
        .ok()
        .and_then(|count| count.checked_mul(candidate.prover_column_degree_bound_exclusive))
        .ok_or_else(|| "VSS row-lane copied coefficient count overflowed".to_owned())?;
    let stripe_private_high_half_value_count = candidate
        .opening_degree_bound_exclusive
        .checked_mul(candidate.coefficient_chunk_count_per_source)
        .ok_or_else(|| "VSS row-lane private high-half count overflowed".to_owned())?;
    let coefficient_fold_count_per_lane = u64::try_from(geometry.padded_coefficient_count)
        .ok()
        .and_then(|count| count.checked_sub(PHASE_LANE_COLUMN_COUNT as u64))
        .ok_or_else(|| "VSS row-lane coefficient-fold count underflowed".to_owned())?;
    let stripe_coefficient_fold_count = coefficient_fold_count_per_lane
        .checked_mul(candidate.coefficient_chunk_count_per_source)
        .ok_or_else(|| "VSS row-lane coefficient-fold count overflowed".to_owned())?;
    let stripe_butterfly_count = DFT_BUTTERFLY_COUNT
        .checked_mul(candidate.coefficient_chunk_count_per_source)
        .ok_or_else(|| "VSS row-lane butterfly count overflowed".to_owned())?;
    let stripe_coset_multiplication_count = u64::try_from(PHASE_LANE_COLUMN_COUNT)
        .ok()
        .and_then(|count| count.checked_mul(candidate.coefficient_chunk_count_per_source))
        .ok_or_else(|| "VSS row-lane coset multiplication count overflowed".to_owned())?;

    Ok(PrimitiveMeasurementRecord {
        schema_version: MEASUREMENT_SCHEMA_VERSION,
        case_identifier: 10,
        case_name: "vss-relation-replay-candidate-row-lane-stripe",
        execution_target: execution_target(),
        iteration_count: candidate.coefficient_chunk_count_per_source,
        elapsed_nanoseconds,
        modeled_peak_live_byte_length,
        checksum_hex: format!("{checksum:016x}"),
        dimensions: vec![
            dimension_u64("tracePackingFactor", candidate.trace_packing_factor),
            dimension_u64("traceValueCount", candidate.relation_trace_domain_size),
            dimension_u64(
                "logicalPolynomialCoefficientCount",
                u64::try_from(logical_polynomial_coefficient_count)
                    .map_err(|_| "VSS row-lane logical width exceeds u64".to_owned())?,
            ),
            dimension("physicalRowWidth", retained_recipe_count)?,
            dimension_u64("physicalRowCount", candidate.physical_row_count),
            dimension_u64("productionRecipeCount", candidate.prover_column_count),
            dimension_u64(
                "proverColumnDegreeBoundExclusive",
                candidate.prover_column_degree_bound_exclusive,
            ),
            dimension("coefficientChunkCount", coefficient_chunk_count)?,
            dimension("witnessValueCount", geometry.witness_values_per_row)?,
            dimension("paddedCoefficientCount", geometry.padded_coefficient_count)?,
            dimension("fullDomainSize", geometry.encoded_column_count)?,
            dimension("laneColumnCount", PHASE_LANE_COLUMN_COUNT)?,
            dimension("laneCount", lane_count)?,
            dimension("laneOrdinal", VSS_RELATION_REPLAY_CANDIDATE_LANE_ORDINAL)?,
            dimension_u64(
                "coefficientFoldCountPerLane",
                coefficient_fold_count_per_lane,
            ),
            dimension_u64("stripeCoefficientFoldCount", stripe_coefficient_fold_count),
            dimension_u64("butterflyCountPerLane", DFT_BUTTERFLY_COUNT),
            dimension_u64("stripeButterflyCount", stripe_butterfly_count),
            dimension_u64(
                "stripeCosetMultiplicationCount",
                stripe_coset_multiplication_count,
            ),
            dimension_u64(
                "copiedCoefficientValueCount",
                copied_coefficient_value_count,
            ),
            dimension_u64(
                "stripePrivateHighHalfValueCount",
                stripe_private_high_half_value_count,
            ),
            dimension("pollCount", poll_count)?,
            dimension("retainedRecipeCount", retained_recipe_count)?,
            dimension_u64(
                "retainedCoefficientPayloadByteLength",
                expected_retained_payload_byte_length,
            ),
            PrimitiveMeasurementDimension {
                name: "retainedInputByteLength",
                value: retained_input_byte_length,
            },
            dimension_u64("replayBufferByteLength", replay_buffer_byte_length),
            dimension_u64(
                "retainedGroupHeaderByteLength",
                retained_group_header_byte_length,
            ),
            dimension_u64(
                "retainedGroupContainerByteLength",
                retained_group_container_byte_length,
            ),
            dimension_u64("rowWorkingBufferByteLength", row_working_buffer_byte_length),
            dimension_u64("ownedFixedStateByteLength", owned_fixed_state_byte_length),
            dimension_u64(
                "materializationPeakLiveByteLength",
                materialization_peak_live_byte_length,
            ),
            dimension_u64("stripePeakLiveByteLength", stripe_peak_live_byte_length),
            dimension(
                "relationPlanHashByteLength",
                measurement.relation_plan_hash().len(),
            )?,
        ],
    })
}

fn measure_authenticated_scratch_record_codec() -> Result<PrimitiveMeasurementRecord, String> {
    let mut plaintext = Vec::new();
    plaintext
        .try_reserve_exact(MAXIMUM_LOCAL_RECORD_PLAINTEXT_BYTE_LENGTH)
        .map_err(|_| "authenticated scratch-record input allocation failed".to_owned())?;
    for byte_ordinal in 0..MAXIMUM_LOCAL_RECORD_PLAINTEXT_BYTE_LENGTH {
        let ordinal = u64::try_from(byte_ordinal)
            .map_err(|_| "authenticated scratch-record byte ordinal exceeds u64".to_owned())?;
        plaintext.push(ordinal.wrapping_mul(131).wrapping_add(17) as u8);
    }
    if plaintext.iter().all(|byte| *byte == 0) {
        return Err("authenticated scratch-record input is degenerate".to_owned());
    }
    let (
        (checksum, canonical_envelope_byte_length, modeled_peak_live_byte_length),
        elapsed_nanoseconds,
    ) = measure_elapsed_nanoseconds(|| {
        measure_common_proof_scratch_record_codec(
            &plaintext,
            AUTHENTICATED_SCRATCH_RECORD_ITERATION_COUNT,
        )
        .map_err(|error| format!("authenticated scratch-record codec refused: {error:?}"))
    })?;
    black_box(checksum);
    Ok(PrimitiveMeasurementRecord {
        schema_version: MEASUREMENT_SCHEMA_VERSION,
        case_identifier: 6,
        case_name: "authenticated-scratch-record-codec",
        execution_target: execution_target(),
        iteration_count: AUTHENTICATED_SCRATCH_RECORD_ITERATION_COUNT as u64,
        elapsed_nanoseconds,
        modeled_peak_live_byte_length: u64::try_from(modeled_peak_live_byte_length)
            .map_err(|_| "authenticated scratch-record live set exceeds u64".to_owned())?,
        checksum_hex: format!("{checksum:016x}"),
        dimensions: vec![
            dimension("plaintextByteLength", plaintext.len())?,
            dimension(
                "canonicalEnvelopeByteLength",
                canonical_envelope_byte_length,
            )?,
            dimension(
                "roundTripCount",
                AUTHENTICATED_SCRATCH_RECORD_ITERATION_COUNT,
            )?,
        ],
    })
}

fn derive_primitive_measurement(
    case_identifier: u32,
) -> Result<PrimitiveMeasurementRecord, String> {
    match case_identifier {
        1 => measure_lane_dft(),
        2 => measure_salted_phase_leaf(),
        3 => measure_private_leaf_salt_derivation(),
        4 => measure_five_level_digest_carry(),
        5 => measure_selected_vss_source_replay(),
        6 => measure_authenticated_scratch_record_codec(),
        7 => measure_selected_vss_checkpoint_opening_lane_dfts(),
        8 => measure_selected_vss_production_weighted_source_replay(),
        9 => measure_vss_relation_replay_candidate_retained_group(),
        10 => measure_vss_relation_replay_candidate_row_lane_stripe(),
        _ => Err("primitive measurement case is unsupported".to_owned()),
    }
}

pub(crate) fn run_primitive_measurement(case_identifier: u32) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&derive_primitive_measurement(case_identifier)?)
        .map_err(|_| "primitive measurement record serialization failed".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_and_validate(case_identifier: u32, expected_case_name: &str) {
        let first = run_primitive_measurement(case_identifier)
            .expect("the selected primitive measurement completes");
        let record: serde_json::Value =
            serde_json::from_slice(&first).expect("the primitive measurement record decodes");
        assert_eq!(record["schemaVersion"], MEASUREMENT_SCHEMA_VERSION);
        assert_eq!(record["caseIdentifier"], case_identifier);
        assert_eq!(record["caseName"], expected_case_name);
        assert_eq!(record["executionTarget"], "release-native");
        assert!(
            record["elapsedNanoseconds"]
                .as_u64()
                .is_some_and(|value| value > 0)
        );
        assert!(
            record["modeledPeakLiveByteLength"]
                .as_u64()
                .is_some_and(|value| value > 0)
        );
        assert_ne!(record["checksumHex"], "0000000000000000");
        assert!(
            record["dimensions"]
                .as_array()
                .is_some_and(|rows| !rows.is_empty())
        );
        println!(
            "primitive measurement: {}",
            String::from_utf8(first).expect("the primitive measurement record is UTF-8")
        );
    }

    #[test]
    fn primitive_measurement_refuses_unknown_case() {
        assert_eq!(
            run_primitive_measurement(0),
            Err("primitive measurement case is unsupported".to_owned())
        );
        assert_eq!(
            run_primitive_measurement(u32::MAX),
            Err("primitive measurement case is unsupported".to_owned())
        );
    }

    #[test]
    fn vss_relation_replay_candidate_model_reproduces_production_and_ranks_the_grid() {
        let current = derive_vss_relation_replay_candidate_ledger(4, 8)
            .expect("the production VSS geometry derives")
            .expect("the production VSS geometry fits its opening bound");
        assert_eq!(
            current,
            VssRelationReplayCandidateLedger {
                trace_packing_factor: 4,
                logical_polynomials_per_physical_row: 8,
                relation_trace_domain_size: 65_536,
                material_group_count: 32,
                material_prover_column_count: 2_880,
                quotient_group_count: 40,
                quotient_prover_column_count: 120,
                shift_selector_column_count: 3,
                prover_column_count: 3_003,
                prover_column_degree_bound_exclusive: 67_584,
                maximum_range_constraint_numerator_degree: 202_749,
                opening_degree_bound_exclusive: 262_144,
                row_code_inverse_rate: 32,
                opening_point_count: 12,
                bound_reduction_aggregate_column_count: 1,
                aggregate_column_role_count: 13,
                aggregate_table_width: 32,
                coefficient_chunk_count_per_source: 3,
                physical_row_count: 1_128,
                lane_dft_count: 72_192,
                butterfly_count: 359_569_293_312,
                coefficient_fold_count: 0,
                coset_multiplication_count: 37_849_399_296,
                private_high_half_value_generation_count: 18_924_699_648,
                column_value_delivery_count: 37_849_399_296,
                transported_value_byte_length: 302_795_194_368,
                leaf_hash_query_count: 33_554_432,
                salted_leaf_keccak_permutation_count: 2_281_701_376,
                merkle_parent_hash_query_count: 33_554_430,
                private_leaf_salt_derivation_count: 33_554_432,
                retained_source_materialization_count: 6_006,
                source_trace_value_generation_count: 393_609_216,
                retained_coefficient_group_byte_length: 4_325_376,
                logical_row_chunk_byte_length: 2_097_152,
            }
        );

        let modeled = derive_vss_relation_replay_candidate_ledger(16, 64)
            .expect("the modeled VSS geometry derives")
            .expect("the modeled VSS geometry fits its opening bound");
        assert_eq!(
            modeled,
            VssRelationReplayCandidateLedger {
                trace_packing_factor: 16,
                logical_polynomials_per_physical_row: 64,
                relation_trace_domain_size: 262_144,
                material_group_count: 8,
                material_prover_column_count: 720,
                quotient_group_count: 10,
                quotient_prover_column_count: 30,
                shift_selector_column_count: 3,
                prover_column_count: 753,
                prover_column_degree_bound_exclusive: 264_192,
                maximum_range_constraint_numerator_degree: 792_573,
                opening_degree_bound_exclusive: 2_097_152,
                row_code_inverse_rate: 4,
                opening_point_count: 24,
                bound_reduction_aggregate_column_count: 1,
                aggregate_column_role_count: 25,
                aggregate_table_width: 4,
                coefficient_chunk_count_per_source: 9,
                physical_row_count: 108,
                lane_dft_count: 6_912,
                butterfly_count: 34_426_847_232,
                coefficient_fold_count: 25_367_150_592,
                coset_multiplication_count: 3_623_878_656,
                private_high_half_value_generation_count: 14_495_514_624,
                column_value_delivery_count: 3_623_878_656,
                transported_value_byte_length: 28_991_029_248,
                leaf_hash_query_count: 33_554_432,
                salted_leaf_keccak_permutation_count: 268_435_456,
                merkle_parent_hash_query_count: 33_554_430,
                private_leaf_salt_derivation_count: 33_554_432,
                retained_source_materialization_count: 1_506,
                source_trace_value_generation_count: 394_788_864,
                retained_coefficient_group_byte_length: 135_266_304,
                logical_row_chunk_byte_length: 16_777_216,
            }
        );

        let grid = derive_vss_relation_replay_candidate_grid()
            .expect("the VSS relation-replay candidate grid derives");
        let minimum_row_count = grid
            .iter()
            .map(|candidate| candidate.physical_row_count)
            .min()
            .expect("the VSS candidate grid is nonempty");
        assert_eq!(minimum_row_count, modeled.physical_row_count);
        assert!(
            grid.iter().any(|candidate| {
                candidate.trace_packing_factor == 32
                    && candidate.logical_polynomials_per_physical_row == 64
                    && candidate.physical_row_count == 204
            }),
            "the wider trace comparator remains in the grid"
        );
        assert_eq!(
            derive_vss_relation_replay_candidate_ledger(16, 8)
                .expect("the under-capacity candidate is structurally defined"),
            None
        );
        assert!(derive_vss_relation_replay_candidate_ledger(16, 128).is_err());

        let production_work = derive_selected_vss_base_phase_work_ledger()
            .expect("the selected VSS work ledger derives");
        let current_recomputed_source_value_count = production_work
            .source_replay_count
            .checked_mul(current.relation_trace_domain_size)
            .expect("the current source-value count derives");
        assert!(modeled.lane_dft_count * 10 <= production_work.lane_dft_count);
        assert!(
            modeled.source_trace_value_generation_count * 90
                <= current_recomputed_source_value_count
        );
        assert!(
            modeled.salted_leaf_keccak_permutation_count * 8
                <= production_work.salted_leaf_keccak_permutation_count
        );

        let selected_plan_hash = SelectedVssSourceReplayMeasurement::prepare()
            .expect("the selected VSS replay source prepares")
            .relation_plan_hash();
        let compiled_candidate =
            SelectedVssSourceReplayMeasurement::prepare_relation_replay_candidate(
                modeled.trace_packing_factor,
                modeled.opening_degree_bound_exclusive,
            )
            .expect("the modeled VSS compiler and replay source agree");
        assert_eq!(
            compiled_candidate.trace_packing_factor(),
            modeled.trace_packing_factor
        );
        assert_eq!(
            compiled_candidate.trace_value_count(),
            usize::try_from(modeled.relation_trace_domain_size)
                .expect("the modeled trace count fits usize")
        );
        assert_eq!(
            compiled_candidate.production_recipe_count(),
            usize::try_from(modeled.prover_column_count)
                .expect("the modeled prover-column count fits usize")
        );
        assert_ne!(compiled_candidate.relation_plan_hash(), selected_plan_hash);
        let (candidate_artifact, candidate_context) =
            SelectedVssSourceReplayMeasurement::validated_relation_replay_candidate(
                modeled.trace_packing_factor,
                modeled.opening_degree_bound_exclusive,
            )
            .expect("the modeled VSS candidate artifact derives");
        let candidate_variant = candidate_artifact
            .compiled_plan()
            .variants()
            .first()
            .expect("the modeled VSS candidate has one variant");
        assert_eq!(
            ValidatedRelationPlanArtifact::from_owned_compiled_plan(
                candidate_artifact.compiled_plan().clone(),
                &candidate_context,
            ),
            Err(crate::bgv::proof_suite::ProofProfileError::InvalidSchedule),
            "the candidate context cannot become a selected profile artifact"
        );
        assert_eq!(
            candidate_variant.ordered_opening_points().len(),
            usize::try_from(modeled.opening_point_count)
                .expect("the modeled opening-point count fits usize")
        );
        assert!(
            candidate_variant
                .ordered_trees()
                .iter()
                .any(|tree| matches!(tree, RelationTreeDescriptor::BoundPublic { .. }))
        );
        assert_eq!(
            RowCodeWhirConstructionPlan::for_primitive_measurement_candidate_variant(
                &candidate_artifact,
                &candidate_context,
                candidate_variant.schedule_position(),
                candidate_variant.top_count(),
                vss_relation_replay_candidate_bound_root_source_trace_domain_size,
            ),
            Err(
                RowCodeWhirConstructionPlanError::InsufficientAggregateTableWidth {
                    aggregate_column_role_count: 25,
                    aggregate_table_width: 4,
                }
            ),
            "the 24 rotations plus bound reduction cannot fit a width-four aggregate table"
        );
        assert_eq!(
            derive_vss_relation_replay_candidate_capacity_refusal(modeled)
                .expect("the modeled candidate capacity refusal derives"),
            VssRelationReplayCandidateCapacityRefusal {
                opening_point_count: 24,
                bound_reduction_aggregate_column_count: 1,
                aggregate_column_role_count: 25,
                aggregate_table_width: 4,
            }
        );
        let quotient_batch_candidate = derive_vss_opening_claim_quotient_candidate_ledger(modeled)
            .expect("the modeled quotient-batch candidate derives");
        assert_eq!(
            quotient_batch_candidate,
            VssOpeningClaimQuotientCandidateLedger {
                direct_aggregate_column_role_count: 25,
                quotient_aggregate_column_role_count: 2,
                aggregate_table_width: 4,
                source_degree_bound_exclusive: 4_194_304,
                opening_claim_count: 24,
                batched_quotient_degree_bound_exclusive: 4_194_303,
                discrepancy_numerator_degree_bound_inclusive: 4_194_326,
                query_domain_size: 16_777_216,
                query_count: 387,
                agreement_ceiling: 4_194_326,
            }
        );
        assert!(
            quotient_batch_candidate.direct_aggregate_column_role_count
                > quotient_batch_candidate.aggregate_table_width
        );
        assert!(
            quotient_batch_candidate.quotient_aggregate_column_role_count
                <= quotient_batch_candidate.aggregate_table_width
        );
        let quotient_batch_construction =
            derive_vss_relation_replay_opening_claim_quotient_candidate_construction_plan(modeled)
                .expect("the quotient-batch candidate construction derives");
        let repeated_quotient_batch_construction =
            derive_vss_relation_replay_opening_claim_quotient_candidate_construction_plan(modeled)
                .expect("the quotient-batch candidate construction re-derives");
        assert_eq!(
            quotient_batch_construction.aggregate_column_roles,
            vec![
                RowCodeWhirAggregateColumnRole::OpeningClaimQuotientBatch {
                    opening_point_count: 24,
                },
                RowCodeWhirAggregateColumnRole::BoundReduction,
            ]
        );
        assert_eq!(
            quotient_batch_construction
                .aggregate_opening_point_count()
                .expect("the quotient-batch logical point count derives"),
            24
        );
        assert!(
            quotient_batch_construction
                .uses_opening_claim_quotient_batch()
                .expect("the quotient-batch layout derives")
        );
        let opening_batches = quotient_batch_construction.opening_batches();
        let outer_query_count = quotient_batch_construction.outer_query_count();
        assert_eq!(outer_query_count, 387);
        assert!(opening_batches.len() > outer_query_count);
        assert!(
            opening_batches[..outer_query_count]
                .iter()
                .all(|batch| batch.requested_aggregate_column_ordinals == [0])
        );
        assert!(
            opening_batches[outer_query_count..]
                .iter()
                .all(|batch| batch.requested_aggregate_column_ordinals == [1])
        );
        let derived_bound_batch_count = quotient_batch_construction
            .bound_reduction_blocks
            .iter()
            .map(|block| block.query_count * 2 + 1 + block.degree_suffix_prefixes.len())
            .sum::<usize>();
        assert_eq!(
            opening_batches.len(),
            outer_query_count + derived_bound_batch_count
        );
        assert_eq!(
            quotient_batch_construction.canonical_identity_hash(),
            repeated_quotient_batch_construction.canonical_identity_hash()
        );
        assert_eq!(
            quotient_batch_construction.oracle_equation_catalog_hash(),
            repeated_quotient_batch_construction.oracle_equation_catalog_hash()
        );
        let quotient_batch_identity = quotient_batch_construction
            .canonical_identity_hash()
            .expect("the quotient-batch identity hashes");
        let mut wrong_claim_count_construction = quotient_batch_construction.clone();
        wrong_claim_count_construction.aggregate_column_roles[0] =
            RowCodeWhirAggregateColumnRole::OpeningClaimQuotientBatch {
                opening_point_count: 23,
            };
        assert_ne!(
            wrong_claim_count_construction.canonical_identity_hash(),
            Ok(quotient_batch_identity),
            "the canonical identity binds the quotient-batch claim count"
        );
        let mut zero_claim_construction = quotient_batch_construction.clone();
        zero_claim_construction.aggregate_column_roles[0] =
            RowCodeWhirAggregateColumnRole::OpeningClaimQuotientBatch {
                opening_point_count: 0,
            };
        assert_eq!(
            zero_claim_construction.aggregate_opening_point_count(),
            Err(RowCodeWhirConstructionPlanError::InvalidOpeningCatalog),
            "an empty quotient batch refuses"
        );
        let mut mixed_reduction_construction = quotient_batch_construction.clone();
        mixed_reduction_construction.aggregate_column_roles.insert(
            0,
            RowCodeWhirAggregateColumnRole::OpeningPoint {
                opening_point_ordinal: 0,
            },
        );
        assert_eq!(
            mixed_reduction_construction.aggregate_opening_point_count(),
            Err(RowCodeWhirConstructionPlanError::InvalidOpeningCatalog),
            "direct and quotient opening reductions cannot be mixed"
        );
        let mut duplicate_quotient_construction = quotient_batch_construction.clone();
        duplicate_quotient_construction
            .aggregate_column_roles
            .insert(
                1,
                RowCodeWhirAggregateColumnRole::OpeningClaimQuotientBatch {
                    opening_point_count: 24,
                },
            );
        assert_eq!(
            duplicate_quotient_construction.aggregate_opening_point_count(),
            Err(RowCodeWhirConstructionPlanError::InvalidOpeningCatalog),
            "two quotient batches refuse"
        );
        let single_aggregate_candidate = grid
            .iter()
            .copied()
            .filter(|candidate| {
                candidate.aggregate_column_role_count <= candidate.aggregate_table_width
            })
            .min_by_key(|candidate| candidate.physical_row_count)
            .expect("the single-aggregate comparator grid is nonempty");
        assert_eq!(
            (
                single_aggregate_candidate.trace_packing_factor,
                single_aggregate_candidate.logical_polynomials_per_physical_row,
                single_aggregate_candidate.physical_row_count,
            ),
            (1, 32, 331)
        );
        assert!(
            current.physical_row_count < single_aggregate_candidate.physical_row_count * 10,
            "the fastest compatible single-aggregate comparator is not a tenfold row reduction"
        );
        let single_aggregate_construction =
            derive_vss_relation_replay_candidate_construction_plan(single_aggregate_candidate)
                .expect("the fastest single-aggregate comparator construction derives");
        let repeated_single_aggregate_construction =
            derive_vss_relation_replay_candidate_construction_plan(single_aggregate_candidate)
                .expect("the fastest single-aggregate comparator construction re-derives");
        assert_eq!(
            single_aggregate_construction.canonical_identity_hash(),
            repeated_single_aggregate_construction.canonical_identity_hash()
        );
        assert_eq!(
            single_aggregate_construction.oracle_equation_catalog_hash(),
            repeated_single_aggregate_construction.oracle_equation_catalog_hash()
        );
        assert_eq!(
            single_aggregate_construction.aggregate_table_width(),
            usize::try_from(single_aggregate_candidate.aggregate_table_width)
                .expect("the single-aggregate table width fits usize")
        );
        assert!(
            !single_aggregate_construction
                .uses_opening_claim_quotient_batch()
                .expect("the direct aggregate layout derives")
        );
        assert_eq!(
            RowCodeWhirConstructionPlan::for_selected_variant(
                &candidate_artifact,
                candidate_variant.schedule_position(),
                candidate_variant.top_count(),
            ),
            Err(RowCodeWhirConstructionPlanError::InvalidSelectedProfile),
            "the measurement-only geometry cannot enter the selected construction route"
        );
        let mut wrong_context = candidate_context.clone();
        wrong_context.maximum_fiat_shamir_candidate_draws_per_output = wrong_context
            .maximum_fiat_shamir_candidate_draws_per_output
            .checked_add(1)
            .expect("the hostile context mutation does not overflow");
        assert_eq!(
            RowCodeWhirConstructionPlan::for_primitive_measurement_candidate_variant(
                &candidate_artifact,
                &wrong_context,
                candidate_variant.schedule_position(),
                candidate_variant.top_count(),
                vss_relation_replay_candidate_bound_root_source_trace_domain_size,
            ),
            Err(RowCodeWhirConstructionPlanError::InvalidSelectedProfile),
            "the measurement route refuses a context not authenticated by the artifact"
        );
        let first_replay = compiled_candidate
            .replay_once()
            .expect("the modeled VSS source replays");
        let second_replay = compiled_candidate
            .replay_once()
            .expect("the modeled VSS source replay is restartable");
        assert_eq!(first_replay, second_replay);
        assert!(first_replay.iter().any(|value| value.canonical() != 0));
        assert!(
            compiled_candidate
                .materialize_retained_recipe_group_once(0)
                .is_err(),
            "an empty retained recipe group refuses"
        );
        assert!(
            compiled_candidate
                .materialize_retained_recipe_group_once(
                    compiled_candidate.production_recipe_count() + 1,
                )
                .is_err(),
            "a retained recipe group wider than the compiled catalog refuses"
        );
        assert!(
            SelectedVssSourceReplayMeasurement::prepare_relation_replay_candidate(16, 262_144)
                .is_err(),
            "the wider relation refuses the selected width-eight opening bound"
        );
        assert!(
            SelectedVssSourceReplayMeasurement::prepare_relation_replay_candidate(
                3,
                modeled.opening_degree_bound_exclusive,
            )
            .is_err(),
            "a non-power-of-two trace packing factor refuses"
        );
    }

    #[test]
    fn vss_relation_replay_candidate_row_chunks_preserve_order_and_zero_tail() {
        let geometry = RowEncodingGeometry::new_weighted_batch_with_log_inverse_rate(2, 3, 2)
            .expect("the focused row geometry derives");
        let retained_coefficients = vec![
            Zeroizing::new(
                (1_u64..=6)
                    .map(|value| ProofBaseFieldElement::from_reduced(u128::from(value)))
                    .collect::<Vec<_>>(),
            ),
            Zeroizing::new(
                (7_u64..=12)
                    .map(|value| ProofBaseFieldElement::from_reduced(u128::from(value)))
                    .collect::<Vec<_>>(),
            ),
        ];
        let first = assemble_vss_relation_replay_candidate_row_chunk(
            &retained_coefficients,
            4,
            0,
            geometry,
        )
        .expect("the first focused row chunk assembles");
        let tail = assemble_vss_relation_replay_candidate_row_chunk(
            &retained_coefficients,
            4,
            1,
            geometry,
        )
        .expect("the focused tail row chunk assembles");
        assert_eq!(
            first
                .iter()
                .map(|value| value.canonical())
                .collect::<Vec<_>>(),
            vec![1, 2, 3, 4, 7, 8, 9, 10],
        );
        assert_eq!(
            tail.iter()
                .map(|value| value.canonical())
                .collect::<Vec<_>>(),
            vec![5, 6, 0, 0, 11, 12, 0, 0],
        );
        assert!(first.capacity() >= geometry.padded_coefficient_count);
        assert!(tail.capacity() >= geometry.padded_coefficient_count);

        assert!(assemble_vss_relation_replay_candidate_row_chunk(&[], 4, 0, geometry).is_err());
        assert!(
            assemble_vss_relation_replay_candidate_row_chunk(
                &retained_coefficients,
                4,
                2,
                geometry,
            )
            .is_err()
        );
        let mismatched_widths = vec![
            Zeroizing::new(vec![ProofBaseFieldElement::ONE; 6]),
            Zeroizing::new(vec![ProofBaseFieldElement::ONE; 5]),
        ];
        assert!(
            assemble_vss_relation_replay_candidate_row_chunk(&mismatched_widths, 4, 0, geometry,)
                .is_err()
        );
        let wrong_geometry = RowEncodingGeometry::new_weighted_batch_with_log_inverse_rate(2, 2, 2)
            .expect("the hostile row geometry derives");
        assert!(
            assemble_vss_relation_replay_candidate_row_chunk(
                &retained_coefficients,
                4,
                0,
                wrong_geometry,
            )
            .is_err()
        );
    }

    #[test]
    #[ignore = "guarded release-native bounded lane DFT measurement"]
    fn selected_bounded_lane_dft_emits_measurement() {
        run_and_validate(1, "bounded-phase-lane-dft");
    }

    #[test]
    #[ignore = "guarded release-native salted phase-leaf measurement"]
    fn selected_salted_phase_leaf_emits_measurement() {
        run_and_validate(2, "salted-phase-column-leaf");
    }

    #[test]
    #[ignore = "guarded release-native private leaf-salt measurement"]
    fn selected_private_leaf_salt_derivation_emits_measurement() {
        run_and_validate(3, "private-leaf-salt-kmac");
    }

    #[test]
    #[ignore = "guarded release-native digest-carry measurement"]
    fn selected_five_level_digest_carry_emits_measurement() {
        run_and_validate(4, "five-level-digest-carry");
    }

    #[test]
    #[ignore = "guarded release-native VSS source-replay measurement"]
    fn selected_vss_source_replay_emits_measurement() {
        run_and_validate(5, "selected-vss-source-replay");
    }

    #[test]
    #[ignore = "guarded release-native authenticated scratch-record codec measurement"]
    fn selected_authenticated_scratch_record_codec_emits_measurement() {
        run_and_validate(6, "authenticated-scratch-record-codec");
    }

    #[test]
    #[ignore = "guarded release-native selected VSS checkpoint-opening lane-DFT measurement"]
    fn selected_vss_checkpoint_opening_lane_dfts_emit_measurement() {
        run_and_validate(7, "selected-vss-checkpoint-opening-lane-dfts");
    }

    #[test]
    #[ignore = "guarded release-native production-weighted VSS source-replay measurement"]
    fn selected_vss_production_weighted_source_replay_emits_measurement() {
        run_and_validate(8, "selected-vss-production-weighted-source-replay");
    }

    #[test]
    #[ignore = "guarded release-native VSS relation-replay candidate retained-group measurement"]
    fn vss_relation_replay_candidate_retained_group_emits_measurement() {
        run_and_validate(9, "vss-relation-replay-candidate-retained-group");
    }

    #[test]
    #[ignore = "guarded release-native VSS relation-replay candidate row-lane stripe measurement"]
    fn vss_relation_replay_candidate_row_lane_stripe_emits_measurement() {
        run_and_validate(10, "vss-relation-replay-candidate-row-lane-stripe");
    }
}
