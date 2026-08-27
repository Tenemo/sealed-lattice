use std::cell::RefCell;

use serde::Serialize;
use sha3::{Digest, Sha3_512};
use zeroize::Zeroizing;

use crate::{
    foundation::{FOUNDATION_PROFILE, Hash512},
    tally_circuit::{CompiledTallyCircuit, TallyCircuitProfile},
};

use super::{
    TallyPreparationContext,
    pseudorandom_zero_sharing_320::{
        CanonicalZeroSharingCodewordBlockVerifier320, PerBitPseudorandomZeroSharingWorkload320,
    },
    pseudorandom_zero_sharing_measurement_fixture_320::derive_all_roster_zero_sharing_measurement_master_320,
    pseudorandom_zero_sharing_participant_cursor_320::{
        PseudorandomZeroSharingCursorResourceModel320, PseudorandomZeroSharingCursorState320,
        PseudorandomZeroSharingParticipantCursor320,
    },
    pseudorandom_zero_sharing_seed_master_join_320::{
        LocallyJoinedPseudorandomZeroSharingSubsetMaster320,
        locally_joined_subset_master_for_measurement,
    },
    pseudorandom_zero_sharing_subset_seed_320::PseudorandomZeroSharingSubsetMasterScope320,
    replicated_random_sharing::ReplicatedRandomSharingSubset,
};

pub(crate) const MEASUREMENT_SUCCESS: u32 = 0;
pub(crate) const MEASUREMENT_CHUNK_READY: u32 = 1;
pub(crate) const MEASUREMENT_FINISHED: u32 = 1;
pub(crate) const MEASUREMENT_CODEWORD_INVALID: u32 = 1;
pub(crate) const MEASUREMENT_ERROR: u32 = u32::MAX;

struct CompletionZeroSharingMeasurement320 {
    masters: Box<[LocallyJoinedPseudorandomZeroSharingSubsetMaster320]>,
    cursor: PseudorandomZeroSharingParticipantCursor320,
    resource_model: PseudorandomZeroSharingCursorResourceModel320,
}

struct CompletionZeroSharingMeasurementFixture320 {
    parameter_identity: Hash512,
    preparation_context: TallyPreparationContext,
    zero_sharing_catalog_identity: Hash512,
    participant_position: u16,
    total_field_count: u64,
    masters: Box<[LocallyJoinedPseudorandomZeroSharingSubsetMaster320]>,
    resource_model: PseudorandomZeroSharingCursorResourceModel320,
}

thread_local! {
    static COMPLETION_ZERO_SHARING_MEASUREMENT: RefCell<Option<CompletionZeroSharingMeasurement320>> = const { RefCell::new(None) };
}

pub(crate) fn open_completion_zero_sharing_measurement_320() -> u32 {
    COMPLETION_ZERO_SHARING_MEASUREMENT.with(|measurement| {
        let mut measurement = measurement.borrow_mut();
        if measurement.is_some() {
            return MEASUREMENT_ERROR;
        }
        let Ok(fixture) = completion_measurement_fixture() else {
            return MEASUREMENT_ERROR;
        };
        let Ok(cursor) = PseudorandomZeroSharingParticipantCursor320::new(
            fixture.parameter_identity,
            fixture.preparation_context,
            fixture.zero_sharing_catalog_identity,
            fixture.participant_position,
            fixture.total_field_count,
            &fixture.masters,
        ) else {
            return MEASUREMENT_ERROR;
        };
        *measurement = Some(CompletionZeroSharingMeasurement320 {
            masters: fixture.masters,
            cursor,
            resource_model: fixture.resource_model,
        });
        MEASUREMENT_SUCCESS
    })
}

/// Opens one participant source cursor whose deterministic subset masters are
/// identical for every holder of the same subset. This diagnostic source is
/// absent from the production package and establishes no seed custody.
pub(crate) fn open_completion_zero_sharing_codeword_source_measurement_320(
    participant_position: u16,
) -> u32 {
    COMPLETION_ZERO_SHARING_MEASUREMENT.with(|measurement| {
        let mut measurement = measurement.borrow_mut();
        if measurement.is_some() {
            return MEASUREMENT_ERROR;
        }
        let Ok(fixture) = completion_codeword_measurement_fixture(participant_position) else {
            return MEASUREMENT_ERROR;
        };
        let Ok(cursor) = PseudorandomZeroSharingParticipantCursor320::new(
            fixture.parameter_identity,
            fixture.preparation_context,
            fixture.zero_sharing_catalog_identity,
            fixture.participant_position,
            fixture.total_field_count,
            &fixture.masters,
        ) else {
            return MEASUREMENT_ERROR;
        };
        *measurement = Some(CompletionZeroSharingMeasurement320 {
            masters: fixture.masters,
            cursor,
            resource_model: fixture.resource_model,
        });
        MEASUREMENT_SUCCESS
    })
}

pub(crate) fn verify_completion_zero_sharing_codeword_block_320(bytes: &[u8]) -> u32 {
    let Ok(verifier) =
        CanonicalZeroSharingCodewordBlockVerifier320::new(FOUNDATION_PROFILE.participant_count)
    else {
        return MEASUREMENT_ERROR;
    };
    match verifier.verify_field_major_block(bytes) {
        Ok(verification) if verification.is_valid => MEASUREMENT_SUCCESS,
        Ok(_) => MEASUREMENT_CODEWORD_INVALID,
        Err(_) => MEASUREMENT_ERROR,
    }
}

pub(crate) fn completion_zero_sharing_codeword_byte_length_320() -> u64 {
    codeword_verifier_resource_value(|verifier| u64::try_from(verifier.codeword_byte_length()).ok())
}

pub(crate) fn completion_zero_sharing_codeword_maximum_block_count_320() -> u64 {
    codeword_verifier_resource_value(|verifier| {
        u64::try_from(verifier.maximum_codeword_count_per_block()).ok()
    })
}

pub(crate) fn completion_zero_sharing_codeword_multiplication_count_320() -> u64 {
    codeword_verifier_resource_value(|verifier| {
        verifier.field_multiplication_count_per_codeword().ok()
    })
}

pub(crate) fn completion_zero_sharing_codeword_addition_count_320() -> u64 {
    codeword_verifier_resource_value(|verifier| verifier.field_addition_count_per_codeword().ok())
}

pub(crate) fn completion_zero_sharing_codeword_comparison_count_320() -> u64 {
    codeword_verifier_resource_value(|verifier| Some(verifier.comparison_count_per_codeword()))
}

pub(crate) fn restore_completion_zero_sharing_measurement_320(checkpoint_bytes: &[u8]) -> u32 {
    COMPLETION_ZERO_SHARING_MEASUREMENT.with(|measurement| {
        let mut measurement = measurement.borrow_mut();
        if measurement.is_some() {
            return MEASUREMENT_ERROR;
        }
        let Ok(fixture) = completion_measurement_fixture() else {
            return MEASUREMENT_ERROR;
        };
        let Ok(cursor) = PseudorandomZeroSharingParticipantCursor320::restore_from_checkpoint(
            fixture.parameter_identity,
            fixture.preparation_context,
            fixture.zero_sharing_catalog_identity,
            fixture.participant_position,
            fixture.total_field_count,
            &fixture.masters,
            checkpoint_bytes,
        ) else {
            return MEASUREMENT_ERROR;
        };
        *measurement = Some(CompletionZeroSharingMeasurement320 {
            masters: fixture.masters,
            cursor,
            resource_model: fixture.resource_model,
        });
        MEASUREMENT_SUCCESS
    })
}

pub(crate) fn restore_completion_zero_sharing_codeword_source_measurement_320(
    participant_position: u16,
    checkpoint_bytes: &[u8],
) -> u32 {
    COMPLETION_ZERO_SHARING_MEASUREMENT.with(|measurement| {
        let mut measurement = measurement.borrow_mut();
        if measurement.is_some() {
            return MEASUREMENT_ERROR;
        }
        let Ok(fixture) = completion_codeword_measurement_fixture(participant_position) else {
            return MEASUREMENT_ERROR;
        };
        let Ok(cursor) = PseudorandomZeroSharingParticipantCursor320::restore_from_checkpoint(
            fixture.parameter_identity,
            fixture.preparation_context,
            fixture.zero_sharing_catalog_identity,
            fixture.participant_position,
            fixture.total_field_count,
            &fixture.masters,
            checkpoint_bytes,
        ) else {
            return MEASUREMENT_ERROR;
        };
        *measurement = Some(CompletionZeroSharingMeasurement320 {
            masters: fixture.masters,
            cursor,
            resource_model: fixture.resource_model,
        });
        MEASUREMENT_SUCCESS
    })
}

pub(crate) fn step_completion_zero_sharing_measurement_320() -> u32 {
    COMPLETION_ZERO_SHARING_MEASUREMENT.with(|measurement| {
        let mut measurement = measurement.borrow_mut();
        let Some(measurement) = measurement.as_mut() else {
            return MEASUREMENT_ERROR;
        };
        match measurement.cursor.step(&measurement.masters) {
            Ok(step) if step.completed_chunk => MEASUREMENT_CHUNK_READY,
            Ok(_) => MEASUREMENT_SUCCESS,
            Err(_) => MEASUREMENT_ERROR,
        }
    })
}

pub(crate) fn completion_zero_sharing_measurement_checkpoint_320() -> Option<Zeroizing<Vec<u8>>> {
    COMPLETION_ZERO_SHARING_MEASUREMENT.with(|measurement| {
        measurement
            .borrow()
            .as_ref()?
            .cursor
            .checkpoint_bytes()
            .ok()
    })
}

pub(crate) fn completion_zero_sharing_measurement_completed_chunk_320() -> Option<Zeroizing<Vec<u8>>>
{
    COMPLETION_ZERO_SHARING_MEASUREMENT.with(|measurement| {
        measurement
            .borrow()
            .as_ref()?
            .cursor
            .completed_chunk_bytes()
            .ok()
    })
}

pub(crate) fn acknowledge_completion_zero_sharing_measurement_chunk_320() -> u32 {
    COMPLETION_ZERO_SHARING_MEASUREMENT.with(|measurement| {
        let mut measurement = measurement.borrow_mut();
        let Some(measurement) = measurement.as_mut() else {
            return MEASUREMENT_ERROR;
        };
        match measurement.cursor.acknowledge_completed_chunk() {
            Ok(PseudorandomZeroSharingCursorState320::Processing) => MEASUREMENT_SUCCESS,
            Ok(PseudorandomZeroSharingCursorState320::Finished) => MEASUREMENT_FINISHED,
            Ok(PseudorandomZeroSharingCursorState320::CompletedChunkReady) | Err(_) => {
                MEASUREMENT_ERROR
            }
        }
    })
}

pub(crate) fn close_completion_zero_sharing_measurement_320() -> u32 {
    COMPLETION_ZERO_SHARING_MEASUREMENT.with(|measurement| {
        let removed = measurement.borrow_mut().take();
        if removed.is_some() {
            MEASUREMENT_SUCCESS
        } else {
            MEASUREMENT_ERROR
        }
    })
}

pub(crate) fn completion_zero_sharing_measurement_state_320() -> u32 {
    COMPLETION_ZERO_SHARING_MEASUREMENT.with(|measurement| {
        measurement
            .borrow()
            .as_ref()
            .map_or(0, |measurement| measurement.cursor.state() as u32)
    })
}

pub(crate) fn completion_zero_sharing_measurement_zero_sharing_count_320() -> u64 {
    measurement_resource_value(|model| model.zero_sharing_count)
}

pub(crate) fn completion_zero_sharing_measurement_basis_stream_count_320() -> u64 {
    measurement_resource_value(|model| model.basis_stream_count)
}

pub(crate) fn completion_zero_sharing_measurement_output_chunk_count_320() -> u64 {
    measurement_resource_value(|model| model.output_chunk_count)
}

pub(crate) fn completion_zero_sharing_measurement_work_checkpoint_count_320() -> u64 {
    measurement_resource_value(|model| model.work_checkpoint_count)
}

pub(crate) fn completion_zero_sharing_measurement_field_output_count_320() -> u64 {
    measurement_resource_value(|model| model.field_output_count)
}

pub(crate) fn completion_zero_sharing_measurement_basis_precomputation_count_320() -> u64 {
    measurement_resource_value(|model| model.basis_precomputation_field_multiplication_count)
}

pub(crate) fn completion_zero_sharing_measurement_combination_multiplication_count_320() -> u64 {
    measurement_resource_value(|model| model.combination_field_multiplication_count)
}

pub(crate) fn completion_zero_sharing_measurement_combination_addition_count_320() -> u64 {
    measurement_resource_value(|model| model.combination_field_addition_count)
}

pub(crate) fn completion_zero_sharing_measurement_expected_checkpoint_traffic_320() -> u64 {
    measurement_resource_value(|model| model.cumulative_completed_step_checkpoint_byte_length)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NativeCompletionZeroSharingMeasurement320 {
    schema_version: u16,
    evidence_classification: &'static str,
    zero_sharing_count: u64,
    basis_stream_count: u64,
    work_checkpoint_count: u64,
    checkpoint_generated_byte_length: u64,
    completed_output_lengths: Vec<usize>,
    #[serde(rename = "completedOutputSha3_512Hex")]
    completed_output_sha3_512_hex: Vec<String>,
    elapsed_milliseconds: f64,
}

pub(crate) fn run_completion_zero_sharing_native_measurement_json() -> Result<String, String> {
    let fixture = completion_measurement_fixture().map_err(|error| error.to_string())?;
    let mut cursor = PseudorandomZeroSharingParticipantCursor320::new(
        fixture.parameter_identity,
        fixture.preparation_context,
        fixture.zero_sharing_catalog_identity,
        fixture.participant_position,
        fixture.total_field_count,
        &fixture.masters,
    )
    .map_err(|error| error.to_string())?;
    let start = std::time::Instant::now();
    let mut work_checkpoint_count = 0_u64;
    let mut checkpoint_generated_byte_length = 0_u64;
    let mut completed_output_lengths = Vec::new();
    let mut completed_output_sha3_512_hex = Vec::new();
    while cursor.state() != PseudorandomZeroSharingCursorState320::Finished {
        cursor
            .step(&fixture.masters)
            .map_err(|error| error.to_string())?;
        work_checkpoint_count = work_checkpoint_count
            .checked_add(1)
            .ok_or_else(|| "native measurement work count overflow".to_owned())?;
        let checkpoint = cursor
            .checkpoint_bytes()
            .map_err(|error| error.to_string())?;
        checkpoint_generated_byte_length = checkpoint_generated_byte_length
            .checked_add(
                u64::try_from(checkpoint.len())
                    .map_err(|_| "native checkpoint length conversion failed".to_owned())?,
            )
            .ok_or_else(|| "native checkpoint traffic overflow".to_owned())?;
        if cursor.state() == PseudorandomZeroSharingCursorState320::CompletedChunkReady {
            let output = cursor
                .completed_chunk_bytes()
                .map_err(|error| error.to_string())?;
            completed_output_lengths.push(output.len());
            completed_output_sha3_512_hex.push(hexadecimal_lower(&Sha3_512::digest(&*output)));
            cursor
                .acknowledge_completed_chunk()
                .map_err(|error| error.to_string())?;
        }
    }
    if work_checkpoint_count != fixture.resource_model.work_checkpoint_count
        || checkpoint_generated_byte_length
            != fixture
                .resource_model
                .cumulative_completed_step_checkpoint_byte_length
    {
        return Err("native measurement disagrees with its production resource model".to_owned());
    }
    serde_json::to_string(&NativeCompletionZeroSharingMeasurement320 {
        schema_version: 1,
        evidence_classification: "native scalar development parity measurement",
        zero_sharing_count: fixture.resource_model.zero_sharing_count,
        basis_stream_count: fixture.resource_model.basis_stream_count,
        work_checkpoint_count,
        checkpoint_generated_byte_length,
        completed_output_lengths,
        completed_output_sha3_512_hex,
        elapsed_milliseconds: start.elapsed().as_secs_f64() * 1_000.0,
    })
    .map_err(|error| error.to_string())
}

fn hexadecimal_lower(bytes: &[u8]) -> String {
    const HEXADECIMAL: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEXADECIMAL[usize::from(byte >> 4)]));
        output.push(char::from(HEXADECIMAL[usize::from(byte & 0x0f)]));
    }
    output
}

fn measurement_resource_value(
    select: impl FnOnce(PseudorandomZeroSharingCursorResourceModel320) -> u64,
) -> u64 {
    COMPLETION_ZERO_SHARING_MEASUREMENT.with(|measurement| {
        measurement
            .borrow()
            .as_ref()
            .map_or(0, |measurement| select(measurement.resource_model))
    })
}

fn codeword_verifier_resource_value(
    select: impl FnOnce(&CanonicalZeroSharingCodewordBlockVerifier320) -> Option<u64>,
) -> u64 {
    let Ok(verifier) =
        CanonicalZeroSharingCodewordBlockVerifier320::new(FOUNDATION_PROFILE.participant_count)
    else {
        return 0;
    };
    select(&verifier).unwrap_or(0)
}

fn completion_measurement_fixture()
-> Result<CompletionZeroSharingMeasurementFixture320, super::TallyPreparationError> {
    let circuit = CompiledTallyCircuit::compile(TallyCircuitProfile::new(
        FOUNDATION_PROFILE.participant_count,
        FOUNDATION_PROFILE.option_count,
        FOUNDATION_PROFILE.option_count,
    )?)?;
    let preparation_context = TallyPreparationContext::new(
        Hash512::from_bytes([0x21; Hash512::BYTE_LENGTH]),
        Hash512::from_bytes([0x43; Hash512::BYTE_LENGTH]),
        [0x65; 32],
        &circuit,
    )?;
    let parameter_identity = Hash512::from_bytes([0x87; Hash512::BYTE_LENGTH]);
    let zero_sharing_catalog_identity = Hash512::from_bytes([0xa9; Hash512::BYTE_LENGTH]);
    let participant_position = 0_u16;
    let workload = PerBitPseudorandomZeroSharingWorkload320::derive(&circuit)?;
    let resource_model = PseudorandomZeroSharingCursorResourceModel320::derive(
        preparation_context.participant_count(),
        participant_position,
        workload.zero_sharing_count,
    )
    .map_err(|_| super::TallyPreparationError::GeometryMismatch)?;
    let masters = ReplicatedRandomSharingSubset::iter(preparation_context.participant_count())?
        .filter_map(|subset| match subset.contains(participant_position) {
            Ok(true) => Some(Ok(subset)),
            Ok(false) => None,
            Err(error) => Some(Err(error)),
        })
        .enumerate()
        .map(|(master_index, subset)| {
            let subset = subset?;
            let scope = PseudorandomZeroSharingSubsetMasterScope320::new(
                parameter_identity,
                preparation_context,
                subset,
            )?;
            let excluded_position_mask = subset.excluded_position_mask().to_le_bytes();
            let bytes = core::array::from_fn(|byte_position| {
                excluded_position_mask[byte_position % excluded_position_mask.len()]
                    ^ u8::try_from(master_index).unwrap_or(0).wrapping_mul(29)
                    ^ u8::try_from(byte_position).unwrap_or(0).wrapping_mul(17)
                    ^ 0x5b
            });
            Ok(locally_joined_subset_master_for_measurement(scope, bytes))
        })
        .collect::<Result<Vec<_>, super::TallyPreparationError>>()?
        .into_boxed_slice();

    Ok(CompletionZeroSharingMeasurementFixture320 {
        parameter_identity,
        preparation_context,
        zero_sharing_catalog_identity,
        participant_position,
        total_field_count: workload.zero_sharing_count,
        masters,
        resource_model,
    })
}

fn completion_codeword_measurement_fixture(
    participant_position: u16,
) -> Result<CompletionZeroSharingMeasurementFixture320, super::TallyPreparationError> {
    codeword_measurement_fixture(participant_position, None)
}

fn codeword_measurement_fixture(
    participant_position: u16,
    requested_total_field_count: Option<u64>,
) -> Result<CompletionZeroSharingMeasurementFixture320, super::TallyPreparationError> {
    let circuit = CompiledTallyCircuit::compile(TallyCircuitProfile::new(
        FOUNDATION_PROFILE.participant_count,
        FOUNDATION_PROFILE.option_count,
        FOUNDATION_PROFILE.option_count,
    )?)?;
    let total_field_count = match requested_total_field_count {
        Some(total_field_count) => total_field_count,
        None => PerBitPseudorandomZeroSharingWorkload320::derive(&circuit)?.zero_sharing_count,
    };
    let preparation_context = TallyPreparationContext::new(
        Hash512::from_bytes([0x21; Hash512::BYTE_LENGTH]),
        Hash512::from_bytes([0x43; Hash512::BYTE_LENGTH]),
        [0x65; 32],
        &circuit,
    )?;
    let parameter_identity = Hash512::from_bytes([0x87; Hash512::BYTE_LENGTH]);
    let zero_sharing_catalog_identity = Hash512::from_bytes([0xa9; Hash512::BYTE_LENGTH]);
    let resource_model = PseudorandomZeroSharingCursorResourceModel320::derive(
        preparation_context.participant_count(),
        participant_position,
        total_field_count,
    )
    .map_err(|_| super::TallyPreparationError::GeometryMismatch)?;
    let masters = ReplicatedRandomSharingSubset::iter(preparation_context.participant_count())?
        .filter_map(|subset| match subset.contains(participant_position) {
            Ok(true) => Some(Ok(subset)),
            Ok(false) => None,
            Err(error) => Some(Err(error)),
        })
        .map(|subset| {
            let subset = subset?;
            let scope = PseudorandomZeroSharingSubsetMasterScope320::new(
                parameter_identity,
                preparation_context,
                subset,
            )?;
            let bytes = derive_all_roster_zero_sharing_measurement_master_320(
                parameter_identity,
                preparation_context.identity(),
                zero_sharing_catalog_identity,
                subset.excluded_position_mask(),
            );
            Ok(locally_joined_subset_master_for_measurement(scope, bytes))
        })
        .collect::<Result<Vec<_>, super::TallyPreparationError>>()?
        .into_boxed_slice();

    Ok(CompletionZeroSharingMeasurementFixture320 {
        parameter_identity,
        preparation_context,
        zero_sharing_catalog_identity,
        participant_position,
        total_field_count,
        masters,
        resource_model,
    })
}
