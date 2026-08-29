use std::{cell::RefCell, time::Instant};

use serde::Serialize;
use sha3::{Digest, Sha3_512};
use zeroize::Zeroizing;

use crate::{
    foundation::{FOUNDATION_PROFILE, Hash512},
    tally_circuit::TallyCircuitProfile,
};

use super::{
    direct_mpc_candidate_compiler::compile_direct_mpc_candidate,
    direct_mpc_participant_cursor::{
        DIRECT_MPC_CURSOR_CHECKPOINT_KEY_BYTE_LENGTH, DirectMpcCursorRefusalCode,
        DirectMpcCursorResourceModel, DirectMpcJoinedSubsetMaster, DirectMpcParticipantCursor,
        DirectMpcPrssContext,
    },
    replicated_random_sharing::ReplicatedRandomSharingSubset,
};

pub(crate) const MEASUREMENT_PROCESSING_STATE: u32 = 1;
pub(crate) const MEASUREMENT_FINISHED_STATE: u32 = 2;
pub(crate) const MEASUREMENT_ERROR_STATE: u32 = u32::MAX;
const MEASUREMENT_SUCCESS_CODE: u32 = 0;
const MEASUREMENT_CURSOR_ALREADY_OPEN_CODE: u32 = 1;
const MEASUREMENT_CURSOR_NOT_OPEN_CODE: u32 = 2;

const PARTICIPANT_POSITION: u16 = 0;
const MEASUREMENT_IDENTITY_DOMAIN: &[u8] = b"sealed-lattice/v1/diagnostic/direct-mpc-prss-identity";
const MEASUREMENT_SUBSET_MASTER_DOMAIN: &[u8] =
    b"sealed-lattice/v1/diagnostic/direct-mpc-prss-subset-master";
const MEASUREMENT_CHECKPOINT_KEY_DOMAIN: &[u8] =
    b"sealed-lattice/v1/diagnostic/direct-mpc-prss-checkpoint-key";

struct DirectMpcScalarMeasurement {
    subset_masters: Box<[DirectMpcJoinedSubsetMaster]>,
    cursor: DirectMpcParticipantCursor,
    resource_model: DirectMpcCursorResourceModel,
}

thread_local! {
    static DIRECT_MPC_SCALAR_MEASUREMENT: RefCell<Option<DirectMpcScalarMeasurement>> = const { RefCell::new(None) };
}

pub(crate) fn open_completion_direct_mpc_scalar_measurement() -> u32 {
    DIRECT_MPC_SCALAR_MEASUREMENT.with(|measurement| {
        let mut measurement = measurement.borrow_mut();
        if measurement.is_some() {
            return MEASUREMENT_CURSOR_ALREADY_OPEN_CODE;
        }
        let Ok(fixture) = completion_fixture() else {
            return DirectMpcCursorRefusalCode::Unexpected as u32;
        };
        let Ok(cursor) = DirectMpcParticipantCursor::new(
            fixture.context,
            PARTICIPANT_POSITION,
            &fixture.subset_masters,
            fixture.checkpoint_authentication_key,
        ) else {
            return DirectMpcCursorRefusalCode::Unexpected as u32;
        };
        *measurement = Some(DirectMpcScalarMeasurement {
            subset_masters: fixture.subset_masters,
            cursor,
            resource_model: fixture.resource_model,
        });
        MEASUREMENT_SUCCESS_CODE
    })
}

pub(crate) fn restore_completion_direct_mpc_scalar_measurement(checkpoint_bytes: &[u8]) -> u32 {
    DIRECT_MPC_SCALAR_MEASUREMENT.with(|measurement| {
        let mut measurement = measurement.borrow_mut();
        if measurement.is_some() {
            return MEASUREMENT_CURSOR_ALREADY_OPEN_CODE;
        }
        let Ok(fixture) = completion_fixture() else {
            return DirectMpcCursorRefusalCode::Unexpected as u32;
        };
        let cursor = match DirectMpcParticipantCursor::restore_from_checkpoint(
            fixture.context,
            PARTICIPANT_POSITION,
            &fixture.subset_masters,
            fixture.checkpoint_authentication_key,
            checkpoint_bytes,
        ) {
            Ok(cursor) => cursor,
            Err(error) => return error.refusal_code() as u32,
        };
        *measurement = Some(DirectMpcScalarMeasurement {
            subset_masters: fixture.subset_masters,
            cursor,
            resource_model: fixture.resource_model,
        });
        MEASUREMENT_SUCCESS_CODE
    })
}

pub(crate) fn step_completion_direct_mpc_scalar_measurement() -> u32 {
    DIRECT_MPC_SCALAR_MEASUREMENT.with(|measurement| {
        let mut measurement = measurement.borrow_mut();
        let Some(measurement) = measurement.as_mut() else {
            return MEASUREMENT_CURSOR_NOT_OPEN_CODE;
        };
        match measurement.cursor.step(&measurement.subset_masters) {
            Ok(_) => MEASUREMENT_SUCCESS_CODE,
            Err(error) => error.refusal_code() as u32,
        }
    })
}

pub(crate) fn completion_direct_mpc_scalar_measurement_state() -> u32 {
    DIRECT_MPC_SCALAR_MEASUREMENT.with(|measurement| {
        let measurement = measurement.borrow();
        let Some(measurement) = measurement.as_ref() else {
            return MEASUREMENT_ERROR_STATE;
        };
        match measurement.cursor.is_finished() {
            Ok(true) => MEASUREMENT_FINISHED_STATE,
            Ok(false) => MEASUREMENT_PROCESSING_STATE,
            Err(_) => MEASUREMENT_ERROR_STATE,
        }
    })
}

pub(crate) fn completion_direct_mpc_scalar_measurement_checkpoint() -> Option<Zeroizing<Vec<u8>>> {
    DIRECT_MPC_SCALAR_MEASUREMENT.with(|measurement| {
        measurement
            .borrow()
            .as_ref()?
            .cursor
            .checkpoint_bytes()
            .ok()
    })
}

pub(crate) fn completion_direct_mpc_scalar_measurement_result() -> Option<Zeroizing<Vec<u8>>> {
    DIRECT_MPC_SCALAR_MEASUREMENT
        .with(|measurement| measurement.borrow().as_ref()?.cursor.result_bytes().ok())
}

pub(crate) fn close_completion_direct_mpc_scalar_measurement() -> u32 {
    DIRECT_MPC_SCALAR_MEASUREMENT.with(|measurement| {
        if measurement.borrow_mut().take().is_some() {
            MEASUREMENT_SUCCESS_CODE
        } else {
            MEASUREMENT_CURSOR_NOT_OPEN_CODE
        }
    })
}

macro_rules! resource_getter {
    ($name:ident, $field:ident) => {
        pub(crate) fn $name() -> u64 {
            DIRECT_MPC_SCALAR_MEASUREMENT.with(|measurement| {
                measurement
                    .borrow()
                    .as_ref()
                    .map_or(0, |measurement| measurement.resource_model.$field)
            })
        }
    };
}

resource_getter!(
    completion_direct_mpc_authorized_subset_count,
    authorized_subset_count_per_participant
);
resource_getter!(
    completion_direct_mpc_ordinary_stream_count,
    ordinary_stream_count
);
resource_getter!(
    completion_direct_mpc_zero_basis_stream_count,
    zero_basis_stream_count
);
resource_getter!(completion_direct_mpc_total_stream_count, total_stream_count);
resource_getter!(
    completion_direct_mpc_ordinary_field_count,
    ordinary_field_count
);
resource_getter!(completion_direct_mpc_zero_field_count, zero_field_count);
resource_getter!(completion_direct_mpc_field_output_count, field_output_count);
resource_getter!(completion_direct_mpc_source_byte_length, source_byte_length);
resource_getter!(
    completion_direct_mpc_basis_multiplication_count,
    basis_precomputation_field_multiplication_count
);
resource_getter!(
    completion_direct_mpc_basis_inverse_count,
    ordinary_basis_modular_inverse_count
);
resource_getter!(
    completion_direct_mpc_weight_multiplication_count,
    weight_field_multiplication_count
);
resource_getter!(
    completion_direct_mpc_accumulation_addition_count,
    accumulation_field_addition_count
);
resource_getter!(
    completion_direct_mpc_maximum_xof_allocation_byte_length,
    maximum_xof_output_allocation_byte_length
);
resource_getter!(
    completion_direct_mpc_canonical_accumulator_byte_length,
    canonical_accumulator_byte_length
);
resource_getter!(
    completion_direct_mpc_internal_accumulator_byte_length,
    internal_accumulator_byte_length
);
resource_getter!(
    completion_direct_mpc_checkpoint_byte_length,
    checkpoint_byte_length
);
resource_getter!(
    completion_direct_mpc_cumulative_checkpoint_byte_length,
    cumulative_checkpoint_byte_length
);
resource_getter!(completion_direct_mpc_result_byte_length, result_byte_length);

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NativeDirectMpcScalarMeasurement {
    schema_version: u16,
    evidence_classification: &'static str,
    participant_position: u16,
    total_stream_count: u64,
    field_output_count: u64,
    source_byte_length: u64,
    checkpoint_generated_byte_length: u64,
    checkpoint_byte_length: u64,
    result_byte_length: usize,
    #[serde(rename = "resultSha3_512Hex")]
    result_sha3_512_hex: String,
    #[serde(rename = "restoredResultSha3_512Hex")]
    restored_result_sha3_512_hex: String,
    restored_result_matches: bool,
    checkpoint_mutation_refusal_code: u32,
    elapsed_milliseconds: f64,
}

pub(crate) fn run_completion_direct_mpc_native_measurement_json() -> Result<String, String> {
    let started = Instant::now();
    let fixture = completion_fixture().map_err(|error| error.to_string())?;
    let mut cursor = DirectMpcParticipantCursor::new(
        fixture.context,
        PARTICIPANT_POSITION,
        &fixture.subset_masters,
        fixture.checkpoint_authentication_key,
    )
    .map_err(|error| error.to_string())?;
    let capture_stream_index = fixture.resource_model.ordinary_stream_count;
    let mut checkpoint_generated_byte_length = 0_u64;
    let mut captured_checkpoint = None;
    while !cursor.is_finished().map_err(|error| error.to_string())? {
        cursor
            .step(&fixture.subset_masters)
            .map_err(|error| error.to_string())?;
        let checkpoint = cursor
            .checkpoint_bytes()
            .map_err(|error| error.to_string())?;
        checkpoint_generated_byte_length = checkpoint_generated_byte_length
            .checked_add(checkpoint.len() as u64)
            .ok_or_else(|| "native direct-MPC checkpoint traffic overflow".to_owned())?;
        if cursor.next_stream_index() == capture_stream_index {
            captured_checkpoint = Some(checkpoint);
        }
    }
    let result = cursor.result_bytes().map_err(|error| error.to_string())?;
    let result_digest = Sha3_512::digest(result.as_slice());
    let captured_checkpoint = captured_checkpoint
        .ok_or_else(|| "native direct-MPC restoration checkpoint is absent".to_owned())?;

    let restored_fixture = completion_fixture().map_err(|error| error.to_string())?;
    let mut restored = DirectMpcParticipantCursor::restore_from_checkpoint(
        restored_fixture.context,
        PARTICIPANT_POSITION,
        &restored_fixture.subset_masters,
        restored_fixture.checkpoint_authentication_key,
        &captured_checkpoint,
    )
    .map_err(|error| error.to_string())?;
    while !restored.is_finished().map_err(|error| error.to_string())? {
        restored
            .step(&restored_fixture.subset_masters)
            .map_err(|error| error.to_string())?;
    }
    let restored_result = restored.result_bytes().map_err(|error| error.to_string())?;
    let restored_digest = Sha3_512::digest(restored_result.as_slice());

    let mut mutated_checkpoint = captured_checkpoint.to_vec();
    let mutation_position = mutated_checkpoint.len() / 2;
    mutated_checkpoint[mutation_position] ^= 0x80;
    let mutation_fixture = completion_fixture().map_err(|error| error.to_string())?;
    let mutation_refusal = DirectMpcParticipantCursor::restore_from_checkpoint(
        mutation_fixture.context,
        PARTICIPANT_POSITION,
        &mutation_fixture.subset_masters,
        mutation_fixture.checkpoint_authentication_key,
        &mutated_checkpoint,
    )
    .expect_err("a mutated checkpoint must refuse")
    .refusal_code() as u32;

    let measurement = NativeDirectMpcScalarMeasurement {
        schema_version: 1,
        evidence_classification: "completion-scale native direct-MPC PRSS development measurement",
        participant_position: PARTICIPANT_POSITION,
        total_stream_count: fixture.resource_model.total_stream_count,
        field_output_count: fixture.resource_model.field_output_count,
        source_byte_length: fixture.resource_model.source_byte_length,
        checkpoint_generated_byte_length,
        checkpoint_byte_length: fixture.resource_model.checkpoint_byte_length,
        result_byte_length: result.len(),
        result_sha3_512_hex: hex(&result_digest),
        restored_result_sha3_512_hex: hex(&restored_digest),
        restored_result_matches: result.as_slice() == restored_result.as_slice(),
        checkpoint_mutation_refusal_code: mutation_refusal,
        elapsed_milliseconds: started.elapsed().as_secs_f64() * 1_000.0,
    };
    serde_json::to_string(&measurement).map_err(|error| error.to_string())
}

struct CompletionFixture {
    context: DirectMpcPrssContext,
    subset_masters: Box<[DirectMpcJoinedSubsetMaster]>,
    checkpoint_authentication_key: [u8; DIRECT_MPC_CURSOR_CHECKPOINT_KEY_BYTE_LENGTH],
    resource_model: DirectMpcCursorResourceModel,
}

fn completion_fixture() -> Result<CompletionFixture, Box<dyn std::error::Error>> {
    let profile = TallyCircuitProfile::new(
        FOUNDATION_PROFILE.participant_count,
        FOUNDATION_PROFILE.option_count,
        FOUNDATION_PROFILE.option_count,
    )?;
    let candidate = compile_direct_mpc_candidate(profile)?;
    let candidate_resource = candidate.resource_model()?;
    let candidate_identity = measurement_identity(1, profile, &candidate_resource);
    let preparation_context_identity = measurement_identity(2, profile, &candidate_resource);
    let seed_terminal_identity = measurement_identity(3, profile, &candidate_resource);
    let context = DirectMpcPrssContext::new(
        candidate_identity,
        preparation_context_identity,
        seed_terminal_identity,
        profile.participant_count(),
        candidate_resource.random_degree_three_sharing_count,
        candidate_resource.random_degree_six_zero_sharing_count,
    );
    let subset_masters = ReplicatedRandomSharingSubset::iter(profile.participant_count())?
        .filter_map(|subset| match subset.contains(PARTICIPANT_POSITION) {
            Ok(true) => Some(Ok(DirectMpcJoinedSubsetMaster::new(
                subset,
                measurement_subset_master(context, subset),
            ))),
            Ok(false) => None,
            Err(error) => Some(Err(error)),
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_boxed_slice();
    let checkpoint_authentication_key = measurement_checkpoint_key(context);
    let resource_model = DirectMpcCursorResourceModel::derive(context, PARTICIPANT_POSITION)?;
    Ok(CompletionFixture {
        context,
        subset_masters,
        checkpoint_authentication_key,
        resource_model,
    })
}

fn measurement_identity(
    identity_kind: u8,
    profile: TallyCircuitProfile,
    resource: &super::direct_mpc_candidate_compiler::DirectMpcCandidateResourceModel,
) -> Hash512 {
    let mut derivation = Sha3_512::new();
    derivation.update(MEASUREMENT_IDENTITY_DOMAIN);
    derivation.update([identity_kind]);
    derivation.update(profile.participant_count().to_le_bytes());
    derivation.update(profile.option_count().to_le_bytes());
    derivation.update(profile.top_count().to_le_bytes());
    derivation.update(resource.beaver_triple_count.to_le_bytes());
    derivation.update(resource.random_degree_three_sharing_count.to_le_bytes());
    derivation.update(resource.random_degree_six_zero_sharing_count.to_le_bytes());
    Hash512::from_bytes(derivation.finalize().into())
}

fn measurement_subset_master(
    context: DirectMpcPrssContext,
    subset: ReplicatedRandomSharingSubset,
) -> [u8; 40] {
    let mut derivation = Sha3_512::new();
    derivation.update(MEASUREMENT_SUBSET_MASTER_DOMAIN);
    derivation.update(context.candidate_identity().as_bytes());
    derivation.update(context.preparation_context_identity().as_bytes());
    derivation.update(context.seed_terminal_identity().as_bytes());
    derivation.update(subset.excluded_position_mask().to_le_bytes());
    let digest = derivation.finalize();
    core::array::from_fn(|position| digest[position])
}

fn measurement_checkpoint_key(
    context: DirectMpcPrssContext,
) -> [u8; DIRECT_MPC_CURSOR_CHECKPOINT_KEY_BYTE_LENGTH] {
    let mut derivation = Sha3_512::new();
    derivation.update(MEASUREMENT_CHECKPOINT_KEY_DOMAIN);
    derivation.update(context.candidate_identity().as_bytes());
    derivation.update(context.preparation_context_identity().as_bytes());
    derivation.update(context.seed_terminal_identity().as_bytes());
    derivation.update(PARTICIPANT_POSITION.to_le_bytes());
    let digest = derivation.finalize();
    core::array::from_fn(|position| digest[position])
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[usize::from(byte >> 4)] as char);
        output.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    output
}
