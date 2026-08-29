#[cfg(feature = "lpsy15-scalar-measurement")]
use std::cell::RefCell;

use serde::Serialize;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    encoding::{CanonicalReader, append_bytes, append_varuint},
    foundation::{FOUNDATION_PROFILE, Hash512},
    tally_circuit::{CompiledTallyCircuit, TallyCircuitProfile},
};

use super::{
    lpsy15_bmr_prf::{
        LPSY15_BMR_PRF_KEY_BYTE_LENGTH, LPSY15_BMR_PRF_OUTPUT_BYTE_LENGTH, Lpsy15BmrPrfInput,
        evaluate_lpsy15_bmr_prf, fixed_output_kmac256,
    },
    lpsy15_candidate_compiler::Lpsy15CandidateCompilation,
    lpsy15_prime_field::Lpsy15PrimeFieldElement,
};

#[cfg(feature = "lpsy15-scalar-measurement")]
pub(crate) const MEASUREMENT_SUCCESS: u32 = 0;
#[cfg(feature = "lpsy15-scalar-measurement")]
pub(crate) const MEASUREMENT_FINISHED: u32 = 1;
#[cfg(feature = "lpsy15-scalar-measurement")]
pub(crate) const MEASUREMENT_ERROR: u32 = u32::MAX;
pub(crate) const FIELD_MEASUREMENT_KIND: u32 = 1;
pub(crate) const PRF_MEASUREMENT_KIND: u32 = 2;
#[cfg(feature = "lpsy15-scalar-measurement")]
pub(crate) const PROCESSING_STATE: u32 = 1;
#[cfg(feature = "lpsy15-scalar-measurement")]
pub(crate) const FINISHED_STATE: u32 = 2;
#[cfg(feature = "lpsy15-scalar-measurement")]
pub(crate) const SAMPLE_WORK_STEP_COUNT: u64 = 4;

const CHECKPOINT_VERSION: u64 = 1;
const CHECKPOINT_AUTHENTICATION_TAG_BYTE_LENGTH: usize = 64;
const FIELD_SCRATCH_STREAM_COUNT: u64 = 7;
const CHECKPOINT_DOMAIN: &[u8] = b"sealed-lattice/v1/preparation/lpsy15-scalar-cursor-checkpoint";
const CHECKPOINT_KEY_CUSTOMIZATION: &[u8] =
    b"sealed-lattice/v1/preparation/lpsy15-scalar-checkpoint-key";
const CHECKPOINT_TAG_CUSTOMIZATION: &[u8] =
    b"sealed-lattice/v1/preparation/lpsy15-scalar-checkpoint-tag";
const MEASUREMENT_CHECKPOINT_MASTER: [u8; LPSY15_BMR_PRF_KEY_BYTE_LENGTH] =
    [0x6d; LPSY15_BMR_PRF_KEY_BYTE_LENGTH];

#[cfg(feature = "lpsy15-scalar-measurement")]
thread_local! {
    static OPEN_MEASUREMENT: RefCell<Option<Lpsy15ScalarMeasurementCursor>> = const {
        RefCell::new(None)
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Lpsy15ScalarMeasurementKind {
    PrimeField,
    BmrPrf,
}

impl Lpsy15ScalarMeasurementKind {
    pub(crate) const fn code(self) -> u32 {
        match self {
            Self::PrimeField => FIELD_MEASUREMENT_KIND,
            Self::BmrPrf => PRF_MEASUREMENT_KIND,
        }
    }

    #[cfg(feature = "lpsy15-scalar-measurement")]
    fn from_code(code: u32) -> Result<Self, Lpsy15ScalarMeasurementError> {
        match code {
            FIELD_MEASUREMENT_KIND => Ok(Self::PrimeField),
            PRF_MEASUREMENT_KIND => Ok(Self::BmrPrf),
            _ => Err(Lpsy15ScalarMeasurementError::UnsupportedKind),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Lpsy15ScalarMeasurementCounts {
    pub(crate) field_multiplication_count: u64,
    pub(crate) field_addition_count: u64,
    pub(crate) prf_call_count: u64,
    pub(crate) prf_message_byte_length: u64,
    pub(crate) prf_permutation_count_per_call: u64,
    pub(crate) work_batch_operation_count: u64,
    pub(crate) field_scratch_byte_length: u64,
    pub(crate) participant_count: u16,
}

impl Lpsy15ScalarMeasurementCounts {
    pub(crate) fn derive() -> Result<Self, Lpsy15ScalarMeasurementError> {
        let profile = TallyCircuitProfile::new(
            FOUNDATION_PROFILE.participant_count,
            FOUNDATION_PROFILE.option_count,
            FOUNDATION_PROFILE.option_count,
        )
        .map_err(|_| Lpsy15ScalarMeasurementError::Construction)?;
        let circuit = CompiledTallyCircuit::compile(profile)
            .map_err(|_| Lpsy15ScalarMeasurementError::Construction)?;
        let compilation = Lpsy15CandidateCompilation::compile(&circuit)
            .map_err(|_| Lpsy15ScalarMeasurementError::Construction)?;
        let ledger = compilation.resource_ledger();
        let expected_scratch_byte_length = ledger
            .field_work_batch_element_count
            .checked_mul(FIELD_SCRATCH_STREAM_COUNT)
            .and_then(|count| {
                count.checked_mul(Lpsy15PrimeFieldElement::ARITHMETIC_BYTE_LENGTH as u64)
            })
            .ok_or(Lpsy15ScalarMeasurementError::ArithmeticOverflow)?;
        if ledger.maximum_field_work_batch_byte_length != expected_scratch_byte_length {
            return Err(Lpsy15ScalarMeasurementError::Construction);
        }
        Ok(Self {
            field_multiplication_count: ledger.complete_field_multiplication_count_per_participant,
            field_addition_count: ledger.complete_field_addition_count_per_participant,
            prf_call_count: ledger.complete_prf_call_count_per_participant,
            prf_message_byte_length: ledger.prf_message_byte_length,
            prf_permutation_count_per_call: ledger.prf_kmac_permutation_count_per_call,
            work_batch_operation_count: ledger.field_work_batch_element_count,
            field_scratch_byte_length: ledger.maximum_field_work_batch_byte_length,
            participant_count: FOUNDATION_PROFILE.participant_count,
        })
    }

    const fn total_operation_count(self, kind: Lpsy15ScalarMeasurementKind) -> u64 {
        match kind {
            Lpsy15ScalarMeasurementKind::PrimeField => self.field_multiplication_count,
            Lpsy15ScalarMeasurementKind::BmrPrf => self.prf_call_count,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lpsy15ScalarMeasurementError {
    ArithmeticOverflow,
    AuthenticationFailed,
    Construction,
    Encoding,
    StateMismatch,
    #[cfg(feature = "lpsy15-scalar-measurement")]
    UnsupportedKind,
}

pub(crate) struct Lpsy15ScalarMeasurementCursor {
    kind: Lpsy15ScalarMeasurementKind,
    pub(crate) counts: Lpsy15ScalarMeasurementCounts,
    pub(crate) completed_operation_count: u64,
    completed_field_addition_count: u64,
    field_addition_schedule: u64,
    field_accumulator: Lpsy15PrimeFieldElement,
    prf_accumulator: [u8; LPSY15_BMR_PRF_OUTPUT_BYTE_LENGTH],
    field_scratch: Zeroizing<Vec<Lpsy15PrimeFieldElement>>,
    checkpoint_authentication_key: Zeroizing<[u8; LPSY15_BMR_PRF_KEY_BYTE_LENGTH]>,
}

impl Lpsy15ScalarMeasurementCursor {
    pub(crate) fn new(
        kind: Lpsy15ScalarMeasurementKind,
    ) -> Result<Self, Lpsy15ScalarMeasurementError> {
        let counts = Lpsy15ScalarMeasurementCounts::derive()?;
        let scratch_element_count = match kind {
            Lpsy15ScalarMeasurementKind::PrimeField => counts
                .field_scratch_byte_length
                .checked_div(Lpsy15PrimeFieldElement::ARITHMETIC_BYTE_LENGTH as u64)
                .and_then(|count| usize::try_from(count).ok())
                .ok_or(Lpsy15ScalarMeasurementError::ArithmeticOverflow)?,
            Lpsy15ScalarMeasurementKind::BmrPrf => 0,
        };
        let mut field_scratch = Zeroizing::new(Vec::with_capacity(scratch_element_count));
        for scratch_position in 0..scratch_element_count {
            field_scratch.push(Lpsy15PrimeFieldElement::from_unsigned64(
                deterministic_word(scratch_position as u64) | 1,
            ));
        }
        let checkpoint_authentication_key = derive_checkpoint_authentication_key(kind, counts);
        Ok(Self {
            kind,
            counts,
            completed_operation_count: 0,
            completed_field_addition_count: 0,
            field_addition_schedule: 0,
            field_accumulator: Lpsy15PrimeFieldElement::from_unsigned64(0xd6e8_feb8_6659_fd93),
            prf_accumulator: [0_u8; LPSY15_BMR_PRF_OUTPUT_BYTE_LENGTH],
            field_scratch,
            checkpoint_authentication_key,
        })
    }

    pub(crate) fn restore(
        kind: Lpsy15ScalarMeasurementKind,
        checkpoint_bytes: &[u8],
    ) -> Result<Self, Lpsy15ScalarMeasurementError> {
        let mut cursor = Self::new(kind)?;
        cursor.restore_state(checkpoint_bytes)?;
        Ok(cursor)
    }

    pub(crate) fn step(&mut self) -> Result<bool, Lpsy15ScalarMeasurementError> {
        let total_operation_count = self.counts.total_operation_count(self.kind);
        if self.completed_operation_count >= total_operation_count {
            return Err(Lpsy15ScalarMeasurementError::StateMismatch);
        }
        let operation_count = self
            .counts
            .work_batch_operation_count
            .min(total_operation_count - self.completed_operation_count);
        match self.kind {
            Lpsy15ScalarMeasurementKind::PrimeField => self.step_prime_field(operation_count)?,
            Lpsy15ScalarMeasurementKind::BmrPrf => self.step_bmr_prf(operation_count)?,
        }
        self.completed_operation_count = self
            .completed_operation_count
            .checked_add(operation_count)
            .ok_or(Lpsy15ScalarMeasurementError::ArithmeticOverflow)?;
        Ok(self.completed_operation_count == total_operation_count)
    }

    fn step_prime_field(
        &mut self,
        operation_count: u64,
    ) -> Result<(), Lpsy15ScalarMeasurementError> {
        let scratch_length = self.field_scratch.len();
        if scratch_length == 0 {
            return Err(Lpsy15ScalarMeasurementError::StateMismatch);
        }
        let starting_scratch_position = usize::try_from(
            self.completed_operation_count
                % u64::try_from(scratch_length)
                    .map_err(|_| Lpsy15ScalarMeasurementError::ArithmeticOverflow)?,
        )
        .map_err(|_| Lpsy15ScalarMeasurementError::ArithmeticOverflow)?;
        for operation_position in 0..operation_count {
            let operation_position = usize::try_from(operation_position)
                .map_err(|_| Lpsy15ScalarMeasurementError::ArithmeticOverflow)?;
            let multiplicand_position =
                (starting_scratch_position + operation_position) % scratch_length;
            let addend_position = (multiplicand_position
                + usize::try_from(self.counts.work_batch_operation_count)
                    .map_err(|_| Lpsy15ScalarMeasurementError::ArithmeticOverflow)?)
                % scratch_length;
            self.field_accumulator = self
                .field_accumulator
                .multiply(self.field_scratch[multiplicand_position]);

            self.field_addition_schedule = self
                .field_addition_schedule
                .checked_add(self.counts.field_addition_count)
                .ok_or(Lpsy15ScalarMeasurementError::ArithmeticOverflow)?;
            if self.field_addition_schedule >= self.counts.field_multiplication_count {
                self.field_addition_schedule -= self.counts.field_multiplication_count;
                self.field_accumulator = self
                    .field_accumulator
                    .add(self.field_scratch[addend_position]);
                self.completed_field_addition_count = self
                    .completed_field_addition_count
                    .checked_add(1)
                    .ok_or(Lpsy15ScalarMeasurementError::ArithmeticOverflow)?;
            }
        }
        Ok(())
    }

    fn step_bmr_prf(&mut self, operation_count: u64) -> Result<(), Lpsy15ScalarMeasurementError> {
        for operation_position in 0..operation_count {
            let operation_ordinal = self
                .completed_operation_count
                .checked_add(operation_position)
                .ok_or(Lpsy15ScalarMeasurementError::ArithmeticOverflow)?;
            let key = deterministic_prf_key(operation_ordinal);
            let prf_output = evaluate_lpsy15_bmr_prf(
                &key,
                deterministic_prf_input(operation_ordinal, self.counts.participant_count),
            )
            .map_err(|_| Lpsy15ScalarMeasurementError::Encoding)?;
            for (accumulator_byte, output_byte) in
                self.prf_accumulator.iter_mut().zip(prf_output.iter())
            {
                *accumulator_byte ^= output_byte;
            }
        }
        Ok(())
    }

    pub(crate) fn checkpoint_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut checkpoint_body = self.snapshot_bytes();
        let tag = fixed_output_kmac256::<CHECKPOINT_AUTHENTICATION_TAG_BYTE_LENGTH>(
            &self.checkpoint_authentication_key,
            CHECKPOINT_TAG_CUSTOMIZATION,
            &checkpoint_body,
        );
        checkpoint_body.extend_from_slice(tag.as_ref());
        checkpoint_body
    }

    pub(crate) fn snapshot_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(320));
        append_bytes(&mut bytes, CHECKPOINT_DOMAIN);
        append_varuint(&mut bytes, CHECKPOINT_VERSION);
        append_varuint(&mut bytes, u64::from(self.kind.code()));
        append_varuint(&mut bytes, self.counts.field_multiplication_count);
        append_varuint(&mut bytes, self.counts.field_addition_count);
        append_varuint(&mut bytes, self.counts.prf_call_count);
        append_varuint(&mut bytes, self.counts.prf_message_byte_length);
        append_varuint(&mut bytes, self.counts.prf_permutation_count_per_call);
        append_varuint(&mut bytes, self.counts.work_batch_operation_count);
        append_varuint(&mut bytes, self.counts.field_scratch_byte_length);
        append_varuint(&mut bytes, self.completed_operation_count);
        append_varuint(&mut bytes, self.completed_field_addition_count);
        append_varuint(&mut bytes, self.field_addition_schedule);
        append_bytes(&mut bytes, &self.field_accumulator.canonical_bytes());
        append_bytes(&mut bytes, &self.prf_accumulator);
        bytes
    }

    fn restore_state(
        &mut self,
        checkpoint_bytes: &[u8],
    ) -> Result<(), Lpsy15ScalarMeasurementError> {
        if checkpoint_bytes.len() < CHECKPOINT_AUTHENTICATION_TAG_BYTE_LENGTH {
            return Err(Lpsy15ScalarMeasurementError::Encoding);
        }
        let body_byte_length = checkpoint_bytes.len() - CHECKPOINT_AUTHENTICATION_TAG_BYTE_LENGTH;
        let (checkpoint_body, supplied_tag) = checkpoint_bytes.split_at(body_byte_length);
        let expected_tag = fixed_output_kmac256::<CHECKPOINT_AUTHENTICATION_TAG_BYTE_LENGTH>(
            &self.checkpoint_authentication_key,
            CHECKPOINT_TAG_CUSTOMIZATION,
            checkpoint_body,
        );
        if !bool::from(expected_tag.as_ref().ct_eq(supplied_tag)) {
            return Err(Lpsy15ScalarMeasurementError::AuthenticationFailed);
        }

        let mut reader = CanonicalReader::new(checkpoint_body);
        require_bytes(&mut reader, CHECKPOINT_DOMAIN)?;
        require_varuint(&mut reader, CHECKPOINT_VERSION)?;
        require_varuint(&mut reader, u64::from(self.kind.code()))?;
        require_varuint(&mut reader, self.counts.field_multiplication_count)?;
        require_varuint(&mut reader, self.counts.field_addition_count)?;
        require_varuint(&mut reader, self.counts.prf_call_count)?;
        require_varuint(&mut reader, self.counts.prf_message_byte_length)?;
        require_varuint(&mut reader, self.counts.prf_permutation_count_per_call)?;
        require_varuint(&mut reader, self.counts.work_batch_operation_count)?;
        require_varuint(&mut reader, self.counts.field_scratch_byte_length)?;
        let completed_operation_count = read_varuint(&mut reader)?;
        let completed_field_addition_count = read_varuint(&mut reader)?;
        let field_addition_schedule = read_varuint(&mut reader)?;
        let field_accumulator = Lpsy15PrimeFieldElement::from_canonical_bytes(read_bytes(
            &mut reader,
            Lpsy15PrimeFieldElement::CANONICAL_BYTE_LENGTH,
        )?)
        .map_err(|_| Lpsy15ScalarMeasurementError::Encoding)?;
        let prf_accumulator_bytes = read_bytes(&mut reader, LPSY15_BMR_PRF_OUTPUT_BYTE_LENGTH)?;
        let prf_accumulator: [u8; LPSY15_BMR_PRF_OUTPUT_BYTE_LENGTH] = prf_accumulator_bytes
            .try_into()
            .map_err(|_| Lpsy15ScalarMeasurementError::Encoding)?;
        if !reader.is_finished() {
            return Err(Lpsy15ScalarMeasurementError::Encoding);
        }

        let total_operation_count = self.counts.total_operation_count(self.kind);
        if completed_operation_count > total_operation_count {
            return Err(Lpsy15ScalarMeasurementError::StateMismatch);
        }
        let (expected_addition_count, expected_addition_schedule) = match self.kind {
            Lpsy15ScalarMeasurementKind::PrimeField => {
                let scaled_completed = u128::from(completed_operation_count)
                    * u128::from(self.counts.field_addition_count);
                (
                    u64::try_from(
                        scaled_completed / u128::from(self.counts.field_multiplication_count),
                    )
                    .map_err(|_| Lpsy15ScalarMeasurementError::ArithmeticOverflow)?,
                    u64::try_from(
                        scaled_completed % u128::from(self.counts.field_multiplication_count),
                    )
                    .map_err(|_| Lpsy15ScalarMeasurementError::ArithmeticOverflow)?,
                )
            }
            Lpsy15ScalarMeasurementKind::BmrPrf => (0, 0),
        };
        if completed_field_addition_count != expected_addition_count
            || field_addition_schedule != expected_addition_schedule
        {
            return Err(Lpsy15ScalarMeasurementError::StateMismatch);
        }

        self.completed_operation_count = completed_operation_count;
        self.completed_field_addition_count = completed_field_addition_count;
        self.field_addition_schedule = field_addition_schedule;
        self.field_accumulator = field_accumulator;
        self.prf_accumulator = prf_accumulator;
        Ok(())
    }
}

impl Drop for Lpsy15ScalarMeasurementCursor {
    fn drop(&mut self) {
        self.prf_accumulator.zeroize();
    }
}

#[cfg(feature = "lpsy15-scalar-measurement")]
pub(crate) fn open_lpsy15_scalar_measurement(kind_code: u32) -> u32 {
    let Ok(kind) = Lpsy15ScalarMeasurementKind::from_code(kind_code) else {
        return MEASUREMENT_ERROR;
    };
    OPEN_MEASUREMENT.with(|measurement| {
        let mut measurement = measurement.borrow_mut();
        if measurement.is_some() {
            return MEASUREMENT_ERROR;
        }
        let Ok(cursor) = Lpsy15ScalarMeasurementCursor::new(kind) else {
            return MEASUREMENT_ERROR;
        };
        *measurement = Some(cursor);
        MEASUREMENT_SUCCESS
    })
}

#[cfg(feature = "lpsy15-scalar-measurement")]
pub(crate) fn restore_lpsy15_scalar_measurement(kind_code: u32, checkpoint: &[u8]) -> u32 {
    let Ok(kind) = Lpsy15ScalarMeasurementKind::from_code(kind_code) else {
        return MEASUREMENT_ERROR;
    };
    OPEN_MEASUREMENT.with(|measurement| {
        let mut measurement = measurement.borrow_mut();
        if measurement.is_some() {
            return MEASUREMENT_ERROR;
        }
        let Ok(cursor) = Lpsy15ScalarMeasurementCursor::restore(kind, checkpoint) else {
            return MEASUREMENT_ERROR;
        };
        *measurement = Some(cursor);
        MEASUREMENT_SUCCESS
    })
}

#[cfg(feature = "lpsy15-scalar-measurement")]
pub(crate) fn step_lpsy15_scalar_measurement() -> u32 {
    OPEN_MEASUREMENT.with(|measurement| {
        let mut measurement = measurement.borrow_mut();
        let Some(cursor) = measurement.as_mut() else {
            return MEASUREMENT_ERROR;
        };
        match cursor.step() {
            Ok(false) => MEASUREMENT_SUCCESS,
            Ok(true) => MEASUREMENT_FINISHED,
            Err(_) => MEASUREMENT_ERROR,
        }
    })
}

#[cfg(feature = "lpsy15-scalar-measurement")]
pub(crate) fn lpsy15_scalar_measurement_checkpoint() -> Option<Zeroizing<Vec<u8>>> {
    OPEN_MEASUREMENT.with(|measurement| {
        measurement
            .borrow()
            .as_ref()
            .map(Lpsy15ScalarMeasurementCursor::checkpoint_bytes)
    })
}

#[cfg(feature = "lpsy15-scalar-measurement")]
pub(crate) fn lpsy15_scalar_measurement_snapshot() -> Option<Zeroizing<Vec<u8>>> {
    OPEN_MEASUREMENT.with(|measurement| {
        measurement
            .borrow()
            .as_ref()
            .map(Lpsy15ScalarMeasurementCursor::snapshot_bytes)
    })
}

#[cfg(feature = "lpsy15-scalar-measurement")]
pub(crate) fn close_lpsy15_scalar_measurement() -> u32 {
    OPEN_MEASUREMENT.with(|measurement| {
        if measurement.borrow_mut().take().is_none() {
            MEASUREMENT_ERROR
        } else {
            MEASUREMENT_SUCCESS
        }
    })
}

#[cfg(feature = "lpsy15-scalar-measurement")]
pub(crate) fn lpsy15_scalar_measurement_state() -> u32 {
    OPEN_MEASUREMENT.with(|measurement| {
        let measurement = measurement.borrow();
        let Some(cursor) = measurement.as_ref() else {
            return 0;
        };
        if cursor.completed_operation_count == cursor.counts.total_operation_count(cursor.kind) {
            FINISHED_STATE
        } else {
            PROCESSING_STATE
        }
    })
}

#[cfg(feature = "lpsy15-scalar-measurement")]
pub(crate) fn lpsy15_scalar_measurement_completed_operation_count() -> u64 {
    with_cursor_value(|cursor| cursor.completed_operation_count)
}

#[cfg(feature = "lpsy15-scalar-measurement")]
pub(crate) fn lpsy15_scalar_measurement_total_operation_count() -> u64 {
    with_cursor_value(|cursor| cursor.counts.total_operation_count(cursor.kind))
}

#[cfg(feature = "lpsy15-scalar-measurement")]
pub(crate) fn lpsy15_scalar_measurement_total_field_addition_count() -> u64 {
    with_cursor_value(|cursor| cursor.counts.field_addition_count)
}

#[cfg(feature = "lpsy15-scalar-measurement")]
pub(crate) fn lpsy15_scalar_measurement_work_batch_operation_count() -> u64 {
    with_cursor_value(|cursor| cursor.counts.work_batch_operation_count)
}

#[cfg(feature = "lpsy15-scalar-measurement")]
pub(crate) fn lpsy15_scalar_measurement_field_scratch_byte_length() -> u64 {
    with_cursor_value(|cursor| cursor.counts.field_scratch_byte_length)
}

#[cfg(feature = "lpsy15-scalar-measurement")]
pub(crate) fn lpsy15_scalar_measurement_prf_message_byte_length() -> u64 {
    with_cursor_value(|cursor| cursor.counts.prf_message_byte_length)
}

#[cfg(feature = "lpsy15-scalar-measurement")]
pub(crate) fn lpsy15_scalar_measurement_prf_permutation_count_per_call() -> u64 {
    with_cursor_value(|cursor| cursor.counts.prf_permutation_count_per_call)
}

#[cfg(feature = "lpsy15-scalar-measurement")]
fn with_cursor_value(select: impl FnOnce(&Lpsy15ScalarMeasurementCursor) -> u64) -> u64 {
    OPEN_MEASUREMENT.with(|measurement| measurement.borrow().as_ref().map(select).unwrap_or(0))
}

fn derive_checkpoint_authentication_key(
    kind: Lpsy15ScalarMeasurementKind,
    counts: Lpsy15ScalarMeasurementCounts,
) -> Zeroizing<[u8; LPSY15_BMR_PRF_KEY_BYTE_LENGTH]> {
    let mut context = Zeroizing::new(Vec::with_capacity(80));
    context.extend_from_slice(&kind.code().to_le_bytes());
    context.extend_from_slice(&counts.field_multiplication_count.to_le_bytes());
    context.extend_from_slice(&counts.field_addition_count.to_le_bytes());
    context.extend_from_slice(&counts.prf_call_count.to_le_bytes());
    context.extend_from_slice(&counts.prf_message_byte_length.to_le_bytes());
    context.extend_from_slice(&counts.prf_permutation_count_per_call.to_le_bytes());
    context.extend_from_slice(&counts.work_batch_operation_count.to_le_bytes());
    context.extend_from_slice(&counts.field_scratch_byte_length.to_le_bytes());
    fixed_output_kmac256(
        &MEASUREMENT_CHECKPOINT_MASTER,
        CHECKPOINT_KEY_CUSTOMIZATION,
        &context,
    )
}

fn deterministic_word(ordinal: u64) -> u64 {
    let mut value = ordinal.wrapping_add(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn deterministic_prf_key(ordinal: u64) -> [u8; LPSY15_BMR_PRF_KEY_BYTE_LENGTH] {
    let mut key = [0_u8; LPSY15_BMR_PRF_KEY_BYTE_LENGTH];
    for (limb_position, key_chunk) in key.chunks_exact_mut(8).enumerate() {
        key_chunk.copy_from_slice(
            &deterministic_word(ordinal ^ ((limb_position as u64) << 48)).to_le_bytes(),
        );
    }
    key
}

fn deterministic_prf_input(ordinal: u64, participant_count: u16) -> Lpsy15BmrPrfInput {
    Lpsy15BmrPrfInput {
        candidate_identity: Hash512::from_bytes([0x11; Hash512::BYTE_LENGTH]),
        roster_root: Hash512::from_bytes([0x22; Hash512::BYTE_LENGTH]),
        circuit_identity: Hash512::from_bytes([0x33; Hash512::BYTE_LENGTH]),
        preparation_attempt_root: Hash512::from_bytes([0x44; Hash512::BYTE_LENGTH]),
        complete_predecessor_root: Hash512::from_bytes([0x55; Hash512::BYTE_LENGTH]),
        gate_index: ordinal as u32,
        input_side: (ordinal & 1) as u16,
        output_component: u16::try_from((ordinal >> 1) % u64::from(participant_count))
            .expect("participant position fits u16"),
        branch: ((ordinal >> 2) & 1) as u16,
    }
}

fn read_varuint(reader: &mut CanonicalReader<'_>) -> Result<u64, Lpsy15ScalarMeasurementError> {
    reader
        .read_varuint()
        .map_err(|_| Lpsy15ScalarMeasurementError::Encoding)
}

fn read_bytes<'a>(
    reader: &mut CanonicalReader<'a>,
    expected_byte_length: usize,
) -> Result<&'a [u8], Lpsy15ScalarMeasurementError> {
    let actual_byte_length = usize::try_from(read_varuint(reader)?)
        .map_err(|_| Lpsy15ScalarMeasurementError::ArithmeticOverflow)?;
    if actual_byte_length != expected_byte_length {
        return Err(Lpsy15ScalarMeasurementError::Encoding);
    }
    reader
        .read_exact(actual_byte_length)
        .map_err(|_| Lpsy15ScalarMeasurementError::Encoding)
}

fn require_bytes(
    reader: &mut CanonicalReader<'_>,
    expected: &[u8],
) -> Result<(), Lpsy15ScalarMeasurementError> {
    if read_bytes(reader, expected.len())? != expected {
        return Err(Lpsy15ScalarMeasurementError::StateMismatch);
    }
    Ok(())
}

fn require_varuint(
    reader: &mut CanonicalReader<'_>,
    expected: u64,
) -> Result<(), Lpsy15ScalarMeasurementError> {
    if read_varuint(reader)? != expected {
        return Err(Lpsy15ScalarMeasurementError::StateMismatch);
    }
    Ok(())
}

#[cfg(all(feature = "lpsy15-scalar-measurement", not(target_arch = "wasm32")))]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct NativeKindResult {
    kind: Lpsy15ScalarMeasurementKind,
    total_operation_count: u64,
    work_batch_operation_count: u64,
    checkpoint_byte_lengths: Vec<usize>,
    #[serde(rename = "checkpointSha3_512Hex")]
    checkpoint_sha3_512_hex: Vec<String>,
    #[serde(rename = "baselineSnapshotSha3_512Hex")]
    baseline_snapshot_sha3_512_hex: String,
    #[serde(rename = "restoredSnapshotSha3_512Hex")]
    restored_snapshot_sha3_512_hex: String,
}

#[cfg(all(feature = "lpsy15-scalar-measurement", not(target_arch = "wasm32")))]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct NativeMeasurementResult {
    schema_version: u64,
    evidence_classification: &'static str,
    field_multiplication_count: u64,
    field_addition_count: u64,
    prf_call_count: u64,
    prf_message_byte_length: u64,
    prf_permutation_count_per_call: u64,
    field_scratch_byte_length: u64,
    results: Vec<NativeKindResult>,
}

#[cfg(all(feature = "lpsy15-scalar-measurement", not(target_arch = "wasm32")))]
pub(crate) fn run_lpsy15_scalar_native_measurement_json() -> Result<String, String> {
    use sha3::{Digest, Sha3_512};

    let counts = Lpsy15ScalarMeasurementCounts::derive().map_err(|error| format!("{error:?}"))?;
    let mut results = Vec::new();
    for kind in [
        Lpsy15ScalarMeasurementKind::PrimeField,
        Lpsy15ScalarMeasurementKind::BmrPrf,
    ] {
        let mut baseline =
            Lpsy15ScalarMeasurementCursor::new(kind).map_err(|error| format!("{error:?}"))?;
        let mut checkpoint_byte_lengths = Vec::new();
        let mut checkpoint_sha3_512_hex = Vec::new();
        let mut captured_checkpoint = None;
        for work_step in 0..SAMPLE_WORK_STEP_COUNT {
            baseline.step().map_err(|error| format!("{error:?}"))?;
            let checkpoint = baseline.checkpoint_bytes();
            checkpoint_byte_lengths.push(checkpoint.len());
            checkpoint_sha3_512_hex.push(lowercase_hex(&Sha3_512::digest(&checkpoint)));
            if work_step + 1 == SAMPLE_WORK_STEP_COUNT / 2 {
                captured_checkpoint = Some(checkpoint.to_vec());
            }
        }
        let baseline_snapshot = baseline.snapshot_bytes();
        let captured_checkpoint = captured_checkpoint.ok_or("native checkpoint missing")?;
        let mut restored = Lpsy15ScalarMeasurementCursor::restore(kind, &captured_checkpoint)
            .map_err(|error| format!("{error:?}"))?;
        for _ in SAMPLE_WORK_STEP_COUNT / 2..SAMPLE_WORK_STEP_COUNT {
            restored.step().map_err(|error| format!("{error:?}"))?;
        }
        let restored_snapshot = restored.snapshot_bytes();
        if baseline_snapshot.as_slice() != restored_snapshot.as_slice() {
            return Err(format!("native {kind:?} restore changed the snapshot"));
        }
        results.push(NativeKindResult {
            kind,
            total_operation_count: counts.total_operation_count(kind),
            work_batch_operation_count: counts.work_batch_operation_count,
            checkpoint_byte_lengths,
            checkpoint_sha3_512_hex,
            baseline_snapshot_sha3_512_hex: lowercase_hex(&Sha3_512::digest(&baseline_snapshot)),
            restored_snapshot_sha3_512_hex: lowercase_hex(&Sha3_512::digest(&restored_snapshot)),
        });
    }
    serde_json::to_string(&NativeMeasurementResult {
        schema_version: 1,
        evidence_classification: "native parity for the LPSY15 scalar development measurement",
        field_multiplication_count: counts.field_multiplication_count,
        field_addition_count: counts.field_addition_count,
        prf_call_count: counts.prf_call_count,
        prf_message_byte_length: counts.prf_message_byte_length,
        prf_permutation_count_per_call: counts.prf_permutation_count_per_call,
        field_scratch_byte_length: counts.field_scratch_byte_length,
        results,
    })
    .map_err(|error| error.to_string())
}

#[cfg(all(feature = "lpsy15-scalar-measurement", not(target_arch = "wasm32")))]
fn lowercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
