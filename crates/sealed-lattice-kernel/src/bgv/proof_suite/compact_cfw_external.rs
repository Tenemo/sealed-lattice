//! Validated external-memory plan for the compact CFW matrix lifecycle.
//!
//! Round zero writes the three first folds from the structured row source.
//! Every later round reads the current matrices once for the round polynomial,
//! then rolls one matrix at a time after the challenge. Distinct last-use steps
//! let the external-memory executor delete one old object before the next new
//! object becomes live, keeping the exact peak at four objects. Final
//! length-one checkpoint objects are deleted in three dedicated cleanup steps.

use std::collections::BTreeSet;

use super::compact_cfw::{
    COMPACT_CFW_MATRIX_COUNT, CompactCfwError, CompactCfwGeometry, CompactCfwMatrixRole,
};
use super::external_memory::{
    ProofExternalMemoryError, ProofExternalMemoryObject, ProofExternalMemoryObjectPlan,
    ProofExternalMemoryPlan, ProofExternalMemoryProtection,
};
use super::external_polynomial::{ExternalPolynomialError, ExternalPolynomialVector};
use super::relation_plan::RelationColumnValueType;
use super::{
    MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH, PROOF_CHALLENGE_EXTENSION_DEGREE,
};

const COMPACT_CFW_STREAM_CHUNK_ELEMENT_COUNT: u64 = 16_384;
const COMPACT_CFW_EXTENSION_ELEMENT_BYTE_LENGTH: u64 = PROOF_CHALLENGE_EXTENSION_DEGREE as u64 * 8;
const COMPACT_CFW_STREAM_CHUNK_BYTE_LENGTH: u64 =
    COMPACT_CFW_STREAM_CHUNK_ELEMENT_COUNT * COMPACT_CFW_EXTENSION_ELEMENT_BYTE_LENGTH;
const COMPACT_CFW_FINAL_CLEANUP_STEP_COUNT: u32 = COMPACT_CFW_MATRIX_COUNT as u32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactCfwExternalPlanError {
    InvalidGeometry,
    CountOverflow,
    ExternalMemory(ProofExternalMemoryError),
    ExternalPolynomial(ExternalPolynomialError),
}

impl From<ProofExternalMemoryError> for CompactCfwExternalPlanError {
    fn from(error: ProofExternalMemoryError) -> Self {
        Self::ExternalMemory(error)
    }
}

impl From<ExternalPolynomialError> for CompactCfwExternalPlanError {
    fn from(error: ExternalPolynomialError) -> Self {
        Self::ExternalPolynomial(error)
    }
}

impl From<CompactCfwError> for CompactCfwExternalPlanError {
    fn from(_error: CompactCfwError) -> Self {
        Self::InvalidGeometry
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactCfwExternalStorageCatalog {
    geometry: CompactCfwGeometry,
    plan: ProofExternalMemoryPlan,
    round_vectors: Vec<[ExternalPolynomialVector; COMPACT_CFW_MATRIX_COUNT]>,
    round_output_steps: Vec<[u32; COMPACT_CFW_MATRIX_COUNT]>,
    step_count: u32,
    object_lifecycle_count: u64,
    maximum_active_object_count: u64,
    append_transaction_count: u64,
    read_transaction_count: u64,
    delete_transaction_count: u64,
    total_transaction_count: u64,
    written_extension_element_count: u64,
    read_extension_element_count: u64,
    total_written_byte_length: u64,
    total_read_byte_length: u64,
    peak_stored_byte_length: u64,
    executor_resident_owned_payload_byte_length: u64,
    secret_seal_invocation_count: u64,
    secret_sealed_plaintext_byte_length: u64,
}

impl CompactCfwExternalStorageCatalog {
    pub(crate) fn derive(
        geometry: CompactCfwGeometry,
    ) -> Result<Self, CompactCfwExternalPlanError> {
        let catalog = Self::derive_without_check(geometry)?;
        catalog.check(geometry)?;
        Ok(catalog)
    }

    fn derive_without_check(
        geometry: CompactCfwGeometry,
    ) -> Result<Self, CompactCfwExternalPlanError> {
        if COMPACT_CFW_STREAM_CHUNK_BYTE_LENGTH
            > u64::from(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH)
        {
            return Err(CompactCfwExternalPlanError::InvalidGeometry);
        }
        let round_count = geometry.sumcheck_round_count();
        if round_count == 0 {
            return Err(CompactCfwExternalPlanError::InvalidGeometry);
        }
        let round_count_u32 =
            u32::try_from(round_count).map_err(|_| CompactCfwExternalPlanError::CountOverflow)?;
        let final_output_step = if round_count == 1 {
            0
        } else {
            round_count_u32
                .checked_mul(COMPACT_CFW_MATRIX_COUNT as u32)
                .and_then(|step| step.checked_sub(COMPACT_CFW_MATRIX_COUNT as u32))
                .ok_or(CompactCfwExternalPlanError::CountOverflow)?
        };
        let step_count = final_output_step
            .checked_add(1)
            .and_then(|count| count.checked_add(COMPACT_CFW_FINAL_CLEANUP_STEP_COUNT))
            .ok_or(CompactCfwExternalPlanError::CountOverflow)?;

        let object_lifecycle_count = u64::try_from(round_count)
            .map_err(|_| CompactCfwExternalPlanError::CountOverflow)?
            .checked_mul(COMPACT_CFW_MATRIX_COUNT as u64)
            .ok_or(CompactCfwExternalPlanError::CountOverflow)?;
        let mut object_plans = Vec::new();
        object_plans
            .try_reserve_exact(
                usize::try_from(object_lifecycle_count)
                    .map_err(|_| CompactCfwExternalPlanError::CountOverflow)?,
            )
            .map_err(|_| CompactCfwExternalPlanError::CountOverflow)?;
        let mut round_vectors = Vec::new();
        round_vectors
            .try_reserve_exact(round_count)
            .map_err(|_| CompactCfwExternalPlanError::CountOverflow)?;
        let mut round_output_steps = Vec::new();
        round_output_steps
            .try_reserve_exact(round_count)
            .map_err(|_| CompactCfwExternalPlanError::CountOverflow)?;

        let mut append_transaction_count = 0_u64;
        let mut read_transaction_count = 0_u64;
        let mut written_extension_element_count = 0_u64;
        let mut read_extension_element_count = 0_u64;
        for round_ordinal in 0..round_count {
            let output_element_count = geometry
                .r1cs_row_count()
                .checked_shr(
                    u32::try_from(round_ordinal + 1)
                        .map_err(|_| CompactCfwExternalPlanError::CountOverflow)?,
                )
                .ok_or(CompactCfwExternalPlanError::InvalidGeometry)?;
            if output_element_count == 0 {
                return Err(CompactCfwExternalPlanError::InvalidGeometry);
            }
            let output_element_count_u64 = u64::try_from(output_element_count)
                .map_err(|_| CompactCfwExternalPlanError::CountOverflow)?;
            let exact_byte_length = output_element_count_u64
                .checked_mul(COMPACT_CFW_EXTENSION_ELEMENT_BYTE_LENGTH)
                .ok_or(CompactCfwExternalPlanError::CountOverflow)?;
            let append_count = exact_byte_length.div_ceil(COMPACT_CFW_STREAM_CHUNK_BYTE_LENGTH);
            append_transaction_count = append_transaction_count
                .checked_add(
                    append_count
                        .checked_mul(COMPACT_CFW_MATRIX_COUNT as u64)
                        .ok_or(CompactCfwExternalPlanError::CountOverflow)?,
                )
                .ok_or(CompactCfwExternalPlanError::CountOverflow)?;
            written_extension_element_count = written_extension_element_count
                .checked_add(
                    output_element_count_u64
                        .checked_mul(COMPACT_CFW_MATRIX_COUNT as u64)
                        .ok_or(CompactCfwExternalPlanError::CountOverflow)?,
                )
                .ok_or(CompactCfwExternalPlanError::CountOverflow)?;
            if round_ordinal + 1 < round_count {
                read_transaction_count = read_transaction_count
                    .checked_add(
                        append_count
                            .checked_mul(2)
                            .and_then(|count| count.checked_mul(COMPACT_CFW_MATRIX_COUNT as u64))
                            .ok_or(CompactCfwExternalPlanError::CountOverflow)?,
                    )
                    .ok_or(CompactCfwExternalPlanError::CountOverflow)?;
                read_extension_element_count = read_extension_element_count
                    .checked_add(
                        output_element_count_u64
                            .checked_mul(2)
                            .and_then(|count| count.checked_mul(COMPACT_CFW_MATRIX_COUNT as u64))
                            .ok_or(CompactCfwExternalPlanError::CountOverflow)?,
                    )
                    .ok_or(CompactCfwExternalPlanError::CountOverflow)?;
            }

            let mut output_steps = [0_u32; COMPACT_CFW_MATRIX_COUNT];
            for (matrix_ordinal, output_step) in output_steps.iter_mut().enumerate() {
                *output_step = compact_cfw_round_output_step(round_ordinal, matrix_ordinal)?;
            }
            let mut vectors = [ExternalPolynomialVector::new(
                ProofExternalMemoryObject::new(0),
                RelationColumnValueType::ChallengeExtension,
                1,
            )?; COMPACT_CFW_MATRIX_COUNT];
            for matrix_role in CompactCfwMatrixRole::ALL {
                let matrix_ordinal = matrix_role.ordinal();
                let object_ordinal = round_ordinal
                    .checked_mul(COMPACT_CFW_MATRIX_COUNT)
                    .and_then(|ordinal| ordinal.checked_add(matrix_ordinal))
                    .ok_or(CompactCfwExternalPlanError::CountOverflow)?;
                let object = ProofExternalMemoryObject::new(
                    u32::try_from(object_ordinal)
                        .map_err(|_| CompactCfwExternalPlanError::CountOverflow)?,
                );
                let issued_step = output_steps[matrix_ordinal];
                let last_use_step = if round_ordinal + 1 < round_count {
                    compact_cfw_round_output_step(round_ordinal + 1, matrix_ordinal)?
                } else {
                    let matrix_ordinal_u32 = u32::try_from(matrix_ordinal)
                        .map_err(|_| CompactCfwExternalPlanError::CountOverflow)?;
                    final_output_step
                        .checked_add(1)
                        .and_then(|step| step.checked_add(matrix_ordinal_u32))
                        .ok_or(CompactCfwExternalPlanError::CountOverflow)?
                };
                object_plans.push(
                    ProofExternalMemoryObjectPlan::new_with_maximum_append_count(
                        object,
                        ProofExternalMemoryProtection::SecretAuthenticatedEncryption,
                        exact_byte_length,
                        append_count,
                        issued_step,
                        issued_step,
                        last_use_step,
                    ),
                );
                vectors[matrix_ordinal] = ExternalPolynomialVector::new(
                    object,
                    RelationColumnValueType::ChallengeExtension,
                    output_element_count,
                )?;
            }
            round_vectors.push(vectors);
            round_output_steps.push(output_steps);
        }

        let delete_transaction_count = object_lifecycle_count;
        let total_transaction_count = object_lifecycle_count
            .checked_mul(2)
            .and_then(|count| count.checked_add(delete_transaction_count))
            .and_then(|count| count.checked_add(append_transaction_count))
            .and_then(|count| count.checked_add(read_transaction_count))
            .ok_or(CompactCfwExternalPlanError::CountOverflow)?;
        let total_written_byte_length = written_extension_element_count
            .checked_mul(COMPACT_CFW_EXTENSION_ELEMENT_BYTE_LENGTH)
            .ok_or(CompactCfwExternalPlanError::CountOverflow)?;
        let total_read_byte_length = read_extension_element_count
            .checked_mul(COMPACT_CFW_EXTENSION_ELEMENT_BYTE_LENGTH)
            .ok_or(CompactCfwExternalPlanError::CountOverflow)?;
        let (maximum_active_object_count, peak_stored_byte_length) =
            maximum_external_liveness(&object_plans)?;
        let plan = ProofExternalMemoryPlan::new(
            step_count,
            u32::try_from(COMPACT_CFW_STREAM_CHUNK_BYTE_LENGTH)
                .map_err(|_| CompactCfwExternalPlanError::CountOverflow)?,
            COMPACT_CFW_STREAM_CHUNK_BYTE_LENGTH,
            1,
            peak_stored_byte_length,
            total_written_byte_length,
            total_read_byte_length.max(1),
            total_transaction_count,
            object_plans,
        )?;
        let executor_resident_owned_payload_byte_length =
            plan.executor_resident_owned_payload_byte_length()?;
        let secret_seal_custody = plan.secret_seal_custody_requirement()?;

        Ok(Self {
            geometry,
            plan,
            round_vectors,
            round_output_steps,
            step_count,
            object_lifecycle_count,
            maximum_active_object_count,
            append_transaction_count,
            read_transaction_count,
            delete_transaction_count,
            total_transaction_count,
            written_extension_element_count,
            read_extension_element_count,
            total_written_byte_length,
            total_read_byte_length,
            peak_stored_byte_length,
            executor_resident_owned_payload_byte_length,
            secret_seal_invocation_count: secret_seal_custody.local_record_seal_invocation_count(),
            secret_sealed_plaintext_byte_length: secret_seal_custody
                .local_record_sealed_plaintext_byte_length(),
        })
    }

    fn check(&self, geometry: CompactCfwGeometry) -> Result<(), CompactCfwExternalPlanError> {
        let expected = Self::derive_without_check(geometry)?;
        let distinct_last_use_step_count = self
            .plan
            .clone()
            .into_object_plans()
            .into_iter()
            .map(ProofExternalMemoryObjectPlan::last_use_step)
            .collect::<BTreeSet<_>>()
            .len();
        if self != &expected
            || self.geometry != geometry
            || self.round_vectors.len() != geometry.sumcheck_round_count()
            || self.round_output_steps.len() != geometry.sumcheck_round_count()
            || u64::try_from(distinct_last_use_step_count)
                .map_err(|_| CompactCfwExternalPlanError::CountOverflow)?
                != self.object_lifecycle_count
            || self.plan.physical_object_count()? as u64 != self.object_lifecycle_count
            || self.plan.object_lifecycle_count()? as u64 != self.object_lifecycle_count
            || self.plan.step_count() != self.step_count
            || u64::from(self.plan.maximum_chunk_byte_length())
                != COMPACT_CFW_STREAM_CHUNK_BYTE_LENGTH
            || self.plan.maximum_transaction_payload_byte_length()
                != COMPACT_CFW_STREAM_CHUNK_BYTE_LENGTH
            || self.plan.maximum_stored_byte_length() != self.peak_stored_byte_length
            || self.plan.maximum_total_written_byte_length() != self.total_written_byte_length
            || self.plan.maximum_total_read_byte_length() != self.total_read_byte_length.max(1)
            || self.plan.maximum_transaction_count() != self.total_transaction_count
        {
            return Err(CompactCfwExternalPlanError::InvalidGeometry);
        }
        Ok(())
    }

    pub(crate) const fn step_count(&self) -> u32 {
        self.step_count
    }

    pub(crate) const fn object_lifecycle_count(&self) -> u64 {
        self.object_lifecycle_count
    }

    pub(crate) const fn maximum_active_object_count(&self) -> u64 {
        self.maximum_active_object_count
    }

    pub(crate) const fn append_transaction_count(&self) -> u64 {
        self.append_transaction_count
    }

    pub(crate) const fn read_transaction_count(&self) -> u64 {
        self.read_transaction_count
    }

    pub(crate) const fn delete_transaction_count(&self) -> u64 {
        self.delete_transaction_count
    }

    pub(crate) const fn total_transaction_count(&self) -> u64 {
        self.total_transaction_count
    }

    pub(crate) const fn written_extension_element_count(&self) -> u64 {
        self.written_extension_element_count
    }

    pub(crate) const fn read_extension_element_count(&self) -> u64 {
        self.read_extension_element_count
    }

    pub(crate) const fn total_written_byte_length(&self) -> u64 {
        self.total_written_byte_length
    }

    pub(crate) const fn total_read_byte_length(&self) -> u64 {
        self.total_read_byte_length
    }

    pub(crate) const fn peak_stored_byte_length(&self) -> u64 {
        self.peak_stored_byte_length
    }

    pub(crate) const fn executor_resident_owned_payload_byte_length(&self) -> u64 {
        self.executor_resident_owned_payload_byte_length
    }

    pub(crate) const fn maximum_chunk_byte_length(&self) -> u32 {
        self.plan.maximum_chunk_byte_length()
    }

    pub(crate) fn runtime_index_resident_owned_payload_byte_length(
        &self,
    ) -> Result<u64, CompactCfwExternalPlanError> {
        let round_vector_byte_length = checked_capacity_byte_length::<
            [ExternalPolynomialVector; COMPACT_CFW_MATRIX_COUNT],
        >(self.round_vectors.capacity())?;
        let round_output_step_byte_length = checked_capacity_byte_length::<
            [u32; COMPACT_CFW_MATRIX_COUNT],
        >(self.round_output_steps.capacity())?;
        round_vector_byte_length
            .checked_add(round_output_step_byte_length)
            .ok_or(CompactCfwExternalPlanError::CountOverflow)
    }

    pub(crate) const fn secret_seal_invocation_count(&self) -> u64 {
        self.secret_seal_invocation_count
    }

    pub(crate) const fn secret_sealed_plaintext_byte_length(&self) -> u64 {
        self.secret_sealed_plaintext_byte_length
    }

    pub(crate) fn round_vectors(&self) -> &[[ExternalPolynomialVector; COMPACT_CFW_MATRIX_COUNT]] {
        &self.round_vectors
    }

    pub(crate) fn round_output_steps(&self) -> &[[u32; COMPACT_CFW_MATRIX_COUNT]] {
        &self.round_output_steps
    }

    pub(crate) fn into_runtime_parts(
        self,
    ) -> (
        ProofExternalMemoryPlan,
        Vec<[ExternalPolynomialVector; COMPACT_CFW_MATRIX_COUNT]>,
        Vec<[u32; COMPACT_CFW_MATRIX_COUNT]>,
        u32,
    ) {
        (
            self.plan,
            self.round_vectors,
            self.round_output_steps,
            self.step_count,
        )
    }

    #[cfg(test)]
    fn into_plan(self) -> ProofExternalMemoryPlan {
        self.plan
    }
}

fn checked_capacity_byte_length<Element>(
    capacity: usize,
) -> Result<u64, CompactCfwExternalPlanError> {
    u64::try_from(capacity)
        .ok()
        .and_then(|count| {
            u64::try_from(core::mem::size_of::<Element>())
                .ok()
                .and_then(|element_byte_length| count.checked_mul(element_byte_length))
        })
        .ok_or(CompactCfwExternalPlanError::CountOverflow)
}

fn compact_cfw_round_output_step(
    round_ordinal: usize,
    matrix_ordinal: usize,
) -> Result<u32, CompactCfwExternalPlanError> {
    if matrix_ordinal >= COMPACT_CFW_MATRIX_COUNT {
        return Err(CompactCfwExternalPlanError::InvalidGeometry);
    }
    if round_ordinal == 0 {
        return Ok(0);
    }
    let preceding_round_count =
        u32::try_from(round_ordinal - 1).map_err(|_| CompactCfwExternalPlanError::CountOverflow)?;
    let matrix_ordinal =
        u32::try_from(matrix_ordinal).map_err(|_| CompactCfwExternalPlanError::CountOverflow)?;
    preceding_round_count
        .checked_mul(COMPACT_CFW_MATRIX_COUNT as u32)
        .and_then(|step| step.checked_add(1))
        .and_then(|step| step.checked_add(matrix_ordinal))
        .ok_or(CompactCfwExternalPlanError::CountOverflow)
}

fn maximum_external_liveness(
    object_plans: &[ProofExternalMemoryObjectPlan],
) -> Result<(u64, u64), CompactCfwExternalPlanError> {
    let mut events = Vec::new();
    events
        .try_reserve_exact(
            object_plans
                .len()
                .checked_mul(2)
                .ok_or(CompactCfwExternalPlanError::CountOverflow)?,
        )
        .map_err(|_| CompactCfwExternalPlanError::CountOverflow)?;
    for object in object_plans {
        events.push((object.issued_step(), true, object.exact_byte_length()));
        events.push((
            object
                .last_use_step()
                .checked_add(1)
                .ok_or(CompactCfwExternalPlanError::CountOverflow)?,
            false,
            object.exact_byte_length(),
        ));
    }
    events.sort_unstable_by_key(|(step, is_issuance, _)| (*step, *is_issuance));
    let mut active_object_count = 0_u64;
    let mut stored_byte_length = 0_u64;
    let mut maximum_active_object_count = 0_u64;
    let mut peak_stored_byte_length = 0_u64;
    for (_, is_issuance, exact_byte_length) in events {
        if is_issuance {
            active_object_count = active_object_count
                .checked_add(1)
                .ok_or(CompactCfwExternalPlanError::CountOverflow)?;
            stored_byte_length = stored_byte_length
                .checked_add(exact_byte_length)
                .ok_or(CompactCfwExternalPlanError::CountOverflow)?;
            maximum_active_object_count = maximum_active_object_count.max(active_object_count);
            peak_stored_byte_length = peak_stored_byte_length.max(stored_byte_length);
        } else {
            active_object_count = active_object_count
                .checked_sub(1)
                .ok_or(CompactCfwExternalPlanError::InvalidGeometry)?;
            stored_byte_length = stored_byte_length
                .checked_sub(exact_byte_length)
                .ok_or(CompactCfwExternalPlanError::InvalidGeometry)?;
        }
    }
    if active_object_count != 0 || stored_byte_length != 0 {
        return Err(CompactCfwExternalPlanError::InvalidGeometry);
    }
    Ok((maximum_active_object_count, peak_stored_byte_length))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_cfw_external_plan_matches_the_complete_lifecycle_ledger() {
        let geometry = CompactCfwGeometry::derive(1 << 22).expect("selected CFW geometry");
        let catalog = CompactCfwExternalStorageCatalog::derive(geometry)
            .expect("validated selected external-memory plan");

        assert_eq!(catalog.step_count(), 70);
        assert_eq!(catalog.object_lifecycle_count(), 69);
        assert_eq!(catalog.maximum_active_object_count(), 4);
        assert_eq!(catalog.append_transaction_count(), 1_575);
        assert_eq!(catalog.read_transaction_count(), 3_144);
        assert_eq!(catalog.delete_transaction_count(), 69);
        assert_eq!(catalog.total_transaction_count(), 4_926);
        assert_eq!(catalog.written_extension_element_count(), 25_165_821);
        assert_eq!(catalog.read_extension_element_count(), 50_331_636);
        assert_eq!(catalog.total_written_byte_length(), 1_006_632_840);
        assert_eq!(catalog.total_read_byte_length(), 2_013_265_440);
        assert_eq!(catalog.peak_stored_byte_length(), 587_202_560);
        assert_eq!(catalog.executor_resident_owned_payload_byte_length(), 4_416);
        assert_eq!(catalog.secret_seal_invocation_count(), 1_713);
        assert_eq!(catalog.secret_sealed_plaintext_byte_length(), 1_006_633_461);
        assert_eq!(catalog.round_vectors().len(), 23);
        assert_eq!(catalog.round_vectors()[0][0].element_count(), 4_194_304);
        assert_eq!(catalog.round_vectors()[22][2].element_count(), 1);
        assert_eq!(catalog.round_output_steps()[0], [0, 0, 0]);
        assert_eq!(catalog.round_output_steps()[1], [1, 2, 3]);
        assert_eq!(catalog.round_output_steps()[22], [64, 65, 66]);

        let plan = catalog.into_plan();
        assert_eq!(plan.physical_object_count(), Ok(69));
        assert_eq!(plan.object_lifecycle_count(), Ok(69));
        let seal_custody = plan
            .secret_seal_custody_requirement()
            .expect("selected secret-storage custody");
        assert_eq!(seal_custody.local_record_seal_invocation_count(), 1_713);
        assert_eq!(
            seal_custody.local_record_sealed_plaintext_byte_length(),
            1_006_633_461
        );
    }

    #[test]
    fn cfw_external_plan_preserves_four_object_liveness_across_geometries() {
        for witness_logarithm in 1..=8 {
            let witness_length = 1_usize << witness_logarithm;
            let geometry =
                CompactCfwGeometry::derive(witness_length).expect("power-of-two CFW geometry");
            let catalog = CompactCfwExternalStorageCatalog::derive(geometry)
                .expect("validated compact external-memory plan");
            assert_eq!(
                catalog.object_lifecycle_count(),
                u64::try_from(geometry.sumcheck_round_count()).expect("round count") * 3
            );
            assert!(catalog.maximum_active_object_count() <= 4);
            assert_eq!(
                catalog.delete_transaction_count(),
                catalog.object_lifecycle_count()
            );
            assert_eq!(
                catalog.round_vectors().last().expect("final round")[0].element_count(),
                1
            );
            assert_eq!(
                catalog.step_count(),
                u32::try_from(geometry.sumcheck_round_count())
                    .expect("round count")
                    .checked_mul(3)
                    .and_then(|count| count.checked_add(1))
                    .expect("step count")
            );
        }
    }
}
