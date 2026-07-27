use super::RowCodeWhirConstructionPlan;
#[cfg(test)]
use super::plain_whir::plain_aggregate_pcs;
use super::plain_whir::{
    PlainAggregatePcs, plain_aggregate_encoded_oracle_geometries,
    plain_aggregate_pcs_for_construction_plan,
};
use super::retained_oracle_codec::{
    RETAINED_PLAIN_WHIR_CHALLENGE_FIELD_BYTE_LENGTH, RETAINED_PLAIN_WHIR_ENCODED_ORACLE_WIDTH,
};
use crate::bgv::proof_suite::{
    MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
    external_memory::{
        ProofExternalMemoryObject, ProofExternalMemoryObjectPlan, ProofExternalMemoryPlan,
        ProofExternalMemoryProtection,
    },
};

const RETAINED_PLAIN_WHIR_ENCODED_ORACLE_COUNT: usize = 5;
const RETAINED_ORACLE_READ_PASS_COUNT: u64 = 2;
const EXTERNAL_MEMORY_TRANSACTION_COUNT_PER_LIFECYCLE: u64 = 3;
const MAXIMUM_RETAINED_ORACLE_TRANSACTION_OPERATION_COUNT: u32 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(test)]
pub(in crate::bgv::proof_suite) struct RetainedPlainWhirExternalMemoryAccounting {
    step_count: u32,
    maximum_chunk_byte_length: u32,
    maximum_transaction_payload_byte_length: u64,
    distinct_physical_object_count: u32,
    object_lifecycle_count: u32,
    peak_stored_byte_length: u64,
    total_written_byte_length: u64,
    total_read_byte_length: u64,
    transaction_count: u64,
    local_record_seal_invocation_count: u64,
    local_record_sealed_plaintext_byte_length: u64,
}

#[cfg(test)]
impl RetainedPlainWhirExternalMemoryAccounting {
    fn from_checked_plan(plan: &ProofExternalMemoryPlan) -> Result<Self, String> {
        let secret_seal_custody_requirement = plan
            .secret_seal_custody_requirement()
            .map_err(|error| format!("derive plain WHIR retained-oracle custody: {error:?}"))?;
        Ok(Self {
            step_count: plan.step_count(),
            maximum_chunk_byte_length: plan.maximum_chunk_byte_length(),
            maximum_transaction_payload_byte_length: plan.maximum_transaction_payload_byte_length(),
            distinct_physical_object_count: plan.physical_object_count().map_err(|error| {
                format!("derive plain WHIR retained-oracle physical object count: {error:?}")
            })?,
            object_lifecycle_count: plan.object_lifecycle_count().map_err(|error| {
                format!("derive plain WHIR retained-oracle lifecycle count: {error:?}")
            })?,
            peak_stored_byte_length: plan.maximum_stored_byte_length(),
            total_written_byte_length: plan.maximum_total_written_byte_length(),
            total_read_byte_length: plan.maximum_total_read_byte_length(),
            transaction_count: plan.maximum_transaction_count(),
            local_record_seal_invocation_count: secret_seal_custody_requirement
                .local_record_seal_invocation_count(),
            local_record_sealed_plaintext_byte_length: secret_seal_custody_requirement
                .local_record_sealed_plaintext_byte_length(),
        })
    }

    pub(in crate::bgv::proof_suite) const fn step_count(self) -> u32 {
        self.step_count
    }

    pub(in crate::bgv::proof_suite) const fn maximum_chunk_byte_length(self) -> u32 {
        self.maximum_chunk_byte_length
    }

    pub(in crate::bgv::proof_suite) const fn maximum_transaction_payload_byte_length(self) -> u64 {
        self.maximum_transaction_payload_byte_length
    }

    pub(in crate::bgv::proof_suite) const fn distinct_physical_object_count(self) -> u32 {
        self.distinct_physical_object_count
    }

    pub(in crate::bgv::proof_suite) const fn object_lifecycle_count(self) -> u32 {
        self.object_lifecycle_count
    }

    pub(in crate::bgv::proof_suite) const fn peak_stored_byte_length(self) -> u64 {
        self.peak_stored_byte_length
    }

    pub(in crate::bgv::proof_suite) const fn total_written_byte_length(self) -> u64 {
        self.total_written_byte_length
    }

    pub(in crate::bgv::proof_suite) const fn total_read_byte_length(self) -> u64 {
        self.total_read_byte_length
    }

    pub(in crate::bgv::proof_suite) const fn transaction_count(self) -> u64 {
        self.transaction_count
    }

    pub(in crate::bgv::proof_suite) const fn local_record_seal_invocation_count(self) -> u64 {
        self.local_record_seal_invocation_count
    }

    pub(in crate::bgv::proof_suite) const fn local_record_sealed_plaintext_byte_length(
        self,
    ) -> u64 {
        self.local_record_sealed_plaintext_byte_length
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RetainedPlainWhirEncodedOracle {
    pub(super) object: ProofExternalMemoryObject,
    pub(super) encoded_height: usize,
    pub(super) exact_byte_length: u64,
}

pub(super) struct PlainWhirRetainedEncodedOraclePlan {
    external_memory_plan: ProofExternalMemoryPlan,
    oracles: [RetainedPlainWhirEncodedOracle; RETAINED_PLAIN_WHIR_ENCODED_ORACLE_COUNT],
}

impl PlainWhirRetainedEncodedOraclePlan {
    pub(super) fn try_new(
        pcs: &PlainAggregatePcs,
        first_physical_object_ordinal: u32,
    ) -> Result<Self, String> {
        let geometries = plain_aggregate_encoded_oracle_geometries(pcs)?;
        if geometries.len() != RETAINED_PLAIN_WHIR_ENCODED_ORACLE_COUNT
            || geometries
                .iter()
                .any(|geometry| geometry.width != RETAINED_PLAIN_WHIR_ENCODED_ORACLE_WIDTH)
        {
            return Err("plain WHIR retained-oracle geometry is not selected".to_owned());
        }
        let canonical_field_element_byte_length =
            u64::try_from(RETAINED_PLAIN_WHIR_CHALLENGE_FIELD_BYTE_LENGTH).map_err(|_| {
                "plain WHIR canonical field element byte length overflowed".to_owned()
            })?;
        let canonical_chunk_byte_length =
            u64::from(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH);

        let object_count = u64::try_from(geometries.len())
            .map_err(|_| "plain WHIR retained-oracle object count exceeds u64".to_owned())?;
        let step_count = u32::try_from(
            geometries
                .len()
                .checked_add(1)
                .ok_or_else(|| "plain WHIR retained-oracle step count overflowed".to_owned())?,
        )
        .map_err(|_| "plain WHIR retained-oracle step count exceeds u32".to_owned())?;

        let mut object_plans = Vec::with_capacity(geometries.len());
        let mut oracles = Vec::with_capacity(geometries.len());
        let mut maximum_stored_byte_length = 0_u64;
        let mut previous_object_byte_length = 0_u64;
        let mut total_written_byte_length = 0_u64;
        let mut chunk_count_per_pass = 0_u64;
        for (encoded_oracle_index, geometry) in geometries.into_iter().enumerate() {
            let height = u64::try_from(geometry.height)
                .map_err(|_| "plain WHIR retained-oracle height exceeds u64".to_owned())?;
            let width = u64::try_from(geometry.width)
                .map_err(|_| "plain WHIR retained-oracle width exceeds u64".to_owned())?;
            let exact_byte_length = height
                .checked_mul(width)
                .and_then(|value_count| {
                    value_count.checked_mul(canonical_field_element_byte_length)
                })
                .ok_or_else(|| "plain WHIR retained-oracle byte length overflowed".to_owned())?;
            maximum_stored_byte_length = maximum_stored_byte_length.max(
                previous_object_byte_length
                    .checked_add(exact_byte_length)
                    .ok_or_else(|| {
                        "plain WHIR retained-oracle overlap byte length overflowed".to_owned()
                    })?,
            );
            previous_object_byte_length = exact_byte_length;
            total_written_byte_length = total_written_byte_length
                .checked_add(exact_byte_length)
                .ok_or_else(|| {
                    "plain WHIR retained-oracle written byte length overflowed".to_owned()
                })?;
            chunk_count_per_pass = chunk_count_per_pass
                .checked_add(exact_byte_length.div_ceil(canonical_chunk_byte_length))
                .ok_or_else(|| "plain WHIR retained-oracle chunk count overflowed".to_owned())?;

            let encoded_oracle_offset = u32::try_from(encoded_oracle_index)
                .map_err(|_| "plain WHIR retained-oracle index exceeds u32".to_owned())?;
            let physical_object_ordinal = first_physical_object_ordinal
                .checked_add(encoded_oracle_offset)
                .ok_or_else(|| {
                    "plain WHIR retained-oracle physical object ordinal overflowed".to_owned()
                })?;
            let issued_and_sealed_step = encoded_oracle_offset;
            let last_use_step = issued_and_sealed_step
                .checked_add(1)
                .ok_or_else(|| "plain WHIR retained-oracle last-use step overflowed".to_owned())?;
            let object = ProofExternalMemoryObject::new(physical_object_ordinal);
            object_plans.push(ProofExternalMemoryObjectPlan::new(
                object,
                ProofExternalMemoryProtection::SecretAuthenticatedEncryption,
                exact_byte_length,
                issued_and_sealed_step,
                issued_and_sealed_step,
                last_use_step,
            ));
            oracles.push(RetainedPlainWhirEncodedOracle {
                object,
                encoded_height: geometry.height,
                exact_byte_length,
            });
        }

        let total_read_byte_length = total_written_byte_length
            .checked_mul(RETAINED_ORACLE_READ_PASS_COUNT)
            .ok_or_else(|| "plain WHIR retained-oracle read byte length overflowed".to_owned())?;
        let data_transaction_count = chunk_count_per_pass
            .checked_mul(
                RETAINED_ORACLE_READ_PASS_COUNT
                    .checked_add(1)
                    .ok_or_else(|| "plain WHIR retained-oracle pass count overflowed".to_owned())?,
            )
            .ok_or_else(|| {
                "plain WHIR retained-oracle data transaction count overflowed".to_owned()
            })?;
        let lifecycle_transaction_count = object_count
            .checked_mul(EXTERNAL_MEMORY_TRANSACTION_COUNT_PER_LIFECYCLE)
            .ok_or_else(|| {
                "plain WHIR retained-oracle lifecycle transaction count overflowed".to_owned()
            })?;
        let maximum_transaction_count = data_transaction_count
            .checked_add(lifecycle_transaction_count)
            .ok_or_else(|| "plain WHIR retained-oracle transaction count overflowed".to_owned())?;

        let external_memory_plan = ProofExternalMemoryPlan::new(
            step_count,
            MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
            canonical_chunk_byte_length,
            MAXIMUM_RETAINED_ORACLE_TRANSACTION_OPERATION_COUNT,
            maximum_stored_byte_length,
            total_written_byte_length,
            total_read_byte_length,
            maximum_transaction_count,
            object_plans,
        )
        .map_err(|error| format!("construct plain WHIR retained-oracle plan: {error:?}"))?;
        let oracles = oracles.try_into().map_err(|_| {
            "plain WHIR retained-oracle descriptor count is not selected".to_owned()
        })?;
        Ok(Self {
            external_memory_plan,
            oracles,
        })
    }

    pub(super) fn for_construction_plan(
        construction_plan: &RowCodeWhirConstructionPlan,
        first_physical_object_ordinal: u32,
    ) -> Result<Self, String> {
        let pcs = plain_aggregate_pcs_for_construction_plan(construction_plan)?;
        Self::try_new(&pcs, first_physical_object_ordinal)
    }

    pub(super) fn into_parts(
        self,
    ) -> (
        ProofExternalMemoryPlan,
        [RetainedPlainWhirEncodedOracle; RETAINED_PLAIN_WHIR_ENCODED_ORACLE_COUNT],
    ) {
        (self.external_memory_plan, self.oracles)
    }

    #[cfg(test)]
    pub(super) fn oracle(
        &self,
        encoded_oracle_index: usize,
    ) -> Option<RetainedPlainWhirEncodedOracle> {
        self.oracles.get(encoded_oracle_index).copied()
    }
}

#[cfg(test)]
pub(super) fn selected_plain_whir_retained_oracle_plan(
    first_physical_object_ordinal: u32,
) -> Result<PlainWhirRetainedEncodedOraclePlan, String> {
    let selected_variable_count =
        super::construction_plan::RowCodeWhirSelectedParameters::selected()
            .polynomial_commitment_variable_count;
    let pcs = plain_aggregate_pcs(selected_variable_count)?;
    PlainWhirRetainedEncodedOraclePlan::try_new(&pcs, first_physical_object_ordinal)
}

#[cfg(test)]
fn selected_plain_whir_retained_oracle_external_memory_plan(
    first_physical_object_ordinal: u32,
) -> Result<ProofExternalMemoryPlan, String> {
    selected_plain_whir_retained_oracle_plan(first_physical_object_ordinal)
        .map(|retained_oracle_plan| retained_oracle_plan.into_parts().0)
}

#[cfg(test)]
pub(in crate::bgv::proof_suite) fn selected_plain_whir_retained_oracle_external_memory_accounting(
    first_physical_object_ordinal: u32,
) -> Result<RetainedPlainWhirExternalMemoryAccounting, String> {
    let plan =
        selected_plain_whir_retained_oracle_external_memory_plan(first_physical_object_ordinal)?;
    RetainedPlainWhirExternalMemoryAccounting::from_checked_plan(&plan)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::bgv::proof_suite::external_memory::{
        ProofExternalMemory, ProofExternalMemoryExecutor,
    };

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct StoredObject {
        exact_byte_length: u64,
        written_byte_length: u64,
        is_sealed: bool,
    }

    #[derive(Default)]
    struct AccountingStorage {
        active_transaction: bool,
        active_operation_count: u32,
        maximum_payload_byte_lengths: Vec<u64>,
        maximum_operation_counts: Vec<u32>,
        append_operation_count: u64,
        read_operation_count: u64,
        objects: BTreeMap<ProofExternalMemoryObject, StoredObject>,
        created_objects: Vec<(
            ProofExternalMemoryObject,
            ProofExternalMemoryProtection,
            u64,
        )>,
        deleted_objects: Vec<ProofExternalMemoryObject>,
    }

    impl AccountingStorage {
        fn record_operation(&mut self) -> Result<(), &'static str> {
            if !self.active_transaction {
                return Err("operation is outside a transaction");
            }
            self.active_operation_count = self
                .active_operation_count
                .checked_add(1)
                .ok_or("operation count overflowed")?;
            let maximum_operation_count = self
                .maximum_operation_counts
                .last()
                .copied()
                .ok_or("transaction operation ceiling is missing")?;
            if self.active_operation_count > maximum_operation_count {
                return Err("transaction operation ceiling was exceeded");
            }
            Ok(())
        }
    }

    impl ProofExternalMemory for AccountingStorage {
        type Error = &'static str;

        fn begin_transaction(
            &mut self,
            maximum_payload_byte_length: u64,
            maximum_operation_count: u32,
        ) -> Result<(), Self::Error> {
            if self.active_transaction {
                return Err("transaction is already active");
            }
            self.active_transaction = true;
            self.active_operation_count = 0;
            self.maximum_payload_byte_lengths
                .push(maximum_payload_byte_length);
            self.maximum_operation_counts.push(maximum_operation_count);
            Ok(())
        }

        fn create_object(
            &mut self,
            object: ProofExternalMemoryObject,
            protection: ProofExternalMemoryProtection,
            exact_byte_length: u64,
        ) -> Result<(), Self::Error> {
            self.record_operation()?;
            if self
                .objects
                .insert(
                    object,
                    StoredObject {
                        exact_byte_length,
                        written_byte_length: 0,
                        is_sealed: false,
                    },
                )
                .is_some()
            {
                return Err("object already exists");
            }
            self.created_objects
                .push((object, protection, exact_byte_length));
            Ok(())
        }

        fn append_object_bytes(
            &mut self,
            object: ProofExternalMemoryObject,
            expected_offset: u64,
            bytes: &[u8],
        ) -> Result<(), Self::Error> {
            self.record_operation()?;
            let stored = self.objects.get_mut(&object).ok_or("object is missing")?;
            if stored.is_sealed || stored.written_byte_length != expected_offset {
                return Err("object append state is invalid");
            }
            stored.written_byte_length = stored
                .written_byte_length
                .checked_add(u64::try_from(bytes.len()).map_err(|_| "append length exceeds u64")?)
                .ok_or("object append length overflowed")?;
            if stored.written_byte_length > stored.exact_byte_length {
                return Err("object append exceeded its exact length");
            }
            self.append_operation_count = self
                .append_operation_count
                .checked_add(1)
                .ok_or("append operation count overflowed")?;
            Ok(())
        }

        fn seal_object(&mut self, object: ProofExternalMemoryObject) -> Result<(), Self::Error> {
            self.record_operation()?;
            let stored = self.objects.get_mut(&object).ok_or("object is missing")?;
            if stored.written_byte_length != stored.exact_byte_length || stored.is_sealed {
                return Err("object cannot be sealed");
            }
            stored.is_sealed = true;
            Ok(())
        }

        fn read_object_bytes(
            &mut self,
            object: ProofExternalMemoryObject,
            offset: u64,
            destination: &mut [u8],
        ) -> Result<(), Self::Error> {
            self.record_operation()?;
            let stored = self.objects.get(&object).ok_or("object is missing")?;
            let read_end = offset
                .checked_add(
                    u64::try_from(destination.len()).map_err(|_| "read length exceeds u64")?,
                )
                .ok_or("read end overflowed")?;
            if !stored.is_sealed || read_end > stored.exact_byte_length {
                return Err("object read state is invalid");
            }
            self.read_operation_count = self
                .read_operation_count
                .checked_add(1)
                .ok_or("read operation count overflowed")?;
            Ok(())
        }

        fn delete_object(&mut self, object: ProofExternalMemoryObject) -> Result<(), Self::Error> {
            self.record_operation()?;
            self.objects.remove(&object).ok_or("object is missing")?;
            self.deleted_objects.push(object);
            Ok(())
        }

        fn commit_transaction(&mut self) -> Result<(), Self::Error> {
            if !self.active_transaction || self.active_operation_count == 0 {
                return Err("transaction cannot commit");
            }
            self.active_transaction = false;
            Ok(())
        }

        fn abort_transaction(&mut self) -> Result<(), Self::Error> {
            if !self.active_transaction {
                return Err("transaction is not active");
            }
            self.active_transaction = false;
            Ok(())
        }
    }

    fn selected_retained_oracle_byte_lengths(
        retained_oracle_plan: &PlainWhirRetainedEncodedOraclePlan,
    ) -> Vec<u64> {
        let oracles = (0..RETAINED_PLAIN_WHIR_ENCODED_ORACLE_COUNT)
            .map(|encoded_oracle_index| {
                retained_oracle_plan
                    .oracle(encoded_oracle_index)
                    .expect("the selected encoded-oracle descriptor exists")
            })
            .collect::<Vec<_>>();
        assert_eq!(retained_oracle_plan.oracle(oracles.len()), None);
        assert_eq!(
            oracles
                .iter()
                .map(|oracle| (oracle.object.ordinal(), oracle.encoded_height))
                .collect::<Vec<_>>(),
            [
                (0, 1 << 20),
                (1, 1 << 19),
                (2, 1 << 18),
                (3, 1 << 17),
                (4, 1 << 16),
            ]
        );
        let canonical_field_element_byte_length =
            u64::try_from(RETAINED_PLAIN_WHIR_CHALLENGE_FIELD_BYTE_LENGTH)
                .expect("the canonical challenge field element width fits u64");
        assert_eq!(canonical_field_element_byte_length, 40);
        oracles
            .iter()
            .map(|oracle| {
                u64::try_from(oracle.encoded_height)
                    .expect("the selected height fits u64")
                    .checked_mul(
                        u64::try_from(RETAINED_PLAIN_WHIR_ENCODED_ORACLE_WIDTH)
                            .expect("the selected width fits u64"),
                    )
                    .and_then(|value_count| {
                        value_count.checked_mul(canonical_field_element_byte_length)
                    })
                    .expect("the selected retained-oracle byte length fits u64")
            })
            .collect()
    }

    fn selected_plain_whir_variable_count() -> usize {
        super::super::construction_plan::RowCodeWhirSelectedParameters::selected()
            .polynomial_commitment_variable_count
    }

    #[test]
    fn selected_plan_executes_the_exact_retained_oracle_lifecycles() {
        let retained_oracle_plan = selected_plain_whir_retained_oracle_plan(0)
            .expect("the selected retained-oracle plan is valid");
        let exact_byte_lengths = selected_retained_oracle_byte_lengths(&retained_oracle_plan);
        assert_eq!(
            exact_byte_lengths,
            [
                320 * 1_048_576,
                160 * 1_048_576,
                80 * 1_048_576,
                40 * 1_048_576,
                20 * 1_048_576,
            ]
        );

        let (plan, oracles) = retained_oracle_plan.into_parts();
        assert_eq!(
            oracles
                .iter()
                .map(|oracle| oracle.object.ordinal())
                .collect::<Vec<_>>(),
            [0, 1, 2, 3, 4]
        );
        assert_eq!(plan.step_count(), 6);
        assert_eq!(plan.physical_object_count(), Ok(5));
        assert_eq!(plan.object_lifecycle_count(), Ok(5));
        assert_eq!(plan.maximum_transaction_operation_count(), 2);

        let mut executor = ProofExternalMemoryExecutor::new(plan);
        assert_eq!(
            executor.maximum_chunk_byte_length(),
            MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH
        );
        let chunk_byte_length = usize::try_from(executor.maximum_chunk_byte_length())
            .expect("the canonical chunk length fits usize");
        let chunk = vec![0_u8; chunk_byte_length];
        let mut read_destination = vec![0_u8; chunk_byte_length];
        let mut storage = AccountingStorage::default();

        for step in 0..6_u32 {
            if let Some(exact_byte_length) = exact_byte_lengths.get(step as usize).copied() {
                let object = oracles[step as usize].object;
                executor
                    .begin_object(&mut storage, object)
                    .expect("begin the retained encoded-oracle object");
                for _ in 0..exact_byte_length.div_ceil(u64::from(
                    MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
                )) {
                    executor
                        .append_object_bytes(&mut storage, object, &chunk)
                        .expect("append one canonical retained-oracle chunk");
                }
                executor
                    .seal_object(&mut storage, object)
                    .expect("seal the retained encoded-oracle object");
                for offset in (0..exact_byte_length).step_by(chunk_byte_length) {
                    executor
                        .read_object_bytes(&mut storage, object, offset, &mut read_destination)
                        .expect("scan one root-building encoded-oracle chunk");
                }
            }

            if step > 0 {
                let object = oracles[(step - 1) as usize].object;
                let exact_byte_length = exact_byte_lengths[(step - 1) as usize];
                for offset in (0..exact_byte_length).step_by(chunk_byte_length) {
                    executor
                        .read_object_bytes(&mut storage, object, offset, &mut read_destination)
                        .expect("scan one opening encoded-oracle chunk");
                }
            }

            executor
                .complete_step(&mut storage)
                .expect("complete the retained-oracle liveness step");
            assert_eq!(
                storage.deleted_objects,
                (0..step)
                    .map(ProofExternalMemoryObject::new)
                    .collect::<Vec<_>>()
            );
        }

        let usage = executor
            .finish()
            .expect("the retained-oracle executor completed");
        assert_eq!(usage.peak_stored_byte_length(), 503_316_480);
        assert_eq!(usage.total_written_byte_length(), 650_117_120);
        assert_eq!(usage.total_read_byte_length(), 1_300_234_240);
        assert_eq!(usage.transaction_count(), 1_875);
        assert_eq!(usage.deleted_object_count(), 5);
        assert_eq!(storage.append_operation_count, 620);
        assert_eq!(storage.read_operation_count, 1_240);
        assert!(storage.objects.is_empty());
        assert_eq!(
            storage.created_objects,
            exact_byte_lengths
                .iter()
                .copied()
                .enumerate()
                .map(|(object_ordinal, exact_byte_length)| (
                    ProofExternalMemoryObject::new(
                        u32::try_from(object_ordinal).expect("the object ordinal fits u32"),
                    ),
                    ProofExternalMemoryProtection::SecretAuthenticatedEncryption,
                    exact_byte_length,
                ))
                .collect::<Vec<_>>()
        );
        assert!(
            storage
                .maximum_payload_byte_lengths
                .iter()
                .all(|byte_length| {
                    *byte_length
                        == u64::from(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH)
                })
        );
        assert!(
            storage
                .maximum_operation_counts
                .iter()
                .all(|operation_count| *operation_count == 2)
        );
        assert_eq!(storage.maximum_operation_counts.len(), 1_875);
    }

    #[test]
    fn plan_uses_checked_noncolliding_physical_object_ordinals() {
        let selected_pcs = plain_aggregate_pcs(selected_plain_whir_variable_count())
            .expect("the selected plain WHIR PCS is valid");
        let first_physical_object_ordinal = 91_u32;
        let retained_oracle_plan = PlainWhirRetainedEncodedOraclePlan::try_new(
            &selected_pcs,
            first_physical_object_ordinal,
        )
        .expect("the nonzero retained-oracle object range is valid");
        assert_eq!(
            (0..RETAINED_PLAIN_WHIR_ENCODED_ORACLE_COUNT)
                .map(|encoded_oracle_index| {
                    retained_oracle_plan
                        .oracle(encoded_oracle_index)
                        .expect("the retained-oracle descriptor exists")
                        .object
                        .ordinal()
                })
                .collect::<Vec<_>>(),
            [91, 92, 93, 94, 95]
        );

        let exact_boundary_plan =
            PlainWhirRetainedEncodedOraclePlan::try_new(&selected_pcs, u32::MAX - 4)
                .expect("five consecutive ordinals ending at u32::MAX are representable");
        assert_eq!(
            (0..RETAINED_PLAIN_WHIR_ENCODED_ORACLE_COUNT)
                .map(|encoded_oracle_index| {
                    exact_boundary_plan
                        .oracle(encoded_oracle_index)
                        .expect("the exact-boundary descriptor exists")
                        .object
                        .ordinal()
                })
                .collect::<Vec<_>>(),
            [
                u32::MAX - 4,
                u32::MAX - 3,
                u32::MAX - 2,
                u32::MAX - 1,
                u32::MAX
            ]
        );
        assert_eq!(
            PlainWhirRetainedEncodedOraclePlan::try_new(&selected_pcs, u32::MAX - 3)
                .err()
                .as_deref(),
            Some("plain WHIR retained-oracle physical object ordinal overflowed")
        );
    }

    #[test]
    fn plan_refuses_a_nonselected_folding_width() {
        let alternate_pcs = super::super::plain_whir::plain_aggregate_pcs_with_parameters(
            selected_plain_whir_variable_count(),
            2,
            4,
        )
        .expect("the alternate plain WHIR PCS is valid");
        let alternate_geometries = plain_aggregate_encoded_oracle_geometries(&alternate_pcs)
            .expect("derive the alternate encoded-oracle geometries");
        assert!(
            alternate_geometries
                .iter()
                .all(|geometry| geometry.width == 16)
        );
        assert_eq!(
            PlainWhirRetainedEncodedOraclePlan::try_new(&alternate_pcs, 0,)
                .err()
                .as_deref(),
            Some("plain WHIR retained-oracle geometry is not selected")
        );
    }

    #[test]
    fn selected_accounting_snapshot_matches_the_checked_plan_and_secret_custody() {
        let accounting = selected_plain_whir_retained_oracle_external_memory_accounting(0)
            .expect("the selected retained-oracle accounting is valid");
        assert_eq!(accounting.step_count(), 6);
        assert_eq!(accounting.maximum_chunk_byte_length(), 1_048_576);
        assert_eq!(
            accounting.maximum_transaction_payload_byte_length(),
            1_048_576
        );
        assert_eq!(accounting.distinct_physical_object_count(), 5);
        assert_eq!(accounting.object_lifecycle_count(), 5);
        assert_eq!(accounting.peak_stored_byte_length(), 503_316_480);
        assert_eq!(accounting.total_written_byte_length(), 650_117_120);
        assert_eq!(accounting.total_read_byte_length(), 1_300_234_240);
        assert_eq!(accounting.transaction_count(), 1_875);
        assert_eq!(accounting.local_record_seal_invocation_count(), 630);
        assert_eq!(
            accounting.local_record_sealed_plaintext_byte_length(),
            650_117_165
        );
    }
}
