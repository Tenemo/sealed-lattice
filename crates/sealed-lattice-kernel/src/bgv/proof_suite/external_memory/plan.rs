use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use zeroize::Zeroizing;

use crate::foundation::{
    MAXIMUM_LOCAL_RECORD_SEAL_INVOCATIONS_PER_ACTIVE_ROOT,
    MAXIMUM_LOCAL_RECORD_SEALED_PLAINTEXT_BYTES_PER_ACTIVE_ROOT,
};

use super::super::MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH;
use super::{
    MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_OBJECT_COUNT,
    MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH, executor::ProofExternalMemoryError,
};

const COMMON_PROOF_EXTERNAL_MEMORY_OBJECT_HEADER_PLAINTEXT_BYTE_LENGTH: u64 =
    1 + core::mem::size_of::<u64>() as u64;
const COMMON_PROOF_EXTERNAL_MEMORY_SECRET_FIXED_RECORD_COUNT: u64 = 2;

/// One plan-local external-memory object.  The surrounding proof transaction
/// supplies the unguessable lease and transaction identifiers; this ordinal is
/// only an address inside that already-authorized namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ProofExternalMemoryObject(u32);

impl ProofExternalMemoryObject {
    pub(crate) const fn new(ordinal: u32) -> Self {
        Self(ordinal)
    }

    pub(crate) const fn ordinal(self) -> u32 {
        self.0
    }
}

/// Protection the transaction substrate must apply while bytes are outside
/// the proof worker.  Secret scratch is never written through the public path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProofExternalMemoryProtection {
    PublicIntegrity,
    SecretAuthenticatedEncryption,
}

/// Active-root local-record custody consumed by secret external-memory object
/// lifecycles. The browser writes one nine-byte object header, at most the
/// planned number of bounded data-chunk records, and one empty seal-marker
/// record for each lifecycle. Public-integrity records never enter the
/// local-record sealing path.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ProofExternalMemorySecretSealCustodyRequirement {
    local_record_seal_invocation_count: u64,
    local_record_sealed_plaintext_byte_length: u64,
}

impl ProofExternalMemorySecretSealCustodyRequirement {
    #[cfg(test)]
    pub(crate) fn for_object_lifecycle(
        protection: ProofExternalMemoryProtection,
        exact_byte_length: u64,
    ) -> Result<Self, ProofExternalMemoryError> {
        let maximum_append_count = exact_byte_length.div_ceil(u64::from(
            MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
        ));
        Self::for_object_lifecycle_with_append_count(
            protection,
            exact_byte_length,
            maximum_append_count,
        )
    }

    fn for_object_lifecycle_with_append_count(
        protection: ProofExternalMemoryProtection,
        exact_byte_length: u64,
        maximum_append_count: u64,
    ) -> Result<Self, ProofExternalMemoryError> {
        if exact_byte_length == 0 {
            return Err(ProofExternalMemoryError::InvalidPlan);
        }
        if protection == ProofExternalMemoryProtection::PublicIntegrity {
            return Ok(Self::default());
        }

        let minimum_append_count = exact_byte_length.div_ceil(u64::from(
            MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
        ));
        if maximum_append_count < minimum_append_count {
            return Err(ProofExternalMemoryError::InvalidPlan);
        }
        let local_record_seal_invocation_count = maximum_append_count
            .checked_add(COMMON_PROOF_EXTERNAL_MEMORY_SECRET_FIXED_RECORD_COUNT)
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
        let local_record_sealed_plaintext_byte_length = exact_byte_length
            .checked_add(COMMON_PROOF_EXTERNAL_MEMORY_OBJECT_HEADER_PLAINTEXT_BYTE_LENGTH)
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
        Ok(Self {
            local_record_seal_invocation_count,
            local_record_sealed_plaintext_byte_length,
        })
    }

    pub(crate) fn checked_add(self, additional: Self) -> Result<Self, ProofExternalMemoryError> {
        Ok(Self {
            local_record_seal_invocation_count: self
                .local_record_seal_invocation_count
                .checked_add(additional.local_record_seal_invocation_count)
                .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?,
            local_record_sealed_plaintext_byte_length: self
                .local_record_sealed_plaintext_byte_length
                .checked_add(additional.local_record_sealed_plaintext_byte_length)
                .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?,
        })
    }

    pub(in crate::bgv::proof_suite) const fn local_record_seal_invocation_count(self) -> u64 {
        self.local_record_seal_invocation_count
    }

    pub(in crate::bgv::proof_suite) const fn local_record_sealed_plaintext_byte_length(
        self,
    ) -> u64 {
        self.local_record_sealed_plaintext_byte_length
    }

    pub(crate) const fn exceeds_active_root_budget(self) -> bool {
        self.local_record_seal_invocation_count
            > MAXIMUM_LOCAL_RECORD_SEAL_INVOCATIONS_PER_ACTIVE_ROOT
            || self.local_record_sealed_plaintext_byte_length
                > MAXIMUM_LOCAL_RECORD_SEALED_PLAINTEXT_BYTES_PER_ACTIVE_ROOT
    }
}

fn secret_seal_custody_requirement_for_object_lifecycles(
    objects: &[ProofExternalMemoryObjectPlan],
) -> Result<ProofExternalMemorySecretSealCustodyRequirement, ProofExternalMemoryError> {
    objects.iter().try_fold(
        ProofExternalMemorySecretSealCustodyRequirement::default(),
        |requirement, object| {
            requirement.checked_add(
                ProofExternalMemorySecretSealCustodyRequirement::for_object_lifecycle_with_append_count(
                    object.protection,
                    object.exact_byte_length,
                    object.maximum_append_count,
                )?,
            )
        },
    )
}

/// One build-linked liveness entry.  Steps are dense zero-based executor
/// phases.  Writes may occur from `issued_step` through `seal_step`; reads may
/// occur after sealing through `last_use_step`; the executor deletes the object
/// transactionally when that last-use step completes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProofExternalMemoryObjectPlan {
    pub(super) object: ProofExternalMemoryObject,
    pub(super) protection: ProofExternalMemoryProtection,
    pub(super) exact_byte_length: u64,
    pub(super) maximum_append_count: u64,
    pub(super) issued_step: u32,
    pub(super) seal_step: u32,
    pub(super) last_use_step: u32,
}

impl ProofExternalMemoryObjectPlan {
    pub(crate) const fn new(
        object: ProofExternalMemoryObject,
        protection: ProofExternalMemoryProtection,
        exact_byte_length: u64,
        issued_step: u32,
        seal_step: u32,
        last_use_step: u32,
    ) -> Self {
        Self::new_with_maximum_append_count(
            object,
            protection,
            exact_byte_length,
            exact_byte_length
                .div_ceil(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH as u64),
            issued_step,
            seal_step,
            last_use_step,
        )
    }

    pub(crate) const fn new_with_maximum_append_count(
        object: ProofExternalMemoryObject,
        protection: ProofExternalMemoryProtection,
        exact_byte_length: u64,
        maximum_append_count: u64,
        issued_step: u32,
        seal_step: u32,
        last_use_step: u32,
    ) -> Self {
        Self {
            object,
            protection,
            exact_byte_length,
            maximum_append_count,
            issued_step,
            seal_step,
            last_use_step,
        }
    }

    pub(crate) const fn object(self) -> ProofExternalMemoryObject {
        self.object
    }

    pub(crate) const fn protection(self) -> ProofExternalMemoryProtection {
        self.protection
    }

    pub(crate) const fn exact_byte_length(self) -> u64 {
        self.exact_byte_length
    }

    pub(crate) const fn maximum_append_count(self) -> u64 {
        self.maximum_append_count
    }

    pub(crate) const fn issued_step(self) -> u32 {
        self.issued_step
    }

    pub(crate) const fn seal_step(self) -> u32 {
        self.seal_step
    }

    pub(crate) const fn last_use_step(self) -> u32 {
        self.last_use_step
    }
}

/// Absolute safety bounds for one generated storage/liveness plan. These are
/// runtime controls, not proof fields, phone targets, or verifier inputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProofExternalMemoryPlan {
    pub(super) step_count: u32,
    pub(super) maximum_chunk_byte_length: u32,
    pub(super) maximum_transaction_payload_byte_length: u64,
    pub(super) maximum_transaction_operation_count: u32,
    pub(super) maximum_stored_byte_length: u64,
    pub(super) maximum_total_written_byte_length: u64,
    pub(super) maximum_total_read_byte_length: u64,
    pub(super) maximum_transaction_count: u64,
    pub(super) objects: Vec<ProofExternalMemoryObjectPlan>,
}

impl ProofExternalMemoryPlan {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        step_count: u32,
        maximum_chunk_byte_length: u32,
        maximum_transaction_payload_byte_length: u64,
        maximum_transaction_operation_count: u32,
        maximum_stored_byte_length: u64,
        maximum_total_written_byte_length: u64,
        maximum_total_read_byte_length: u64,
        maximum_transaction_count: u64,
        mut objects: Vec<ProofExternalMemoryObjectPlan>,
    ) -> Result<Self, ProofExternalMemoryError> {
        if maximum_chunk_byte_length != 0 {
            for object in &mut objects {
                object.maximum_append_count = object.maximum_append_count.max(
                    object
                        .exact_byte_length
                        .div_ceil(u64::from(maximum_chunk_byte_length)),
                );
            }
        }
        let plan = Self {
            step_count,
            maximum_chunk_byte_length,
            maximum_transaction_payload_byte_length,
            maximum_transaction_operation_count,
            maximum_stored_byte_length,
            maximum_total_written_byte_length,
            maximum_total_read_byte_length,
            maximum_transaction_count,
            objects,
        };
        plan.validate()?;
        Ok(plan)
    }

    pub(in crate::bgv::proof_suite) const fn step_count(&self) -> u32 {
        self.step_count
    }

    pub(in crate::bgv::proof_suite) const fn maximum_chunk_byte_length(&self) -> u32 {
        self.maximum_chunk_byte_length
    }

    pub(in crate::bgv::proof_suite) const fn maximum_transaction_payload_byte_length(&self) -> u64 {
        self.maximum_transaction_payload_byte_length
    }

    pub(in crate::bgv::proof_suite) const fn maximum_stored_byte_length(&self) -> u64 {
        self.maximum_stored_byte_length
    }

    pub(in crate::bgv::proof_suite) const fn maximum_total_written_byte_length(&self) -> u64 {
        self.maximum_total_written_byte_length
    }

    pub(in crate::bgv::proof_suite) const fn maximum_total_read_byte_length(&self) -> u64 {
        self.maximum_total_read_byte_length
    }

    pub(in crate::bgv::proof_suite) const fn maximum_transaction_count(&self) -> u64 {
        self.maximum_transaction_count
    }

    pub(in crate::bgv::proof_suite) fn into_object_plans(
        self,
    ) -> Vec<ProofExternalMemoryObjectPlan> {
        self.objects
    }

    pub(in crate::bgv::proof_suite) fn secret_seal_custody_requirement(
        &self,
    ) -> Result<ProofExternalMemorySecretSealCustodyRequirement, ProofExternalMemoryError> {
        secret_seal_custody_requirement_for_object_lifecycles(&self.objects)
    }

    pub(super) fn validate(&self) -> Result<(), ProofExternalMemoryError> {
        if self.step_count == 0
            || self.maximum_chunk_byte_length == 0
            || self.maximum_transaction_payload_byte_length == 0
            || self.maximum_transaction_operation_count == 0
            || self.maximum_stored_byte_length == 0
            || self.maximum_total_written_byte_length == 0
            || self.maximum_total_read_byte_length == 0
            || self.maximum_transaction_count == 0
            || self.objects.is_empty()
            || u64::from(self.maximum_chunk_byte_length)
                > self.maximum_transaction_payload_byte_length
        {
            return Err(ProofExternalMemoryError::InvalidPlan);
        }
        if usize::try_from(self.maximum_transaction_operation_count)
            .ok()
            .is_none_or(|operation_count| {
                operation_count > MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_OBJECT_COUNT
            })
            || self.maximum_stored_byte_length
                > MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH
        {
            return Err(ProofExternalMemoryError::ResourceLimitExceeded);
        }
        if secret_seal_custody_requirement_for_object_lifecycles(&self.objects)?
            .exceeds_active_root_budget()
        {
            return Err(ProofExternalMemoryError::ResourceLimitExceeded);
        }

        let mut object_ordinals = BTreeSet::new();
        let mut lifecycle_intervals = Vec::new();
        lifecycle_intervals
            .try_reserve_exact(self.objects.len())
            .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?;
        let mut deletion_count_by_step = BTreeMap::<u32, u32>::new();
        let mut scheduled_total_write = 0_u64;
        let event_count = self
            .objects
            .len()
            .checked_mul(2)
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
        let mut liveness_events = Vec::new();
        liveness_events
            .try_reserve_exact(event_count)
            .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?;
        for object in &self.objects {
            if object.exact_byte_length == 0
                || object.maximum_append_count
                    < object.exact_byte_length.div_ceil(u64::from(
                        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
                    ))
                || object.issued_step > object.seal_step
                || object.seal_step > object.last_use_step
                || object.last_use_step >= self.step_count
            {
                return Err(ProofExternalMemoryError::InvalidPlan);
            }
            object_ordinals.insert(object.object);
            lifecycle_intervals.push((object.object, object.issued_step, object.last_use_step));
            let deletion_count = deletion_count_by_step
                .entry(object.last_use_step)
                .or_default();
            *deletion_count = deletion_count
                .checked_add(1)
                .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
            scheduled_total_write = scheduled_total_write
                .checked_add(object.exact_byte_length)
                .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
            liveness_events.push((object.issued_step, true, object.exact_byte_length));
            liveness_events.push((
                object
                    .last_use_step
                    .checked_add(1)
                    .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?,
                false,
                object.exact_byte_length,
            ));
        }
        if object_ordinals.len() > MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_OBJECT_COUNT
            || deletion_count_by_step.values().copied().max().unwrap_or(0)
                > self.maximum_transaction_operation_count
        {
            return Err(ProofExternalMemoryError::ResourceLimitExceeded);
        }
        lifecycle_intervals
            .sort_unstable_by_key(|(object, issued_step, _)| (*object, *issued_step));
        if lifecycle_intervals.windows(2).any(|pair| {
            let (previous_object, _, previous_last_use_step) = pair[0];
            let (next_object, next_issued_step, _) = pair[1];
            previous_object == next_object && previous_last_use_step >= next_issued_step
        }) {
            return Err(ProofExternalMemoryError::InvalidPlan);
        }
        if scheduled_total_write > self.maximum_total_written_byte_length {
            return Err(ProofExternalMemoryError::ResourceLimitExceeded);
        }

        // An object occupies external storage from issuance through its
        // declared last-use step.  Event sweeping keeps validation bounded by
        // the object count even when an invalid caller supplies a huge step
        // count.  Deletions sort before issuances at the same step.
        liveness_events.sort_unstable_by_key(|(step, is_issuance, _)| (*step, *is_issuance));
        let mut live_byte_length = 0_u64;
        for (_, is_issuance, exact_byte_length) in liveness_events {
            if is_issuance {
                live_byte_length = live_byte_length
                    .checked_add(exact_byte_length)
                    .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
                if live_byte_length > self.maximum_stored_byte_length {
                    return Err(ProofExternalMemoryError::ResourceLimitExceeded);
                }
            } else {
                live_byte_length = live_byte_length
                    .checked_sub(exact_byte_length)
                    .ok_or(ProofExternalMemoryError::InvalidPlan)?;
            }
        }
        if live_byte_length != 0 {
            return Err(ProofExternalMemoryError::InvalidPlan);
        }
        Ok(())
    }

    pub(in crate::bgv::proof_suite) fn physical_object_count(
        &self,
    ) -> Result<u32, ProofExternalMemoryError> {
        u32::try_from(
            self.objects
                .iter()
                .map(|object| object.object)
                .collect::<BTreeSet<_>>()
                .len(),
        )
        .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)
    }

    pub(in crate::bgv::proof_suite) fn object_lifecycle_count(
        &self,
    ) -> Result<u32, ProofExternalMemoryError> {
        u32::try_from(self.objects.len())
            .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)
    }
}

#[cfg(test)]
mod custody_requirement_tests {
    use super::*;

    #[test]
    fn secret_seal_custody_requirement_uses_canonical_record_geometry() {
        assert_eq!(
            MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
            1_048_576
        );
        assert_eq!(
            COMMON_PROOF_EXTERNAL_MEMORY_OBJECT_HEADER_PLAINTEXT_BYTE_LENGTH,
            9
        );
        assert_eq!(
            ProofExternalMemorySecretSealCustodyRequirement::for_object_lifecycle(
                ProofExternalMemoryProtection::PublicIntegrity,
                u64::MAX,
            ),
            Ok(ProofExternalMemorySecretSealCustodyRequirement::default()),
            "public-integrity objects never consume the active-root seal budget",
        );

        let canonical_chunk_byte_length =
            u64::from(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH);
        for (exact_byte_length, expected_invocation_count) in [
            (1, 3),
            (canonical_chunk_byte_length - 1, 3),
            (canonical_chunk_byte_length, 3),
            (canonical_chunk_byte_length + 1, 4),
        ] {
            let requirement =
                ProofExternalMemorySecretSealCustodyRequirement::for_object_lifecycle(
                    ProofExternalMemoryProtection::SecretAuthenticatedEncryption,
                    exact_byte_length,
                )
                .expect("the secret lifecycle geometry is representable");
            assert_eq!(
                requirement.local_record_seal_invocation_count(),
                expected_invocation_count,
            );
            assert_eq!(
                requirement.local_record_sealed_plaintext_byte_length(),
                exact_byte_length + 9,
            );
        }
        assert_eq!(
            ProofExternalMemorySecretSealCustodyRequirement::for_object_lifecycle(
                ProofExternalMemoryProtection::SecretAuthenticatedEncryption,
                0,
            ),
            Err(ProofExternalMemoryError::InvalidPlan),
        );
    }

    #[test]
    fn secret_seal_custody_requirement_accepts_exact_active_root_boundaries() {
        let exact_boundaries = ProofExternalMemorySecretSealCustodyRequirement {
            local_record_seal_invocation_count:
                MAXIMUM_LOCAL_RECORD_SEAL_INVOCATIONS_PER_ACTIVE_ROOT,
            local_record_sealed_plaintext_byte_length:
                MAXIMUM_LOCAL_RECORD_SEALED_PLAINTEXT_BYTES_PER_ACTIVE_ROOT,
        };
        assert!(!exact_boundaries.exceeds_active_root_budget());
        assert!(
            ProofExternalMemorySecretSealCustodyRequirement {
                local_record_seal_invocation_count:
                    MAXIMUM_LOCAL_RECORD_SEAL_INVOCATIONS_PER_ACTIVE_ROOT + 1,
                ..exact_boundaries
            }
            .exceeds_active_root_budget()
        );
        assert!(
            ProofExternalMemorySecretSealCustodyRequirement {
                local_record_sealed_plaintext_byte_length:
                    MAXIMUM_LOCAL_RECORD_SEALED_PLAINTEXT_BYTES_PER_ACTIVE_ROOT + 1,
                ..exact_boundaries
            }
            .exceeds_active_root_budget()
        );
    }

    #[test]
    fn plan_counts_reused_object_ordinals_as_distinct_secret_lifecycles() {
        let lifecycle_count = 1_024_u32;
        let exact_lifecycle_byte_length = MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH
            - COMMON_PROOF_EXTERNAL_MEMORY_OBJECT_HEADER_PLAINTEXT_BYTE_LENGTH;
        let exact_total_written_byte_length = exact_lifecycle_byte_length
            .checked_mul(u64::from(lifecycle_count))
            .expect("the exact-boundary test total fits u64");
        let reused_object = ProofExternalMemoryObject::new(7);
        let exact_boundary_lifecycles = (0..lifecycle_count)
            .map(|step| {
                ProofExternalMemoryObjectPlan::new(
                    reused_object,
                    ProofExternalMemoryProtection::SecretAuthenticatedEncryption,
                    exact_lifecycle_byte_length,
                    step,
                    step,
                    step,
                )
            })
            .collect::<Vec<_>>();
        ProofExternalMemoryPlan::new(
            lifecycle_count,
            MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
            u64::from(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH),
            1,
            exact_lifecycle_byte_length,
            exact_total_written_byte_length,
            1,
            1,
            exact_boundary_lifecycles.clone(),
        )
        .expect("reused lifecycles at the exact sealed-plaintext boundary are accepted");

        let mut one_byte_over_lifecycles = exact_boundary_lifecycles;
        one_byte_over_lifecycles[0].exact_byte_length += 1;
        assert_eq!(
            ProofExternalMemoryPlan::new(
                lifecycle_count,
                MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
                u64::from(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH),
                1,
                MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH,
                exact_total_written_byte_length + 1,
                1,
                1,
                one_byte_over_lifecycles,
            ),
            Err(ProofExternalMemoryError::ResourceLimitExceeded),
            "physical-ordinal reuse cannot evade the per-lifecycle custody budget",
        );
    }

    #[test]
    fn secret_seal_custody_requirement_refuses_checked_arithmetic_overflow() {
        assert_eq!(
            ProofExternalMemorySecretSealCustodyRequirement::for_object_lifecycle(
                ProofExternalMemoryProtection::SecretAuthenticatedEncryption,
                u64::MAX,
            ),
            Err(ProofExternalMemoryError::ResourceLimitExceeded),
        );
        let maximum = ProofExternalMemorySecretSealCustodyRequirement {
            local_record_seal_invocation_count: u64::MAX,
            local_record_sealed_plaintext_byte_length: u64::MAX,
        };
        let one = ProofExternalMemorySecretSealCustodyRequirement {
            local_record_seal_invocation_count: 1,
            local_record_sealed_plaintext_byte_length: 1,
        };
        assert_eq!(
            maximum.checked_add(one),
            Err(ProofExternalMemoryError::ResourceLimitExceeded),
        );
    }
}

/// The transaction-owned browser storage boundary.  Implementations must make
/// `commit_transaction` atomic and use copy-on-write storage.  A secret object
/// must be encrypted and authenticated before a successful commit. A failed
/// commit is repaired from the existing authenticated journal before this
/// executor is resumed.
pub(crate) trait ProofExternalMemory {
    type Error;

    fn begin_transaction(
        &mut self,
        maximum_payload_byte_length: u64,
        maximum_operation_count: u32,
    ) -> Result<(), Self::Error>;

    fn create_object(
        &mut self,
        object: ProofExternalMemoryObject,
        protection: ProofExternalMemoryProtection,
        exact_byte_length: u64,
    ) -> Result<(), Self::Error>;

    fn append_object_bytes(
        &mut self,
        object: ProofExternalMemoryObject,
        expected_offset: u64,
        bytes: &[u8],
    ) -> Result<(), Self::Error>;

    /// Transfers an append allocation when the producer can relinquish it.
    /// Implementations without an owned fast path preserve the ordinary
    /// borrowed behavior and leave the producer allocation unchanged.
    fn append_owned_object_bytes(
        &mut self,
        object: ProofExternalMemoryObject,
        expected_offset: u64,
        bytes: &mut Zeroizing<Vec<u8>>,
    ) -> Result<(), Self::Error> {
        self.append_object_bytes(object, expected_offset, bytes.as_slice())
    }

    fn seal_object(&mut self, object: ProofExternalMemoryObject) -> Result<(), Self::Error>;

    fn read_object_bytes(
        &mut self,
        object: ProofExternalMemoryObject,
        offset: u64,
        destination: &mut [u8],
    ) -> Result<(), Self::Error>;

    fn delete_object(&mut self, object: ProofExternalMemoryObject) -> Result<(), Self::Error>;

    fn commit_transaction(&mut self) -> Result<(), Self::Error>;

    fn abort_transaction(&mut self) -> Result<(), Self::Error>;
}

/// One owned operation in a yielded browser transaction.  Secret append bytes
/// are already protected by the transaction-owned storage custody layer before
/// they become durable; this request never becomes a proof artifact.
#[derive(PartialEq, Eq)]
pub(crate) enum ProofExternalMemoryTransactionOperation {
    Create {
        object: ProofExternalMemoryObject,
        protection: ProofExternalMemoryProtection,
        exact_byte_length: u64,
    },
    Append {
        object: ProofExternalMemoryObject,
        expected_offset: u64,
        bytes: Zeroizing<Vec<u8>>,
    },
    Seal {
        object: ProofExternalMemoryObject,
    },
    Read {
        object: ProofExternalMemoryObject,
        offset: u64,
        byte_length: u32,
    },
    Delete {
        object: ProofExternalMemoryObject,
    },
}

impl fmt::Debug for ProofExternalMemoryTransactionOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Create {
                object,
                protection,
                exact_byte_length,
            } => formatter
                .debug_struct("Create")
                .field("object", object)
                .field("protection", protection)
                .field("exact_byte_length", exact_byte_length)
                .finish(),
            Self::Append {
                object,
                expected_offset,
                bytes,
            } => formatter
                .debug_struct("Append")
                .field("object", object)
                .field("expected_offset", expected_offset)
                .field("byte_length", &bytes.len())
                .field("bytes", &"[REDACTED]")
                .finish(),
            Self::Seal { object } => formatter
                .debug_struct("Seal")
                .field("object", object)
                .finish(),
            Self::Read {
                object,
                offset,
                byte_length,
            } => formatter
                .debug_struct("Read")
                .field("object", object)
                .field("offset", offset)
                .field("byte_length", byte_length)
                .finish(),
            Self::Delete { object } => formatter
                .debug_struct("Delete")
                .field("object", object)
                .finish(),
        }
    }
}
