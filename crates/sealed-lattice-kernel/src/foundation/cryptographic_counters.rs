use super::RefusalReason;

pub const MAXIMUM_OBJECT_SIGNATURE_GENERATIONS_PER_CEREMONY: u64 = 1 << 20;
pub const MAXIMUM_OBJECT_SIGNATURE_VERIFICATIONS_PER_CEREMONY: u64 = 1 << 32;
pub const MAXIMUM_MAILBOX_ENCAPSULATIONS_PER_CEREMONY: u64 = 1 << 16;
pub const MAXIMUM_AUTHENTICATED_MAILBOX_OPENINGS_PER_CEREMONY: u64 = 1 << 16;
pub const MAXIMUM_DEVICE_WRAPPING_OPENS_PER_CEREMONY: u64 = 1 << 16;
pub const MAXIMUM_LOCAL_RECORD_OPENS_PER_CEREMONY: u64 = 1 << 32;
pub const MAXIMUM_MAILBOX_PLAINTEXT_BYTES_PER_CEREMONY: u64 = 1 << 40;
pub const MAXIMUM_LOCAL_RECORD_PLAINTEXT_BYTES_PER_CEREMONY: u64 = 1 << 41;
pub const MAXIMUM_PROOF_VERIFICATIONS_PER_CEREMONY: u64 = 1 << 32;

/// Authenticated continuation state for the broad ceremony-wide cryptographic
/// interface ceilings. Owning checkpoint and state schemas remain responsible
/// for authenticating this value and rejecting rollback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CryptographicCounterSnapshot {
    pub object_signature_generation_count: u64,
    pub object_signature_verification_count: u64,
    pub mailbox_encapsulation_count: u64,
    pub authenticated_mailbox_opening_count: u64,
    pub device_wrapping_open_count: u64,
    pub local_record_open_count: u64,
    pub mailbox_plaintext_byte_count: u64,
    pub local_record_plaintext_byte_count: u64,
    pub proof_verification_count: u64,
}

impl CryptographicCounterSnapshot {
    pub fn validate(self) -> Result<Self, RefusalReason> {
        if self.object_signature_generation_count
            > MAXIMUM_OBJECT_SIGNATURE_GENERATIONS_PER_CEREMONY
            || self.object_signature_verification_count
                > MAXIMUM_OBJECT_SIGNATURE_VERIFICATIONS_PER_CEREMONY
            || self.mailbox_encapsulation_count > MAXIMUM_MAILBOX_ENCAPSULATIONS_PER_CEREMONY
            || self.authenticated_mailbox_opening_count
                > MAXIMUM_AUTHENTICATED_MAILBOX_OPENINGS_PER_CEREMONY
            || self.device_wrapping_open_count > MAXIMUM_DEVICE_WRAPPING_OPENS_PER_CEREMONY
            || self.local_record_open_count > MAXIMUM_LOCAL_RECORD_OPENS_PER_CEREMONY
            || self.mailbox_plaintext_byte_count > MAXIMUM_MAILBOX_PLAINTEXT_BYTES_PER_CEREMONY
            || self.local_record_plaintext_byte_count
                > MAXIMUM_LOCAL_RECORD_PLAINTEXT_BYTES_PER_CEREMONY
            || self.proof_verification_count > MAXIMUM_PROOF_VERIFICATIONS_PER_CEREMONY
        {
            return Err(RefusalReason::OutsideSupportedProfile);
        }
        Ok(self)
    }
}

/// Process-local enforcement of the independent cryptographic interface
/// ceilings. Every method consumes its charge before the caller begins the
/// corresponding operation, and no charge can be released after an operation
/// later refuses. Durable orchestration must authenticate the snapshot and
/// prevent rollback across restarts.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CryptographicInterfaceCounters {
    snapshot: CryptographicCounterSnapshot,
}

impl CryptographicInterfaceCounters {
    pub const fn new() -> Self {
        Self {
            snapshot: CryptographicCounterSnapshot {
                object_signature_generation_count: 0,
                object_signature_verification_count: 0,
                mailbox_encapsulation_count: 0,
                authenticated_mailbox_opening_count: 0,
                device_wrapping_open_count: 0,
                local_record_open_count: 0,
                mailbox_plaintext_byte_count: 0,
                local_record_plaintext_byte_count: 0,
                proof_verification_count: 0,
            },
        }
    }

    pub fn try_restore(snapshot: CryptographicCounterSnapshot) -> Result<Self, RefusalReason> {
        Ok(Self {
            snapshot: snapshot.validate()?,
        })
    }

    pub const fn snapshot(&self) -> CryptographicCounterSnapshot {
        self.snapshot
    }

    pub fn consume_object_signature_generation(&mut self) -> Result<(), RefusalReason> {
        consume_one(
            &mut self.snapshot.object_signature_generation_count,
            MAXIMUM_OBJECT_SIGNATURE_GENERATIONS_PER_CEREMONY,
        )
    }

    pub fn consume_object_signature_verification(&mut self) -> Result<(), RefusalReason> {
        consume_one(
            &mut self.snapshot.object_signature_verification_count,
            MAXIMUM_OBJECT_SIGNATURE_VERIFICATIONS_PER_CEREMONY,
        )
    }

    pub fn consume_mailbox_encapsulation(
        &mut self,
        plaintext_byte_length: u64,
    ) -> Result<(), RefusalReason> {
        consume_operation_and_bytes(
            &mut self.snapshot.mailbox_encapsulation_count,
            MAXIMUM_MAILBOX_ENCAPSULATIONS_PER_CEREMONY,
            &mut self.snapshot.mailbox_plaintext_byte_count,
            MAXIMUM_MAILBOX_PLAINTEXT_BYTES_PER_CEREMONY,
            plaintext_byte_length,
        )
    }

    pub fn consume_authenticated_mailbox_opening(
        &mut self,
        plaintext_byte_length: u64,
    ) -> Result<(), RefusalReason> {
        consume_operation_and_bytes(
            &mut self.snapshot.authenticated_mailbox_opening_count,
            MAXIMUM_AUTHENTICATED_MAILBOX_OPENINGS_PER_CEREMONY,
            &mut self.snapshot.mailbox_plaintext_byte_count,
            MAXIMUM_MAILBOX_PLAINTEXT_BYTES_PER_CEREMONY,
            plaintext_byte_length,
        )
    }

    pub fn consume_device_wrapping_open(&mut self) -> Result<(), RefusalReason> {
        consume_one(
            &mut self.snapshot.device_wrapping_open_count,
            MAXIMUM_DEVICE_WRAPPING_OPENS_PER_CEREMONY,
        )
    }

    pub fn consume_local_record_open(
        &mut self,
        plaintext_byte_length: u64,
    ) -> Result<(), RefusalReason> {
        consume_operation_and_bytes(
            &mut self.snapshot.local_record_open_count,
            MAXIMUM_LOCAL_RECORD_OPENS_PER_CEREMONY,
            &mut self.snapshot.local_record_plaintext_byte_count,
            MAXIMUM_LOCAL_RECORD_PLAINTEXT_BYTES_PER_CEREMONY,
            plaintext_byte_length,
        )
    }

    pub fn consume_proof_verification(&mut self) -> Result<(), RefusalReason> {
        consume_one(
            &mut self.snapshot.proof_verification_count,
            MAXIMUM_PROOF_VERIFICATIONS_PER_CEREMONY,
        )
    }
}

fn consume_one(counter: &mut u64, ceiling: u64) -> Result<(), RefusalReason> {
    let next = counter
        .checked_add(1)
        .ok_or(RefusalReason::OutsideSupportedProfile)?;
    if next > ceiling {
        return Err(RefusalReason::OutsideSupportedProfile);
    }
    *counter = next;
    Ok(())
}

fn consume_operation_and_bytes(
    operation_counter: &mut u64,
    operation_ceiling: u64,
    byte_counter: &mut u64,
    byte_ceiling: u64,
    plaintext_byte_length: u64,
) -> Result<(), RefusalReason> {
    let next_operation_count = operation_counter
        .checked_add(1)
        .ok_or(RefusalReason::OutsideSupportedProfile)?;
    let next_byte_count = byte_counter
        .checked_add(plaintext_byte_length)
        .ok_or(RefusalReason::OutsideSupportedProfile)?;
    if next_operation_count > operation_ceiling || next_byte_count > byte_ceiling {
        return Err(RefusalReason::OutsideSupportedProfile);
    }
    *operation_counter = next_operation_count;
    *byte_counter = next_byte_count;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_independent_ceiling_accepts_its_boundary_and_refuses_one_more() {
        let mut counters =
            CryptographicInterfaceCounters::try_restore(CryptographicCounterSnapshot {
                object_signature_generation_count: MAXIMUM_OBJECT_SIGNATURE_GENERATIONS_PER_CEREMONY
                    - 1,
                object_signature_verification_count:
                    MAXIMUM_OBJECT_SIGNATURE_VERIFICATIONS_PER_CEREMONY - 1,
                mailbox_encapsulation_count: MAXIMUM_MAILBOX_ENCAPSULATIONS_PER_CEREMONY - 1,
                authenticated_mailbox_opening_count:
                    MAXIMUM_AUTHENTICATED_MAILBOX_OPENINGS_PER_CEREMONY - 1,
                device_wrapping_open_count: MAXIMUM_DEVICE_WRAPPING_OPENS_PER_CEREMONY - 1,
                local_record_open_count: MAXIMUM_LOCAL_RECORD_OPENS_PER_CEREMONY - 1,
                mailbox_plaintext_byte_count: MAXIMUM_MAILBOX_PLAINTEXT_BYTES_PER_CEREMONY - 2,
                local_record_plaintext_byte_count: MAXIMUM_LOCAL_RECORD_PLAINTEXT_BYTES_PER_CEREMONY
                    - 1,
                proof_verification_count: MAXIMUM_PROOF_VERIFICATIONS_PER_CEREMONY - 1,
            })
            .expect("at-boundary-minus-one counters restore");

        assert_eq!(counters.consume_object_signature_generation(), Ok(()));
        assert_eq!(
            counters.consume_object_signature_generation(),
            Err(RefusalReason::OutsideSupportedProfile)
        );
        assert_eq!(counters.consume_object_signature_verification(), Ok(()));
        assert_eq!(
            counters.consume_object_signature_verification(),
            Err(RefusalReason::OutsideSupportedProfile)
        );
        assert_eq!(counters.consume_mailbox_encapsulation(1), Ok(()));
        assert_eq!(counters.consume_authenticated_mailbox_opening(1), Ok(()));
        assert_eq!(
            counters.consume_authenticated_mailbox_opening(0),
            Err(RefusalReason::OutsideSupportedProfile)
        );
        assert_eq!(counters.consume_device_wrapping_open(), Ok(()));
        assert_eq!(
            counters.consume_device_wrapping_open(),
            Err(RefusalReason::OutsideSupportedProfile)
        );
        assert_eq!(counters.consume_local_record_open(1), Ok(()));
        assert_eq!(
            counters.consume_local_record_open(0),
            Err(RefusalReason::OutsideSupportedProfile)
        );
        assert_eq!(counters.consume_proof_verification(), Ok(()));
        assert_eq!(
            counters.consume_proof_verification(),
            Err(RefusalReason::OutsideSupportedProfile)
        );
    }

    #[test]
    fn combined_operation_and_byte_charges_are_atomic() {
        let initial_snapshot = CryptographicCounterSnapshot {
            mailbox_encapsulation_count: 7,
            mailbox_plaintext_byte_count: MAXIMUM_MAILBOX_PLAINTEXT_BYTES_PER_CEREMONY - 3,
            local_record_open_count: 11,
            local_record_plaintext_byte_count: MAXIMUM_LOCAL_RECORD_PLAINTEXT_BYTES_PER_CEREMONY
                - 5,
            ..CryptographicCounterSnapshot::default()
        };
        let mut counters = CryptographicInterfaceCounters::try_restore(initial_snapshot)
            .expect("bounded counters restore");

        assert_eq!(
            counters.consume_mailbox_encapsulation(4),
            Err(RefusalReason::OutsideSupportedProfile)
        );
        assert_eq!(counters.snapshot(), initial_snapshot);
        assert_eq!(
            counters.consume_local_record_open(6),
            Err(RefusalReason::OutsideSupportedProfile)
        );
        assert_eq!(counters.snapshot(), initial_snapshot);

        counters
            .consume_mailbox_encapsulation(3)
            .expect("exact mailbox byte boundary accepts");
        counters
            .consume_local_record_open(5)
            .expect("exact local-record byte boundary accepts");
        assert_eq!(
            counters.snapshot().mailbox_plaintext_byte_count,
            MAXIMUM_MAILBOX_PLAINTEXT_BYTES_PER_CEREMONY
        );
        assert_eq!(
            counters.snapshot().local_record_plaintext_byte_count,
            MAXIMUM_LOCAL_RECORD_PLAINTEXT_BYTES_PER_CEREMONY
        );
    }

    #[test]
    fn restored_state_above_any_ceiling_refuses() {
        let mut invalid_snapshots = Vec::new();
        let fields = [
            (MAXIMUM_OBJECT_SIGNATURE_GENERATIONS_PER_CEREMONY, 0usize),
            (MAXIMUM_OBJECT_SIGNATURE_VERIFICATIONS_PER_CEREMONY, 1),
            (MAXIMUM_MAILBOX_ENCAPSULATIONS_PER_CEREMONY, 2),
            (MAXIMUM_AUTHENTICATED_MAILBOX_OPENINGS_PER_CEREMONY, 3),
            (MAXIMUM_DEVICE_WRAPPING_OPENS_PER_CEREMONY, 4),
            (MAXIMUM_LOCAL_RECORD_OPENS_PER_CEREMONY, 5),
            (MAXIMUM_MAILBOX_PLAINTEXT_BYTES_PER_CEREMONY, 6),
            (MAXIMUM_LOCAL_RECORD_PLAINTEXT_BYTES_PER_CEREMONY, 7),
            (MAXIMUM_PROOF_VERIFICATIONS_PER_CEREMONY, 8),
        ];
        for (ceiling, field_index) in fields {
            let mut snapshot = CryptographicCounterSnapshot::default();
            let invalid_value = ceiling + 1;
            match field_index {
                0 => snapshot.object_signature_generation_count = invalid_value,
                1 => snapshot.object_signature_verification_count = invalid_value,
                2 => snapshot.mailbox_encapsulation_count = invalid_value,
                3 => snapshot.authenticated_mailbox_opening_count = invalid_value,
                4 => snapshot.device_wrapping_open_count = invalid_value,
                5 => snapshot.local_record_open_count = invalid_value,
                6 => snapshot.mailbox_plaintext_byte_count = invalid_value,
                7 => snapshot.local_record_plaintext_byte_count = invalid_value,
                8 => snapshot.proof_verification_count = invalid_value,
                _ => unreachable!("test field index is closed"),
            }
            invalid_snapshots.push(snapshot);
        }

        for invalid_snapshot in invalid_snapshots {
            assert_eq!(
                CryptographicInterfaceCounters::try_restore(invalid_snapshot),
                Err(RefusalReason::OutsideSupportedProfile)
            );
        }
    }

    #[test]
    fn snapshot_round_trip_preserves_every_counter_exactly() {
        let mut counters = CryptographicInterfaceCounters::new();
        counters
            .consume_object_signature_generation()
            .expect("signature generation consumes");
        counters
            .consume_object_signature_verification()
            .expect("signature verification consumes");
        counters
            .consume_mailbox_encapsulation(17)
            .expect("mailbox seal consumes");
        counters
            .consume_authenticated_mailbox_opening(19)
            .expect("mailbox open consumes");
        counters
            .consume_device_wrapping_open()
            .expect("device open consumes");
        counters
            .consume_local_record_open(23)
            .expect("record open consumes");
        counters
            .consume_proof_verification()
            .expect("proof verification consumes");

        let snapshot = counters.snapshot();
        let restored = CryptographicInterfaceCounters::try_restore(snapshot)
            .expect("authenticated counter snapshot restores");
        assert_eq!(restored.snapshot(), snapshot);
        assert_eq!(snapshot.mailbox_plaintext_byte_count, 36);
        assert_eq!(snapshot.local_record_plaintext_byte_count, 23);
    }
}
