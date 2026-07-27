use std::{cell::RefCell, collections::HashMap};

use super::{
    Hash512, ML_DSA_65_SIGNATURE_BYTE_LENGTH, ObjectEnvelope, RefusalReason, Roster, SignedCarrier,
    signature_message,
};

const MAXIMUM_PREPARED_SIGNED_CARRIER_COUNT: usize = 64;

#[derive(Clone)]
struct PreparedSignedCarrier {
    envelope: ObjectEnvelope,
    roster: Roster,
    canonical_carrier_byte_length: usize,
}

#[derive(Default)]
struct PreparedSignedCarrierRegistry {
    next_handle: u32,
    records: HashMap<u32, PreparedSignedCarrier>,
}

impl PreparedSignedCarrierRegistry {
    fn retain(&mut self, record: PreparedSignedCarrier) -> Result<u32, RefusalReason> {
        if self.records.len() >= MAXIMUM_PREPARED_SIGNED_CARRIER_COUNT {
            return Err(RefusalReason::OutsideSupportedProfile);
        }
        self.next_handle = self
            .next_handle
            .checked_add(1)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        self.records.insert(self.next_handle, record);
        Ok(self.next_handle)
    }

    fn get(&self, handle: u32) -> Result<&PreparedSignedCarrier, RefusalReason> {
        self.records
            .get(&handle)
            .ok_or(RefusalReason::ConsumedState)
    }

    fn remove(&mut self, handle: u32) -> Result<PreparedSignedCarrier, RefusalReason> {
        self.records
            .remove(&handle)
            .ok_or(RefusalReason::ConsumedState)
    }
}

thread_local! {
    static PREPARED_SIGNED_CARRIER_REGISTRY: RefCell<PreparedSignedCarrierRegistry> =
        RefCell::new(PreparedSignedCarrierRegistry::default());
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PreparedSignedCarrierDescription {
    handle: u32,
    signature_message: Hash512,
    canonical_carrier_byte_length: usize,
}

impl PreparedSignedCarrierDescription {
    pub(crate) const fn handle(self) -> u32 {
        self.handle
    }

    pub(crate) const fn signature_message(self) -> Hash512 {
        self.signature_message
    }

    pub(crate) const fn canonical_carrier_byte_length(self) -> usize {
        self.canonical_carrier_byte_length
    }
}

pub(crate) fn retain_prepared_signed_carrier(
    envelope: ObjectEnvelope,
    roster: &Roster,
    expected_roster_hash: Hash512,
) -> Result<PreparedSignedCarrierDescription, RefusalReason> {
    let roster_hash = roster.roster_hash().map_err(|error| error.refusal_reason)?;
    if roster_hash != expected_roster_hash {
        return Err(RefusalReason::WrongHashOrRoot);
    }
    let signature_message =
        signature_message(&envelope, roster_hash).map_err(|error| error.refusal_reason)?;
    let canonical_carrier_byte_length = SignedCarrier {
        envelope: envelope.clone(),
        signature: [0_u8; ML_DSA_65_SIGNATURE_BYTE_LENGTH],
    }
    .encode()
    .map_err(|error| error.refusal_reason)?
    .len();
    let handle = PREPARED_SIGNED_CARRIER_REGISTRY.with(|registry| {
        registry.borrow_mut().retain(PreparedSignedCarrier {
            envelope,
            roster: roster.clone(),
            canonical_carrier_byte_length,
        })
    })?;
    Ok(PreparedSignedCarrierDescription {
        handle,
        signature_message,
        canonical_carrier_byte_length,
    })
}

pub(crate) fn prepared_signed_carrier_byte_length(handle: u32) -> Result<usize, RefusalReason> {
    PREPARED_SIGNED_CARRIER_REGISTRY.with(|registry| {
        registry
            .borrow()
            .get(handle)
            .map(|record| record.canonical_carrier_byte_length)
    })
}

pub(crate) fn finish_prepared_signed_carrier(
    handle: u32,
    signature: [u8; ML_DSA_65_SIGNATURE_BYTE_LENGTH],
) -> Result<Vec<u8>, RefusalReason> {
    let record =
        PREPARED_SIGNED_CARRIER_REGISTRY.with(|registry| registry.borrow_mut().remove(handle))?;
    let carrier = SignedCarrier {
        envelope: record.envelope,
        signature,
    };
    carrier.verify_signature(&record.roster).into_result()?;
    carrier.encode().map_err(|error| error.refusal_reason)
}

pub(crate) fn cancel_prepared_signed_carrier(handle: u32) -> Result<(), RefusalReason> {
    PREPARED_SIGNED_CARRIER_REGISTRY.with(|registry| registry.borrow_mut().remove(handle).map(drop))
}

#[cfg(test)]
mod tests {
    use fips203::{
        ml_kem_768,
        traits::{KeyGen as KemKeyGen, SerDes as KemSerDes},
    };
    use fips204::{
        ml_dsa_65,
        traits::{KeyGen as SignatureKeyGen, SerDes as SignatureSerDes},
    };

    use super::*;
    use crate::foundation::{FOUNDATION_PROFILE, FoundationObjectType, RosterEntry};

    fn selected_test_roster() -> Roster {
        let entries = (0..FOUNDATION_PROFILE.participant_count)
            .map(|roster_position| {
                let mut signing_seed = [0x41_u8; 32];
                signing_seed[0] =
                    u8::try_from(roster_position + 1).expect("test roster position fits u8");
                let (signing_verification_key, _) = ml_dsa_65::KG::keygen_from_seed(&signing_seed);
                let mut mailbox_seed = [0x63_u8; 32];
                mailbox_seed[0] =
                    u8::try_from(roster_position + 1).expect("test roster position fits u8");
                let mut mailbox_fallback_seed = [0x97_u8; 32];
                mailbox_fallback_seed[31] =
                    u8::try_from(FOUNDATION_PROFILE.participant_count - roster_position)
                        .expect("reverse test roster position fits u8");
                let (mailbox_encapsulation_key, _) =
                    ml_kem_768::KG::keygen_from_seed(mailbox_seed, mailbox_fallback_seed);
                RosterEntry {
                    roster_position,
                    signing_verification_key: signing_verification_key.into_bytes(),
                    mailbox_encapsulation_key: mailbox_encapsulation_key.into_bytes(),
                }
            })
            .collect();
        Roster::new(entries).expect("selected test roster is valid")
    }

    #[test]
    fn invalid_finish_consumes_setup_ballot_and_target_carrier_handles() {
        let roster = selected_test_roster();
        let roster_hash = roster.roster_hash().expect("test roster hash derives");
        let producer_participant_id = roster.entries[0]
            .participant_identity()
            .expect("test participant identity derives");

        for (object_type, payload_marker) in [
            (FoundationObjectType::SetupIntent, 0x11),
            (FoundationObjectType::BallotPackage, 0x22),
            (FoundationObjectType::TargetDecryptionShare, 0x33),
        ] {
            let prepared = retain_prepared_signed_carrier(
                ObjectEnvelope {
                    suite_id: Hash512::from_bytes([0x51; Hash512::BYTE_LENGTH]),
                    object_type,
                    ceremony_context_hash: Hash512::from_bytes([0x52; Hash512::BYTE_LENGTH]),
                    action_context_hash: Hash512::from_bytes([0x53; Hash512::BYTE_LENGTH]),
                    producer_participant_id: Some(producer_participant_id),
                    producer_sequence: 0,
                    ordered_prerequisite_hashes: Vec::new(),
                    payload_bytes: vec![payload_marker],
                },
                &roster,
                roster_hash,
            )
            .expect("test carrier preparation succeeds");
            assert_eq!(
                prepared_signed_carrier_byte_length(prepared.handle()),
                Ok(prepared.canonical_carrier_byte_length())
            );
            assert_eq!(
                finish_prepared_signed_carrier(
                    prepared.handle(),
                    [0_u8; ML_DSA_65_SIGNATURE_BYTE_LENGTH],
                ),
                Err(RefusalReason::InvalidSignature)
            );
            assert_eq!(
                finish_prepared_signed_carrier(
                    prepared.handle(),
                    [0_u8; ML_DSA_65_SIGNATURE_BYTE_LENGTH],
                ),
                Err(RefusalReason::ConsumedState)
            );
            assert_eq!(
                cancel_prepared_signed_carrier(prepared.handle()),
                Err(RefusalReason::ConsumedState)
            );
        }
    }
}
