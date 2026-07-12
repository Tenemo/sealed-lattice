use std::collections::BTreeMap;

use super::{Hash512, RefusalReason};

/// The complete proof-family set admitted by the version-one foundation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum ProofFamily {
    SourceBatchedVerifiableSecretSharingLinkage = 0x2110,
    AggregateThresholdShare = 0x2111,
    SameSecretLinkage = 0x1211,
    PublicKeyShare = 0x1212,
    CollectivePublicKeyAggregate = 0x1213,
    RelinearizationRoundOne = 0x1214,
    RelinearizationRoundOneAggregate = 0x1215,
    RelinearizationRoundTwo = 0x1216,
    GaloisKeyShare = 0x1217,
    EvaluatorKeyAggregate = 0x1218,
    BallotValidity = 0x1302,
    PairedTargetShare = 0x1621,
}

impl ProofFamily {
    pub const ALL: [Self; 12] = [
        Self::SourceBatchedVerifiableSecretSharingLinkage,
        Self::AggregateThresholdShare,
        Self::SameSecretLinkage,
        Self::PublicKeyShare,
        Self::CollectivePublicKeyAggregate,
        Self::RelinearizationRoundOne,
        Self::RelinearizationRoundOneAggregate,
        Self::RelinearizationRoundTwo,
        Self::GaloisKeyShare,
        Self::EvaluatorKeyAggregate,
        Self::BallotValidity,
        Self::PairedTargetShare,
    ];

    pub const fn statement_schema_identifier(self) -> u16 {
        self as u16
    }

    pub const fn from_statement_schema_identifier(identifier: u16) -> Option<Self> {
        match identifier {
            0x2110 => Some(Self::SourceBatchedVerifiableSecretSharingLinkage),
            0x2111 => Some(Self::AggregateThresholdShare),
            0x1211 => Some(Self::SameSecretLinkage),
            0x1212 => Some(Self::PublicKeyShare),
            0x1213 => Some(Self::CollectivePublicKeyAggregate),
            0x1214 => Some(Self::RelinearizationRoundOne),
            0x1215 => Some(Self::RelinearizationRoundOneAggregate),
            0x1216 => Some(Self::RelinearizationRoundTwo),
            0x1217 => Some(Self::GaloisKeyShare),
            0x1218 => Some(Self::EvaluatorKeyAggregate),
            0x1302 => Some(Self::BallotValidity),
            0x1621 => Some(Self::PairedTargetShare),
            _ => None,
        }
    }

    const fn profile_index(self) -> usize {
        match self {
            Self::SourceBatchedVerifiableSecretSharingLinkage => 0,
            Self::AggregateThresholdShare => 1,
            Self::SameSecretLinkage => 2,
            Self::PublicKeyShare => 3,
            Self::CollectivePublicKeyAggregate => 4,
            Self::RelinearizationRoundOne => 5,
            Self::RelinearizationRoundOneAggregate => 6,
            Self::RelinearizationRoundTwo => 7,
            Self::GaloisKeyShare => 8,
            Self::EvaluatorKeyAggregate => 9,
            Self::BallotValidity => 10,
            Self::PairedTargetShare => 11,
        }
    }
}

/// One exact application slot. The enum shape prevents a caller from supplying
/// optional coordinates that do not belong to the selected proof family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProofApplicationSlot {
    SourceBatchedVerifiableSecretSharingLinkage {
        dealer_position: u16,
    },
    AggregateThresholdShare {
        recipient_position: u16,
    },
    SameSecretLinkage {
        trustee_position: u16,
    },
    PublicKeyShare {
        trustee_position: u16,
    },
    CollectivePublicKeyAggregate,
    RelinearizationRoundOne {
        trustee_position: u16,
        relinearization_position: u16,
    },
    RelinearizationRoundOneAggregate {
        relinearization_position: u16,
    },
    RelinearizationRoundTwo {
        trustee_position: u16,
        relinearization_position: u16,
    },
    GaloisKeyShare {
        trustee_position: u16,
        galois_position: u16,
    },
    EvaluatorKeyAggregate,
    BallotValidity {
        candidate_ordinal: u32,
    },
    PairedTargetShare {
        trustee_position: u16,
    },
}

impl ProofApplicationSlot {
    pub const fn family(self) -> ProofFamily {
        match self {
            Self::SourceBatchedVerifiableSecretSharingLinkage { .. } => {
                ProofFamily::SourceBatchedVerifiableSecretSharingLinkage
            }
            Self::AggregateThresholdShare { .. } => ProofFamily::AggregateThresholdShare,
            Self::SameSecretLinkage { .. } => ProofFamily::SameSecretLinkage,
            Self::PublicKeyShare { .. } => ProofFamily::PublicKeyShare,
            Self::CollectivePublicKeyAggregate => ProofFamily::CollectivePublicKeyAggregate,
            Self::RelinearizationRoundOne { .. } => ProofFamily::RelinearizationRoundOne,
            Self::RelinearizationRoundOneAggregate { .. } => {
                ProofFamily::RelinearizationRoundOneAggregate
            }
            Self::RelinearizationRoundTwo { .. } => ProofFamily::RelinearizationRoundTwo,
            Self::GaloisKeyShare { .. } => ProofFamily::GaloisKeyShare,
            Self::EvaluatorKeyAggregate => ProofFamily::EvaluatorKeyAggregate,
            Self::BallotValidity { .. } => ProofFamily::BallotValidity,
            Self::PairedTargetShare { .. } => ProofFamily::PairedTargetShare,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofFamilyByteCeiling {
    pub family: ProofFamily,
    pub maximum_complete_proof_byte_length: u64,
}

/// Verifier-derived proof multiplicities and generated complete-byte ceilings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofAttemptProfile {
    roster_size: u16,
    relinearization_position_count: u16,
    galois_position_count: u16,
    maximum_candidate_packages_per_action: u32,
    maximum_target_share_submissions: u16,
    maximum_proof_objects_per_action: u32,
    maximum_proof_bytes_per_action: u64,
    family_byte_ceilings: [u64; 12],
}

impl ProofAttemptProfile {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        roster_size: u16,
        relinearization_position_count: u16,
        galois_position_count: u16,
        maximum_candidate_packages_per_action: u32,
        maximum_target_share_submissions: u16,
        maximum_proof_objects_per_action: u32,
        maximum_proof_bytes_per_action: u64,
        ordered_family_byte_ceilings: [ProofFamilyByteCeiling; 12],
    ) -> Result<Self, RefusalReason> {
        if roster_size == 0
            || relinearization_position_count == 0
            || galois_position_count == 0
            || maximum_candidate_packages_per_action < u32::from(roster_size)
            || maximum_target_share_submissions != roster_size
        {
            return Err(RefusalReason::OutsideSupportedProfile);
        }

        let mut family_byte_ceilings = [0u64; 12];
        for (index, entry) in ordered_family_byte_ceilings.into_iter().enumerate() {
            if entry.family != ProofFamily::ALL[index]
                || entry.maximum_complete_proof_byte_length == 0
            {
                return Err(RefusalReason::OutsideSupportedProfile);
            }
            family_byte_ceilings[index] = entry.maximum_complete_proof_byte_length;
        }

        let profile = Self {
            roster_size,
            relinearization_position_count,
            galois_position_count,
            maximum_candidate_packages_per_action,
            maximum_target_share_submissions,
            maximum_proof_objects_per_action,
            maximum_proof_bytes_per_action,
            family_byte_ceilings,
        };
        if profile.derived_maximum_proof_object_count()?
            != u64::from(maximum_proof_objects_per_action)
            || profile.derived_maximum_proof_byte_length()? != maximum_proof_bytes_per_action
        {
            return Err(RefusalReason::OutsideSupportedProfile);
        }
        Ok(profile)
    }

    pub const fn maximum_proof_objects_per_action(&self) -> u32 {
        self.maximum_proof_objects_per_action
    }

    pub const fn maximum_proof_bytes_per_action(&self) -> u64 {
        self.maximum_proof_bytes_per_action
    }

    pub fn attempt_ceiling(&self, family: ProofFamily) -> Result<u64, RefusalReason> {
        let roster_size = u64::from(self.roster_size);
        let relinearization_position_count = u64::from(self.relinearization_position_count);
        let galois_position_count = u64::from(self.galois_position_count);
        match family {
            ProofFamily::SourceBatchedVerifiableSecretSharingLinkage
            | ProofFamily::AggregateThresholdShare
            | ProofFamily::SameSecretLinkage
            | ProofFamily::PublicKeyShare => Ok(roster_size),
            ProofFamily::CollectivePublicKeyAggregate | ProofFamily::EvaluatorKeyAggregate => Ok(1),
            ProofFamily::RelinearizationRoundOne | ProofFamily::RelinearizationRoundTwo => {
                roster_size
                    .checked_mul(relinearization_position_count)
                    .ok_or(RefusalReason::OutsideSupportedProfile)
            }
            ProofFamily::RelinearizationRoundOneAggregate => Ok(relinearization_position_count),
            ProofFamily::GaloisKeyShare => roster_size
                .checked_mul(galois_position_count)
                .ok_or(RefusalReason::OutsideSupportedProfile),
            ProofFamily::BallotValidity => {
                Ok(u64::from(self.maximum_candidate_packages_per_action))
            }
            ProofFamily::PairedTargetShare => Ok(u64::from(self.maximum_target_share_submissions)),
        }
    }

    pub const fn proof_byte_ceiling(&self, family: ProofFamily) -> u64 {
        self.family_byte_ceilings[family.profile_index()]
    }

    pub fn validate_slot(&self, slot: ProofApplicationSlot) -> Result<(), RefusalReason> {
        let participant_is_valid = |position: u16| position < self.roster_size;
        let relinearization_position_is_valid =
            |position: u16| position < self.relinearization_position_count;
        let valid = match slot {
            ProofApplicationSlot::SourceBatchedVerifiableSecretSharingLinkage {
                dealer_position,
            } => participant_is_valid(dealer_position),
            ProofApplicationSlot::AggregateThresholdShare { recipient_position } => {
                participant_is_valid(recipient_position)
            }
            ProofApplicationSlot::SameSecretLinkage { trustee_position }
            | ProofApplicationSlot::PublicKeyShare { trustee_position }
            | ProofApplicationSlot::PairedTargetShare { trustee_position } => {
                participant_is_valid(trustee_position)
            }
            ProofApplicationSlot::CollectivePublicKeyAggregate
            | ProofApplicationSlot::EvaluatorKeyAggregate => true,
            ProofApplicationSlot::RelinearizationRoundOne {
                trustee_position,
                relinearization_position,
            }
            | ProofApplicationSlot::RelinearizationRoundTwo {
                trustee_position,
                relinearization_position,
            } => {
                participant_is_valid(trustee_position)
                    && relinearization_position_is_valid(relinearization_position)
            }
            ProofApplicationSlot::RelinearizationRoundOneAggregate {
                relinearization_position,
            } => relinearization_position_is_valid(relinearization_position),
            ProofApplicationSlot::GaloisKeyShare {
                trustee_position,
                galois_position,
            } => {
                participant_is_valid(trustee_position)
                    && galois_position < self.galois_position_count
            }
            ProofApplicationSlot::BallotValidity { candidate_ordinal } => {
                candidate_ordinal < self.maximum_candidate_packages_per_action
            }
        };
        if valid {
            Ok(())
        } else {
            Err(RefusalReason::WrongContext)
        }
    }

    fn derived_maximum_proof_object_count(&self) -> Result<u64, RefusalReason> {
        ProofFamily::ALL
            .into_iter()
            .try_fold(0u64, |total, family| {
                total
                    .checked_add(self.attempt_ceiling(family)?)
                    .ok_or(RefusalReason::OutsideSupportedProfile)
            })
    }

    fn derived_maximum_proof_byte_length(&self) -> Result<u64, RefusalReason> {
        ProofFamily::ALL
            .into_iter()
            .try_fold(0u64, |total, family| {
                let family_total = self
                    .attempt_ceiling(family)?
                    .checked_mul(self.proof_byte_ceiling(family))
                    .ok_or(RefusalReason::OutsideSupportedProfile)?;
                total
                    .checked_add(family_total)
                    .ok_or(RefusalReason::OutsideSupportedProfile)
            })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProofAttemptState {
    Reserved,
    CryptographicVerificationBegan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProofAttemptRecord {
    proof_header_hash: Hash512,
    complete_proof_digest: Hash512,
    complete_proof_byte_length: u64,
    state: ProofAttemptState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofAttemptReservationDisposition {
    Reserved,
    ByteIdenticalReplay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofAttemptStartDisposition {
    BeginCryptographicVerification,
    AlreadyConsumed,
}

/// Process-local proof-attempt accounting. This core deliberately does not
/// claim durable authority; the browser transaction service must persist the
/// same state transition before it is used as a restart-safe protocol gate.
#[derive(Debug, Clone)]
pub struct EphemeralProofAttemptTracker {
    profile: ProofAttemptProfile,
    attempts: BTreeMap<ProofApplicationSlot, ProofAttemptRecord>,
    family_reserved_counts: [u64; 12],
    reserved_object_count: u32,
    reserved_byte_length: u64,
}

impl EphemeralProofAttemptTracker {
    pub fn new(profile: ProofAttemptProfile) -> Self {
        Self {
            profile,
            attempts: BTreeMap::new(),
            family_reserved_counts: [0; 12],
            reserved_object_count: 0,
            reserved_byte_length: 0,
        }
    }

    pub const fn reserved_object_count(&self) -> u32 {
        self.reserved_object_count
    }

    pub const fn reserved_byte_length(&self) -> u64 {
        self.reserved_byte_length
    }

    pub fn family_reserved_count(&self, family: ProofFamily) -> u64 {
        self.family_reserved_counts[family.profile_index()]
    }

    pub fn reserve(
        &mut self,
        slot: ProofApplicationSlot,
        proof_header_hash: Hash512,
        complete_proof_digest: Hash512,
        complete_proof_byte_length: u64,
    ) -> Result<ProofAttemptReservationDisposition, RefusalReason> {
        self.profile.validate_slot(slot)?;
        let family = slot.family();
        if complete_proof_byte_length == 0
            || complete_proof_byte_length > self.profile.proof_byte_ceiling(family)
        {
            return Err(RefusalReason::OutsideSupportedProfile);
        }

        if let Some(existing) = self.attempts.get(&slot) {
            return if existing.proof_header_hash == proof_header_hash
                && existing.complete_proof_digest == complete_proof_digest
                && existing.complete_proof_byte_length == complete_proof_byte_length
            {
                Ok(ProofAttemptReservationDisposition::ByteIdenticalReplay)
            } else {
                Err(RefusalReason::Equivocation)
            };
        }

        let family_index = family.profile_index();
        let next_family_count = self.family_reserved_counts[family_index]
            .checked_add(1)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        let next_object_count = self
            .reserved_object_count
            .checked_add(1)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        let next_byte_length = self
            .reserved_byte_length
            .checked_add(complete_proof_byte_length)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        if next_family_count > self.profile.attempt_ceiling(family)?
            || next_object_count > self.profile.maximum_proof_objects_per_action()
            || next_byte_length > self.profile.maximum_proof_bytes_per_action()
        {
            return Err(RefusalReason::OutsideSupportedProfile);
        }

        self.attempts.insert(
            slot,
            ProofAttemptRecord {
                proof_header_hash,
                complete_proof_digest,
                complete_proof_byte_length,
                state: ProofAttemptState::Reserved,
            },
        );
        self.family_reserved_counts[family_index] = next_family_count;
        self.reserved_object_count = next_object_count;
        self.reserved_byte_length = next_byte_length;
        Ok(ProofAttemptReservationDisposition::Reserved)
    }

    pub fn begin_cryptographic_verification(
        &mut self,
        slot: ProofApplicationSlot,
        proof_header_hash: Hash512,
        complete_proof_digest: Hash512,
        complete_proof_byte_length: u64,
    ) -> Result<ProofAttemptStartDisposition, RefusalReason> {
        let record = self
            .attempts
            .get_mut(&slot)
            .ok_or(RefusalReason::MissingPrerequisite)?;
        if record.proof_header_hash != proof_header_hash
            || record.complete_proof_digest != complete_proof_digest
            || record.complete_proof_byte_length != complete_proof_byte_length
        {
            return Err(RefusalReason::Equivocation);
        }
        match record.state {
            ProofAttemptState::Reserved => {
                record.state = ProofAttemptState::CryptographicVerificationBegan;
                Ok(ProofAttemptStartDisposition::BeginCryptographicVerification)
            }
            ProofAttemptState::CryptographicVerificationBegan => {
                Ok(ProofAttemptStartDisposition::AlreadyConsumed)
            }
        }
    }

    pub fn reserve_and_begin_cryptographic_verification(
        &mut self,
        slot: ProofApplicationSlot,
        proof_header_hash: Hash512,
        complete_proof_digest: Hash512,
        complete_proof_byte_length: u64,
    ) -> Result<ProofAttemptStartDisposition, RefusalReason> {
        self.reserve(
            slot,
            proof_header_hash,
            complete_proof_digest,
            complete_proof_byte_length,
        )?;
        self.begin_cryptographic_verification(
            slot,
            proof_header_hash,
            complete_proof_digest,
            complete_proof_byte_length,
        )
    }

    pub fn release_unstarted_reservation(
        &mut self,
        slot: ProofApplicationSlot,
        proof_header_hash: Hash512,
        complete_proof_digest: Hash512,
        complete_proof_byte_length: u64,
    ) -> Result<(), RefusalReason> {
        let record = self
            .attempts
            .get(&slot)
            .copied()
            .ok_or(RefusalReason::MissingPrerequisite)?;
        if record.proof_header_hash != proof_header_hash
            || record.complete_proof_digest != complete_proof_digest
            || record.complete_proof_byte_length != complete_proof_byte_length
        {
            return Err(RefusalReason::Equivocation);
        }
        if record.state == ProofAttemptState::CryptographicVerificationBegan {
            return Err(RefusalReason::ConsumedState);
        }

        self.attempts.remove(&slot);
        let family_index = slot.family().profile_index();
        self.family_reserved_counts[family_index] -= 1;
        self.reserved_object_count -= 1;
        self.reserved_byte_length -= complete_proof_byte_length;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ordered_byte_ceilings() -> [ProofFamilyByteCeiling; 12] {
        std::array::from_fn(|index| ProofFamilyByteCeiling {
            family: ProofFamily::ALL[index],
            maximum_complete_proof_byte_length: 101 + index as u64,
        })
    }

    fn profile() -> ProofAttemptProfile {
        let roster_size = 10;
        let relinearization_position_count = 4;
        let galois_position_count = 6;
        let maximum_candidate_packages_per_action = 20;
        let maximum_target_share_submissions = roster_size;
        let family_byte_ceilings = ordered_byte_ceilings();
        let temporary = ProofAttemptProfile {
            roster_size,
            relinearization_position_count,
            galois_position_count,
            maximum_candidate_packages_per_action,
            maximum_target_share_submissions,
            maximum_proof_objects_per_action: 0,
            maximum_proof_bytes_per_action: 0,
            family_byte_ceilings: family_byte_ceilings
                .map(|entry| entry.maximum_complete_proof_byte_length),
        };
        ProofAttemptProfile::new(
            roster_size,
            relinearization_position_count,
            galois_position_count,
            maximum_candidate_packages_per_action,
            maximum_target_share_submissions,
            u32::try_from(
                temporary
                    .derived_maximum_proof_object_count()
                    .expect("object count"),
            )
            .expect("test object count fits u32"),
            temporary
                .derived_maximum_proof_byte_length()
                .expect("byte length"),
            family_byte_ceilings,
        )
        .expect("profile is internally consistent")
    }

    fn hash(byte: u8) -> Hash512 {
        Hash512::from_bytes([byte; 64])
    }

    #[test]
    fn profile_derives_every_family_and_exact_global_equations() {
        let profile = profile();
        let expected_counts = [10, 10, 10, 10, 1, 40, 4, 40, 60, 1, 20, 10];
        for (family, expected_count) in ProofFamily::ALL.into_iter().zip(expected_counts) {
            assert_eq!(profile.attempt_ceiling(family), Ok(expected_count));
            assert_eq!(
                ProofFamily::from_statement_schema_identifier(family.statement_schema_identifier()),
                Some(family)
            );
        }
        assert_eq!(profile.maximum_proof_objects_per_action(), 216);
        assert_eq!(
            profile.maximum_proof_bytes_per_action(),
            ProofFamily::ALL
                .into_iter()
                .map(|family| {
                    profile.attempt_ceiling(family).expect("ceiling")
                        * profile.proof_byte_ceiling(family)
                })
                .sum::<u64>()
        );
        assert_eq!(ProofFamily::from_statement_schema_identifier(0), None);
    }

    #[test]
    fn inconsistent_caps_order_zero_values_and_overflow_refuse() {
        let valid = profile();
        let byte_ceilings = ordered_byte_ceilings();
        assert_eq!(
            ProofAttemptProfile::new(
                10,
                4,
                6,
                20,
                10,
                valid.maximum_proof_objects_per_action() - 1,
                valid.maximum_proof_bytes_per_action(),
                byte_ceilings,
            ),
            Err(RefusalReason::OutsideSupportedProfile)
        );

        let mut disordered = byte_ceilings;
        disordered.swap(0, 1);
        assert!(ProofAttemptProfile::new(10, 4, 6, 20, 10, 216, 1, disordered).is_err());
        let mut zero_bytes = byte_ceilings;
        zero_bytes[5].maximum_complete_proof_byte_length = 0;
        assert!(ProofAttemptProfile::new(10, 4, 6, 20, 10, 216, 1, zero_bytes).is_err());
        let huge = std::array::from_fn(|index| ProofFamilyByteCeiling {
            family: ProofFamily::ALL[index],
            maximum_complete_proof_byte_length: u64::MAX,
        });
        assert!(ProofAttemptProfile::new(10, 4, 6, 20, 10, 216, u64::MAX, huge).is_err());
        assert!(
            ProofAttemptProfile::new(
                u16::MAX,
                u16::MAX,
                u16::MAX,
                u32::MAX,
                u16::MAX,
                u32::MAX,
                u64::MAX,
                byte_ceilings,
            )
            .is_err()
        );
    }

    #[test]
    fn slot_coordinates_are_closed_and_bounded() {
        let profile = profile();
        let valid_slots = [
            ProofApplicationSlot::SourceBatchedVerifiableSecretSharingLinkage {
                dealer_position: 9,
            },
            ProofApplicationSlot::AggregateThresholdShare {
                recipient_position: 9,
            },
            ProofApplicationSlot::SameSecretLinkage {
                trustee_position: 9,
            },
            ProofApplicationSlot::PublicKeyShare {
                trustee_position: 9,
            },
            ProofApplicationSlot::CollectivePublicKeyAggregate,
            ProofApplicationSlot::RelinearizationRoundOne {
                trustee_position: 9,
                relinearization_position: 3,
            },
            ProofApplicationSlot::RelinearizationRoundOneAggregate {
                relinearization_position: 3,
            },
            ProofApplicationSlot::RelinearizationRoundTwo {
                trustee_position: 9,
                relinearization_position: 3,
            },
            ProofApplicationSlot::GaloisKeyShare {
                trustee_position: 9,
                galois_position: 5,
            },
            ProofApplicationSlot::EvaluatorKeyAggregate,
            ProofApplicationSlot::BallotValidity {
                candidate_ordinal: 19,
            },
            ProofApplicationSlot::PairedTargetShare {
                trustee_position: 9,
            },
        ];
        for slot in valid_slots {
            assert_eq!(profile.validate_slot(slot), Ok(()));
        }
        for slot in [
            ProofApplicationSlot::SameSecretLinkage {
                trustee_position: 10,
            },
            ProofApplicationSlot::RelinearizationRoundOne {
                trustee_position: 0,
                relinearization_position: 4,
            },
            ProofApplicationSlot::GaloisKeyShare {
                trustee_position: 0,
                galois_position: 6,
            },
            ProofApplicationSlot::BallotValidity {
                candidate_ordinal: 20,
            },
        ] {
            assert_eq!(
                profile.validate_slot(slot),
                Err(RefusalReason::WrongContext)
            );
        }
    }

    #[test]
    fn reservation_replay_equivocation_and_permanent_consumption_are_exact() {
        let profile = profile();
        let byte_length = profile.proof_byte_ceiling(ProofFamily::BallotValidity);
        let mut tracker = EphemeralProofAttemptTracker::new(profile);
        let slot = ProofApplicationSlot::BallotValidity {
            candidate_ordinal: 0,
        };
        assert_eq!(
            tracker.reserve(slot, hash(1), hash(11), byte_length),
            Ok(ProofAttemptReservationDisposition::Reserved)
        );
        assert_eq!(tracker.reserved_object_count(), 1);
        assert_eq!(tracker.reserved_byte_length(), byte_length);
        assert_eq!(
            tracker.reserve(slot, hash(1), hash(11), byte_length),
            Ok(ProofAttemptReservationDisposition::ByteIdenticalReplay)
        );
        assert_eq!(
            tracker.reserve(slot, hash(2), hash(11), byte_length),
            Err(RefusalReason::Equivocation)
        );
        assert_eq!(
            tracker.reserve(slot, hash(1), hash(12), byte_length),
            Err(RefusalReason::Equivocation)
        );
        assert_eq!(
            tracker.begin_cryptographic_verification(slot, hash(1), hash(11), byte_length),
            Ok(ProofAttemptStartDisposition::BeginCryptographicVerification)
        );
        assert_eq!(
            tracker.begin_cryptographic_verification(slot, hash(1), hash(11), byte_length),
            Ok(ProofAttemptStartDisposition::AlreadyConsumed)
        );
        assert_eq!(
            tracker.release_unstarted_reservation(slot, hash(1), hash(11), byte_length),
            Err(RefusalReason::ConsumedState)
        );
        assert_eq!(tracker.reserved_object_count(), 1);
    }

    #[test]
    fn unstarted_reservation_can_be_released_without_leaking_a_charge() {
        let profile = profile();
        let byte_length = profile.proof_byte_ceiling(ProofFamily::SameSecretLinkage);
        let mut tracker = EphemeralProofAttemptTracker::new(profile);
        let slot = ProofApplicationSlot::SameSecretLinkage {
            trustee_position: 3,
        };
        tracker
            .reserve(slot, hash(3), hash(13), byte_length)
            .expect("reserve");
        assert_eq!(
            tracker.release_unstarted_reservation(slot, hash(4), hash(13), byte_length),
            Err(RefusalReason::Equivocation)
        );
        tracker
            .release_unstarted_reservation(slot, hash(3), hash(13), byte_length)
            .expect("unstarted reservation releases");
        assert_eq!(tracker.reserved_object_count(), 0);
        assert_eq!(tracker.reserved_byte_length(), 0);
        assert_eq!(
            tracker.family_reserved_count(ProofFamily::SameSecretLinkage),
            0
        );
        assert_eq!(
            tracker.begin_cryptographic_verification(slot, hash(3), hash(13), byte_length),
            Err(RefusalReason::MissingPrerequisite)
        );
    }

    #[test]
    fn complete_family_slots_reach_but_do_not_exceed_their_derived_ceiling() {
        let profile = profile();
        let byte_length = profile.proof_byte_ceiling(ProofFamily::SameSecretLinkage);
        let mut tracker = EphemeralProofAttemptTracker::new(profile);
        for trustee_position in 0..10 {
            tracker
                .reserve_and_begin_cryptographic_verification(
                    ProofApplicationSlot::SameSecretLinkage { trustee_position },
                    hash(u8::try_from(trustee_position + 1).expect("position fits")),
                    hash(u8::try_from(trustee_position + 21).expect("position fits")),
                    byte_length,
                )
                .expect("derived slot accepts once");
        }
        assert_eq!(
            tracker.family_reserved_count(ProofFamily::SameSecretLinkage),
            10
        );
        assert_eq!(
            tracker.reserve(
                ProofApplicationSlot::SameSecretLinkage {
                    trustee_position: 10,
                },
                hash(100),
                hash(110),
                byte_length,
            ),
            Err(RefusalReason::WrongContext)
        );
        assert_eq!(
            tracker.reserve(
                ProofApplicationSlot::BallotValidity {
                    candidate_ordinal: 0,
                },
                hash(101),
                hash(111),
                tracker
                    .profile
                    .proof_byte_ceiling(ProofFamily::BallotValidity)
                    + 1,
            ),
            Err(RefusalReason::OutsideSupportedProfile)
        );
    }
}
