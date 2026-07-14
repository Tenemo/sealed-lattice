use super::schemas::{SchemaResult, read_hash, read_item, read_u16, require_header};
use super::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple, FOUNDATION_PROFILE,
    FoundationSchemaError, Hash512, RefusalReason, hash_foundation_tuple_512 as hash512,
};

pub const PROOF_APPLICATION_SLOT_SCHEMA_IDENTIFIER: u16 = 0x0109;
const FOUNDATION_SCHEMA_VERSION: u16 = 1;

const VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER: u16 = 0x2110;
const AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER: u16 = 0x2111;
const SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER: u16 = 0x1211;
const PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER: u16 = 0x1212;
const COLLECTIVE_PUBLIC_KEY_STATEMENT_SCHEMA_IDENTIFIER: u16 = 0x1213;
const RKG_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER: u16 = 0x1214;
const RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER: u16 = 0x1215;
const RKG_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER: u16 = 0x1216;
const GALOIS_SHARE_STATEMENT_SCHEMA_IDENTIFIER: u16 = 0x1217;
const EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER: u16 = 0x1218;
const BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER: u16 = 0x1302;
const TARGET_DECRYPTION_SHARE_STATEMENT_SCHEMA_IDENTIFIER: u16 = 0x1621;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofApplicationCoordinates {
    Participant {
        roster_position: u16,
    },
    Global,
    ParticipantSchedule {
        roster_position: u16,
        schedule_position: u32,
    },
    Schedule {
        schedule_position: u32,
    },
    BallotCandidate {
        roster_position: u16,
        producer_sequence: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofApplicationSlot {
    suite_id: Hash512,
    ceremony_context_hash: Hash512,
    action_context_hash: Hash512,
    application_statement_schema_identifier: u16,
    coordinates: ProofApplicationCoordinates,
}

impl ProofApplicationSlot {
    pub fn new(
        suite_id: Hash512,
        ceremony_context_hash: Hash512,
        action_context_hash: Hash512,
        application_statement_schema_identifier: u16,
        coordinates: ProofApplicationCoordinates,
    ) -> SchemaResult<Self> {
        validate_coordinates(application_statement_schema_identifier, coordinates)?;
        Ok(Self {
            suite_id,
            ceremony_context_hash,
            action_context_hash,
            application_statement_schema_identifier,
            coordinates,
        })
    }

    pub const fn suite_id(&self) -> Hash512 {
        self.suite_id
    }

    pub const fn ceremony_context_hash(&self) -> Hash512 {
        self.ceremony_context_hash
    }

    pub const fn action_context_hash(&self) -> Hash512 {
        self.action_context_hash
    }

    pub const fn application_statement_schema_identifier(&self) -> u16 {
        self.application_statement_schema_identifier
    }

    pub const fn coordinates(&self) -> ProofApplicationCoordinates {
        self.coordinates
    }

    pub(super) fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
        validate_coordinates(
            self.application_statement_schema_identifier,
            self.coordinates,
        )?;
        let (roster_position, schedule_position, producer_sequence) =
            optional_coordinate_values(self.coordinates);
        let roster_position_item = roster_position.map(CanonicalItem::unsigned16);
        let schedule_position_item = schedule_position.map(CanonicalItem::unsigned32);
        let producer_sequence_item = producer_sequence.map(CanonicalItem::unsigned64);

        Ok(CanonicalTuple::new(
            PROOF_APPLICATION_SLOT_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::hash512(self.suite_id.into_bytes()),
                CanonicalItem::hash512(self.ceremony_context_hash.into_bytes()),
                CanonicalItem::hash512(self.action_context_hash.into_bytes()),
                CanonicalItem::unsigned16(self.application_statement_schema_identifier),
                CanonicalItem::optional(
                    CanonicalItemType::Unsigned16,
                    roster_position_item.as_ref(),
                )?,
                CanonicalItem::optional(
                    CanonicalItemType::Unsigned32,
                    schedule_position_item.as_ref(),
                )?,
                CanonicalItem::optional(
                    CanonicalItemType::Unsigned64,
                    producer_sequence_item.as_ref(),
                )?,
            ],
        ))
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple()?.encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        require_header(&tuple, PROOF_APPLICATION_SLOT_SCHEMA_IDENTIFIER, 7)?;
        let application_statement_schema_identifier = read_u16(&tuple.items[3])?;
        let roster_position = read_optional_u16(&tuple.items[4])?;
        let schedule_position = read_optional_u32(&tuple.items[5])?;
        let producer_sequence = read_optional_u64(&tuple.items[6])?;
        let coordinates = coordinates_from_optional_values(
            application_statement_schema_identifier,
            roster_position,
            schedule_position,
            producer_sequence,
        )?;
        Self::new(
            read_hash(&tuple.items[0])?,
            read_hash(&tuple.items[1])?,
            read_hash(&tuple.items[2])?,
            application_statement_schema_identifier,
            coordinates,
        )
    }

    pub fn application_slot_hash(&self) -> SchemaResult<Hash512> {
        Ok(hash512(
            "sealed-lattice/proof/application-slot/v1",
            &[CanonicalItem::variable_bytes(self.encode()?)?],
        )?)
    }
}

fn optional_coordinate_values(
    coordinates: ProofApplicationCoordinates,
) -> (Option<u16>, Option<u32>, Option<u64>) {
    match coordinates {
        ProofApplicationCoordinates::Participant { roster_position } => {
            (Some(roster_position), None, None)
        }
        ProofApplicationCoordinates::Global => (None, None, None),
        ProofApplicationCoordinates::ParticipantSchedule {
            roster_position,
            schedule_position,
        } => (Some(roster_position), Some(schedule_position), None),
        ProofApplicationCoordinates::Schedule { schedule_position } => {
            (None, Some(schedule_position), None)
        }
        ProofApplicationCoordinates::BallotCandidate {
            roster_position,
            producer_sequence,
        } => (Some(roster_position), None, Some(producer_sequence)),
    }
}

fn validate_roster_position(roster_position: u16) -> SchemaResult<()> {
    if roster_position >= FOUNDATION_PROFILE.participant_count {
        return Err(FoundationSchemaError::new(
            RefusalReason::OutsideSupportedProfile,
            "proof application roster position is outside the frozen roster",
        ));
    }
    Ok(())
}

fn validate_coordinates(
    statement_schema_identifier: u16,
    coordinates: ProofApplicationCoordinates,
) -> SchemaResult<()> {
    let expected_coordinate_class = match statement_schema_identifier {
        VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER
        | AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER
        | SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER
        | PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER
        | TARGET_DECRYPTION_SHARE_STATEMENT_SCHEMA_IDENTIFIER => 1,
        COLLECTIVE_PUBLIC_KEY_STATEMENT_SCHEMA_IDENTIFIER
        | EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER => 2,
        RKG_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER
        | RKG_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER
        | GALOIS_SHARE_STATEMENT_SCHEMA_IDENTIFIER => 3,
        RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER => 4,
        BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER => 5,
        _ => {
            return Err(FoundationSchemaError::new(
                RefusalReason::WrongTypeOrLength,
                "proof application statement family is not assigned",
            ));
        }
    };
    let actual_coordinate_class = match coordinates {
        ProofApplicationCoordinates::Participant { roster_position } => {
            validate_roster_position(roster_position)?;
            1
        }
        ProofApplicationCoordinates::Global => 2,
        ProofApplicationCoordinates::ParticipantSchedule {
            roster_position, ..
        } => {
            validate_roster_position(roster_position)?;
            3
        }
        ProofApplicationCoordinates::Schedule { .. } => 4,
        ProofApplicationCoordinates::BallotCandidate {
            roster_position, ..
        } => {
            validate_roster_position(roster_position)?;
            5
        }
    };
    if actual_coordinate_class != expected_coordinate_class {
        return Err(FoundationSchemaError::new(
            RefusalReason::WrongTypeOrLength,
            "proof application coordinates do not match the statement family",
        ));
    }
    Ok(())
}

fn coordinates_from_optional_values(
    statement_schema_identifier: u16,
    roster_position: Option<u16>,
    schedule_position: Option<u32>,
    producer_sequence: Option<u64>,
) -> SchemaResult<ProofApplicationCoordinates> {
    let coordinates = match (roster_position, schedule_position, producer_sequence) {
        (Some(roster_position), None, None) => {
            ProofApplicationCoordinates::Participant { roster_position }
        }
        (None, None, None) => ProofApplicationCoordinates::Global,
        (Some(roster_position), Some(schedule_position), None) => {
            ProofApplicationCoordinates::ParticipantSchedule {
                roster_position,
                schedule_position,
            }
        }
        (None, Some(schedule_position), None) => {
            ProofApplicationCoordinates::Schedule { schedule_position }
        }
        (Some(roster_position), None, Some(producer_sequence)) => {
            ProofApplicationCoordinates::BallotCandidate {
                roster_position,
                producer_sequence,
            }
        }
        _ => {
            return Err(FoundationSchemaError::new(
                RefusalReason::WrongTypeOrLength,
                "proof application optional coordinates have an unassigned combination",
            ));
        }
    };
    validate_coordinates(statement_schema_identifier, coordinates)?;
    Ok(coordinates)
}

fn read_optional_fixed<const BYTE_LENGTH: usize>(
    item: &CanonicalItem,
    expected_type: CanonicalItemType,
) -> SchemaResult<Option<[u8; BYTE_LENGTH]>> {
    let bytes = read_item(item, CanonicalItemType::Optional)?;
    if bytes.len() < 3 || u16::from_le_bytes([bytes[0], bytes[1]]) != expected_type.canonical_code()
    {
        return Err(FoundationSchemaError::new(
            RefusalReason::WrongTypeOrLength,
            "proof application optional coordinate has the wrong contained type",
        ));
    }
    match bytes[2] {
        0 if bytes.len() == 3 => Ok(None),
        1 if bytes.len() == BYTE_LENGTH + 3 => {
            let value = bytes[3..].try_into().map_err(|_| {
                FoundationSchemaError::new(
                    RefusalReason::MalformedEncoding,
                    "proof application optional coordinate length is malformed",
                )
            })?;
            Ok(Some(value))
        }
        _ => Err(FoundationSchemaError::new(
            RefusalReason::MalformedEncoding,
            "proof application optional coordinate is malformed",
        )),
    }
}

fn read_optional_u16(item: &CanonicalItem) -> SchemaResult<Option<u16>> {
    Ok(read_optional_fixed::<2>(item, CanonicalItemType::Unsigned16)?.map(u16::from_le_bytes))
}

fn read_optional_u32(item: &CanonicalItem) -> SchemaResult<Option<u32>> {
    Ok(read_optional_fixed::<4>(item, CanonicalItemType::Unsigned32)?.map(u32::from_le_bytes))
}

fn read_optional_u64(item: &CanonicalItem) -> SchemaResult<Option<u64>> {
    Ok(read_optional_fixed::<8>(item, CanonicalItemType::Unsigned64)?.map(u64::from_le_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(fill: u8) -> Hash512 {
        Hash512::from_bytes([fill; Hash512::BYTE_LENGTH])
    }

    fn slot(
        statement_schema_identifier: u16,
        coordinates: ProofApplicationCoordinates,
    ) -> ProofApplicationSlot {
        ProofApplicationSlot::new(
            hash(0x11),
            hash(0x22),
            hash(0x33),
            statement_schema_identifier,
            coordinates,
        )
        .expect("test proof application slot is valid")
    }

    #[test]
    fn every_assigned_statement_family_round_trips_its_exact_coordinate_shape() {
        let assigned_slots = [
            slot(
                VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
                ProofApplicationCoordinates::Participant { roster_position: 0 },
            ),
            slot(
                AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
                ProofApplicationCoordinates::Participant { roster_position: 9 },
            ),
            slot(
                SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
                ProofApplicationCoordinates::Participant { roster_position: 4 },
            ),
            slot(
                PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
                ProofApplicationCoordinates::Participant { roster_position: 5 },
            ),
            slot(
                COLLECTIVE_PUBLIC_KEY_STATEMENT_SCHEMA_IDENTIFIER,
                ProofApplicationCoordinates::Global,
            ),
            slot(
                RKG_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER,
                ProofApplicationCoordinates::ParticipantSchedule {
                    roster_position: 1,
                    schedule_position: 19,
                },
            ),
            slot(
                RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
                ProofApplicationCoordinates::Schedule {
                    schedule_position: 20,
                },
            ),
            slot(
                RKG_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER,
                ProofApplicationCoordinates::ParticipantSchedule {
                    roster_position: 2,
                    schedule_position: 21,
                },
            ),
            slot(
                GALOIS_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
                ProofApplicationCoordinates::ParticipantSchedule {
                    roster_position: 3,
                    schedule_position: 22,
                },
            ),
            slot(
                EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
                ProofApplicationCoordinates::Global,
            ),
            slot(
                BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
                ProofApplicationCoordinates::BallotCandidate {
                    roster_position: 6,
                    producer_sequence: u64::MAX,
                },
            ),
            slot(
                TARGET_DECRYPTION_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
                ProofApplicationCoordinates::Participant { roster_position: 7 },
            ),
        ];

        for assigned_slot in assigned_slots {
            let bytes = assigned_slot.encode().expect("slot encodes");
            assert_eq!(
                ProofApplicationSlot::decode(&bytes, &CanonicalDecodeLimits::default())
                    .expect("slot decodes"),
                assigned_slot
            );
        }
    }

    #[test]
    fn unassigned_coordinate_shapes_and_roster_positions_refuse() {
        for invalid_slot in [
            ProofApplicationSlot::new(
                hash(1),
                hash(2),
                hash(3),
                COLLECTIVE_PUBLIC_KEY_STATEMENT_SCHEMA_IDENTIFIER,
                ProofApplicationCoordinates::Participant { roster_position: 0 },
            ),
            ProofApplicationSlot::new(
                hash(1),
                hash(2),
                hash(3),
                RKG_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER,
                ProofApplicationCoordinates::Schedule {
                    schedule_position: 0,
                },
            ),
            ProofApplicationSlot::new(
                hash(1),
                hash(2),
                hash(3),
                BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
                ProofApplicationCoordinates::BallotCandidate {
                    roster_position: FOUNDATION_PROFILE.participant_count,
                    producer_sequence: 0,
                },
            ),
            ProofApplicationSlot::new(
                hash(1),
                hash(2),
                hash(3),
                0xffff,
                ProofApplicationCoordinates::Global,
            ),
        ] {
            assert!(invalid_slot.is_err());
        }
    }

    #[test]
    fn every_bound_coordinate_changes_the_application_slot_hash() {
        let baseline = slot(
            BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
            ProofApplicationCoordinates::BallotCandidate {
                roster_position: 1,
                producer_sequence: 2,
            },
        );
        let changed_sequence = slot(
            BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
            ProofApplicationCoordinates::BallotCandidate {
                roster_position: 1,
                producer_sequence: 3,
            },
        );
        let changed_participant = slot(
            BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
            ProofApplicationCoordinates::BallotCandidate {
                roster_position: 2,
                producer_sequence: 2,
            },
        );
        assert_ne!(
            baseline.application_slot_hash().expect("hash"),
            changed_sequence.application_slot_hash().expect("hash")
        );
        assert_ne!(
            baseline.application_slot_hash().expect("hash"),
            changed_participant.application_slot_hash().expect("hash")
        );
    }

    #[test]
    fn trailing_and_truncated_slot_encodings_refuse() {
        let bytes = slot(
            SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
            ProofApplicationCoordinates::Participant { roster_position: 0 },
        )
        .encode()
        .expect("slot encodes");
        for truncated_length in [0, 1, bytes.len() - 1] {
            assert!(
                ProofApplicationSlot::decode(
                    &bytes[..truncated_length],
                    &CanonicalDecodeLimits::default(),
                )
                .is_err()
            );
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(
            ProofApplicationSlot::decode(&trailing, &CanonicalDecodeLimits::default()).is_err()
        );
    }
}
