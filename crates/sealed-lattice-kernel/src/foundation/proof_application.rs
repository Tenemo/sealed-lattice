use super::schemas::{SchemaResult, read_hash, require_header};
use super::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple, FoundationSchemaError,
    Hash512, ProofApplicationSlot, RefusalReason, StreamDescriptor, hash_foundation_tuple_512,
};

pub const PROOF_OBJECT_HEADER_SCHEMA_IDENTIFIER: u16 = 0x0102;
pub const PROOF_OBJECT_HEADER_SCHEMA_VERSION: u16 = 1;
pub const PROOF_APPLICATION_BINDING_SCHEMA_IDENTIFIER: u16 = 0x010a;

const FOUNDATION_SCHEMA_VERSION: u16 = 1;
const PROOF_HEADER_HASH_DOMAIN: &str = "sealed-lattice/proof/header/v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofObjectHeader {
    canonical_application_statement_bytes: Vec<u8>,
}

impl ProofObjectHeader {
    pub fn from_canonical_application_statement(
        canonical_application_statement_bytes: Vec<u8>,
        limits: &CanonicalDecodeLimits,
    ) -> SchemaResult<Self> {
        if canonical_application_statement_bytes.is_empty() {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "proof application statement must be nonempty",
            ));
        }
        let statement = CanonicalTuple::decode(&canonical_application_statement_bytes, limits)?;
        if statement.encode()? != canonical_application_statement_bytes {
            return Err(schema_error(
                RefusalReason::MalformedEncoding,
                "proof application statement is not canonical",
            ));
        }
        Ok(Self {
            canonical_application_statement_bytes,
        })
    }

    pub fn canonical_application_statement_bytes(&self) -> &[u8] {
        &self.canonical_application_statement_bytes
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple()?.encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        require_header(&tuple, PROOF_OBJECT_HEADER_SCHEMA_IDENTIFIER, 1)?;
        let statement_bytes = read_variable_bytes(&tuple.items[0])?.to_vec();
        Self::from_canonical_application_statement(statement_bytes, limits)
    }

    pub fn proof_header_hash(&self) -> SchemaResult<Hash512> {
        Ok(hash_foundation_tuple_512(
            PROOF_HEADER_HASH_DOMAIN,
            &[CanonicalItem::variable_bytes(self.encode()?)?],
        )?)
    }

    fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
        Ok(CanonicalTuple::new(
            PROOF_OBJECT_HEADER_SCHEMA_IDENTIFIER,
            PROOF_OBJECT_HEADER_SCHEMA_VERSION,
            vec![CanonicalItem::variable_bytes(
                &self.canonical_application_statement_bytes,
            )?],
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofApplicationBinding {
    application_slot: ProofApplicationSlot,
    proof_header_hash: Hash512,
    proof_stream_descriptor: StreamDescriptor,
}

impl ProofApplicationBinding {
    pub fn new(
        application_slot: ProofApplicationSlot,
        proof_header_hash: Hash512,
        proof_stream_descriptor: StreamDescriptor,
    ) -> SchemaResult<Self> {
        let _ = application_slot.canonical_tuple()?;
        let _ = proof_stream_descriptor.canonical_tuple()?;
        Ok(Self {
            application_slot,
            proof_header_hash,
            proof_stream_descriptor,
        })
    }

    pub const fn application_slot(&self) -> ProofApplicationSlot {
        self.application_slot
    }

    pub const fn proof_header_hash(&self) -> Hash512 {
        self.proof_header_hash
    }

    pub const fn proof_stream_descriptor(&self) -> &StreamDescriptor {
        &self.proof_stream_descriptor
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple()?.encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        require_header(&tuple, PROOF_APPLICATION_BINDING_SCHEMA_IDENTIFIER, 3)?;
        let application_slot_tuple = read_nested_tuple(&tuple.items[0], limits)?;
        let application_slot = ProofApplicationSlot::decode_tuple(&application_slot_tuple)?;
        let proof_header_hash = read_hash(&tuple.items[1])?;
        let stream_descriptor_tuple = read_nested_tuple(&tuple.items[2], limits)?;
        let proof_stream_descriptor = StreamDescriptor::from_tuple(&stream_descriptor_tuple)?;
        Self::new(application_slot, proof_header_hash, proof_stream_descriptor)
    }

    fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
        let application_slot_tuple = self.application_slot.canonical_tuple()?;
        Ok(CanonicalTuple::new(
            PROOF_APPLICATION_BINDING_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::nested_tuple(&application_slot_tuple)?,
                CanonicalItem::hash512(self.proof_header_hash.into_bytes()),
                CanonicalItem::nested_tuple(&self.proof_stream_descriptor.canonical_tuple()?)?,
            ],
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofFamilyApplicationCeiling {
    pub application_statement_schema_identifier: u16,
    pub application_slot_ceiling: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofFamilyApplicationInventoryEntry {
    application_statement_schema_identifier: u16,
    physical_proof_application_count: u32,
    logical_relation_instance_count: u32,
}

impl ProofFamilyApplicationInventoryEntry {
    pub const fn application_statement_schema_identifier(&self) -> u16 {
        self.application_statement_schema_identifier
    }

    pub const fn physical_proof_application_count(&self) -> u32 {
        self.physical_proof_application_count
    }

    pub const fn logical_relation_instance_count(&self) -> u32 {
        self.logical_relation_instance_count
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofFamilyApplicationInventory {
    ordered_family_entries: [ProofFamilyApplicationInventoryEntry; 12],
}

impl ProofFamilyApplicationInventory {
    pub const fn ordered_family_entries(&self) -> &[ProofFamilyApplicationInventoryEntry; 12] {
        &self.ordered_family_entries
    }

    pub fn family_entry(
        &self,
        application_statement_schema_identifier: u16,
    ) -> Option<&ProofFamilyApplicationInventoryEntry> {
        self.ordered_family_entries.iter().find(|family| {
            family.application_statement_schema_identifier
                == application_statement_schema_identifier
        })
    }

    pub fn total_physical_proof_application_count(&self) -> SchemaResult<u32> {
        self.ordered_family_entries
            .iter()
            .try_fold(0_u32, |total, family| {
                total
                    .checked_add(family.physical_proof_application_count)
                    .ok_or_else(proof_family_count_overflow)
            })
    }

    pub fn total_logical_relation_instance_count(&self) -> SchemaResult<u32> {
        self.ordered_family_entries
            .iter()
            .try_fold(0_u32, |total, family| {
                total
                    .checked_add(family.logical_relation_instance_count)
                    .ok_or_else(proof_family_count_overflow)
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofApplicationSlotCeilings {
    ordered_family_ceilings: [ProofFamilyApplicationCeiling; 12],
    total_application_slot_ceiling: u32,
}

impl ProofApplicationSlotCeilings {
    pub(crate) const SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER: u16 = 0x1211;
    pub(crate) const PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER: u16 = 0x1212;
    pub(crate) const COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER: u16 = 0x1213;
    pub(crate) const RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER: u16 = 0x1214;
    pub(crate) const RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER: u16 = 0x1215;
    pub(crate) const RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER: u16 = 0x1216;
    pub(crate) const GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER: u16 = 0x1217;
    pub(crate) const EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER: u16 = 0x1218;
    pub(crate) const BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER: u16 = 0x1302;
    pub(crate) const TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER: u16 = 0x1621;
    pub(crate) const VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER: u16 = 0x2110;
    pub(crate) const AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER: u16 = 0x2111;

    pub(crate) const PUBLIC_ONLY_FAMILY_SCHEMA_IDENTIFIERS: [u16; 3] = [
        Self::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        Self::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        Self::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
    ];

    pub(crate) const SECRET_BEARING_FAMILY_SCHEMA_IDENTIFIERS: [u16; 9] = [
        Self::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
        Self::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
        Self::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER,
        Self::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER,
        Self::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
        Self::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
        Self::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER,
        Self::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
        Self::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
    ];

    pub fn derive(
        roster_size: u16,
        selected_relinearization_position_count: u32,
        selected_galois_batch_count: u32,
        maximum_candidate_packages_per_action: u32,
    ) -> SchemaResult<Self> {
        if roster_size == 0
            || selected_relinearization_position_count == 0
            || selected_galois_batch_count == 0
            || maximum_candidate_packages_per_action == 0
        {
            return Err(schema_error(
                RefusalReason::OutsideSupportedProfile,
                "proof application slot inputs must be positive",
            ));
        }

        let roster_size = u32::from(roster_size);
        let relinearization_trustee_slot_count = roster_size
            .checked_mul(selected_relinearization_position_count)
            .ok_or_else(proof_family_count_overflow)?;
        let galois_trustee_slot_count = roster_size
            .checked_mul(selected_galois_batch_count)
            .ok_or_else(proof_family_count_overflow)?;
        let ordered_family_ceilings = [
            family_ceiling(
                Self::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
                roster_size,
            ),
            family_ceiling(
                Self::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
                roster_size,
            ),
            family_ceiling(Self::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER, roster_size),
            family_ceiling(
                Self::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
                roster_size,
            ),
            family_ceiling(
                Self::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
                1,
            ),
            family_ceiling(
                Self::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER,
                relinearization_trustee_slot_count,
            ),
            family_ceiling(
                Self::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
                selected_relinearization_position_count,
            ),
            family_ceiling(
                Self::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER,
                relinearization_trustee_slot_count,
            ),
            family_ceiling(
                Self::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
                galois_trustee_slot_count,
            ),
            family_ceiling(Self::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER, 1),
            family_ceiling(
                Self::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
                maximum_candidate_packages_per_action,
            ),
            family_ceiling(
                Self::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER,
                roster_size,
            ),
        ];
        let total_application_slot_ceiling =
            ordered_family_ceilings
                .iter()
                .try_fold(0_u32, |total, family| {
                    total
                        .checked_add(family.application_slot_ceiling)
                        .ok_or_else(proof_family_count_overflow)
                })?;
        Ok(Self {
            ordered_family_ceilings,
            total_application_slot_ceiling,
        })
    }

    pub const fn ordered_family_ceilings(&self) -> &[ProofFamilyApplicationCeiling; 12] {
        &self.ordered_family_ceilings
    }

    pub const fn total_application_slot_ceiling(&self) -> u32 {
        self.total_application_slot_ceiling
    }

    /// Derives the lifecycle-ordered physical and logical proof-family inventory.
    pub fn derive_proof_family_application_inventory(
        &self,
        galois_key_share_relation_instance_count_per_batch: u32,
        evaluator_key_aggregate_relation_instance_count_per_proof: u32,
    ) -> SchemaResult<ProofFamilyApplicationInventory> {
        if galois_key_share_relation_instance_count_per_batch == 0
            || evaluator_key_aggregate_relation_instance_count_per_proof == 0
        {
            return Err(schema_error(
                RefusalReason::OutsideSupportedProfile,
                "proof-family logical expansion counts must be positive",
            ));
        }

        let empty_family_entry = ProofFamilyApplicationInventoryEntry {
            application_statement_schema_identifier: 0,
            physical_proof_application_count: 0,
            logical_relation_instance_count: 0,
        };
        let mut ordered_family_entries = [empty_family_entry; 12];
        for (family_index, family) in self.ordered_family_ceilings.iter().enumerate() {
            let logical_relation_instance_count_per_proof =
                match family.application_statement_schema_identifier {
                    Self::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER => {
                        galois_key_share_relation_instance_count_per_batch
                    }
                    Self::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER => {
                        evaluator_key_aggregate_relation_instance_count_per_proof
                    }
                    _ => 1,
                };
            let logical_relation_instance_count = family
                .application_slot_ceiling
                .checked_mul(logical_relation_instance_count_per_proof)
                .ok_or_else(proof_family_count_overflow)?;
            ordered_family_entries[family_index] = ProofFamilyApplicationInventoryEntry {
                application_statement_schema_identifier: family
                    .application_statement_schema_identifier,
                physical_proof_application_count: family.application_slot_ceiling,
                logical_relation_instance_count,
            };
        }
        let inventory = ProofFamilyApplicationInventory {
            ordered_family_entries,
        };
        let _ = inventory.total_physical_proof_application_count()?;
        let _ = inventory.total_logical_relation_instance_count()?;
        Ok(inventory)
    }

    pub fn family_ceiling(&self, application_statement_schema_identifier: u16) -> Option<u32> {
        self.ordered_family_ceilings
            .iter()
            .find(|family| {
                family.application_statement_schema_identifier
                    == application_statement_schema_identifier
            })
            .map(|family| family.application_slot_ceiling)
    }
}

const fn family_ceiling(
    application_statement_schema_identifier: u16,
    application_slot_ceiling: u32,
) -> ProofFamilyApplicationCeiling {
    ProofFamilyApplicationCeiling {
        application_statement_schema_identifier,
        application_slot_ceiling,
    }
}

fn read_variable_bytes(item: &CanonicalItem) -> SchemaResult<&[u8]> {
    if item.item_type() != CanonicalItemType::RawBytes {
        return Err(schema_error(
            RefusalReason::WrongTypeOrLength,
            "proof header statement has the wrong canonical item type",
        ));
    }
    let bytes = item.canonical_bytes();
    if bytes.len() < 4 {
        return Err(schema_error(
            RefusalReason::MalformedEncoding,
            "proof header statement length is truncated",
        ));
    }
    let declared_byte_length = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    if usize::try_from(declared_byte_length).ok() != Some(bytes.len() - 4) {
        return Err(schema_error(
            RefusalReason::MalformedEncoding,
            "proof header statement length is malformed",
        ));
    }
    Ok(&bytes[4..])
}

fn read_nested_tuple(
    item: &CanonicalItem,
    limits: &CanonicalDecodeLimits,
) -> SchemaResult<CanonicalTuple> {
    if item.item_type() != CanonicalItemType::NestedTuple {
        return Err(schema_error(
            RefusalReason::WrongTypeOrLength,
            "proof application binding has the wrong nested item type",
        ));
    }
    Ok(CanonicalTuple::decode(item.canonical_bytes(), limits)?)
}

const fn schema_error(
    refusal_reason: RefusalReason,
    message: &'static str,
) -> FoundationSchemaError {
    FoundationSchemaError {
        refusal_reason,
        message,
    }
}

const fn proof_family_count_overflow() -> FoundationSchemaError {
    schema_error(
        RefusalReason::OutsideSupportedProfile,
        "proof-family count overflows the supported counter",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn application_statement() -> Vec<u8> {
        CanonicalTuple::new(0x2110, 1, vec![CanonicalItem::unsigned16(7)])
            .encode()
            .expect("application statement encodes")
    }

    fn application_slot() -> ProofApplicationSlot {
        ProofApplicationSlot::new(
            Hash512::from_bytes([0x11; 64]),
            Hash512::from_bytes([0x22; 64]),
            Hash512::from_bytes([0x33; 64]),
            0x2110,
            Some(2),
            None,
            None,
        )
        .expect("application slot is valid")
    }

    #[test]
    fn proof_header_and_binding_round_trip_canonically() {
        let limits = CanonicalDecodeLimits::default();
        let header = ProofObjectHeader::from_canonical_application_statement(
            application_statement(),
            &limits,
        )
        .expect("proof header is valid");
        let header_bytes = header.encode().expect("proof header encodes");
        assert_eq!(
            ProofObjectHeader::decode(&header_bytes, &limits).expect("proof header decodes"),
            header
        );

        let binding = ProofApplicationBinding::new(
            application_slot(),
            header.proof_header_hash().expect("proof header hashes"),
            StreamDescriptor::new(
                1,
                vec![Hash512::from_bytes([0x44; 64])],
                Hash512::from_bytes([0x45; 64]),
            )
            .expect("proof descriptor is valid"),
        )
        .expect("proof binding is valid");
        let binding_bytes = binding.encode().expect("proof binding encodes");
        assert_eq!(
            ProofApplicationBinding::decode(&binding_bytes, &limits)
                .expect("proof binding decodes"),
            binding
        );
    }

    #[test]
    fn proof_header_rejects_a_noncanonical_statement_or_wrong_item_type() {
        let limits = CanonicalDecodeLimits::default();
        assert!(ProofObjectHeader::from_canonical_application_statement(vec![], &limits).is_err());

        let malformed_statement = vec![0_u8; 7];
        assert!(
            ProofObjectHeader::from_canonical_application_statement(malformed_statement, &limits,)
                .is_err()
        );

        let wrong_item = CanonicalTuple::new(
            PROOF_OBJECT_HEADER_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![CanonicalItem::unsigned16(3)],
        )
        .encode()
        .expect("wrongly typed header encodes");
        assert!(ProofObjectHeader::decode(&wrong_item, &limits).is_err());
    }

    #[test]
    fn family_slot_ceilings_follow_the_complete_action_equation() {
        let ceilings =
            ProofApplicationSlotCeilings::derive(5, 3, 4, 17).expect("slot ceilings derive");
        let expected = [
            (0x2110, 5),
            (0x2111, 5),
            (0x1211, 5),
            (0x1212, 5),
            (0x1213, 1),
            (0x1214, 15),
            (0x1215, 3),
            (0x1216, 15),
            (0x1217, 20),
            (0x1218, 1),
            (0x1302, 17),
            (0x1621, 5),
        ];
        for (family, ceiling) in expected {
            assert_eq!(ceilings.family_ceiling(family), Some(ceiling));
        }
        assert_eq!(ceilings.total_application_slot_ceiling(), 97);
        let inventory = ceilings
            .derive_proof_family_application_inventory(6, 7)
            .expect("proof-family application inventory derives");
        assert_eq!(
            inventory
                .total_physical_proof_application_count()
                .expect("physical proof-application total derives"),
            97
        );
        assert_eq!(
            inventory
                .total_logical_relation_instance_count()
                .expect("logical relation-instance total derives"),
            203
        );
        assert_eq!(ceilings.family_ceiling(0xffff), None);
    }

    #[test]
    fn selected_proof_family_inventory_derives_every_physical_and_logical_count() {
        let ceilings = ProofApplicationSlotCeilings::derive(
            crate::foundation::FOUNDATION_PROFILE.participant_count,
            1,
            1,
            crate::foundation::SELECTED_MAXIMUM_CANDIDATE_PACKAGES_PER_ACTION,
        )
        .expect("selected proof-family ceilings derive");
        let inventory = ceilings
            .derive_proof_family_application_inventory(6, 7)
            .expect("selected proof-family inventory derives");
        assert_eq!(
            inventory.ordered_family_entries().map(|family| {
                (
                    family.application_statement_schema_identifier(),
                    family.physical_proof_application_count(),
                    family.logical_relation_instance_count(),
                )
            }),
            [
                (0x2110, 10, 10),
                (0x2111, 10, 10),
                (0x1211, 10, 10),
                (0x1212, 10, 10),
                (0x1213, 1, 1),
                (0x1214, 10, 10),
                (0x1215, 1, 1),
                (0x1216, 10, 10),
                (0x1217, 10, 60),
                (0x1218, 1, 7),
                (0x1302, 20, 20),
                (0x1621, 10, 10),
            ]
        );
        assert_eq!(
            inventory
                .total_physical_proof_application_count()
                .expect("selected physical proof-application total derives"),
            103
        );
        assert_eq!(
            inventory
                .total_logical_relation_instance_count()
                .expect("selected logical relation-instance total derives"),
            159
        );
    }

    #[test]
    fn proof_family_inventory_is_structural_for_every_roster_size() {
        for roster_size in 3_u16..=20 {
            let maximum_candidate_packages_per_action = u32::from(roster_size) * 2;
            let ceilings = ProofApplicationSlotCeilings::derive(
                roster_size,
                1,
                1,
                maximum_candidate_packages_per_action,
            )
            .expect("structural proof-family ceilings derive");
            let inventory = ceilings
                .derive_proof_family_application_inventory(6, 7)
                .expect("structural proof-family inventory derives");
            let roster_size = u32::from(roster_size);
            assert_eq!(
                inventory.ordered_family_entries().map(|family| (
                    family.physical_proof_application_count(),
                    family.logical_relation_instance_count(),
                )),
                [
                    (roster_size, roster_size),
                    (roster_size, roster_size),
                    (roster_size, roster_size),
                    (roster_size, roster_size),
                    (1, 1),
                    (roster_size, roster_size),
                    (1, 1),
                    (roster_size, roster_size),
                    (roster_size, roster_size * 6),
                    (1, 7),
                    (
                        maximum_candidate_packages_per_action,
                        maximum_candidate_packages_per_action,
                    ),
                    (roster_size, roster_size),
                ]
            );
            assert_eq!(
                inventory
                    .total_physical_proof_application_count()
                    .expect("structural physical proof-application total derives"),
                roster_size * 10 + 3
            );
            assert_eq!(
                inventory
                    .total_logical_relation_instance_count()
                    .expect("structural logical relation-instance total derives"),
                roster_size * 15 + 9
            );
        }
    }

    #[test]
    fn proof_family_inventory_rejects_zero_and_overflow() {
        for invalid_inputs in [(0, 1, 1, 1), (1, 0, 1, 1), (1, 1, 0, 1), (1, 1, 1, 0)] {
            assert_eq!(
                ProofApplicationSlotCeilings::derive(
                    invalid_inputs.0,
                    invalid_inputs.1,
                    invalid_inputs.2,
                    invalid_inputs.3,
                )
                .expect_err("zero proof-family input must be rejected")
                .refusal_reason,
                RefusalReason::OutsideSupportedProfile
            );
        }

        for hostile_inputs in [
            (u16::MAX, u32::MAX, 1, 1),
            (u16::MAX, 1, u32::MAX, 1),
            (u16::MAX, 1, 1, u32::MAX),
        ] {
            assert_eq!(
                ProofApplicationSlotCeilings::derive(
                    hostile_inputs.0,
                    hostile_inputs.1,
                    hostile_inputs.2,
                    hostile_inputs.3,
                )
                .expect_err("overflowing proof-family input must be rejected")
                .refusal_reason,
                RefusalReason::OutsideSupportedProfile
            );
        }

        let ceilings = ProofApplicationSlotCeilings::derive(1, 1, 1, 1)
            .expect("minimal proof-family ceilings derive");
        for invalid_expansion_counts in [(0, 1), (1, 0)] {
            assert_eq!(
                ceilings
                    .derive_proof_family_application_inventory(
                        invalid_expansion_counts.0,
                        invalid_expansion_counts.1,
                    )
                    .expect_err("zero logical expansion count must be rejected")
                    .refusal_reason,
                RefusalReason::OutsideSupportedProfile
            );
        }
        for hostile_expansion_counts in [(u32::MAX, 1), (1, u32::MAX)] {
            assert_eq!(
                ceilings
                    .derive_proof_family_application_inventory(
                        hostile_expansion_counts.0,
                        hostile_expansion_counts.1,
                    )
                    .expect_err("overflowing logical inventory must be rejected")
                    .refusal_reason,
                RefusalReason::OutsideSupportedProfile
            );
        }
    }
}
