use super::canonical_tuple::CanonicalDecodeBudget;
use super::schemas::{
    FoundationSchemaError, SchemaResult, optional_u16, optional_u32, optional_u64,
    read_fixed_bytes, read_hash, read_nested_tuple_with_budget, read_optional_u16,
    read_optional_u32, read_optional_u64, read_u16, require_header,
};
use super::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalTuple, FOUNDATION_PROFILE, Hash512, ProofFamily,
    ProofPrivateCoinClassification, RefusalReason, StreamDescriptor, hash512,
};

pub const PROOF_APPLICATION_SLOT_SCHEMA_IDENTIFIER: u16 = 0x0109;
pub const PROOF_APPLICATION_BINDING_SCHEMA_IDENTIFIER: u16 = 0x010a;
pub const PERSISTENT_PROOF_COIN_INPUT_SCHEMA_IDENTIFIER: u16 = 0x0401;
pub const ORDINARY_PROOF_COIN_INPUT_SCHEMA_IDENTIFIER: u16 = 0x0403;

const PROOF_APPLICATION_SCHEMA_VERSION: u16 = 1;
const ORDINARY_PROOF_ATTEMPT_NONCE_BYTE_LENGTH: usize = 32;

/// Canonical verifier-derived coordinates for one proof-family application.
///
/// Construction closes the family-specific optional-field grammar and the
/// fixed roster bound. The owning verifier must additionally derive the exact
/// schedule position and producer sequence from the accepted suite, action,
/// and carrier instead of trusting decoded values.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProofApplicationSlot {
    protocol_version: u16,
    suite_id: Hash512,
    ceremony_context_hash: Hash512,
    action_context_hash: Hash512,
    proof_family: ProofFamily,
    roster_position: Option<u16>,
    schedule_position: Option<u32>,
    producer_sequence: Option<u64>,
}

impl ProofApplicationSlot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        protocol_version: u16,
        suite_id: Hash512,
        ceremony_context_hash: Hash512,
        action_context_hash: Hash512,
        proof_family: ProofFamily,
        roster_position: Option<u16>,
        schedule_position: Option<u32>,
        producer_sequence: Option<u64>,
    ) -> SchemaResult<Self> {
        if protocol_version != FOUNDATION_PROFILE.protocol_version {
            return Err(schema_error(
                RefusalReason::WrongContext,
                "proof application slot has an unsupported protocol version",
            ));
        }
        if roster_position.is_some_and(|position| position >= FOUNDATION_PROFILE.participant_count)
        {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "proof application roster position is outside the foundation profile",
            ));
        }

        let coordinates_are_valid = match proof_family {
            ProofFamily::SourceBatchedVerifiableSecretSharingLinkage
            | ProofFamily::AggregateThresholdShare
            | ProofFamily::SameSecretLinkage
            | ProofFamily::PublicKeyShare
            | ProofFamily::PairedTargetShare => {
                roster_position.is_some()
                    && schedule_position.is_none()
                    && producer_sequence.is_none()
            }
            ProofFamily::CollectivePublicKeyAggregate | ProofFamily::EvaluatorKeyAggregate => {
                roster_position.is_none()
                    && schedule_position.is_none()
                    && producer_sequence.is_none()
            }
            ProofFamily::RelinearizationRoundOne
            | ProofFamily::RelinearizationRoundTwo
            | ProofFamily::GaloisKeyShare => {
                roster_position.is_some()
                    && schedule_position.is_some()
                    && producer_sequence.is_none()
            }
            ProofFamily::RelinearizationRoundOneAggregate => {
                roster_position.is_none()
                    && schedule_position.is_some()
                    && producer_sequence.is_none()
            }
            ProofFamily::BallotValidity => {
                roster_position.is_some()
                    && schedule_position.is_none()
                    && producer_sequence.is_some()
            }
        };
        if !coordinates_are_valid {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "proof application coordinates do not match the closed family grammar",
            ));
        }

        Ok(Self {
            protocol_version,
            suite_id,
            ceremony_context_hash,
            action_context_hash,
            proof_family,
            roster_position,
            schedule_position,
            producer_sequence,
        })
    }

    pub const fn protocol_version(&self) -> u16 {
        self.protocol_version
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

    pub const fn proof_family(&self) -> ProofFamily {
        self.proof_family
    }

    pub const fn roster_position(&self) -> Option<u16> {
        self.roster_position
    }

    pub const fn schedule_position(&self) -> Option<u32> {
        self.schedule_position
    }

    pub const fn producer_sequence(&self) -> Option<u64> {
        self.producer_sequence
    }

    fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
        Self::new(
            self.protocol_version,
            self.suite_id,
            self.ceremony_context_hash,
            self.action_context_hash,
            self.proof_family,
            self.roster_position,
            self.schedule_position,
            self.producer_sequence,
        )?;
        Ok(CanonicalTuple::new(
            PROOF_APPLICATION_SLOT_SCHEMA_IDENTIFIER,
            PROOF_APPLICATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.protocol_version),
                CanonicalItem::hash512(self.suite_id.into_bytes()),
                CanonicalItem::hash512(self.ceremony_context_hash.into_bytes()),
                CanonicalItem::hash512(self.action_context_hash.into_bytes()),
                CanonicalItem::unsigned16(self.proof_family.statement_schema_identifier()),
                optional_u16(self.roster_position)?,
                optional_u32(self.schedule_position)?,
                optional_u64(self.producer_sequence)?,
            ],
        ))
    }

    fn from_tuple(tuple: &CanonicalTuple) -> SchemaResult<Self> {
        require_header(tuple, PROOF_APPLICATION_SLOT_SCHEMA_IDENTIFIER, 8)?;
        let statement_schema_identifier = read_u16(&tuple.items[4])?;
        let proof_family = ProofFamily::from_statement_schema_identifier(
            statement_schema_identifier,
        )
        .ok_or_else(|| {
            schema_error(
                RefusalReason::WrongTypeOrLength,
                "proof application statement family is unassigned",
            )
        })?;
        Self::new(
            read_u16(&tuple.items[0])?,
            read_hash(&tuple.items[1])?,
            read_hash(&tuple.items[2])?,
            read_hash(&tuple.items[3])?,
            proof_family,
            read_optional_u16(&tuple.items[5])?,
            read_optional_u32(&tuple.items[6])?,
            read_optional_u64(&tuple.items[7])?,
        )
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple()?.encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        Self::from_tuple(&CanonicalTuple::decode(bytes, limits)?)
    }

    pub fn application_slot_hash(&self) -> SchemaResult<Hash512> {
        Ok(hash512(
            "sealed-lattice/proof/application-slot/v1",
            &[CanonicalItem::variable_bytes(self.encode()?)?],
        )?)
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
        ProofApplicationSlot::new(
            application_slot.protocol_version,
            application_slot.suite_id,
            application_slot.ceremony_context_hash,
            application_slot.action_context_hash,
            application_slot.proof_family,
            application_slot.roster_position,
            application_slot.schedule_position,
            application_slot.producer_sequence,
        )?;
        StreamDescriptor::new(
            proof_stream_descriptor.total_byte_length,
            proof_stream_descriptor.ordered_chunk_digests.clone(),
            proof_stream_descriptor.full_object_digest,
        )?;
        Ok(Self {
            application_slot,
            proof_header_hash,
            proof_stream_descriptor,
        })
    }

    pub const fn application_slot(&self) -> &ProofApplicationSlot {
        &self.application_slot
    }

    pub const fn proof_header_hash(&self) -> Hash512 {
        self.proof_header_hash
    }

    pub const fn proof_stream_descriptor(&self) -> &StreamDescriptor {
        &self.proof_stream_descriptor
    }

    fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
        Self::new(
            self.application_slot.clone(),
            self.proof_header_hash,
            self.proof_stream_descriptor.clone(),
        )?;
        Ok(CanonicalTuple::new(
            PROOF_APPLICATION_BINDING_SCHEMA_IDENTIFIER,
            PROOF_APPLICATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::nested_tuple(&self.application_slot.canonical_tuple()?)?,
                CanonicalItem::hash512(self.proof_header_hash.into_bytes()),
                CanonicalItem::nested_tuple(&self.proof_stream_descriptor.canonical_tuple()?)?,
            ],
        ))
    }

    fn from_tuple_with_budget(
        tuple: &CanonicalTuple,
        limits: &CanonicalDecodeLimits,
        budget: &mut CanonicalDecodeBudget,
    ) -> SchemaResult<Self> {
        require_header(tuple, PROOF_APPLICATION_BINDING_SCHEMA_IDENTIFIER, 3)?;
        let application_slot_tuple =
            read_nested_tuple_with_budget(&tuple.items[0], limits, budget)?;
        let stream_descriptor_tuple =
            read_nested_tuple_with_budget(&tuple.items[2], limits, budget)?;
        Self::new(
            ProofApplicationSlot::from_tuple(&application_slot_tuple)?,
            read_hash(&tuple.items[1])?,
            StreamDescriptor::from_tuple(&stream_descriptor_tuple)?,
        )
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple()?.encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let mut budget = CanonicalDecodeBudget::new(limits);
        let tuple = CanonicalTuple::decode_with_budget(bytes, limits, &mut budget)?;
        Self::from_tuple_with_budget(&tuple, limits, &mut budget)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistentProofCoinInput {
    application_slot: ProofApplicationSlot,
    application_statement_hash: Hash512,
}

impl PersistentProofCoinInput {
    pub fn new(
        application_slot: ProofApplicationSlot,
        application_statement_hash: Hash512,
    ) -> SchemaResult<Self> {
        if application_slot
            .proof_family()
            .private_coin_classification()
            != ProofPrivateCoinClassification::ResetSafeSecretBearing
        {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "persistent proof coins require a reset-safe secret-bearing family",
            ));
        }
        Ok(Self {
            application_slot,
            application_statement_hash,
        })
    }

    pub const fn application_slot(&self) -> &ProofApplicationSlot {
        &self.application_slot
    }

    pub const fn application_statement_hash(&self) -> Hash512 {
        self.application_statement_hash
    }

    fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
        Self::new(
            self.application_slot.clone(),
            self.application_statement_hash,
        )?;
        Ok(CanonicalTuple::new(
            PERSISTENT_PROOF_COIN_INPUT_SCHEMA_IDENTIFIER,
            PROOF_APPLICATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::nested_tuple(&self.application_slot.canonical_tuple()?)?,
                CanonicalItem::hash512(self.application_statement_hash.into_bytes()),
            ],
        ))
    }

    fn from_tuple_with_budget(
        tuple: &CanonicalTuple,
        limits: &CanonicalDecodeLimits,
        budget: &mut CanonicalDecodeBudget,
    ) -> SchemaResult<Self> {
        require_header(tuple, PERSISTENT_PROOF_COIN_INPUT_SCHEMA_IDENTIFIER, 2)?;
        let application_slot_tuple =
            read_nested_tuple_with_budget(&tuple.items[0], limits, budget)?;
        Self::new(
            ProofApplicationSlot::from_tuple(&application_slot_tuple)?,
            read_hash(&tuple.items[1])?,
        )
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple()?.encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let mut budget = CanonicalDecodeBudget::new(limits);
        let tuple = CanonicalTuple::decode_with_budget(bytes, limits, &mut budget)?;
        Self::from_tuple_with_budget(&tuple, limits, &mut budget)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrdinaryProofCoinInput {
    application_slot: ProofApplicationSlot,
    application_statement_hash: Hash512,
    ordinary_proof_attempt_nonce: [u8; ORDINARY_PROOF_ATTEMPT_NONCE_BYTE_LENGTH],
}

impl OrdinaryProofCoinInput {
    pub fn new(
        application_slot: ProofApplicationSlot,
        application_statement_hash: Hash512,
        ordinary_proof_attempt_nonce: [u8; ORDINARY_PROOF_ATTEMPT_NONCE_BYTE_LENGTH],
    ) -> SchemaResult<Self> {
        if application_slot
            .proof_family()
            .private_coin_classification()
            != ProofPrivateCoinClassification::OrdinarySecretBearing
        {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "ordinary proof coins require the ballot-validity family",
            ));
        }
        Ok(Self {
            application_slot,
            application_statement_hash,
            ordinary_proof_attempt_nonce,
        })
    }

    pub const fn application_slot(&self) -> &ProofApplicationSlot {
        &self.application_slot
    }

    pub const fn application_statement_hash(&self) -> Hash512 {
        self.application_statement_hash
    }

    pub const fn ordinary_proof_attempt_nonce(
        &self,
    ) -> &[u8; ORDINARY_PROOF_ATTEMPT_NONCE_BYTE_LENGTH] {
        &self.ordinary_proof_attempt_nonce
    }

    fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
        Self::new(
            self.application_slot.clone(),
            self.application_statement_hash,
            self.ordinary_proof_attempt_nonce,
        )?;
        Ok(CanonicalTuple::new(
            ORDINARY_PROOF_COIN_INPUT_SCHEMA_IDENTIFIER,
            PROOF_APPLICATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::nested_tuple(&self.application_slot.canonical_tuple()?)?,
                CanonicalItem::hash512(self.application_statement_hash.into_bytes()),
                CanonicalItem::fixed_bytes(self.ordinary_proof_attempt_nonce)?,
            ],
        ))
    }

    fn from_tuple_with_budget(
        tuple: &CanonicalTuple,
        limits: &CanonicalDecodeLimits,
        budget: &mut CanonicalDecodeBudget,
    ) -> SchemaResult<Self> {
        require_header(tuple, ORDINARY_PROOF_COIN_INPUT_SCHEMA_IDENTIFIER, 3)?;
        let application_slot_tuple =
            read_nested_tuple_with_budget(&tuple.items[0], limits, budget)?;
        Self::new(
            ProofApplicationSlot::from_tuple(&application_slot_tuple)?,
            read_hash(&tuple.items[1])?,
            read_fixed_bytes(&tuple.items[2])?,
        )
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple()?.encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let mut budget = CanonicalDecodeBudget::new(limits);
        let tuple = CanonicalTuple::decode_with_budget(bytes, limits, &mut budget)?;
        Self::from_tuple_with_budget(&tuple, limits, &mut budget)
    }
}

pub fn derive_application_statement_hash(
    canonical_application_statement_bytes: &[u8],
) -> SchemaResult<Hash512> {
    Ok(hash512(
        "sealed-lattice/proof/application-statement/v1",
        &[CanonicalItem::variable_bytes(
            canonical_application_statement_bytes,
        )?],
    )?)
}

fn schema_error(refusal_reason: RefusalReason, message: &'static str) -> FoundationSchemaError {
    FoundationSchemaError::new(refusal_reason, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slot_for_family(proof_family: ProofFamily) -> ProofApplicationSlot {
        let (roster_position, schedule_position, producer_sequence) = match proof_family {
            ProofFamily::SourceBatchedVerifiableSecretSharingLinkage
            | ProofFamily::AggregateThresholdShare
            | ProofFamily::SameSecretLinkage
            | ProofFamily::PublicKeyShare
            | ProofFamily::PairedTargetShare => (Some(2), None, None),
            ProofFamily::CollectivePublicKeyAggregate | ProofFamily::EvaluatorKeyAggregate => {
                (None, None, None)
            }
            ProofFamily::RelinearizationRoundOne
            | ProofFamily::RelinearizationRoundTwo
            | ProofFamily::GaloisKeyShare => (Some(3), Some(5), None),
            ProofFamily::RelinearizationRoundOneAggregate => (None, Some(7), None),
            ProofFamily::BallotValidity => (Some(4), None, Some(11)),
        };
        ProofApplicationSlot::new(
            FOUNDATION_PROFILE.protocol_version,
            Hash512::from_bytes([0x11; 64]),
            Hash512::from_bytes([0x22; 64]),
            Hash512::from_bytes([0x33; 64]),
            proof_family,
            roster_position,
            schedule_position,
            producer_sequence,
        )
        .expect("test proof application slot is valid")
    }

    #[test]
    fn every_family_slot_round_trips_with_only_its_closed_coordinates() {
        for proof_family in ProofFamily::ALL {
            let slot = slot_for_family(proof_family);
            let encoded = slot.encode().expect("proof application slot encodes");
            assert_eq!(
                ProofApplicationSlot::decode(&encoded, &CanonicalDecodeLimits::default())
                    .expect("proof application slot decodes"),
                slot
            );
            assert_ne!(
                slot.application_slot_hash()
                    .expect("application slot hash derives"),
                Hash512::from_bytes([0; 64])
            );
        }
    }

    #[test]
    fn wrong_family_coordinate_combinations_and_roster_bounds_refuse() {
        let common_arguments = (
            FOUNDATION_PROFILE.protocol_version,
            Hash512::from_bytes([0x11; 64]),
            Hash512::from_bytes([0x22; 64]),
            Hash512::from_bytes([0x33; 64]),
        );
        for (proof_family, roster_position, schedule_position, producer_sequence) in [
            (
                ProofFamily::CollectivePublicKeyAggregate,
                Some(0),
                None,
                None,
            ),
            (ProofFamily::RelinearizationRoundOne, Some(0), None, None),
            (
                ProofFamily::RelinearizationRoundOneAggregate,
                Some(0),
                Some(0),
                None,
            ),
            (ProofFamily::BallotValidity, Some(0), Some(0), Some(0)),
            (ProofFamily::BallotValidity, Some(0), None, None),
            (ProofFamily::PairedTargetShare, Some(0), None, Some(0)),
        ] {
            assert_eq!(
                ProofApplicationSlot::new(
                    common_arguments.0,
                    common_arguments.1,
                    common_arguments.2,
                    common_arguments.3,
                    proof_family,
                    roster_position,
                    schedule_position,
                    producer_sequence,
                )
                .expect_err("wrong coordinate grammar must refuse")
                .refusal_reason,
                RefusalReason::WrongTypeOrLength
            );
        }
        assert_eq!(
            ProofApplicationSlot::new(
                common_arguments.0,
                common_arguments.1,
                common_arguments.2,
                common_arguments.3,
                ProofFamily::SameSecretLinkage,
                Some(FOUNDATION_PROFILE.participant_count),
                None,
                None,
            )
            .expect_err("out-of-range roster position must refuse")
            .refusal_reason,
            RefusalReason::WrongTypeOrLength
        );
        assert_eq!(
            ProofApplicationSlot::new(
                2,
                common_arguments.1,
                common_arguments.2,
                common_arguments.3,
                ProofFamily::SameSecretLinkage,
                Some(0),
                None,
                None,
            )
            .expect_err("unsupported protocol version must refuse")
            .refusal_reason,
            RefusalReason::WrongContext
        );
    }

    #[test]
    fn application_binding_round_trips_the_complete_stream_descriptor() {
        let binding = ProofApplicationBinding::new(
            slot_for_family(ProofFamily::SameSecretLinkage),
            Hash512::from_bytes([0x44; 64]),
            StreamDescriptor::new(
                1_048_577,
                vec![
                    Hash512::from_bytes([0x55; 64]),
                    Hash512::from_bytes([0x56; 64]),
                ],
                Hash512::from_bytes([0x57; 64]),
            )
            .expect("test stream descriptor is valid"),
        )
        .expect("test proof application binding is valid");
        let encoded = binding.encode().expect("proof application binding encodes");
        assert_eq!(
            ProofApplicationBinding::decode(&encoded, &CanonicalDecodeLimits::default())
                .expect("proof application binding decodes"),
            binding
        );

        let mut trailing = encoded;
        trailing.push(0);
        assert!(
            ProofApplicationBinding::decode(&trailing, &CanonicalDecodeLimits::default()).is_err()
        );
    }

    #[test]
    fn proof_coin_inputs_enforce_the_family_privacy_classification() {
        let statement_hash = Hash512::from_bytes([0x61; 64]);
        for proof_family in ProofFamily::ALL {
            let slot = slot_for_family(proof_family);
            match proof_family.private_coin_classification() {
                ProofPrivateCoinClassification::ResetSafeSecretBearing => {
                    let input = PersistentProofCoinInput::new(slot.clone(), statement_hash)
                        .expect("reset-safe family accepts persistent proof coins");
                    let encoded = input.encode().expect("persistent proof input encodes");
                    assert_eq!(
                        PersistentProofCoinInput::decode(
                            &encoded,
                            &CanonicalDecodeLimits::default()
                        )
                        .expect("persistent proof input decodes"),
                        input
                    );
                    assert!(OrdinaryProofCoinInput::new(slot, statement_hash, [7; 32]).is_err());
                }
                ProofPrivateCoinClassification::OrdinarySecretBearing => {
                    let input = OrdinaryProofCoinInput::new(slot.clone(), statement_hash, [7; 32])
                        .expect("ordinary family accepts ordinary proof coins");
                    let encoded = input.encode().expect("ordinary proof input encodes");
                    assert_eq!(
                        OrdinaryProofCoinInput::decode(&encoded, &CanonicalDecodeLimits::default())
                            .expect("ordinary proof input decodes"),
                        input
                    );
                    assert!(PersistentProofCoinInput::new(slot, statement_hash).is_err());
                }
                ProofPrivateCoinClassification::PublicOnly => {
                    assert!(PersistentProofCoinInput::new(slot.clone(), statement_hash).is_err());
                    assert!(OrdinaryProofCoinInput::new(slot, statement_hash, [7; 32]).is_err());
                }
            }
        }
    }

    #[test]
    fn statement_hash_is_canonical_byte_sensitive() {
        let first = derive_application_statement_hash(&[1, 2, 3])
            .expect("first application statement hash derives");
        let same = derive_application_statement_hash(&[1, 2, 3])
            .expect("same application statement hash derives");
        let changed = derive_application_statement_hash(&[1, 2, 4])
            .expect("changed application statement hash derives");
        assert_eq!(first, same);
        assert_ne!(first, changed);
    }
}
