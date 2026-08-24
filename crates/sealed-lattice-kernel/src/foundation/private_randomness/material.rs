use core::fmt;

use zeroize::{Zeroize, Zeroizing};

use super::super::schemas::{SchemaResult, read_hash, read_u16, require_header};
use super::super::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalTuple, FOUNDATION_PROFILE, Hash512,
    ParticipantIdentity, RefusalReason, hash_foundation_tuple_512 as hash512,
};
use super::domain::{AttemptClass, PrivateRandomnessDomain};
use super::proof_coins::{
    OrdinaryProofCoinInput, PersistentProofCoinInput, PrivateRandomnessAttemptIdentifier,
    ProofApplicationSlot,
};
use super::stream::{
    Kmac256FramedInput, PrivateRandomCursor, PrivateRandomnessStream, kmac256, kmac256_zeroizing,
    require_attempt_class,
};
use super::validation::{read_participant_identity, require_protocol_version};
use super::{
    ACTION_RANDOMNESS_COMMITMENT_DOMAIN, ACTION_RANDOMNESS_COMMITMENT_PREIMAGE_BYTE_LENGTH,
    ACTION_RANDOMNESS_DERIVATION_INPUT_SCHEMA_IDENTIFIER,
    ACTION_RANDOMNESS_KEY_HIERARCHY_CUSTOMIZATION, ACTION_RANDOMNESS_KEY_MATERIAL_BYTE_LENGTH,
    ACTION_RANDOMNESS_ROOT_BYTE_LENGTH, FOUNDATION_SCHEMA_VERSION,
    ORDINARY_PROOF_ATTEMPT_CUSTOMIZATION, PERSISTENT_PROOF_PREPARATION_CUSTOMIZATION,
    PERSISTENT_PROOF_WITNESS_ATTEMPT_CUSTOMIZATION,
    PRIVATE_RANDOMNESS_ATTEMPT_IDENTIFIER_BYTE_LENGTH, PRIVATE_RANDOMNESS_BLOCK_BYTE_LENGTH,
    PRIVATE_RANDOMNESS_STREAM_KEY_BYTE_LENGTH, PROOF_COIN_KEY_BYTE_LENGTH,
    RESET_SAFE_PROOF_FAMILIES, SETUP_ACTION_RANDOMNESS_AUTHORIZATION_DOMAIN,
    SETUP_ATTEMPT_CUSTOMIZATION, SETUP_STRUCTURED_COMMITMENT_OPENING_CONTEXT_HASH_DOMAIN,
    SETUP_STRUCTURED_COMMITMENT_OPENING_CONTEXT_SCHEMA_IDENTIFIER,
    SETUP_STRUCTURED_COMMITMENT_OPENING_CONTEXT_SCHEMA_VERSION,
    TARGET_DECRYPTION_SHARE_PROOF_FAMILY, TARGET_RELEASE_ATTEMPT_CUSTOMIZATION, schema_error,
};

/// In-process keyed binding for the canonical semantic witness of one
/// reset-safe proof attempt. Witness bytes are absorbed directly into KMAC;
/// no unkeyed witness digest is created, returned, stored, or published. The
/// preparation identifier proves that this binding uses the same action key as
/// the independently prepared reservation before generation is authorized.
pub(crate) struct PersistentProofWitnessCoinBinding {
    input: PersistentProofCoinInput,
    preparation_identifier: PrivateRandomnessAttemptIdentifier,
    framed_input: Kmac256FramedInput,
    canonical_witness_part_count: u64,
}

impl PersistentProofWitnessCoinBinding {
    pub(crate) fn absorb_canonical_bytes(&mut self, bytes: &[u8]) -> SchemaResult<()> {
        self.canonical_witness_part_count = self
            .canonical_witness_part_count
            .checked_add(1)
            .ok_or_else(|| {
                schema_error(
                    RefusalReason::OutsideSupportedProfile,
                    "canonical proof witness has too many framed parts",
                )
            })?;
        self.framed_input.absorb_part(bytes).ok_or_else(|| {
            schema_error(
                RefusalReason::OutsideSupportedProfile,
                "canonical proof witness part is too large",
            )
        })
    }

    pub(crate) fn absorb_canonical_i8_values(&mut self, values: &[i8]) -> SchemaResult<()> {
        const BUFFER_BYTE_LENGTH: usize = 4_096;
        let mut buffer = Zeroizing::new([0_u8; BUFFER_BYTE_LENGTH]);
        self.absorb_canonical_bytes(
            &u64::try_from(values.len())
                .map_err(|_| {
                    schema_error(
                        RefusalReason::OutsideSupportedProfile,
                        "canonical signed coefficient count does not fit",
                    )
                })?
                .to_le_bytes(),
        )?;
        for chunk in values.chunks(BUFFER_BYTE_LENGTH) {
            for (destination, value) in buffer.iter_mut().zip(chunk) {
                *destination = value.to_le_bytes()[0];
            }
            self.absorb_canonical_bytes(&buffer[..chunk.len()])?;
            buffer[..chunk.len()].zeroize();
        }
        Ok(())
    }

    pub(crate) fn absorb_canonical_u64_values(&mut self, values: &[u64]) -> SchemaResult<()> {
        const VALUES_PER_BUFFER: usize = 512;
        let mut buffer = Zeroizing::new([0_u8; VALUES_PER_BUFFER * 8]);
        self.absorb_canonical_bytes(
            &u64::try_from(values.len())
                .map_err(|_| {
                    schema_error(
                        RefusalReason::OutsideSupportedProfile,
                        "canonical field-value count does not fit",
                    )
                })?
                .to_le_bytes(),
        )?;
        for chunk in values.chunks(VALUES_PER_BUFFER) {
            for (destination, value) in buffer.chunks_exact_mut(8).zip(chunk) {
                destination.copy_from_slice(&value.to_le_bytes());
            }
            let byte_length = chunk.len().checked_mul(8).ok_or_else(|| {
                schema_error(
                    RefusalReason::OutsideSupportedProfile,
                    "canonical field-value byte length does not fit",
                )
            })?;
            self.absorb_canonical_bytes(&buffer[..byte_length])?;
            buffer[..byte_length].zeroize();
        }
        Ok(())
    }

    pub(crate) const fn input(&self) -> PersistentProofCoinInput {
        self.input
    }

    pub(crate) const fn preparation_identifier(&self) -> PrivateRandomnessAttemptIdentifier {
        self.preparation_identifier
    }

    pub(crate) fn finish(self) -> SchemaResult<PrivateRandomnessAttemptIdentifier> {
        if self.canonical_witness_part_count == 0 {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "persistent proof coins require a canonical semantic witness",
            ));
        }
        Ok(PrivateRandomnessAttemptIdentifier {
            bytes: self
                .framed_input
                .finish::<PRIVATE_RANDOMNESS_ATTEMPT_IDENTIFIER_BYTE_LENGTH>(),
            attempt_class: AttemptClass::ResetSafeProof,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActionRandomnessDerivationInput {
    suite_identifier: Hash512,
    ceremony_context_hash: Hash512,
    action_context_hash: Hash512,
    participant_identity: ParticipantIdentity,
}

impl ActionRandomnessDerivationInput {
    pub const fn new(
        suite_identifier: Hash512,
        ceremony_context_hash: Hash512,
        action_context_hash: Hash512,
        participant_identity: ParticipantIdentity,
    ) -> Self {
        Self {
            suite_identifier,
            ceremony_context_hash,
            action_context_hash,
            participant_identity,
        }
    }

    pub const fn suite_identifier(self) -> Hash512 {
        self.suite_identifier
    }

    pub const fn ceremony_context_hash(self) -> Hash512 {
        self.ceremony_context_hash
    }

    pub const fn action_context_hash(self) -> Hash512 {
        self.action_context_hash
    }

    pub const fn participant_identity(self) -> ParticipantIdentity {
        self.participant_identity
    }

    fn canonical_tuple(self) -> CanonicalTuple {
        CanonicalTuple::new(
            ACTION_RANDOMNESS_DERIVATION_INPUT_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(FOUNDATION_PROFILE.protocol_version),
                CanonicalItem::hash512(self.suite_identifier.into_bytes()),
                CanonicalItem::hash512(self.ceremony_context_hash.into_bytes()),
                CanonicalItem::hash512(self.action_context_hash.into_bytes()),
                CanonicalItem::participant_identity(self.participant_identity.into_bytes()),
            ],
        )
    }

    pub fn encode(self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple().encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        require_header(
            &tuple,
            ACTION_RANDOMNESS_DERIVATION_INPUT_SCHEMA_IDENTIFIER,
            5,
        )?;
        require_protocol_version(read_u16(&tuple.items[0])?)?;
        Ok(Self::new(
            read_hash(&tuple.items[1])?,
            read_hash(&tuple.items[2])?,
            read_hash(&tuple.items[3])?,
            read_participant_identity(&tuple.items[4])?,
        ))
    }
}

/// One reset-safe structured-commitment opening polynomial coordinate.
///
/// The action-randomness derivation input already binds the suite, ceremony,
/// action, and source participant. This context binds every remaining
/// coordinate that distinguishes one opening polynomial from another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SetupStructuredCommitmentOpeningContext {
    source_setup_intent_object_hash: Hash512,
    commitment_data_prime_index: u16,
    distribution_purpose: u16,
    component_ordinal: u16,
}

impl SetupStructuredCommitmentOpeningContext {
    pub fn new(
        source_setup_intent_object_hash: Hash512,
        commitment_data_prime_index: u16,
        distribution_purpose: u16,
        component_ordinal: u16,
    ) -> SchemaResult<Self> {
        let component_is_assigned = match distribution_purpose {
            11 => component_ordinal < 2,
            12 => component_ordinal < 1,
            _ => false,
        };
        if !component_is_assigned {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "structured-commitment opening purpose or component is not assigned",
            ));
        }
        Ok(Self {
            source_setup_intent_object_hash,
            commitment_data_prime_index,
            distribution_purpose,
            component_ordinal,
        })
    }

    pub const fn source_setup_intent_object_hash(self) -> Hash512 {
        self.source_setup_intent_object_hash
    }

    pub const fn commitment_data_prime_index(self) -> u16 {
        self.commitment_data_prime_index
    }

    pub const fn distribution_purpose(self) -> u16 {
        self.distribution_purpose
    }

    pub const fn component_ordinal(self) -> u16 {
        self.component_ordinal
    }

    fn canonical_tuple(self) -> CanonicalTuple {
        CanonicalTuple::new(
            SETUP_STRUCTURED_COMMITMENT_OPENING_CONTEXT_SCHEMA_IDENTIFIER,
            SETUP_STRUCTURED_COMMITMENT_OPENING_CONTEXT_SCHEMA_VERSION,
            vec![
                CanonicalItem::hash512(self.source_setup_intent_object_hash.into_bytes()),
                CanonicalItem::unsigned16(self.commitment_data_prime_index),
                CanonicalItem::unsigned16(self.distribution_purpose),
                CanonicalItem::unsigned16(self.component_ordinal),
            ],
        )
    }

    pub fn encode(self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple().encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        if tuple.schema_identifier != SETUP_STRUCTURED_COMMITMENT_OPENING_CONTEXT_SCHEMA_IDENTIFIER
            || tuple.items.len() != 4
        {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "structured-commitment opening context has the wrong schema or item count",
            ));
        }
        if tuple.schema_version != SETUP_STRUCTURED_COMMITMENT_OPENING_CONTEXT_SCHEMA_VERSION {
            return Err(schema_error(
                RefusalReason::UnsupportedVersionOrSuite,
                "structured-commitment opening context version is unsupported",
            ));
        }
        Self::new(
            read_hash(&tuple.items[0])?,
            read_u16(&tuple.items[1])?,
            read_u16(&tuple.items[2])?,
            read_u16(&tuple.items[3])?,
        )
    }

    pub fn hash(self) -> SchemaResult<Hash512> {
        Ok(hash512(
            SETUP_STRUCTURED_COMMITMENT_OPENING_CONTEXT_HASH_DOMAIN,
            &[CanonicalItem::variable_bytes(self.encode()?)?],
        )?)
    }
}

pub struct ActionRandomnessRoot {
    root: Zeroizing<[u8; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH]>,
}

impl ActionRandomnessRoot {
    /// Takes ownership of a fresh action root supplied by the platform random generator.
    pub fn from_injected_bytes(root: Zeroizing<[u8; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH]>) -> Self {
        Self { root }
    }

    pub fn derive(
        self,
        derivation_input: ActionRandomnessDerivationInput,
    ) -> SchemaResult<ActionPrivateRandomness> {
        let canonical_derivation_input = derivation_input.encode()?;
        let key_material = kmac256_zeroizing::<ACTION_RANDOMNESS_KEY_MATERIAL_BYTE_LENGTH>(
            self.root.as_ref(),
            &canonical_derivation_input,
            ACTION_RANDOMNESS_KEY_HIERARCHY_CUSTOMIZATION,
        );

        let mut commitment_preimage =
            Zeroizing::new([0u8; ACTION_RANDOMNESS_COMMITMENT_PREIMAGE_BYTE_LENGTH]);
        commitment_preimage
            .copy_from_slice(&key_material[..ACTION_RANDOMNESS_COMMITMENT_PREIMAGE_BYTE_LENGTH]);
        let mut private_randomness_stream_key =
            Zeroizing::new([0u8; PRIVATE_RANDOMNESS_STREAM_KEY_BYTE_LENGTH]);
        private_randomness_stream_key.copy_from_slice(
            &key_material[ACTION_RANDOMNESS_COMMITMENT_PREIMAGE_BYTE_LENGTH
                ..ACTION_RANDOMNESS_COMMITMENT_PREIMAGE_BYTE_LENGTH
                    + PRIVATE_RANDOMNESS_STREAM_KEY_BYTE_LENGTH],
        );
        let mut proof_coin_key = Zeroizing::new([0u8; PROOF_COIN_KEY_BYTE_LENGTH]);
        proof_coin_key.copy_from_slice(
            &key_material[ACTION_RANDOMNESS_COMMITMENT_PREIMAGE_BYTE_LENGTH
                + PRIVATE_RANDOMNESS_STREAM_KEY_BYTE_LENGTH..],
        );

        let action_randomness_commitment = hash512(
            ACTION_RANDOMNESS_COMMITMENT_DOMAIN,
            &[
                CanonicalItem::variable_bytes(canonical_derivation_input)?,
                CanonicalItem::fixed_bytes(commitment_preimage.as_ref())?,
            ],
        )?;

        Ok(ActionPrivateRandomness {
            root: self.root,
            derivation_input,
            action_randomness_commitment,
            private_randomness_stream_key,
            proof_coin_key,
        })
    }
}

impl fmt::Debug for ActionRandomnessRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActionRandomnessRoot")
            .field("root", &"[REDACTED]")
            .finish()
    }
}

pub struct ActionPrivateRandomness {
    root: Zeroizing<[u8; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH]>,
    derivation_input: ActionRandomnessDerivationInput,
    action_randomness_commitment: Hash512,
    pub(super) private_randomness_stream_key:
        Zeroizing<[u8; PRIVATE_RANDOMNESS_STREAM_KEY_BYTE_LENGTH]>,
    proof_coin_key: Zeroizing<[u8; PROOF_COIN_KEY_BYTE_LENGTH]>,
}

impl ActionPrivateRandomness {
    pub(crate) fn root(&self) -> &[u8; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH] {
        &self.root
    }

    pub const fn derivation_input(&self) -> ActionRandomnessDerivationInput {
        self.derivation_input
    }

    pub const fn action_randomness_commitment(&self) -> Hash512 {
        self.action_randomness_commitment
    }

    pub(crate) fn setup_action_randomness_authorization(
        &self,
        roster_hash: Hash512,
    ) -> SchemaResult<Hash512> {
        Ok(hash512(
            SETUP_ACTION_RANDOMNESS_AUTHORIZATION_DOMAIN,
            &[
                CanonicalItem::hash512(self.derivation_input.suite_identifier.into_bytes()),
                CanonicalItem::hash512(self.derivation_input.ceremony_context_hash.into_bytes()),
                CanonicalItem::hash512(self.derivation_input.action_context_hash.into_bytes()),
                CanonicalItem::hash512(roster_hash.into_bytes()),
                CanonicalItem::participant_identity(
                    self.derivation_input.participant_identity.into_bytes(),
                ),
                CanonicalItem::hash512(self.action_randomness_commitment.into_bytes()),
            ],
        )?)
    }

    pub fn setup_attempt_identifier(&self) -> PrivateRandomnessAttemptIdentifier {
        PrivateRandomnessAttemptIdentifier {
            bytes: kmac256::<PRIVATE_RANDOMNESS_ATTEMPT_IDENTIFIER_BYTE_LENGTH>(
                self.private_randomness_stream_key.as_ref(),
                self.action_randomness_commitment.as_bytes(),
                SETUP_ATTEMPT_CUSTOMIZATION,
            ),
            attempt_class: AttemptClass::ResetSafeSetup,
        }
    }

    /// Takes ownership of the one fresh identifier injected before ballot encryption starts.
    pub fn ballot_encryption_attempt_identifier(
        &self,
        injected_attempt_identifier: Zeroizing<
            [u8; PRIVATE_RANDOMNESS_ATTEMPT_IDENTIFIER_BYTE_LENGTH],
        >,
    ) -> PrivateRandomnessAttemptIdentifier {
        PrivateRandomnessAttemptIdentifier {
            bytes: *injected_attempt_identifier,
            attempt_class: AttemptClass::BallotEncryption,
        }
    }

    pub(crate) fn persistent_proof_preparation_identifier(
        &self,
        input: &PersistentProofCoinInput,
    ) -> SchemaResult<PrivateRandomnessAttemptIdentifier> {
        self.require_matching_slot(input.application_slot)?;
        if input.application_slot.attempt_class()? != AttemptClass::ResetSafeProof {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "persistent proof coins require a reset-safe proof or construction-hiding family",
            ));
        }
        Ok(PrivateRandomnessAttemptIdentifier {
            bytes: kmac256::<PRIVATE_RANDOMNESS_ATTEMPT_IDENTIFIER_BYTE_LENGTH>(
                self.proof_coin_key.as_ref(),
                &input.encode()?,
                PERSISTENT_PROOF_PREPARATION_CUSTOMIZATION,
            ),
            attempt_class: AttemptClass::ResetSafeProof,
        })
    }

    pub(crate) fn begin_persistent_proof_witness_coin_binding(
        &self,
        input: &PersistentProofCoinInput,
    ) -> SchemaResult<PersistentProofWitnessCoinBinding> {
        self.require_matching_slot(input.application_slot)?;
        if !RESET_SAFE_PROOF_FAMILIES.contains(
            &input
                .application_slot
                .application_statement_schema_identifier(),
        ) {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "persistent witness coins require a secret-bearing reset-safe proof family",
            ));
        }
        let mut framed_input = Kmac256FramedInput::new(
            self.proof_coin_key.as_ref(),
            PERSISTENT_PROOF_WITNESS_ATTEMPT_CUSTOMIZATION,
        );
        framed_input.absorb_part(&input.encode()?).ok_or_else(|| {
            schema_error(
                RefusalReason::OutsideSupportedProfile,
                "persistent proof coin input is too large",
            )
        })?;
        Ok(PersistentProofWitnessCoinBinding {
            input: *input,
            preparation_identifier: self.persistent_proof_preparation_identifier(input)?,
            framed_input,
            canonical_witness_part_count: 0,
        })
    }

    pub fn ordinary_proof_attempt_identifier(
        &self,
        input: &OrdinaryProofCoinInput,
    ) -> SchemaResult<PrivateRandomnessAttemptIdentifier> {
        self.require_matching_slot(input.application_slot)?;
        if input.application_slot.attempt_class()? != AttemptClass::OrdinaryProof {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "ordinary proof coins require the ordinary ballot proof family",
            ));
        }
        Ok(PrivateRandomnessAttemptIdentifier {
            bytes: kmac256::<PRIVATE_RANDOMNESS_ATTEMPT_IDENTIFIER_BYTE_LENGTH>(
                self.proof_coin_key.as_ref(),
                &input.encode()?,
                ORDINARY_PROOF_ATTEMPT_CUSTOMIZATION,
            ),
            attempt_class: AttemptClass::OrdinaryProof,
        })
    }

    pub fn target_release_attempt_identifier(
        &self,
        application_slot: ProofApplicationSlot,
    ) -> SchemaResult<PrivateRandomnessAttemptIdentifier> {
        self.require_matching_slot(application_slot)?;
        if application_slot.application_statement_schema_identifier
            != TARGET_DECRYPTION_SHARE_PROOF_FAMILY
        {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "target release requires the target-decryption-share application slot",
            ));
        }
        Ok(PrivateRandomnessAttemptIdentifier {
            bytes: kmac256::<PRIVATE_RANDOMNESS_ATTEMPT_IDENTIFIER_BYTE_LENGTH>(
                self.private_randomness_stream_key.as_ref(),
                application_slot.hash()?.as_bytes(),
                TARGET_RELEASE_ATTEMPT_CUSTOMIZATION,
            ),
            attempt_class: AttemptClass::TargetRelease,
        })
    }

    pub fn begin_stream(
        &self,
        domain: PrivateRandomnessDomain,
        derivation_context_hash: Hash512,
        attempt_identifier: PrivateRandomnessAttemptIdentifier,
    ) -> SchemaResult<PrivateRandomnessStream<'_>> {
        require_attempt_class(domain, attempt_identifier)?;
        Ok(PrivateRandomnessStream {
            action_private_randomness: self,
            domain,
            derivation_context_hash,
            attempt_identifier,
            next_counter: 0,
            buffered_block: Zeroizing::new([0u8; PRIVATE_RANDOMNESS_BLOCK_BYTE_LENGTH]),
            next_unread_bit_offset_in_buffered_block: None,
        })
    }

    /// Restores an exact cursor after the containing private attempt record was authenticated.
    pub fn resume_stream(
        &self,
        domain: PrivateRandomnessDomain,
        derivation_context_hash: Hash512,
        attempt_identifier: PrivateRandomnessAttemptIdentifier,
        cursor: PrivateRandomCursor,
    ) -> SchemaResult<PrivateRandomnessStream<'_>> {
        require_attempt_class(domain, attempt_identifier)?;
        if cursor.domain != domain
            || cursor.derivation_context_hash() != derivation_context_hash
            || cursor.stream_attempt_identifier != attempt_identifier.bytes
        {
            return Err(schema_error(
                RefusalReason::WrongContext,
                "private-randomness cursor does not match the requested stream",
            ));
        }

        let mut stream = PrivateRandomnessStream {
            action_private_randomness: self,
            domain,
            derivation_context_hash,
            attempt_identifier,
            next_counter: cursor.next_counter(),
            buffered_block: Zeroizing::new([0u8; PRIVATE_RANDOMNESS_BLOCK_BYTE_LENGTH]),
            next_unread_bit_offset_in_buffered_block: cursor
                .next_unread_bit_offset_in_buffered_block(),
        };
        if cursor.next_unread_bit_offset_in_buffered_block().is_some() {
            let buffered_counter = cursor.next_counter().checked_sub(1).ok_or_else(|| {
                schema_error(
                    RefusalReason::MalformedEncoding,
                    "private-randomness cursor cannot reference a block before counter zero",
                )
            })?;
            stream.buffered_block = stream.derive_block(buffered_counter)?;
        }
        Ok(stream)
    }

    fn require_matching_slot(&self, application_slot: ProofApplicationSlot) -> SchemaResult<()> {
        if application_slot.suite_identifier != self.derivation_input.suite_identifier
            || application_slot.ceremony_context_hash != self.derivation_input.ceremony_context_hash
            || application_slot.action_context_hash != self.derivation_input.action_context_hash
        {
            return Err(schema_error(
                RefusalReason::WrongContext,
                "proof application slot does not match the action randomness binding",
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for ActionPrivateRandomness {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActionPrivateRandomness")
            .field("root", &"[REDACTED]")
            .field("derivation_input", &self.derivation_input)
            .field(
                "action_randomness_commitment",
                &self.action_randomness_commitment,
            )
            .field("private_randomness_stream_key", &"[REDACTED]")
            .field("proof_coin_key", &"[REDACTED]")
            .finish()
    }
}
