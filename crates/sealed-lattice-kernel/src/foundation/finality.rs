use super::canonical_tuple::CanonicalDecodeBudget;
use super::schemas::{
    EvaluatorReplayPayload, SchemaResult, read_hash, read_nested_tuple_list_with_budget,
    require_header,
};
use super::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalStreamDomain,
    CanonicalStreamVerifier, CanonicalTuple, FOUNDATION_PROFILE, FoundationObjectType,
    FoundationSchemaError, Hash512, ObjectEnvelope, ParticipantIdentity, RefusalReason, Roster,
    SignedCarrier, StateCapabilityKind, StateCertificate, StateError,
    StateReservationVerificationInput, StateVerifier, StreamDescriptor, VerificationResult,
    VerifiedCanonicalStreamSummary, VerifiedStateOutput, VerifiedStateRecovery,
    VerifiedTranscriptObject,
    derive_canonical_stream_descriptor, hash_foundation_tuple_512,
};

pub const FINALITY_STATEMENT_SCHEMA_IDENTIFIER: u16 = 0x1600;
pub const FINALITY_SIGNATURE_PAYLOAD_SCHEMA_IDENTIFIER: u16 = 0x1601;
pub const FINALITY_SIGNER_INPUT_SCHEMA_IDENTIFIER: u16 = 0x1615;
pub const FINALITY_CERTIFICATE_SCHEMA_IDENTIFIER: u16 = 0x1616;

const FINALITY_SCHEMA_VERSION: u16 = 1;
const FINALITY_STATEMENT_HASH_DOMAIN: &str = "sealed-lattice/finality/statement/v1";

/// The shared finality statement signed by the quorum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalityStatement {
    suite_identifier: Hash512,
    ceremony_context_hash: Hash512,
    action_context_hash: Hash512,
    roster_hash: Hash512,
    evaluator_replay_object_hash: Hash512,
}

impl FinalityStatement {
    pub const fn new(
        suite_identifier: Hash512,
        ceremony_context_hash: Hash512,
        action_context_hash: Hash512,
        roster_hash: Hash512,
        evaluator_replay_object_hash: Hash512,
    ) -> Self {
        Self {
            suite_identifier,
            ceremony_context_hash,
            action_context_hash,
            roster_hash,
            evaluator_replay_object_hash,
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

    pub const fn roster_hash(self) -> Hash512 {
        self.roster_hash
    }

    pub const fn evaluator_replay_object_hash(self) -> Hash512 {
        self.evaluator_replay_object_hash
    }

    pub fn encode(self) -> SchemaResult<Vec<u8>> {
        Ok(CanonicalTuple::new(
            FINALITY_STATEMENT_SCHEMA_IDENTIFIER,
            FINALITY_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(FOUNDATION_PROFILE.protocol_version),
                CanonicalItem::hash512(self.suite_identifier.into_bytes()),
                CanonicalItem::hash512(self.ceremony_context_hash.into_bytes()),
                CanonicalItem::hash512(self.action_context_hash.into_bytes()),
                CanonicalItem::hash512(self.roster_hash.into_bytes()),
                CanonicalItem::hash512(self.evaluator_replay_object_hash.into_bytes()),
            ],
        )
        .encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        require_header(&tuple, FINALITY_STATEMENT_SCHEMA_IDENTIFIER, 6)?;
        let protocol_version = read_unsigned16(&tuple.items[0])?;
        if protocol_version != FOUNDATION_PROFILE.protocol_version {
            return Err(schema_error(
                RefusalReason::UnsupportedVersionOrSuite,
                "finality statement protocol version is unsupported",
            ));
        }
        Ok(Self::new(
            read_hash(&tuple.items[1])?,
            read_hash(&tuple.items[2])?,
            read_hash(&tuple.items[3])?,
            read_hash(&tuple.items[4])?,
            read_hash(&tuple.items[5])?,
        ))
    }

    pub fn finality_hash(self) -> SchemaResult<Hash512> {
        Ok(hash_foundation_tuple_512(
            FINALITY_STATEMENT_HASH_DOMAIN,
            &[CanonicalItem::variable_bytes(self.encode()?)?],
        )?)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalitySignaturePayload {
    finality_hash: Hash512,
}

impl FinalitySignaturePayload {
    pub const fn new(finality_hash: Hash512) -> Self {
        Self { finality_hash }
    }

    pub const fn finality_hash(self) -> Hash512 {
        self.finality_hash
    }

    pub fn encode(self) -> SchemaResult<Vec<u8>> {
        Ok(CanonicalTuple::new(
            FINALITY_SIGNATURE_PAYLOAD_SCHEMA_IDENTIFIER,
            FINALITY_SCHEMA_VERSION,
            vec![CanonicalItem::hash512(self.finality_hash.into_bytes())],
        )
        .encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        require_header(&tuple, FINALITY_SIGNATURE_PAYLOAD_SCHEMA_IDENTIFIER, 1)?;
        Ok(Self::new(read_hash(&tuple.items[0])?))
    }
}

/// One finality signer and the exact state authorization for its signed
/// carrier. Transport certificates remain outside the shared finality hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalitySignerInput {
    canonical_signed_finality_carrier: Vec<u8>,
    canonical_signed_reservation_intent_carrier: Vec<u8>,
    reservation_certificate: StateCertificate,
    canonical_signed_output_intent_carrier: Vec<u8>,
    output_certificate: StateCertificate,
}

impl FinalitySignerInput {
    pub fn new(
        canonical_signed_finality_carrier: Vec<u8>,
        canonical_signed_reservation_intent_carrier: Vec<u8>,
        reservation_certificate: StateCertificate,
        canonical_signed_output_intent_carrier: Vec<u8>,
        output_certificate: StateCertificate,
        limits: &CanonicalDecodeLimits,
    ) -> SchemaResult<Self> {
        require_canonical_signed_carrier(&canonical_signed_finality_carrier, limits)?;
        require_canonical_signed_carrier(&canonical_signed_reservation_intent_carrier, limits)?;
        require_canonical_signed_carrier(&canonical_signed_output_intent_carrier, limits)?;
        // Exercise both nested values before retaining them. This prevents a
        // second, unchecked certificate representation inside finality.
        let reservation_certificate_bytes = reservation_certificate
            .encode()
            .map_err(state_schema_error)?;
        let output_certificate_bytes = output_certificate.encode().map_err(state_schema_error)?;
        let _ = StateCertificate::decode(&reservation_certificate_bytes, limits)
            .map_err(state_schema_error)?;
        let _ = StateCertificate::decode(&output_certificate_bytes, limits)
            .map_err(state_schema_error)?;
        Ok(Self {
            canonical_signed_finality_carrier,
            canonical_signed_reservation_intent_carrier,
            reservation_certificate,
            canonical_signed_output_intent_carrier,
            output_certificate,
        })
    }

    pub fn canonical_signed_finality_carrier(&self) -> &[u8] {
        &self.canonical_signed_finality_carrier
    }

    pub fn canonical_signed_reservation_intent_carrier(&self) -> &[u8] {
        &self.canonical_signed_reservation_intent_carrier
    }

    pub const fn reservation_certificate(&self) -> &StateCertificate {
        &self.reservation_certificate
    }

    pub fn canonical_signed_output_intent_carrier(&self) -> &[u8] {
        &self.canonical_signed_output_intent_carrier
    }

    pub const fn output_certificate(&self) -> &StateCertificate {
        &self.output_certificate
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        let reservation_certificate_bytes = self
            .reservation_certificate
            .encode()
            .map_err(state_schema_error)?;
        let reservation_certificate = CanonicalTuple::decode(
            &reservation_certificate_bytes,
            &CanonicalDecodeLimits::default(),
        )?;
        let output_certificate_bytes = self
            .output_certificate
            .encode()
            .map_err(state_schema_error)?;
        let output_certificate =
            CanonicalTuple::decode(&output_certificate_bytes, &CanonicalDecodeLimits::default())?;
        Ok(CanonicalTuple::new(
            FINALITY_SIGNER_INPUT_SCHEMA_IDENTIFIER,
            FINALITY_SCHEMA_VERSION,
            vec![
                CanonicalItem::variable_bytes(&self.canonical_signed_finality_carrier)?,
                CanonicalItem::variable_bytes(&self.canonical_signed_reservation_intent_carrier)?,
                CanonicalItem::nested_tuple(&reservation_certificate)?,
                CanonicalItem::variable_bytes(&self.canonical_signed_output_intent_carrier)?,
                CanonicalItem::nested_tuple(&output_certificate)?,
            ],
        )
        .encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        Self::from_tuple(&tuple, limits)
    }

    fn from_tuple(tuple: &CanonicalTuple, limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        require_header(tuple, FINALITY_SIGNER_INPUT_SCHEMA_IDENTIFIER, 5)?;
        let reservation_certificate = StateCertificate::decode(
            &read_nested_tuple(&tuple.items[2], limits)?.encode()?,
            limits,
        )
        .map_err(state_schema_error)?;
        let output_certificate = StateCertificate::decode(
            &read_nested_tuple(&tuple.items[4], limits)?.encode()?,
            limits,
        )
        .map_err(state_schema_error)?;
        Self::new(
            read_variable_bytes(&tuple.items[0])?.to_vec(),
            read_variable_bytes(&tuple.items[1])?.to_vec(),
            reservation_certificate,
            read_variable_bytes(&tuple.items[3])?.to_vec(),
            output_certificate,
            limits,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalityCertificate {
    ordered_signer_inputs: Vec<FinalitySignerInput>,
}

/// Opaque evidence that the deterministic evaluator replay relation was rerun
/// for one board-ingested replay object. The owning evaluator verifier is the
/// only production caller of the crate-private constructor.
pub struct VerifiedEvaluatorReplay {
    object: VerifiedTranscriptObject,
    suite_identifier: Hash512,
    ceremony_context_hash: Hash512,
    action_context_hash: Hash512,
    roster_hash: Hash512,
    verified_setup_source_hash: Hash512,
    verified_aggregate_source_hash: Hash512,
    top_count: u16,
    target_identifier_descriptor: StreamDescriptor,
    target_order_descriptor: StreamDescriptor,
    target_identifier_stream: VerifiedCanonicalStreamSummary,
    target_order_stream: VerifiedCanonicalStreamSummary,
}

impl VerifiedEvaluatorReplay {
    pub(crate) fn from_verified_relation(
        object: &VerifiedTranscriptObject,
        roster_hash: Hash512,
        top_count: u16,
        target_identifier_stream: VerifiedCanonicalStreamSummary,
        target_order_stream: VerifiedCanonicalStreamSummary,
        limits: &CanonicalDecodeLimits,
    ) -> SchemaResult<Self> {
        if top_count == 0 || top_count > FOUNDATION_PROFILE.option_count {
            return Err(schema_error(
                RefusalReason::OutsideSupportedProfile,
                "verified evaluator replay top count is outside the action profile",
            ));
        }
        if object.object_type() != FoundationObjectType::EvaluatorReplay {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "verified evaluator replay source has the wrong object family",
            ));
        }
        let envelope = ObjectEnvelope::decode(object.canonical_carrier_bytes(), limits)?;
        if envelope.object_type != FoundationObjectType::EvaluatorReplay
            || envelope.object_hash()? != object.object_hash()
        {
            return Err(schema_error(
                RefusalReason::WrongHashOrRoot,
                "verified evaluator replay source does not match its board capability",
            ));
        }
        let payload = EvaluatorReplayPayload::decode(&envelope.payload_bytes, limits)?;
        let verified_setup_source_hash = payload.verified_setup_source_hash();
        let verified_aggregate_source_hash = payload.verified_aggregate_source_hash();
        let target_identifier_descriptor = payload.target_identifier_descriptor().clone();
        let target_order_descriptor = payload.target_order_descriptor().clone();
        require_replay_stream(
            &target_identifier_descriptor,
            &target_identifier_stream,
            CanonicalStreamDomain::ReplayTargetIdentifierCiphertext,
        )?;
        require_replay_stream(
            &target_order_descriptor,
            &target_order_stream,
            CanonicalStreamDomain::ReplayTargetOrderCiphertext,
        )?;
        Ok(Self {
            object: object.clone(),
            suite_identifier: envelope.suite_id,
            ceremony_context_hash: envelope.ceremony_context_hash,
            action_context_hash: envelope.action_context_hash,
            roster_hash,
            verified_setup_source_hash,
            verified_aggregate_source_hash,
            top_count,
            target_identifier_descriptor,
            target_order_descriptor,
            target_identifier_stream,
            target_order_stream,
        })
    }

    pub fn object_hash(&self) -> Hash512 {
        self.object.object_hash()
    }

    pub const fn verified_setup_source_hash(&self) -> Hash512 {
        self.verified_setup_source_hash
    }

    pub const fn verified_aggregate_source_hash(&self) -> Hash512 {
        self.verified_aggregate_source_hash
    }

    pub const fn top_count(&self) -> u16 {
        self.top_count
    }

    pub const fn target_identifier_descriptor(&self) -> &StreamDescriptor {
        &self.target_identifier_descriptor
    }

    pub const fn target_order_descriptor(&self) -> &StreamDescriptor {
        &self.target_order_descriptor
    }

    pub const fn target_identifier_full_object_digest(&self) -> Hash512 {
        self.target_identifier_stream.full_object_digest()
    }

    pub const fn target_order_full_object_digest(&self) -> Hash512 {
        self.target_order_stream.full_object_digest()
    }

    fn retained_clone(&self) -> Self {
        Self {
            object: self.object.clone(),
            suite_identifier: self.suite_identifier,
            ceremony_context_hash: self.ceremony_context_hash,
            action_context_hash: self.action_context_hash,
            roster_hash: self.roster_hash,
            verified_setup_source_hash: self.verified_setup_source_hash,
            verified_aggregate_source_hash: self.verified_aggregate_source_hash,
            top_count: self.top_count,
            target_identifier_descriptor: self.target_identifier_descriptor.clone(),
            target_order_descriptor: self.target_order_descriptor.clone(),
            target_identifier_stream: self.target_identifier_stream.clone(),
            target_order_stream: self.target_order_stream.clone(),
        }
    }
}

/// Non-serializable finality capability. It retains the exact replay source,
/// accepted finality objects, and verifier-created state outputs.
pub struct VerifiedFinality {
    statement: FinalityStatement,
    finality_hash: Hash512,
    verified_evaluator_replay: VerifiedEvaluatorReplay,
    finality_objects: Vec<VerifiedTranscriptObject>,
    state_outputs: Vec<VerifiedStateOutput>,
}

impl VerifiedFinality {
    pub const fn statement(&self) -> FinalityStatement {
        self.statement
    }

    pub const fn finality_hash(&self) -> Hash512 {
        self.finality_hash
    }

    pub fn verified_evaluator_replay_object_hash(&self) -> Hash512 {
        self.verified_evaluator_replay.object_hash()
    }

    pub const fn verified_setup_source_hash(&self) -> Hash512 {
        self.verified_evaluator_replay.verified_setup_source_hash()
    }

    pub const fn verified_aggregate_source_hash(&self) -> Hash512 {
        self.verified_evaluator_replay
            .verified_aggregate_source_hash()
    }

    pub const fn top_count(&self) -> u16 {
        self.verified_evaluator_replay.top_count()
    }

    pub const fn target_identifier_descriptor(&self) -> &StreamDescriptor {
        self.verified_evaluator_replay
            .target_identifier_descriptor()
    }

    pub const fn target_order_descriptor(&self) -> &StreamDescriptor {
        self.verified_evaluator_replay.target_order_descriptor()
    }

    pub const fn target_identifier_full_object_digest(&self) -> Hash512 {
        self.verified_evaluator_replay
            .target_identifier_full_object_digest()
    }

    pub const fn target_order_full_object_digest(&self) -> Hash512 {
        self.verified_evaluator_replay
            .target_order_full_object_digest()
    }

    pub fn accepted_finality_object_hashes(&self) -> Vec<Hash512> {
        self.finality_objects
            .iter()
            .map(VerifiedTranscriptObject::object_hash)
            .collect()
    }

    pub(crate) fn state_outputs(&self) -> &[VerifiedStateOutput] {
        &self.state_outputs
    }
}

pub struct FinalityVerificationInput<'input> {
    pub statement: FinalityStatement,
    pub certificate: &'input FinalityCertificate,
    pub verified_evaluator_replay: &'input VerifiedEvaluatorReplay,
    pub verified_finality_objects: &'input [&'input VerifiedTranscriptObject],
    pub verified_predecessor_recoveries: &'input [Option<&'input VerifiedStateRecovery>],
}

/// Verifies one finality certificate against the frozen external roster and
/// the shared state substrate. No signer, key, position, or replay source is
/// accepted from transport metadata.
pub struct FinalityVerifier {
    suite_identifier: Hash512,
    ceremony_context_hash: Hash512,
    action_context_hash: Hash512,
    roster: Roster,
    roster_hash: Hash512,
    state_verifier: StateVerifier,
    canonical_decode_limits: CanonicalDecodeLimits,
}

impl FinalityVerifier {
    pub fn new(
        suite_identifier: Hash512,
        ceremony_context_hash: Hash512,
        action_context_hash: Hash512,
        roster: &Roster,
        maximum_recovery_transitions_per_state_key: u64,
        canonical_decode_limits: CanonicalDecodeLimits,
    ) -> SchemaResult<Self> {
        let canonical_roster = Roster::new(roster.entries.clone())?;
        let roster_hash = canonical_roster.roster_hash()?;
        let state_verifier = StateVerifier::new(
            suite_identifier,
            ceremony_context_hash,
            action_context_hash,
            &canonical_roster,
            maximum_recovery_transitions_per_state_key,
            canonical_decode_limits,
        )
        .map_err(state_schema_error)?;
        Ok(Self {
            suite_identifier,
            ceremony_context_hash,
            action_context_hash,
            roster: canonical_roster,
            roster_hash,
            state_verifier,
            canonical_decode_limits,
        })
    }

    pub fn verify(
        &self,
        input: FinalityVerificationInput<'_>,
    ) -> VerificationResult<VerifiedFinality> {
        match self.verify_inner(input) {
            Ok(value) => VerificationResult::valid(value),
            Err(error) => VerificationResult::refused(error.refusal_reason),
        }
    }

    fn verify_inner(&self, input: FinalityVerificationInput<'_>) -> SchemaResult<VerifiedFinality> {
        self.require_statement_context(input.statement, input.verified_evaluator_replay)?;
        let signer_inputs = input.certificate.ordered_signer_inputs();
        if input.verified_finality_objects.len() != signer_inputs.len() {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "finality provenance lists do not match the signer count",
            ));
        }
        if input.verified_predecessor_recoveries.len() != signer_inputs.len() {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "finality predecessor-recovery list does not match the signer count",
            ));
        }
        let finality_hash = input.statement.finality_hash()?;
        let mut previous_roster_position = None;
        let mut retained_finality_objects = Vec::with_capacity(signer_inputs.len());
        let mut state_outputs = Vec::with_capacity(signer_inputs.len());
        for (signer_index, signer_input) in signer_inputs.iter().enumerate() {
            let finality_carrier = SignedCarrier::decode(
                signer_input.canonical_signed_finality_carrier(),
                &self.canonical_decode_limits,
            )?;
            let signer = self.require_finality_carrier(
                &finality_carrier,
                finality_hash,
                input.statement.evaluator_replay_object_hash(),
            )?;
            let roster_position = self.roster_position(signer)?;
            if previous_roster_position.is_some_and(|previous| previous >= roster_position) {
                return Err(schema_error(
                    RefusalReason::Equivocation,
                    "finality signers are duplicated or not in external-roster order",
                ));
            }
            previous_roster_position = Some(roster_position);

            let verified_finality_object = input.verified_finality_objects[signer_index];
            if verified_finality_object.object_type() != FoundationObjectType::FinalitySignature
                || verified_finality_object.object_hash()
                    != finality_carrier.envelope.object_hash()?
                || verified_finality_object.canonical_carrier_bytes()
                    != signer_input.canonical_signed_finality_carrier()
            {
                return Err(schema_error(
                    RefusalReason::WrongHashOrRoot,
                    "finality carrier does not match its canonical-board capability",
                ));
            }

            let reservation_certificate_bytes = signer_input
                .reservation_certificate()
                .encode()
                .map_err(state_schema_error)?;
            let verified_reservation = self
                .state_verifier
                .verify_reservation(StateReservationVerificationInput {
                    subject_participant_id: signer,
                    capability_kind: StateCapabilityKind::FinalitySignature,
                    verified_predecessor_recovery: input
                        .verified_predecessor_recoveries[signer_index],
                    expected_authorization_hash: finality_hash,
                    canonical_reservation_intent_carrier: signer_input
                        .canonical_signed_reservation_intent_carrier(),
                    canonical_state_certificate: &reservation_certificate_bytes,
                })
                .into_result()
                .map_err(finality_refusal)?;

            let verified_stream = verify_finality_exact_output_stream(
                signer_input.canonical_signed_finality_carrier(),
            )?;
            let output_certificate_bytes = signer_input
                .output_certificate()
                .encode()
                .map_err(state_schema_error)?;
            let verified_output = self
                .state_verifier
                .verify_output_from_verified_stream(
                    &verified_reservation,
                    signer_input.canonical_signed_output_intent_carrier(),
                    &output_certificate_bytes,
                    verified_stream,
                )
                .into_result()
                .map_err(finality_refusal)?;
            if verified_output.subject_participant_id() != signer
                || verified_output.authorization_hash() != finality_hash
            {
                return Err(schema_error(
                    RefusalReason::WrongContext,
                    "finality carrier and state output have different subject state",
                ));
            }
            retained_finality_objects.push((*verified_finality_object).clone());
            state_outputs.push(verified_output);
        }

        Ok(VerifiedFinality {
            statement: input.statement,
            finality_hash,
            verified_evaluator_replay: input.verified_evaluator_replay.retained_clone(),
            finality_objects: retained_finality_objects,
            state_outputs,
        })
    }

    fn require_statement_context(
        &self,
        statement: FinalityStatement,
        verified_evaluator_replay: &VerifiedEvaluatorReplay,
    ) -> SchemaResult<()> {
        if statement.suite_identifier() != self.suite_identifier
            || statement.ceremony_context_hash() != self.ceremony_context_hash
            || statement.action_context_hash() != self.action_context_hash
            || statement.roster_hash() != self.roster_hash
            || verified_evaluator_replay.suite_identifier != self.suite_identifier
            || verified_evaluator_replay.ceremony_context_hash != self.ceremony_context_hash
            || verified_evaluator_replay.action_context_hash != self.action_context_hash
            || verified_evaluator_replay.roster_hash != self.roster_hash
        {
            return Err(schema_error(
                RefusalReason::WrongContext,
                "finality statement or replay source belongs to another context",
            ));
        }
        if statement.evaluator_replay_object_hash() != verified_evaluator_replay.object_hash() {
            return Err(schema_error(
                RefusalReason::MissingPrerequisite,
                "finality statement does not reference its verified evaluator replay",
            ));
        }
        Ok(())
    }

    fn require_finality_carrier(
        &self,
        carrier: &SignedCarrier,
        finality_hash: Hash512,
        evaluator_replay_object_hash: Hash512,
    ) -> SchemaResult<ParticipantIdentity> {
        let envelope = &carrier.envelope;
        if envelope.object_type != FoundationObjectType::FinalitySignature
            || envelope.suite_id != self.suite_identifier
            || envelope.ceremony_context_hash != self.ceremony_context_hash
            || envelope.action_context_hash != self.action_context_hash
            || envelope.producer_sequence != 0
        {
            return Err(schema_error(
                RefusalReason::WrongContext,
                "finality carrier has the wrong family, context, or sequence",
            ));
        }
        let Some(signer) = envelope.producer_participant_id else {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "finality carrier has no signer",
            ));
        };
        if envelope.ordered_prerequisite_hashes.as_slice() != [evaluator_replay_object_hash] {
            return Err(schema_error(
                RefusalReason::MissingPrerequisite,
                "finality carrier does not have the exact evaluator prerequisite",
            ));
        }
        let payload = FinalitySignaturePayload::decode(
            &envelope.payload_bytes,
            &self.canonical_decode_limits,
        )?;
        if payload.finality_hash() != finality_hash {
            return Err(schema_error(
                RefusalReason::WrongHashOrRoot,
                "finality carrier signs a different statement",
            ));
        }
        carrier
            .verify_signature(&self.roster)
            .into_result()
            .map_err(finality_refusal)?;
        Ok(signer)
    }

    fn roster_position(&self, signer: ParticipantIdentity) -> SchemaResult<u16> {
        self.roster
            .entries
            .iter()
            .enumerate()
            .find_map(|(position, entry)| {
                (entry.participant_identity().ok() == Some(signer)).then_some(position)
            })
            .map(|position| {
                u16::try_from(position).map_err(|_| {
                    schema_error(
                        RefusalReason::OutsideSupportedProfile,
                        "finality roster position does not fit its canonical width",
                    )
                })
            })
            .transpose()?
            .ok_or_else(|| {
                schema_error(
                    RefusalReason::WrongContext,
                    "finality signer is absent from the external roster",
                )
            })
    }
}

fn require_replay_stream(
    descriptor: &StreamDescriptor,
    verified_stream: &VerifiedCanonicalStreamSummary,
    expected_domain: CanonicalStreamDomain,
) -> SchemaResult<()> {
    if verified_stream.stream_domain() != expected_domain
        || verified_stream.total_byte_length() != descriptor.total_byte_length
        || verified_stream.full_object_digest() != descriptor.full_object_digest
    {
        return Err(schema_error(
            RefusalReason::WrongHashOrRoot,
            "verified evaluator stream does not match its replay descriptor",
        ));
    }
    Ok(())
}

fn verify_finality_exact_output_stream(
    canonical_signed_finality_carrier: &[u8],
) -> SchemaResult<super::VerifiedCanonicalStreamSummary> {
    let descriptor = derive_canonical_stream_descriptor(
        CanonicalStreamDomain::StateFinalitySignatureExactOutput,
        canonical_signed_finality_carrier,
    )
    .map_err(finality_refusal)?;
    let mut verifier = CanonicalStreamVerifier::new(
        CanonicalStreamDomain::StateFinalitySignatureExactOutput,
        descriptor,
    )
    .map_err(finality_refusal)?;
    for (chunk_index, chunk_bytes) in canonical_signed_finality_carrier
        .chunks(FOUNDATION_PROFILE.stream_chunk_byte_length)
        .enumerate()
    {
        verifier
            .absorb_chunk(chunk_index, chunk_bytes)
            .into_result()
            .map_err(finality_refusal)?;
    }
    verifier
        .finish_with_summary()
        .into_result()
        .map_err(finality_refusal)
}

impl FinalityCertificate {
    pub fn new(ordered_signer_inputs: Vec<FinalitySignerInput>) -> SchemaResult<Self> {
        let signer_count = ordered_signer_inputs.len();
        if signer_count < usize::from(FOUNDATION_PROFILE.finality_quorum)
            || signer_count > usize::from(FOUNDATION_PROFILE.participant_count)
        {
            return Err(schema_error(
                RefusalReason::OutsideSupportedProfile,
                "finality signer count is outside the supported profile",
            ));
        }
        Ok(Self {
            ordered_signer_inputs,
        })
    }

    pub fn ordered_signer_inputs(&self) -> &[FinalitySignerInput] {
        &self.ordered_signer_inputs
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        let signer_tuples = self
            .ordered_signer_inputs
            .iter()
            .map(|input| -> SchemaResult<CanonicalTuple> {
                let encoded_input = input.encode()?;
                Ok(CanonicalTuple::decode(
                    &encoded_input,
                    &CanonicalDecodeLimits::default(),
                )?)
            })
            .collect::<SchemaResult<Vec<_>>>()?;
        let signer_items = signer_tuples
            .iter()
            .map(CanonicalItem::nested_tuple)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(CanonicalTuple::new(
            FINALITY_CERTIFICATE_SCHEMA_IDENTIFIER,
            FINALITY_SCHEMA_VERSION,
            vec![CanonicalItem::homogeneous_list(
                CanonicalItemType::NestedTuple,
                &signer_items,
            )?],
        )
        .encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        require_header(&tuple, FINALITY_CERTIFICATE_SCHEMA_IDENTIFIER, 1)?;
        let mut budget = CanonicalDecodeBudget::new(limits);
        let signer_tuples =
            read_nested_tuple_list_with_budget(&tuple.items[0], limits, &mut budget)?;
        let signer_inputs = signer_tuples
            .iter()
            .map(|signer_tuple| FinalitySignerInput::from_tuple(signer_tuple, limits))
            .collect::<SchemaResult<Vec<_>>>()?;
        Self::new(signer_inputs)
    }
}

fn require_canonical_signed_carrier(
    bytes: &[u8],
    limits: &CanonicalDecodeLimits,
) -> SchemaResult<()> {
    if bytes.is_empty() || bytes.len() > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length {
        return Err(schema_error(
            RefusalReason::OutsideSupportedProfile,
            "finality transport carrier length is outside the supported profile",
        ));
    }
    let carrier = SignedCarrier::decode(bytes, limits)?;
    if carrier.encode()? != bytes {
        return Err(schema_error(
            RefusalReason::MalformedEncoding,
            "finality transport carrier is not canonical",
        ));
    }
    Ok(())
}

fn read_unsigned16(item: &CanonicalItem) -> SchemaResult<u16> {
    if item.item_type() != CanonicalItemType::Unsigned16 || item.canonical_bytes().len() != 2 {
        return Err(schema_error(
            RefusalReason::WrongTypeOrLength,
            "finality unsigned integer has the wrong type or length",
        ));
    }
    Ok(u16::from_le_bytes([
        item.canonical_bytes()[0],
        item.canonical_bytes()[1],
    ]))
}

fn read_variable_bytes(item: &CanonicalItem) -> SchemaResult<&[u8]> {
    if item.item_type() != CanonicalItemType::RawBytes {
        return Err(schema_error(
            RefusalReason::WrongTypeOrLength,
            "finality byte field has the wrong type",
        ));
    }
    Ok(item.variable_value_bytes()?)
}

fn read_nested_tuple(
    item: &CanonicalItem,
    limits: &CanonicalDecodeLimits,
) -> SchemaResult<CanonicalTuple> {
    if item.item_type() != CanonicalItemType::NestedTuple {
        return Err(schema_error(
            RefusalReason::WrongTypeOrLength,
            "finality nested value has the wrong type",
        ));
    }
    Ok(CanonicalTuple::decode(item.canonical_bytes(), limits)?)
}

fn schema_error(refusal_reason: RefusalReason, message: &'static str) -> FoundationSchemaError {
    FoundationSchemaError::new(refusal_reason, message)
}

fn state_schema_error(error: StateError) -> FoundationSchemaError {
    FoundationSchemaError::new(error.refusal_reason, error.message)
}

fn finality_refusal(refusal_reason: RefusalReason) -> FoundationSchemaError {
    FoundationSchemaError::new(refusal_reason, "finality verification refused")
}

#[cfg(test)]
mod tests;
