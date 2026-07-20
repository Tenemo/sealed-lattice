use zeroize::Zeroize;

use crate::{
    bgv::{
        coefficient_codec::canonical_modulus_byte_length,
        modular_arithmetic::add_mod_fast,
        parameters::{DATA_PRIMES, POLYNOMIAL_DEGREE},
        proof_suite::{
            CommonProofRuntimeError, VerifiedBallotCiphertextPolynomial,
            VerifiedBallotValidityOutput, consume_verified_ballot_validity_output,
            with_verified_ballot_validity_output,
        },
    },
    foundation::{
        AggregatePayload, CanonicalDecodeLimits, CanonicalStreamDomain, CanonicalStreamWriter,
        FOUNDATION_PROFILE, FoundationObjectType, Hash512, RefusalReason, StreamDescriptor,
        VerifiedTranscriptObject,
    },
};

use super::{
    engine::Ciphertext,
    program::{VerifiedEvaluatorAggregate, VerifiedEvaluatorAggregateContext},
    top_k::SELECTED_EVALUATOR_WORKING_LEVEL,
};

const AGGREGATE_CIPHERTEXT_COMPONENT_COUNT: usize = 2;

#[derive(Clone, Copy)]
struct VerifiedBallotAggregationContext {
    protocol_version: u16,
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
    action_context_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    verified_setup_source_hash: [u8; Hash512::BYTE_LENGTH],
}

#[derive(Clone, Copy)]
struct PreflightedVerifiedBallot {
    context: VerifiedBallotAggregationContext,
    producer_roster_position: u16,
    ballot_package_object_hash: Hash512,
}

impl VerifiedBallotAggregationContext {
    fn from_output(output: &VerifiedBallotValidityOutput) -> Self {
        Self {
            protocol_version: output.protocol_version(),
            suite_identifier: output.suite_identifier(),
            ceremony_context_hash: output.ceremony_context_hash(),
            action_context_hash: output.action_context_hash(),
            roster_hash: output.roster_hash(),
            verified_setup_source_hash: output.verified_setup_source_hash(),
        }
    }

    fn matches(self, other: Self) -> bool {
        self.protocol_version == other.protocol_version
            && self.suite_identifier == other.suite_identifier
            && self.ceremony_context_hash == other.ceremony_context_hash
            && self.action_context_hash == other.action_context_hash
            && self.roster_hash == other.roster_hash
            && self.verified_setup_source_hash == other.verified_setup_source_hash
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VerifiedBallotAggregationError {
    Runtime(CommonProofRuntimeError),
    Refused(RefusalReason),
}

/// Incrementally consumes positively verified ballots in frozen-roster order.
/// It retains only the running ciphertext aggregate and the selected object
/// hashes required to match the canonical aggregate object.
pub(crate) struct IncrementalVerifiedBallotAggregation {
    context: Option<VerifiedBallotAggregationContext>,
    last_producer_roster_position: Option<u16>,
    selected_ballot_object_hashes: Vec<Hash512>,
    aggregate_ciphertext: Option<Ciphertext>,
    refusal_reason: Option<RefusalReason>,
}

impl IncrementalVerifiedBallotAggregation {
    pub(crate) fn new() -> Self {
        Self {
            context: None,
            last_producer_roster_position: None,
            selected_ballot_object_hashes: Vec::with_capacity(usize::from(
                FOUNDATION_PROFILE.participant_count,
            )),
            aggregate_ciphertext: None,
            refusal_reason: None,
        }
    }

    /// Borrows and completely validates the output before its one-shot
    /// ownership transfer. Any rejection poisons this accumulator, while the
    /// output remains available for explicit release by its JavaScript owner.
    /// A successful return is therefore the exact point at which both sides
    /// may mark the ballot authority consumed.
    pub(crate) fn absorb_verified_ballot_output(
        &mut self,
        verified_ballot_output_handle: u32,
    ) -> Result<(), VerifiedBallotAggregationError> {
        if let Some(refusal_reason) = self.refusal_reason {
            return Err(VerifiedBallotAggregationError::Refused(refusal_reason));
        }
        let preflight =
            match with_verified_ballot_validity_output(verified_ballot_output_handle, |output| {
                Ok(self.preflight_verified_ballot(output))
            }) {
                Ok(Ok(preflight)) => preflight,
                Ok(Err(refusal_reason)) => {
                    self.poison(refusal_reason);
                    return Err(VerifiedBallotAggregationError::Refused(refusal_reason));
                }
                Err(error) => {
                    self.poison(RefusalReason::ConsumedState);
                    return Err(VerifiedBallotAggregationError::Runtime(error));
                }
            };
        let output = match consume_verified_ballot_validity_output(verified_ballot_output_handle) {
            Ok(output) => output,
            Err(error) => {
                self.poison(RefusalReason::ConsumedState);
                return Err(VerifiedBallotAggregationError::Runtime(error));
            }
        };
        self.commit_preflighted_verified_ballot(output, preflight);
        Ok(())
    }

    /// Finalizes only against a board-verified deterministic aggregate object.
    /// Its ordered selected-ballot hashes bind order and content, while its
    /// aggregate descriptor must equal the componentwise recomputation.
    pub(crate) fn finish(
        mut self,
        verified_aggregate_object: &VerifiedTranscriptObject,
        verified_action_top_count: u16,
        limits: &CanonicalDecodeLimits,
    ) -> Result<VerifiedEvaluatorAggregate, RefusalReason> {
        self.preflight_finish()?;
        let context = self.context.ok_or(RefusalReason::MissingPrerequisite)?;
        let aggregate_ciphertext = self
            .aggregate_ciphertext
            .as_ref()
            .ok_or(RefusalReason::MissingPrerequisite)?;
        let aggregate_descriptor = derive_aggregate_ciphertext_descriptor(aggregate_ciphertext)?;
        let aggregate_envelope = verified_aggregate_object.envelope();
        let aggregate_payload = AggregatePayload::decode(&aggregate_envelope.payload_bytes, limits)
            .map_err(|error| error.refusal_reason)?;
        validate_verified_aggregate_object(
            context,
            &self.selected_ballot_object_hashes,
            &aggregate_descriptor,
            aggregate_envelope,
            &aggregate_payload,
        )?;
        let ballot_count = u16::try_from(self.selected_ballot_object_hashes.len())
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        let aggregate_ciphertext = self
            .aggregate_ciphertext
            .take()
            .ok_or(RefusalReason::MissingPrerequisite)?;
        VerifiedEvaluatorAggregate::from_verified_ballot_aggregate(
            VerifiedEvaluatorAggregateContext::from_verified_sources(
                context.protocol_version,
                context.suite_identifier,
                context.ceremony_context_hash,
                context.action_context_hash,
                context.roster_hash,
                context.verified_setup_source_hash,
                verified_aggregate_object.object_hash().into_bytes(),
            ),
            ballot_count,
            verified_action_top_count,
            aggregate_ciphertext,
        )
    }

    pub(super) fn preflight_finish(&self) -> Result<(), RefusalReason> {
        if let Some(refusal_reason) = self.refusal_reason {
            return Err(refusal_reason);
        }
        if self.context.is_none()
            || self.aggregate_ciphertext.is_none()
            || self.selected_ballot_object_hashes.is_empty()
        {
            return Err(RefusalReason::MissingPrerequisite);
        }
        Ok(())
    }

    fn preflight_verified_ballot(
        &self,
        output: &VerifiedBallotValidityOutput,
    ) -> Result<PreflightedVerifiedBallot, RefusalReason> {
        if DATA_PRIMES.len() != SELECTED_EVALUATOR_WORKING_LEVEL + 1 {
            return Err(RefusalReason::UnsupportedVersionOrSuite);
        }
        if self.selected_ballot_object_hashes.len()
            >= usize::from(FOUNDATION_PROFILE.participant_count)
        {
            return Err(RefusalReason::OutsideSupportedProfile);
        }
        let output_context = VerifiedBallotAggregationContext::from_output(output);
        if output_context.protocol_version != FOUNDATION_PROFILE.protocol_version {
            return Err(RefusalReason::UnsupportedVersionOrSuite);
        }
        if self
            .context
            .is_some_and(|context| !context.matches(output_context))
        {
            return Err(RefusalReason::WrongContext);
        }
        let producer_roster_position = output.producer_roster_position();
        if producer_roster_position >= FOUNDATION_PROFILE.participant_count {
            return Err(RefusalReason::OutsideSupportedProfile);
        }
        if self
            .last_producer_roster_position
            .is_some_and(|previous_position| producer_roster_position <= previous_position)
        {
            return Err(RefusalReason::WrongContext);
        }
        if output.ciphertext_descriptor().total_byte_length
            != selected_ciphertext_total_byte_length()?
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        self.validate_ciphertext_catalog(output.ciphertext_catalog())?;
        Ok(PreflightedVerifiedBallot {
            context: output_context,
            producer_roster_position,
            ballot_package_object_hash: Hash512::from_bytes(output.ballot_package_object_hash()),
        })
    }

    fn validate_ciphertext_catalog(
        &self,
        ciphertext_catalog: &[VerifiedBallotCiphertextPolynomial],
    ) -> Result<(), RefusalReason> {
        let active_limb_count = DATA_PRIMES.len();
        let expected_polynomial_count = AGGREGATE_CIPHERTEXT_COMPONENT_COUNT
            .checked_mul(active_limb_count)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        if ciphertext_catalog.len() != expected_polynomial_count {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        if let Some(aggregate_ciphertext) = &self.aggregate_ciphertext
            && (aggregate_ciphertext.level != SELECTED_EVALUATOR_WORKING_LEVEL
                || aggregate_ciphertext.decrypt_scaling != 1
                || aggregate_ciphertext.components.len() != AGGREGATE_CIPHERTEXT_COMPONENT_COUNT
                || aggregate_ciphertext.components.iter().any(|component| {
                    component.len() != active_limb_count
                        || component
                            .iter()
                            .any(|coefficients| coefficients.len() != POLYNOMIAL_DEGREE)
                }))
        {
            return Err(RefusalReason::ConsumedState);
        }

        for (polynomial_ordinal, polynomial) in ciphertext_catalog.iter().enumerate() {
            let component_ordinal = polynomial_ordinal / active_limb_count;
            let data_modulus_index = polynomial_ordinal % active_limb_count;
            if usize::from(polynomial.component_ordinal()) != component_ordinal
                || usize::from(polynomial.data_modulus_index()) != data_modulus_index
            {
                return Err(RefusalReason::WrongTypeOrLength);
            }
            let modulus = DATA_PRIMES[data_modulus_index];
            if polynomial.modulus() != modulus {
                return Err(RefusalReason::UnsupportedVersionOrSuite);
            }
            let coefficients = polynomial.coefficients();
            if coefficients.len() != POLYNOMIAL_DEGREE {
                return Err(RefusalReason::WrongTypeOrLength);
            }
            if coefficients
                .iter()
                .any(|coefficient| *coefficient >= modulus)
            {
                return Err(RefusalReason::MalformedEncoding);
            }
        }
        Ok(())
    }

    fn commit_preflighted_verified_ballot(
        &mut self,
        output: VerifiedBallotValidityOutput,
        preflight: PreflightedVerifiedBallot,
    ) {
        let active_limb_count = DATA_PRIMES.len();
        let ciphertext_catalog = output.into_ciphertext_catalog();
        let first_ballot = self.aggregate_ciphertext.is_none();
        let aggregate_ciphertext = self.aggregate_ciphertext.get_or_insert_with(|| Ciphertext {
            components: (0..AGGREGATE_CIPHERTEXT_COMPONENT_COUNT)
                .map(|_| Vec::with_capacity(active_limb_count))
                .collect(),
            level: SELECTED_EVALUATOR_WORKING_LEVEL,
            decrypt_scaling: 1,
        });
        for (polynomial_ordinal, polynomial) in ciphertext_catalog.into_iter().enumerate() {
            let component_ordinal = polynomial_ordinal / active_limb_count;
            let data_modulus_index = polynomial_ordinal % active_limb_count;
            let coefficients = polynomial.coefficients();
            if first_ballot {
                aggregate_ciphertext.components[component_ordinal].push(coefficients.to_vec());
                continue;
            }
            let aggregate_coefficients = aggregate_ciphertext
                .components
                .get_mut(component_ordinal)
                .and_then(|component| component.get_mut(data_modulus_index))
                .expect("the borrowed ballot preflight validated aggregate geometry");
            let modulus = DATA_PRIMES[data_modulus_index];
            for (aggregate_coefficient, coefficient) in
                aggregate_coefficients.iter_mut().zip(coefficients.iter())
            {
                *aggregate_coefficient =
                    add_mod_fast(*aggregate_coefficient, *coefficient, modulus);
            }
        }
        self.context.get_or_insert(preflight.context);
        self.last_producer_roster_position = Some(preflight.producer_roster_position);
        self.selected_ballot_object_hashes
            .push(preflight.ballot_package_object_hash);
    }

    fn poison(&mut self, refusal_reason: RefusalReason) {
        if self.refusal_reason.is_none() {
            self.refusal_reason = Some(refusal_reason);
        }
        if let Some(mut aggregate_ciphertext) = self.aggregate_ciphertext.take() {
            aggregate_ciphertext.components.zeroize();
        }
        self.selected_ballot_object_hashes.clear();
        self.context = None;
        self.last_producer_roster_position = None;
    }
}

impl Default for IncrementalVerifiedBallotAggregation {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for IncrementalVerifiedBallotAggregation {
    fn drop(&mut self) {
        if let Some(mut aggregate_ciphertext) = self.aggregate_ciphertext.take() {
            aggregate_ciphertext.components.zeroize();
        }
    }
}

fn validate_verified_aggregate_object(
    context: VerifiedBallotAggregationContext,
    selected_ballot_object_hashes: &[Hash512],
    aggregate_descriptor: &StreamDescriptor,
    aggregate_envelope: &crate::foundation::ObjectEnvelope,
    aggregate_payload: &AggregatePayload,
) -> Result<(), RefusalReason> {
    if aggregate_envelope.object_type != FoundationObjectType::Aggregate
        || aggregate_envelope.producer_participant_id.is_some()
        || aggregate_envelope.producer_sequence != 0
        || !aggregate_envelope.ordered_prerequisite_hashes.is_empty()
    {
        return Err(RefusalReason::WrongTypeOrLength);
    }
    if aggregate_envelope.suite_id.into_bytes() != context.suite_identifier
        || aggregate_envelope.ceremony_context_hash.into_bytes() != context.ceremony_context_hash
        || aggregate_envelope.action_context_hash.into_bytes() != context.action_context_hash
        || aggregate_payload.verified_setup_source_hash().into_bytes()
            != context.verified_setup_source_hash
    {
        return Err(RefusalReason::WrongContext);
    }
    if aggregate_payload.selected_ballot_object_hashes() != selected_ballot_object_hashes
        || aggregate_payload.aggregate_ciphertext_descriptor() != aggregate_descriptor
    {
        return Err(RefusalReason::WrongHashOrRoot);
    }
    Ok(())
}

fn selected_ciphertext_total_byte_length() -> Result<u64, RefusalReason> {
    let polynomial_degree =
        u64::try_from(POLYNOMIAL_DEGREE).map_err(|_| RefusalReason::OutsideSupportedProfile)?;
    let bytes_per_component = DATA_PRIMES.iter().try_fold(0_u64, |total, modulus| {
        let coefficient_byte_length = u64::try_from(canonical_modulus_byte_length(*modulus))
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        total
            .checked_add(
                polynomial_degree
                    .checked_mul(coefficient_byte_length)
                    .ok_or(RefusalReason::OutsideSupportedProfile)?,
            )
            .ok_or(RefusalReason::OutsideSupportedProfile)
    })?;
    u64::try_from(AGGREGATE_CIPHERTEXT_COMPONENT_COUNT)
        .map_err(|_| RefusalReason::OutsideSupportedProfile)?
        .checked_mul(bytes_per_component)
        .and_then(|coefficient_bytes| coefficient_bytes.checked_add(4))
        .ok_or(RefusalReason::OutsideSupportedProfile)
}

fn derive_aggregate_ciphertext_descriptor(
    aggregate_ciphertext: &Ciphertext,
) -> Result<StreamDescriptor, RefusalReason> {
    if aggregate_ciphertext.level != SELECTED_EVALUATOR_WORKING_LEVEL
        || aggregate_ciphertext.decrypt_scaling != 1
        || aggregate_ciphertext.components.len() != AGGREGATE_CIPHERTEXT_COMPONENT_COUNT
        || DATA_PRIMES.len() != SELECTED_EVALUATOR_WORKING_LEVEL + 1
    {
        return Err(RefusalReason::WrongTypeOrLength);
    }
    let mut writer = CanonicalStreamWriter::new(
        CanonicalStreamDomain::AggregateCiphertext,
        selected_ciphertext_total_byte_length()?,
    )?;
    let mut chunk = Vec::with_capacity(FOUNDATION_PROFILE.stream_chunk_byte_length);
    let mut next_chunk_index = 0_usize;
    let level = u16::try_from(aggregate_ciphertext.level)
        .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
    let component_count = u16::try_from(AGGREGATE_CIPHERTEXT_COMPONENT_COUNT)
        .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
    absorb_descriptor_bytes(
        &mut writer,
        &mut chunk,
        &mut next_chunk_index,
        &level.to_le_bytes(),
    )?;
    absorb_descriptor_bytes(
        &mut writer,
        &mut chunk,
        &mut next_chunk_index,
        &component_count.to_le_bytes(),
    )?;

    for component in &aggregate_ciphertext.components {
        if component.len() != DATA_PRIMES.len() {
            chunk.zeroize();
            return Err(RefusalReason::WrongTypeOrLength);
        }
        for (data_modulus_index, coefficients) in component.iter().enumerate() {
            if coefficients.len() != POLYNOMIAL_DEGREE {
                chunk.zeroize();
                return Err(RefusalReason::WrongTypeOrLength);
            }
            let modulus = DATA_PRIMES[data_modulus_index];
            let coefficient_byte_length = canonical_modulus_byte_length(modulus);
            for coefficient in coefficients {
                if *coefficient >= modulus {
                    chunk.zeroize();
                    return Err(RefusalReason::MalformedEncoding);
                }
                absorb_descriptor_bytes(
                    &mut writer,
                    &mut chunk,
                    &mut next_chunk_index,
                    &coefficient.to_le_bytes()[..coefficient_byte_length],
                )?;
            }
        }
    }
    if !chunk.is_empty() {
        writer.absorb_chunk(next_chunk_index, &chunk)?;
    }
    chunk.zeroize();
    writer.finish()
}

#[inline]
fn absorb_descriptor_bytes(
    writer: &mut CanonicalStreamWriter,
    chunk: &mut Vec<u8>,
    next_chunk_index: &mut usize,
    mut bytes: &[u8],
) -> Result<(), RefusalReason> {
    while !bytes.is_empty() {
        let remaining_capacity = FOUNDATION_PROFILE
            .stream_chunk_byte_length
            .checked_sub(chunk.len())
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        if remaining_capacity == 0 {
            writer.absorb_chunk(*next_chunk_index, chunk)?;
            *next_chunk_index = next_chunk_index
                .checked_add(1)
                .ok_or(RefusalReason::OutsideSupportedProfile)?;
            chunk.clear();
            continue;
        }
        let copied_byte_length = remaining_capacity.min(bytes.len());
        chunk.extend_from_slice(&bytes[..copied_byte_length]);
        bytes = &bytes[copied_byte_length..];
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::foundation::ObjectEnvelope;

    use super::*;

    fn test_hash(byte: u8) -> Hash512 {
        Hash512::from_bytes([byte; Hash512::BYTE_LENGTH])
    }

    fn test_context() -> VerifiedBallotAggregationContext {
        VerifiedBallotAggregationContext {
            protocol_version: FOUNDATION_PROFILE.protocol_version,
            suite_identifier: [0x11; Hash512::BYTE_LENGTH],
            ceremony_context_hash: [0x22; Hash512::BYTE_LENGTH],
            action_context_hash: [0x33; Hash512::BYTE_LENGTH],
            roster_hash: [0x44; Hash512::BYTE_LENGTH],
            verified_setup_source_hash: [0x55; Hash512::BYTE_LENGTH],
        }
    }

    fn test_descriptor(byte: u8) -> StreamDescriptor {
        let digest = test_hash(byte);
        StreamDescriptor::new(1, vec![digest], digest)
            .expect("one-byte aggregate stream has one chunk")
    }

    fn test_aggregate_envelope(
        context: VerifiedBallotAggregationContext,
        payload: &AggregatePayload,
    ) -> ObjectEnvelope {
        ObjectEnvelope {
            suite_id: Hash512::from_bytes(context.suite_identifier),
            object_type: FoundationObjectType::Aggregate,
            ceremony_context_hash: Hash512::from_bytes(context.ceremony_context_hash),
            action_context_hash: Hash512::from_bytes(context.action_context_hash),
            producer_participant_id: None,
            producer_sequence: 0,
            ordered_prerequisite_hashes: Vec::new(),
            payload_bytes: payload.encode().expect("aggregate payload encodes"),
        }
    }

    #[test]
    fn aggregate_validation_accepts_exact_selected_ballots_and_recomputed_stream() {
        let context = test_context();
        let selected_ballot_object_hashes = vec![test_hash(0x61), test_hash(0x62)];
        let aggregate_descriptor = test_descriptor(0x71);
        let payload = AggregatePayload::new(
            Hash512::from_bytes(context.verified_setup_source_hash),
            selected_ballot_object_hashes.clone(),
            aggregate_descriptor.clone(),
        )
        .expect("aggregate payload");
        let envelope = test_aggregate_envelope(context, &payload);
        let decoded_payload =
            AggregatePayload::decode(&envelope.payload_bytes, &CanonicalDecodeLimits::default())
                .expect("aggregate payload decodes");

        assert_eq!(
            validate_verified_aggregate_object(
                context,
                &selected_ballot_object_hashes,
                &aggregate_descriptor,
                &envelope,
                &decoded_payload,
            ),
            Ok(())
        );
    }

    #[test]
    fn aggregate_validation_rejects_rebound_ballot_hashes_and_stream_root() {
        let context = test_context();
        let selected_ballot_object_hashes = vec![test_hash(0x61), test_hash(0x62)];
        let aggregate_descriptor = test_descriptor(0x71);

        let rebound_ballot_payload = AggregatePayload::new(
            Hash512::from_bytes(context.verified_setup_source_hash),
            vec![test_hash(0x61), test_hash(0x63)],
            aggregate_descriptor.clone(),
        )
        .expect("rebound-ballot aggregate payload");
        let rebound_ballot_envelope = test_aggregate_envelope(context, &rebound_ballot_payload);
        let decoded_rebound_ballot_payload = AggregatePayload::decode(
            &rebound_ballot_envelope.payload_bytes,
            &CanonicalDecodeLimits::default(),
        )
        .expect("rebound-ballot aggregate payload decodes");
        assert_eq!(
            validate_verified_aggregate_object(
                context,
                &selected_ballot_object_hashes,
                &aggregate_descriptor,
                &rebound_ballot_envelope,
                &decoded_rebound_ballot_payload,
            ),
            Err(RefusalReason::WrongHashOrRoot)
        );

        let rebound_stream_payload = AggregatePayload::new(
            Hash512::from_bytes(context.verified_setup_source_hash),
            selected_ballot_object_hashes.clone(),
            test_descriptor(0x72),
        )
        .expect("rebound-stream aggregate payload");
        let rebound_stream_envelope = test_aggregate_envelope(context, &rebound_stream_payload);
        let decoded_rebound_stream_payload = AggregatePayload::decode(
            &rebound_stream_envelope.payload_bytes,
            &CanonicalDecodeLimits::default(),
        )
        .expect("rebound-stream aggregate payload decodes");
        assert_eq!(
            validate_verified_aggregate_object(
                context,
                &selected_ballot_object_hashes,
                &aggregate_descriptor,
                &rebound_stream_envelope,
                &decoded_rebound_stream_payload,
            ),
            Err(RefusalReason::WrongHashOrRoot)
        );
    }
}
