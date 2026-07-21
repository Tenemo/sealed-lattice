use zeroize::Zeroize;

use crate::{
    bgv::{
        coefficient_codec::canonical_modulus_byte_length,
        direct_ballots::PAIR_CHARACTER_CIPHERTEXT_COUNT,
        key_switch_topology::KeySwitchDecompositionTopology,
        parameters::{DATA_PRIMES, POLYNOMIAL_DEGREE},
        proof_suite::{
            CommonProofRuntimeError, SelectedEvaluatorEntryKind,
            VerifiedBallotCiphertextPolynomial, VerifiedBallotValidityOutput,
            consume_verified_ballot_validity_output, with_verified_ballot_validity_output,
        },
        setup::VerifiedAcceptedSetupAuthority,
    },
    foundation::{
        AggregatePayload, CanonicalDecodeLimits, CanonicalStreamDomain, CanonicalStreamWriter,
        FOUNDATION_PROFILE, FoundationObjectType, Hash512, RefusalReason, StreamDescriptor,
        VerifiedTranscriptObject, encode_aggregate_carrier,
    },
};

use super::{
    engine::Ciphertext,
    pair_character_product::{
        PairCharacterProductAccounting, PairCharacterProductForest,
        canonical_pair_character_product_schedule,
    },
    program::{VerifiedEvaluatorAggregate, VerifiedEvaluatorAggregateContext},
    replay::VerifiedEvaluatorKeyContext,
    top_k::{
        CHARACTER_OUTPUT_LEVEL, SELECTED_EVALUATOR_MODULUS_SCHEDULE,
        SELECTED_EVALUATOR_WORKING_LEVEL, SELECTED_RELINEARIZATION_KEY_LEVEL,
    },
};

const CIPHERTEXT_COMPONENT_COUNT: usize = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct VerifiedBallotAggregationContext {
    protocol_version: u16,
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
    action_context_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    verified_setup_source_hash: [u8; Hash512::BYTE_LENGTH],
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
        self == other
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PreflightedVerifiedBallot {
    context: VerifiedBallotAggregationContext,
    producer_roster_position: u16,
    ballot_package_object_hash: Hash512,
    expected_prior_ballot_count: usize,
    expected_prior_producer_roster_position: Option<u16>,
}

impl PreflightedVerifiedBallot {
    pub(crate) const fn ballot_package_object_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.ballot_package_object_hash.into_bytes()
    }

    pub(crate) const fn producer_roster_position(&self) -> u16 {
        self.producer_roster_position
    }

    pub(crate) const fn verified_setup_source_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.context.verified_setup_source_hash
    }

    pub(crate) fn matches_verified_accepted_setup(
        &self,
        accepted_setup: &VerifiedAcceptedSetupAuthority,
    ) -> bool {
        accepted_setup.protocol_version() == self.context.protocol_version
            && accepted_setup.suite_identifier() == self.context.suite_identifier
            && accepted_setup.ceremony_context_hash() == self.context.ceremony_context_hash
            && accepted_setup.action_context_hash() == self.context.action_context_hash
            && accepted_setup.roster_hash() == self.context.roster_hash
            && accepted_setup.exact_verified_setup_source_hash()
                == self.context.verified_setup_source_hash
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VerifiedBallotAggregationError {
    Runtime(CommonProofRuntimeError),
    Refused(RefusalReason),
}

/// Exact operation totals for the two ordered character streams. The maximum
/// resident count is derived for their production sequence, including the
/// untouched other forest and old/output overlap at every operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TwoStreamPairCharacterProductAccounting {
    pub(crate) ballot_ciphertext_count: usize,
    pub(crate) ciphertext_multiplication_count: usize,
    pub(crate) relinearization_count: usize,
    pub(crate) normalization_plaintext_multiplication_count: usize,
    pub(crate) modulus_switch_count: usize,
    pub(crate) modulus_drop_count: usize,
    pub(crate) maximum_resident_ciphertext_count: usize,
    pub(crate) relinearization_key_load_count: usize,
    pub(crate) key_store_read_byte_count: u64,
    pub(crate) key_ntt_transform_count: usize,
    pub(crate) memory: TwoStreamPairCharacterProductMemoryAccounting,
}

/// Exact coefficient-payload and streamed-key memory for the canonical product.
///
/// Rust collection headers and allocator metadata are deliberately separate
/// from this cross-target ledger. Every value here is a payload that has the
/// same width in the native and WebAssembly implementations: `u64` ciphertext
/// or key coefficients, `i128` key-switch reconstruction coefficients, or
/// canonical store bytes crossing the JavaScript/WebAssembly boundary.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct TwoStreamPairCharacterProductMemoryAccounting {
    pub(crate) maximum_live_ciphertext_coefficient_byte_length: u64,
    pub(crate) relinearization_key_component_wire_byte_length: u64,
    pub(crate) resident_relinearization_key_coefficient_byte_length: u64,
    pub(crate) maximum_key_store_chunk_byte_length: u64,
    pub(crate) final_key_store_chunk_byte_length: u64,
    pub(crate) key_replay_limb_buffer_byte_length: u64,
    pub(crate) peak_key_replay_wasm_resident_byte_length: u64,
    pub(crate) maximum_ciphertext_tensor_transient_byte_length: u64,
    pub(crate) maximum_ciphertext_tensor_scratch_byte_length: u64,
    pub(crate) maximum_relinearization_transient_byte_length: u64,
    pub(crate) maximum_relinearization_scratch_byte_length: u64,
    pub(crate) maximum_plaintext_multiplication_transient_byte_length: u64,
    pub(crate) maximum_plaintext_multiplication_scratch_byte_length: u64,
    pub(crate) maximum_modulus_switch_transient_byte_length: u64,
    pub(crate) maximum_modulus_switch_scratch_byte_length: u64,
    pub(crate) maximum_operation_transient_byte_length: u64,
    pub(crate) maximum_operation_scratch_byte_length: u64,
    pub(crate) peak_combined_wasm_resident_byte_length: u64,
}

struct ZeroizingCiphertextPair {
    ciphertexts: Option<[Ciphertext; PAIR_CHARACTER_CIPHERTEXT_COUNT]>,
}

impl ZeroizingCiphertextPair {
    fn new(ciphertexts: [Ciphertext; PAIR_CHARACTER_CIPHERTEXT_COUNT]) -> Self {
        Self {
            ciphertexts: Some(ciphertexts),
        }
    }

    fn as_ref(&self) -> &[Ciphertext; PAIR_CHARACTER_CIPHERTEXT_COUNT] {
        self.ciphertexts
            .as_ref()
            .expect("zeroizing ciphertext-pair ownership is present")
    }

    fn as_mut(&mut self) -> &mut [Ciphertext; PAIR_CHARACTER_CIPHERTEXT_COUNT] {
        self.ciphertexts
            .as_mut()
            .expect("zeroizing ciphertext-pair ownership is present")
    }

    fn into_inner(mut self) -> [Ciphertext; PAIR_CHARACTER_CIPHERTEXT_COUNT] {
        self.ciphertexts
            .take()
            .expect("zeroizing ciphertext-pair ownership is present")
    }
}

impl Drop for ZeroizingCiphertextPair {
    fn drop(&mut self) {
        if let Some(ciphertexts) = self.ciphertexts.as_mut() {
            for ciphertext in ciphertexts {
                zeroize_ciphertext(ciphertext);
            }
        }
    }
}

/// Incrementally consumes positively verified ballots in frozen-roster order.
/// Each accepted ballot contributes exactly two ordinal-preserving character
/// ciphertexts to two independent multiplicative forests.
pub(crate) struct IncrementalVerifiedBallotAggregation {
    context: Option<VerifiedBallotAggregationContext>,
    last_producer_roster_position: Option<u16>,
    selected_ballot_object_hashes: Vec<Hash512>,
    product_forests: [Option<PairCharacterProductForest>; PAIR_CHARACTER_CIPHERTEXT_COUNT],
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
            product_forests: core::array::from_fn(|_| Some(PairCharacterProductForest::new())),
            refusal_reason: None,
        }
    }

    /// Borrows the retained positive-verification authority without consuming
    /// it. This allows the runtime to load the one resident relinearization key
    /// only after all ballot and ordering checks pass.
    pub(crate) fn preflight_verified_ballot_output(
        &self,
        verified_ballot_output_handle: u32,
    ) -> Result<PreflightedVerifiedBallot, RefusalReason> {
        if let Some(refusal_reason) = self.refusal_reason {
            return Err(refusal_reason);
        }
        with_verified_ballot_validity_output(verified_ballot_output_handle, |output| {
            Ok(self.preflight_verified_ballot(output))
        })
        .map_err(|_| RefusalReason::ConsumedState)?
    }

    pub(crate) fn requires_relinearization_key_for_preflight(
        &self,
        preflight: &PreflightedVerifiedBallot,
    ) -> Result<bool, RefusalReason> {
        if let Some(refusal_reason) = self.refusal_reason {
            return Err(refusal_reason);
        }
        if preflight.expected_prior_ballot_count != self.selected_ballot_object_hashes.len()
            || preflight.expected_prior_producer_roster_position
                != self.last_producer_roster_position
        {
            return Err(RefusalReason::ConsumedState);
        }
        Ok(preflight.expected_prior_ballot_count > 0)
    }

    /// Consumes the exact preflighted authority and commits both ciphertexts.
    /// Ballot one needs no key; every later commit borrows the selected level-22
    /// relinearization context and never retains or clones it.
    pub(crate) fn commit_preflighted_verified_ballot_output(
        &mut self,
        verified_ballot_output_handle: u32,
        preflight: PreflightedVerifiedBallot,
        relinearization_key_context: Option<&VerifiedEvaluatorKeyContext>,
    ) -> Result<(), VerifiedBallotAggregationError> {
        if let Some(refusal_reason) = self.refusal_reason {
            return Err(VerifiedBallotAggregationError::Refused(refusal_reason));
        }
        if preflight.expected_prior_ballot_count != self.selected_ballot_object_hashes.len()
            || preflight.expected_prior_producer_roster_position
                != self.last_producer_roster_position
        {
            return Err(VerifiedBallotAggregationError::Refused(
                RefusalReason::ConsumedState,
            ));
        }
        if preflight.expected_prior_ballot_count > 0 {
            let key_validation = relinearization_key_context
                .ok_or(RefusalReason::MissingPrerequisite)
                .and_then(validate_relinearization_key_context);
            if let Err(refusal_reason) = key_validation {
                self.poison(refusal_reason);
                return Err(VerifiedBallotAggregationError::Refused(refusal_reason));
            }
        }

        let borrowed_preparation =
            with_verified_ballot_validity_output(verified_ballot_output_handle, |output| {
                Ok(self
                    .preflight_verified_ballot(output)
                    .and_then(|repeated_preflight| {
                        ciphertexts_from_verified_catalog(output.ciphertext_catalog())
                            .map(|ciphertexts| (repeated_preflight, ciphertexts))
                    }))
            })
            .map_err(|_| VerifiedBallotAggregationError::Refused(RefusalReason::ConsumedState))?;
        let (repeated_preflight, ciphertexts) = match borrowed_preparation {
            Ok(preparation) => preparation,
            Err(refusal_reason) => {
                self.poison(refusal_reason);
                return Err(VerifiedBallotAggregationError::Refused(refusal_reason));
            }
        };
        let ciphertexts = ZeroizingCiphertextPair::new(ciphertexts);
        if repeated_preflight != preflight {
            self.poison(RefusalReason::ConsumedState);
            return Err(VerifiedBallotAggregationError::Refused(
                RefusalReason::ConsumedState,
            ));
        }
        if self.product_forests.iter().any(Option::is_none) {
            self.poison(RefusalReason::ConsumedState);
            return Err(VerifiedBallotAggregationError::Refused(
                RefusalReason::ConsumedState,
            ));
        }
        let [first_ciphertext, mut second_ciphertext] = ciphertexts.into_inner();
        let first_result = self.product_forests[0]
            .as_mut()
            .expect("both pair-character product forests passed the ownership check")
            .absorb(first_ciphertext, relinearization_key_context);
        if first_result.is_err() {
            zeroize_ciphertext(&mut second_ciphertext);
            self.poison(RefusalReason::MalformedEncoding);
            return Err(VerifiedBallotAggregationError::Refused(
                RefusalReason::MalformedEncoding,
            ));
        }
        if self.product_forests[1]
            .as_mut()
            .expect("both pair-character product forests passed the ownership check")
            .absorb(second_ciphertext, relinearization_key_context)
            .is_err()
        {
            self.poison(RefusalReason::MalformedEncoding);
            return Err(VerifiedBallotAggregationError::Refused(
                RefusalReason::MalformedEncoding,
            ));
        }
        if let Err(error) = consume_verified_ballot_validity_output(verified_ballot_output_handle) {
            self.poison(RefusalReason::ConsumedState);
            return Err(VerifiedBallotAggregationError::Runtime(error));
        }
        self.context.get_or_insert(preflight.context);
        self.last_producer_roster_position = Some(preflight.producer_roster_position);
        self.selected_ballot_object_hashes
            .push(preflight.ballot_package_object_hash);
        Ok(())
    }

    pub(super) fn preflight_finish(&self) -> Result<(), RefusalReason> {
        if let Some(refusal_reason) = self.refusal_reason {
            return Err(refusal_reason);
        }
        let ballot_count = self.selected_ballot_object_hashes.len();
        if self.context.is_none()
            || ballot_count == 0
            || self.product_forests.iter().any(|forest| {
                forest.as_ref().is_none_or(|forest| {
                    forest.accounting().ballot_ciphertext_count != ballot_count
                })
            })
        {
            return Err(RefusalReason::MissingPrerequisite);
        }
        Ok(())
    }

    /// Completes both forests sequentially, derives their exact level-19
    /// descriptors, and emits the canonical carrier for board publication.
    pub(crate) fn prepare_finalization(
        mut self,
        relinearization_key_context: Option<&VerifiedEvaluatorKeyContext>,
    ) -> Result<PreparedVerifiedBallotAggregation, RefusalReason> {
        self.preflight_finish()?;
        let ballot_count = self.selected_ballot_object_hashes.len();
        if ballot_count > 1 {
            validate_relinearization_key_context(
                relinearization_key_context.ok_or(RefusalReason::MissingPrerequisite)?,
            )?;
        }
        let context = self.context.ok_or(RefusalReason::MissingPrerequisite)?;
        let first_forest = self.product_forests[0]
            .take()
            .ok_or(RefusalReason::ConsumedState)?;
        let second_forest = self.product_forests[1]
            .take()
            .ok_or(RefusalReason::ConsumedState)?;
        let (mut first_ciphertext, first_accounting) = first_forest
            .finalize(relinearization_key_context)
            .map_err(|_| RefusalReason::MalformedEncoding)?;
        let (second_ciphertext, second_accounting) =
            match second_forest.finalize(relinearization_key_context) {
                Ok(output) => output,
                Err(_) => {
                    zeroize_ciphertext(&mut first_ciphertext);
                    return Err(RefusalReason::MalformedEncoding);
                }
            };
        let ciphertexts = ZeroizingCiphertextPair::new([first_ciphertext, second_ciphertext]);
        let preparation = (|| {
            let descriptors = [
                derive_aggregate_ciphertext_descriptor(&ciphertexts.as_ref()[0])?,
                derive_aggregate_ciphertext_descriptor(&ciphertexts.as_ref()[1])?,
            ];
            let accounting =
                combine_product_accounting(ballot_count, [first_accounting, second_accounting])?;
            let carrier_bytes = encode_aggregate_carrier(
                Hash512::from_bytes(context.suite_identifier),
                Hash512::from_bytes(context.ceremony_context_hash),
                Hash512::from_bytes(context.action_context_hash),
                Hash512::from_bytes(context.verified_setup_source_hash),
                self.selected_ballot_object_hashes.clone(),
                descriptors.clone(),
            )
            .map_err(|error| error.refusal_reason)?;
            Ok::<_, RefusalReason>((descriptors, accounting, carrier_bytes))
        })();
        let (descriptors, accounting, carrier_bytes) = preparation?;
        Ok(PreparedVerifiedBallotAggregation {
            context,
            selected_ballot_object_hashes: core::mem::take(&mut self.selected_ballot_object_hashes),
            ciphertexts: Some(ciphertexts.into_inner()),
            descriptors,
            carrier_bytes,
            accounting,
        })
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
            != selected_ballot_ciphertext_total_byte_length()?
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        validate_ciphertext_catalog(output.ciphertext_catalog())?;
        Ok(PreflightedVerifiedBallot {
            context: output_context,
            producer_roster_position,
            ballot_package_object_hash: Hash512::from_bytes(output.ballot_package_object_hash()),
            expected_prior_ballot_count: self.selected_ballot_object_hashes.len(),
            expected_prior_producer_roster_position: self.last_producer_roster_position,
        })
    }

    fn poison(&mut self, refusal_reason: RefusalReason) {
        if self.refusal_reason.is_none() {
            self.refusal_reason = Some(refusal_reason);
        }
        for forest in &mut self.product_forests {
            if let Some(forest) = forest.as_mut() {
                forest.poison();
            }
            forest.take();
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
        self.poison(RefusalReason::ConsumedState);
    }
}

/// Owns the finalized ciphertexts while the canonical aggregate carrier is
/// published and board-verified. A failed bind leaves this value intact for a
/// retry with the correct verified object; a successful bind moves ownership
/// exactly once into the evaluator authority.
pub(crate) struct PreparedVerifiedBallotAggregation {
    context: VerifiedBallotAggregationContext,
    selected_ballot_object_hashes: Vec<Hash512>,
    ciphertexts: Option<[Ciphertext; PAIR_CHARACTER_CIPHERTEXT_COUNT]>,
    descriptors: [StreamDescriptor; PAIR_CHARACTER_CIPHERTEXT_COUNT],
    carrier_bytes: Vec<u8>,
    accounting: TwoStreamPairCharacterProductAccounting,
}

impl PreparedVerifiedBallotAggregation {
    pub(crate) fn carrier_bytes(&self) -> &[u8] {
        &self.carrier_bytes
    }

    #[cfg(test)]
    pub(crate) const fn descriptors(&self) -> &[StreamDescriptor; PAIR_CHARACTER_CIPHERTEXT_COUNT] {
        &self.descriptors
    }

    pub(crate) const fn accounting(&self) -> TwoStreamPairCharacterProductAccounting {
        self.accounting
    }

    #[cfg(test)]
    pub(crate) fn ciphertexts_for_test(&self) -> &[Ciphertext; PAIR_CHARACTER_CIPHERTEXT_COUNT] {
        self.ciphertexts
            .as_ref()
            .expect("prepared aggregate retains ciphertexts before board binding")
    }

    pub(crate) fn bind_verified_aggregate(
        &mut self,
        verified_aggregate_object: &VerifiedTranscriptObject,
        verified_action_top_count: u16,
        limits: &CanonicalDecodeLimits,
    ) -> Result<VerifiedEvaluatorAggregate, RefusalReason> {
        if verified_action_top_count == 0
            || verified_action_top_count > FOUNDATION_PROFILE.option_count
        {
            return Err(RefusalReason::OutsideSupportedProfile);
        }
        let envelope = verified_aggregate_object.envelope();
        let payload = AggregatePayload::decode(&envelope.payload_bytes, limits)
            .map_err(|error| error.refusal_reason)?;
        validate_verified_aggregate_object(
            self.context,
            &self.selected_ballot_object_hashes,
            &self.descriptors,
            envelope,
            &payload,
        )?;
        if verified_aggregate_object.canonical_carrier_bytes() != self.carrier_bytes.as_slice() {
            return Err(RefusalReason::WrongHashOrRoot);
        }
        let ballot_count = u16::try_from(self.selected_ballot_object_hashes.len())
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        let ciphertexts = self
            .ciphertexts
            .take()
            .ok_or(RefusalReason::ConsumedState)?;
        VerifiedEvaluatorAggregate::from_verified_ballot_aggregate(
            VerifiedEvaluatorAggregateContext::from_verified_sources(
                self.context.protocol_version,
                self.context.suite_identifier,
                self.context.ceremony_context_hash,
                self.context.action_context_hash,
                self.context.roster_hash,
                self.context.verified_setup_source_hash,
                verified_aggregate_object.object_hash().into_bytes(),
            ),
            ballot_count,
            verified_action_top_count,
            ciphertexts,
        )
    }
}

impl Drop for PreparedVerifiedBallotAggregation {
    fn drop(&mut self) {
        if let Some(ciphertexts) = self.ciphertexts.as_mut() {
            for ciphertext in ciphertexts {
                zeroize_ciphertext(ciphertext);
            }
        }
    }
}

fn validate_relinearization_key_context(
    context: &VerifiedEvaluatorKeyContext,
) -> Result<(), RefusalReason> {
    if !matches!(
        context.position().key_kind(),
        SelectedEvaluatorEntryKind::Relinearization { catalog_level }
            if catalog_level == SELECTED_RELINEARIZATION_KEY_LEVEL
    ) {
        return Err(RefusalReason::WrongContext);
    }
    Ok(())
}

fn validate_ciphertext_catalog(
    ciphertext_catalog: &[VerifiedBallotCiphertextPolynomial],
) -> Result<(), RefusalReason> {
    let active_limb_count = DATA_PRIMES.len();
    let polynomials_per_ciphertext = CIPHERTEXT_COMPONENT_COUNT
        .checked_mul(active_limb_count)
        .ok_or(RefusalReason::OutsideSupportedProfile)?;
    let expected_polynomial_count = PAIR_CHARACTER_CIPHERTEXT_COUNT
        .checked_mul(polynomials_per_ciphertext)
        .ok_or(RefusalReason::OutsideSupportedProfile)?;
    if ciphertext_catalog.len() != expected_polynomial_count {
        return Err(RefusalReason::WrongTypeOrLength);
    }
    for (polynomial_ordinal, polynomial) in ciphertext_catalog.iter().enumerate() {
        let ciphertext_ordinal = polynomial_ordinal / polynomials_per_ciphertext;
        let component_ordinal =
            (polynomial_ordinal % polynomials_per_ciphertext) / active_limb_count;
        let data_modulus_index = polynomial_ordinal % active_limb_count;
        let modulus = DATA_PRIMES[data_modulus_index];
        if usize::from(polynomial.ciphertext_ordinal()) != ciphertext_ordinal
            || usize::from(polynomial.component_ordinal()) != component_ordinal
            || usize::from(polynomial.data_modulus_index()) != data_modulus_index
            || polynomial.modulus() != modulus
            || polynomial.coefficients().len() != POLYNOMIAL_DEGREE
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        if polynomial
            .coefficients()
            .iter()
            .any(|coefficient| *coefficient >= modulus)
        {
            return Err(RefusalReason::MalformedEncoding);
        }
    }
    Ok(())
}

fn ciphertexts_from_verified_catalog(
    ciphertext_catalog: &[VerifiedBallotCiphertextPolynomial],
) -> Result<[Ciphertext; PAIR_CHARACTER_CIPHERTEXT_COUNT], RefusalReason> {
    validate_ciphertext_catalog(ciphertext_catalog)?;
    let active_limb_count = DATA_PRIMES.len();
    let mut ciphertexts = ZeroizingCiphertextPair::new(core::array::from_fn(|_| Ciphertext {
        components: (0..CIPHERTEXT_COMPONENT_COUNT)
            .map(|_| Vec::with_capacity(active_limb_count))
            .collect(),
        level: SELECTED_EVALUATOR_WORKING_LEVEL,
        decrypt_scaling: 1,
    }));
    for polynomial in ciphertext_catalog {
        let ciphertext_ordinal = usize::from(polynomial.ciphertext_ordinal());
        let component_ordinal = usize::from(polynomial.component_ordinal());
        let data_modulus_index = usize::from(polynomial.data_modulus_index());
        let Some(target_component) = ciphertexts
            .as_mut()
            .get_mut(ciphertext_ordinal)
            .and_then(|ciphertext| ciphertext.components.get_mut(component_ordinal))
        else {
            return Err(RefusalReason::WrongTypeOrLength);
        };
        if target_component.len() != data_modulus_index {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        target_component.push(polynomial.coefficients().to_vec());
    }
    Ok(ciphertexts.into_inner())
}

fn validate_verified_aggregate_object(
    context: VerifiedBallotAggregationContext,
    selected_ballot_object_hashes: &[Hash512],
    aggregate_descriptors: &[StreamDescriptor; PAIR_CHARACTER_CIPHERTEXT_COUNT],
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
        || aggregate_payload.aggregate_ciphertext_descriptors() != aggregate_descriptors
    {
        return Err(RefusalReason::WrongHashOrRoot);
    }
    Ok(())
}

fn selected_ballot_ciphertext_total_byte_length() -> Result<u64, RefusalReason> {
    let single_ciphertext_length =
        selected_ciphertext_total_byte_length(SELECTED_EVALUATOR_WORKING_LEVEL)?;
    single_ciphertext_length
        .checked_sub(4)
        .and_then(|coefficient_bytes| {
            u64::try_from(PAIR_CHARACTER_CIPHERTEXT_COUNT)
                .ok()
                .and_then(|count| coefficient_bytes.checked_mul(count))
        })
        .and_then(|coefficient_bytes| coefficient_bytes.checked_add(4))
        .ok_or(RefusalReason::OutsideSupportedProfile)
}

fn selected_ciphertext_total_byte_length(level: usize) -> Result<u64, RefusalReason> {
    if level >= DATA_PRIMES.len() {
        return Err(RefusalReason::OutsideSupportedProfile);
    }
    let polynomial_degree =
        u64::try_from(POLYNOMIAL_DEGREE).map_err(|_| RefusalReason::OutsideSupportedProfile)?;
    let bytes_per_component = DATA_PRIMES[..=level].iter().try_fold(
        0_u64,
        |total, modulus| -> Result<u64, RefusalReason> {
            let coefficient_byte_length = u64::try_from(canonical_modulus_byte_length(*modulus))
                .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
            total
                .checked_add(
                    polynomial_degree
                        .checked_mul(coefficient_byte_length)
                        .ok_or(RefusalReason::OutsideSupportedProfile)?,
                )
                .ok_or(RefusalReason::OutsideSupportedProfile)
        },
    )?;
    let coefficient_bytes = u64::try_from(CIPHERTEXT_COMPONENT_COUNT)
        .map_err(|_| RefusalReason::OutsideSupportedProfile)?
        .checked_mul(bytes_per_component)
        .ok_or(RefusalReason::OutsideSupportedProfile)?;
    coefficient_bytes
        .checked_add(4)
        .ok_or(RefusalReason::OutsideSupportedProfile)
}

fn derive_aggregate_ciphertext_descriptor(
    aggregate_ciphertext: &Ciphertext,
) -> Result<StreamDescriptor, RefusalReason> {
    if aggregate_ciphertext.level != CHARACTER_OUTPUT_LEVEL
        || aggregate_ciphertext.decrypt_scaling != 1
        || aggregate_ciphertext.components.len() != CIPHERTEXT_COMPONENT_COUNT
    {
        return Err(RefusalReason::WrongTypeOrLength);
    }
    let total_byte_length = selected_ciphertext_total_byte_length(aggregate_ciphertext.level)?;
    let mut writer = CanonicalStreamWriter::new(
        CanonicalStreamDomain::AggregateCiphertext,
        total_byte_length,
    )?;
    let mut chunk = Vec::with_capacity(FOUNDATION_PROFILE.stream_chunk_byte_length);
    let mut next_chunk_index = 0_usize;
    let level = u16::try_from(aggregate_ciphertext.level)
        .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
    let component_count = u16::try_from(CIPHERTEXT_COMPONENT_COUNT)
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
        if component.len() != aggregate_ciphertext.level + 1 {
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

fn combine_product_accounting(
    ballot_count: usize,
    stream_accounting: [PairCharacterProductAccounting; PAIR_CHARACTER_CIPHERTEXT_COUNT],
) -> Result<TwoStreamPairCharacterProductAccounting, RefusalReason> {
    let schedule = canonical_pair_character_product_schedule(ballot_count)
        .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
    if stream_accounting[0] != stream_accounting[1] || stream_accounting[0] != schedule.accounting {
        return Err(RefusalReason::WrongTypeOrLength);
    }
    canonical_two_stream_pair_character_product_accounting(ballot_count)
}

pub(crate) fn canonical_two_stream_pair_character_product_accounting(
    ballot_count: usize,
) -> Result<TwoStreamPairCharacterProductAccounting, RefusalReason> {
    let schedule = canonical_pair_character_product_schedule(ballot_count)
        .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
    let per_stream = schedule.accounting;
    let resource_derivation = derive_two_stream_pair_character_product_resources(ballot_count)?;
    Ok(TwoStreamPairCharacterProductAccounting {
        ballot_ciphertext_count: per_stream
            .ballot_ciphertext_count
            .checked_mul(PAIR_CHARACTER_CIPHERTEXT_COUNT)
            .ok_or(RefusalReason::OutsideSupportedProfile)?,
        ciphertext_multiplication_count: per_stream
            .ciphertext_multiplication_count
            .checked_mul(PAIR_CHARACTER_CIPHERTEXT_COUNT)
            .ok_or(RefusalReason::OutsideSupportedProfile)?,
        relinearization_count: per_stream
            .relinearization_count
            .checked_mul(PAIR_CHARACTER_CIPHERTEXT_COUNT)
            .ok_or(RefusalReason::OutsideSupportedProfile)?,
        normalization_plaintext_multiplication_count: per_stream
            .normalization_plaintext_multiplication_count
            .checked_mul(PAIR_CHARACTER_CIPHERTEXT_COUNT)
            .ok_or(RefusalReason::OutsideSupportedProfile)?,
        modulus_switch_count: per_stream
            .modulus_switch_count()
            .checked_mul(PAIR_CHARACTER_CIPHERTEXT_COUNT)
            .ok_or(RefusalReason::OutsideSupportedProfile)?,
        modulus_drop_count: per_stream
            .modulus_drop_count()
            .checked_mul(PAIR_CHARACTER_CIPHERTEXT_COUNT)
            .ok_or(RefusalReason::OutsideSupportedProfile)?,
        maximum_resident_ciphertext_count: resource_derivation.maximum_resident_ciphertext_count,
        relinearization_key_load_count: resource_derivation.relinearization_key_load_count,
        key_store_read_byte_count: resource_derivation.key_store_read_byte_count,
        key_ntt_transform_count: resource_derivation.key_ntt_transform_count,
        memory: resource_derivation.memory,
    })
}

#[cfg(test)]
fn canonical_two_stream_maximum_resident_ciphertext_count(
    ballot_count: usize,
) -> Result<usize, RefusalReason> {
    Ok(
        derive_two_stream_pair_character_product_resources(ballot_count)?
            .maximum_resident_ciphertext_count,
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ResidentProductCiphertext {
    multiplication_depth: usize,
    level: usize,
}

#[derive(Default)]
struct TwoStreamPairCharacterProductResourceDerivation {
    maximum_resident_ciphertext_count: usize,
    relinearization_key_load_count: usize,
    key_store_read_byte_count: u64,
    key_ntt_transform_count: usize,
    memory: TwoStreamPairCharacterProductMemoryAccounting,
}

impl TwoStreamPairCharacterProductResourceDerivation {
    fn record_boundary(
        &mut self,
        live_ciphertext_count: usize,
        live_ciphertext_coefficient_byte_length: u64,
        resident_key_byte_length: u64,
    ) -> Result<(), RefusalReason> {
        self.maximum_resident_ciphertext_count = self
            .maximum_resident_ciphertext_count
            .max(live_ciphertext_count);
        self.memory.maximum_live_ciphertext_coefficient_byte_length = self
            .memory
            .maximum_live_ciphertext_coefficient_byte_length
            .max(live_ciphertext_coefficient_byte_length);
        self.record_combined_peak(checked_add_u64(
            live_ciphertext_coefficient_byte_length,
            resident_key_byte_length,
        )?);
        Ok(())
    }

    fn record_ciphertext_tensor(
        &mut self,
        outer_live_ciphertext_count: usize,
        outer_live_ciphertext_coefficient_byte_length: u64,
        level: usize,
        resident_key_byte_length: u64,
    ) -> Result<(), RefusalReason> {
        let polynomial_byte_length = polynomial_u64_byte_length()?;
        // On wasm32 the limb iterator is sequential. At the final limb the
        // three-component output is complete while four operand NTTs and three
        // product NTTs remain live inside `ciphertext_tensor_limb`.
        let scratch_byte_length = checked_mul_u64(7, polynomial_byte_length)?;
        let output_byte_length = ciphertext_coefficient_byte_length(level, 3)?;
        let transient_byte_length = checked_add_u64(output_byte_length, scratch_byte_length)?;
        self.memory.maximum_ciphertext_tensor_scratch_byte_length = self
            .memory
            .maximum_ciphertext_tensor_scratch_byte_length
            .max(scratch_byte_length);
        self.memory.maximum_ciphertext_tensor_transient_byte_length = self
            .memory
            .maximum_ciphertext_tensor_transient_byte_length
            .max(transient_byte_length);
        self.record_operation(
            outer_live_ciphertext_count,
            outer_live_ciphertext_coefficient_byte_length,
            output_byte_length,
            transient_byte_length,
            scratch_byte_length,
            resident_key_byte_length,
        )
    }

    fn record_relinearization(
        &mut self,
        outer_live_ciphertext_count: usize,
        outer_live_ciphertext_coefficient_byte_length: u64,
        level: usize,
        resident_key_byte_length: u64,
    ) -> Result<(), RefusalReason> {
        let polynomial_byte_length = polynomial_u64_byte_length()?;
        let active_topology = KeySwitchDecompositionTopology::for_level(level)
            .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)?;
        let data_limb_count = u64::try_from(active_topology.data_prime_count())
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        let extended_limb_count = u64::try_from(active_topology.extended_limb_count())
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        let special_limb_count = extended_limb_count
            .checked_sub(data_limb_count)
            .ok_or(RefusalReason::WrongTypeOrLength)?;

        // The first hybrid modulus-down is the largest key-switch scratch
        // phase: both extended accumulators, the centered digit and its NTT,
        // one switched output component, and the centered special-basis
        // reconstruction coexist. The small special-basis catalogs are one
        // u128 accumulated modulus plus two u64 values per special prime.
        let first_modulus_down_polynomial_count = extended_limb_count
            .checked_mul(2)
            .and_then(|count| count.checked_add(data_limb_count))
            .and_then(|count| count.checked_add(6))
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        let first_modulus_down_scratch_byte_length = checked_add_u64(
            checked_mul_u64(first_modulus_down_polynomial_count, polynomial_byte_length)?,
            checked_mul_u64(special_limb_count, 32)?,
        )?;
        // After key-switching returns, both switched components coexist with
        // the two cloned components that form the returned ciphertext.
        let output_byte_length = ciphertext_coefficient_byte_length(level, 2)?;
        let post_key_switch_scratch_byte_length = output_byte_length;
        let scratch_byte_length =
            first_modulus_down_scratch_byte_length.max(post_key_switch_scratch_byte_length);
        let transient_byte_length = first_modulus_down_scratch_byte_length.max(checked_add_u64(
            output_byte_length,
            post_key_switch_scratch_byte_length,
        )?);
        self.memory.maximum_relinearization_scratch_byte_length = self
            .memory
            .maximum_relinearization_scratch_byte_length
            .max(scratch_byte_length);
        self.memory.maximum_relinearization_transient_byte_length = self
            .memory
            .maximum_relinearization_transient_byte_length
            .max(transient_byte_length);
        self.record_operation(
            outer_live_ciphertext_count,
            outer_live_ciphertext_coefficient_byte_length,
            output_byte_length,
            transient_byte_length,
            scratch_byte_length,
            resident_key_byte_length,
        )
    }

    fn record_plaintext_multiplication(
        &mut self,
        outer_live_ciphertext_count: usize,
        outer_live_ciphertext_coefficient_byte_length: u64,
        level: usize,
        resident_key_byte_length: u64,
    ) -> Result<(), RefusalReason> {
        let polynomial_byte_length = polynomial_u64_byte_length()?;
        // The lifted plaintext, its NTT, one component NTT, and its pointwise
        // product remain live while the last inverse transform completes.
        let scratch_byte_length = checked_mul_u64(4, polynomial_byte_length)?;
        let output_byte_length = ciphertext_coefficient_byte_length(level, 2)?;
        let transient_byte_length = checked_add_u64(output_byte_length, scratch_byte_length)?;
        self.memory
            .maximum_plaintext_multiplication_scratch_byte_length = self
            .memory
            .maximum_plaintext_multiplication_scratch_byte_length
            .max(scratch_byte_length);
        self.memory
            .maximum_plaintext_multiplication_transient_byte_length = self
            .memory
            .maximum_plaintext_multiplication_transient_byte_length
            .max(transient_byte_length);
        self.record_operation(
            outer_live_ciphertext_count,
            outer_live_ciphertext_coefficient_byte_length,
            output_byte_length,
            transient_byte_length,
            scratch_byte_length,
            resident_key_byte_length,
        )
    }

    fn record_modulus_switch(
        &mut self,
        outer_live_ciphertext_count: usize,
        outer_live_ciphertext_coefficient_byte_length: u64,
        source_level: usize,
        resident_key_byte_length: u64,
    ) -> Result<(), RefusalReason> {
        let target_level = source_level
            .checked_sub(1)
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        let polynomial_byte_length = polynomial_u64_byte_length()?;
        // One i128 correction polynomial and the u64 inverse catalog remain
        // live while the two lower-level output components are completed.
        let correction_byte_length = checked_mul_u64(2, polynomial_byte_length)?;
        let dropped_inverse_byte_length = checked_mul_u64(
            u64::try_from(target_level + 1).map_err(|_| RefusalReason::OutsideSupportedProfile)?,
            u64::from(u64::BITS / 8),
        )?;
        let scratch_byte_length =
            checked_add_u64(correction_byte_length, dropped_inverse_byte_length)?;
        let output_byte_length = ciphertext_coefficient_byte_length(target_level, 2)?;
        let transient_byte_length = checked_add_u64(output_byte_length, scratch_byte_length)?;
        self.memory.maximum_modulus_switch_scratch_byte_length = self
            .memory
            .maximum_modulus_switch_scratch_byte_length
            .max(scratch_byte_length);
        self.memory.maximum_modulus_switch_transient_byte_length = self
            .memory
            .maximum_modulus_switch_transient_byte_length
            .max(transient_byte_length);
        self.record_operation(
            outer_live_ciphertext_count,
            outer_live_ciphertext_coefficient_byte_length,
            output_byte_length,
            transient_byte_length,
            scratch_byte_length,
            resident_key_byte_length,
        )
    }

    fn record_operation(
        &mut self,
        outer_live_ciphertext_count: usize,
        outer_live_ciphertext_coefficient_byte_length: u64,
        output_byte_length: u64,
        transient_byte_length: u64,
        scratch_byte_length: u64,
        resident_key_byte_length: u64,
    ) -> Result<(), RefusalReason> {
        self.memory.maximum_operation_transient_byte_length = self
            .memory
            .maximum_operation_transient_byte_length
            .max(transient_byte_length);
        self.memory.maximum_operation_scratch_byte_length = self
            .memory
            .maximum_operation_scratch_byte_length
            .max(scratch_byte_length);
        self.record_boundary(
            outer_live_ciphertext_count
                .checked_add(1)
                .ok_or(RefusalReason::OutsideSupportedProfile)?,
            checked_add_u64(
                outer_live_ciphertext_coefficient_byte_length,
                output_byte_length,
            )?,
            resident_key_byte_length,
        )?;
        self.record_combined_peak(checked_sum_u64(&[
            outer_live_ciphertext_coefficient_byte_length,
            transient_byte_length,
            resident_key_byte_length,
        ])?);
        Ok(())
    }

    fn record_key_replay_peak(
        &mut self,
        live_ciphertext_coefficient_byte_length: u64,
        one_component_resident_byte_length: u64,
    ) -> Result<(), RefusalReason> {
        let limb_buffer_byte_length = self.memory.key_replay_limb_buffer_byte_length;
        let final_chunk_byte_length = self.memory.final_key_store_chunk_byte_length;
        // Both coefficient decoders are allocated during the first physical
        // pass. Only the auxiliary decoder remains during the second pass,
        // whose final chunk coexists with the complete resident key.
        let runtime_pass_peak = checked_sum_u64(&[
            one_component_resident_byte_length,
            checked_mul_u64(2, limb_buffer_byte_length)?,
            final_chunk_byte_length,
        ])?;
        let auxiliary_pass_peak = checked_sum_u64(&[
            self.memory
                .resident_relinearization_key_coefficient_byte_length,
            limb_buffer_byte_length,
            final_chunk_byte_length,
        ])?;
        let peak = checked_add_u64(
            live_ciphertext_coefficient_byte_length,
            runtime_pass_peak.max(auxiliary_pass_peak),
        )?;
        self.memory.peak_key_replay_wasm_resident_byte_length = peak;
        self.record_combined_peak(peak);
        Ok(())
    }

    fn record_combined_peak(&mut self, candidate: u64) {
        self.memory.peak_combined_wasm_resident_byte_length = self
            .memory
            .peak_combined_wasm_resident_byte_length
            .max(candidate);
    }
}

fn derive_two_stream_pair_character_product_resources(
    ballot_count: usize,
) -> Result<TwoStreamPairCharacterProductResourceDerivation, RefusalReason> {
    if ballot_count == 0 || ballot_count > usize::from(FOUNDATION_PROFILE.participant_count) {
        return Err(RefusalReason::OutsideSupportedProfile);
    }
    let mut derivation = TwoStreamPairCharacterProductResourceDerivation::default();
    let mut forests = [
        Vec::<ResidentProductCiphertext>::new(),
        Vec::<ResidentProductCiphertext>::new(),
    ];
    let selected_key_topology =
        KeySwitchDecompositionTopology::for_level(SELECTED_RELINEARIZATION_KEY_LEVEL)
            .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)?;
    let uses_relinearization_key = ballot_count >= 2;
    let one_key_component_resident_byte_length = if uses_relinearization_key {
        selected_key_topology
            .resident_component_byte_length(POLYNOMIAL_DEGREE)
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?
    } else {
        0
    };
    let resident_key_byte_length = if uses_relinearization_key {
        checked_mul_u64(2, one_key_component_resident_byte_length)?
    } else {
        0
    };
    let key_component_wire_byte_length = if uses_relinearization_key {
        selected_key_topology
            .canonical_component_wire_byte_length(POLYNOMIAL_DEGREE)
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?
    } else {
        0
    };
    let stream_chunk_byte_length = u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length)
        .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
    derivation.relinearization_key_load_count = usize::from(uses_relinearization_key);
    derivation.key_store_read_byte_count = if uses_relinearization_key {
        checked_mul_u64(2, key_component_wire_byte_length)?
    } else {
        0
    };
    derivation.key_ntt_transform_count = if uses_relinearization_key {
        selected_key_topology
            .data_block_count()
            .checked_mul(selected_key_topology.extended_limb_count())
            .and_then(|count| count.checked_mul(2))
            .ok_or(RefusalReason::OutsideSupportedProfile)?
    } else {
        0
    };
    derivation
        .memory
        .relinearization_key_component_wire_byte_length = key_component_wire_byte_length;
    derivation
        .memory
        .resident_relinearization_key_coefficient_byte_length = resident_key_byte_length;
    derivation.memory.maximum_key_store_chunk_byte_length = if uses_relinearization_key {
        key_component_wire_byte_length.min(stream_chunk_byte_length)
    } else {
        0
    };
    derivation.memory.final_key_store_chunk_byte_length = if uses_relinearization_key {
        let remainder = key_component_wire_byte_length % stream_chunk_byte_length;
        if remainder == 0 {
            stream_chunk_byte_length
        } else {
            remainder
        }
    } else {
        0
    };
    derivation.memory.key_replay_limb_buffer_byte_length = if uses_relinearization_key {
        polynomial_u64_byte_length()?
    } else {
        0
    };

    let fresh_ciphertext_byte_length = ciphertext_coefficient_byte_length(
        SELECTED_EVALUATOR_WORKING_LEVEL,
        CIPHERTEXT_COMPONENT_COUNT,
    )?;
    for ballot_ordinal in 0..ballot_count {
        if ballot_ordinal == 1 {
            derivation.record_key_replay_peak(
                forest_coefficient_byte_length(&forests)?,
                one_key_component_resident_byte_length,
            )?;
        }
        let active_resident_key_byte_length = if ballot_ordinal == 0 {
            0
        } else {
            resident_key_byte_length
        };
        derivation.record_boundary(
            forest_ciphertext_count(&forests)
                .checked_add(PAIR_CHARACTER_CIPHERTEXT_COUNT)
                .ok_or(RefusalReason::OutsideSupportedProfile)?,
            checked_add_u64(
                forest_coefficient_byte_length(&forests)?,
                checked_mul_u64(
                    u64::try_from(PAIR_CHARACTER_CIPHERTEXT_COUNT)
                        .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
                    fresh_ciphertext_byte_length,
                )?,
            )?,
            active_resident_key_byte_length,
        )?;
        for stream_ordinal in 0..PAIR_CHARACTER_CIPHERTEXT_COUNT {
            let pending_input_count = PAIR_CHARACTER_CIPHERTEXT_COUNT - stream_ordinal - 1;
            forests[stream_ordinal].push(ResidentProductCiphertext {
                multiplication_depth: 0,
                level: SELECTED_EVALUATOR_WORKING_LEVEL,
            });
            derivation.record_boundary(
                forest_ciphertext_count(&forests)
                    .checked_add(pending_input_count)
                    .ok_or(RefusalReason::OutsideSupportedProfile)?,
                checked_add_u64(
                    forest_coefficient_byte_length(&forests)?,
                    checked_mul_u64(
                        u64::try_from(pending_input_count)
                            .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
                        fresh_ciphertext_byte_length,
                    )?,
                )?,
                active_resident_key_byte_length,
            )?;
            while forests[stream_ordinal].len() >= 2 {
                let right = forests[stream_ordinal][forests[stream_ordinal].len() - 1];
                let left = forests[stream_ordinal][forests[stream_ordinal].len() - 2];
                if left.multiplication_depth != right.multiplication_depth {
                    break;
                }
                derive_resource_merge(
                    &mut derivation,
                    &mut forests,
                    stream_ordinal,
                    pending_input_count,
                    active_resident_key_byte_length,
                )?;
            }
        }
    }

    for stream_ordinal in 0..PAIR_CHARACTER_CIPHERTEXT_COUNT {
        while forests[stream_ordinal].len() > 1 {
            derive_resource_merge(
                &mut derivation,
                &mut forests,
                stream_ordinal,
                0,
                resident_key_byte_length,
            )?;
        }
        let mut root = forests[stream_ordinal]
            .pop()
            .ok_or(RefusalReason::ConsumedState)?;
        let unrelated_count = forest_ciphertext_count(&forests);
        let unrelated_byte_length = forest_coefficient_byte_length(&forests)?;
        if ballot_count < usize::from(FOUNDATION_PROFILE.participant_count) {
            let root_byte_length =
                ciphertext_coefficient_byte_length(root.level, CIPHERTEXT_COMPONENT_COUNT)?;
            derivation.record_plaintext_multiplication(
                unrelated_count
                    .checked_add(1)
                    .ok_or(RefusalReason::OutsideSupportedProfile)?,
                checked_add_u64(unrelated_byte_length, root_byte_length)?,
                root.level,
                resident_key_byte_length,
            )?;
        }
        while root.level > CHARACTER_OUTPUT_LEVEL {
            let root_byte_length =
                ciphertext_coefficient_byte_length(root.level, CIPHERTEXT_COMPONENT_COUNT)?;
            derivation.record_modulus_switch(
                unrelated_count
                    .checked_add(1)
                    .ok_or(RefusalReason::OutsideSupportedProfile)?,
                checked_add_u64(unrelated_byte_length, root_byte_length)?,
                root.level,
                resident_key_byte_length,
            )?;
            root.level -= 1;
        }
        forests[stream_ordinal].push(root);
        derivation.record_boundary(
            forest_ciphertext_count(&forests),
            forest_coefficient_byte_length(&forests)?,
            resident_key_byte_length,
        )?;
    }

    Ok(derivation)
}

fn derive_resource_merge(
    derivation: &mut TwoStreamPairCharacterProductResourceDerivation,
    forests: &mut [Vec<ResidentProductCiphertext>; PAIR_CHARACTER_CIPHERTEXT_COUNT],
    stream_ordinal: usize,
    pending_input_count: usize,
    resident_key_byte_length: u64,
) -> Result<(), RefusalReason> {
    let mut right = forests[stream_ordinal]
        .pop()
        .ok_or(RefusalReason::ConsumedState)?;
    let mut left = forests[stream_ordinal]
        .pop()
        .ok_or(RefusalReason::ConsumedState)?;
    let unrelated_count = forest_ciphertext_count(forests)
        .checked_add(pending_input_count)
        .ok_or(RefusalReason::OutsideSupportedProfile)?;
    let unrelated_byte_length = checked_add_u64(
        forest_coefficient_byte_length(forests)?,
        checked_mul_u64(
            u64::try_from(pending_input_count)
                .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
            ciphertext_coefficient_byte_length(
                SELECTED_EVALUATOR_WORKING_LEVEL,
                CIPHERTEXT_COMPONENT_COUNT,
            )?,
        )?,
    )?;
    let alignment_level = left.level.min(right.level);
    while left.level > alignment_level {
        record_resource_modulus_switch(
            derivation,
            unrelated_count,
            unrelated_byte_length,
            left,
            right,
            resident_key_byte_length,
        )?;
        left.level -= 1;
    }
    while right.level > alignment_level {
        record_resource_modulus_switch(
            derivation,
            unrelated_count,
            unrelated_byte_length,
            right,
            left,
            resident_key_byte_length,
        )?;
        right.level -= 1;
    }
    let left_byte_length =
        ciphertext_coefficient_byte_length(left.level, CIPHERTEXT_COMPONENT_COUNT)?;
    let right_byte_length =
        ciphertext_coefficient_byte_length(right.level, CIPHERTEXT_COMPONENT_COUNT)?;
    let tensor_outer_byte_length =
        checked_sum_u64(&[unrelated_byte_length, left_byte_length, right_byte_length])?;
    derivation.record_ciphertext_tensor(
        unrelated_count
            .checked_add(2)
            .ok_or(RefusalReason::OutsideSupportedProfile)?,
        tensor_outer_byte_length,
        alignment_level,
        resident_key_byte_length,
    )?;
    let tensor_byte_length = ciphertext_coefficient_byte_length(alignment_level, 3)?;
    derivation.record_relinearization(
        unrelated_count
            .checked_add(1)
            .ok_or(RefusalReason::OutsideSupportedProfile)?,
        checked_add_u64(unrelated_byte_length, tensor_byte_length)?,
        alignment_level,
        resident_key_byte_length,
    )?;

    let multiplication_depth = left
        .multiplication_depth
        .max(right.multiplication_depth)
        .checked_add(1)
        .ok_or(RefusalReason::OutsideSupportedProfile)?;
    let depth_drop_count = *SELECTED_EVALUATOR_MODULUS_SCHEDULE
        .character_depth_drop_counts
        .get(multiplication_depth - 1)
        .ok_or(RefusalReason::UnsupportedVersionOrSuite)?;
    let output_level = alignment_level
        .checked_sub(depth_drop_count)
        .ok_or(RefusalReason::WrongTypeOrLength)?;
    let mut output = ResidentProductCiphertext {
        multiplication_depth,
        level: alignment_level,
    };
    while output.level > output_level {
        let output_byte_length =
            ciphertext_coefficient_byte_length(output.level, CIPHERTEXT_COMPONENT_COUNT)?;
        derivation.record_modulus_switch(
            unrelated_count
                .checked_add(1)
                .ok_or(RefusalReason::OutsideSupportedProfile)?,
            checked_add_u64(unrelated_byte_length, output_byte_length)?,
            output.level,
            resident_key_byte_length,
        )?;
        output.level -= 1;
    }
    forests[stream_ordinal].push(output);
    derivation.record_boundary(
        unrelated_count
            .checked_add(1)
            .ok_or(RefusalReason::OutsideSupportedProfile)?,
        checked_add_u64(
            unrelated_byte_length,
            ciphertext_coefficient_byte_length(output.level, CIPHERTEXT_COMPONENT_COUNT)?,
        )?,
        resident_key_byte_length,
    )?;
    Ok(())
}

fn record_resource_modulus_switch(
    derivation: &mut TwoStreamPairCharacterProductResourceDerivation,
    unrelated_count: usize,
    unrelated_byte_length: u64,
    source: ResidentProductCiphertext,
    other_input: ResidentProductCiphertext,
    resident_key_byte_length: u64,
) -> Result<(), RefusalReason> {
    derivation.record_modulus_switch(
        unrelated_count
            .checked_add(2)
            .ok_or(RefusalReason::OutsideSupportedProfile)?,
        checked_sum_u64(&[
            unrelated_byte_length,
            ciphertext_coefficient_byte_length(source.level, CIPHERTEXT_COMPONENT_COUNT)?,
            ciphertext_coefficient_byte_length(other_input.level, CIPHERTEXT_COMPONENT_COUNT)?,
        ])?,
        source.level,
        resident_key_byte_length,
    )
}

fn forest_ciphertext_count(
    forests: &[Vec<ResidentProductCiphertext>; PAIR_CHARACTER_CIPHERTEXT_COUNT],
) -> usize {
    forests.iter().map(Vec::len).sum()
}

fn forest_coefficient_byte_length(
    forests: &[Vec<ResidentProductCiphertext>; PAIR_CHARACTER_CIPHERTEXT_COUNT],
) -> Result<u64, RefusalReason> {
    forests.iter().flatten().try_fold(0_u64, |total, node| {
        checked_add_u64(
            total,
            ciphertext_coefficient_byte_length(node.level, CIPHERTEXT_COMPONENT_COUNT)?,
        )
    })
}

fn ciphertext_coefficient_byte_length(
    level: usize,
    component_count: usize,
) -> Result<u64, RefusalReason> {
    if level >= DATA_PRIMES.len() || component_count == 0 {
        return Err(RefusalReason::UnsupportedVersionOrSuite);
    }
    checked_mul_u64(
        u64::try_from(level + 1).map_err(|_| RefusalReason::OutsideSupportedProfile)?,
        checked_mul_u64(
            u64::try_from(component_count).map_err(|_| RefusalReason::OutsideSupportedProfile)?,
            polynomial_u64_byte_length()?,
        )?,
    )
}

fn polynomial_u64_byte_length() -> Result<u64, RefusalReason> {
    checked_mul_u64(
        u64::try_from(POLYNOMIAL_DEGREE).map_err(|_| RefusalReason::OutsideSupportedProfile)?,
        u64::from(u64::BITS / 8),
    )
}

fn checked_sum_u64(values: &[u64]) -> Result<u64, RefusalReason> {
    values
        .iter()
        .try_fold(0_u64, |total, value| checked_add_u64(total, *value))
}

fn checked_add_u64(left: u64, right: u64) -> Result<u64, RefusalReason> {
    left.checked_add(right)
        .ok_or(RefusalReason::OutsideSupportedProfile)
}

fn checked_mul_u64(left: u64, right: u64) -> Result<u64, RefusalReason> {
    left.checked_mul(right)
        .ok_or(RefusalReason::OutsideSupportedProfile)
}

fn zeroize_ciphertext(ciphertext: &mut Ciphertext) {
    ciphertext.components.zeroize();
    ciphertext.level.zeroize();
    ciphertext.decrypt_scaling.zeroize();
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
    fn aggregate_validation_accepts_both_ordered_recomputed_streams() {
        let context = test_context();
        let selected_ballot_object_hashes = vec![test_hash(0x61), test_hash(0x62)];
        let aggregate_descriptors = [test_descriptor(0x71), test_descriptor(0x72)];
        let payload = AggregatePayload::new(
            Hash512::from_bytes(context.verified_setup_source_hash),
            selected_ballot_object_hashes.clone(),
            aggregate_descriptors.clone(),
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
                &aggregate_descriptors,
                &envelope,
                &decoded_payload,
            ),
            Ok(())
        );
    }

    #[test]
    fn aggregate_validation_rejects_rebound_hashes_and_either_stream() {
        let context = test_context();
        let selected_ballot_object_hashes = vec![test_hash(0x61), test_hash(0x62)];
        let descriptors = [test_descriptor(0x71), test_descriptor(0x72)];
        for (hashes, rebound_descriptors) in [
            (vec![test_hash(0x61), test_hash(0x63)], descriptors.clone()),
            (
                selected_ballot_object_hashes.clone(),
                [test_descriptor(0x73), descriptors[1].clone()],
            ),
            (
                selected_ballot_object_hashes.clone(),
                [descriptors[0].clone(), test_descriptor(0x74)],
            ),
            (
                selected_ballot_object_hashes.clone(),
                [descriptors[1].clone(), descriptors[0].clone()],
            ),
        ] {
            let payload = AggregatePayload::new(
                Hash512::from_bytes(context.verified_setup_source_hash),
                hashes,
                rebound_descriptors,
            )
            .expect("rebound aggregate payload");
            let envelope = test_aggregate_envelope(context, &payload);
            let decoded = AggregatePayload::decode(
                &envelope.payload_bytes,
                &CanonicalDecodeLimits::default(),
            )
            .expect("rebound payload decodes");
            assert_eq!(
                validate_verified_aggregate_object(
                    context,
                    &selected_ballot_object_hashes,
                    &descriptors,
                    &envelope,
                    &decoded,
                ),
                Err(RefusalReason::WrongHashOrRoot)
            );
        }
    }

    #[test]
    fn combined_residency_pins_the_sequential_two_stream_schedule() {
        let expected = [3, 5, 5, 7, 7, 7, 7, 9, 9, 9];
        for (ballot_index, expected_maximum) in expected.into_iter().enumerate() {
            assert_eq!(
                canonical_two_stream_maximum_resident_ciphertext_count(ballot_index + 1)
                    .expect("combined resident schedule"),
                expected_maximum
            );
        }
        assert!(canonical_two_stream_maximum_resident_ciphertext_count(0).is_err());
        assert!(canonical_two_stream_maximum_resident_ciphertext_count(11).is_err());
    }

    #[test]
    fn output_descriptor_length_uses_only_the_level_nineteen_basis() {
        let level_nineteen_length = selected_ciphertext_total_byte_length(CHARACTER_OUTPUT_LEVEL)
            .expect("level-19 descriptor length");
        let level_twenty_two_length =
            selected_ciphertext_total_byte_length(SELECTED_EVALUATOR_WORKING_LEVEL)
                .expect("level-22 descriptor length");
        assert!(level_nineteen_length < level_twenty_two_length);
        assert_eq!(
            selected_ballot_ciphertext_total_byte_length().expect("two input ciphertexts"),
            2 * (level_twenty_two_length - 4) + 4
        );
    }
}
