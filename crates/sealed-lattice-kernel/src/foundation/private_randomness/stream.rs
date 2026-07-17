use core::{cmp, fmt};

use tiny_keccak::{Hasher, Kmac};
use zeroize::Zeroizing;

use super::super::schemas::{
    SchemaResult, read_fixed_bytes, read_hash, read_u16, read_u64, require_header,
};
use super::super::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple, FOUNDATION_PROFILE,
    FoundationSchemaError, Hash512, RefusalReason,
};
use super::domain::PrivateRandomnessDomain;
use super::material::{ActionPrivateRandomness, ActionRandomnessDerivationInput};
use super::proof_coins::PrivateRandomnessAttemptIdentifier;
use super::validation::{
    read_optional_u16, read_participant_identity, require_protocol_version, validate_cursor_offset,
};
use super::{
    FOUNDATION_SCHEMA_VERSION, PRIVATE_RANDOM_BLOCK_INPUT_SCHEMA_IDENTIFIER,
    PRIVATE_RANDOMNESS_ATTEMPT_IDENTIFIER_BYTE_LENGTH, PRIVATE_RANDOMNESS_BLOCK_BIT_LENGTH,
    PRIVATE_RANDOMNESS_BLOCK_BYTE_LENGTH, PRIVATE_RANDOMNESS_BLOCK_CUSTOMIZATION,
    RANDOM_CURSOR_SCHEMA_IDENTIFIER, schema_error,
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateRandomBlockInput {
    derivation_input: ActionRandomnessDerivationInput,
    pub(super) domain: PrivateRandomnessDomain,
    pub(super) derivation_context_hash: Hash512,
    attempt_identifier: [u8; PRIVATE_RANDOMNESS_ATTEMPT_IDENTIFIER_BYTE_LENGTH],
    counter: u64,
}

impl fmt::Debug for PrivateRandomBlockInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateRandomBlockInput")
            .field("derivation_input", &self.derivation_input)
            .field("domain", &self.domain)
            .field("derivation_context_hash", &self.derivation_context_hash)
            .field("attempt_identifier", &"[REDACTED]")
            .field("counter", &self.counter)
            .finish()
    }
}

impl PrivateRandomBlockInput {
    pub(super) fn new(
        derivation_input: ActionRandomnessDerivationInput,
        domain: PrivateRandomnessDomain,
        derivation_context_hash: Hash512,
        attempt_identifier: PrivateRandomnessAttemptIdentifier,
        counter: u64,
    ) -> SchemaResult<Self> {
        require_attempt_class(domain, attempt_identifier)?;
        Ok(Self {
            derivation_input,
            domain,
            derivation_context_hash,
            attempt_identifier: attempt_identifier.bytes,
            counter,
        })
    }

    pub const fn derivation_input(self) -> ActionRandomnessDerivationInput {
        self.derivation_input
    }

    pub const fn domain(self) -> PrivateRandomnessDomain {
        self.domain
    }

    pub const fn derivation_context_hash(self) -> Hash512 {
        self.derivation_context_hash
    }

    pub const fn attempt_identifier(
        self,
    ) -> [u8; PRIVATE_RANDOMNESS_ATTEMPT_IDENTIFIER_BYTE_LENGTH] {
        self.attempt_identifier
    }

    pub const fn counter(self) -> u64 {
        self.counter
    }

    fn canonical_tuple(self) -> SchemaResult<CanonicalTuple> {
        Ok(CanonicalTuple::new(
            PRIVATE_RANDOM_BLOCK_INPUT_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(FOUNDATION_PROFILE.protocol_version),
                CanonicalItem::hash512(self.derivation_input.suite_identifier().into_bytes()),
                CanonicalItem::hash512(self.derivation_input.ceremony_context_hash().into_bytes()),
                CanonicalItem::hash512(self.derivation_input.action_context_hash().into_bytes()),
                CanonicalItem::participant_identity(
                    self.derivation_input.participant_identity().into_bytes(),
                ),
                CanonicalItem::unsigned16(self.domain.family),
                CanonicalItem::unsigned16(self.domain.purpose),
                CanonicalItem::hash512(self.derivation_context_hash.into_bytes()),
                CanonicalItem::fixed_bytes(self.attempt_identifier)?,
                CanonicalItem::unsigned64(self.counter),
            ],
        ))
    }

    pub fn encode(self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple()?.encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        require_header(&tuple, PRIVATE_RANDOM_BLOCK_INPUT_SCHEMA_IDENTIFIER, 10)?;
        require_protocol_version(read_u16(&tuple.items[0])?)?;
        let domain = PrivateRandomnessDomain::from_assigned_pair(
            read_u16(&tuple.items[5])?,
            read_u16(&tuple.items[6])?,
        )?;
        let derivation_input = ActionRandomnessDerivationInput::new(
            read_hash(&tuple.items[1])?,
            read_hash(&tuple.items[2])?,
            read_hash(&tuple.items[3])?,
            read_participant_identity(&tuple.items[4])?,
        );
        let attempt_identifier = PrivateRandomnessAttemptIdentifier {
            bytes: read_fixed_bytes(&tuple.items[8])?,
            attempt_class: domain.attempt_class(),
        };
        Self::new(
            derivation_input,
            domain,
            read_hash(&tuple.items[7])?,
            attempt_identifier,
            read_u64(&tuple.items[9])?,
        )
    }
}

pub struct PrivateRandomnessStream<'action> {
    pub(super) action_private_randomness: &'action ActionPrivateRandomness,
    pub(super) domain: PrivateRandomnessDomain,
    pub(super) derivation_context_hash: Hash512,
    pub(super) attempt_identifier: PrivateRandomnessAttemptIdentifier,
    pub(super) next_counter: u64,
    pub(super) buffered_block: Zeroizing<[u8; PRIVATE_RANDOMNESS_BLOCK_BYTE_LENGTH]>,
    pub(super) next_unread_bit_offset_in_buffered_block: Option<u16>,
}

impl PrivateRandomnessStream<'_> {
    pub fn cursor(&self) -> PrivateRandomCursor {
        PrivateRandomCursor {
            domain: self.domain,
            derivation_context_hash: self.derivation_context_hash,
            stream_attempt_identifier: self.attempt_identifier.bytes,
            next_counter: self.next_counter,
            next_unread_bit_offset_in_buffered_block: self.next_unread_bit_offset_in_buffered_block,
        }
    }

    pub fn fill_bytes(&mut self, output: &mut [u8]) -> SchemaResult<()> {
        if self
            .next_unread_bit_offset_in_buffered_block
            .is_some_and(|offset| offset % 8 != 0)
        {
            return Err(schema_error(
                RefusalReason::ConsumedState,
                "byte-oriented private randomness cannot resume from a partial byte",
            ));
        }

        let mut output_offset = 0usize;
        while output_offset < output.len() {
            self.ensure_buffered_block()?;
            let bit_offset = usize::from(self.buffered_bit_offset()?);
            let block_byte_offset = bit_offset / 8;
            let copy_length = cmp::min(
                output.len() - output_offset,
                PRIVATE_RANDOMNESS_BLOCK_BYTE_LENGTH - block_byte_offset,
            );
            output[output_offset..output_offset + copy_length].copy_from_slice(
                &self.buffered_block[block_byte_offset..block_byte_offset + copy_length],
            );
            output_offset += copy_length;
            let consumed_bit_length = u16::try_from(copy_length * 8).map_err(|_| {
                schema_error(
                    RefusalReason::OutsideSupportedProfile,
                    "private-randomness byte consumption does not fit the cursor offset",
                )
            })?;
            self.advance_buffered_bit_offset(consumed_bit_length)?;
        }
        Ok(())
    }

    pub fn sample_modulo(
        &mut self,
        modulus: u64,
        maximum_candidate_draws_per_output: u32,
    ) -> SchemaResult<u64> {
        sample_modulo_from_byte_source(
            modulus,
            maximum_candidate_draws_per_output,
            |candidate_bytes| self.fill_bytes(candidate_bytes),
        )
    }

    pub fn sample_centered_ternary(
        &mut self,
        maximum_candidate_draws_per_output: u32,
    ) -> SchemaResult<i8> {
        match self.sample_modulo(3, maximum_candidate_draws_per_output)? {
            0 => Ok(-1),
            1 => Ok(0),
            2 => Ok(1),
            _ => Err(schema_error(
                RefusalReason::InvalidArithmeticRelation,
                "private ternary sampling produced a residue outside modulo three",
            )),
        }
    }

    pub fn sample_bit(&mut self) -> SchemaResult<bool> {
        self.ensure_buffered_block()?;
        let bit_offset = self.buffered_bit_offset()?;
        let byte = self.buffered_block[usize::from(bit_offset / 8)];
        let bit = ((byte >> (bit_offset % 8)) & 1) == 1;
        self.advance_buffered_bit_offset(1)?;
        Ok(bit)
    }

    pub fn sample_centered_binomial(&mut self, eta: u16) -> SchemaResult<i32> {
        if eta == 0 {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "centered-binomial sampling requires a positive eta",
            ));
        }
        let mut positive_sum = 0i32;
        for _ in 0..eta {
            positive_sum += i32::from(self.sample_bit()?);
        }
        let mut negative_sum = 0i32;
        for _ in 0..eta {
            negative_sum += i32::from(self.sample_bit()?);
        }
        Ok(positive_sum - negative_sum)
    }

    fn ensure_buffered_block(&mut self) -> SchemaResult<()> {
        if self.next_unread_bit_offset_in_buffered_block.is_some() {
            return Ok(());
        }
        let counter = self.next_counter;
        let next_counter = self.next_counter.checked_add(1).ok_or_else(|| {
            schema_error(
                RefusalReason::ConsumedState,
                "private-randomness block counter is exhausted",
            )
        })?;
        let block = self.derive_block(counter)?;
        self.next_counter = next_counter;
        self.buffered_block = block;
        self.next_unread_bit_offset_in_buffered_block = Some(0);
        Ok(())
    }

    pub(super) fn derive_block(
        &self,
        counter: u64,
    ) -> SchemaResult<Zeroizing<[u8; PRIVATE_RANDOMNESS_BLOCK_BYTE_LENGTH]>> {
        let input = PrivateRandomBlockInput::new(
            self.action_private_randomness.derivation_input(),
            self.domain,
            self.derivation_context_hash,
            self.attempt_identifier,
            counter,
        )?;
        Ok(kmac256_zeroizing::<PRIVATE_RANDOMNESS_BLOCK_BYTE_LENGTH>(
            self.action_private_randomness
                .private_randomness_stream_key
                .as_ref(),
            &input.encode()?,
            PRIVATE_RANDOMNESS_BLOCK_CUSTOMIZATION,
        ))
    }

    fn buffered_bit_offset(&self) -> SchemaResult<u16> {
        self.next_unread_bit_offset_in_buffered_block
            .ok_or_else(|| {
                schema_error(
                    RefusalReason::ConsumedState,
                    "private-randomness stream has no buffered block",
                )
            })
    }

    fn advance_buffered_bit_offset(&mut self, consumed_bit_length: u16) -> SchemaResult<()> {
        let next_offset = self
            .buffered_bit_offset()?
            .checked_add(consumed_bit_length)
            .ok_or_else(|| {
                schema_error(
                    RefusalReason::ConsumedState,
                    "private-randomness buffered bit offset overflows",
                )
            })?;
        if next_offset == PRIVATE_RANDOMNESS_BLOCK_BIT_LENGTH {
            self.buffered_block = Zeroizing::new([0u8; PRIVATE_RANDOMNESS_BLOCK_BYTE_LENGTH]);
            self.next_unread_bit_offset_in_buffered_block = None;
        } else if next_offset < PRIVATE_RANDOMNESS_BLOCK_BIT_LENGTH {
            self.next_unread_bit_offset_in_buffered_block = Some(next_offset);
        } else {
            return Err(schema_error(
                RefusalReason::ConsumedState,
                "private-randomness consumption exceeds the buffered block",
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for PrivateRandomnessStream<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateRandomnessStream")
            .field("domain", &self.domain)
            .field("derivation_context_hash", &self.derivation_context_hash)
            .field("attempt_identifier", &self.attempt_identifier)
            .field("next_counter", &self.next_counter)
            .field(
                "next_unread_bit_offset_in_buffered_block",
                &self.next_unread_bit_offset_in_buffered_block,
            )
            .field("buffered_block", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateRandomCursor {
    pub(super) domain: PrivateRandomnessDomain,
    derivation_context_hash: Hash512,
    pub(super) stream_attempt_identifier: [u8; PRIVATE_RANDOMNESS_ATTEMPT_IDENTIFIER_BYTE_LENGTH],
    next_counter: u64,
    next_unread_bit_offset_in_buffered_block: Option<u16>,
}

impl fmt::Debug for PrivateRandomCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateRandomCursor")
            .field("domain", &self.domain)
            .field("derivation_context_hash", &self.derivation_context_hash)
            .field("stream_attempt_identifier", &"[REDACTED]")
            .field("next_counter", &self.next_counter)
            .field(
                "next_unread_bit_offset_in_buffered_block",
                &self.next_unread_bit_offset_in_buffered_block,
            )
            .finish()
    }
}

impl PrivateRandomCursor {
    pub fn new(
        family: u16,
        purpose: u16,
        derivation_context_hash: Hash512,
        stream_attempt_identifier: [u8; PRIVATE_RANDOMNESS_ATTEMPT_IDENTIFIER_BYTE_LENGTH],
        next_counter: u64,
        next_unread_bit_offset_in_buffered_block: Option<u16>,
    ) -> SchemaResult<Self> {
        let cursor = Self {
            domain: PrivateRandomnessDomain::from_assigned_pair(family, purpose)?,
            derivation_context_hash,
            stream_attempt_identifier,
            next_counter,
            next_unread_bit_offset_in_buffered_block,
        };
        validate_cursor_offset(
            cursor.next_counter,
            cursor.next_unread_bit_offset_in_buffered_block,
        )?;
        Ok(cursor)
    }

    pub const fn family(self) -> u16 {
        self.domain.family
    }

    pub const fn purpose(self) -> u16 {
        self.domain.purpose
    }

    pub const fn derivation_context_hash(self) -> Hash512 {
        self.derivation_context_hash
    }

    pub const fn stream_attempt_identifier(
        self,
    ) -> [u8; PRIVATE_RANDOMNESS_ATTEMPT_IDENTIFIER_BYTE_LENGTH] {
        self.stream_attempt_identifier
    }

    pub const fn next_counter(self) -> u64 {
        self.next_counter
    }

    pub const fn next_unread_bit_offset_in_buffered_block(self) -> Option<u16> {
        self.next_unread_bit_offset_in_buffered_block
    }

    fn canonical_tuple(self) -> SchemaResult<CanonicalTuple> {
        validate_cursor_offset(
            self.next_counter,
            self.next_unread_bit_offset_in_buffered_block,
        )?;
        let offset_item = self
            .next_unread_bit_offset_in_buffered_block
            .map(CanonicalItem::unsigned16);
        Ok(CanonicalTuple::new(
            RANDOM_CURSOR_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.domain.family),
                CanonicalItem::unsigned16(self.domain.purpose),
                CanonicalItem::hash512(self.derivation_context_hash.into_bytes()),
                CanonicalItem::fixed_bytes(self.stream_attempt_identifier)?,
                CanonicalItem::unsigned64(self.next_counter),
                CanonicalItem::optional(CanonicalItemType::Unsigned16, offset_item.as_ref())?,
            ],
        ))
    }

    pub fn encode(self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple()?.encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        require_header(&tuple, RANDOM_CURSOR_SCHEMA_IDENTIFIER, 6)?;
        let family = read_u16(&tuple.items[0])?;
        let purpose = read_u16(&tuple.items[1])?;
        let next_counter = read_u64(&tuple.items[4])?;
        let next_unread_bit_offset_in_buffered_block = read_optional_u16(&tuple.items[5])?;
        validate_cursor_offset(next_counter, next_unread_bit_offset_in_buffered_block)?;
        Self::new(
            family,
            purpose,
            read_hash(&tuple.items[2])?,
            read_fixed_bytes(&tuple.items[3])?,
            next_counter,
            next_unread_bit_offset_in_buffered_block,
        )
    }
}

pub(super) fn require_attempt_class(
    domain: PrivateRandomnessDomain,
    attempt_identifier: PrivateRandomnessAttemptIdentifier,
) -> SchemaResult<()> {
    if domain.attempt_class() != attempt_identifier.attempt_class {
        return Err(schema_error(
            RefusalReason::WrongContext,
            "private-randomness attempt identifier is not valid for the requested domain",
        ));
    }
    Ok(())
}

fn candidate_draw_ceiling_exhausted() -> FoundationSchemaError {
    schema_error(
        RefusalReason::OutsideSupportedProfile,
        "private rejection sampler exhausted its per-output candidate-draw ceiling",
    )
}

pub(super) fn sample_modulo_from_byte_source<FillBytes>(
    modulus: u64,
    maximum_candidate_draws_per_output: u32,
    mut fill_bytes: FillBytes,
) -> SchemaResult<u64>
where
    FillBytes: FnMut(&mut [u8]) -> SchemaResult<()>,
{
    if modulus <= 1 {
        return Err(schema_error(
            RefusalReason::WrongTypeOrLength,
            "private rejection sampling requires a modulus greater than one",
        ));
    }
    if maximum_candidate_draws_per_output == 0 {
        return Err(candidate_draw_ceiling_exhausted());
    }

    let significant_bit_length = u64::BITS - modulus.leading_zeros();
    let sample_byte_length =
        usize::try_from(significant_bit_length.div_ceil(8)).expect("a u64 sample width fits usize");
    let sample_space = 1u128 << (sample_byte_length * 8);
    let modulus_u128 = u128::from(modulus);
    let acceptance_limit = sample_space - (sample_space % modulus_u128);

    for _ in 0..maximum_candidate_draws_per_output {
        let mut candidate_bytes = [0u8; size_of::<u64>()];
        fill_bytes(&mut candidate_bytes[..sample_byte_length])?;
        let candidate = u64::from_le_bytes(candidate_bytes);
        if u128::from(candidate) < acceptance_limit {
            return Ok(candidate % modulus);
        }
    }
    Err(candidate_draw_ceiling_exhausted())
}

pub(super) fn kmac256<const OUTPUT_BYTE_LENGTH: usize>(
    key: &[u8],
    message: &[u8],
    customization: &[u8],
) -> [u8; OUTPUT_BYTE_LENGTH] {
    *kmac256_zeroizing(key, message, customization)
}

pub(super) fn kmac256_zeroizing<const OUTPUT_BYTE_LENGTH: usize>(
    key: &[u8],
    message: &[u8],
    customization: &[u8],
) -> Zeroizing<[u8; OUTPUT_BYTE_LENGTH]> {
    let mut output = Zeroizing::new([0u8; OUTPUT_BYTE_LENGTH]);
    let mut kmac = Kmac::v256(key, customization);
    kmac.update(message);
    kmac.finalize(output.as_mut());
    output
}
