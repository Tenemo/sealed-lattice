//! Fixed-width verifier messages for the compact ring-vector construction.
//!
//! One logical verifier move is one complete uniformly random bit string. The
//! string has a plan-derived fixed width and is decoded in a fixed order into
//! challenge-extension elements, base-field elements, and sorted distinct
//! query sets. Every logical output owns the same bounded candidate budget.
//! Geometry and exact-width XOF decoding are ordinary release code consumed by
//! the compact verifier. The byte decoder remains test-only because verifier
//! messages are derived and are never accepted from proof bytes.

use std::collections::BTreeSet;

use num_bigint::BigUint;
use num_traits::One;

use super::field::{PROOF_BASE_FIELD_MODULUS, PROOF_CHALLENGE_EXTENSION_DEGREE};
use super::field::{ProofBaseFieldElement, ProofChallengeExtensionElement};
use super::profile::PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT;
use crate::foundation::{BoundedFoundationTupleXofReader, CanonicalItem};
#[cfg(test)]
use crate::foundation::{Hash512, StreamingFoundationTupleHash512};

pub(crate) const FIXED_UNIFORM_VERIFIER_MESSAGE_GEOMETRY_VERSION: u16 = 2;
const EXTENSION_CANDIDATE_BYTE_LENGTH: usize = 64;
const BASE_OR_QUERY_CANDIDATE_BYTE_LENGTH: usize = std::mem::size_of::<u64>();
#[cfg(test)]
const TEST_FIXED_UNIFORM_VERIFIER_MESSAGE_DOMAIN: &str =
    "sealed-lattice/test/fixed-uniform-verifier-message/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FixedUniformDistinctQueryGeometry {
    domain_cardinality: u64,
    query_count: u64,
}

impl FixedUniformDistinctQueryGeometry {
    pub(crate) const fn new(domain_cardinality: u64, query_count: u64) -> Self {
        Self {
            domain_cardinality,
            query_count,
        }
    }

    pub(crate) const fn domain_cardinality(self) -> u64 {
        self.domain_cardinality
    }

    pub(crate) const fn query_count(self) -> u64 {
        self.query_count
    }

    fn validate(self) -> Result<(), FixedUniformVerifierMessageError> {
        if self.domain_cardinality == 0
            || !self.domain_cardinality.is_power_of_two()
            || self.query_count == 0
            || self.query_count > self.domain_cardinality
        {
            return Err(FixedUniformVerifierMessageError::InvalidGeometry);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FixedUniformVerifierMessageGeometry {
    extension_output_count: u64,
    excluded_extension_prefix_cardinality: u64,
    base_field_output_count: u64,
    distinct_query_groups: Vec<FixedUniformDistinctQueryGeometry>,
}

impl FixedUniformVerifierMessageGeometry {
    pub(crate) fn new(
        extension_output_count: u64,
        excluded_extension_prefix_cardinality: u64,
        base_field_output_count: u64,
        distinct_query_groups: Vec<FixedUniformDistinctQueryGeometry>,
    ) -> Result<Self, FixedUniformVerifierMessageError> {
        let geometry = Self {
            extension_output_count,
            excluded_extension_prefix_cardinality,
            base_field_output_count,
            distinct_query_groups,
        };
        geometry.validate()?;
        Ok(geometry)
    }

    pub(crate) const fn extension_output_count(&self) -> u64 {
        self.extension_output_count
    }

    pub(crate) const fn excluded_extension_prefix_cardinality(&self) -> u64 {
        self.excluded_extension_prefix_cardinality
    }

    pub(crate) const fn base_field_output_count(&self) -> u64 {
        self.base_field_output_count
    }

    pub(crate) fn distinct_query_groups(&self) -> &[FixedUniformDistinctQueryGeometry] {
        &self.distinct_query_groups
    }

    #[cfg(test)]
    pub(crate) fn fixed_candidate_slot_count(
        &self,
    ) -> Result<u64, FixedUniformVerifierMessageError> {
        self.validate()?;
        let query_output_count =
            self.distinct_query_groups
                .iter()
                .try_fold(0_u64, |count, group| {
                    count
                        .checked_add(group.query_count)
                        .ok_or(FixedUniformVerifierMessageError::LengthOverflow)
                })?;
        self.extension_output_count
            .checked_add(self.base_field_output_count)
            .and_then(|count| count.checked_add(query_output_count))
            .and_then(|count| {
                count.checked_mul(u64::from(
                    PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
                ))
            })
            .ok_or(FixedUniformVerifierMessageError::LengthOverflow)
    }

    pub(crate) fn exact_message_byte_length(
        &self,
    ) -> Result<usize, FixedUniformVerifierMessageError> {
        let byte_length = self.exact_message_byte_length_u64()?;
        usize::try_from(byte_length).map_err(|_| FixedUniformVerifierMessageError::LengthOverflow)
    }

    pub(crate) fn exact_message_byte_length_u64(
        &self,
    ) -> Result<u64, FixedUniformVerifierMessageError> {
        self.validate()?;
        let draw_count = u64::from(PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT);
        let extension_byte_length = self
            .extension_output_count
            .checked_mul(draw_count)
            .and_then(|count| count.checked_mul(EXTENSION_CANDIDATE_BYTE_LENGTH as u64))
            .ok_or(FixedUniformVerifierMessageError::LengthOverflow)?;
        let base_and_query_output_count = self.distinct_query_groups.iter().try_fold(
            self.base_field_output_count,
            |count, group| {
                count
                    .checked_add(group.query_count)
                    .ok_or(FixedUniformVerifierMessageError::LengthOverflow)
            },
        )?;
        let base_and_query_byte_length = base_and_query_output_count
            .checked_mul(draw_count)
            .and_then(|count| count.checked_mul(BASE_OR_QUERY_CANDIDATE_BYTE_LENGTH as u64))
            .ok_or(FixedUniformVerifierMessageError::LengthOverflow)?;
        extension_byte_length
            .checked_add(base_and_query_byte_length)
            .ok_or(FixedUniformVerifierMessageError::LengthOverflow)
    }

    #[cfg(test)]
    pub(crate) fn concrete_xof_call_count(&self) -> Result<u64, FixedUniformVerifierMessageError> {
        self.exact_message_byte_length()?;
        Ok(1)
    }

    fn validate(&self) -> Result<(), FixedUniformVerifierMessageError> {
        if PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT == 0
            || (self.extension_output_count == 0 && self.excluded_extension_prefix_cardinality != 0)
        {
            return Err(FixedUniformVerifierMessageError::InvalidGeometry);
        }
        for group in &self.distinct_query_groups {
            group.validate()?;
        }
        let query_output_count =
            self.distinct_query_groups
                .iter()
                .try_fold(0_u64, |count, group| {
                    count
                        .checked_add(group.query_count)
                        .ok_or(FixedUniformVerifierMessageError::LengthOverflow)
                })?;
        if self
            .extension_output_count
            .checked_add(self.base_field_output_count)
            .and_then(|count| count.checked_add(query_output_count))
            .ok_or(FixedUniformVerifierMessageError::LengthOverflow)?
            == 0
        {
            return Err(FixedUniformVerifierMessageError::InvalidGeometry);
        }

        let extension_cardinality = challenge_extension_cardinality();
        if BigUint::from(self.excluded_extension_prefix_cardinality) + BigUint::one()
            >= extension_cardinality
        {
            return Err(FixedUniformVerifierMessageError::InvalidGeometry);
        }
        Ok(())
    }

    pub(super) fn canonical_geometry_items(
        &self,
    ) -> Result<Vec<CanonicalItem>, FixedUniformVerifierMessageError> {
        self.validate()?;
        let mut items = Vec::new();
        items
            .try_reserve_exact(
                8_usize
                    .checked_add(
                        self.distinct_query_groups
                            .len()
                            .checked_mul(2)
                            .ok_or(FixedUniformVerifierMessageError::LengthOverflow)?,
                    )
                    .ok_or(FixedUniformVerifierMessageError::LengthOverflow)?,
            )
            .map_err(|_| FixedUniformVerifierMessageError::LengthOverflow)?;
        items.push(CanonicalItem::unsigned16(
            FIXED_UNIFORM_VERIFIER_MESSAGE_GEOMETRY_VERSION,
        ));
        items.push(CanonicalItem::unsigned32(
            PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
        ));
        items.push(CanonicalItem::unsigned64(
            EXTENSION_CANDIDATE_BYTE_LENGTH as u64,
        ));
        items.push(CanonicalItem::unsigned64(
            BASE_OR_QUERY_CANDIDATE_BYTE_LENGTH as u64,
        ));
        items.push(CanonicalItem::unsigned64(self.extension_output_count));
        items.push(CanonicalItem::unsigned64(
            self.excluded_extension_prefix_cardinality,
        ));
        items.push(CanonicalItem::unsigned64(self.base_field_output_count));
        items.push(CanonicalItem::unsigned64(
            u64::try_from(self.distinct_query_groups.len())
                .map_err(|_| FixedUniformVerifierMessageError::LengthOverflow)?,
        ));
        for group in &self.distinct_query_groups {
            items.push(CanonicalItem::unsigned64(group.domain_cardinality));
            items.push(CanonicalItem::unsigned64(group.query_count));
        }
        Ok(items)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DecodedFixedUniformVerifierMessage {
    extension_elements: Vec<ProofChallengeExtensionElement>,
    base_field_elements: Vec<ProofBaseFieldElement>,
    distinct_query_groups: Vec<Vec<u64>>,
}

impl DecodedFixedUniformVerifierMessage {
    pub(crate) fn extension_elements(&self) -> &[ProofChallengeExtensionElement] {
        &self.extension_elements
    }

    pub(crate) fn base_field_elements(&self) -> &[ProofBaseFieldElement] {
        &self.base_field_elements
    }

    pub(crate) fn distinct_query_groups(&self) -> &[Vec<u64>] {
        &self.distinct_query_groups
    }

    /// Test-only malicious-verifier boundary. It permits arbitrary field
    /// values while preserving the same typed geometry and query invariants as
    /// the production decoder.
    #[cfg(test)]
    pub(crate) fn from_adversarial_values(
        geometry: &FixedUniformVerifierMessageGeometry,
        extension_elements: Vec<ProofChallengeExtensionElement>,
        base_field_elements: Vec<ProofBaseFieldElement>,
        distinct_query_groups: Vec<Vec<u64>>,
    ) -> Result<Self, FixedUniformVerifierMessageError> {
        geometry.validate()?;
        if u64::try_from(extension_elements.len()).ok() != Some(geometry.extension_output_count)
            || u64::try_from(base_field_elements.len()).ok()
                != Some(geometry.base_field_output_count)
            || distinct_query_groups.len() != geometry.distinct_query_groups.len()
            || extension_elements.iter().any(|element| {
                let coordinates = element.canonical_coordinates();
                coordinates[1..].iter().all(|coordinate| *coordinate == 0)
                    && coordinates[0] < geometry.excluded_extension_prefix_cardinality
            })
            || distinct_query_groups
                .iter()
                .zip(&geometry.distinct_query_groups)
                .any(|(indices, group)| {
                    u64::try_from(indices.len()).ok() != Some(group.query_count)
                        || indices
                            .iter()
                            .any(|index| *index >= group.domain_cardinality)
                        || indices.windows(2).any(|pair| pair[0] >= pair[1])
                })
        {
            return Err(FixedUniformVerifierMessageError::InvalidDecodedMessage);
        }
        Ok(Self {
            extension_elements,
            base_field_elements,
            distinct_query_groups,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FixedUniformVerifierMessageError {
    InvalidGeometry,
    LengthOverflow,
    #[cfg(test)]
    TruncatedMessage,
    #[cfg(test)]
    TrailingMessageBytes,
    FieldSamplingExhausted,
    DistinctQuerySamplingExhausted,
    InvalidFieldElement,
    FoundationHashSchedule,
    #[cfg(test)]
    InvalidDecodedMessage,
}

#[cfg(test)]
pub(crate) fn decode_fixed_uniform_verifier_message(
    geometry: &FixedUniformVerifierMessageGeometry,
    message_bytes: &[u8],
) -> Result<DecodedFixedUniformVerifierMessage, FixedUniformVerifierMessageError> {
    let expected_byte_length = geometry.exact_message_byte_length()?;
    if message_bytes.len() < expected_byte_length {
        return Err(FixedUniformVerifierMessageError::TruncatedMessage);
    }
    if message_bytes.len() > expected_byte_length {
        return Err(FixedUniformVerifierMessageError::TrailingMessageBytes);
    }
    decode_from_reader(geometry, SliceFixedMessageReader::new(message_bytes))
}

pub(crate) fn decode_fixed_uniform_verifier_message_from_xof(
    geometry: &FixedUniformVerifierMessageGeometry,
    reader: BoundedFoundationTupleXofReader,
) -> Result<DecodedFixedUniformVerifierMessage, FixedUniformVerifierMessageError> {
    decode_from_reader(geometry, DerivedFixedMessageReader(reader))
}

trait FixedMessageReader: Sized {
    fn read(&mut self, output: &mut [u8]) -> Result<(), FixedUniformVerifierMessageError>;
    fn discard(&mut self, byte_length: usize) -> Result<(), FixedUniformVerifierMessageError>;
    fn finish(self) -> Result<(), FixedUniformVerifierMessageError>;
}

struct DerivedFixedMessageReader(BoundedFoundationTupleXofReader);

impl FixedMessageReader for DerivedFixedMessageReader {
    fn read(&mut self, output: &mut [u8]) -> Result<(), FixedUniformVerifierMessageError> {
        self.0
            .read(output)
            .map_err(|_| FixedUniformVerifierMessageError::FoundationHashSchedule)
    }

    fn discard(&mut self, byte_length: usize) -> Result<(), FixedUniformVerifierMessageError> {
        self.0
            .discard(byte_length)
            .map_err(|_| FixedUniformVerifierMessageError::FoundationHashSchedule)
    }

    fn finish(self) -> Result<(), FixedUniformVerifierMessageError> {
        self.0
            .finish()
            .map_err(|_| FixedUniformVerifierMessageError::FoundationHashSchedule)
    }
}

#[cfg(test)]
struct SliceFixedMessageReader<'message> {
    message_bytes: &'message [u8],
    offset: usize,
}

#[cfg(test)]
impl<'message> SliceFixedMessageReader<'message> {
    const fn new(message_bytes: &'message [u8]) -> Self {
        Self {
            message_bytes,
            offset: 0,
        }
    }
}

#[cfg(test)]
impl FixedMessageReader for SliceFixedMessageReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> Result<(), FixedUniformVerifierMessageError> {
        let end = self
            .offset
            .checked_add(output.len())
            .ok_or(FixedUniformVerifierMessageError::LengthOverflow)?;
        let source = self
            .message_bytes
            .get(self.offset..end)
            .ok_or(FixedUniformVerifierMessageError::TruncatedMessage)?;
        output.copy_from_slice(source);
        self.offset = end;
        Ok(())
    }

    fn discard(&mut self, byte_length: usize) -> Result<(), FixedUniformVerifierMessageError> {
        let end = self
            .offset
            .checked_add(byte_length)
            .ok_or(FixedUniformVerifierMessageError::LengthOverflow)?;
        if end > self.message_bytes.len() {
            return Err(FixedUniformVerifierMessageError::TruncatedMessage);
        }
        self.offset = end;
        Ok(())
    }

    fn finish(self) -> Result<(), FixedUniformVerifierMessageError> {
        if self.offset == self.message_bytes.len() {
            Ok(())
        } else {
            Err(FixedUniformVerifierMessageError::TrailingMessageBytes)
        }
    }
}

fn decode_from_reader<Reader: FixedMessageReader>(
    geometry: &FixedUniformVerifierMessageGeometry,
    mut reader: Reader,
) -> Result<DecodedFixedUniformVerifierMessage, FixedUniformVerifierMessageError> {
    geometry.validate()?;

    let extension_output_count = usize::try_from(geometry.extension_output_count)
        .map_err(|_| FixedUniformVerifierMessageError::LengthOverflow)?;
    let mut extension_elements = Vec::new();
    extension_elements
        .try_reserve_exact(extension_output_count)
        .map_err(|_| FixedUniformVerifierMessageError::LengthOverflow)?;
    let extension_cardinality = challenge_extension_cardinality();
    let allowed_extension_cardinality =
        &extension_cardinality - BigUint::from(geometry.excluded_extension_prefix_cardinality);
    let extension_candidate_space = BigUint::one() << 512_usize;
    let extension_acceptance_limit = (&extension_candidate_space / &allowed_extension_cardinality)
        * &allowed_extension_cardinality;
    for _ in 0..extension_output_count {
        extension_elements.push(sample_extension_element(
            &mut reader,
            &allowed_extension_cardinality,
            &extension_acceptance_limit,
            geometry.excluded_extension_prefix_cardinality,
        )?);
    }

    let base_field_output_count = usize::try_from(geometry.base_field_output_count)
        .map_err(|_| FixedUniformVerifierMessageError::LengthOverflow)?;
    let mut base_field_elements = Vec::new();
    base_field_elements
        .try_reserve_exact(base_field_output_count)
        .map_err(|_| FixedUniformVerifierMessageError::LengthOverflow)?;
    for _ in 0..base_field_output_count {
        base_field_elements.push(sample_base_field_element(&mut reader)?);
    }

    let mut distinct_query_groups = Vec::new();
    distinct_query_groups
        .try_reserve_exact(geometry.distinct_query_groups.len())
        .map_err(|_| FixedUniformVerifierMessageError::LengthOverflow)?;
    for group in &geometry.distinct_query_groups {
        distinct_query_groups.push(sample_distinct_query_group(&mut reader, *group)?);
    }

    reader.finish()?;
    Ok(DecodedFixedUniformVerifierMessage {
        extension_elements,
        base_field_elements,
        distinct_query_groups,
    })
}

fn sample_extension_element<Reader: FixedMessageReader>(
    reader: &mut Reader,
    allowed_cardinality: &BigUint,
    acceptance_limit: &BigUint,
    excluded_prefix_cardinality: u64,
) -> Result<ProofChallengeExtensionElement, FixedUniformVerifierMessageError> {
    let mut accepted_element = None;
    let mut candidate_bytes = [0_u8; EXTENSION_CANDIDATE_BYTE_LENGTH];
    for _ in 0..PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT {
        if accepted_element.is_some() {
            reader.discard(EXTENSION_CANDIDATE_BYTE_LENGTH)?;
            continue;
        }
        reader.read(&mut candidate_bytes)?;
        let candidate = BigUint::from_bytes_le(&candidate_bytes);
        if &candidate >= acceptance_limit {
            continue;
        }
        let encoded_element =
            candidate % allowed_cardinality + BigUint::from(excluded_prefix_cardinality);
        accepted_element = Some(decode_extension_radix(encoded_element)?);
    }
    accepted_element.ok_or(FixedUniformVerifierMessageError::FieldSamplingExhausted)
}

fn decode_extension_radix(
    mut encoded_element: BigUint,
) -> Result<ProofChallengeExtensionElement, FixedUniformVerifierMessageError> {
    let base_field_modulus = BigUint::from(PROOF_BASE_FIELD_MODULUS);
    let mut coordinates = [0_u64; PROOF_CHALLENGE_EXTENSION_DEGREE];
    for coordinate in &mut coordinates {
        *coordinate = u64::try_from(&encoded_element % &base_field_modulus)
            .map_err(|_| FixedUniformVerifierMessageError::InvalidFieldElement)?;
        encoded_element /= &base_field_modulus;
    }
    if encoded_element != BigUint::default() {
        return Err(FixedUniformVerifierMessageError::InvalidFieldElement);
    }
    ProofChallengeExtensionElement::from_canonical_coordinates(coordinates)
        .map_err(|_| FixedUniformVerifierMessageError::InvalidFieldElement)
}

fn sample_base_field_element<Reader: FixedMessageReader>(
    reader: &mut Reader,
) -> Result<ProofBaseFieldElement, FixedUniformVerifierMessageError> {
    let mut accepted_element = None;
    let mut candidate_bytes = [0_u8; BASE_OR_QUERY_CANDIDATE_BYTE_LENGTH];
    for _ in 0..PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT {
        if accepted_element.is_some() {
            reader.discard(BASE_OR_QUERY_CANDIDATE_BYTE_LENGTH)?;
            continue;
        }
        reader.read(&mut candidate_bytes)?;
        let candidate = u64::from_le_bytes(candidate_bytes);
        if candidate >= PROOF_BASE_FIELD_MODULUS {
            continue;
        }
        accepted_element = Some(
            ProofBaseFieldElement::from_canonical(candidate)
                .map_err(|_| FixedUniformVerifierMessageError::InvalidFieldElement)?,
        );
    }
    accepted_element.ok_or(FixedUniformVerifierMessageError::FieldSamplingExhausted)
}

fn sample_distinct_query_group<Reader: FixedMessageReader>(
    reader: &mut Reader,
    geometry: FixedUniformDistinctQueryGeometry,
) -> Result<Vec<u64>, FixedUniformVerifierMessageError> {
    geometry.validate()?;
    let query_count = usize::try_from(geometry.query_count)
        .map_err(|_| FixedUniformVerifierMessageError::LengthOverflow)?;
    let mut accepted_queries = BTreeSet::new();
    let mut candidate_bytes = [0_u8; BASE_OR_QUERY_CANDIDATE_BYTE_LENGTH];
    for _ in 0..query_count {
        let mut accepted_query = None;
        for _ in 0..PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT {
            if accepted_query.is_some() {
                reader.discard(BASE_OR_QUERY_CANDIDATE_BYTE_LENGTH)?;
                continue;
            }
            reader.read(&mut candidate_bytes)?;
            let candidate = u64::from_le_bytes(candidate_bytes) & (geometry.domain_cardinality - 1);
            if !accepted_queries.contains(&candidate) {
                accepted_query = Some(candidate);
            }
        }
        let accepted_query = accepted_query
            .ok_or(FixedUniformVerifierMessageError::DistinctQuerySamplingExhausted)?;
        accepted_queries.insert(accepted_query);
    }
    Ok(accepted_queries.into_iter().collect())
}

fn challenge_extension_cardinality() -> BigUint {
    BigUint::from(PROOF_BASE_FIELD_MODULUS).pow(PROOF_CHALLENGE_EXTENSION_DEGREE as u32)
}

#[cfg(test)]
fn test_fixed_uniform_verifier_message_reader(
    starting_transcript_state: Hash512,
    logical_verifier_move_ordinal: u32,
    geometry: &FixedUniformVerifierMessageGeometry,
) -> Result<BoundedFoundationTupleXofReader, FixedUniformVerifierMessageError> {
    let output_byte_length = geometry.exact_message_byte_length()?;
    let mut prefix_items = vec![
        CanonicalItem::hash512(starting_transcript_state.into_bytes()),
        CanonicalItem::unsigned32(logical_verifier_move_ordinal),
        CanonicalItem::unsigned64(
            u64::try_from(output_byte_length)
                .map_err(|_| FixedUniformVerifierMessageError::LengthOverflow)?,
        ),
    ];
    prefix_items.extend(geometry.canonical_geometry_items()?);
    StreamingFoundationTupleHash512::new_variable_bytes(
        TEST_FIXED_UNIFORM_VERIFIER_MESSAGE_DOMAIN,
        &prefix_items,
        0,
    )
    .and_then(|hasher| hasher.finalize_bounded_xof(output_byte_length))
    .map_err(|_| FixedUniformVerifierMessageError::FoundationHashSchedule)
}

#[cfg(test)]
pub(crate) fn derive_fixed_uniform_verifier_message(
    starting_transcript_state: Hash512,
    logical_verifier_move_ordinal: u32,
    geometry: &FixedUniformVerifierMessageGeometry,
) -> Result<DecodedFixedUniformVerifierMessage, FixedUniformVerifierMessageError> {
    let reader = test_fixed_uniform_verifier_message_reader(
        starting_transcript_state,
        logical_verifier_move_ordinal,
        geometry,
    )?;
    decode_fixed_uniform_verifier_message_from_xof(geometry, reader)
}

#[cfg(test)]
pub(super) fn materialize_fixed_uniform_verifier_message(
    starting_transcript_state: Hash512,
    logical_verifier_move_ordinal: u32,
    geometry: &FixedUniformVerifierMessageGeometry,
) -> Result<Vec<u8>, FixedUniformVerifierMessageError> {
    let output_byte_length = geometry.exact_message_byte_length()?;
    let mut reader = test_fixed_uniform_verifier_message_reader(
        starting_transcript_state,
        logical_verifier_move_ordinal,
        geometry,
    )?;
    let mut output = vec![0_u8; output_byte_length];
    reader
        .read(&mut output)
        .map_err(|_| FixedUniformVerifierMessageError::FoundationHashSchedule)?;
    reader
        .finish()
        .map_err(|_| FixedUniformVerifierMessageError::FoundationHashSchedule)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one_extension_geometry(
        excluded_prefix_cardinality: u64,
    ) -> FixedUniformVerifierMessageGeometry {
        FixedUniformVerifierMessageGeometry::new(1, excluded_prefix_cardinality, 0, Vec::new())
            .expect("one extension output is valid")
    }

    fn message_with_first_candidate_per_output(
        geometry: &FixedUniformVerifierMessageGeometry,
        extension_candidates: &[[u8; EXTENSION_CANDIDATE_BYTE_LENGTH]],
        base_candidates: &[u64],
        query_candidates: &[Vec<u64>],
    ) -> Vec<u8> {
        let mut bytes = vec![0_u8; geometry.exact_message_byte_length().expect("valid width")];
        let draw_count =
            usize::try_from(PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT).unwrap();
        let mut offset = 0_usize;
        for candidate in extension_candidates {
            bytes[offset..offset + EXTENSION_CANDIDATE_BYTE_LENGTH].copy_from_slice(candidate);
            offset += draw_count * EXTENSION_CANDIDATE_BYTE_LENGTH;
        }
        for candidate in base_candidates {
            bytes[offset..offset + BASE_OR_QUERY_CANDIDATE_BYTE_LENGTH]
                .copy_from_slice(&candidate.to_le_bytes());
            offset += draw_count * BASE_OR_QUERY_CANDIDATE_BYTE_LENGTH;
        }
        for group_candidates in query_candidates {
            for candidate in group_candidates {
                bytes[offset..offset + BASE_OR_QUERY_CANDIDATE_BYTE_LENGTH]
                    .copy_from_slice(&candidate.to_le_bytes());
                offset += draw_count * BASE_OR_QUERY_CANDIDATE_BYTE_LENGTH;
            }
        }
        assert_eq!(offset, bytes.len());
        bytes
    }

    #[test]
    fn decoder_refuses_invalid_geometry_truncation_and_trailing_bytes() {
        assert_eq!(
            FixedUniformVerifierMessageGeometry::new(0, 0, 0, Vec::new()),
            Err(FixedUniformVerifierMessageError::InvalidGeometry)
        );
        assert_eq!(
            FixedUniformVerifierMessageGeometry::new(0, 1, 1, Vec::new()),
            Err(FixedUniformVerifierMessageError::InvalidGeometry)
        );
        assert_eq!(
            FixedUniformVerifierMessageGeometry::new(
                0,
                0,
                0,
                vec![FixedUniformDistinctQueryGeometry::new(12, 3)],
            ),
            Err(FixedUniformVerifierMessageError::InvalidGeometry)
        );
        assert_eq!(
            FixedUniformVerifierMessageGeometry::new(
                0,
                0,
                0,
                vec![FixedUniformDistinctQueryGeometry::new(8, 9)],
            ),
            Err(FixedUniformVerifierMessageError::InvalidGeometry)
        );

        let geometry = FixedUniformVerifierMessageGeometry::new(0, 0, 1, Vec::new())
            .expect("one base output is valid");
        let valid = message_with_first_candidate_per_output(&geometry, &[], &[7], &[]);
        assert_eq!(
            decode_fixed_uniform_verifier_message(&geometry, &valid[..valid.len() - 1]),
            Err(FixedUniformVerifierMessageError::TruncatedMessage)
        );
        let mut trailing = valid;
        trailing.push(0);
        assert_eq!(
            decode_fixed_uniform_verifier_message(&geometry, &trailing),
            Err(FixedUniformVerifierMessageError::TrailingMessageBytes)
        );
    }

    #[test]
    fn extension_decoder_rejects_candidates_then_maps_excluded_prefixes_exactly() {
        let geometry = one_extension_geometry(PROOF_BASE_FIELD_MODULUS);
        let mut bytes = vec![0xff; geometry.exact_message_byte_length().expect("valid width")];
        bytes[EXTENSION_CANDIDATE_BYTE_LENGTH..2 * EXTENSION_CANDIDATE_BYTE_LENGTH].fill(0);
        let decoded = decode_fixed_uniform_verifier_message(&geometry, &bytes)
            .expect("the second candidate is accepted");
        assert_eq!(
            decoded.extension_elements()[0].canonical_coordinates(),
            [0, 1, 0, 0, 0]
        );

        let two_excluded = one_extension_geometry(2);
        let zero_message = vec![0_u8; two_excluded.exact_message_byte_length().unwrap()];
        let decoded = decode_fixed_uniform_verifier_message(&two_excluded, &zero_message)
            .expect("zero maps above the excluded prefix");
        assert_eq!(
            decoded.extension_elements()[0].canonical_coordinates(),
            [2, 0, 0, 0, 0]
        );
    }

    #[test]
    fn field_decoder_refuses_fixed_slot_exhaustion() {
        let extension_geometry = one_extension_geometry(0);
        let rejected_extensions =
            vec![0xff; extension_geometry.exact_message_byte_length().unwrap()];
        assert_eq!(
            decode_fixed_uniform_verifier_message(&extension_geometry, &rejected_extensions),
            Err(FixedUniformVerifierMessageError::FieldSamplingExhausted)
        );

        let base_geometry = FixedUniformVerifierMessageGeometry::new(0, 0, 1, Vec::new()).unwrap();
        let rejected_base = vec![
            0xff;
            base_geometry
                .exact_message_byte_length()
                .expect("valid width")
        ];
        assert_eq!(
            decode_fixed_uniform_verifier_message(&base_geometry, &rejected_base),
            Err(FixedUniformVerifierMessageError::FieldSamplingExhausted)
        );
    }

    #[test]
    fn distinct_query_decoder_rejects_duplicates_and_sorts_the_accepted_set() {
        let geometry = FixedUniformVerifierMessageGeometry::new(
            0,
            0,
            0,
            vec![FixedUniformDistinctQueryGeometry::new(16, 3)],
        )
        .unwrap();
        let mut bytes =
            message_with_first_candidate_per_output(&geometry, &[], &[], &[vec![9, 0, 4]]);
        let output_width = usize::try_from(PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT)
            .unwrap()
            * BASE_OR_QUERY_CANDIDATE_BYTE_LENGTH;
        bytes[output_width..output_width + BASE_OR_QUERY_CANDIDATE_BYTE_LENGTH]
            .copy_from_slice(&9_u64.to_le_bytes());
        bytes[output_width + BASE_OR_QUERY_CANDIDATE_BYTE_LENGTH
            ..output_width + 2 * BASE_OR_QUERY_CANDIDATE_BYTE_LENGTH]
            .copy_from_slice(&2_u64.to_le_bytes());
        let decoded = decode_fixed_uniform_verifier_message(&geometry, &bytes)
            .expect("the duplicate is skipped and the next query is accepted");
        assert_eq!(decoded.distinct_query_groups(), &[vec![2, 4, 9]]);

        let exhausted_geometry = FixedUniformVerifierMessageGeometry::new(
            0,
            0,
            0,
            vec![FixedUniformDistinctQueryGeometry::new(2, 2)],
        )
        .unwrap();
        let exhausted = vec![0_u8; exhausted_geometry.exact_message_byte_length().unwrap()];
        assert_eq!(
            decode_fixed_uniform_verifier_message(&exhausted_geometry, &exhausted),
            Err(FixedUniformVerifierMessageError::DistinctQuerySamplingExhausted)
        );
    }

    #[test]
    fn decoder_preserves_the_complete_component_and_group_order() {
        let geometry = FixedUniformVerifierMessageGeometry::new(
            2,
            0,
            2,
            vec![
                FixedUniformDistinctQueryGeometry::new(8, 2),
                FixedUniformDistinctQueryGeometry::new(32, 3),
            ],
        )
        .unwrap();
        let extension_one = {
            let mut bytes = [0_u8; EXTENSION_CANDIDATE_BYTE_LENGTH];
            bytes[0] = 11;
            bytes
        };
        let extension_two = {
            let mut bytes = [0_u8; EXTENSION_CANDIDATE_BYTE_LENGTH];
            bytes[0] = 29;
            bytes
        };
        let bytes = message_with_first_candidate_per_output(
            &geometry,
            &[extension_one, extension_two],
            &[31, 37],
            &[vec![7, 1], vec![19, 3, 12]],
        );
        let decoded = decode_fixed_uniform_verifier_message(&geometry, &bytes).unwrap();
        assert_eq!(
            decoded
                .extension_elements()
                .iter()
                .map(|element| element.canonical_coordinates()[0])
                .collect::<Vec<_>>(),
            vec![11, 29]
        );
        assert_eq!(
            decoded
                .base_field_elements()
                .iter()
                .map(|element| element.canonical())
                .collect::<Vec<_>>(),
            vec![31, 37]
        );
        assert_eq!(
            decoded.distinct_query_groups(),
            &[vec![1, 7], vec![3, 12, 19]]
        );
    }

    #[test]
    fn direct_xof_test_schedule_is_deterministic_and_binds_every_input() {
        let geometry = FixedUniformVerifierMessageGeometry::new(
            1,
            2,
            1,
            vec![FixedUniformDistinctQueryGeometry::new(16, 2)],
        )
        .unwrap();
        let state = Hash512::from_bytes([0x51; Hash512::BYTE_LENGTH]);
        let message = materialize_fixed_uniform_verifier_message(state, 7, &geometry).unwrap();
        assert_eq!(geometry.concrete_xof_call_count(), Ok(1));
        assert_eq!(
            derive_fixed_uniform_verifier_message(state, 7, &geometry),
            decode_fixed_uniform_verifier_message(&geometry, &message)
        );
        assert_eq!(
            materialize_fixed_uniform_verifier_message(state, 7, &geometry).unwrap(),
            message
        );
        assert_ne!(
            materialize_fixed_uniform_verifier_message(
                Hash512::from_bytes([0x52; Hash512::BYTE_LENGTH]),
                7,
                &geometry,
            )
            .unwrap(),
            message
        );
        assert_ne!(
            materialize_fixed_uniform_verifier_message(state, 8, &geometry).unwrap(),
            message
        );
        let changed_geometry = FixedUniformVerifierMessageGeometry::new(
            1,
            3,
            1,
            vec![FixedUniformDistinctQueryGeometry::new(16, 2)],
        )
        .unwrap();
        assert_ne!(
            materialize_fixed_uniform_verifier_message(state, 7, &changed_geometry).unwrap(),
            message
        );
    }
}
