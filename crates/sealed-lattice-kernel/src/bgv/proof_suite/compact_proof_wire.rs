//! Canonical wire geometry for the compact ring-vector proof slice.
//!
//! All geometry is verifier-owned. The wire carries roots, independent
//! Fiat-Shamir round salts, canonical field values, fresh Merkle leaf salts,
//! and compact frontier dictionaries in the fixed response order; it carries
//! no producer status, assurance, accounting, or section-length claims.
//! Dictionary entries are strictly sorted and unique, every entry is
//! referenced, and every response ordinal is fixed by the checked
//! construction. The encoder, incremental assembler, strict decoder, and
//! public-input codec are ordinary release code consumed by the compact
//! transport verifier.

use std::ops::Range;

use super::COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH;
use super::MAXIMUM_COMMON_PROOF_BYTE_LENGTH;
#[cfg(test)]
use super::compact_proof_contract::CompactPublicKeyProofContract;
#[cfg(test)]
use super::field::PROOF_BASE_FIELD_MODULUS;
use super::field::PROOF_CHALLENGE_EXTENSION_DEGREE;
use super::field::{ProofBaseFieldElement, ProofChallengeExtensionElement};
use super::fixed_uniform_verifier_message::FixedUniformVerifierMessageGeometry;
use crate::foundation::Hash512;

pub(crate) const COMPACT_PROOF_WIRE_MAGIC: [u8; 8] = *b"SLCPRF01";
pub(crate) const COMPACT_PUBLIC_INPUT_WIRE_MAGIC: [u8; 8] = *b"SLCPUB01";
pub(crate) const COMPACT_PACKING_FACTOR: u16 = 1;
const MERKLE_DIGEST_BYTE_LENGTH: usize = Hash512::BYTE_LENGTH;
/// CDHZ exposes the Fiat-Shamir salt size as a construction parameter. The
/// compact construction fixes it to the existing 512-bit transcript width.
/// This public round salt is independent of the 128-byte secret-leaf salt.
pub(crate) const COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH: usize = Hash512::BYTE_LENGTH;
pub(crate) const FRONTIER_DICTIONARY_REFERENCE_BYTE_LENGTH: usize = size_of::<u32>();
pub(crate) const VARIABLE_RESPONSE_COUNT_BYTE_LENGTH: usize = 3 * size_of::<u32>();
pub(crate) const PROOF_FIXED_HEADER_BYTE_LENGTH: usize =
    COMPACT_PROOF_WIRE_MAGIC.len() + size_of::<u16>() + size_of::<u32>();
pub(crate) const PUBLIC_INPUT_BINDING_COUNT: usize = 4;
pub(crate) const PUBLIC_INPUT_FIXED_HEADER_BYTE_LENGTH: usize = COMPACT_PUBLIC_INPUT_WIRE_MAGIC
    .len()
    + size_of::<u16>()
    + PUBLIC_INPUT_BINDING_COUNT * Hash512::BYTE_LENGTH
    + 3 * size_of::<u32>();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum CompactPublicInputBindingRole {
    SuiteIdentifier = 1,
    ApplicationStatementHash = 2,
    ManifestHash = 3,
    RelationPlanHash = 4,
}

pub(crate) const fn compact_public_input_binding_roles()
-> [CompactPublicInputBindingRole; PUBLIC_INPUT_BINDING_COUNT] {
    [
        CompactPublicInputBindingRole::SuiteIdentifier,
        CompactPublicInputBindingRole::ApplicationStatementHash,
        CompactPublicInputBindingRole::ManifestHash,
        CompactPublicInputBindingRole::RelationPlanHash,
    ]
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactProofResponseWireGeometry {
    ordinal: u32,
    minimum_queried_base_field_element_count: u64,
    maximum_queried_base_field_element_count: u64,
    minimum_queried_extension_field_element_count: u64,
    maximum_queried_extension_field_element_count: u64,
    minimum_queried_leaf_count: u64,
    maximum_queried_leaf_count: u64,
    maximum_frontier_node_count: u64,
    verifier_message_geometry: FixedUniformVerifierMessageGeometry,
}

impl CompactProofResponseWireGeometry {
    #[cfg(test)]
    pub(crate) fn new(
        ordinal: u32,
        queried_base_field_element_count: u64,
        queried_extension_field_element_count: u64,
        queried_leaf_count: u64,
        maximum_frontier_node_count: u64,
        verifier_message_geometry: FixedUniformVerifierMessageGeometry,
    ) -> Result<Self, CompactProofWireError> {
        Self::new_with_count_ranges(
            ordinal,
            queried_base_field_element_count,
            queried_base_field_element_count,
            queried_extension_field_element_count,
            queried_extension_field_element_count,
            queried_leaf_count,
            queried_leaf_count,
            maximum_frontier_node_count,
            verifier_message_geometry,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_with_count_ranges(
        ordinal: u32,
        minimum_queried_base_field_element_count: u64,
        maximum_queried_base_field_element_count: u64,
        minimum_queried_extension_field_element_count: u64,
        maximum_queried_extension_field_element_count: u64,
        minimum_queried_leaf_count: u64,
        maximum_queried_leaf_count: u64,
        maximum_frontier_node_count: u64,
        verifier_message_geometry: FixedUniformVerifierMessageGeometry,
    ) -> Result<Self, CompactProofWireError> {
        let geometry = Self {
            ordinal,
            minimum_queried_base_field_element_count,
            maximum_queried_base_field_element_count,
            minimum_queried_extension_field_element_count,
            maximum_queried_extension_field_element_count,
            minimum_queried_leaf_count,
            maximum_queried_leaf_count,
            maximum_frontier_node_count,
            verifier_message_geometry,
        };
        geometry.validate()?;
        Ok(geometry)
    }

    pub(crate) const fn ordinal(&self) -> u32 {
        self.ordinal
    }

    #[cfg(test)]
    pub(crate) const fn queried_base_field_element_count(&self) -> u64 {
        self.maximum_queried_base_field_element_count
    }

    #[cfg(test)]
    pub(crate) const fn queried_extension_field_element_count(&self) -> u64 {
        self.maximum_queried_extension_field_element_count
    }

    #[cfg(test)]
    pub(crate) const fn queried_leaf_count(&self) -> u64 {
        self.maximum_queried_leaf_count
    }

    pub(crate) const fn minimum_queried_base_field_element_count(&self) -> u64 {
        self.minimum_queried_base_field_element_count
    }

    pub(crate) const fn maximum_queried_base_field_element_count(&self) -> u64 {
        self.maximum_queried_base_field_element_count
    }

    pub(crate) const fn minimum_queried_extension_field_element_count(&self) -> u64 {
        self.minimum_queried_extension_field_element_count
    }

    pub(crate) const fn maximum_queried_extension_field_element_count(&self) -> u64 {
        self.maximum_queried_extension_field_element_count
    }

    pub(crate) const fn minimum_queried_leaf_count(&self) -> u64 {
        self.minimum_queried_leaf_count
    }

    pub(crate) const fn maximum_queried_leaf_count(&self) -> u64 {
        self.maximum_queried_leaf_count
    }

    pub(crate) const fn has_variable_counts(&self) -> bool {
        self.minimum_queried_base_field_element_count
            != self.maximum_queried_base_field_element_count
            || self.minimum_queried_extension_field_element_count
                != self.maximum_queried_extension_field_element_count
            || self.minimum_queried_leaf_count != self.maximum_queried_leaf_count
    }

    pub(crate) const fn maximum_frontier_node_count(&self) -> u64 {
        self.maximum_frontier_node_count
    }

    pub(crate) const fn verifier_message_geometry(&self) -> &FixedUniformVerifierMessageGeometry {
        &self.verifier_message_geometry
    }

    fn validate(&self) -> Result<(), CompactProofWireError> {
        if self.minimum_queried_leaf_count == 0
            || self.minimum_queried_leaf_count > self.maximum_queried_leaf_count
            || self.minimum_queried_base_field_element_count
                > self.maximum_queried_base_field_element_count
            || self.minimum_queried_extension_field_element_count
                > self.maximum_queried_extension_field_element_count
            || self
                .maximum_queried_base_field_element_count
                .checked_add(self.maximum_queried_extension_field_element_count)
                .ok_or(CompactProofWireError::LengthOverflow)?
                == 0
            || self
                .verifier_message_geometry()
                .exact_message_byte_length()?
                == 0
        {
            return Err(CompactProofWireError::InvalidGeometry);
        }
        Ok(())
    }

    pub(crate) fn maximum_canonical_byte_length(&self) -> Result<usize, CompactProofWireError> {
        self.validate()?;
        let base_value_byte_length = checked_usize_product(&[
            checked_usize(self.maximum_queried_base_field_element_count)?,
            size_of::<u64>(),
        ])?;
        let extension_value_byte_length = checked_usize_product(&[
            checked_usize(self.maximum_queried_extension_field_element_count)?,
            PROOF_CHALLENGE_EXTENSION_DEGREE,
            size_of::<u64>(),
        ])?;
        let salt_byte_length = checked_usize_product(&[
            checked_usize(self.maximum_queried_leaf_count)?,
            COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH,
        ])?;
        let maximum_frontier_node_count = checked_usize(self.maximum_frontier_node_count())?;
        [
            size_of::<u32>(),
            MERKLE_DIGEST_BYTE_LENGTH,
            COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH,
            if self.has_variable_counts() {
                VARIABLE_RESPONSE_COUNT_BYTE_LENGTH
            } else {
                0
            },
            base_value_byte_length,
            extension_value_byte_length,
            salt_byte_length,
            2 * size_of::<u32>(),
            checked_usize_product(&[maximum_frontier_node_count, MERKLE_DIGEST_BYTE_LENGTH])?,
            checked_usize_product(&[
                maximum_frontier_node_count,
                FRONTIER_DICTIONARY_REFERENCE_BYTE_LENGTH,
            ])?,
        ]
        .into_iter()
        .try_fold(0_usize, checked_usize_add)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactProofWireGeometry {
    responses: Vec<CompactProofResponseWireGeometry>,
    maximum_canonical_byte_length: usize,
}

impl CompactProofWireGeometry {
    pub(crate) fn new(
        responses: Vec<CompactProofResponseWireGeometry>,
    ) -> Result<Self, CompactProofWireError> {
        if responses.is_empty() {
            return Err(CompactProofWireError::InvalidGeometry);
        }
        let maximum_canonical_byte_length = responses.iter().enumerate().try_fold(
            PROOF_FIXED_HEADER_BYTE_LENGTH,
            |byte_length, (ordinal, response)| {
                if usize::try_from(response.ordinal()).ok() != Some(ordinal) {
                    return Err(CompactProofWireError::InvalidGeometry);
                }
                checked_usize_add(byte_length, response.maximum_canonical_byte_length()?)
            },
        )?;
        if maximum_canonical_byte_length > MAXIMUM_COMMON_PROOF_BYTE_LENGTH {
            return Err(CompactProofWireError::ProofByteCeilingExceeded);
        }
        Ok(Self {
            responses,
            maximum_canonical_byte_length,
        })
    }

    pub(crate) fn responses(&self) -> &[CompactProofResponseWireGeometry] {
        &self.responses
    }

    pub(crate) const fn maximum_canonical_byte_length(&self) -> usize {
        self.maximum_canonical_byte_length
    }

    fn total_queried_leaf_count(&self) -> Result<usize, CompactProofWireError> {
        self.responses.iter().try_fold(0_usize, |count, response| {
            checked_usize(response.maximum_queried_leaf_count())
                .and_then(|response_count| checked_usize_add(count, response_count))
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactProofResponseWireInput {
    root: [u8; MERKLE_DIGEST_BYTE_LENGTH],
    fiat_shamir_round_salt: [u8; COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH],
    base_field_values: Vec<ProofBaseFieldElement>,
    extension_field_values: Vec<ProofChallengeExtensionElement>,
    leaf_salts: Vec<[u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]>,
    frontier: Vec<[u8; MERKLE_DIGEST_BYTE_LENGTH]>,
}

impl CompactProofResponseWireInput {
    pub(crate) fn new(
        root: [u8; MERKLE_DIGEST_BYTE_LENGTH],
        fiat_shamir_round_salt: [u8; COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH],
        base_field_values: Vec<ProofBaseFieldElement>,
        extension_field_values: Vec<ProofChallengeExtensionElement>,
        leaf_salts: Vec<[u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]>,
        frontier: Vec<[u8; MERKLE_DIGEST_BYTE_LENGTH]>,
    ) -> Self {
        Self {
            root,
            fiat_shamir_round_salt,
            base_field_values,
            extension_field_values,
            leaf_salts,
            frontier,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg(test)]
pub(crate) struct CompactProofWireInput {
    responses: Vec<CompactProofResponseWireInput>,
}

#[cfg(test)]
impl CompactProofWireInput {
    pub(crate) fn new(responses: Vec<CompactProofResponseWireInput>) -> Self {
        Self { responses }
    }
}

/// Incrementally assembles responses in verifier-owned chronology order.
///
/// This state lets the prover discard each response input after its bytes have
/// been appended. Global leaf-salt uniqueness is checked before any completed
/// proof bytes are returned.
pub(crate) struct CompactProofWireAssembler {
    geometry: CompactProofWireGeometry,
    canonical: Vec<u8>,
    accepted_leaf_salts: Vec<[u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]>,
    next_response_index: usize,
}

impl CompactProofWireAssembler {
    pub(crate) fn new(geometry: &CompactProofWireGeometry) -> Result<Self, CompactProofWireError> {
        let mut canonical = Vec::new();
        canonical
            .try_reserve_exact(geometry.maximum_canonical_byte_length())
            .map_err(|_| CompactProofWireError::LengthOverflow)?;
        canonical.extend_from_slice(&COMPACT_PROOF_WIRE_MAGIC);
        canonical.extend_from_slice(&COMPACT_PACKING_FACTOR.to_le_bytes());
        canonical.extend_from_slice(
            &u32::try_from(geometry.responses.len())
                .map_err(|_| CompactProofWireError::LengthOverflow)?
                .to_le_bytes(),
        );

        let mut accepted_leaf_salts = Vec::new();
        accepted_leaf_salts
            .try_reserve_exact(geometry.total_queried_leaf_count()?)
            .map_err(|_| CompactProofWireError::LengthOverflow)?;
        Ok(Self {
            geometry: geometry.clone(),
            canonical,
            accepted_leaf_salts,
            next_response_index: 0,
        })
    }

    /// Rebuilds the incremental assembler from a canonical prefix ending
    /// exactly after `completed_response_count` complete responses.
    ///
    /// The fixed header continues to declare the verifier-owned total response
    /// count. The prefix decoder therefore accepts neither a shortened header
    /// nor bytes from the next response. It also reconstructs the global leaf-
    /// salt registry so a duplicate introduced after resume is still refused
    /// by [`Self::finish`].
    pub(crate) fn restore_from_canonical_prefix(
        geometry: &CompactProofWireGeometry,
        canonical_prefix_bytes: &[u8],
        completed_response_count: usize,
    ) -> Result<Self, CompactProofWireError> {
        let decoded_prefix = decode_compact_proof_wire_prefix_with_leaf_salts(
            geometry,
            canonical_prefix_bytes,
            completed_response_count,
        )?;
        let mut canonical = Vec::new();
        canonical
            .try_reserve_exact(geometry.maximum_canonical_byte_length())
            .map_err(|_| CompactProofWireError::LengthOverflow)?;
        canonical.extend_from_slice(canonical_prefix_bytes);

        let mut accepted_leaf_salts = decoded_prefix
            .accepted_leaf_salt_offsets
            .into_iter()
            .map(|offset| {
                read_array_at::<COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH>(
                    canonical_prefix_bytes,
                    offset as usize,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        accepted_leaf_salts
            .try_reserve_exact(
                geometry
                    .total_queried_leaf_count()?
                    .checked_sub(accepted_leaf_salts.len())
                    .ok_or(CompactProofWireError::InvalidGeometry)?,
            )
            .map_err(|_| CompactProofWireError::LengthOverflow)?;
        Ok(Self {
            geometry: geometry.clone(),
            canonical,
            accepted_leaf_salts,
            next_response_index: completed_response_count,
        })
    }

    pub(crate) fn canonical_prefix_bytes(&self) -> &[u8] {
        &self.canonical
    }

    pub(crate) const fn completed_response_count(&self) -> usize {
        self.next_response_index
    }

    pub(crate) fn append_response(
        &mut self,
        response: &CompactProofResponseWireInput,
    ) -> Result<(), CompactProofWireError> {
        let response_geometry = self
            .geometry
            .responses
            .get(self.next_response_index)
            .ok_or(CompactProofWireError::WrongResponseCount)?;
        validate_response_input(response_geometry, response)?;

        self.canonical
            .extend_from_slice(&response_geometry.ordinal.to_le_bytes());
        self.canonical.extend_from_slice(&response.root);
        self.canonical
            .extend_from_slice(&response.fiat_shamir_round_salt);
        if response_geometry.has_variable_counts() {
            for count in [
                response.base_field_values.len(),
                response.extension_field_values.len(),
                response.leaf_salts.len(),
            ] {
                self.canonical.extend_from_slice(
                    &u32::try_from(count)
                        .map_err(|_| CompactProofWireError::LengthOverflow)?
                        .to_le_bytes(),
                );
            }
        }
        for value in &response.base_field_values {
            self.canonical
                .extend_from_slice(&value.canonical().to_le_bytes());
        }
        for value in &response.extension_field_values {
            for coordinate in value.canonical_coordinates() {
                self.canonical.extend_from_slice(&coordinate.to_le_bytes());
            }
        }
        for salt in &response.leaf_salts {
            self.accepted_leaf_salts.push(*salt);
            self.canonical.extend_from_slice(salt);
        }

        let mut frontier_dictionary = Vec::new();
        frontier_dictionary
            .try_reserve_exact(response.frontier.len())
            .map_err(|_| CompactProofWireError::LengthOverflow)?;
        frontier_dictionary.extend_from_slice(&response.frontier);
        frontier_dictionary.sort_unstable();
        frontier_dictionary.dedup();
        self.canonical.extend_from_slice(
            &u32::try_from(frontier_dictionary.len())
                .map_err(|_| CompactProofWireError::LengthOverflow)?
                .to_le_bytes(),
        );
        self.canonical.extend_from_slice(
            &u32::try_from(response.frontier.len())
                .map_err(|_| CompactProofWireError::LengthOverflow)?
                .to_le_bytes(),
        );
        for node in &frontier_dictionary {
            self.canonical.extend_from_slice(node);
        }
        for node in &response.frontier {
            let dictionary_ordinal = frontier_dictionary
                .binary_search(node)
                .map_err(|_| CompactProofWireError::InvalidFrontierDictionaryReference)?;
            self.canonical.extend_from_slice(
                &u32::try_from(dictionary_ordinal)
                    .map_err(|_| CompactProofWireError::LengthOverflow)?
                    .to_le_bytes(),
            );
        }
        if self.canonical.len() > self.geometry.maximum_canonical_byte_length {
            return Err(CompactProofWireError::GeometryBoundExceeded);
        }
        self.next_response_index = self
            .next_response_index
            .checked_add(1)
            .ok_or(CompactProofWireError::LengthOverflow)?;
        Ok(())
    }

    pub(crate) fn finish(mut self) -> Result<Vec<u8>, CompactProofWireError> {
        if self.next_response_index != self.geometry.responses.len() {
            return Err(CompactProofWireError::WrongResponseCount);
        }
        self.accepted_leaf_salts.sort_unstable();
        if self
            .accepted_leaf_salts
            .windows(2)
            .any(|pair| pair[0] == pair[1])
        {
            return Err(CompactProofWireError::DuplicateLeafSalt);
        }
        Ok(self.canonical)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DecodedCompactProofResponse {
    canonical_bytes: Range<usize>,
    ordinal: u32,
    root: [u8; MERKLE_DIGEST_BYTE_LENGTH],
    queried_base_field_element_count: usize,
    queried_extension_field_element_count: usize,
    queried_leaf_count: usize,
    fiat_shamir_round_salt_bytes: Range<usize>,
    base_field_value_bytes: Range<usize>,
    extension_field_value_bytes: Range<usize>,
    leaf_salt_bytes: Range<usize>,
    frontier_dictionary_bytes: Range<usize>,
    frontier_reference_bytes: Range<usize>,
    frontier_dictionary_count: usize,
    frontier_node_count: usize,
}

impl DecodedCompactProofResponse {
    pub(crate) const fn ordinal(&self) -> u32 {
        self.ordinal
    }

    pub(crate) const fn root(&self) -> [u8; MERKLE_DIGEST_BYTE_LENGTH] {
        self.root
    }

    pub(crate) const fn queried_base_field_element_count(&self) -> usize {
        self.queried_base_field_element_count
    }

    pub(crate) const fn queried_extension_field_element_count(&self) -> usize {
        self.queried_extension_field_element_count
    }

    pub(crate) const fn queried_leaf_count(&self) -> usize {
        self.queried_leaf_count
    }

    #[cfg(test)]
    pub(crate) fn canonical_byte_length(&self) -> usize {
        self.canonical_bytes.len()
    }

    #[cfg(test)]
    pub(crate) fn answer_byte_length(&self) -> usize {
        self.base_field_value_bytes.len() + self.extension_field_value_bytes.len()
    }

    /// Exact transported Merkle opening length, excluding the opened answer
    /// values. This includes leaf salts, the two frontier counts, the sorted
    /// digest dictionary, and every dictionary reference.
    #[cfg(test)]
    pub(crate) fn merkle_opening_byte_length(&self) -> usize {
        self.leaf_salt_bytes.len()
            + 2 * size_of::<u32>()
            + self.frontier_dictionary_bytes.len()
            + self.frontier_reference_bytes.len()
    }

    #[cfg(test)]
    pub(crate) const fn frontier_dictionary_count(&self) -> usize {
        self.frontier_dictionary_count
    }

    pub(crate) fn fiat_shamir_round_salt(
        &self,
        canonical_proof_bytes: &[u8],
    ) -> Result<[u8; COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH], CompactProofWireError> {
        read_array_at(
            canonical_proof_bytes,
            self.fiat_shamir_round_salt_bytes.start,
        )
    }

    pub(crate) fn base_field_value(
        &self,
        canonical_proof_bytes: &[u8],
        value_ordinal: usize,
    ) -> Result<ProofBaseFieldElement, CompactProofWireError> {
        let offset = indexed_offset(
            &self.base_field_value_bytes,
            value_ordinal,
            size_of::<u64>(),
        )?;
        ProofBaseFieldElement::from_canonical(read_u64_at(canonical_proof_bytes, offset)?)
            .map_err(|_| CompactProofWireError::NonCanonicalBaseFieldElement)
    }

    /// Borrows an already-decoded base-field value range exactly as carried
    /// on the canonical proof wire. The decoder established canonical field
    /// encodings before this response was constructed.
    pub(super) fn canonical_base_field_value_bytes<'proof>(
        &self,
        canonical_proof_bytes: &'proof [u8],
        first_value_ordinal: usize,
        value_count: usize,
    ) -> Result<&'proof [u8], CompactProofWireError> {
        canonical_value_bytes(
            canonical_proof_bytes,
            &self.base_field_value_bytes,
            first_value_ordinal,
            value_count,
            size_of::<u64>(),
        )
    }

    pub(crate) fn extension_field_value(
        &self,
        canonical_proof_bytes: &[u8],
        value_ordinal: usize,
    ) -> Result<ProofChallengeExtensionElement, CompactProofWireError> {
        let extension_byte_length = PROOF_CHALLENGE_EXTENSION_DEGREE
            .checked_mul(size_of::<u64>())
            .ok_or(CompactProofWireError::LengthOverflow)?;
        let offset = indexed_offset(
            &self.extension_field_value_bytes,
            value_ordinal,
            extension_byte_length,
        )?;
        read_extension_at(canonical_proof_bytes, offset)
    }

    /// Borrows an already-decoded extension-field value range exactly as
    /// carried on the canonical proof wire.
    pub(super) fn canonical_extension_field_value_bytes<'proof>(
        &self,
        canonical_proof_bytes: &'proof [u8],
        first_value_ordinal: usize,
        value_count: usize,
    ) -> Result<&'proof [u8], CompactProofWireError> {
        let extension_byte_length = PROOF_CHALLENGE_EXTENSION_DEGREE
            .checked_mul(size_of::<u64>())
            .ok_or(CompactProofWireError::LengthOverflow)?;
        canonical_value_bytes(
            canonical_proof_bytes,
            &self.extension_field_value_bytes,
            first_value_ordinal,
            value_count,
            extension_byte_length,
        )
    }

    pub(crate) fn leaf_salt(
        &self,
        canonical_proof_bytes: &[u8],
        leaf_ordinal: usize,
    ) -> Result<[u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH], CompactProofWireError> {
        let offset = indexed_offset(
            &self.leaf_salt_bytes,
            leaf_ordinal,
            COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH,
        )?;
        read_array_at(canonical_proof_bytes, offset)
    }

    pub(crate) fn frontier_node(
        &self,
        canonical_proof_bytes: &[u8],
        frontier_ordinal: usize,
    ) -> Result<[u8; MERKLE_DIGEST_BYTE_LENGTH], CompactProofWireError> {
        let reference_offset = indexed_offset(
            &self.frontier_reference_bytes,
            frontier_ordinal,
            FRONTIER_DICTIONARY_REFERENCE_BYTE_LENGTH,
        )?;
        let dictionary_ordinal =
            usize::try_from(read_u32_at(canonical_proof_bytes, reference_offset)?)
                .map_err(|_| CompactProofWireError::LengthOverflow)?;
        if dictionary_ordinal >= self.frontier_dictionary_count {
            return Err(CompactProofWireError::InvalidFrontierDictionaryReference);
        }
        let dictionary_offset = indexed_offset(
            &self.frontier_dictionary_bytes,
            dictionary_ordinal,
            MERKLE_DIGEST_BYTE_LENGTH,
        )?;
        read_array_at(canonical_proof_bytes, dictionary_offset)
    }

    pub(crate) const fn frontier_node_count(&self) -> usize {
        self.frontier_node_count
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DecodedCompactProofWire {
    canonical_byte_length: usize,
    responses: Vec<DecodedCompactProofResponse>,
}

impl DecodedCompactProofWire {
    pub(crate) const fn canonical_byte_length(&self) -> usize {
        self.canonical_byte_length
    }

    pub(crate) fn responses(&self) -> &[DecodedCompactProofResponse] {
        &self.responses
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CompactPublicInputBindings {
    suite_identifier: Hash512,
    application_statement_hash: Hash512,
    manifest_hash: Hash512,
    relation_plan_hash: Hash512,
}

impl CompactPublicInputBindings {
    pub(crate) const fn new(
        suite_identifier: Hash512,
        application_statement_hash: Hash512,
        manifest_hash: Hash512,
        relation_plan_hash: Hash512,
    ) -> Self {
        Self {
            suite_identifier,
            application_statement_hash,
            manifest_hash,
            relation_plan_hash,
        }
    }

    pub(crate) const fn ordered_hashes(self) -> [Hash512; PUBLIC_INPUT_BINDING_COUNT] {
        [
            self.suite_identifier,
            self.application_statement_hash,
            self.manifest_hash,
            self.relation_plan_hash,
        ]
    }

    pub(crate) const fn relation_plan_hash(self) -> Hash512 {
        self.relation_plan_hash
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CompactPublicInputWireGeometry {
    ring_vector_count: u32,
    ring_degree: u32,
    field_element_count: u32,
    exact_canonical_byte_length: usize,
}

impl CompactPublicInputWireGeometry {
    pub(crate) fn new(
        ring_vector_count: u64,
        ring_degree: u64,
    ) -> Result<Self, CompactProofWireError> {
        if ring_vector_count == 0 || ring_degree == 0 {
            return Err(CompactProofWireError::InvalidGeometry);
        }
        let ring_vector_count =
            u32::try_from(ring_vector_count).map_err(|_| CompactProofWireError::LengthOverflow)?;
        let ring_degree =
            u32::try_from(ring_degree).map_err(|_| CompactProofWireError::LengthOverflow)?;
        let field_element_count = ring_vector_count
            .checked_mul(ring_degree)
            .ok_or(CompactProofWireError::LengthOverflow)?;
        let exact_canonical_byte_length = checked_usize_add(
            PUBLIC_INPUT_FIXED_HEADER_BYTE_LENGTH,
            checked_usize_product(&[
                usize::try_from(field_element_count)
                    .map_err(|_| CompactProofWireError::LengthOverflow)?,
                size_of::<u64>(),
            ])?,
        )?;
        Ok(Self {
            ring_vector_count,
            ring_degree,
            field_element_count,
            exact_canonical_byte_length,
        })
    }

    #[cfg(test)]
    pub(crate) const fn exact_canonical_byte_length(self) -> usize {
        self.exact_canonical_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn field_element_count(self) -> u32 {
        self.field_element_count
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DecodedCompactPublicInput {
    canonical_byte_length: usize,
    field_value_bytes: Range<usize>,
    field_element_count: usize,
}

impl DecodedCompactPublicInput {
    pub(crate) const fn canonical_byte_length(&self) -> usize {
        self.canonical_byte_length
    }

    pub(crate) fn field_element(
        &self,
        canonical_public_input_bytes: &[u8],
        element_ordinal: usize,
    ) -> Result<ProofBaseFieldElement, CompactProofWireError> {
        let offset = indexed_offset(&self.field_value_bytes, element_ordinal, size_of::<u64>())?;
        ProofBaseFieldElement::from_canonical(read_u64_at(canonical_public_input_bytes, offset)?)
            .map_err(|_| CompactProofWireError::NonCanonicalBaseFieldElement)
    }

    pub(crate) const fn field_element_count(&self) -> usize {
        self.field_element_count
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactProofWireError {
    InvalidGeometry,
    LengthOverflow,
    ProofByteCeilingExceeded,
    GeometryBoundExceeded,
    Truncated,
    TrailingBytes,
    WrongProofMagic,
    WrongPublicInputMagic,
    WrongPackingFactor,
    WrongResponseCount,
    WrongResponseOrdinal,
    WrongPublicInputBinding,
    WrongPublicInputCount,
    NonCanonicalBaseFieldElement,
    NonCanonicalExtensionFieldElement,
    DuplicateLeafSalt,
    OversizedFrontierDictionary,
    DuplicateOrUnsortedFrontierDictionary,
    OversizedFrontier,
    InvalidFrontierDictionaryReference,
    UnusedFrontierDictionaryEntry,
}

impl From<super::fixed_uniform_verifier_message::FixedUniformVerifierMessageError>
    for CompactProofWireError
{
    fn from(
        error: super::fixed_uniform_verifier_message::FixedUniformVerifierMessageError,
    ) -> Self {
        match error {
            super::fixed_uniform_verifier_message::FixedUniformVerifierMessageError::LengthOverflow => {
                Self::LengthOverflow
            }
            _ => Self::InvalidGeometry,
        }
    }
}

#[cfg(test)]
pub(crate) fn encode_compact_proof_wire(
    geometry: &CompactProofWireGeometry,
    input: &CompactProofWireInput,
) -> Result<Vec<u8>, CompactProofWireError> {
    if input.responses.len() != geometry.responses.len() {
        return Err(CompactProofWireError::WrongResponseCount);
    }
    let mut assembler = CompactProofWireAssembler::new(geometry)?;
    for response in &input.responses {
        assembler.append_response(response)?;
    }
    assembler.finish()
}

pub(crate) fn decode_compact_proof_wire(
    geometry: &CompactProofWireGeometry,
    canonical_proof_bytes: &[u8],
) -> Result<DecodedCompactProofWire, CompactProofWireError> {
    enforce_compact_proof_byte_ceiling(canonical_proof_bytes.len())?;
    let decoded = decode_compact_proof_wire_prefix(
        geometry,
        canonical_proof_bytes,
        geometry.responses.len(),
    )?;
    Ok(DecodedCompactProofWire {
        canonical_byte_length: canonical_proof_bytes.len(),
        responses: decoded.responses,
    })
}

fn enforce_compact_proof_byte_ceiling(
    canonical_proof_byte_length: usize,
) -> Result<(), CompactProofWireError> {
    if canonical_proof_byte_length > MAXIMUM_COMMON_PROOF_BYTE_LENGTH {
        return Err(CompactProofWireError::ProofByteCeilingExceeded);
    }
    Ok(())
}

struct DecodedCompactProofWirePrefix {
    responses: Vec<DecodedCompactProofResponse>,
    accepted_leaf_salt_offsets: Vec<u32>,
}

pub(crate) fn decode_compact_proof_wire_prefix(
    geometry: &CompactProofWireGeometry,
    canonical_prefix_bytes: &[u8],
    completed_response_count: usize,
) -> Result<DecodedCompactProofWire, CompactProofWireError> {
    let decoded = decode_compact_proof_wire_prefix_with_leaf_salts(
        geometry,
        canonical_prefix_bytes,
        completed_response_count,
    )?;
    Ok(DecodedCompactProofWire {
        canonical_byte_length: canonical_prefix_bytes.len(),
        responses: decoded.responses,
    })
}

fn decode_compact_proof_wire_prefix_with_leaf_salts(
    geometry: &CompactProofWireGeometry,
    canonical_prefix_bytes: &[u8],
    completed_response_count: usize,
) -> Result<DecodedCompactProofWirePrefix, CompactProofWireError> {
    if canonical_prefix_bytes.len() > geometry.maximum_canonical_byte_length {
        return Err(CompactProofWireError::GeometryBoundExceeded);
    }
    if completed_response_count > geometry.responses.len() {
        return Err(CompactProofWireError::WrongResponseCount);
    }

    let mut reader = CompactWireReader::new(canonical_prefix_bytes);
    if reader.read_array::<8>()? != COMPACT_PROOF_WIRE_MAGIC {
        return Err(CompactProofWireError::WrongProofMagic);
    }
    if reader.read_u16()? != COMPACT_PACKING_FACTOR {
        return Err(CompactProofWireError::WrongPackingFactor);
    }
    if usize::try_from(reader.read_u32()?).ok() != Some(geometry.responses.len()) {
        return Err(CompactProofWireError::WrongResponseCount);
    }

    let mut accepted_leaf_salt_offsets = Vec::new();
    accepted_leaf_salt_offsets
        .try_reserve_exact(geometry.total_queried_leaf_count()?)
        .map_err(|_| CompactProofWireError::LengthOverflow)?;
    let mut decoded_responses = Vec::new();
    decoded_responses
        .try_reserve_exact(geometry.responses.len())
        .map_err(|_| CompactProofWireError::LengthOverflow)?;
    for response_geometry in &geometry.responses[..completed_response_count] {
        let canonical_response_start = reader.offset;
        let ordinal = reader.read_u32()?;
        if ordinal != response_geometry.ordinal {
            return Err(CompactProofWireError::WrongResponseOrdinal);
        }
        let root = reader.read_array()?;
        let fiat_shamir_round_salt_bytes =
            reader.take_range(COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH)?;

        let (
            queried_base_field_element_count,
            queried_extension_field_element_count,
            queried_leaf_count,
        ) = if response_geometry.has_variable_counts() {
            (
                usize::try_from(reader.read_u32()?)
                    .map_err(|_| CompactProofWireError::LengthOverflow)?,
                usize::try_from(reader.read_u32()?)
                    .map_err(|_| CompactProofWireError::LengthOverflow)?,
                usize::try_from(reader.read_u32()?)
                    .map_err(|_| CompactProofWireError::LengthOverflow)?,
            )
        } else {
            (
                checked_usize(response_geometry.maximum_queried_base_field_element_count)?,
                checked_usize(response_geometry.maximum_queried_extension_field_element_count)?,
                checked_usize(response_geometry.maximum_queried_leaf_count)?,
            )
        };
        validate_response_counts(
            response_geometry,
            queried_base_field_element_count,
            queried_extension_field_element_count,
            queried_leaf_count,
        )?;
        let base_field_value_bytes =
            reader.read_canonical_base_field_values(queried_base_field_element_count)?;
        let extension_field_value_bytes =
            reader.read_canonical_extension_field_values(queried_extension_field_element_count)?;
        let leaf_salt_bytes =
            reader.read_leaf_salts(queried_leaf_count, &mut accepted_leaf_salt_offsets)?;

        let frontier_dictionary_count = usize::try_from(reader.read_u32()?)
            .map_err(|_| CompactProofWireError::LengthOverflow)?;
        let frontier_node_count = usize::try_from(reader.read_u32()?)
            .map_err(|_| CompactProofWireError::LengthOverflow)?;
        let maximum_frontier_node_count =
            checked_usize(response_geometry.maximum_frontier_node_count)?;
        if frontier_dictionary_count > frontier_node_count
            || frontier_dictionary_count > maximum_frontier_node_count
        {
            return Err(CompactProofWireError::OversizedFrontierDictionary);
        }
        if frontier_node_count > maximum_frontier_node_count {
            return Err(CompactProofWireError::OversizedFrontier);
        }
        if (frontier_node_count == 0) != (frontier_dictionary_count == 0) {
            return Err(CompactProofWireError::InvalidFrontierDictionaryReference);
        }
        let frontier_dictionary_bytes =
            reader.read_strictly_sorted_dictionary(frontier_dictionary_count)?;
        let (frontier_reference_bytes, used_dictionary_entries) =
            reader.read_frontier_references(frontier_node_count, frontier_dictionary_count)?;
        if used_dictionary_entries.contains(&0) {
            return Err(CompactProofWireError::UnusedFrontierDictionaryEntry);
        }
        decoded_responses.push(DecodedCompactProofResponse {
            canonical_bytes: canonical_response_start..reader.offset,
            ordinal,
            root,
            queried_base_field_element_count,
            queried_extension_field_element_count,
            queried_leaf_count,
            fiat_shamir_round_salt_bytes,
            base_field_value_bytes,
            extension_field_value_bytes,
            leaf_salt_bytes,
            frontier_dictionary_bytes,
            frontier_reference_bytes,
            frontier_dictionary_count,
            frontier_node_count,
        });
    }
    reader.finish()?;
    accepted_leaf_salt_offsets.sort_unstable_by(|left, right| {
        leaf_salt_bytes_at_offset(canonical_prefix_bytes, *left)
            .cmp(leaf_salt_bytes_at_offset(canonical_prefix_bytes, *right))
    });
    if accepted_leaf_salt_offsets.windows(2).any(|pair| {
        leaf_salt_bytes_at_offset(canonical_prefix_bytes, pair[0])
            == leaf_salt_bytes_at_offset(canonical_prefix_bytes, pair[1])
    }) {
        return Err(CompactProofWireError::DuplicateLeafSalt);
    }
    Ok(DecodedCompactProofWirePrefix {
        responses: decoded_responses,
        accepted_leaf_salt_offsets,
    })
}

pub(crate) fn encode_compact_public_input(
    geometry: CompactPublicInputWireGeometry,
    bindings: CompactPublicInputBindings,
    field_elements: &[ProofBaseFieldElement],
) -> Result<Vec<u8>, CompactProofWireError> {
    if field_elements.len()
        != usize::try_from(geometry.field_element_count)
            .map_err(|_| CompactProofWireError::LengthOverflow)?
    {
        return Err(CompactProofWireError::WrongPublicInputCount);
    }
    let mut canonical = Vec::new();
    canonical
        .try_reserve_exact(geometry.exact_canonical_byte_length)
        .map_err(|_| CompactProofWireError::LengthOverflow)?;
    canonical.extend_from_slice(&COMPACT_PUBLIC_INPUT_WIRE_MAGIC);
    canonical.extend_from_slice(&COMPACT_PACKING_FACTOR.to_le_bytes());
    for binding in bindings.ordered_hashes() {
        canonical.extend_from_slice(binding.as_bytes());
    }
    canonical.extend_from_slice(&geometry.ring_vector_count.to_le_bytes());
    canonical.extend_from_slice(&geometry.ring_degree.to_le_bytes());
    canonical.extend_from_slice(&geometry.field_element_count.to_le_bytes());
    for element in field_elements {
        canonical.extend_from_slice(&element.canonical().to_le_bytes());
    }
    if canonical.len() != geometry.exact_canonical_byte_length {
        return Err(CompactProofWireError::LengthOverflow);
    }
    Ok(canonical)
}

pub(crate) fn decode_compact_public_input(
    geometry: CompactPublicInputWireGeometry,
    expected_bindings: CompactPublicInputBindings,
    canonical_public_input_bytes: &[u8],
) -> Result<DecodedCompactPublicInput, CompactProofWireError> {
    if canonical_public_input_bytes.len() < geometry.exact_canonical_byte_length {
        return Err(CompactProofWireError::Truncated);
    }
    if canonical_public_input_bytes.len() > geometry.exact_canonical_byte_length {
        return Err(CompactProofWireError::TrailingBytes);
    }
    let mut reader = CompactWireReader::new(canonical_public_input_bytes);
    if reader.read_array::<8>()? != COMPACT_PUBLIC_INPUT_WIRE_MAGIC {
        return Err(CompactProofWireError::WrongPublicInputMagic);
    }
    if reader.read_u16()? != COMPACT_PACKING_FACTOR {
        return Err(CompactProofWireError::WrongPackingFactor);
    }
    for expected_binding in expected_bindings.ordered_hashes() {
        if reader.read_array::<{ Hash512::BYTE_LENGTH }>()? != expected_binding.into_bytes() {
            return Err(CompactProofWireError::WrongPublicInputBinding);
        }
    }
    if reader.read_u32()? != geometry.ring_vector_count
        || reader.read_u32()? != geometry.ring_degree
        || reader.read_u32()? != geometry.field_element_count
    {
        return Err(CompactProofWireError::WrongPublicInputCount);
    }
    let field_value_bytes = reader.read_canonical_base_field_values(
        usize::try_from(geometry.field_element_count)
            .map_err(|_| CompactProofWireError::LengthOverflow)?,
    )?;
    reader.finish()?;
    Ok(DecodedCompactPublicInput {
        canonical_byte_length: canonical_public_input_bytes.len(),
        field_value_bytes,
        field_element_count: usize::try_from(geometry.field_element_count)
            .map_err(|_| CompactProofWireError::LengthOverflow)?,
    })
}

fn validate_response_input(
    geometry: &CompactProofResponseWireGeometry,
    response: &CompactProofResponseWireInput,
) -> Result<(), CompactProofWireError> {
    validate_response_counts(
        geometry,
        response.base_field_values.len(),
        response.extension_field_values.len(),
        response.leaf_salts.len(),
    )?;
    if response.frontier.len() > checked_usize(geometry.maximum_frontier_node_count)? {
        return Err(CompactProofWireError::InvalidGeometry);
    }
    Ok(())
}

fn validate_response_counts(
    geometry: &CompactProofResponseWireGeometry,
    queried_base_field_element_count: usize,
    queried_extension_field_element_count: usize,
    queried_leaf_count: usize,
) -> Result<(), CompactProofWireError> {
    let queried_base_field_element_count = u64::try_from(queried_base_field_element_count)
        .map_err(|_| CompactProofWireError::LengthOverflow)?;
    let queried_extension_field_element_count =
        u64::try_from(queried_extension_field_element_count)
            .map_err(|_| CompactProofWireError::LengthOverflow)?;
    let queried_leaf_count =
        u64::try_from(queried_leaf_count).map_err(|_| CompactProofWireError::LengthOverflow)?;
    if !(geometry.minimum_queried_base_field_element_count
        ..=geometry.maximum_queried_base_field_element_count)
        .contains(&queried_base_field_element_count)
        || !(geometry.minimum_queried_extension_field_element_count
            ..=geometry.maximum_queried_extension_field_element_count)
            .contains(&queried_extension_field_element_count)
        || !(geometry.minimum_queried_leaf_count..=geometry.maximum_queried_leaf_count)
            .contains(&queried_leaf_count)
    {
        return Err(CompactProofWireError::InvalidGeometry);
    }
    Ok(())
}

struct CompactWireReader<'bytes> {
    bytes: &'bytes [u8],
    offset: usize,
}

impl<'bytes> CompactWireReader<'bytes> {
    const fn new(bytes: &'bytes [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_array<const BYTE_LENGTH: usize>(
        &mut self,
    ) -> Result<[u8; BYTE_LENGTH], CompactProofWireError> {
        let range = self.take_range(BYTE_LENGTH)?;
        self.bytes[range]
            .try_into()
            .map_err(|_| CompactProofWireError::Truncated)
    }

    fn read_u16(&mut self) -> Result<u16, CompactProofWireError> {
        Ok(u16::from_le_bytes(self.read_array()?))
    }

    fn read_u32(&mut self) -> Result<u32, CompactProofWireError> {
        Ok(u32::from_le_bytes(self.read_array()?))
    }

    fn read_u64(&mut self) -> Result<u64, CompactProofWireError> {
        Ok(u64::from_le_bytes(self.read_array()?))
    }

    fn read_canonical_base_field_values(
        &mut self,
        value_count: usize,
    ) -> Result<Range<usize>, CompactProofWireError> {
        let start = self.offset;
        for _ in 0..value_count {
            ProofBaseFieldElement::from_canonical(self.read_u64()?)
                .map_err(|_| CompactProofWireError::NonCanonicalBaseFieldElement)?;
        }
        Ok(start..self.offset)
    }

    fn read_canonical_extension_field_values(
        &mut self,
        value_count: usize,
    ) -> Result<Range<usize>, CompactProofWireError> {
        let start = self.offset;
        for _ in 0..value_count {
            let mut coordinates = [0_u64; PROOF_CHALLENGE_EXTENSION_DEGREE];
            for coordinate in &mut coordinates {
                *coordinate = self.read_u64()?;
            }
            ProofChallengeExtensionElement::from_canonical_coordinates(coordinates)
                .map_err(|_| CompactProofWireError::NonCanonicalExtensionFieldElement)?;
        }
        Ok(start..self.offset)
    }

    fn read_leaf_salts(
        &mut self,
        leaf_count: usize,
        accepted_leaf_salt_offsets: &mut Vec<u32>,
    ) -> Result<Range<usize>, CompactProofWireError> {
        let start = self.offset;
        for _ in 0..leaf_count {
            let salt_offset =
                u32::try_from(self.offset).map_err(|_| CompactProofWireError::LengthOverflow)?;
            self.take_range(COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH)?;
            accepted_leaf_salt_offsets.push(salt_offset);
        }
        Ok(start..self.offset)
    }

    fn read_strictly_sorted_dictionary(
        &mut self,
        entry_count: usize,
    ) -> Result<Range<usize>, CompactProofWireError> {
        let start = self.offset;
        let mut preceding = None;
        for _ in 0..entry_count {
            let entry = self.read_array::<MERKLE_DIGEST_BYTE_LENGTH>()?;
            if preceding.is_some_and(|preceding_entry| preceding_entry >= entry) {
                return Err(CompactProofWireError::DuplicateOrUnsortedFrontierDictionary);
            }
            preceding = Some(entry);
        }
        Ok(start..self.offset)
    }

    fn read_frontier_references(
        &mut self,
        frontier_node_count: usize,
        dictionary_entry_count: usize,
    ) -> Result<(Range<usize>, Vec<u8>), CompactProofWireError> {
        let start = self.offset;
        let mut used_entries = vec![0_u8; dictionary_entry_count];
        for _ in 0..frontier_node_count {
            let dictionary_ordinal = usize::try_from(self.read_u32()?)
                .map_err(|_| CompactProofWireError::LengthOverflow)?;
            let used = used_entries
                .get_mut(dictionary_ordinal)
                .ok_or(CompactProofWireError::InvalidFrontierDictionaryReference)?;
            *used = 1;
        }
        Ok((start..self.offset, used_entries))
    }

    fn take_range(&mut self, byte_length: usize) -> Result<Range<usize>, CompactProofWireError> {
        let end = self
            .offset
            .checked_add(byte_length)
            .ok_or(CompactProofWireError::LengthOverflow)?;
        if end > self.bytes.len() {
            return Err(CompactProofWireError::Truncated);
        }
        let range = self.offset..end;
        self.offset = end;
        Ok(range)
    }

    fn finish(self) -> Result<(), CompactProofWireError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(CompactProofWireError::TrailingBytes)
        }
    }
}

fn leaf_salt_bytes_at_offset(canonical_proof_bytes: &[u8], offset: u32) -> &[u8] {
    // The reader mints an offset only after the complete salt range is in the
    // canonical proof, whose verifier-owned geometry is capped below u32::MAX.
    let start = offset as usize;
    let end = start + COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH;
    &canonical_proof_bytes[start..end]
}

fn checked_usize(value: u64) -> Result<usize, CompactProofWireError> {
    usize::try_from(value).map_err(|_| CompactProofWireError::LengthOverflow)
}

fn checked_usize_add(left: usize, right: usize) -> Result<usize, CompactProofWireError> {
    left.checked_add(right)
        .ok_or(CompactProofWireError::LengthOverflow)
}

fn checked_usize_product(values: &[usize]) -> Result<usize, CompactProofWireError> {
    values.iter().try_fold(1_usize, |product, value| {
        product
            .checked_mul(*value)
            .ok_or(CompactProofWireError::LengthOverflow)
    })
}

fn indexed_offset(
    range: &Range<usize>,
    ordinal: usize,
    item_byte_length: usize,
) -> Result<usize, CompactProofWireError> {
    let offset = ordinal
        .checked_mul(item_byte_length)
        .and_then(|offset| range.start.checked_add(offset))
        .ok_or(CompactProofWireError::LengthOverflow)?;
    let end = offset
        .checked_add(item_byte_length)
        .ok_or(CompactProofWireError::LengthOverflow)?;
    if end > range.end {
        return Err(CompactProofWireError::InvalidGeometry);
    }
    Ok(offset)
}

fn canonical_value_bytes<'proof>(
    canonical_proof_bytes: &'proof [u8],
    response_value_range: &Range<usize>,
    first_value_ordinal: usize,
    value_count: usize,
    value_byte_length: usize,
) -> Result<&'proof [u8], CompactProofWireError> {
    let first_byte_offset = first_value_ordinal
        .checked_mul(value_byte_length)
        .and_then(|offset| response_value_range.start.checked_add(offset))
        .ok_or(CompactProofWireError::LengthOverflow)?;
    let byte_length = value_count
        .checked_mul(value_byte_length)
        .ok_or(CompactProofWireError::LengthOverflow)?;
    let end = first_byte_offset
        .checked_add(byte_length)
        .ok_or(CompactProofWireError::LengthOverflow)?;
    if first_byte_offset < response_value_range.start || end > response_value_range.end {
        return Err(CompactProofWireError::InvalidGeometry);
    }
    canonical_proof_bytes
        .get(first_byte_offset..end)
        .ok_or(CompactProofWireError::Truncated)
}

fn read_array_at<const BYTE_LENGTH: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; BYTE_LENGTH], CompactProofWireError> {
    let end = offset
        .checked_add(BYTE_LENGTH)
        .ok_or(CompactProofWireError::LengthOverflow)?;
    bytes
        .get(offset..end)
        .ok_or(CompactProofWireError::Truncated)?
        .try_into()
        .map_err(|_| CompactProofWireError::Truncated)
}

fn read_u32_at(bytes: &[u8], offset: usize) -> Result<u32, CompactProofWireError> {
    Ok(u32::from_le_bytes(read_array_at(bytes, offset)?))
}

fn read_u64_at(bytes: &[u8], offset: usize) -> Result<u64, CompactProofWireError> {
    Ok(u64::from_le_bytes(read_array_at(bytes, offset)?))
}

fn read_extension_at(
    bytes: &[u8],
    offset: usize,
) -> Result<ProofChallengeExtensionElement, CompactProofWireError> {
    let mut coordinates = [0_u64; PROOF_CHALLENGE_EXTENSION_DEGREE];
    for (coordinate_ordinal, coordinate) in coordinates.iter_mut().enumerate() {
        let coordinate_offset = coordinate_ordinal
            .checked_mul(size_of::<u64>())
            .and_then(|relative| offset.checked_add(relative))
            .ok_or(CompactProofWireError::LengthOverflow)?;
        *coordinate = read_u64_at(bytes, coordinate_offset)?;
    }
    ProofChallengeExtensionElement::from_canonical_coordinates(coordinates)
        .map_err(|_| CompactProofWireError::NonCanonicalExtensionFieldElement)
}

#[cfg(test)]
mod tests {
    use super::super::fixed_uniform_verifier_message::FixedUniformDistinctQueryGeometry;
    use super::*;

    fn verifier_message_geometry() -> FixedUniformVerifierMessageGeometry {
        FixedUniformVerifierMessageGeometry::new(
            1,
            0,
            1,
            vec![FixedUniformDistinctQueryGeometry::new(16, 2)],
        )
        .expect("test verifier-message geometry")
    }

    fn proof_geometry() -> CompactProofWireGeometry {
        CompactProofWireGeometry::new(vec![
            CompactProofResponseWireGeometry::new(0, 3, 0, 2, 4, verifier_message_geometry())
                .unwrap(),
            CompactProofResponseWireGeometry::new(1, 0, 2, 2, 2, verifier_message_geometry())
                .unwrap(),
        ])
        .unwrap()
    }

    fn salt(value: u8) -> [u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH] {
        [value; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]
    }

    fn round_salt(value: u8) -> [u8; COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH] {
        [value; COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH]
    }

    fn extension(value: u64) -> ProofChallengeExtensionElement {
        ProofChallengeExtensionElement::from_canonical_coordinates([value, 2, 3, 5, 7]).unwrap()
    }

    fn proof_input() -> CompactProofWireInput {
        CompactProofWireInput::new(vec![
            CompactProofResponseWireInput::new(
                [0x11; MERKLE_DIGEST_BYTE_LENGTH],
                round_salt(0x51),
                [13, 17, 19]
                    .into_iter()
                    .map(|value| ProofBaseFieldElement::from_canonical(value).unwrap())
                    .collect(),
                Vec::new(),
                vec![salt(0x21), salt(0x22)],
                vec![
                    [0x41; MERKLE_DIGEST_BYTE_LENGTH],
                    [0x31; MERKLE_DIGEST_BYTE_LENGTH],
                    [0x41; MERKLE_DIGEST_BYTE_LENGTH],
                ],
            ),
            CompactProofResponseWireInput::new(
                [0x12; MERKLE_DIGEST_BYTE_LENGTH],
                round_salt(0x52),
                Vec::new(),
                vec![extension(23), extension(29)],
                vec![salt(0x23), salt(0x24)],
                Vec::new(),
            ),
        ])
    }

    #[test]
    fn proof_wire_round_trips_canonical_fields_salts_and_frontier_references() {
        let geometry = proof_geometry();
        let input = proof_input();
        let canonical = encode_compact_proof_wire(&geometry, &input).unwrap();
        let decoded = decode_compact_proof_wire(&geometry, &canonical).unwrap();
        assert_eq!(decoded.canonical_byte_length(), canonical.len());
        assert!(canonical.len() < geometry.maximum_canonical_byte_length());
        assert_eq!(decoded.responses().len(), 2);
        assert_eq!(decoded.responses()[0].ordinal(), 0);
        assert_eq!(
            decoded.responses()[0].root(),
            [0x11; MERKLE_DIGEST_BYTE_LENGTH]
        );
        assert_eq!(
            decoded.responses()[0]
                .fiat_shamir_round_salt(&canonical)
                .unwrap(),
            round_salt(0x51)
        );
        assert_eq!(
            decoded.responses()[0]
                .base_field_value(&canonical, 2)
                .unwrap()
                .canonical(),
            19
        );
        assert_eq!(
            decoded.responses()[1]
                .extension_field_value(&canonical, 1)
                .unwrap()
                .canonical_coordinates(),
            [29, 2, 3, 5, 7]
        );
        assert_eq!(
            decoded.responses()[0]
                .canonical_base_field_value_bytes(&canonical, 0, 3)
                .unwrap(),
            [13_u64, 17, 19]
                .into_iter()
                .flat_map(u64::to_le_bytes)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            decoded.responses()[1]
                .canonical_extension_field_value_bytes(&canonical, 1, 1)
                .unwrap(),
            [29_u64, 2, 3, 5, 7]
                .into_iter()
                .flat_map(u64::to_le_bytes)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            decoded.responses()[0].canonical_base_field_value_bytes(&canonical, 3, 0),
            Ok(&[][..])
        );
        assert_eq!(
            decoded.responses()[0].canonical_base_field_value_bytes(&canonical, 2, 2),
            Err(CompactProofWireError::InvalidGeometry)
        );
        assert_eq!(
            decoded.responses()[1].canonical_extension_field_value_bytes(&canonical, 2, 1),
            Err(CompactProofWireError::InvalidGeometry)
        );
        assert_eq!(
            decoded.responses()[0].canonical_base_field_value_bytes(&canonical[..1], 0, 1),
            Err(CompactProofWireError::Truncated)
        );
        assert_eq!(
            decoded.responses()[0].leaf_salt(&canonical, 1).unwrap(),
            salt(0x22)
        );
        assert_eq!(decoded.responses()[0].frontier_node_count(), 3);
        assert_eq!(
            decoded.responses()[0].frontier_node(&canonical, 0).unwrap(),
            [0x41; MERKLE_DIGEST_BYTE_LENGTH]
        );
        assert_eq!(
            decoded.responses()[0].frontier_node(&canonical, 1).unwrap(),
            [0x31; MERKLE_DIGEST_BYTE_LENGTH]
        );
        assert_eq!(
            encode_compact_proof_wire(&geometry, &input).unwrap(),
            canonical
        );
    }

    #[test]
    fn incremental_proof_assembler_matches_batch_encoding() {
        let geometry = proof_geometry();
        let input = proof_input();
        let expected = encode_compact_proof_wire(&geometry, &input).unwrap();

        let mut assembler = CompactProofWireAssembler::new(&geometry).unwrap();
        drop(geometry);
        assembler.append_response(&input.responses[0]).unwrap();
        assembler.append_response(&input.responses[1]).unwrap();
        assert_eq!(assembler.finish().unwrap(), expected);
    }

    #[test]
    fn canonical_prefix_restore_rebuilds_global_state_and_refuses_nonboundaries() {
        let geometry = proof_geometry();
        let input = proof_input();
        let expected = encode_compact_proof_wire(&geometry, &input).unwrap();

        let mut initial = CompactProofWireAssembler::new(&geometry).unwrap();
        initial.append_response(&input.responses[0]).unwrap();
        assert_eq!(initial.completed_response_count(), 1);
        let canonical_prefix = initial.canonical_prefix_bytes().to_vec();
        let decoded_prefix =
            decode_compact_proof_wire_prefix(&geometry, &canonical_prefix, 1).unwrap();
        assert_eq!(decoded_prefix.responses().len(), 1);
        assert_eq!(decoded_prefix.responses()[0].root(), [0x11; 64]);

        let mut restored = CompactProofWireAssembler::restore_from_canonical_prefix(
            &geometry,
            &canonical_prefix,
            1,
        )
        .unwrap();
        assert_eq!(restored.completed_response_count(), 1);
        assert_eq!(restored.canonical_prefix_bytes(), canonical_prefix);
        restored.append_response(&input.responses[1]).unwrap();
        assert_eq!(restored.finish().unwrap(), expected);

        assert_eq!(
            CompactProofWireAssembler::restore_from_canonical_prefix(
                &geometry,
                &canonical_prefix[..canonical_prefix.len() - 1],
                1,
            )
            .map(|_| ()),
            Err(CompactProofWireError::Truncated)
        );
        assert_eq!(
            CompactProofWireAssembler::restore_from_canonical_prefix(
                &geometry,
                &expected[..canonical_prefix.len() + 1],
                1,
            )
            .map(|_| ()),
            Err(CompactProofWireError::TrailingBytes)
        );
        assert_eq!(
            CompactProofWireAssembler::restore_from_canonical_prefix(
                &geometry,
                &canonical_prefix,
                0,
            )
            .map(|_| ()),
            Err(CompactProofWireError::TrailingBytes)
        );

        let mut reordered = canonical_prefix.clone();
        reordered
            [PROOF_FIXED_HEADER_BYTE_LENGTH..PROOF_FIXED_HEADER_BYTE_LENGTH + size_of::<u32>()]
            .copy_from_slice(&1_u32.to_le_bytes());
        assert_eq!(
            CompactProofWireAssembler::restore_from_canonical_prefix(&geometry, &reordered, 1)
                .map(|_| ()),
            Err(CompactProofWireError::WrongResponseOrdinal)
        );

        let mut duplicate_after_resume = input.responses[1].clone();
        duplicate_after_resume.leaf_salts[0] = input.responses[0].leaf_salts[0];
        let mut restored = CompactProofWireAssembler::restore_from_canonical_prefix(
            &geometry,
            &canonical_prefix,
            1,
        )
        .unwrap();
        restored.append_response(&duplicate_after_resume).unwrap();
        assert_eq!(
            restored.finish(),
            Err(CompactProofWireError::DuplicateLeafSalt)
        );
    }

    #[test]
    fn incremental_proof_assembler_refuses_incomplete_extra_and_duplicate_responses() {
        let geometry = proof_geometry();
        let input = proof_input();

        let mut incomplete = CompactProofWireAssembler::new(&geometry).unwrap();
        incomplete.append_response(&input.responses[0]).unwrap();
        assert_eq!(
            incomplete.finish(),
            Err(CompactProofWireError::WrongResponseCount)
        );

        let mut extra = CompactProofWireAssembler::new(&geometry).unwrap();
        extra.append_response(&input.responses[0]).unwrap();
        extra.append_response(&input.responses[1]).unwrap();
        assert_eq!(
            extra.append_response(&input.responses[1]),
            Err(CompactProofWireError::WrongResponseCount)
        );

        let mut duplicate_input = input.clone();
        duplicate_input.responses[1].leaf_salts[0] = duplicate_input.responses[0].leaf_salts[0];
        let mut duplicate = CompactProofWireAssembler::new(&geometry).unwrap();
        duplicate
            .append_response(&duplicate_input.responses[0])
            .unwrap();
        duplicate
            .append_response(&duplicate_input.responses[1])
            .unwrap();
        assert_eq!(
            duplicate.finish(),
            Err(CompactProofWireError::DuplicateLeafSalt)
        );
    }

    #[test]
    fn proof_decoder_refuses_header_length_and_response_order_mutations() {
        let geometry = proof_geometry();
        let canonical = encode_compact_proof_wire(&geometry, &proof_input()).unwrap();

        let mut wrong_magic = canonical.clone();
        wrong_magic[0] ^= 1;
        assert_eq!(
            decode_compact_proof_wire(&geometry, &wrong_magic),
            Err(CompactProofWireError::WrongProofMagic)
        );
        let mut wrong_factor = canonical.clone();
        wrong_factor[COMPACT_PROOF_WIRE_MAGIC.len()] ^= 1;
        assert_eq!(
            decode_compact_proof_wire(&geometry, &wrong_factor),
            Err(CompactProofWireError::WrongPackingFactor)
        );
        let response_count_offset = COMPACT_PROOF_WIRE_MAGIC.len() + size_of::<u16>();
        let mut wrong_count = canonical.clone();
        wrong_count[response_count_offset..response_count_offset + size_of::<u32>()]
            .copy_from_slice(&3_u32.to_le_bytes());
        assert_eq!(
            decode_compact_proof_wire(&geometry, &wrong_count),
            Err(CompactProofWireError::WrongResponseCount)
        );
        let mut wrong_ordinal = canonical.clone();
        wrong_ordinal
            [PROOF_FIXED_HEADER_BYTE_LENGTH..PROOF_FIXED_HEADER_BYTE_LENGTH + size_of::<u32>()]
            .copy_from_slice(&1_u32.to_le_bytes());
        assert_eq!(
            decode_compact_proof_wire(&geometry, &wrong_ordinal),
            Err(CompactProofWireError::WrongResponseOrdinal)
        );
        assert_eq!(
            decode_compact_proof_wire(&geometry, &canonical[..canonical.len() - 1]),
            Err(CompactProofWireError::Truncated)
        );
        assert_eq!(
            enforce_compact_proof_byte_ceiling(MAXIMUM_COMMON_PROOF_BYTE_LENGTH + 1),
            Err(CompactProofWireError::ProofByteCeilingExceeded)
        );
        let mut trailing = canonical;
        trailing.push(0);
        assert_eq!(
            decode_compact_proof_wire(&geometry, &trailing),
            Err(CompactProofWireError::TrailingBytes)
        );
    }

    #[test]
    fn proof_decoder_refuses_noncanonical_fields_and_duplicate_salts() {
        let geometry = proof_geometry();
        let canonical = encode_compact_proof_wire(&geometry, &proof_input()).unwrap();
        let decoded = decode_compact_proof_wire(&geometry, &canonical).unwrap();

        let mut noncanonical_base = canonical.clone();
        let base_offset = decoded.responses[0].base_field_value_bytes.start;
        noncanonical_base[base_offset..base_offset + size_of::<u64>()]
            .copy_from_slice(&PROOF_BASE_FIELD_MODULUS.to_le_bytes());
        assert_eq!(
            decode_compact_proof_wire(&geometry, &noncanonical_base),
            Err(CompactProofWireError::NonCanonicalBaseFieldElement)
        );

        let mut noncanonical_extension = canonical.clone();
        let extension_offset = decoded.responses[1].extension_field_value_bytes.start;
        noncanonical_extension[extension_offset..extension_offset + size_of::<u64>()]
            .copy_from_slice(&PROOF_BASE_FIELD_MODULUS.to_le_bytes());
        assert_eq!(
            decode_compact_proof_wire(&geometry, &noncanonical_extension),
            Err(CompactProofWireError::NonCanonicalExtensionFieldElement)
        );

        let mut duplicate_salt = canonical.clone();
        let first_salt = decoded.responses[0].leaf_salt_bytes.start;
        let second_salt = first_salt + COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH;
        let copied =
            read_array_at::<COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH>(&duplicate_salt, first_salt)
                .unwrap();
        duplicate_salt[second_salt..second_salt + COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]
            .copy_from_slice(&copied);
        assert_eq!(
            decode_compact_proof_wire(&geometry, &duplicate_salt),
            Err(CompactProofWireError::DuplicateLeafSalt)
        );

        let mut duplicate_across_responses = canonical;
        let second_response_salt = decoded.responses[1].leaf_salt_bytes.start;
        duplicate_across_responses[second_response_salt
            ..second_response_salt + COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]
            .copy_from_slice(&copied);
        assert_eq!(
            decode_compact_proof_wire(&geometry, &duplicate_across_responses),
            Err(CompactProofWireError::DuplicateLeafSalt)
        );
    }

    #[test]
    fn proof_decoder_refuses_hostile_frontier_dictionaries_and_references() {
        let geometry = proof_geometry();
        let canonical = encode_compact_proof_wire(&geometry, &proof_input()).unwrap();
        let decoded = decode_compact_proof_wire(&geometry, &canonical).unwrap();
        let response = &decoded.responses[0];

        let mut reordered_dictionary = canonical.clone();
        let dictionary_start = response.frontier_dictionary_bytes.start;
        let first = reordered_dictionary
            [dictionary_start..dictionary_start + MERKLE_DIGEST_BYTE_LENGTH]
            .to_vec();
        let second = reordered_dictionary[dictionary_start + MERKLE_DIGEST_BYTE_LENGTH
            ..dictionary_start + 2 * MERKLE_DIGEST_BYTE_LENGTH]
            .to_vec();
        reordered_dictionary[dictionary_start..dictionary_start + MERKLE_DIGEST_BYTE_LENGTH]
            .copy_from_slice(&second);
        reordered_dictionary[dictionary_start + MERKLE_DIGEST_BYTE_LENGTH
            ..dictionary_start + 2 * MERKLE_DIGEST_BYTE_LENGTH]
            .copy_from_slice(&first);
        assert_eq!(
            decode_compact_proof_wire(&geometry, &reordered_dictionary),
            Err(CompactProofWireError::DuplicateOrUnsortedFrontierDictionary)
        );

        let mut invalid_reference = canonical.clone();
        let reference_start = response.frontier_reference_bytes.start;
        invalid_reference[reference_start..reference_start + size_of::<u32>()]
            .copy_from_slice(&2_u32.to_le_bytes());
        assert_eq!(
            decode_compact_proof_wire(&geometry, &invalid_reference),
            Err(CompactProofWireError::InvalidFrontierDictionaryReference)
        );

        let mut unused_dictionary_entry = canonical;
        for reference in unused_dictionary_entry[response.frontier_reference_bytes.clone()]
            .chunks_exact_mut(size_of::<u32>())
        {
            reference.copy_from_slice(&0_u32.to_le_bytes());
        }
        assert_eq!(
            decode_compact_proof_wire(&geometry, &unused_dictionary_entry),
            Err(CompactProofWireError::UnusedFrontierDictionaryEntry)
        );
    }

    #[test]
    fn public_input_wire_binds_every_context_and_refuses_noncanonical_values() {
        let geometry = CompactPublicInputWireGeometry::new(2, 3).unwrap();
        let bindings = CompactPublicInputBindings::new(
            Hash512::from_bytes([0x11; 64]),
            Hash512::from_bytes([0x22; 64]),
            Hash512::from_bytes([0x33; 64]),
            Hash512::from_bytes([0x44; 64]),
        );
        let values = [1, 2, 3, 5, 8, 13]
            .into_iter()
            .map(|value| ProofBaseFieldElement::from_canonical(value).unwrap())
            .collect::<Vec<_>>();
        let canonical = encode_compact_public_input(geometry, bindings, &values).unwrap();
        let decoded = decode_compact_public_input(geometry, bindings, &canonical).unwrap();
        assert_eq!(decoded.canonical_byte_length(), canonical.len());
        assert_eq!(decoded.field_element_count(), 6);
        assert_eq!(decoded.field_element(&canonical, 4).unwrap().canonical(), 8);

        let mut wrong_factor = canonical.clone();
        wrong_factor[COMPACT_PUBLIC_INPUT_WIRE_MAGIC.len()] ^= 1;
        assert_eq!(
            decode_compact_public_input(geometry, bindings, &wrong_factor),
            Err(CompactProofWireError::WrongPackingFactor)
        );
        let binding_start = COMPACT_PUBLIC_INPUT_WIRE_MAGIC.len() + size_of::<u16>();
        for binding_ordinal in 0..PUBLIC_INPUT_BINDING_COUNT {
            let mut wrong_binding = canonical.clone();
            wrong_binding[binding_start + binding_ordinal * Hash512::BYTE_LENGTH] ^= 1;
            assert_eq!(
                decode_compact_public_input(geometry, bindings, &wrong_binding),
                Err(CompactProofWireError::WrongPublicInputBinding)
            );
        }
        let mut wrong_count = canonical.clone();
        let count_offset = COMPACT_PUBLIC_INPUT_WIRE_MAGIC.len()
            + size_of::<u16>()
            + PUBLIC_INPUT_BINDING_COUNT * Hash512::BYTE_LENGTH;
        wrong_count[count_offset..count_offset + size_of::<u32>()]
            .copy_from_slice(&3_u32.to_le_bytes());
        assert_eq!(
            decode_compact_public_input(geometry, bindings, &wrong_count),
            Err(CompactProofWireError::WrongPublicInputCount)
        );
        let mut noncanonical = canonical.clone();
        let field_offset = PUBLIC_INPUT_FIXED_HEADER_BYTE_LENGTH;
        noncanonical[field_offset..field_offset + size_of::<u64>()]
            .copy_from_slice(&PROOF_BASE_FIELD_MODULUS.to_le_bytes());
        assert_eq!(
            decode_compact_public_input(geometry, bindings, &noncanonical),
            Err(CompactProofWireError::NonCanonicalBaseFieldElement)
        );
        assert_eq!(
            decode_compact_public_input(geometry, bindings, &canonical[..canonical.len() - 1]),
            Err(CompactProofWireError::Truncated)
        );
        let mut trailing = canonical;
        trailing.push(0);
        assert_eq!(
            decode_compact_public_input(geometry, bindings, &trailing),
            Err(CompactProofWireError::TrailingBytes)
        );
    }

    #[test]
    fn wire_geometry_rejects_invalid_order_counts_and_absolute_overflow() {
        assert_eq!(
            CompactProofWireGeometry::new(Vec::new()),
            Err(CompactProofWireError::InvalidGeometry)
        );
        assert_eq!(
            CompactProofResponseWireGeometry::new(0, 0, 0, 1, 0, verifier_message_geometry(),),
            Err(CompactProofWireError::InvalidGeometry)
        );
        let reordered = vec![
            CompactProofResponseWireGeometry::new(1, 1, 0, 1, 0, verifier_message_geometry())
                .unwrap(),
        ];
        assert_eq!(
            CompactProofWireGeometry::new(reordered),
            Err(CompactProofWireError::InvalidGeometry)
        );
        assert_eq!(
            CompactPublicInputWireGeometry::new(u64::from(u32::MAX), 2),
            Err(CompactProofWireError::LengthOverflow)
        );
    }

    #[test]
    fn selected_geometry_bounds_leaf_salt_registry_to_four_byte_offsets() {
        let contract = CompactPublicKeyProofContract::decode_selected().unwrap();
        let verifier_inputs = contract.verifier_inputs();
        let geometry = verifier_inputs.proof_wire_geometry;
        let leaf_salt_count = geometry.total_queried_leaf_count().unwrap();
        let offset_storage_byte_length =
            checked_usize_product(&[leaf_salt_count, size_of::<u32>()]).unwrap();
        let copied_salt_storage_byte_length =
            checked_usize_product(&[leaf_salt_count, COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH])
                .unwrap();

        assert_eq!(leaf_salt_count, 79_310);
        assert!(u32::try_from(geometry.maximum_canonical_byte_length()).is_ok());
        assert_eq!(offset_storage_byte_length, 317_240);
        assert_eq!(copied_salt_storage_byte_length, 10_151_680);
        assert_eq!(
            copied_salt_storage_byte_length / offset_storage_byte_length,
            32
        );
    }
}
