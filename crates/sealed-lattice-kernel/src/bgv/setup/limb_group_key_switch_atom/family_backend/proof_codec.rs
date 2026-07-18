//! Canonical binary codec for the atom-family FRI proofs.
//!
//! Statement-derived dimensions are not repeated in the proof. The decoder is
//! given the expected FRI, column, query, and lookup-terminal shape and reads
//! exactly that shape. Only genuinely data-dependent collections carry a
//! count. Scalars are fixed-width: field elements are `LIMB_COUNT`
//! little-endian `u64` limbs; digests and salts are byte runs. Decoding rejects
//! truncated or trailing bytes and non-canonical field residues. Trustee
//! evaluation-key transport carries this byte form.

use super::super::proof_field::ProofFieldParameters;
use super::super::wide_unsigned::is_less_than;
use super::column_commitment::{ColumnOpening, ColumnRow};
use super::key_proof::{KeyFriProof, KeyFriProofDecodingShape};
use super::low_degree::{FriLayerOpening, FriProof, FriQueryAnswer};
use super::merkle::{BatchedMerkleOpening, MERKLE_DIGEST_BYTES, MerkleDigest};
use super::private_randomness::PROOF_SALT_BYTE_LENGTH;
use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};

const CODEC_MAGIC: &[u8; 8] = b"SLKSATM3";
const SALT_BYTES: usize = PROOF_SALT_BYTE_LENGTH;

fn invalid_codec(message: &str) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::MalformedLength, message)
}

#[cfg(test)]
pub(super) struct Writer {
    // Exposed to sibling `family_backend` modules so they can reuse this
    // canonical writer and take the finished byte buffer.
    pub(super) bytes: Vec<u8>,
}

#[cfg(test)]
impl Writer {
    pub(super) fn new() -> Self {
        Self {
            bytes: CODEC_MAGIC.to_vec(),
        }
    }

    fn write_u32(&mut self, value: usize) -> CanonicalResult<()> {
        let value = u32::try_from(value).map_err(|_| invalid_codec("length exceeds u32"))?;
        self.bytes.extend_from_slice(&value.to_le_bytes());
        Ok(())
    }

    pub(super) fn write_field<const LIMB_COUNT: usize>(&mut self, element: &[u64; LIMB_COUNT]) {
        for limb in element {
            self.bytes.extend_from_slice(&limb.to_le_bytes());
        }
    }

    fn write_fields<const LIMB_COUNT: usize>(&mut self, elements: &[[u64; LIMB_COUNT]]) {
        for element in elements {
            self.write_field(element);
        }
    }

    pub(super) fn write_digest(&mut self, digest: &MerkleDigest) {
        self.bytes.extend_from_slice(digest);
    }

    fn write_digests(&mut self, digests: &[MerkleDigest]) {
        for digest in digests {
            self.write_digest(digest);
        }
    }

    fn write_digest_vec(&mut self, digests: &[MerkleDigest]) -> CanonicalResult<()> {
        self.write_u32(digests.len())?;
        self.write_digests(digests);
        Ok(())
    }

    fn write_salt(&mut self, salt: &[u8]) -> CanonicalResult<()> {
        if salt.len() != SALT_BYTES {
            return Err(invalid_codec("salt has an unexpected width"));
        }
        self.bytes.extend_from_slice(salt);
        Ok(())
    }
}

pub(super) struct Reader<'a, const LIMB_COUNT: usize> {
    bytes: &'a [u8],
    position: usize,
    parameters: &'a ProofFieldParameters<LIMB_COUNT>,
}

impl<'a, const LIMB_COUNT: usize> Reader<'a, LIMB_COUNT> {
    pub(super) fn new(
        bytes: &'a [u8],
        parameters: &'a ProofFieldParameters<LIMB_COUNT>,
    ) -> CanonicalResult<Self> {
        if bytes.len() < CODEC_MAGIC.len() || &bytes[..CODEC_MAGIC.len()] != CODEC_MAGIC {
            return Err(invalid_codec("proof codec magic mismatch"));
        }
        Ok(Self {
            bytes,
            position: CODEC_MAGIC.len(),
            parameters,
        })
    }

    fn take(&mut self, count: usize) -> CanonicalResult<&'a [u8]> {
        let end = self
            .position
            .checked_add(count)
            .ok_or_else(|| invalid_codec("length overflow"))?;
        if end > self.bytes.len() {
            return Err(invalid_codec("proof stream is truncated"));
        }
        let slice = &self.bytes[self.position..end];
        self.position = end;
        Ok(slice)
    }

    // Upper bound on how many more elements can possibly remain: every element
    // consumes at least one byte, so a count-prefix larger than this is a
    // malformed stream. This caps `Vec::with_capacity` against the byte budget
    // so an attacker-controlled length prefix cannot force a huge speculative
    // allocation before the elements themselves are read.
    fn remaining_element_bound(&self) -> usize {
        self.bytes.len().saturating_sub(self.position)
    }

    fn read_u32(&mut self) -> CanonicalResult<usize> {
        let slice = self.take(4)?;
        Ok(u32::from_le_bytes(slice.try_into().expect("four bytes")) as usize)
    }

    pub(super) fn read_field(&mut self) -> CanonicalResult<[u64; LIMB_COUNT]> {
        let slice = self.take(LIMB_COUNT * 8)?;
        let mut element = [0_u64; LIMB_COUNT];
        for (limb, chunk) in element.iter_mut().zip(slice.chunks_exact(8)) {
            *limb = u64::from_le_bytes(chunk.try_into().expect("eight bytes"));
        }
        // Canonical: the stored Montgomery representative is always below the
        // modulus, so a limb array at or above it is a malformed element.
        if !is_less_than(&element, &self.parameters.modulus) {
            return Err(invalid_codec("field element is not a canonical residue"));
        }
        Ok(element)
    }

    fn read_fields(&mut self, count: usize) -> CanonicalResult<Vec<[u64; LIMB_COUNT]>> {
        (0..count).map(|_| self.read_field()).collect()
    }

    pub(super) fn read_digest(&mut self) -> CanonicalResult<MerkleDigest> {
        let slice = self.take(MERKLE_DIGEST_BYTES)?;
        Ok(slice.try_into().expect("digest width"))
    }

    fn read_digests(&mut self, count: usize) -> CanonicalResult<Vec<MerkleDigest>> {
        (0..count).map(|_| self.read_digest()).collect()
    }

    fn read_digest_vec(&mut self) -> CanonicalResult<Vec<MerkleDigest>> {
        let count = self.read_u32()?;
        if count > self.remaining_element_bound() / MERKLE_DIGEST_BYTES {
            return Err(invalid_codec(
                "digest count exceeds the remaining proof bytes",
            ));
        }
        self.read_digests(count)
    }

    fn read_salt(&mut self) -> CanonicalResult<Vec<u8>> {
        Ok(self.take(SALT_BYTES)?.to_vec())
    }

    pub(super) fn finish(self) -> CanonicalResult<()> {
        if self.position != self.bytes.len() {
            return Err(invalid_codec("proof stream has trailing bytes"));
        }
        Ok(())
    }
}

#[cfg(test)]
pub(super) fn write_fri<const LIMB_COUNT: usize>(
    writer: &mut Writer,
    fri: &FriProof<LIMB_COUNT>,
) -> CanonicalResult<()> {
    writer.write_digests(&fri.layer_roots);
    writer.write_fields(&fri.final_coefficients);
    for answer in &fri.query_answers {
        for layer in &answer.layers {
            writer.write_field(&layer.value);
            writer.write_field(&layer.sibling_value);
            writer.write_salt(&layer.value_salt)?;
            writer.write_salt(&layer.sibling_salt)?;
            writer.write_digest_vec(&layer.opening.authentication_nodes)?;
        }
    }
    Ok(())
}

pub(super) fn read_fri<const LIMB_COUNT: usize>(
    reader: &mut Reader<'_, LIMB_COUNT>,
    shape: &KeyFriProofDecodingShape,
) -> CanonicalResult<FriProof<LIMB_COUNT>> {
    let layer_roots = reader.read_digests(shape.fri_layer_count)?;
    let final_coefficients = reader.read_fields(shape.fri_final_coefficient_count)?;
    let mut query_answers = Vec::with_capacity(shape.query_count);
    for _ in 0..shape.query_count {
        let mut layers = Vec::with_capacity(shape.fri_layer_count);
        for _ in 0..shape.fri_layer_count {
            let value = reader.read_field()?;
            let sibling_value = reader.read_field()?;
            let value_salt = reader.read_salt()?;
            let sibling_salt = reader.read_salt()?;
            let authentication_nodes = reader.read_digest_vec()?;
            layers.push(FriLayerOpening {
                value,
                sibling_value,
                value_salt,
                sibling_salt,
                opening: BatchedMerkleOpening {
                    authentication_nodes,
                },
            });
        }
        query_answers.push(FriQueryAnswer { layers });
    }
    Ok(FriProof {
        layer_roots,
        final_coefficients,
        query_answers,
    })
}

#[cfg(test)]
pub(super) fn write_column_opening<const LIMB_COUNT: usize>(
    writer: &mut Writer,
    opening: &ColumnOpening<LIMB_COUNT>,
) -> CanonicalResult<()> {
    writer.write_u32(opening.rows.len())?;
    for row in &opening.rows {
        writer.write_u32(row.index)?;
        writer.write_fields(&row.values);
        writer.write_salt(&row.salt)?;
    }
    writer.write_digest_vec(&opening.opening.authentication_nodes)?;
    Ok(())
}

pub(super) fn read_column_opening<const LIMB_COUNT: usize>(
    reader: &mut Reader<'_, LIMB_COUNT>,
    expected_column_count: usize,
) -> CanonicalResult<ColumnOpening<LIMB_COUNT>> {
    let row_count = reader.read_u32()?;
    let mut rows = Vec::with_capacity(row_count.min(reader.remaining_element_bound()));
    for _ in 0..row_count {
        let index = reader.read_u32()?;
        let values = reader.read_fields(expected_column_count)?;
        let salt = reader.read_salt()?;
        rows.push(ColumnRow {
            index,
            values,
            salt,
        });
    }
    let authentication_nodes = reader.read_digest_vec()?;
    Ok(ColumnOpening {
        rows,
        opening: BatchedMerkleOpening {
            authentication_nodes,
        },
    })
}

#[cfg(test)]
pub(super) fn encode_key_proof<const LIMB_COUNT: usize>(
    proof: &KeyFriProof<LIMB_COUNT>,
) -> CanonicalResult<Vec<u8>> {
    let mut writer = Writer::new();
    writer.write_digest(&proof.base_root);
    writer.write_digest(&proof.material_root);
    writer.write_digest(&proof.aux_root);
    writer.write_digest(&proof.quotient_root);
    write_fri(&mut writer, &proof.fri)?;
    write_column_opening(&mut writer, &proof.base_opening)?;
    write_column_opening(&mut writer, &proof.material_opening)?;
    write_column_opening(&mut writer, &proof.aux_opening)?;
    write_column_opening(&mut writer, &proof.quotient_opening)?;
    writer.write_field(&proof.lookup_terminal);
    writer.write_fields(&proof.table_terminals);
    Ok(writer.bytes)
}

pub(super) fn decode_key_proof<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    bytes: &[u8],
    shape: &KeyFriProofDecodingShape,
) -> CanonicalResult<KeyFriProof<LIMB_COUNT>> {
    let mut reader = Reader::new(bytes, parameters)?;
    let base_root = reader.read_digest()?;
    let material_root = reader.read_digest()?;
    let aux_root = reader.read_digest()?;
    let quotient_root = reader.read_digest()?;
    let fri = read_fri(&mut reader, shape)?;
    let base_opening = read_column_opening(&mut reader, shape.base_column_count)?;
    let material_opening = read_column_opening(&mut reader, shape.material_column_count)?;
    let aux_opening = read_column_opening(&mut reader, shape.auxiliary_column_count)?;
    let quotient_opening = read_column_opening(&mut reader, shape.quotient_column_count)?;
    let lookup_terminal = reader.read_field()?;
    let table_terminals = reader.read_fields(shape.table_terminal_count)?;
    reader.finish()?;
    Ok(KeyFriProof {
        base_root,
        material_root,
        aux_root,
        quotient_root,
        fri,
        base_opening,
        material_opening,
        aux_opening,
        quotient_opening,
        lookup_terminal,
        table_terminals,
    })
}

#[cfg(test)]
mod tests {
    use super::super::super::proof_field::selected_key_switch_proof_field_parameters;
    use super::super::key_proof::{
        KeyFriProofParameters, KeySource, key_fri_proof_decoding_shape, prove_round_one_key_fri,
        verify_round_one_key_fri,
    };
    use super::super::private_randomness::PrivateProofRandomness;
    use super::super::test_support::build_synthetic_key_fixture;
    use super::*;

    fn sample_proof() -> (
        super::super::key_proof::KeyPublic<13>,
        usize,
        KeyFriProofParameters,
        KeyFriProof<13>,
    ) {
        let parameters = selected_key_switch_proof_field_parameters();
        let ring_degree = 64;
        let digit_count = 3;
        let (secret, digits, public) =
            build_synthetic_key_fixture(ring_degree, digit_count, &KeySource::RoundOne);
        let proof_parameters = KeyFriProofParameters {
            query_count: 40,
            mask_degree: 0,
        };
        let mut private_randomness = PrivateProofRandomness::for_test(0x2024);
        let proof = prove_round_one_key_fri(
            &parameters,
            ring_degree,
            &public,
            &secret,
            &digits,
            &proof_parameters,
            &mut private_randomness,
        )
        .expect("prove");
        (public, ring_degree, proof_parameters, proof)
    }

    #[test]
    fn encode_decode_round_trips_and_the_decoded_proof_verifies() {
        let parameters = selected_key_switch_proof_field_parameters();
        let (public, ring_degree, proof_parameters, proof) = sample_proof();
        let bytes = encode_key_proof(&proof).expect("encode");
        let decoding_shape = key_fri_proof_decoding_shape(
            ring_degree,
            public.digits.len(),
            false,
            proof_parameters.query_count,
        )
        .expect("decoding shape");
        let decoded = decode_key_proof(&parameters, &bytes, &decoding_shape).expect("decode");
        // Re-encoding the decoded proof reproduces the exact bytes (canonical).
        let reencoded = encode_key_proof(&decoded).expect("re-encode");
        assert_eq!(bytes, reencoded, "encoding must be canonical");
        // The decoded proof still verifies.
        assert!(
            verify_round_one_key_fri(
                &parameters,
                ring_degree,
                &public,
                &decoded,
                &proof_parameters
            )
            .expect("verify")
        );
    }

    #[test]
    fn malformed_proof_encodings_are_rejected() {
        let parameters = selected_key_switch_proof_field_parameters();
        let (public, ring_degree, proof_parameters, proof) = sample_proof();
        let bytes = encode_key_proof(&proof).expect("encode");
        let decoding_shape = key_fri_proof_decoding_shape(
            ring_degree,
            public.digits.len(),
            false,
            proof_parameters.query_count,
        )
        .expect("decoding shape");

        let mut trailing = bytes.clone();
        trailing.push(0);
        let truncated = bytes[..bytes.len() - 1].to_vec();
        let truncated_header = bytes[..4].to_vec();
        let mut wrong_magic = bytes.clone();
        wrong_magic[0] ^= 0xff;
        let mut corrupted_length = bytes;
        let offset = CODEC_MAGIC.len()
            + 4 * MERKLE_DIGEST_BYTES
            + decoding_shape.fri_layer_count * MERKLE_DIGEST_BYTES
            + decoding_shape.fri_final_coefficient_count * 13 * 8
            + 2 * 13 * 8
            + 2 * SALT_BYTES;
        corrupted_length[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());

        for (case_name, malformed) in [
            ("trailing bytes", trailing),
            ("truncation", truncated),
            ("truncated header", truncated_header),
            ("wrong magic", wrong_magic),
            ("corrupted length", corrupted_length),
        ] {
            assert!(
                decode_key_proof(&parameters, &malformed, &decoding_shape).is_err(),
                "{case_name} must be rejected"
            );
        }
    }
}
