//! Canonical length-framed binary codec for the atom-family FRI proofs.
//!
//! The encoding is self-describing (every variable-length vector carries a
//! `u32` count) and fixed-width for scalars (field elements are `LIMB_COUNT`
//! little-endian `u64` limbs; digests and salts are byte runs). Decoding is
//! strict: it bounds-checks every read, rejects a truncated or trailing-byte
//! stream, rejects field limbs that are not a reduced residue below the
//! modulus, and rejects salts or digests of the wrong width. Trustee
//! evaluation-key transport carries this byte form.

use super::super::proof_field::ProofFieldParameters;
use super::super::wide_unsigned::is_less_than;
use super::column_commitment::{ColumnOpening, ColumnRow};
use super::key_proof::KeyFriProof;
use super::low_degree::{FriLayerOpening, FriProof, FriQueryAnswer};
use super::merkle::{BatchedMerkleOpening, MERKLE_DIGEST_BYTES, MerkleDigest};
use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};

const CODEC_MAGIC: &[u8; 8] = b"SLKSATM1";
const SALT_BYTES: usize = 8;

fn invalid_codec(message: &str) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::MalformedLength, message)
}

pub(super) struct Writer {
    // Exposed to sibling `family_backend` modules so they can reuse this
    // canonical writer and take the finished byte buffer.
    pub(super) bytes: Vec<u8>,
}

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

    fn write_field_vec<const LIMB_COUNT: usize>(
        &mut self,
        elements: &[[u64; LIMB_COUNT]],
    ) -> CanonicalResult<()> {
        self.write_u32(elements.len())?;
        for element in elements {
            self.write_field(element);
        }
        Ok(())
    }

    pub(super) fn write_digest(&mut self, digest: &MerkleDigest) {
        self.bytes.extend_from_slice(digest);
    }

    fn write_digest_vec(&mut self, digests: &[MerkleDigest]) -> CanonicalResult<()> {
        self.write_u32(digests.len())?;
        for digest in digests {
            self.write_digest(digest);
        }
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

    fn read_field_vec(&mut self) -> CanonicalResult<Vec<[u64; LIMB_COUNT]>> {
        let count = self.read_u32()?;
        (0..count).map(|_| self.read_field()).collect()
    }

    pub(super) fn read_digest(&mut self) -> CanonicalResult<MerkleDigest> {
        let slice = self.take(MERKLE_DIGEST_BYTES)?;
        Ok(slice.try_into().expect("digest width"))
    }

    fn read_digest_vec(&mut self) -> CanonicalResult<Vec<MerkleDigest>> {
        let count = self.read_u32()?;
        (0..count).map(|_| self.read_digest()).collect()
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

pub(super) fn write_fri<const LIMB_COUNT: usize>(
    writer: &mut Writer,
    fri: &FriProof<LIMB_COUNT>,
) -> CanonicalResult<()> {
    writer.write_digest_vec(&fri.layer_roots)?;
    writer.write_field_vec(&fri.final_coefficients)?;
    writer.write_u32(fri.query_answers.len())?;
    for answer in &fri.query_answers {
        writer.write_u32(answer.layers.len())?;
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
) -> CanonicalResult<FriProof<LIMB_COUNT>> {
    let layer_roots = reader.read_digest_vec()?;
    let final_coefficients = reader.read_field_vec()?;
    let answer_count = reader.read_u32()?;
    let mut query_answers = Vec::with_capacity(answer_count.min(reader.remaining_element_bound()));
    for _ in 0..answer_count {
        let layer_count = reader.read_u32()?;
        let mut layers = Vec::with_capacity(layer_count.min(reader.remaining_element_bound()));
        for _ in 0..layer_count {
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

pub(super) fn write_column_opening<const LIMB_COUNT: usize>(
    writer: &mut Writer,
    opening: &ColumnOpening<LIMB_COUNT>,
) -> CanonicalResult<()> {
    writer.write_u32(opening.rows.len())?;
    for row in &opening.rows {
        writer.write_u32(row.index)?;
        writer.write_field_vec(&row.values)?;
        writer.write_salt(&row.salt)?;
    }
    writer.write_digest_vec(&opening.opening.authentication_nodes)?;
    Ok(())
}

pub(super) fn read_column_opening<const LIMB_COUNT: usize>(
    reader: &mut Reader<'_, LIMB_COUNT>,
) -> CanonicalResult<ColumnOpening<LIMB_COUNT>> {
    let row_count = reader.read_u32()?;
    let mut rows = Vec::with_capacity(row_count.min(reader.remaining_element_bound()));
    for _ in 0..row_count {
        let index = reader.read_u32()?;
        let values = reader.read_field_vec()?;
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
    writer.write_field_vec(&proof.table_terminals)?;
    Ok(writer.bytes)
}

pub(super) fn decode_key_proof<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    bytes: &[u8],
) -> CanonicalResult<KeyFriProof<LIMB_COUNT>> {
    let mut reader = Reader::new(bytes, parameters)?;
    let base_root = reader.read_digest()?;
    let material_root = reader.read_digest()?;
    let aux_root = reader.read_digest()?;
    let quotient_root = reader.read_digest()?;
    let fri = read_fri(&mut reader)?;
    let base_opening = read_column_opening(&mut reader)?;
    let material_opening = read_column_opening(&mut reader)?;
    let aux_opening = read_column_opening(&mut reader)?;
    let quotient_opening = read_column_opening(&mut reader)?;
    let lookup_terminal = reader.read_field()?;
    let table_terminals = reader.read_field_vec()?;
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
    use super::super::super::proof_field::sixteen_limb_group_field_parameters;
    use super::super::key_proof::{
        KeyFriProofParameters, prove_round_one_key_fri, verify_round_one_key_fri,
    };
    use super::*;

    fn sample_proof() -> (
        super::super::key_proof::KeyPublic<13>,
        usize,
        KeyFriProofParameters,
        KeyFriProof<13>,
    ) {
        use super::super::super::negacyclic_transform::NegacyclicDomain;
        use super::super::key_proof::{DigitPublic, DigitWitness, KeyPublic};
        let parameters = sixteen_limb_group_field_parameters();
        let ring_degree = 64;
        let digit_count = 3;
        let domain = NegacyclicDomain::new(&parameters, ring_degree).expect("domain");
        let secret: Vec<i64> = (0..ring_degree).map(|i| ((i * 7) % 3) as i64 - 1).collect();
        let secret_field: Vec<[u64; 13]> = secret
            .iter()
            .map(|v| parameters.signed_word_to_element(*v))
            .collect();
        let group_modulus = parameters.unsigned_word_to_element(1_000_003);
        let plaintext_modulus = parameters.unsigned_word_to_element(65_537);
        let mut digits = Vec::new();
        let mut public_digits = Vec::new();
        for digit_index in 0..digit_count {
            let error: Vec<i64> = (0..ring_degree)
                .map(|i| (((i + digit_index) * 5) % 5) as i64 - 2)
                .collect();
            let carry: Vec<i64> = (0..ring_degree)
                .map(|i| ((i + digit_index) % 3) as i64 - 1)
                .collect();
            let error_field: Vec<[u64; 13]> = error
                .iter()
                .map(|v| parameters.signed_word_to_element(*v))
                .collect();
            let carry_field: Vec<[u64; 13]> = carry
                .iter()
                .map(|v| parameters.signed_word_to_element(*v))
                .collect();
            let mut sample = Vec::with_capacity(ring_degree);
            let mut state = 0xa5_u64.wrapping_add(digit_index as u64 * 0x1000);
            for _ in 0..ring_degree {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                sample.push(parameters.unsigned_word_to_element(state));
            }
            let gadget_idempotent =
                parameters.unsigned_word_to_element(0x9e37 + digit_index as u64);
            let a_times_s = domain.negacyclic_product(&sample, &secret_field);
            let mut component_b = vec![parameters.zero(); ring_degree];
            for index in 0..ring_degree {
                let t_e = parameters.multiply(&plaintext_modulus, &error_field[index]);
                let g_s = parameters.multiply(&gadget_idempotent, &secret_field[index]);
                let q_c = parameters.multiply(&group_modulus, &carry_field[index]);
                let mut value = parameters.add(&t_e, &g_s);
                value = parameters.add(&value, &q_c);
                value = parameters.subtract(&value, &a_times_s[index]);
                component_b[index] = value;
            }
            digits.push(DigitWitness { error, carry });
            public_digits.push(DigitPublic {
                recombined_sample: sample,
                recombined_component_b: component_b,
                gadget_idempotent,
            });
        }
        let public = KeyPublic {
            digits: public_digits,
            group_modulus,
            plaintext_modulus,
        };
        let proof_parameters = KeyFriProofParameters {
            query_count: 40,
            mask_degree: 0,
        };
        let mut salt_seed = 0x2024;
        let proof = prove_round_one_key_fri(
            &parameters,
            ring_degree,
            &public,
            &secret,
            &digits,
            &proof_parameters,
            &mut salt_seed,
        )
        .expect("prove");
        (public, ring_degree, proof_parameters, proof)
    }

    #[test]
    fn encode_decode_round_trips_and_the_decoded_proof_verifies() {
        let parameters = sixteen_limb_group_field_parameters();
        let (public, ring_degree, proof_parameters, proof) = sample_proof();
        let bytes = encode_key_proof(&proof).expect("encode");
        let decoded = decode_key_proof(&parameters, &bytes).expect("decode");
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
        let parameters = sixteen_limb_group_field_parameters();
        let (_public, _ring_degree, _proof_parameters, proof) = sample_proof();
        let bytes = encode_key_proof(&proof).expect("encode");

        let mut trailing = bytes.clone();
        trailing.push(0);
        let truncated = bytes[..bytes.len() - 1].to_vec();
        let truncated_header = bytes[..4].to_vec();
        let mut wrong_magic = bytes.clone();
        wrong_magic[0] ^= 0xff;
        let mut corrupted_length = bytes;
        let offset = CODEC_MAGIC.len() + 4 * MERKLE_DIGEST_BYTES;
        corrupted_length[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());

        for (case_name, malformed) in [
            ("trailing bytes", trailing),
            ("truncation", truncated),
            ("truncated header", truncated_header),
            ("wrong magic", wrong_magic),
            ("corrupted length", corrupted_length),
        ] {
            assert!(
                decode_key_proof(&parameters, &malformed).is_err(),
                "{case_name} must be rejected"
            );
        }
    }
}
