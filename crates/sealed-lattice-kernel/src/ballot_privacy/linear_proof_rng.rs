use aes::{
    Aes256,
    cipher::{Block, BlockEncrypt, Key, KeyInit},
};

use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};

pub fn generate_linear_proof_aes256ctr_stream(
    seed: &[u8; 32],
    domain_separator: u64,
    output_length: usize,
) -> Vec<u8> {
    let cipher = Aes256::new(Key::<Aes256>::from_slice(seed));
    let mut counter_block = [0_u8; 16];
    // Counter layout: domain_separator in the low 8 bytes; the block counter
    // increments from the high 8 bytes (see increment_linear_proof_counter), so
    // the 64-bit domain and 64-bit counter spaces never collide.
    counter_block[..8].copy_from_slice(&domain_separator.to_le_bytes());

    let mut output = Vec::with_capacity(output_length);
    while output.len() < output_length {
        let mut encrypted_block = Block::<Aes256>::clone_from_slice(&counter_block);
        cipher.encrypt_block(&mut encrypted_block);
        let remaining_output = output_length - output.len();
        output.extend_from_slice(&encrypted_block[..remaining_output.min(16)]);
        increment_linear_proof_counter(&mut counter_block);
    }

    output
}

pub fn sample_linear_proof_uniform_u64_values(
    value_count: usize,
    modulus: u64,
    modulus_bit_length: usize,
    seed: &[u8; 32],
    domain_separator: u64,
) -> CanonicalResult<Vec<u64>> {
    LinearProofUniformSampler::new(seed).sample_uniform_u64_values(
        value_count,
        modulus,
        modulus_bit_length,
        domain_separator,
    )
}

/// Reusable uniform sampler that builds the AES-256 key schedule once and shares
/// it across many domain-separated draws (for example every entry of an expanded
/// public matrix). Produced values are byte-for-byte identical to reseeding a
/// fresh AES-256-CTR stream per draw.
pub(crate) struct LinearProofUniformSampler {
    cipher: Aes256,
}

impl LinearProofUniformSampler {
    pub(crate) fn new(seed: &[u8; 32]) -> Self {
        Self {
            cipher: Aes256::new(Key::<Aes256>::from_slice(seed)),
        }
    }

    pub(crate) fn sample_uniform_u64_values(
        &self,
        value_count: usize,
        modulus: u64,
        modulus_bit_length: usize,
        domain_separator: u64,
    ) -> CanonicalResult<Vec<u64>> {
        if value_count == 0 {
            return Ok(Vec::new());
        }
        if modulus < 2 {
            return Err(invalid_rng("uniform modulus must be at least two"));
        }
        if modulus_bit_length == 0 || modulus_bit_length > 63 {
            return Err(invalid_rng(
                "uniform modulus bit length must be between one and sixty-three",
            ));
        }
        // Rejection sampling for uniform-mod-q from bit-packed bytes: require the
        // modulus in [2^(bits-1), 2^bits) so the bit-length hugs the modulus and
        // bounds the rejection probability below (candidate < modulus accepts).
        if modulus < (1_u64 << (modulus_bit_length - 1)) || modulus >= (1_u64 << modulus_bit_length)
        {
            return Err(invalid_rng(
                "uniform modulus does not match the requested bit length",
            ));
        }

        let mut accepted_values = Vec::with_capacity(value_count);
        let mut stream = LinearProofAesCtrStream::new(&self.cipher, domain_separator);
        while accepted_values.len() < value_count {
            let remaining_values = value_count - accepted_values.len();
            let byte_count = (modulus_bit_length * remaining_values).div_ceil(8);
            let round = stream.advance(byte_count);
            let round_bytes = &stream.buffer[round];

            for candidate_index in 0..remaining_values {
                let candidate = read_little_endian_bit_packed_value(
                    round_bytes,
                    candidate_index,
                    modulus_bit_length,
                )?;
                if candidate < modulus {
                    accepted_values.push(candidate);
                    if accepted_values.len() == value_count {
                        break;
                    }
                }
            }
        }

        Ok(accepted_values)
    }
}

pub fn sample_linear_proof_autostable_challenge_coefficients(
    coefficient_count: usize,
    coefficient_bound: i64,
    modulus_bit_length: usize,
    seed: &[u8; 32],
    domain_separator: u64,
) -> CanonicalResult<Vec<i64>> {
    if coefficient_count == 0 || !coefficient_count.is_multiple_of(2) {
        return Err(invalid_rng(
            "autostable coefficient count must be a non-zero even number",
        ));
    }
    if coefficient_bound < 0 {
        return Err(invalid_rng(
            "autostable coefficient bound must be non-negative",
        ));
    }
    let unsigned_modulus = u64::try_from(
        coefficient_bound
            .checked_mul(2)
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| invalid_rng("autostable modulus overflowed"))?,
    )
    .map_err(|_| invalid_rng("autostable modulus does not fit in u64"))?;
    let sample_count = coefficient_count / 2;
    let sampled_values = sample_linear_proof_uniform_u64_values(
        sample_count,
        unsigned_modulus,
        modulus_bit_length,
        seed,
        domain_separator,
    )?;
    // "Autostable" construction: sample count/2 lower coefficients, force the
    // middle coefficient (index count/2) to zero, then set the upper half to the
    // negated mirror of the lower half. This yields a polynomial fixed by sigma
    // (sigma(c) = c), the symmetry the auto-fold soundness argument relies on.
    let mut coefficients = vec![0_i64; coefficient_count];
    for (coefficient_index, sampled_value) in sampled_values.iter().enumerate() {
        coefficients[coefficient_index] = i64::try_from(*sampled_value)
            .map_err(|_| invalid_rng("sampled challenge value does not fit in i64"))?
            - coefficient_bound;
    }
    coefficients[sample_count] = 0;
    for coefficient_index in (sample_count + 1)..coefficient_count {
        coefficients[coefficient_index] = -coefficients[coefficient_count - coefficient_index];
    }

    Ok(coefficients)
}

/// Incremental AES-256-CTR byte stream over a borrowed cipher. Blocks are
/// produced once and appended, so growing the stream never regenerates earlier
/// blocks and the cipher key schedule is shared across draws. The bytes are
/// identical to `generate_linear_proof_aes256ctr_stream` for the same seed and
/// domain separator.
struct LinearProofAesCtrStream<'cipher> {
    cipher: &'cipher Aes256,
    counter_block: [u8; 16],
    buffer: Vec<u8>,
    consumed_bytes: usize,
}

impl<'cipher> LinearProofAesCtrStream<'cipher> {
    fn new(cipher: &'cipher Aes256, domain_separator: u64) -> Self {
        let mut counter_block = [0_u8; 16];
        counter_block[..8].copy_from_slice(&domain_separator.to_le_bytes());
        Self {
            cipher,
            counter_block,
            buffer: Vec::new(),
            consumed_bytes: 0,
        }
    }

    fn advance(&mut self, byte_count: usize) -> core::ops::Range<usize> {
        let start = self.consumed_bytes;
        let end = start + byte_count;
        while self.buffer.len() < end {
            let mut encrypted_block = Block::<Aes256>::clone_from_slice(&self.counter_block);
            self.cipher.encrypt_block(&mut encrypted_block);
            self.buffer.extend_from_slice(encrypted_block.as_slice());
            increment_linear_proof_counter(&mut self.counter_block);
        }
        self.consumed_bytes = end;

        start..end
    }
}

fn increment_linear_proof_counter(counter_block: &mut [u8; 16]) {
    for byte_index in (0..counter_block.len()).rev() {
        let (updated_byte, overflowed) = counter_block[byte_index].overflowing_add(1);
        counter_block[byte_index] = updated_byte;
        if !overflowed {
            break;
        }
    }
}

fn read_little_endian_bit_packed_value(
    bytes: &[u8],
    value_index: usize,
    bit_length: usize,
) -> CanonicalResult<u64> {
    let start_bit = value_index
        .checked_mul(bit_length)
        .ok_or_else(|| invalid_rng("uniform bit index overflowed"))?;
    let end_bit = start_bit
        .checked_add(bit_length)
        .ok_or_else(|| invalid_rng("uniform bit index overflowed"))?;
    let start_byte = start_bit / 8;
    let end_byte = end_bit.div_ceil(8);
    if end_byte > bytes.len() {
        return Err(invalid_rng("uniform bit stream ended early"));
    }

    // Assemble the (at most nine) straddled bytes little-endian, then shift the
    // sub-byte start offset away and mask to the requested width. This matches
    // the previous bit-by-bit little-endian reader exactly.
    let mut accumulator = 0_u128;
    for (byte_offset, byte) in bytes[start_byte..end_byte].iter().enumerate() {
        accumulator |= u128::from(*byte) << (8 * byte_offset);
    }
    let bit_offset = (start_bit % 8) as u32;
    let mask = (1_u128 << bit_length) - 1;

    Ok(((accumulator >> bit_offset) & mask) as u64)
}

fn invalid_rng(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

#[cfg(test)]
mod tests {
    use super::{
        generate_linear_proof_aes256ctr_stream,
        sample_linear_proof_autostable_challenge_coefficients,
        sample_linear_proof_uniform_u64_values,
    };
    use crate::{hashing::to_hex, transcript_core::decode_hex};

    #[test]
    fn aes256ctr_stream_matches_upstream_linear_proof_known_answer() {
        let seed_bytes =
            decode_hex("ff7a617ce69148e4f1726e2f43581de2aa62d9f805532edff1eed687fb54153d")
                .expect("seed should decode");
        let mut seed = [0_u8; 32];
        seed.copy_from_slice(&seed_bytes);
        let domain_bytes = decode_hex("001cc5b751a51d70").expect("domain should decode");
        let mut domain_buffer = [0_u8; 8];
        domain_buffer.copy_from_slice(&domain_bytes);
        let domain_separator = u64::from_le_bytes(domain_buffer);

        let stream = generate_linear_proof_aes256ctr_stream(&seed, domain_separator, 36);

        assert_eq!(
            to_hex(&stream),
            "913cd4d68a9feed715e3bd37489e266f8a3c490cefe47e14bbde6ade9317f9619c99e38a"
        );
    }

    #[test]
    fn uniform_sampler_rejects_out_of_range_candidates_deterministically() {
        let seed = [7_u8; 32];
        let first = sample_linear_proof_uniform_u64_values(128, 17, 5, &seed, 9)
            .expect("uniform sampling should succeed");
        let second = sample_linear_proof_uniform_u64_values(128, 17, 5, &seed, 9)
            .expect("uniform sampling should repeat");

        assert_eq!(first, second);
        assert!(first.iter().all(|value| *value < 17));
        assert!(first.contains(&16));
    }

    #[test]
    fn autostable_challenge_has_expected_symmetry() {
        let seed = [11_u8; 32];
        let coefficients =
            sample_linear_proof_autostable_challenge_coefficients(64, 8, 5, &seed, 0)
                .expect("autostable sampling should succeed");

        assert_eq!(coefficients[32], 0);
        assert!(
            coefficients
                .iter()
                .all(|coefficient| (-8..=8).contains(coefficient))
        );
        for coefficient_index in 33..64 {
            assert_eq!(
                coefficients[coefficient_index],
                -coefficients[64 - coefficient_index]
            );
        }
    }
}
