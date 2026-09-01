// The ring, codec, NTT, compression, and centered-binomial arithmetic in this
// module are adapted from fips203 0.4.3 by Eric Schorn and the RustCrypto
// developers under MIT OR Apache-2.0. This variant deliberately carries an
// explicit matrix and consumes direct randomness; it is not FIPS K-PKE or
// ML-KEM.

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

pub const ENCRYPTION_KEY_BYTE_LENGTH: usize = 4_608;
pub const DECRYPTION_KEY_BYTE_LENGTH: usize = 1_152;
pub const CIPHERTEXT_BYTE_LENGTH: usize =
    RANK * VECTOR_CIPHERTEXT_POLYNOMIAL_BYTE_LENGTH + COMPRESSED_MESSAGE_POLYNOMIAL_BYTE_LENGTH;
pub const MESSAGE_BYTE_LENGTH: usize = 32;
pub const KEY_GENERATION_RANDOMNESS_BYTE_LENGTH: usize = 6_912;
pub const ENCRYPTION_RANDOMNESS_BYTE_LENGTH: usize = 896;

const MODULUS: u16 = 3_329;
const ROOT_OF_UNITY: u16 = 17;
const RANK: usize = 3;
const POLYNOMIAL_COEFFICIENT_COUNT: usize = 256;
const ENCODED_POLYNOMIAL_12_BYTE_LENGTH: usize = 384;
const MATRIX_POLYNOMIAL_COUNT: usize = RANK * RANK;
const MATRIX_RANDOMNESS_BYTE_LENGTH: usize = 6_144;
const MATRIX_CANDIDATE_COUNT: usize = 4_096;
const MATRIX_COEFFICIENT_COUNT: usize = MATRIX_POLYNOMIAL_COUNT * POLYNOMIAL_COEFFICIENT_COUNT;
const CBD2_POLYNOMIAL_BYTE_LENGTH: usize = 128;
const VECTOR_CIPHERTEXT_POLYNOMIAL_BYTE_LENGTH: usize = 320;
const COMPRESSED_MESSAGE_POLYNOMIAL_BYTE_LENGTH: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairEncryptionError {
    InvalidCiphertextLength,
    InvalidDecryptionKeyLength,
    InvalidEncryptionKeyLength,
    InvalidEncryptionRandomnessLength,
    InvalidKeyGenerationRandomnessLength,
    InvalidMessageLength,
    NoncanonicalCoefficient,
    SamplerCapExceeded,
}

impl fmt::Display for PairEncryptionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidCiphertextLength => "pair ciphertext has the wrong length",
            Self::InvalidDecryptionKeyLength => "pair decryption key has the wrong length",
            Self::InvalidEncryptionKeyLength => "pair encryption key has the wrong length",
            Self::InvalidEncryptionRandomnessLength => {
                "pair encryption randomness has the wrong length"
            }
            Self::InvalidKeyGenerationRandomnessLength => {
                "pair key-generation randomness has the wrong length"
            }
            Self::InvalidMessageLength => "pair plaintext has the wrong length",
            Self::NoncanonicalCoefficient => "pair key contains a noncanonical coefficient",
            Self::SamplerCapExceeded => "pair matrix sampler exhausted its fixed tape",
        })
    }
}

impl std::error::Error for PairEncryptionError {}

#[derive(Clone, Copy, Default, Zeroize)]
struct Coefficient(u16);

impl Coefficient {
    fn from_canonical(value: u16) -> Result<Self, PairEncryptionError> {
        if value >= MODULUS {
            return Err(PairEncryptionError::NoncanonicalCoefficient);
        }
        Ok(Self(value))
    }

    fn add(self, other: Self) -> Self {
        let sum = u32::from(self.0) + u32::from(other.0);
        let reduced = sum.wrapping_sub(u32::from(MODULUS));
        let reduced = reduced.wrapping_add((reduced >> 16) & u32::from(MODULUS));
        debug_assert!(reduced < u32::from(MODULUS));
        Self(reduced as u16)
    }

    fn sub(self, other: Self) -> Self {
        let difference = u32::from(self.0).wrapping_sub(u32::from(other.0));
        let reduced = difference.wrapping_add((difference >> 16) & u32::from(MODULUS));
        debug_assert!(reduced < u32::from(MODULUS));
        Self(reduced as u16)
    }

    fn mul(self, other: Self) -> Self {
        const RECIPROCAL: u64 = (1_u64 << 36).div_ceil(MODULUS as u64);
        let product = u32::from(self.0) * u32::from(other.0);
        let quotient = ((u64::from(product) * RECIPROCAL) >> 36) as u32;
        let remainder = product - quotient * u32::from(MODULUS);
        debug_assert!(remainder < u32::from(MODULUS));
        Self(remainder as u16)
    }

    fn base_mul(self, a1: Self, b0: Self, b1: Self, gamma: Self) -> Self {
        const RECIPROCAL: u128 = (1_u128 << 100).div_ceil(MODULUS as u128);
        let product = u64::from(self.0) * u64::from(b0.0)
            + u64::from(a1.0) * u64::from(b1.0) * u64::from(gamma.0);
        let quotient = (u128::from(product) * RECIPROCAL) >> 100;
        let remainder = u128::from(product) - quotient * u128::from(MODULUS);
        debug_assert!(remainder < u128::from(MODULUS));
        Self(remainder as u16)
    }

    fn base_mul_second(self, a1: Self, b0: Self, b1: Self) -> Self {
        const RECIPROCAL: u64 = (1_u64 << 36).div_ceil(MODULUS as u64);
        let product = u32::from(self.0) * u32::from(b1.0) + u32::from(a1.0) * u32::from(b0.0);
        let quotient = ((u64::from(product) * RECIPROCAL) >> 36) as u32;
        let remainder = product - quotient * u32::from(MODULUS);
        debug_assert!(remainder < u32::from(MODULUS));
        Self(remainder as u16)
    }
}

type Polynomial = [Coefficient; POLYNOMIAL_COEFFICIENT_COUNT];
type PolynomialVector = [Polynomial; RANK];
type PolynomialMatrix = [[Polynomial; RANK]; RANK];

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PairEncryptionKeyPair {
    pub encryption_key: [u8; ENCRYPTION_KEY_BYTE_LENGTH],
    pub decryption_key: [u8; DECRYPTION_KEY_BYTE_LENGTH],
}

pub fn generate_key_pair(randomness: &[u8]) -> Result<PairEncryptionKeyPair, PairEncryptionError> {
    if randomness.len() != KEY_GENERATION_RANDOMNESS_BYTE_LENGTH {
        return Err(PairEncryptionError::InvalidKeyGenerationRandomnessLength);
    }
    let matrix_tape = &randomness[..MATRIX_RANDOMNESS_BYTE_LENGTH];
    let noise_tape = &randomness[MATRIX_RANDOMNESS_BYTE_LENGTH..];
    let matrix = sample_explicit_matrix(matrix_tape)?;
    let mut secret: PolynomialVector = core::array::from_fn(|index| {
        sample_cbd2(
            &noise_tape
                [index * CBD2_POLYNOMIAL_BYTE_LENGTH..(index + 1) * CBD2_POLYNOMIAL_BYTE_LENGTH],
        )
    });
    let mut error: PolynomialVector = core::array::from_fn(|index| {
        let tape_index = RANK + index;
        sample_cbd2(
            &noise_tape[tape_index * CBD2_POLYNOMIAL_BYTE_LENGTH
                ..(tape_index + 1) * CBD2_POLYNOMIAL_BYTE_LENGTH],
        )
    });
    let mut secret_ntt: PolynomialVector = core::array::from_fn(|index| ntt(&secret[index]));
    let mut error_ntt: PolynomialVector = core::array::from_fn(|index| ntt(&error[index]));
    let matrix_ntt: PolynomialMatrix =
        core::array::from_fn(|row| core::array::from_fn(|column| ntt(&matrix[row][column])));
    let mut public_vector = multiply_matrix_vector(&matrix_ntt, &secret_ntt);
    add_vector_in_place(&mut public_vector, &error_ntt);

    let mut encryption_key = [0_u8; ENCRYPTION_KEY_BYTE_LENGTH];
    let mut encryption_key_offset = 0;
    for row in &matrix_ntt {
        for polynomial in row {
            byte_encode(
                12,
                polynomial,
                &mut encryption_key[encryption_key_offset..][..384],
            );
            encryption_key_offset += ENCODED_POLYNOMIAL_12_BYTE_LENGTH;
        }
    }
    for polynomial in &public_vector {
        byte_encode(
            12,
            polynomial,
            &mut encryption_key[encryption_key_offset..][..384],
        );
        encryption_key_offset += ENCODED_POLYNOMIAL_12_BYTE_LENGTH;
    }

    let mut decryption_key = [0_u8; DECRYPTION_KEY_BYTE_LENGTH];
    for (polynomial, output) in secret_ntt
        .iter()
        .zip(decryption_key.chunks_exact_mut(ENCODED_POLYNOMIAL_12_BYTE_LENGTH))
    {
        byte_encode(12, polynomial, output);
    }

    secret.zeroize();
    error.zeroize();
    secret_ntt.zeroize();
    error_ntt.zeroize();
    public_vector.zeroize();
    Ok(PairEncryptionKeyPair {
        encryption_key,
        decryption_key,
    })
}

pub fn encrypt(
    encryption_key: &[u8],
    message: &[u8],
    randomness: &[u8],
) -> Result<[u8; CIPHERTEXT_BYTE_LENGTH], PairEncryptionError> {
    if encryption_key.len() != ENCRYPTION_KEY_BYTE_LENGTH {
        return Err(PairEncryptionError::InvalidEncryptionKeyLength);
    }
    if message.len() != MESSAGE_BYTE_LENGTH {
        return Err(PairEncryptionError::InvalidMessageLength);
    }
    if randomness.len() != ENCRYPTION_RANDOMNESS_BYTE_LENGTH {
        return Err(PairEncryptionError::InvalidEncryptionRandomnessLength);
    }
    let (matrix_ntt, public_vector) = decode_encryption_key(encryption_key)?;
    let mut ephemeral_secret: PolynomialVector = core::array::from_fn(|index| {
        sample_cbd2(
            &randomness
                [index * CBD2_POLYNOMIAL_BYTE_LENGTH..(index + 1) * CBD2_POLYNOMIAL_BYTE_LENGTH],
        )
    });
    let mut vector_error: PolynomialVector = core::array::from_fn(|index| {
        let tape_index = RANK + index;
        sample_cbd2(
            &randomness[tape_index * CBD2_POLYNOMIAL_BYTE_LENGTH
                ..(tape_index + 1) * CBD2_POLYNOMIAL_BYTE_LENGTH],
        )
    });
    let mut scalar_error = sample_cbd2(&randomness[6 * CBD2_POLYNOMIAL_BYTE_LENGTH..]);
    let mut ephemeral_secret_ntt: PolynomialVector =
        core::array::from_fn(|index| ntt(&ephemeral_secret[index]));

    let mut vector_ciphertext =
        multiply_transposed_matrix_vector(&matrix_ntt, &ephemeral_secret_ntt);
    for polynomial in &mut vector_ciphertext {
        *polynomial = ntt_inverse(polynomial);
    }
    add_vector_in_place(&mut vector_ciphertext, &vector_error);

    let mut scalar_ciphertext = ntt_inverse(&dot_product(&public_vector, &ephemeral_secret_ntt));
    add_polynomial_in_place(&mut scalar_ciphertext, &scalar_error);
    let encoded_message = decode_polynomial(1, message)?;
    add_polynomial_in_place(&mut scalar_ciphertext, &decompress(1, encoded_message));

    let mut ciphertext = [0_u8; CIPHERTEXT_BYTE_LENGTH];
    for (polynomial, output) in vector_ciphertext.iter_mut().zip(
        ciphertext[..RANK * VECTOR_CIPHERTEXT_POLYNOMIAL_BYTE_LENGTH]
            .chunks_exact_mut(VECTOR_CIPHERTEXT_POLYNOMIAL_BYTE_LENGTH),
    ) {
        compress_in_place(10, polynomial);
        byte_encode(10, polynomial, output);
    }
    compress_in_place(4, &mut scalar_ciphertext);
    byte_encode(
        4,
        &scalar_ciphertext,
        &mut ciphertext[RANK * VECTOR_CIPHERTEXT_POLYNOMIAL_BYTE_LENGTH..],
    );

    ephemeral_secret.zeroize();
    vector_error.zeroize();
    scalar_error.zeroize();
    ephemeral_secret_ntt.zeroize();
    vector_ciphertext.zeroize();
    scalar_ciphertext.zeroize();
    Ok(ciphertext)
}

pub fn validate_encryption_key(encryption_key: &[u8]) -> Result<(), PairEncryptionError> {
    decode_encryption_key(encryption_key).map(|_| ())
}

pub fn decrypt(
    decryption_key: &[u8],
    ciphertext: &[u8],
) -> Result<[u8; MESSAGE_BYTE_LENGTH], PairEncryptionError> {
    if decryption_key.len() != DECRYPTION_KEY_BYTE_LENGTH {
        return Err(PairEncryptionError::InvalidDecryptionKeyLength);
    }
    if ciphertext.len() != CIPHERTEXT_BYTE_LENGTH {
        return Err(PairEncryptionError::InvalidCiphertextLength);
    }
    let mut secret_ntt: PolynomialVector = decode_polynomial_vector(12, decryption_key)?;
    let mut vector_ciphertext: PolynomialVector = core::array::from_fn(|index| {
        let start = index * VECTOR_CIPHERTEXT_POLYNOMIAL_BYTE_LENGTH;
        let encoded = decode_polynomial(
            10,
            &ciphertext[start..start + VECTOR_CIPHERTEXT_POLYNOMIAL_BYTE_LENGTH],
        )
        .expect("ten-bit ciphertext polynomial has a fixed canonical range");
        decompress(10, encoded)
    });
    let mut scalar_ciphertext = decompress(
        4,
        decode_polynomial(
            4,
            &ciphertext[RANK * VECTOR_CIPHERTEXT_POLYNOMIAL_BYTE_LENGTH..],
        )?,
    );
    let mut vector_ciphertext_ntt: PolynomialVector =
        core::array::from_fn(|index| ntt(&vector_ciphertext[index]));
    let mut product = ntt_inverse(&dot_product(&secret_ntt, &vector_ciphertext_ntt));
    for (value, subtrahend) in scalar_ciphertext.iter_mut().zip(product) {
        *value = value.sub(subtrahend);
    }
    compress_in_place(1, &mut scalar_ciphertext);
    let mut message = [0_u8; MESSAGE_BYTE_LENGTH];
    byte_encode(1, &scalar_ciphertext, &mut message);

    secret_ntt.zeroize();
    vector_ciphertext.zeroize();
    vector_ciphertext_ntt.zeroize();
    product.zeroize();
    scalar_ciphertext.zeroize();
    Ok(message)
}

fn sample_explicit_matrix(tape: &[u8]) -> Result<PolynomialMatrix, PairEncryptionError> {
    if tape.len() != MATRIX_RANDOMNESS_BYTE_LENGTH {
        return Err(PairEncryptionError::InvalidKeyGenerationRandomnessLength);
    }
    let mut accepted = [Coefficient::default(); MATRIX_COEFFICIENT_COUNT];
    let mut accepted_count = 0;
    let mut candidate_count = 0;
    for bytes in tape.chunks_exact(3) {
        let candidates = [
            u16::from(bytes[0]) | ((u16::from(bytes[1]) & 0x0f) << 8),
            (u16::from(bytes[1]) >> 4) | (u16::from(bytes[2]) << 4),
        ];
        for candidate in candidates {
            candidate_count += 1;
            if candidate < MODULUS && accepted_count < MATRIX_COEFFICIENT_COUNT {
                accepted[accepted_count] = Coefficient(candidate);
                accepted_count += 1;
            }
        }
    }
    debug_assert_eq!(candidate_count, MATRIX_CANDIDATE_COUNT);
    if accepted_count != MATRIX_COEFFICIENT_COUNT {
        return Err(PairEncryptionError::SamplerCapExceeded);
    }
    Ok(core::array::from_fn(|row| {
        core::array::from_fn(|column| {
            core::array::from_fn(|coefficient| {
                accepted[(row * RANK + column) * POLYNOMIAL_COEFFICIENT_COUNT + coefficient]
            })
        })
    }))
}

fn sample_cbd2(bytes: &[u8]) -> Polynomial {
    debug_assert_eq!(bytes.len(), CBD2_POLYNOMIAL_BYTE_LENGTH);
    let mut output = [Coefficient::default(); POLYNOMIAL_COEFFICIENT_COUNT];
    for (coefficient_index, nibble) in bytes
        .iter()
        .flat_map(|byte| [byte & 0x0f, byte >> 4])
        .enumerate()
    {
        let positive = count_low_two_bits(nibble);
        let negative = count_low_two_bits(nibble >> 2);
        output[coefficient_index] = Coefficient(positive).sub(Coefficient(negative));
    }
    output
}

fn count_low_two_bits(value: u8) -> u16 {
    u16::from(value & 1) + u16::from((value >> 1) & 1)
}

fn decode_encryption_key(
    bytes: &[u8],
) -> Result<(PolynomialMatrix, PolynomialVector), PairEncryptionError> {
    if bytes.len() != ENCRYPTION_KEY_BYTE_LENGTH {
        return Err(PairEncryptionError::InvalidEncryptionKeyLength);
    }
    let mut polynomials =
        [[Coefficient::default(); POLYNOMIAL_COEFFICIENT_COUNT]; MATRIX_POLYNOMIAL_COUNT + RANK];
    for (index, polynomial) in polynomials.iter_mut().enumerate() {
        let start = index * ENCODED_POLYNOMIAL_12_BYTE_LENGTH;
        *polynomial = decode_canonical_polynomial_12(
            &bytes[start..start + ENCODED_POLYNOMIAL_12_BYTE_LENGTH],
        )?;
    }
    let matrix =
        core::array::from_fn(|row| core::array::from_fn(|column| polynomials[row * RANK + column]));
    let public_vector = core::array::from_fn(|index| polynomials[MATRIX_POLYNOMIAL_COUNT + index]);
    Ok((matrix, public_vector))
}

fn decode_polynomial_vector(
    width: u32,
    bytes: &[u8],
) -> Result<PolynomialVector, PairEncryptionError> {
    let polynomial_byte_length = 32 * width as usize;
    if bytes.len() != RANK * polynomial_byte_length {
        return Err(PairEncryptionError::InvalidDecryptionKeyLength);
    }
    let mut output = [[Coefficient::default(); POLYNOMIAL_COEFFICIENT_COUNT]; RANK];
    for (index, polynomial) in output.iter_mut().enumerate() {
        *polynomial = decode_polynomial(
            width,
            &bytes[index * polynomial_byte_length..(index + 1) * polynomial_byte_length],
        )?;
    }
    Ok(output)
}

fn decode_canonical_polynomial_12(bytes: &[u8]) -> Result<Polynomial, PairEncryptionError> {
    let polynomial = decode_polynomial(12, bytes)?;
    let mut reencoded = [0_u8; ENCODED_POLYNOMIAL_12_BYTE_LENGTH];
    byte_encode(12, &polynomial, &mut reencoded);
    if reencoded != bytes {
        return Err(PairEncryptionError::NoncanonicalCoefficient);
    }
    Ok(polynomial)
}

fn decode_polynomial(width: u32, bytes: &[u8]) -> Result<Polynomial, PairEncryptionError> {
    if bytes.len() != 32 * width as usize {
        return Err(PairEncryptionError::NoncanonicalCoefficient);
    }
    let mut output = [Coefficient::default(); POLYNOMIAL_COEFFICIENT_COUNT];
    let mut accumulator = 0_u32;
    let mut accumulator_bits = 0_u32;
    let mut coefficient_index = 0;
    for byte in bytes {
        accumulator |= u32::from(*byte) << accumulator_bits;
        accumulator_bits += 8;
        while accumulator_bits >= width {
            let value = (accumulator & ((1_u32 << width) - 1)) as u16;
            output[coefficient_index] = if width == 12 {
                Coefficient::from_canonical(value)?
            } else {
                Coefficient(value)
            };
            coefficient_index += 1;
            accumulator >>= width;
            accumulator_bits -= width;
        }
    }
    if coefficient_index != POLYNOMIAL_COEFFICIENT_COUNT || accumulator_bits != 0 {
        return Err(PairEncryptionError::NoncanonicalCoefficient);
    }
    Ok(output)
}

fn byte_encode(width: u32, polynomial: &Polynomial, output: &mut [u8]) {
    debug_assert_eq!(output.len(), 32 * width as usize);
    let mut accumulator = 0_u32;
    let mut accumulator_bits = 0_u32;
    let mut output_index = 0;
    for coefficient in polynomial {
        accumulator |= u32::from(coefficient.0) << accumulator_bits;
        accumulator_bits += width;
        while accumulator_bits >= 8 {
            output[output_index] = accumulator as u8;
            output_index += 1;
            accumulator >>= 8;
            accumulator_bits -= 8;
        }
    }
    debug_assert_eq!(output_index, output.len());
    debug_assert_eq!(accumulator_bits, 0);
}

fn compress_in_place(width: u32, polynomial: &mut Polynomial) {
    const RECIPROCAL: u32 = (1_u64 << 36).div_ceil(MODULUS as u64) as u32;
    for coefficient in polynomial {
        let scaled = (u32::from(coefficient.0) << width) + u32::from(MODULUS / 2);
        let compressed = (u64::from(scaled) * u64::from(RECIPROCAL)) >> 36;
        coefficient.0 = (compressed & ((1_u64 << width) - 1)) as u16;
    }
}

fn decompress(width: u32, mut polynomial: Polynomial) -> Polynomial {
    for coefficient in &mut polynomial {
        let scaled = u32::from(MODULUS) * u32::from(coefficient.0) + (1_u32 << width) - 1;
        coefficient.0 = (scaled >> width) as u16;
    }
    polynomial
}

fn add_polynomial_in_place(left: &mut Polynomial, right: &Polynomial) {
    for (left_value, right_value) in left.iter_mut().zip(right) {
        *left_value = left_value.add(*right_value);
    }
}

fn add_vector_in_place(left: &mut PolynomialVector, right: &PolynomialVector) {
    for (left_polynomial, right_polynomial) in left.iter_mut().zip(right) {
        add_polynomial_in_place(left_polynomial, right_polynomial);
    }
}

fn multiply_matrix_vector(
    matrix: &PolynomialMatrix,
    vector: &PolynomialVector,
) -> PolynomialVector {
    core::array::from_fn(|row| {
        let mut output = [Coefficient::default(); POLYNOMIAL_COEFFICIENT_COUNT];
        for (matrix_polynomial, vector_polynomial) in matrix[row].iter().zip(vector) {
            add_polynomial_in_place(
                &mut output,
                &multiply_ntts(matrix_polynomial, vector_polynomial),
            );
        }
        output
    })
}

fn multiply_transposed_matrix_vector(
    matrix: &PolynomialMatrix,
    vector: &PolynomialVector,
) -> PolynomialVector {
    core::array::from_fn(|column| {
        let mut output = [Coefficient::default(); POLYNOMIAL_COEFFICIENT_COUNT];
        for row in 0..RANK {
            add_polynomial_in_place(
                &mut output,
                &multiply_ntts(&matrix[row][column], &vector[row]),
            );
        }
        output
    })
}

fn dot_product(left: &PolynomialVector, right: &PolynomialVector) -> Polynomial {
    let mut output = [Coefficient::default(); POLYNOMIAL_COEFFICIENT_COUNT];
    for (left_polynomial, right_polynomial) in left.iter().zip(right) {
        add_polynomial_in_place(
            &mut output,
            &multiply_ntts(left_polynomial, right_polynomial),
        );
    }
    output
}

fn ntt(input: &Polynomial) -> Polynomial {
    let mut output = *input;
    let mut zeta_index = 1;
    for length in [128, 64, 32, 16, 8, 4, 2] {
        for start in (0..POLYNOMIAL_COEFFICIENT_COUNT).step_by(2 * length) {
            let zeta = ZETA_TABLE[zeta_index << 1];
            zeta_index += 1;
            for index in start..start + length {
                let product = output[index + length].mul(zeta);
                output[index + length] = output[index].sub(product);
                output[index] = output[index].add(product);
            }
        }
    }
    output
}

fn ntt_inverse(input: &Polynomial) -> Polynomial {
    let mut output = *input;
    let mut zeta_index = 127;
    for length in [2, 4, 8, 16, 32, 64, 128] {
        for start in (0..POLYNOMIAL_COEFFICIENT_COUNT).step_by(2 * length) {
            let zeta = ZETA_TABLE[zeta_index << 1];
            zeta_index -= 1;
            for index in start..start + length {
                let previous = output[index];
                output[index] = previous.add(output[index + length]);
                output[index + length] = zeta.mul(output[index + length].sub(previous));
            }
        }
    }
    let inverse_128 = Coefficient(3_303);
    for value in &mut output {
        *value = value.mul(inverse_128);
    }
    output
}

fn multiply_ntts(left: &Polynomial, right: &Polynomial) -> Polynomial {
    let mut output = [Coefficient::default(); POLYNOMIAL_COEFFICIENT_COUNT];
    for index in 0..128 {
        let zeta = ZETA_TABLE[index ^ 0x80];
        output[2 * index] = left[2 * index].base_mul(
            left[2 * index + 1],
            right[2 * index],
            right[2 * index + 1],
            zeta,
        );
        output[2 * index + 1] = left[2 * index].base_mul_second(
            left[2 * index + 1],
            right[2 * index],
            right[2 * index + 1],
        );
    }
    output
}

const fn zeta_table() -> [Coefficient; 256] {
    let mut output = [Coefficient(0); 256];
    let mut value = 1_u32;
    let mut index = 0_u32;
    while index < 256 {
        output[(index as u8).reverse_bits() as usize] = Coefficient(value as u16);
        value = (value * ROOT_OF_UNITY as u32) % MODULUS as u32;
        index += 1;
    }
    output
}

static ZETA_TABLE: [Coefficient; 256] = zeta_table();

#[cfg(test)]
mod tests {
    use super::*;

    fn pseudorandom_bytes(length: usize, seed: u64) -> Vec<u8> {
        let mut state = seed;
        (0..length)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect()
    }

    #[test]
    fn explicit_matrix_key_and_ciphertext_round_trip() {
        let key_randomness = pseudorandom_bytes(KEY_GENERATION_RANDOMNESS_BYTE_LENGTH, 0x5a17);
        let key_pair = generate_key_pair(&key_randomness).expect("fixed matrix tape succeeds");
        let encryption_randomness = pseudorandom_bytes(ENCRYPTION_RANDOMNESS_BYTE_LENGTH, 0x9123);
        for message in [[0_u8; 32], [0xff_u8; 32], core::array::from_fn(|i| i as u8)] {
            let ciphertext = encrypt(&key_pair.encryption_key, &message, &encryption_randomness)
                .expect("encryption succeeds");
            assert_eq!(
                decrypt(&key_pair.decryption_key, &ciphertext).expect("decryption succeeds"),
                message
            );
        }
    }

    #[test]
    fn canonical_key_parser_rejects_out_of_range_coefficients() {
        let key_randomness = pseudorandom_bytes(KEY_GENERATION_RANDOMNESS_BYTE_LENGTH, 0x33a1);
        let mut key_pair = generate_key_pair(&key_randomness).expect("fixed matrix tape succeeds");
        key_pair.encryption_key[..3].fill(0xff);
        assert_eq!(
            encrypt(
                &key_pair.encryption_key,
                &[0_u8; MESSAGE_BYTE_LENGTH],
                &[0_u8; ENCRYPTION_RANDOMNESS_BYTE_LENGTH],
            ),
            Err(PairEncryptionError::NoncanonicalCoefficient)
        );
    }

    #[test]
    fn fixed_matrix_sampler_fails_closed() {
        assert!(matches!(
            sample_explicit_matrix(&[0xff_u8; MATRIX_RANDOMNESS_BYTE_LENGTH]),
            Err(PairEncryptionError::SamplerCapExceeded)
        ));
    }

    #[test]
    fn ntt_product_matches_independent_negacyclic_multiplication() {
        for seed in [1_u64, 0x51a7, 0xffff_ffff_ffff_ffff] {
            let left_bytes = pseudorandom_bytes(2 * POLYNOMIAL_COEFFICIENT_COUNT, seed);
            let right_bytes = pseudorandom_bytes(2 * POLYNOMIAL_COEFFICIENT_COUNT, seed ^ 0xa53c);
            let left: Polynomial = core::array::from_fn(|index| {
                Coefficient(
                    u16::from_le_bytes([left_bytes[2 * index], left_bytes[2 * index + 1]])
                        % MODULUS,
                )
            });
            let right: Polynomial = core::array::from_fn(|index| {
                Coefficient(
                    u16::from_le_bytes([right_bytes[2 * index], right_bytes[2 * index + 1]])
                        % MODULUS,
                )
            });
            let actual = ntt_inverse(&multiply_ntts(&ntt(&left), &ntt(&right)));
            let mut expected = [0_i64; POLYNOMIAL_COEFFICIENT_COUNT];
            for (left_index, left_value) in left.iter().enumerate() {
                for (right_index, right_value) in right.iter().enumerate() {
                    let raw_index = left_index + right_index;
                    let product = i64::from(left_value.0) * i64::from(right_value.0);
                    if raw_index < POLYNOMIAL_COEFFICIENT_COUNT {
                        expected[raw_index] += product;
                    } else {
                        expected[raw_index - POLYNOMIAL_COEFFICIENT_COUNT] -= product;
                    }
                }
            }
            for (actual_value, expected_value) in actual.iter().zip(expected) {
                assert_eq!(
                    actual_value.0,
                    expected_value.rem_euclid(i64::from(MODULUS)) as u16
                );
            }
        }
    }

    #[test]
    fn compression_and_decompression_match_the_integer_definitions() {
        for width in [1_u32, 4, 10] {
            for value in 0..MODULUS {
                let mut polynomial = [Coefficient(value); POLYNOMIAL_COEFFICIENT_COUNT];
                compress_in_place(width, &mut polynomial);
                let expected = ((((u32::from(value) << width) + u32::from(MODULUS / 2))
                    / u32::from(MODULUS))
                    & ((1_u32 << width) - 1)) as u16;
                assert_eq!(polynomial[0].0, expected);
            }
            for value in 0..(1_u16 << width) {
                let polynomial =
                    decompress(width, [Coefficient(value); POLYNOMIAL_COEFFICIENT_COUNT]);
                let expected = ((u32::from(MODULUS) * u32::from(value) + (1_u32 << width) - 1)
                    >> width) as u16;
                assert_eq!(polynomial[0].0, expected);
            }
        }
    }
}
