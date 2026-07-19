//! Canonical target partial-decryption stream encoding.

use crate::bgv::{
    evaluator::top_k::CANONICAL_TARGET_CIPHERTEXT_LEVEL,
    parameters::{DATA_PRIMES, POLYNOMIAL_DEGREE},
};

const TARGET_ROLE_BYTE_LENGTH: usize = size_of::<u16>();
const TARGET_PRIME_BYTE_LENGTH: usize = size_of::<u64>();
const CANONICAL_RESIDUE_BYTE_LENGTH: usize = size_of::<u64>();
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub(crate) enum TargetPartialDecryptionRole {
    TargetIdentifier = 0,
    TargetOrder = 1,
}

impl TargetPartialDecryptionRole {
    fn decode(value: u16) -> Result<Self, TargetPartialDecryptionStreamError> {
        match value {
            0 => Ok(Self::TargetIdentifier),
            1 => Ok(Self::TargetOrder),
            _ => Err(TargetPartialDecryptionStreamError::InvalidRole),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TargetPartialDecryptionStreamError {
    InvalidRole,
    InvalidTargetPrime,
    InvalidLimbCount,
    InvalidCoefficientCount,
    InvalidByteLength,
    NoncanonicalResidue,
    CountOverflow,
}

/// A validated borrowed view of one selected target partial-decryption stream.
///
/// The canonical bytes start with the little-endian suite target-role
/// identifier. Every suite target prime then appears in order as one
/// little-endian `u64`, immediately followed by its `N` little-endian
/// canonical residues.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CanonicalTargetPartialDecryptionStream<'bytes> {
    canonical_bytes: &'bytes [u8],
    role: TargetPartialDecryptionRole,
}

impl<'bytes> CanonicalTargetPartialDecryptionStream<'bytes> {
    pub(crate) fn decode(
        canonical_bytes: &'bytes [u8],
    ) -> Result<Self, TargetPartialDecryptionStreamError> {
        if canonical_bytes.len() != selected_target_partial_decryption_stream_byte_length()? {
            return Err(TargetPartialDecryptionStreamError::InvalidByteLength);
        }
        let role = TargetPartialDecryptionRole::decode(u16::from_le_bytes(
            canonical_bytes[..TARGET_ROLE_BYTE_LENGTH]
                .try_into()
                .map_err(|_| TargetPartialDecryptionStreamError::InvalidByteLength)?,
        ))?;

        let limb_byte_length = selected_target_limb_byte_length()?;
        for (limb_index, modulus) in DATA_PRIMES
            .iter()
            .take(selected_target_data_prime_count())
            .copied()
            .enumerate()
        {
            let limb_offset = limb_index
                .checked_mul(limb_byte_length)
                .and_then(|offset| offset.checked_add(TARGET_ROLE_BYTE_LENGTH))
                .ok_or(TargetPartialDecryptionStreamError::CountOverflow)?;
            let encoded_modulus = u64::from_le_bytes(
                canonical_bytes[limb_offset..limb_offset + TARGET_PRIME_BYTE_LENGTH]
                    .try_into()
                    .map_err(|_| TargetPartialDecryptionStreamError::InvalidByteLength)?,
            );
            if encoded_modulus != modulus {
                return Err(TargetPartialDecryptionStreamError::InvalidTargetPrime);
            }
            let residue_start = limb_offset + TARGET_PRIME_BYTE_LENGTH;
            let residue_end = limb_offset + limb_byte_length;
            for residue_bytes in canonical_bytes[residue_start..residue_end].chunks_exact(8) {
                let residue = u64::from_le_bytes(
                    residue_bytes
                        .try_into()
                        .map_err(|_| TargetPartialDecryptionStreamError::InvalidByteLength)?,
                );
                if residue >= modulus {
                    return Err(TargetPartialDecryptionStreamError::NoncanonicalResidue);
                }
            }
        }

        Ok(Self {
            canonical_bytes,
            role,
        })
    }

    pub(crate) const fn canonical_bytes(self) -> &'bytes [u8] {
        self.canonical_bytes
    }

    pub(crate) const fn role(self) -> TargetPartialDecryptionRole {
        self.role
    }

    pub(crate) fn coefficient(self, limb_index: usize, coefficient_index: usize) -> Option<u64> {
        if limb_index >= selected_target_data_prime_count()
            || coefficient_index >= POLYNOMIAL_DEGREE
        {
            return None;
        }
        let limb_offset = limb_index
            .checked_mul(selected_target_limb_byte_length().ok()?)?
            .checked_add(TARGET_ROLE_BYTE_LENGTH)?;
        let byte_offset = coefficient_index
            .checked_mul(CANONICAL_RESIDUE_BYTE_LENGTH)?
            .checked_add(limb_offset)?
            .checked_add(TARGET_PRIME_BYTE_LENGTH)?;
        let byte_end = byte_offset.checked_add(CANONICAL_RESIDUE_BYTE_LENGTH)?;
        Some(u64::from_le_bytes(
            self.canonical_bytes
                .get(byte_offset..byte_end)?
                .try_into()
                .ok()?,
        ))
    }

    pub(crate) fn ordered_limbs(self) -> Result<Vec<Vec<u64>>, TargetPartialDecryptionStreamError> {
        (0..selected_target_data_prime_count())
            .map(|limb_index| {
                (0..POLYNOMIAL_DEGREE)
                    .map(|coefficient_index| {
                        self.coefficient(limb_index, coefficient_index)
                            .ok_or(TargetPartialDecryptionStreamError::InvalidByteLength)
                    })
                    .collect()
            })
            .collect()
    }
}

pub(crate) fn encode_target_partial_decryption_stream(
    role: TargetPartialDecryptionRole,
    ordered_limbs: &[Vec<u64>],
) -> Result<Vec<u8>, TargetPartialDecryptionStreamError> {
    if ordered_limbs.len() != selected_target_data_prime_count() {
        return Err(TargetPartialDecryptionStreamError::InvalidLimbCount);
    }
    let mut canonical_bytes =
        Vec::with_capacity(selected_target_partial_decryption_stream_byte_length()?);
    canonical_bytes.extend_from_slice(&(role as u16).to_le_bytes());
    for (limb, modulus) in ordered_limbs.iter().zip(DATA_PRIMES.iter().copied()) {
        if limb.len() != POLYNOMIAL_DEGREE {
            return Err(TargetPartialDecryptionStreamError::InvalidCoefficientCount);
        }
        canonical_bytes.extend_from_slice(&modulus.to_le_bytes());
        for residue in limb {
            if *residue >= modulus {
                return Err(TargetPartialDecryptionStreamError::NoncanonicalResidue);
            }
            canonical_bytes.extend_from_slice(&residue.to_le_bytes());
        }
    }
    CanonicalTargetPartialDecryptionStream::decode(&canonical_bytes)?;
    Ok(canonical_bytes)
}

pub(crate) const fn selected_target_data_prime_count() -> usize {
    CANONICAL_TARGET_CIPHERTEXT_LEVEL + 1
}

fn selected_target_limb_byte_length() -> Result<usize, TargetPartialDecryptionStreamError> {
    POLYNOMIAL_DEGREE
        .checked_mul(CANONICAL_RESIDUE_BYTE_LENGTH)
        .and_then(|byte_length| byte_length.checked_add(TARGET_PRIME_BYTE_LENGTH))
        .ok_or(TargetPartialDecryptionStreamError::CountOverflow)
}

pub(crate) fn selected_target_partial_decryption_stream_byte_length()
-> Result<usize, TargetPartialDecryptionStreamError> {
    selected_target_data_prime_count()
        .checked_mul(selected_target_limb_byte_length()?)
        .and_then(|byte_length| byte_length.checked_add(TARGET_ROLE_BYTE_LENGTH))
        .ok_or(TargetPartialDecryptionStreamError::CountOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn selected_limbs() -> Vec<Vec<u64>> {
        DATA_PRIMES
            .iter()
            .take(selected_target_data_prime_count())
            .map(|modulus| vec![modulus - 1; POLYNOMIAL_DEGREE])
            .collect()
    }

    #[test]
    fn selected_target_partial_stream_round_trips_role_primes_and_residues() {
        let limbs = selected_limbs();
        let bytes = encode_target_partial_decryption_stream(
            TargetPartialDecryptionRole::TargetOrder,
            &limbs,
        )
        .expect("stream encodes");
        assert_eq!(
            bytes.len(),
            selected_target_partial_decryption_stream_byte_length().expect("length")
        );
        let decoded =
            CanonicalTargetPartialDecryptionStream::decode(&bytes).expect("stream decodes");
        assert_eq!(decoded.canonical_bytes(), bytes);
        assert_eq!(decoded.role(), TargetPartialDecryptionRole::TargetOrder);
        assert_eq!(decoded.coefficient(0, 0), Some(DATA_PRIMES[0] - 1));
        assert_eq!(
            decoded.coefficient(
                selected_target_data_prime_count() - 1,
                POLYNOMIAL_DEGREE - 1
            ),
            Some(DATA_PRIMES[selected_target_data_prime_count() - 1] - 1)
        );
        assert_eq!(
            decoded.coefficient(selected_target_data_prime_count(), 0),
            None
        );
        assert_eq!(decoded.coefficient(0, POLYNOMIAL_DEGREE), None);
    }

    #[test]
    fn selected_target_partial_stream_rejects_truncation_extension_and_role_drift() {
        let mut bytes = encode_target_partial_decryption_stream(
            TargetPartialDecryptionRole::TargetIdentifier,
            &selected_limbs(),
        )
        .expect("stream");
        for truncated_length in [0, 1, 2, bytes.len() - 1] {
            assert_eq!(
                CanonicalTargetPartialDecryptionStream::decode(&bytes[..truncated_length]),
                Err(TargetPartialDecryptionStreamError::InvalidByteLength)
            );
        }
        bytes[..2].copy_from_slice(&2_u16.to_le_bytes());
        assert_eq!(
            CanonicalTargetPartialDecryptionStream::decode(&bytes),
            Err(TargetPartialDecryptionStreamError::InvalidRole)
        );
        let mut extended = bytes;
        extended.push(0);
        assert_eq!(
            CanonicalTargetPartialDecryptionStream::decode(&extended),
            Err(TargetPartialDecryptionStreamError::InvalidByteLength)
        );
    }

    #[test]
    fn selected_target_partial_stream_rejects_wrong_limb_shape() {
        assert_eq!(
            encode_target_partial_decryption_stream(
                TargetPartialDecryptionRole::TargetIdentifier,
                &selected_limbs()[..1],
            ),
            Err(TargetPartialDecryptionStreamError::InvalidLimbCount)
        );
        let mut limbs = selected_limbs();
        limbs[0].pop();
        assert_eq!(
            encode_target_partial_decryption_stream(
                TargetPartialDecryptionRole::TargetIdentifier,
                &limbs,
            ),
            Err(TargetPartialDecryptionStreamError::InvalidCoefficientCount)
        );
    }

    #[test]
    fn selected_target_partial_stream_rejects_prime_order_and_noncanonical_residue() {
        let mut bytes = encode_target_partial_decryption_stream(
            TargetPartialDecryptionRole::TargetIdentifier,
            &selected_limbs(),
        )
        .expect("stream encodes");
        bytes[2..10].copy_from_slice(&DATA_PRIMES[1].to_le_bytes());
        assert_eq!(
            CanonicalTargetPartialDecryptionStream::decode(&bytes),
            Err(TargetPartialDecryptionStreamError::InvalidTargetPrime)
        );

        let mut limbs = selected_limbs();
        let last_limb = selected_target_data_prime_count() - 1;
        limbs[last_limb][POLYNOMIAL_DEGREE - 1] = DATA_PRIMES[last_limb];
        assert_eq!(
            encode_target_partial_decryption_stream(
                TargetPartialDecryptionRole::TargetOrder,
                &limbs,
            ),
            Err(TargetPartialDecryptionStreamError::NoncanonicalResidue)
        );
    }
}
