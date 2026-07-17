use std::sync::Arc;

use super::*;
use crate::foundation::{CanonicalStreamDomain, VerifiedCanonicalStreamSummary};

#[derive(Clone)]
pub(super) struct CanonicalPublicKeyShareMaterialLimb {
    pub(super) coefficients: Vec<u64>,
}

#[derive(Clone)]
pub(super) struct CanonicalPublicKeyShareMaterialRecord {
    pub(super) limbs: Vec<CanonicalPublicKeyShareMaterialLimb>,
}

pub(super) struct DecodedCanonicalPublicKeyShareMaterial {
    pub(super) records: Vec<CanonicalPublicKeyShareMaterialRecord>,
}

pub(in crate::bgv::setup) struct VerifiedCanonicalPublicKeyShareMaterial {
    chunks: Vec<Vec<u8>>,
    total_byte_length: u64,
}

pub(in crate::bgv::setup) type VerifiedCanonicalPublicKeyShareMaterialHandle =
    Arc<VerifiedCanonicalPublicKeyShareMaterial>;

pub(in crate::bgv::setup) struct VerifiedCanonicalPublicKeyShareMaterialStoreEntry {
    pub(in crate::bgv::setup) material: VerifiedCanonicalPublicKeyShareMaterialHandle,
}

pub(in crate::bgv::setup) struct CanonicalPublicKeyShareMaterialStream {
    chunks: Vec<Vec<u8>>,
    observed_byte_length: u64,
    total_byte_length: u64,
}

pub(in crate::bgv::setup) fn begin_verified_canonical_public_key_share_material_stream(
    total_byte_length: u64,
) -> CanonicalResult<CanonicalPublicKeyShareMaterialStream> {
    if total_byte_length < minimum_public_key_share_material_byte_length()?
        || total_byte_length > maximum_public_key_share_material_byte_length()?
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "public-key share material stream length is outside the accepted setup profile",
        ));
    }
    Ok(CanonicalPublicKeyShareMaterialStream {
        chunks: Vec::new(),
        observed_byte_length: 0,
        total_byte_length,
    })
}

pub(in crate::bgv::setup) fn absorb_verified_canonical_public_key_share_material_chunk(
    stream: &mut CanonicalPublicKeyShareMaterialStream,
    chunk: &[u8],
) -> CanonicalResult<()> {
    let chunk_byte_length = u64::try_from(chunk.len()).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "public-key share material chunk length does not fit u64",
        )
    })?;
    let observed_byte_length = stream
        .observed_byte_length
        .checked_add(chunk_byte_length)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "public-key share material stream length overflowed u64",
            )
        })?;
    if observed_byte_length > stream.total_byte_length {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "public-key share material stream exceeds its declared length",
        ));
    }
    stream.observed_byte_length = observed_byte_length;
    stream.chunks.push(chunk.to_vec());
    Ok(())
}

pub(in crate::bgv::setup) fn finish_verified_canonical_public_key_share_material_stream(
    stream: CanonicalPublicKeyShareMaterialStream,
    stream_summary: Arc<VerifiedCanonicalStreamSummary>,
) -> CanonicalResult<VerifiedCanonicalPublicKeyShareMaterialStoreEntry> {
    if stream_summary.stream_domain() != CanonicalStreamDomain::PublicKeyShareMaterial
        || stream_summary.total_byte_length() != stream.total_byte_length
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "public-key share material does not match its authenticated stream summary",
        ));
    }
    if stream.observed_byte_length != stream.total_byte_length {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "public-key share material stream ended before its declared length",
        ));
    }
    Ok(VerifiedCanonicalPublicKeyShareMaterialStoreEntry {
        material: Arc::new(VerifiedCanonicalPublicKeyShareMaterial {
            chunks: stream.chunks,
            total_byte_length: stream.total_byte_length,
        }),
    })
}

pub(in crate::bgv::setup) fn cancel_verified_canonical_public_key_share_material_stream(
    _stream: CanonicalPublicKeyShareMaterialStream,
) {
}

pub(super) fn decode_verified_canonical_public_key_share_material(
    material: &VerifiedCanonicalPublicKeyShareMaterial,
    participant_count: u64,
    ring_degree: usize,
) -> CanonicalResult<DecodedCanonicalPublicKeyShareMaterial> {
    if !super::super::participant_count_is_configurable(participant_count) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "public-key share material participant count is outside the accepted setup profile",
        ));
    }
    if ring_degree == 0 || ring_degree > POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "public-key share material ring degree is outside the accepted setup profile",
        ));
    }
    if material.total_byte_length
        != public_key_share_material_byte_length(participant_count, ring_degree)?
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "public-key share material length does not match the accepted roster and ring degree",
        ));
    }

    let mut reader = CanonicalPublicKeyShareMaterialReader::new(&material.chunks);
    if reader.read_fixed::<8>()?.as_slice() != PUBLIC_KEY_SHARE_MATERIAL_BINARY_MAGIC {
        return Err(public_key_share_material_decode_error(
            "public-key share material binary magic does not match",
        ));
    }

    let participant_capacity = usize::try_from(participant_count).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "public-key share material participant count does not fit usize",
        )
    })?;
    let mut records = Vec::with_capacity(participant_capacity);
    for _trustee_roster_position in 0..participant_count {
        let mut limbs = Vec::with_capacity(DATA_PRIMES.len());
        for rns_prime in DATA_PRIMES {
            let mut coefficients = Vec::with_capacity(ring_degree);
            for _coefficient_index in 0..ring_degree {
                let coefficient = reader.read_unsigned64()?;
                if coefficient >= rns_prime {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::ComponentMismatch,
                        "public-key share material coefficient is not a canonical residue",
                    ));
                }
                coefficients.push(coefficient);
            }
            limbs.push(CanonicalPublicKeyShareMaterialLimb { coefficients });
        }
        records.push(CanonicalPublicKeyShareMaterialRecord { limbs });
    }

    Ok(DecodedCanonicalPublicKeyShareMaterial { records })
}

struct CanonicalPublicKeyShareMaterialReader<'a> {
    chunks: &'a [Vec<u8>],
    chunk_index: usize,
    byte_index: usize,
}

impl<'a> CanonicalPublicKeyShareMaterialReader<'a> {
    fn new(chunks: &'a [Vec<u8>]) -> Self {
        Self {
            chunks,
            chunk_index: 0,
            byte_index: 0,
        }
    }

    fn read_fixed<const BYTE_LENGTH: usize>(&mut self) -> CanonicalResult<[u8; BYTE_LENGTH]> {
        let mut bytes = [0_u8; BYTE_LENGTH];
        let mut destination_offset = 0;
        while destination_offset < BYTE_LENGTH {
            let chunk = self.chunks.get(self.chunk_index).ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "public-key share material ended before its canonical body was complete",
                )
            })?;
            if self.byte_index == chunk.len() {
                self.chunk_index += 1;
                self.byte_index = 0;
                continue;
            }
            let copied_byte_length =
                (BYTE_LENGTH - destination_offset).min(chunk.len() - self.byte_index);
            bytes[destination_offset..destination_offset + copied_byte_length]
                .copy_from_slice(&chunk[self.byte_index..self.byte_index + copied_byte_length]);
            destination_offset += copied_byte_length;
            self.byte_index += copied_byte_length;
        }
        Ok(bytes)
    }

    fn read_unsigned64(&mut self) -> CanonicalResult<u64> {
        Ok(u64::from_le_bytes(self.read_fixed::<8>()?))
    }
}

fn public_key_share_material_byte_length(
    participant_count: u64,
    ring_degree: usize,
) -> CanonicalResult<u64> {
    let rns_limb_count = u64::try_from(DATA_PRIMES.len()).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "public-key share material RNS limb count does not fit u64",
        )
    })?;
    let ring_degree = u64::try_from(ring_degree).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "public-key share material ring degree does not fit u64",
        )
    })?;
    let magic_byte_length =
        u64::try_from(PUBLIC_KEY_SHARE_MATERIAL_BINARY_MAGIC.len()).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "public-key share material magic length does not fit u64",
            )
        })?;
    participant_count
        .checked_mul(rns_limb_count)
        .and_then(|value| value.checked_mul(ring_degree))
        .and_then(|value| value.checked_mul(8))
        .and_then(|value| value.checked_add(magic_byte_length))
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "public-key share material length overflowed u64",
            )
        })
}

fn minimum_public_key_share_material_byte_length() -> CanonicalResult<u64> {
    public_key_share_material_byte_length(
        u64::from(crate::foundation::MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT),
        1,
    )
}

fn maximum_public_key_share_material_byte_length() -> CanonicalResult<u64> {
    public_key_share_material_byte_length(
        u64::from(crate::foundation::MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT),
        POLYNOMIAL_DEGREE,
    )
}

fn public_key_share_material_decode_error(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidProtocolObject, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PARTICIPANT_COUNT: u64 = 3;
    const TEST_RING_DEGREE: usize = 2;

    fn encoded_material() -> Vec<u8> {
        let mut bytes = PUBLIC_KEY_SHARE_MATERIAL_BINARY_MAGIC.to_vec();
        for trustee_roster_position in 0..TEST_PARTICIPANT_COUNT {
            for (rns_limb_index, _rns_prime) in DATA_PRIMES.iter().enumerate() {
                for coefficient_index in 0..TEST_RING_DEGREE {
                    let coefficient = trustee_roster_position
                        + u64::try_from(rns_limb_index).expect("RNS limb index fits u64")
                        + u64::try_from(coefficient_index).expect("coefficient index fits u64");
                    bytes.extend_from_slice(&coefficient.to_le_bytes());
                }
            }
        }
        bytes
    }

    fn verified_material(bytes: Vec<u8>) -> VerifiedCanonicalPublicKeyShareMaterial {
        VerifiedCanonicalPublicKeyShareMaterial {
            total_byte_length: u64::try_from(bytes.len()).expect("material length fits u64"),
            chunks: bytes.chunks(5).map(<[u8]>::to_vec).collect(),
        }
    }

    #[test]
    fn decoder_uses_the_authoritative_shape_across_chunk_boundaries() {
        let material = verified_material(encoded_material());
        let decoded = decode_verified_canonical_public_key_share_material(
            &material,
            TEST_PARTICIPANT_COUNT,
            TEST_RING_DEGREE,
        )
        .expect("canonical public-key share material");

        assert_eq!(
            decoded.records.len(),
            usize::try_from(TEST_PARTICIPANT_COUNT).expect("participant count fits usize")
        );
        assert_eq!(decoded.records[1].limbs.len(), DATA_PRIMES.len());
        assert_eq!(decoded.records[1].limbs[2].coefficients, vec![3, 4]);
    }

    #[test]
    fn decoder_rejects_a_body_with_the_wrong_authoritative_length() {
        let mut bytes = encoded_material();
        bytes.pop();
        let material = verified_material(bytes);
        let Err(error) = decode_verified_canonical_public_key_share_material(
            &material,
            TEST_PARTICIPANT_COUNT,
            TEST_RING_DEGREE,
        ) else {
            panic!("truncated public-key share material must be rejected");
        };

        assert_eq!(error.code, CanonicalErrorCode::MalformedLength);
    }

    #[test]
    fn decoder_rejects_a_noncanonical_coefficient() {
        let mut bytes = encoded_material();
        bytes[PUBLIC_KEY_SHARE_MATERIAL_BINARY_MAGIC.len()
            ..PUBLIC_KEY_SHARE_MATERIAL_BINARY_MAGIC.len() + 8]
            .copy_from_slice(&DATA_PRIMES[0].to_le_bytes());
        let material = verified_material(bytes);
        let Err(error) = decode_verified_canonical_public_key_share_material(
            &material,
            TEST_PARTICIPANT_COUNT,
            TEST_RING_DEGREE,
        ) else {
            panic!("noncanonical public-key share coefficient must be rejected");
        };

        assert_eq!(error.code, CanonicalErrorCode::ComponentMismatch);
    }

    #[test]
    fn decoder_rejects_the_previous_binary_format_magic() {
        let mut bytes = encoded_material();
        bytes[..PUBLIC_KEY_SHARE_MATERIAL_BINARY_MAGIC.len()].copy_from_slice(b"SLPKSMV1");
        let material = verified_material(bytes);
        let Err(error) = decode_verified_canonical_public_key_share_material(
            &material,
            TEST_PARTICIPANT_COUNT,
            TEST_RING_DEGREE,
        ) else {
            panic!("obsolete public-key share material encoding must be rejected");
        };

        assert_eq!(error.code, CanonicalErrorCode::InvalidProtocolObject);
    }
}
