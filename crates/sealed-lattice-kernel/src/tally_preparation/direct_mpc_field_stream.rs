use core::fmt;

use sha3::{
    CShake256, CShake256Core,
    digest::{ExtendableOutput, Update, XofReader},
};
use zeroize::Zeroizing;

use crate::foundation::{
    CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalCodecError, CanonicalItem,
    CanonicalTuple, FOUNDATION_PROFILE, Hash512,
};

use super::{
    TallyPreparationError,
    direct_mpc_candidate_compiler::{
        DIRECT_MPC_FIELD_SAMPLE_BYTE_LENGTH, reduce_little_endian_field_sample,
    },
    direct_mpc_prime_field::DirectMpcPrimeFieldElement,
    replicated_random_sharing::ReplicatedRandomSharingSubset,
};

pub(crate) const DIRECT_MPC_FIELD_STREAM_CUSTOMIZATION: &[u8] =
    b"sealed-lattice/v1/direct-mpc/pseudorandom-field-stream";
pub(crate) const DIRECT_MPC_SUBSET_MASTER_BYTE_LENGTH: usize = 40;
pub(crate) const DIRECT_MPC_FIELD_STREAM_QUERY_BYTE_LENGTH: usize = 302;

const PREPARATION_ATTEMPT_ORDINAL: u16 = 0;
const CSHAKE256_RATE_BYTE_LENGTH: usize = 136;
const ENCODED_CSHAKE256_RATE: [u8; 2] = [1, 136];
const ENCODED_SUBSET_MASTER_BIT_LENGTH: [u8; 3] = [2, 1, 64];
const KMACXOF_UNBOUNDED_OUTPUT_LENGTH: [u8; 2] = [0, 1];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub(crate) enum DirectMpcFieldStreamKind {
    OrdinaryDegreeThree = 1,
    DegreeSixZeroBasis = 2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DirectMpcFieldStreamError {
    Canonical(CanonicalCodecError),
    Preparation(TallyPreparationError),
    OrdinaryBasisPositionNonzero {
        basis_position: u16,
    },
    ZeroBasisPositionOutOfRange {
        basis_position: u16,
        active_fault_bound: u16,
    },
    FieldCountZero,
    ChunkIndexOutOfRange {
        chunk_index: u64,
        chunk_count: u64,
    },
    ArithmeticOverflow,
    IntegerConversion,
    QueryGeometryMismatch {
        actual_byte_length: usize,
    },
}

impl fmt::Display for DirectMpcFieldStreamError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Canonical(error) => {
                write!(formatter, "canonical field-stream query error: {error}")
            }
            Self::Preparation(error) => write!(formatter, "preparation geometry error: {error}"),
            Self::OrdinaryBasisPositionNonzero { basis_position } => write!(
                formatter,
                "ordinary direct-MPC field stream has basis position {basis_position}; expected zero"
            ),
            Self::ZeroBasisPositionOutOfRange {
                basis_position,
                active_fault_bound,
            } => write!(
                formatter,
                "direct-MPC zero-basis position {basis_position} is outside active fault bound {active_fault_bound}"
            ),
            Self::FieldCountZero => formatter.write_str("direct-MPC field-stream count is zero"),
            Self::ChunkIndexOutOfRange {
                chunk_index,
                chunk_count,
            } => write!(
                formatter,
                "direct-MPC field-stream chunk {chunk_index} is outside chunk count {chunk_count}"
            ),
            Self::ArithmeticOverflow => {
                formatter.write_str("direct-MPC field-stream arithmetic overflow")
            }
            Self::IntegerConversion => {
                formatter.write_str("direct-MPC field-stream integer conversion failed")
            }
            Self::QueryGeometryMismatch { actual_byte_length } => write!(
                formatter,
                "direct-MPC field-stream query has {actual_byte_length} bytes; expected {DIRECT_MPC_FIELD_STREAM_QUERY_BYTE_LENGTH}"
            ),
        }
    }
}

impl std::error::Error for DirectMpcFieldStreamError {}

impl From<CanonicalCodecError> for DirectMpcFieldStreamError {
    fn from(error: CanonicalCodecError) -> Self {
        Self::Canonical(error)
    }
}

impl From<TallyPreparationError> for DirectMpcFieldStreamError {
    fn from(error: TallyPreparationError) -> Self {
        Self::Preparation(error)
    }
}

/// Public coordinate for one independently restartable direct-MPC PRSS stream.
///
/// The three identities bind the unactivated candidate, preparation context,
/// and positively verified seed terminal. This coordinate carries no seed or
/// continuation authority by itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DirectMpcFieldStreamCoordinate {
    candidate_identity: Hash512,
    preparation_context_identity: Hash512,
    seed_terminal_identity: Hash512,
    stream_kind: DirectMpcFieldStreamKind,
    subset: ReplicatedRandomSharingSubset,
    basis_position: u16,
    total_field_count: u64,
}

impl DirectMpcFieldStreamCoordinate {
    pub(crate) fn new(
        candidate_identity: Hash512,
        preparation_context_identity: Hash512,
        seed_terminal_identity: Hash512,
        stream_kind: DirectMpcFieldStreamKind,
        subset: ReplicatedRandomSharingSubset,
        basis_position: u16,
        total_field_count: u64,
    ) -> Result<Self, DirectMpcFieldStreamError> {
        match stream_kind {
            DirectMpcFieldStreamKind::OrdinaryDegreeThree if basis_position != 0 => {
                return Err(DirectMpcFieldStreamError::OrdinaryBasisPositionNonzero {
                    basis_position,
                });
            }
            DirectMpcFieldStreamKind::DegreeSixZeroBasis
                if basis_position >= subset.active_fault_bound() =>
            {
                return Err(DirectMpcFieldStreamError::ZeroBasisPositionOutOfRange {
                    basis_position,
                    active_fault_bound: subset.active_fault_bound(),
                });
            }
            _ => {}
        }
        if total_field_count == 0 {
            return Err(DirectMpcFieldStreamError::FieldCountZero);
        }
        Ok(Self {
            candidate_identity,
            preparation_context_identity,
            seed_terminal_identity,
            stream_kind,
            subset,
            basis_position,
            total_field_count,
        })
    }

    pub(crate) fn chunk_count(self) -> Result<u64, DirectMpcFieldStreamError> {
        direct_mpc_field_stream_chunk_count(self.total_field_count)
    }

    pub(crate) fn canonical_query_bytes(
        self,
        chunk_index: u64,
    ) -> Result<Vec<u8>, DirectMpcFieldStreamError> {
        let geometry = derive_chunk_geometry(self.total_field_count, chunk_index)?;
        let query = CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            vec![
                CanonicalItem::hash512(self.candidate_identity.into_bytes()),
                CanonicalItem::hash512(self.preparation_context_identity.into_bytes()),
                CanonicalItem::hash512(self.seed_terminal_identity.into_bytes()),
                CanonicalItem::unsigned16(PREPARATION_ATTEMPT_ORDINAL),
                CanonicalItem::unsigned16(self.stream_kind as u16),
                CanonicalItem::unsigned16(self.subset.participant_count()),
                CanonicalItem::unsigned32(self.subset.excluded_position_mask()),
                CanonicalItem::unsigned16(self.basis_position),
                CanonicalItem::unsigned64(self.total_field_count),
                CanonicalItem::unsigned64(chunk_index),
                CanonicalItem::unsigned64(geometry.field_count),
            ],
        )
        .encode()?;
        if query.len() != DIRECT_MPC_FIELD_STREAM_QUERY_BYTE_LENGTH {
            return Err(DirectMpcFieldStreamError::QueryGeometryMismatch {
                actual_byte_length: query.len(),
            });
        }
        Ok(query)
    }
}

pub(crate) struct DirectMpcFieldStreamChunk {
    first_field_index: u64,
    field_count: u64,
    sample_bytes: Zeroizing<Vec<u8>>,
}

impl DirectMpcFieldStreamChunk {
    pub(crate) const fn first_field_index(&self) -> u64 {
        self.first_field_index
    }

    pub(crate) const fn field_count(&self) -> u64 {
        self.field_count
    }

    pub(crate) fn sample_byte_length(&self) -> usize {
        self.sample_bytes.len()
    }

    pub(crate) fn field_element(
        &self,
        position_within_chunk: u64,
    ) -> Result<DirectMpcPrimeFieldElement, DirectMpcFieldStreamError> {
        if position_within_chunk >= self.field_count {
            return Err(DirectMpcFieldStreamError::ChunkIndexOutOfRange {
                chunk_index: position_within_chunk,
                chunk_count: self.field_count,
            });
        }
        let sample_byte_length = usize::try_from(DIRECT_MPC_FIELD_SAMPLE_BYTE_LENGTH)
            .map_err(|_| DirectMpcFieldStreamError::IntegerConversion)?;
        let start = usize::try_from(position_within_chunk)
            .map_err(|_| DirectMpcFieldStreamError::IntegerConversion)?
            .checked_mul(sample_byte_length)
            .ok_or(DirectMpcFieldStreamError::ArithmeticOverflow)?;
        let end = start
            .checked_add(sample_byte_length)
            .ok_or(DirectMpcFieldStreamError::ArithmeticOverflow)?;
        Ok(reduce_little_endian_field_sample(
            &self.sample_bytes[start..end],
        ))
    }
}

impl fmt::Debug for DirectMpcFieldStreamChunk {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DirectMpcFieldStreamChunk")
            .field("first_field_index", &self.first_field_index)
            .field("field_count", &self.field_count)
            .field("sample_bytes", &"[redacted]")
            .finish()
    }
}

pub(crate) fn generate_direct_mpc_field_stream_chunk(
    subset_master: &[u8; DIRECT_MPC_SUBSET_MASTER_BYTE_LENGTH],
    coordinate: DirectMpcFieldStreamCoordinate,
    chunk_index: u64,
) -> Result<DirectMpcFieldStreamChunk, DirectMpcFieldStreamError> {
    let geometry = derive_chunk_geometry(coordinate.total_field_count, chunk_index)?;
    let query = coordinate.canonical_query_bytes(chunk_index)?;
    let sample_byte_length = usize::try_from(DIRECT_MPC_FIELD_SAMPLE_BYTE_LENGTH)
        .map_err(|_| DirectMpcFieldStreamError::IntegerConversion)?;
    let output_byte_length = usize::try_from(geometry.field_count)
        .map_err(|_| DirectMpcFieldStreamError::IntegerConversion)?
        .checked_mul(sample_byte_length)
        .ok_or(DirectMpcFieldStreamError::ArithmeticOverflow)?;
    Ok(DirectMpcFieldStreamChunk {
        first_field_index: geometry.first_field_index,
        field_count: geometry.field_count,
        sample_bytes: expand_direct_mpc_field_stream_kmacxof256(
            subset_master,
            &query,
            output_byte_length,
        ),
    })
}

fn expand_direct_mpc_field_stream_kmacxof256(
    key: &[u8; DIRECT_MPC_SUBSET_MASTER_BYTE_LENGTH],
    message: &[u8],
    output_byte_length: usize,
) -> Zeroizing<Vec<u8>> {
    let mut padded_key = Zeroizing::new([0_u8; CSHAKE256_RATE_BYTE_LENGTH]);
    let key_length_start = ENCODED_CSHAKE256_RATE.len();
    let key_start = key_length_start + ENCODED_SUBSET_MASTER_BIT_LENGTH.len();
    let key_end = key_start + key.len();
    padded_key[..key_length_start].copy_from_slice(&ENCODED_CSHAKE256_RATE);
    padded_key[key_length_start..key_start].copy_from_slice(&ENCODED_SUBSET_MASTER_BIT_LENGTH);
    padded_key[key_start..key_end].copy_from_slice(key);

    let mut kmac = CShake256::from_core(CShake256Core::new_with_function_name(
        b"KMAC",
        DIRECT_MPC_FIELD_STREAM_CUSTOMIZATION,
    ));
    kmac.update(padded_key.as_ref());
    kmac.update(message);
    kmac.update(&KMACXOF_UNBOUNDED_OUTPUT_LENGTH);
    let mut output = Zeroizing::new(vec![0_u8; output_byte_length]);
    kmac.finalize_xof().read(output.as_mut());
    output
}

#[cfg(test)]
pub(super) fn expand_direct_mpc_field_stream_kmacxof256_for_test(
    key: &[u8; DIRECT_MPC_SUBSET_MASTER_BYTE_LENGTH],
    message: &[u8],
    output_byte_length: usize,
) -> Zeroizing<Vec<u8>> {
    expand_direct_mpc_field_stream_kmacxof256(key, message, output_byte_length)
}

pub(crate) fn direct_mpc_field_stream_elements_per_chunk() -> Result<u64, DirectMpcFieldStreamError>
{
    let stream_chunk_byte_length = u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length)
        .map_err(|_| DirectMpcFieldStreamError::IntegerConversion)?;
    stream_chunk_byte_length
        .checked_div(DIRECT_MPC_FIELD_SAMPLE_BYTE_LENGTH)
        .filter(|field_count| *field_count > 0)
        .ok_or(DirectMpcFieldStreamError::ArithmeticOverflow)
}

pub(crate) fn direct_mpc_field_stream_chunk_count(
    total_field_count: u64,
) -> Result<u64, DirectMpcFieldStreamError> {
    if total_field_count == 0 {
        return Err(DirectMpcFieldStreamError::FieldCountZero);
    }
    let fields_per_chunk = direct_mpc_field_stream_elements_per_chunk()?;
    total_field_count
        .checked_add(fields_per_chunk - 1)
        .and_then(|value| value.checked_div(fields_per_chunk))
        .ok_or(DirectMpcFieldStreamError::ArithmeticOverflow)
}

#[derive(Debug, Clone, Copy)]
struct DirectMpcFieldChunkGeometry {
    first_field_index: u64,
    field_count: u64,
}

fn derive_chunk_geometry(
    total_field_count: u64,
    chunk_index: u64,
) -> Result<DirectMpcFieldChunkGeometry, DirectMpcFieldStreamError> {
    let fields_per_chunk = direct_mpc_field_stream_elements_per_chunk()?;
    let chunk_count = direct_mpc_field_stream_chunk_count(total_field_count)?;
    if chunk_index >= chunk_count {
        return Err(DirectMpcFieldStreamError::ChunkIndexOutOfRange {
            chunk_index,
            chunk_count,
        });
    }
    let first_field_index = chunk_index
        .checked_mul(fields_per_chunk)
        .ok_or(DirectMpcFieldStreamError::ArithmeticOverflow)?;
    let field_count = total_field_count
        .checked_sub(first_field_index)
        .ok_or(DirectMpcFieldStreamError::ArithmeticOverflow)?
        .min(fields_per_chunk);
    Ok(DirectMpcFieldChunkGeometry {
        first_field_index,
        field_count,
    })
}
