//! Bounded external-memory polynomial vectors and range reads.
//!
//! Quotient transforms run once per column in a domain-sized in-memory buffer.
//! External storage therefore owns only persistent vectors and authenticated
//! range reads; the former multi-pass transform machinery is intentionally not
//! part of this module.

use zeroize::Zeroizing;

use super::external_memory::{
    ProofExternalMemory, ProofExternalMemoryExecutor, ProofExternalMemoryExecutorError,
};
use super::relation_plan::RelationColumnValueType;
use super::{
    PROOF_CHALLENGE_EXTENSION_DEGREE, ProofChallengeExtensionElement, ProofExternalMemoryError,
    ProofExternalMemoryObject, ProofFieldError,
};

const BASE_FIELD_ELEMENT_BYTE_LENGTH: usize = 8;
const EXTENSION_FIELD_ELEMENT_BYTE_LENGTH: usize = PROOF_CHALLENGE_EXTENSION_DEGREE * 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExternalPolynomialError {
    InvalidVector,
    CountOverflow,
    AllocationLimitExceeded,
    Field(ProofFieldError),
}

impl From<ProofFieldError> for ExternalPolynomialError {
    fn from(error: ProofFieldError) -> Self {
        Self::Field(error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExternalPolynomialVector {
    object: ProofExternalMemoryObject,
    value_type: RelationColumnValueType,
    element_count: usize,
}

impl ExternalPolynomialVector {
    pub(crate) fn new(
        object: ProofExternalMemoryObject,
        value_type: RelationColumnValueType,
        element_count: usize,
    ) -> Result<Self, ExternalPolynomialError> {
        if element_count == 0 {
            return Err(ExternalPolynomialError::InvalidVector);
        }
        Ok(Self {
            object,
            value_type,
            element_count,
        })
    }

    pub(crate) const fn object(self) -> ProofExternalMemoryObject {
        self.object
    }

    pub(crate) const fn value_type(self) -> RelationColumnValueType {
        self.value_type
    }

    pub(crate) const fn element_count(self) -> usize {
        self.element_count
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ExternalPolynomialReadError<StorageError> {
    Polynomial(ExternalPolynomialError),
    Storage(ProofExternalMemoryExecutorError<StorageError>),
}

impl<StorageError> From<ExternalPolynomialError> for ExternalPolynomialReadError<StorageError> {
    fn from(error: ExternalPolynomialError) -> Self {
        Self::Polynomial(error)
    }
}

impl<StorageError> From<ProofExternalMemoryExecutorError<StorageError>>
    for ExternalPolynomialReadError<StorageError>
{
    fn from(error: ProofExternalMemoryExecutorError<StorageError>) -> Self {
        Self::Storage(error)
    }
}

pub(crate) fn read_external_polynomial_extension_values<Storage: ProofExternalMemory>(
    executor: &mut ProofExternalMemoryExecutor,
    storage: &mut Storage,
    vector: ExternalPolynomialVector,
    element_offset: usize,
    element_count: usize,
) -> Result<
    Zeroizing<Vec<ProofChallengeExtensionElement>>,
    ExternalPolynomialReadError<Storage::Error>,
> {
    if vector.value_type() != RelationColumnValueType::ChallengeExtension
        || element_count == 0
        || element_offset
            .checked_add(element_count)
            .filter(|end| *end <= vector.element_count())
            .is_none()
    {
        return Err(ExternalPolynomialError::InvalidVector.into());
    }

    let byte_offset = element_offset
        .checked_mul(EXTENSION_FIELD_ELEMENT_BYTE_LENGTH)
        .and_then(|offset| u64::try_from(offset).ok())
        .ok_or(ExternalPolynomialError::CountOverflow)?;
    let byte_length = element_count
        .checked_mul(EXTENSION_FIELD_ELEMENT_BYTE_LENGTH)
        .ok_or(ExternalPolynomialError::CountOverflow)?;
    let mut encoded_values = Zeroizing::new(Vec::new());
    encoded_values
        .try_reserve_exact(byte_length)
        .map_err(|_| ExternalPolynomialError::AllocationLimitExceeded)?;
    encoded_values.resize(byte_length, 0);
    executor.read_object_bytes(storage, vector.object(), byte_offset, &mut encoded_values)?;

    let mut values = Zeroizing::new(Vec::new());
    values
        .try_reserve_exact(element_count)
        .map_err(|_| ExternalPolynomialError::AllocationLimitExceeded)?;
    for encoded_value in encoded_values.chunks_exact(EXTENSION_FIELD_ELEMENT_BYTE_LENGTH) {
        let mut coordinates = [0_u64; PROOF_CHALLENGE_EXTENSION_DEGREE];
        for (coordinate, encoded_coordinate) in coordinates
            .iter_mut()
            .zip(encoded_value.chunks_exact(BASE_FIELD_ELEMENT_BYTE_LENGTH))
        {
            let mut canonical_coordinate = [0_u8; BASE_FIELD_ELEMENT_BYTE_LENGTH];
            canonical_coordinate.copy_from_slice(encoded_coordinate);
            *coordinate = u64::from_le_bytes(canonical_coordinate);
        }
        values.push(
            ProofChallengeExtensionElement::from_canonical_coordinates(coordinates)
                .map_err(ExternalPolynomialError::from)?,
        );
    }
    if values.len() != element_count {
        return Err(ExternalPolynomialError::InvalidVector.into());
    }
    Ok(values)
}

pub(crate) const fn external_value_byte_length(value_type: RelationColumnValueType) -> u64 {
    match value_type {
        RelationColumnValueType::BaseField => BASE_FIELD_ELEMENT_BYTE_LENGTH as u64,
        RelationColumnValueType::ChallengeExtension => EXTENSION_FIELD_ELEMENT_BYTE_LENGTH as u64,
    }
}

pub(crate) fn map_external_polynomial_read_error(
    error: ExternalPolynomialError,
) -> ProofExternalMemoryError {
    match error {
        ExternalPolynomialError::CountOverflow
        | ExternalPolynomialError::AllocationLimitExceeded => {
            ProofExternalMemoryError::ResourceLimitExceeded
        }
        ExternalPolynomialError::InvalidVector | ExternalPolynomialError::Field(_) => {
            ProofExternalMemoryError::InvalidPlan
        }
    }
}
