//! Bounded external-memory polynomial vectors and range reads.
//!
//! Quotient transforms run once per column in a domain-sized in-memory buffer.
//! External storage therefore owns only persistent vectors and authenticated
//! range reads; the former multi-pass transform machinery is intentionally not
//! part of this module.

use zeroize::{Zeroize, Zeroizing};

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

pub(crate) fn read_external_polynomial_values_as_extension<Storage: ProofExternalMemory>(
    executor: &mut ProofExternalMemoryExecutor,
    storage: &mut Storage,
    vector: ExternalPolynomialVector,
    element_offset: usize,
    element_count: usize,
) -> Result<
    Zeroizing<Vec<ProofChallengeExtensionElement>>,
    ExternalPolynomialReadError<Storage::Error>,
> {
    let mut values = Zeroizing::new(Vec::new());
    read_external_polynomial_values_as_extension_into(
        executor,
        storage,
        vector,
        element_offset,
        element_count,
        &mut values,
    )?;
    Ok(values)
}

pub(crate) fn read_external_polynomial_values_as_extension_into<Storage: ProofExternalMemory>(
    executor: &mut ProofExternalMemoryExecutor,
    storage: &mut Storage,
    vector: ExternalPolynomialVector,
    element_offset: usize,
    element_count: usize,
    values: &mut Zeroizing<Vec<ProofChallengeExtensionElement>>,
) -> Result<(), ExternalPolynomialReadError<Storage::Error>> {
    if element_count == 0
        || element_offset
            .checked_add(element_count)
            .filter(|end| *end <= vector.element_count())
            .is_none()
    {
        return Err(ExternalPolynomialError::InvalidVector.into());
    }

    let element_byte_length = usize::try_from(external_value_byte_length(vector.value_type()))
        .map_err(|_| ExternalPolynomialError::CountOverflow)?;
    let byte_offset = element_offset
        .checked_mul(element_byte_length)
        .and_then(|offset| u64::try_from(offset).ok())
        .ok_or(ExternalPolynomialError::CountOverflow)?;
    let byte_length = element_count
        .checked_mul(element_byte_length)
        .ok_or(ExternalPolynomialError::CountOverflow)?;
    let mut encoded_values = Zeroizing::new(Vec::new());
    encoded_values
        .try_reserve_exact(byte_length)
        .map_err(|_| ExternalPolynomialError::AllocationLimitExceeded)?;
    encoded_values.resize(byte_length, 0);
    executor.read_object_bytes(storage, vector.object(), byte_offset, &mut encoded_values)?;

    values.zeroize();
    values.clear();
    if values.capacity() < element_count {
        values
            .try_reserve_exact(element_count)
            .map_err(|_| ExternalPolynomialError::AllocationLimitExceeded)?;
    }
    for encoded_value in encoded_values.chunks_exact(element_byte_length) {
        let mut coordinates = [0_u64; PROOF_CHALLENGE_EXTENSION_DEGREE];
        for (coordinate, encoded_coordinate) in coordinates.iter_mut().zip(
            encoded_value
                .chunks_exact(BASE_FIELD_ELEMENT_BYTE_LENGTH)
                .take(match vector.value_type() {
                    RelationColumnValueType::BaseField => 1,
                    RelationColumnValueType::ChallengeExtension => PROOF_CHALLENGE_EXTENSION_DEGREE,
                }),
        ) {
            let mut canonical_coordinate = [0_u8; BASE_FIELD_ELEMENT_BYTE_LENGTH];
            canonical_coordinate.copy_from_slice(encoded_coordinate);
            *coordinate = u64::from_le_bytes(canonical_coordinate);
        }
        match ProofChallengeExtensionElement::from_canonical_coordinates(coordinates) {
            Ok(value) => values.push(value),
            Err(error) => {
                values.zeroize();
                values.clear();
                return Err(ExternalPolynomialError::from(error).into());
            }
        }
    }
    if values.len() != element_count {
        values.zeroize();
        values.clear();
        return Err(ExternalPolynomialError::InvalidVector.into());
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::{
        PROOF_BASE_FIELD_MODULUS,
        external_memory::{
            ProofExternalMemoryObjectPlan, ProofExternalMemoryPlan, ProofExternalMemoryProtection,
            tests::TestStorage,
        },
    };

    fn prepared_external_polynomial(
        value_type: RelationColumnValueType,
        element_count: usize,
        encoded_values: &[u8],
        maximum_total_read_byte_length: u64,
    ) -> (
        ProofExternalMemoryExecutor,
        TestStorage,
        ExternalPolynomialVector,
    ) {
        let object = ProofExternalMemoryObject::new(0);
        let exact_byte_length =
            u64::try_from(encoded_values.len()).expect("the test polynomial byte length fits u64");
        let maximum_chunk_byte_length =
            u32::try_from(encoded_values.len()).expect("the test polynomial byte length fits u32");
        let plan = ProofExternalMemoryPlan::new(
            1,
            maximum_chunk_byte_length,
            exact_byte_length,
            1,
            exact_byte_length,
            exact_byte_length,
            maximum_total_read_byte_length,
            8,
            vec![ProofExternalMemoryObjectPlan::new(
                object,
                ProofExternalMemoryProtection::SecretAuthenticatedEncryption,
                exact_byte_length,
                0,
                0,
                0,
            )],
        )
        .expect("the test external-polynomial plan is valid");
        let mut executor = ProofExternalMemoryExecutor::new(plan);
        let mut storage = TestStorage::default();
        executor
            .begin_object(&mut storage, object)
            .expect("the test polynomial object begins");
        executor
            .append_object_bytes(&mut storage, object, encoded_values)
            .expect("the test polynomial bytes append");
        executor
            .seal_object(&mut storage, object)
            .expect("the test polynomial object seals");
        let vector = ExternalPolynomialVector::new(object, value_type, element_count)
            .expect("the test external-polynomial vector is valid");
        (executor, storage, vector)
    }

    fn encode_extension_values(values: &[[u64; PROOF_CHALLENGE_EXTENSION_DEGREE]]) -> Vec<u8> {
        values
            .iter()
            .flat_map(|coordinates| coordinates.iter())
            .flat_map(|coordinate| coordinate.to_le_bytes())
            .collect()
    }

    #[test]
    fn base_field_polynomial_reads_embed_values_in_the_extension_field() {
        let encoded_values = [3_u64, 5, PROOF_BASE_FIELD_MODULUS - 1]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect::<Vec<_>>();
        let (mut executor, mut storage, vector) = prepared_external_polynomial(
            RelationColumnValueType::BaseField,
            3,
            &encoded_values,
            16,
        );

        let values =
            read_external_polynomial_values_as_extension(&mut executor, &mut storage, vector, 1, 2)
                .expect("the base-field range embeds canonically");
        assert_eq!(values[0].canonical_coordinates(), [5, 0, 0, 0, 0]);
        assert_eq!(
            values[1].canonical_coordinates(),
            [PROOF_BASE_FIELD_MODULUS - 1, 0, 0, 0, 0]
        );
        executor
            .complete_step(&mut storage)
            .expect("the test polynomial lifecycle completes");
        assert_eq!(
            executor
                .finish()
                .expect("the test external-memory executor finishes")
                .total_read_byte_length(),
            16
        );
    }

    #[test]
    fn extension_field_polynomial_reads_preserve_every_coordinate() {
        let expected_values = [[1_u64, 2, 3, 4, 5], [8, 13, 21, 34, 55]];
        let encoded_values = encode_extension_values(&expected_values);
        let (mut executor, mut storage, vector) = prepared_external_polynomial(
            RelationColumnValueType::ChallengeExtension,
            expected_values.len(),
            &encoded_values,
            EXTENSION_FIELD_ELEMENT_BYTE_LENGTH as u64,
        );

        let values =
            read_external_polynomial_values_as_extension(&mut executor, &mut storage, vector, 1, 1)
                .expect("the extension-field range decodes canonically");
        assert_eq!(values[0].canonical_coordinates(), expected_values[1]);
        executor
            .complete_step(&mut storage)
            .expect("the test polynomial lifecycle completes");
        assert_eq!(
            executor
                .finish()
                .expect("the test external-memory executor finishes")
                .total_read_byte_length(),
            EXTENSION_FIELD_ELEMENT_BYTE_LENGTH as u64
        );
    }

    #[test]
    fn extension_field_polynomial_reads_reuse_the_caller_owned_decode_buffer() {
        let expected_values = [
            ProofChallengeExtensionElement::from_canonical_coordinates([3, 5, 7, 11, 13])
                .expect("canonical extension value"),
            ProofChallengeExtensionElement::from_canonical_coordinates([17, 19, 23, 29, 31])
                .expect("canonical extension value"),
            ProofChallengeExtensionElement::from_canonical_coordinates([37, 41, 43, 47, 53])
                .expect("canonical extension value"),
        ];
        let encoded_values =
            encode_extension_values(&expected_values.map(|value| value.canonical_coordinates()));
        let (mut executor, mut storage, vector) = prepared_external_polynomial(
            RelationColumnValueType::ChallengeExtension,
            expected_values.len(),
            &encoded_values,
            (2 * EXTENSION_FIELD_ELEMENT_BYTE_LENGTH) as u64,
        );
        let mut destination = Zeroizing::new(Vec::new());
        destination
            .try_reserve_exact(expected_values.len())
            .expect("bounded destination allocation");
        destination.push(ProofChallengeExtensionElement::ZERO);
        let allocation_pointer = destination.as_ptr();

        read_external_polynomial_values_as_extension_into(
            &mut executor,
            &mut storage,
            vector,
            1,
            2,
            &mut destination,
        )
        .expect("the range decodes into the retained allocation");

        assert_eq!(destination.as_ptr(), allocation_pointer);
        assert_eq!(destination.as_slice(), &expected_values[1..]);
        executor
            .complete_step(&mut storage)
            .expect("the test polynomial lifecycle completes");
        executor
            .finish()
            .expect("the test external-memory plan is fully consumed");
    }

    #[test]
    fn external_polynomial_reads_refuse_noncanonical_field_values() {
        let encoded_values = PROOF_BASE_FIELD_MODULUS.to_le_bytes();
        let (mut executor, mut storage, vector) = prepared_external_polynomial(
            RelationColumnValueType::BaseField,
            1,
            &encoded_values,
            BASE_FIELD_ELEMENT_BYTE_LENGTH as u64,
        );

        assert!(matches!(
            read_external_polynomial_values_as_extension(&mut executor, &mut storage, vector, 0, 1,),
            Err(ExternalPolynomialReadError::Polynomial(
                ExternalPolynomialError::Field(_)
            ))
        ));
    }

    #[test]
    fn failed_external_polynomial_decode_clears_the_caller_owned_buffer() {
        let encoded_values = PROOF_BASE_FIELD_MODULUS.to_le_bytes();
        let (mut executor, mut storage, vector) = prepared_external_polynomial(
            RelationColumnValueType::BaseField,
            1,
            &encoded_values,
            BASE_FIELD_ELEMENT_BYTE_LENGTH as u64,
        );
        let mut destination = Zeroizing::new(vec![ProofChallengeExtensionElement::ONE]);

        assert!(matches!(
            read_external_polynomial_values_as_extension_into(
                &mut executor,
                &mut storage,
                vector,
                0,
                1,
                &mut destination,
            ),
            Err(ExternalPolynomialReadError::Polynomial(
                ExternalPolynomialError::Field(_)
            ))
        ));
        assert!(destination.is_empty());
    }
}
