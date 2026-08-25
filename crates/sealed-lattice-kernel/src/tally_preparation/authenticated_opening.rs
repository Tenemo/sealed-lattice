use core::fmt;

use zeroize::Zeroize;

use crate::{
    encoding::{CanonicalReader, append_bytes, append_varuint},
    hashing::hash_framed_parts_512,
};

use super::{BinaryFieldElement256, TallyPreparationError};

pub(crate) const AUTHENTICATED_SHARE_COMMITMENT_BYTE_LENGTH: usize = 64;
pub(crate) const AUTHENTICATED_SHARE_SALT_BYTE_LENGTH: usize = 96;

pub(super) const AUTHENTICATED_SHARE_COMMITMENT_DOMAIN: &str =
    "sealed-lattice/garbled-tally/authenticated-share-commitment/v1";
pub(super) const AUTHENTICATED_SHARE_OPENING_MAGIC: &[u8] =
    b"sealed-lattice/authenticated-share-opening";
pub(super) const AUTHENTICATED_SHARE_VERIFICATION_KEY_MAGIC: &[u8] =
    b"sealed-lattice/authenticated-share-verification-key";
pub(super) const AUTHENTICATED_SHARE_ARTIFACT_VERSION: u64 = 1;

const SCALAR_VALUE_LIMB_COUNT: usize = 1;
const LABEL_BODY_VALUE_LIMB_COUNT: usize = 3;
const MAXIMUM_VALUE_LIMB_COUNT: usize = LABEL_BODY_VALUE_LIMB_COUNT;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuthenticatedShareCommitment([u8; AUTHENTICATED_SHARE_COMMITMENT_BYTE_LENGTH]);

impl AuthenticatedShareCommitment {
    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, TallyPreparationError> {
        let canonical_bytes = bytes.try_into().map_err(|_| {
            TallyPreparationError::AuthenticatedShareCommitmentByteLength {
                expected: AUTHENTICATED_SHARE_COMMITMENT_BYTE_LENGTH,
                actual: bytes.len(),
            }
        })?;
        Ok(Self(canonical_bytes))
    }

    pub(crate) const fn canonical_bytes(self) -> [u8; AUTHENTICATED_SHARE_COMMITMENT_BYTE_LENGTH] {
        self.0
    }
}

impl fmt::Debug for AuthenticatedShareCommitment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatedShareCommitment([digest])")
    }
}

#[derive(PartialEq, Eq)]
pub(crate) struct AuthenticatedShareVerificationKey {
    coefficients: [BinaryFieldElement256; MAXIMUM_VALUE_LIMB_COUNT],
    coefficient_count: usize,
    offset: BinaryFieldElement256,
}

impl AuthenticatedShareVerificationKey {
    pub(crate) fn scalar(
        coefficient: BinaryFieldElement256,
        offset: BinaryFieldElement256,
    ) -> Self {
        Self {
            coefficients: [
                coefficient,
                BinaryFieldElement256::ZERO,
                BinaryFieldElement256::ZERO,
            ],
            coefficient_count: SCALAR_VALUE_LIMB_COUNT,
            offset,
        }
    }

    pub(crate) fn label_body(
        coefficients: [BinaryFieldElement256; LABEL_BODY_VALUE_LIMB_COUNT],
        offset: BinaryFieldElement256,
    ) -> Self {
        Self {
            coefficients,
            coefficient_count: LABEL_BODY_VALUE_LIMB_COUNT,
            offset,
        }
    }

    pub(crate) fn coefficients(&self) -> &[BinaryFieldElement256] {
        &self.coefficients[..self.coefficient_count]
    }

    pub(crate) const fn offset(&self) -> BinaryFieldElement256 {
        self.offset
    }

    pub(crate) fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        append_bytes(&mut bytes, AUTHENTICATED_SHARE_VERIFICATION_KEY_MAGIC);
        append_varuint(&mut bytes, AUTHENTICATED_SHARE_ARTIFACT_VERSION);
        append_varuint(&mut bytes, self.coefficient_count as u64);
        for coefficient in self.coefficients() {
            append_bytes(&mut bytes, &coefficient.canonical_bytes());
        }
        append_bytes(&mut bytes, &self.offset.canonical_bytes());
        bytes
    }

    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, TallyPreparationError> {
        let mut reader = CanonicalReader::new(bytes);
        if reader.read_bytes()?.as_slice() != AUTHENTICATED_SHARE_VERIFICATION_KEY_MAGIC {
            return Err(TallyPreparationError::AuthenticatedShareVerificationKeyMagicMismatch);
        }
        let version = reader.read_varuint()?;
        if version != AUTHENTICATED_SHARE_ARTIFACT_VERSION {
            return Err(
                TallyPreparationError::UnsupportedAuthenticatedShareVerificationKeyVersion {
                    version,
                },
            );
        }
        let coefficient_count = read_supported_limb_count(&mut reader)?;
        let mut coefficients = [BinaryFieldElement256::ZERO; MAXIMUM_VALUE_LIMB_COUNT];
        for coefficient in &mut coefficients[..coefficient_count] {
            *coefficient = BinaryFieldElement256::from_canonical_bytes(&reader.read_bytes()?)?;
        }
        let offset = BinaryFieldElement256::from_canonical_bytes(&reader.read_bytes()?)?;
        if !reader.is_finished() {
            return Err(TallyPreparationError::TrailingAuthenticatedShareVerificationKeyBytes);
        }
        Ok(Self {
            coefficients,
            coefficient_count,
            offset,
        })
    }
}

impl fmt::Debug for AuthenticatedShareVerificationKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedShareVerificationKey")
            .field("coefficient_count", &self.coefficient_count)
            .field("coefficients", &"[redacted]")
            .field("offset", &"[redacted]")
            .finish()
    }
}

impl Drop for AuthenticatedShareVerificationKey {
    fn drop(&mut self) {
        self.coefficients.zeroize();
        self.coefficient_count.zeroize();
        self.offset.zeroize();
    }
}

#[derive(PartialEq, Eq)]
pub(crate) struct AuthenticatedShareOpening {
    values: [BinaryFieldElement256; MAXIMUM_VALUE_LIMB_COUNT],
    value_count: usize,
    tag: BinaryFieldElement256,
    salt: [u8; AUTHENTICATED_SHARE_SALT_BYTE_LENGTH],
}

impl AuthenticatedShareOpening {
    fn new(
        values: &[BinaryFieldElement256],
        tag: BinaryFieldElement256,
        salt: [u8; AUTHENTICATED_SHARE_SALT_BYTE_LENGTH],
    ) -> Result<Self, TallyPreparationError> {
        validate_supported_limb_count(values.len())?;
        let mut fixed_values = [BinaryFieldElement256::ZERO; MAXIMUM_VALUE_LIMB_COUNT];
        fixed_values[..values.len()].copy_from_slice(values);
        Ok(Self {
            values: fixed_values,
            value_count: values.len(),
            tag,
            salt,
        })
    }

    pub(crate) fn values(&self) -> &[BinaryFieldElement256] {
        &self.values[..self.value_count]
    }

    pub(crate) const fn tag(&self) -> BinaryFieldElement256 {
        self.tag
    }

    pub(crate) const fn salt(&self) -> &[u8; AUTHENTICATED_SHARE_SALT_BYTE_LENGTH] {
        &self.salt
    }

    pub(crate) fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        append_bytes(&mut bytes, AUTHENTICATED_SHARE_OPENING_MAGIC);
        append_varuint(&mut bytes, AUTHENTICATED_SHARE_ARTIFACT_VERSION);
        append_varuint(&mut bytes, self.value_count as u64);
        for value in self.values() {
            append_bytes(&mut bytes, &value.canonical_bytes());
        }
        append_bytes(&mut bytes, &self.tag.canonical_bytes());
        append_bytes(&mut bytes, &self.salt);
        bytes
    }

    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, TallyPreparationError> {
        let mut reader = CanonicalReader::new(bytes);
        if reader.read_bytes()?.as_slice() != AUTHENTICATED_SHARE_OPENING_MAGIC {
            return Err(TallyPreparationError::AuthenticatedShareOpeningMagicMismatch);
        }
        let version = reader.read_varuint()?;
        if version != AUTHENTICATED_SHARE_ARTIFACT_VERSION {
            return Err(
                TallyPreparationError::UnsupportedAuthenticatedShareOpeningVersion { version },
            );
        }
        let value_count = read_supported_limb_count(&mut reader)?;
        let mut values = [BinaryFieldElement256::ZERO; MAXIMUM_VALUE_LIMB_COUNT];
        for value in &mut values[..value_count] {
            *value = BinaryFieldElement256::from_canonical_bytes(&reader.read_bytes()?)?;
        }
        let tag = BinaryFieldElement256::from_canonical_bytes(&reader.read_bytes()?)?;
        let salt_bytes = reader.read_bytes()?;
        let salt = salt_bytes.as_slice().try_into().map_err(|_| {
            TallyPreparationError::AuthenticatedShareSaltByteLength {
                expected: AUTHENTICATED_SHARE_SALT_BYTE_LENGTH,
                actual: salt_bytes.len(),
            }
        })?;
        if !reader.is_finished() {
            return Err(TallyPreparationError::TrailingAuthenticatedShareOpeningBytes);
        }
        Ok(Self {
            values,
            value_count,
            tag,
            salt,
        })
    }
}

impl fmt::Debug for AuthenticatedShareOpening {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedShareOpening")
            .field("value_count", &self.value_count)
            .field("values", &"[redacted]")
            .field("tag", &"[redacted]")
            .field("salt", &"[redacted]")
            .finish()
    }
}

impl Drop for AuthenticatedShareOpening {
    fn drop(&mut self) {
        self.values.zeroize();
        self.value_count.zeroize();
        self.tag.zeroize();
        self.salt.zeroize();
    }
}

pub(crate) fn create_authenticated_share_opening(
    context_bytes: &[u8],
    coordinate_bytes: &[u8],
    values: &[BinaryFieldElement256],
    verification_key: &AuthenticatedShareVerificationKey,
    salt: [u8; AUTHENTICATED_SHARE_SALT_BYTE_LENGTH],
) -> Result<(AuthenticatedShareCommitment, AuthenticatedShareOpening), TallyPreparationError> {
    validate_context_and_coordinate(context_bytes, coordinate_bytes)?;
    let tag = compute_authenticated_share_tag(verification_key, values)?;
    let opening = AuthenticatedShareOpening::new(values, tag, salt)?;
    let commitment = commit_authenticated_share_opening(context_bytes, coordinate_bytes, &opening)?;
    Ok((commitment, opening))
}

pub(crate) fn commit_authenticated_share_opening(
    context_bytes: &[u8],
    coordinate_bytes: &[u8],
    opening: &AuthenticatedShareOpening,
) -> Result<AuthenticatedShareCommitment, TallyPreparationError> {
    validate_context_and_coordinate(context_bytes, coordinate_bytes)?;
    let opening_bytes = opening.canonical_bytes();
    Ok(AuthenticatedShareCommitment(hash_framed_parts_512(
        AUTHENTICATED_SHARE_COMMITMENT_DOMAIN,
        &[context_bytes, coordinate_bytes, &opening_bytes],
    )))
}

pub(crate) fn verify_authenticated_share_opening(
    context_bytes: &[u8],
    coordinate_bytes: &[u8],
    expected_commitment: AuthenticatedShareCommitment,
    verification_key: &AuthenticatedShareVerificationKey,
    opening: &AuthenticatedShareOpening,
) -> Result<(), TallyPreparationError> {
    let actual_commitment =
        commit_authenticated_share_opening(context_bytes, coordinate_bytes, opening)?;
    if actual_commitment != expected_commitment {
        return Err(TallyPreparationError::AuthenticatedShareCommitmentMismatch);
    }
    let expected_tag = compute_authenticated_share_tag(verification_key, opening.values())?;
    if expected_tag != opening.tag {
        return Err(TallyPreparationError::AuthenticatedShareTagMismatch);
    }
    Ok(())
}

pub(super) fn compute_authenticated_share_tag(
    verification_key: &AuthenticatedShareVerificationKey,
    values: &[BinaryFieldElement256],
) -> Result<BinaryFieldElement256, TallyPreparationError> {
    validate_supported_limb_count(values.len())?;
    if verification_key.coefficients().len() != values.len() {
        return Err(
            TallyPreparationError::AuthenticatedShareVerificationKeyLimbCountMismatch {
                expected: values.len(),
                actual: verification_key.coefficients().len(),
            },
        );
    }
    Ok(verification_key
        .coefficients()
        .iter()
        .copied()
        .zip(values.iter().copied())
        .fold(verification_key.offset(), |tag, (coefficient, value)| {
            tag.add(coefficient.multiply(value))
        }))
}

fn validate_context_and_coordinate(
    context_bytes: &[u8],
    coordinate_bytes: &[u8],
) -> Result<(), TallyPreparationError> {
    if context_bytes.is_empty() {
        return Err(TallyPreparationError::AuthenticatedShareContextEmpty);
    }
    if coordinate_bytes.is_empty() {
        return Err(TallyPreparationError::AuthenticatedShareCoordinateEmpty);
    }
    Ok(())
}

fn validate_supported_limb_count(limb_count: usize) -> Result<(), TallyPreparationError> {
    if limb_count != SCALAR_VALUE_LIMB_COUNT && limb_count != LABEL_BODY_VALUE_LIMB_COUNT {
        return Err(TallyPreparationError::AuthenticatedShareValueLimbCount { actual: limb_count });
    }
    Ok(())
}

fn read_supported_limb_count(
    reader: &mut CanonicalReader<'_>,
) -> Result<usize, TallyPreparationError> {
    let limb_count = usize::try_from(reader.read_varuint()?)
        .map_err(|_| TallyPreparationError::IntegerConversion)?;
    validate_supported_limb_count(limb_count)?;
    Ok(limb_count)
}

#[cfg(test)]
pub(super) fn authenticated_share_opening_with_tag_for_test(
    values: &[BinaryFieldElement256],
    tag: BinaryFieldElement256,
    salt: [u8; AUTHENTICATED_SHARE_SALT_BYTE_LENGTH],
) -> Result<AuthenticatedShareOpening, TallyPreparationError> {
    AuthenticatedShareOpening::new(values, tag, salt)
}
