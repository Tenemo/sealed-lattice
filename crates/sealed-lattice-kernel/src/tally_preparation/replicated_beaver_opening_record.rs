#[cfg(test)]
use fips204::{
    ml_dsa_65,
    traits::{SerDes, Verifier},
};

use crate::{
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalReader, append_bytes, append_varuint},
    foundation::Hash512,
    hashing::hash_framed_parts_512,
};

#[cfg(test)]
use crate::foundation::{ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH, Roster};

use super::{
    BinaryFieldElement256, TallyPreparationError,
    output_sharing::canonical_evaluation_point,
    replicated_beaver_opening::{TripleReductionOpeningCoordinate, TripleReductionOpeningError},
};

#[cfg(test)]
use super::{
    TallyPreparationContext,
    replicated_beaver_opening::{
        TripleReductionOpeningCollector, TripleReductionOpeningProgress,
        TripleReductionOpeningSubmission,
    },
};

const TRIPLE_REDUCTION_OPENING_BODY_MAGIC: &[u8] = b"sealed-lattice/triple-reduction-opening-body";
const SIGNED_TRIPLE_REDUCTION_OPENING_MAGIC: &[u8] =
    b"sealed-lattice/signed-triple-reduction-opening";
const TRIPLE_REDUCTION_OPENING_RECORD_VERSION: u64 = 1;
pub(crate) const ML_DSA_65_SIGNATURE_BYTE_LENGTH: usize = 3_309;
const SIGNED_TRIPLE_REDUCTION_OPENING_IDENTITY_DOMAIN: &str =
    "sealed-lattice/signed-triple-reduction-opening-identity/v1";
pub(crate) const TRIPLE_REDUCTION_OPENING_SIGNATURE_CONTEXT: &[u8] =
    b"sealed-lattice/triple-reduction-opening/v1";

const HASH_BYTE_LENGTH: usize = Hash512::BYTE_LENGTH;
const FIELD_BYTE_LENGTH: usize = BinaryFieldElement256::CANONICAL_BYTE_LENGTH;
const MAXIMUM_U16_VARUINT_BYTE_LENGTH: usize = 3;
const MAXIMUM_TRIPLE_REDUCTION_OPENING_BODY_BYTE_LENGTH: usize =
    framed_byte_length(TRIPLE_REDUCTION_OPENING_BODY_MAGIC.len())
        + 1
        + framed_byte_length(HASH_BYTE_LENGTH)
        + MAXIMUM_U16_VARUINT_BYTE_LENGTH
        + MAXIMUM_U16_VARUINT_BYTE_LENGTH
        + framed_byte_length(FIELD_BYTE_LENGTH)
        + framed_byte_length(FIELD_BYTE_LENGTH);
const MAXIMUM_SIGNED_TRIPLE_REDUCTION_OPENING_BYTE_LENGTH: usize =
    framed_byte_length(SIGNED_TRIPLE_REDUCTION_OPENING_MAGIC.len())
        + 1
        + framed_byte_length(MAXIMUM_TRIPLE_REDUCTION_OPENING_BODY_BYTE_LENGTH)
        + framed_byte_length(ML_DSA_65_SIGNATURE_BYTE_LENGTH);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SignedTripleReductionOpeningError {
    Canonical(CanonicalError),
    Preparation(TallyPreparationError),
    Opening(TripleReductionOpeningError),
    RecordTooLong {
        maximum: usize,
        actual: usize,
    },
    BodyMagicMismatch,
    SignedRecordMagicMismatch,
    UnsupportedVersion {
        version: u64,
    },
    BodyNotCanonical,
    SignedRecordNotCanonical,
    SignatureByteLength {
        expected: usize,
        actual: usize,
    },
    ContextMismatch,
    RosterMismatch,
    SenderPositionOutOfRange {
        roster_position: u16,
        participant_count: u16,
    },
    MalformedSigningVerificationKey,
    InvalidSignature,
}

impl From<CanonicalError> for SignedTripleReductionOpeningError {
    fn from(error: CanonicalError) -> Self {
        Self::Canonical(error)
    }
}

impl From<TallyPreparationError> for SignedTripleReductionOpeningError {
    fn from(error: TallyPreparationError) -> Self {
        Self::Preparation(error)
    }
}

impl From<TripleReductionOpeningError> for SignedTripleReductionOpeningError {
    fn from(error: TripleReductionOpeningError) -> Self {
        Self::Opening(error)
    }
}

/// Canonical unsigned sender body for one degree-double opening value.
///
/// `from_untrusted_fields` exists for parsing and hostile proof-model cases; a
/// body becomes an authenticated sender slot only after the signed collector
/// verifies its detached ML-DSA-65 signature against the context roster.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TripleReductionOpeningRecordBody {
    coordinate_identity: Hash512,
    participant_count: u16,
    roster_position: u16,
    evaluation_point: BinaryFieldElement256,
    value: BinaryFieldElement256,
}

impl TripleReductionOpeningRecordBody {
    pub(crate) fn new(
        coordinate: TripleReductionOpeningCoordinate,
        roster_position: u16,
        value: BinaryFieldElement256,
    ) -> Result<Self, SignedTripleReductionOpeningError> {
        Ok(Self {
            coordinate_identity: coordinate.identity(),
            participant_count: coordinate.participant_count(),
            roster_position,
            evaluation_point: canonical_evaluation_point(
                coordinate.participant_count(),
                roster_position,
            )?,
            value,
        })
    }

    pub(crate) const fn from_untrusted_fields(
        coordinate_identity: Hash512,
        participant_count: u16,
        roster_position: u16,
        evaluation_point: BinaryFieldElement256,
        value: BinaryFieldElement256,
    ) -> Self {
        Self {
            coordinate_identity,
            participant_count,
            roster_position,
            evaluation_point,
            value,
        }
    }

    pub(crate) const fn coordinate_identity(self) -> Hash512 {
        self.coordinate_identity
    }

    pub(crate) const fn participant_count(self) -> u16 {
        self.participant_count
    }

    pub(crate) const fn roster_position(self) -> u16 {
        self.roster_position
    }

    pub(crate) const fn evaluation_point(self) -> BinaryFieldElement256 {
        self.evaluation_point
    }

    pub(crate) const fn value(self) -> BinaryFieldElement256 {
        self.value
    }

    pub(crate) fn canonical_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(MAXIMUM_TRIPLE_REDUCTION_OPENING_BODY_BYTE_LENGTH);
        append_bytes(&mut bytes, TRIPLE_REDUCTION_OPENING_BODY_MAGIC);
        append_varuint(&mut bytes, TRIPLE_REDUCTION_OPENING_RECORD_VERSION);
        append_bytes(&mut bytes, self.coordinate_identity.as_bytes());
        append_varuint(&mut bytes, u64::from(self.participant_count));
        append_varuint(&mut bytes, u64::from(self.roster_position));
        append_bytes(&mut bytes, &self.evaluation_point.canonical_bytes());
        append_bytes(&mut bytes, &self.value.canonical_bytes());
        bytes
    }

    pub(crate) fn from_canonical_bytes(
        bytes: &[u8],
    ) -> Result<Self, SignedTripleReductionOpeningError> {
        if bytes.len() > MAXIMUM_TRIPLE_REDUCTION_OPENING_BODY_BYTE_LENGTH {
            return Err(SignedTripleReductionOpeningError::RecordTooLong {
                maximum: MAXIMUM_TRIPLE_REDUCTION_OPENING_BODY_BYTE_LENGTH,
                actual: bytes.len(),
            });
        }
        let mut reader = CanonicalReader::new(bytes);
        if reader.read_bytes()?.as_slice() != TRIPLE_REDUCTION_OPENING_BODY_MAGIC {
            return Err(SignedTripleReductionOpeningError::BodyMagicMismatch);
        }
        let version = reader.read_varuint()?;
        if version != TRIPLE_REDUCTION_OPENING_RECORD_VERSION {
            return Err(SignedTripleReductionOpeningError::UnsupportedVersion { version });
        }
        let coordinate_identity = Hash512::from_bytes(read_fixed_bytes::<HASH_BYTE_LENGTH>(
            &mut reader,
            "triple-reduction coordinate identity",
        )?);
        let participant_count = read_u16(&mut reader, "participant count")?;
        let roster_position = read_u16(&mut reader, "roster position")?;
        let evaluation_point =
            BinaryFieldElement256::from_canonical_bytes(&read_fixed_bytes::<FIELD_BYTE_LENGTH>(
                &mut reader,
                "evaluation point",
            )?)?;
        let value = BinaryFieldElement256::from_canonical_bytes(&read_fixed_bytes::<
            FIELD_BYTE_LENGTH,
        >(
            &mut reader, "opening value"
        )?)?;
        if !reader.is_finished() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::TrailingBytes,
                "triple-reduction opening body has trailing bytes",
            )
            .into());
        }
        let body = Self {
            coordinate_identity,
            participant_count,
            roster_position,
            evaluation_point,
            value,
        };
        if body.canonical_bytes() != bytes {
            return Err(SignedTripleReductionOpeningError::BodyNotCanonical);
        }
        Ok(body)
    }
}

/// Canonical body and raw ML-DSA-65 signature bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SignedTripleReductionOpeningRecord {
    body: TripleReductionOpeningRecordBody,
    signature: [u8; ML_DSA_65_SIGNATURE_BYTE_LENGTH],
}

impl SignedTripleReductionOpeningRecord {
    pub(crate) const fn new(
        body: TripleReductionOpeningRecordBody,
        signature: [u8; ML_DSA_65_SIGNATURE_BYTE_LENGTH],
    ) -> Self {
        Self { body, signature }
    }

    pub(crate) const fn body(&self) -> TripleReductionOpeningRecordBody {
        self.body
    }

    pub(crate) fn canonical_bytes(&self) -> Vec<u8> {
        let body_bytes = self.body.canonical_bytes();
        let mut bytes = Vec::with_capacity(MAXIMUM_SIGNED_TRIPLE_REDUCTION_OPENING_BYTE_LENGTH);
        append_bytes(&mut bytes, SIGNED_TRIPLE_REDUCTION_OPENING_MAGIC);
        append_varuint(&mut bytes, TRIPLE_REDUCTION_OPENING_RECORD_VERSION);
        append_bytes(&mut bytes, &body_bytes);
        append_bytes(&mut bytes, &self.signature);
        bytes
    }

    pub(crate) fn from_canonical_bytes(
        bytes: &[u8],
    ) -> Result<Self, SignedTripleReductionOpeningError> {
        if bytes.len() > MAXIMUM_SIGNED_TRIPLE_REDUCTION_OPENING_BYTE_LENGTH {
            return Err(SignedTripleReductionOpeningError::RecordTooLong {
                maximum: MAXIMUM_SIGNED_TRIPLE_REDUCTION_OPENING_BYTE_LENGTH,
                actual: bytes.len(),
            });
        }
        let mut reader = CanonicalReader::new(bytes);
        if reader.read_bytes()?.as_slice() != SIGNED_TRIPLE_REDUCTION_OPENING_MAGIC {
            return Err(SignedTripleReductionOpeningError::SignedRecordMagicMismatch);
        }
        let version = reader.read_varuint()?;
        if version != TRIPLE_REDUCTION_OPENING_RECORD_VERSION {
            return Err(SignedTripleReductionOpeningError::UnsupportedVersion { version });
        }
        let body = TripleReductionOpeningRecordBody::from_canonical_bytes(&reader.read_bytes()?)?;
        let signature_bytes = reader.read_bytes()?;
        let signature = <[u8; ML_DSA_65_SIGNATURE_BYTE_LENGTH]>::try_from(
            signature_bytes.as_slice(),
        )
        .map_err(|_| SignedTripleReductionOpeningError::SignatureByteLength {
            expected: ML_DSA_65_SIGNATURE_BYTE_LENGTH,
            actual: signature_bytes.len(),
        })?;
        if !reader.is_finished() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::TrailingBytes,
                "signed triple-reduction opening has trailing bytes",
            )
            .into());
        }
        let record = Self { body, signature };
        if record.canonical_bytes() != bytes {
            return Err(SignedTripleReductionOpeningError::SignedRecordNotCanonical);
        }
        Ok(record)
    }

    fn identity(&self) -> Hash512 {
        Hash512::from_bytes(hash_framed_parts_512(
            SIGNED_TRIPLE_REDUCTION_OPENING_IDENTITY_DOMAIN,
            &[&self.canonical_bytes()],
        ))
    }
}

/// Signature-verifying front end for the algebraic all-roster collector.
///
/// Structural and signature failures are refused before a sender slot exists.
/// Once a record has a valid roster signature, coordinate, point, count, and
/// equivocation failures flow into the accepted-or-burn algebra state. The
/// resulting algebra record is still not a preparation capsule or workflow
/// capability.
#[cfg(test)]
pub(crate) struct SignedTripleReductionOpeningCollector {
    participant_count: u16,
    signing_verification_keys: Box<[[u8; ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH]]>,
    algebraic_collector: TripleReductionOpeningCollector,
}

#[cfg(test)]
impl SignedTripleReductionOpeningCollector {
    pub(crate) fn new(
        context: TallyPreparationContext,
        coordinate: TripleReductionOpeningCoordinate,
        roster: &Roster,
    ) -> Result<Self, SignedTripleReductionOpeningError> {
        if coordinate.context_identity() != context.identity()
            || coordinate.participant_count() != context.participant_count()
        {
            return Err(SignedTripleReductionOpeningError::ContextMismatch);
        }
        roster
            .validate()
            .map_err(|_| SignedTripleReductionOpeningError::RosterMismatch)?;
        if roster
            .roster_hash()
            .map_err(|_| SignedTripleReductionOpeningError::RosterMismatch)?
            != context.roster_hash()
            || roster.entries.len() != usize::from(context.participant_count())
        {
            return Err(SignedTripleReductionOpeningError::RosterMismatch);
        }
        for entry in &roster.entries {
            ml_dsa_65::PublicKey::try_from_bytes(entry.signing_verification_key)
                .map_err(|_| SignedTripleReductionOpeningError::MalformedSigningVerificationKey)?;
        }
        let signing_verification_keys = roster
            .entries
            .iter()
            .map(|entry| entry.signing_verification_key)
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Ok(Self {
            participant_count: context.participant_count(),
            signing_verification_keys,
            algebraic_collector: TripleReductionOpeningCollector::new(coordinate)?,
        })
    }

    pub(crate) fn absorb_canonical_record(
        &mut self,
        bytes: &[u8],
    ) -> Result<TripleReductionOpeningProgress, SignedTripleReductionOpeningError> {
        let record = SignedTripleReductionOpeningRecord::from_canonical_bytes(bytes)?;
        let body = record.body();
        let signing_verification_key = self
            .signing_verification_keys
            .get(usize::from(body.roster_position()))
            .ok_or(
                SignedTripleReductionOpeningError::SenderPositionOutOfRange {
                    roster_position: body.roster_position(),
                    participant_count: self.participant_count,
                },
            )?;
        let public_key = ml_dsa_65::PublicKey::try_from_bytes(*signing_verification_key)
            .map_err(|_| SignedTripleReductionOpeningError::MalformedSigningVerificationKey)?;
        if !public_key.verify(
            &body.canonical_bytes(),
            &record.signature,
            TRIPLE_REDUCTION_OPENING_SIGNATURE_CONTEXT,
        ) {
            return Err(SignedTripleReductionOpeningError::InvalidSignature);
        }
        let submission = TripleReductionOpeningSubmission::from_verified_fields(
            record.identity(),
            body.coordinate_identity(),
            body.participant_count(),
            body.roster_position(),
            body.evaluation_point(),
            body.value(),
        );
        Ok(self.algebraic_collector.absorb(submission)?)
    }
}

const fn framed_byte_length(payload_byte_length: usize) -> usize {
    varuint_byte_length(payload_byte_length) + payload_byte_length
}

const fn varuint_byte_length(mut value: usize) -> usize {
    let mut byte_length = 1;
    while value >= 0x80 {
        value >>= 7;
        byte_length += 1;
    }
    byte_length
}

fn read_fixed_bytes<const BYTE_LENGTH: usize>(
    reader: &mut CanonicalReader<'_>,
    field_name: &'static str,
) -> Result<[u8; BYTE_LENGTH], SignedTripleReductionOpeningError> {
    let bytes = reader.read_bytes()?;
    <[u8; BYTE_LENGTH]>::try_from(bytes.as_slice()).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{field_name} has the wrong byte length"),
        )
        .into()
    })
}

fn read_u16(
    reader: &mut CanonicalReader<'_>,
    field_name: &'static str,
) -> Result<u16, SignedTripleReductionOpeningError> {
    u16::try_from(reader.read_varuint()?).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{field_name} does not fit u16"),
        )
        .into()
    })
}
