use subtle::ConstantTimeEq;

use crate::{foundation::Hash512, tally_circuit::CompiledTallyCircuit};

use super::{
    BinaryFieldElement256, TallyPreparationContext, TallyPreparationError,
    authenticated_key_release::AuthenticatedKeyFieldCodewordChecker,
    authenticated_key_share_vector::{
        AuthenticatedKeyShareVectorDescriptor, AuthenticatedKeyShareVectorPayloadChunk,
    },
    authenticated_key_share_vector_codeword_manifest::AuthenticatedKeyShareVectorCodewordManifest,
    output_sharing::DEGREE_THREE_RECONSTRUCTION_THRESHOLD,
};

pub(crate) const MAXIMUM_CODEWORD_CHECK_SIMULTANEOUS_PAYLOAD_CHUNK_COUNT: u64 = 1;
pub(crate) const MAXIMUM_CODEWORD_CHECK_RETAINED_BASIS_FIELD_CHUNK_COUNT: u64 = 4;
pub(crate) const MAXIMUM_CODEWORD_CHECK_OUTPUT_FIELD_CHUNK_COUNT: u64 = 1;
pub(crate) const MAXIMUM_CODEWORD_CHECK_PAYLOAD_AND_FIELD_BUFFER_COUNT: u64 = 5;

/// Chunk-major direct verifier for every public point in each authenticated
/// key-share polynomial.
///
/// The verifier checks one exact all-roster, degree-three codeword and emits
/// its reconstructed constant term only after all nonbasis points pass. It
/// retains four decoded public basis chunks and borrows one transport payload
/// at a time. The check proves no malicious-preparation provenance, signature,
/// predecessor state, or one-shot release condition and cannot mint a
/// workflow capability.
pub(crate) struct AuthenticatedKeyShareVectorCodewordCheck {
    participant_count: u16,
    descriptors: Box<[AuthenticatedKeyShareVectorDescriptor]>,
    field_checker: AuthenticatedKeyFieldCodewordChecker,
    chunk_count: u64,
    next_chunk_index: u64,
    total_field_count: u64,
    checked_field_count: u64,
    next_sender_position: u16,
    basis_fields: [Option<Box<[BinaryFieldElement256]>>; DEGREE_THREE_RECONSTRUCTION_THRESHOLD],
    failed: bool,
}

impl AuthenticatedKeyShareVectorCodewordCheck {
    pub(crate) fn begin(
        context: TallyPreparationContext,
        circuit: &CompiledTallyCircuit,
        holder_commitment_root: Hash512,
        manifest: &AuthenticatedKeyShareVectorCodewordManifest,
        descriptors: &[AuthenticatedKeyShareVectorDescriptor],
    ) -> Result<Self, TallyPreparationError> {
        manifest.verify_source_and_descriptors(
            context,
            circuit,
            holder_commitment_root,
            descriptors,
        )?;
        let field_checker = AuthenticatedKeyFieldCodewordChecker::new(context.participant_count())?;
        if usize::from(manifest.reconstruction_threshold()) != DEGREE_THREE_RECONSTRUCTION_THRESHOLD
            || descriptors.len() != usize::from(context.participant_count())
        {
            return Err(TallyPreparationError::AuthenticatedKeyShareVectorCodewordManifestMismatch);
        }
        let first_descriptor = descriptors.first().ok_or(
            TallyPreparationError::AuthenticatedKeyShareVectorCodewordManifestDescriptorCountMismatch {
                expected: usize::from(context.participant_count()),
                actual: descriptors.len(),
            },
        )?;
        let chunk_count = first_descriptor.chunk_count();
        if descriptors.iter().any(|descriptor| {
            descriptor.chunk_count() != chunk_count
                || descriptor.total_field_count() != manifest.total_field_count()
        }) {
            return Err(TallyPreparationError::AuthenticatedKeyShareVectorGeometryMismatch);
        }

        Ok(Self {
            participant_count: field_checker.participant_count(),
            descriptors: descriptors.to_vec().into_boxed_slice(),
            field_checker,
            chunk_count,
            next_chunk_index: 0,
            total_field_count: manifest.total_field_count(),
            checked_field_count: 0,
            next_sender_position: 0,
            basis_fields: core::array::from_fn(|_basis_position| None),
            failed: false,
        })
    }

    /// Absorbs the next roster-ordered payload for the current chunk.
    ///
    /// Callers must supply all roster positions for one chunk before moving to
    /// the next chunk. The input slice is borrowed only for this call.
    pub(crate) fn absorb_next_payload_chunk(
        &mut self,
        payload: &[u8],
    ) -> Result<(), TallyPreparationError> {
        self.require_live_incomplete_check()?;
        if self.next_sender_position == self.participant_count {
            return Err(
                TallyPreparationError::AuthenticatedKeyShareVectorCodewordChunkAwaitingFinalization,
            );
        }
        let sender_position = self.next_sender_position;
        let descriptor = &self.descriptors[usize::from(sender_position)];
        let payload_chunk = descriptor.verify_payload_chunk(self.next_chunk_index, payload)?;
        self.validate_current_chunk_geometry(&payload_chunk)?;

        if usize::from(sender_position) < DEGREE_THREE_RECONSTRUCTION_THRESHOLD {
            self.absorb_basis_chunk(sender_position, &payload_chunk)?;
        } else if let Err(error) = self.verify_nonbasis_chunk(sender_position, &payload_chunk) {
            self.failed = true;
            return Err(error);
        }
        self.next_sender_position = self
            .next_sender_position
            .checked_add(1)
            .ok_or(TallyPreparationError::ArithmeticOverflow)?;
        Ok(())
    }

    /// Reconstructs the current constant-term chunk after every roster point
    /// has passed.
    ///
    /// Keeping finalization separate from payload absorption ensures that the
    /// output allocation never overlaps a borrowed transport payload.
    pub(crate) fn finalize_current_chunk(
        &mut self,
    ) -> Result<PubliclyCheckedAuthenticatedKeyFieldChunk, TallyPreparationError> {
        self.require_live_incomplete_check()?;
        if self.next_sender_position != self.participant_count {
            return Err(
                TallyPreparationError::AuthenticatedKeyShareVectorCodewordChunkIncomplete {
                    expected_sender_count: self.participant_count,
                    absorbed_sender_count: self.next_sender_position,
                },
            );
        }
        let field_count = self.current_basis_field_count()?;
        let coefficients = self.field_checker.constant_term_coefficients();
        let mut reconstructed_fields = Vec::with_capacity(field_count);
        for position_within_chunk in 0..field_count {
            reconstructed_fields
                .push(self.interpolate_basis_field(position_within_chunk, coefficients)?);
        }
        let first_field_index = self.checked_field_count;
        self.checked_field_count = self
            .checked_field_count
            .checked_add(
                u64::try_from(field_count).map_err(|_| TallyPreparationError::IntegerConversion)?,
            )
            .ok_or(TallyPreparationError::ArithmeticOverflow)?;
        self.next_chunk_index = self
            .next_chunk_index
            .checked_add(1)
            .ok_or(TallyPreparationError::ArithmeticOverflow)?;
        self.next_sender_position = 0;
        for basis_fields in &mut self.basis_fields {
            *basis_fields = None;
        }
        Ok(PubliclyCheckedAuthenticatedKeyFieldChunk {
            first_field_index,
            reconstructed_fields: reconstructed_fields.into_boxed_slice(),
        })
    }

    pub(crate) fn finish(self) -> Result<(), TallyPreparationError> {
        if self.next_chunk_index != self.chunk_count
            || self.checked_field_count != self.total_field_count
            || self.next_sender_position != 0
            || self.basis_fields.iter().any(Option::is_some)
            || self.failed
        {
            return Err(
                TallyPreparationError::AuthenticatedKeyShareVectorCodewordCheckIncomplete {
                    expected_chunk_count: self.chunk_count,
                    checked_chunk_count: self.next_chunk_index,
                    expected_field_count: self.total_field_count,
                    checked_field_count: self.checked_field_count,
                    absorbed_sender_count: self.next_sender_position,
                },
            );
        }
        Ok(())
    }

    fn require_live_incomplete_check(&self) -> Result<(), TallyPreparationError> {
        if self.failed {
            return Err(TallyPreparationError::AuthenticatedKeyShareVectorCodewordCheckFailed);
        }
        if self.next_chunk_index >= self.chunk_count {
            return Err(
                TallyPreparationError::AuthenticatedKeyShareVectorCodewordCheckAlreadyComplete,
            );
        }
        Ok(())
    }

    fn validate_current_chunk_geometry(
        &self,
        payload_chunk: &AuthenticatedKeyShareVectorPayloadChunk<'_>,
    ) -> Result<(), TallyPreparationError> {
        if payload_chunk.first_field_index() != self.checked_field_count {
            return Err(TallyPreparationError::AuthenticatedKeyShareVectorGeometryMismatch);
        }
        if let Some(expected_field_count) = self
            .basis_fields
            .iter()
            .find_map(|basis_fields| basis_fields.as_ref().map(|fields| fields.len()))
            && expected_field_count
                != usize::try_from(payload_chunk.field_count())
                    .map_err(|_| TallyPreparationError::IntegerConversion)?
        {
            return Err(TallyPreparationError::AuthenticatedKeyShareVectorGeometryMismatch);
        }
        Ok(())
    }

    fn absorb_basis_chunk(
        &mut self,
        sender_position: u16,
        payload_chunk: &AuthenticatedKeyShareVectorPayloadChunk<'_>,
    ) -> Result<(), TallyPreparationError> {
        let basis_position = usize::from(sender_position);
        if self.basis_fields[basis_position].is_some() {
            return Err(TallyPreparationError::AuthenticatedKeyShareVectorGeometryMismatch);
        }
        let field_count = usize::try_from(payload_chunk.field_count())
            .map_err(|_| TallyPreparationError::IntegerConversion)?;
        let mut decoded_fields = Vec::with_capacity(field_count);
        for position_within_chunk in 0..field_count {
            decoded_fields.push(
                payload_chunk.field_value(
                    u64::try_from(position_within_chunk)
                        .map_err(|_| TallyPreparationError::IntegerConversion)?,
                )?,
            );
        }
        self.basis_fields[basis_position] = Some(decoded_fields.into_boxed_slice());
        Ok(())
    }

    fn verify_nonbasis_chunk(
        &self,
        sender_position: u16,
        payload_chunk: &AuthenticatedKeyShareVectorPayloadChunk<'_>,
    ) -> Result<(), TallyPreparationError> {
        let field_count = self.current_basis_field_count()?;
        if field_count
            != usize::try_from(payload_chunk.field_count())
                .map_err(|_| TallyPreparationError::IntegerConversion)?
        {
            return Err(TallyPreparationError::AuthenticatedKeyShareVectorGeometryMismatch);
        }
        let coefficients = self
            .field_checker
            .nonbasis_point_coefficients(sender_position)?;
        for position_within_chunk in 0..field_count {
            let expected_value =
                self.interpolate_basis_field(position_within_chunk, coefficients)?;
            let actual_value = payload_chunk.field_value(
                u64::try_from(position_within_chunk)
                    .map_err(|_| TallyPreparationError::IntegerConversion)?,
            )?;
            if expected_value.ct_eq(&actual_value).unwrap_u8() != 1 {
                return Err(TallyPreparationError::InconsistentShare {
                    roster_position: sender_position,
                });
            }
        }
        Ok(())
    }

    fn current_basis_field_count(&self) -> Result<usize, TallyPreparationError> {
        let field_count = self
            .basis_fields
            .first()
            .and_then(Option::as_ref)
            .map(|fields| fields.len())
            .ok_or(TallyPreparationError::AuthenticatedKeyShareVectorGeometryMismatch)?;
        if self.basis_fields.iter().any(|basis_fields| {
            basis_fields.as_ref().map(|fields| fields.len()) != Some(field_count)
        }) {
            return Err(TallyPreparationError::AuthenticatedKeyShareVectorGeometryMismatch);
        }
        Ok(field_count)
    }

    fn interpolate_basis_field(
        &self,
        position_within_chunk: usize,
        coefficients: [BinaryFieldElement256; DEGREE_THREE_RECONSTRUCTION_THRESHOLD],
    ) -> Result<BinaryFieldElement256, TallyPreparationError> {
        self.basis_fields.iter().zip(coefficients).try_fold(
            BinaryFieldElement256::ZERO,
            |sum, (basis_fields, coefficient)| {
                let value = basis_fields
                    .as_ref()
                    .and_then(|fields| fields.get(position_within_chunk))
                    .copied()
                    .ok_or(TallyPreparationError::AuthenticatedKeyShareVectorGeometryMismatch)?;
                Ok(sum.add(value.multiply(coefficient)))
            },
        )
    }
}

/// Verifier-derived public key fields for one complete all-roster codeword
/// chunk. Retaining or publishing this value does not authorize protocol
/// progress.
pub(crate) struct PubliclyCheckedAuthenticatedKeyFieldChunk {
    first_field_index: u64,
    reconstructed_fields: Box<[BinaryFieldElement256]>,
}

impl PubliclyCheckedAuthenticatedKeyFieldChunk {
    pub(crate) const fn first_field_index(&self) -> u64 {
        self.first_field_index
    }

    pub(crate) fn reconstructed_fields(&self) -> &[BinaryFieldElement256] {
        &self.reconstructed_fields
    }
}
