use subtle::ConstantTimeEq;

use crate::{foundation::Hash512, tally_circuit::CompiledTallyCircuit};

use super::{
    BinaryFieldElement256, TallyPreparationContext, TallyPreparationError,
    authenticated_key_release::AuthenticatedKeyFieldLocalChecker,
    authenticated_key_share_vector::{
        AuthenticatedKeyShareVectorDescriptor, AuthenticatedKeyShareVectorPayloadChunk,
    },
    authenticated_key_share_vector_manifest::{
        AuthenticatedKeyShareVectorAcknowledgementBody, AuthenticatedKeyShareVectorManifest,
    },
    output_sharing::DEGREE_THREE_RECONSTRUCTION_THRESHOLD,
};

pub(crate) const MAXIMUM_LOCAL_CHECK_SIMULTANEOUS_PAYLOAD_CHUNK_COUNT: u64 = 2;
pub(crate) const MAXIMUM_LOCAL_CHECK_FIELD_ACCUMULATOR_COUNT: u64 = 2;
pub(crate) const MAXIMUM_LOCAL_CHECK_PAYLOAD_AND_ACCUMULATOR_BUFFER_COUNT: u64 = 3;

/// Streaming verifier for one participant's complete fixed-basis key-share
/// check.
///
/// The state retains only public descriptors and counters. Private payload
/// chunks are borrowed for one call and are never retained. Successful finish
/// establishes local polynomial consistency with the manifest-bound public
/// basis, but it does not establish that the local descriptor came from a
/// maliciously secure preparation protocol. It cannot mint a workflow
/// acceptance capability.
pub(crate) struct AuthenticatedKeyShareVectorLocalCheck {
    manifest_identity: Hash512,
    participant_count: u16,
    participant_position: u16,
    published_basis_descriptors: Box<[AuthenticatedKeyShareVectorDescriptor]>,
    local_descriptor: AuthenticatedKeyShareVectorDescriptor,
    field_checker: AuthenticatedKeyFieldLocalChecker,
    chunk_count: u64,
    next_chunk_index: u64,
    total_field_count: u64,
    checked_field_count: u64,
    next_basis_position: usize,
    reconstructed_fields: Option<Vec<BinaryFieldElement256>>,
    expected_local_fields: Option<Vec<BinaryFieldElement256>>,
    failed: bool,
}

impl AuthenticatedKeyShareVectorLocalCheck {
    pub(crate) fn begin(
        context: TallyPreparationContext,
        circuit: &CompiledTallyCircuit,
        holder_commitment_root: Hash512,
        manifest: &AuthenticatedKeyShareVectorManifest,
        published_basis_descriptors: &[AuthenticatedKeyShareVectorDescriptor],
        local_descriptor: &AuthenticatedKeyShareVectorDescriptor,
        participant_position: u16,
    ) -> Result<Self, TallyPreparationError> {
        manifest.verify_source_and_descriptors(
            context,
            circuit,
            holder_commitment_root,
            published_basis_descriptors,
        )?;
        let field_checker = AuthenticatedKeyFieldLocalChecker::new(
            context.participant_count(),
            participant_position,
        )?;
        if usize::from(manifest.reconstruction_threshold()) != DEGREE_THREE_RECONSTRUCTION_THRESHOLD
            || published_basis_descriptors.len() != DEGREE_THREE_RECONSTRUCTION_THRESHOLD
        {
            return Err(
                TallyPreparationError::AuthenticatedKeyReleaseBasisCountMismatch {
                    expected: DEGREE_THREE_RECONSTRUCTION_THRESHOLD,
                    actual: published_basis_descriptors.len(),
                },
            );
        }
        local_descriptor.verify_source(context, circuit, holder_commitment_root)?;
        if local_descriptor.sender_position() != participant_position
            || local_descriptor.participant_count() != field_checker.participant_count()
            || local_descriptor.total_field_count() != manifest.total_field_count()
        {
            return Err(TallyPreparationError::AuthenticatedKeyShareVectorLocalDescriptorMismatch);
        }
        let chunk_count = local_descriptor.chunk_count();
        if published_basis_descriptors
            .iter()
            .any(|descriptor| descriptor.chunk_count() != chunk_count)
        {
            return Err(TallyPreparationError::AuthenticatedKeyShareVectorGeometryMismatch);
        }

        Ok(Self {
            manifest_identity: manifest.identity(),
            participant_count: field_checker.participant_count(),
            participant_position: field_checker.participant_position(),
            published_basis_descriptors: published_basis_descriptors.to_vec().into_boxed_slice(),
            local_descriptor: local_descriptor.clone(),
            field_checker,
            chunk_count,
            next_chunk_index: 0,
            total_field_count: manifest.total_field_count(),
            checked_field_count: 0,
            next_basis_position: 0,
            reconstructed_fields: None,
            expected_local_fields: None,
            failed: false,
        })
    }

    /// Folds the next public basis chunk into the current reconstructed-key
    /// chunk.
    ///
    /// Public basis positions are implicit and must be supplied in canonical
    /// order. A basis participant supplies its retained local chunk only beside
    /// the public chunk at the same roster position. Therefore this call
    /// borrows at most two transport payloads at once.
    pub(crate) fn absorb_next_published_basis_payload_chunk(
        &mut self,
        published_basis_payload_chunk: &[u8],
        local_payload_chunk: Option<&[u8]>,
    ) -> Result<Option<LocallyCheckedAuthenticatedKeyFieldChunk>, TallyPreparationError> {
        self.require_live_incomplete_check()?;
        if self.next_basis_position >= DEGREE_THREE_RECONSTRUCTION_THRESHOLD {
            return Err(
                TallyPreparationError::AuthenticatedKeyShareVectorLocalPayloadOutOfSequence {
                    absorbed_basis_count: self.next_basis_position,
                },
            );
        }

        let basis_position = self.next_basis_position;
        let local_payload_expected = usize::from(self.participant_position) == basis_position;
        if local_payload_chunk.is_some() != local_payload_expected {
            return Err(
                TallyPreparationError::AuthenticatedKeyShareVectorLocalPayloadPresenceMismatch {
                    basis_position: u16::try_from(basis_position)
                        .map_err(|_| TallyPreparationError::IntegerConversion)?,
                    expected: local_payload_expected,
                    actual: local_payload_chunk.is_some(),
                },
            );
        }

        let published_basis_chunk = self.published_basis_descriptors[basis_position]
            .verify_payload_chunk(self.next_chunk_index, published_basis_payload_chunk)?;
        self.validate_current_chunk_geometry(&published_basis_chunk)?;
        let local_chunk = local_payload_chunk
            .map(|local_payload_chunk| {
                self.local_descriptor
                    .verify_payload_chunk(self.next_chunk_index, local_payload_chunk)
            })
            .transpose()?;
        if let Some(local_chunk) = &local_chunk {
            validate_matching_chunk_geometry(&published_basis_chunk, local_chunk)?;
        }

        let constant_term_coefficient =
            self.field_checker.constant_term_coefficients()[basis_position];
        let local_point_coefficient = self
            .field_checker
            .local_point_coefficients()
            .map(|coefficients| coefficients[basis_position]);
        if let Err(error) = accumulate_basis_contribution(
            &mut self.reconstructed_fields,
            &mut self.expected_local_fields,
            &published_basis_chunk,
            local_chunk.as_ref(),
            constant_term_coefficient,
            local_point_coefficient,
            self.participant_position,
        ) {
            self.failed = true;
            return Err(error);
        }
        self.next_basis_position = self
            .next_basis_position
            .checked_add(1)
            .ok_or(TallyPreparationError::ArithmeticOverflow)?;

        if self.next_basis_position == DEGREE_THREE_RECONSTRUCTION_THRESHOLD
            && self.field_checker.local_point_coefficients().is_none()
        {
            return self.complete_current_chunk().map(Some);
        }
        Ok(None)
    }

    /// Checks a nonbasis participant's retained local chunk after all four
    /// public basis chunks for the same chunk index have been folded.
    pub(crate) fn verify_next_nonbasis_local_payload_chunk(
        &mut self,
        local_payload_chunk: &[u8],
    ) -> Result<LocallyCheckedAuthenticatedKeyFieldChunk, TallyPreparationError> {
        self.require_live_incomplete_check()?;
        if self.field_checker.local_point_coefficients().is_none()
            || self.next_basis_position != DEGREE_THREE_RECONSTRUCTION_THRESHOLD
        {
            return Err(
                TallyPreparationError::AuthenticatedKeyShareVectorLocalPayloadOutOfSequence {
                    absorbed_basis_count: self.next_basis_position,
                },
            );
        }

        let local_chunk = self
            .local_descriptor
            .verify_payload_chunk(self.next_chunk_index, local_payload_chunk)?;
        self.validate_current_chunk_geometry(&local_chunk)?;
        let expected_local_fields = self
            .expected_local_fields
            .as_ref()
            .ok_or(TallyPreparationError::AuthenticatedKeyShareVectorGeometryMismatch)?;
        if u64::try_from(expected_local_fields.len())
            .map_err(|_| TallyPreparationError::IntegerConversion)?
            != local_chunk.field_count()
        {
            return Err(TallyPreparationError::AuthenticatedKeyShareVectorGeometryMismatch);
        }
        for (position_within_chunk, expected_local_value) in
            expected_local_fields.iter().enumerate()
        {
            let local_value = local_chunk.field_value(
                u64::try_from(position_within_chunk)
                    .map_err(|_| TallyPreparationError::IntegerConversion)?,
            )?;
            if expected_local_value.ct_eq(&local_value).unwrap_u8() != 1 {
                self.failed = true;
                return Err(TallyPreparationError::InconsistentShare {
                    roster_position: self.participant_position,
                });
            }
        }
        self.expected_local_fields = None;
        self.complete_current_chunk()
    }

    fn require_live_incomplete_check(&self) -> Result<(), TallyPreparationError> {
        if self.failed {
            return Err(TallyPreparationError::AuthenticatedKeyShareVectorLocalCheckFailed);
        }
        if self.next_chunk_index >= self.chunk_count {
            return Err(
                TallyPreparationError::AuthenticatedKeyShareVectorLocalCheckAlreadyComplete,
            );
        }
        Ok(())
    }

    fn validate_current_chunk_geometry(
        &self,
        chunk: &AuthenticatedKeyShareVectorPayloadChunk<'_>,
    ) -> Result<(), TallyPreparationError> {
        if chunk.first_field_index() != self.checked_field_count {
            return Err(TallyPreparationError::AuthenticatedKeyShareVectorGeometryMismatch);
        }
        Ok(())
    }

    fn complete_current_chunk(
        &mut self,
    ) -> Result<LocallyCheckedAuthenticatedKeyFieldChunk, TallyPreparationError> {
        if self.next_basis_position != DEGREE_THREE_RECONSTRUCTION_THRESHOLD
            || self.expected_local_fields.is_some()
        {
            return Err(TallyPreparationError::AuthenticatedKeyShareVectorGeometryMismatch);
        }
        let first_field_index = self.checked_field_count;
        let reconstructed_fields = self
            .reconstructed_fields
            .take()
            .ok_or(TallyPreparationError::AuthenticatedKeyShareVectorGeometryMismatch)?;
        let field_count = u64::try_from(reconstructed_fields.len())
            .map_err(|_| TallyPreparationError::IntegerConversion)?;
        self.checked_field_count = self
            .checked_field_count
            .checked_add(field_count)
            .ok_or(TallyPreparationError::ArithmeticOverflow)?;
        self.next_chunk_index = self
            .next_chunk_index
            .checked_add(1)
            .ok_or(TallyPreparationError::ArithmeticOverflow)?;
        self.next_basis_position = 0;
        Ok(LocallyCheckedAuthenticatedKeyFieldChunk {
            first_field_index,
            reconstructed_fields: reconstructed_fields.into_boxed_slice(),
        })
    }

    pub(crate) fn finish(
        self,
    ) -> Result<LocallyCheckedAuthenticatedKeyShareVector, TallyPreparationError> {
        if self.next_chunk_index != self.chunk_count
            || self.checked_field_count != self.total_field_count
            || self.next_basis_position != 0
            || self.reconstructed_fields.is_some()
            || self.expected_local_fields.is_some()
            || self.failed
        {
            return Err(
                TallyPreparationError::AuthenticatedKeyShareVectorLocalCheckIncomplete {
                    expected_chunk_count: self.chunk_count,
                    checked_chunk_count: self.next_chunk_index,
                    expected_field_count: self.total_field_count,
                    checked_field_count: self.checked_field_count,
                    absorbed_basis_count: self.next_basis_position,
                },
            );
        }
        Ok(LocallyCheckedAuthenticatedKeyShareVector {
            manifest_identity: self.manifest_identity,
            participant_count: self.participant_count,
            participant_position: self.participant_position,
        })
    }
}

/// One locally complete share-vector check. The private fields prevent raw
/// producer bytes from constructing this value.
pub(crate) struct LocallyCheckedAuthenticatedKeyShareVector {
    manifest_identity: Hash512,
    participant_count: u16,
    participant_position: u16,
}

impl core::fmt::Debug for LocallyCheckedAuthenticatedKeyShareVector {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("LocallyCheckedAuthenticatedKeyShareVector")
            .field("manifest_identity", &self.manifest_identity)
            .field("participant_count", &self.participant_count)
            .field("participant_position", &self.participant_position)
            .finish()
    }
}

/// Verifier-derived public key fields for one canonical payload chunk.
/// Retaining or publishing this value does not authorize protocol progress.
pub(crate) struct LocallyCheckedAuthenticatedKeyFieldChunk {
    first_field_index: u64,
    reconstructed_fields: Box<[BinaryFieldElement256]>,
}

impl LocallyCheckedAuthenticatedKeyFieldChunk {
    pub(crate) const fn first_field_index(&self) -> u64 {
        self.first_field_index
    }

    pub(crate) fn reconstructed_fields(&self) -> &[BinaryFieldElement256] {
        &self.reconstructed_fields
    }
}

/// Consumes a verifier-minted complete local check to create the unsigned body
/// that a separate one-shot state and signature owner may authenticate.
pub(crate) fn create_authenticated_key_share_vector_acknowledgement_body(
    checked_share_vector: LocallyCheckedAuthenticatedKeyShareVector,
    manifest: &AuthenticatedKeyShareVectorManifest,
) -> Result<AuthenticatedKeyShareVectorAcknowledgementBody, TallyPreparationError> {
    if checked_share_vector.manifest_identity != manifest.identity()
        || checked_share_vector.participant_count != manifest.participant_count()
    {
        return Err(TallyPreparationError::AuthenticatedKeyShareVectorAcknowledgementMismatch);
    }
    AuthenticatedKeyShareVectorAcknowledgementBody::unsigned_body_for_participant(
        manifest,
        checked_share_vector.participant_position,
    )
}

fn accumulate_basis_contribution(
    reconstructed_fields: &mut Option<Vec<BinaryFieldElement256>>,
    expected_local_fields: &mut Option<Vec<BinaryFieldElement256>>,
    published_basis_chunk: &AuthenticatedKeyShareVectorPayloadChunk<'_>,
    basis_local_chunk: Option<&AuthenticatedKeyShareVectorPayloadChunk<'_>>,
    constant_term_coefficient: BinaryFieldElement256,
    local_point_coefficient: Option<BinaryFieldElement256>,
    participant_position: u16,
) -> Result<(), TallyPreparationError> {
    let field_count = usize::try_from(published_basis_chunk.field_count())
        .map_err(|_| TallyPreparationError::IntegerConversion)?;
    let reconstructed_fields =
        reconstructed_fields.get_or_insert_with(|| vec![BinaryFieldElement256::ZERO; field_count]);
    if reconstructed_fields.len() != field_count {
        return Err(TallyPreparationError::AuthenticatedKeyShareVectorGeometryMismatch);
    }
    let mut expected_local_fields = match local_point_coefficient {
        Some(_coefficient) => {
            let fields = expected_local_fields
                .get_or_insert_with(|| vec![BinaryFieldElement256::ZERO; field_count]);
            if fields.len() != field_count {
                return Err(TallyPreparationError::AuthenticatedKeyShareVectorGeometryMismatch);
            }
            Some(fields)
        }
        None => {
            if expected_local_fields.is_some() {
                return Err(TallyPreparationError::AuthenticatedKeyShareVectorGeometryMismatch);
            }
            None
        }
    };
    for position_within_chunk in 0..field_count {
        let canonical_position = u64::try_from(position_within_chunk)
            .map_err(|_| TallyPreparationError::IntegerConversion)?;
        let published_value = published_basis_chunk.field_value(canonical_position)?;
        if let Some(basis_local_chunk) = basis_local_chunk {
            let local_value = basis_local_chunk.field_value(canonical_position)?;
            if published_value.ct_eq(&local_value).unwrap_u8() != 1 {
                return Err(TallyPreparationError::InconsistentShare {
                    roster_position: participant_position,
                });
            }
        }
        reconstructed_fields[position_within_chunk] = reconstructed_fields[position_within_chunk]
            .add(published_value.multiply(constant_term_coefficient));
        if let (Some(expected_local_fields), Some(local_point_coefficient)) = (
            expected_local_fields.as_deref_mut(),
            local_point_coefficient,
        ) {
            expected_local_fields[position_within_chunk] = expected_local_fields
                [position_within_chunk]
                .add(published_value.multiply(local_point_coefficient));
        }
    }
    Ok(())
}

fn validate_matching_chunk_geometry(
    published_basis_chunk: &AuthenticatedKeyShareVectorPayloadChunk<'_>,
    local_chunk: &AuthenticatedKeyShareVectorPayloadChunk<'_>,
) -> Result<(), TallyPreparationError> {
    if published_basis_chunk.first_field_index() != local_chunk.first_field_index()
        || published_basis_chunk.field_count() != local_chunk.field_count()
    {
        return Err(TallyPreparationError::AuthenticatedKeyShareVectorGeometryMismatch);
    }
    Ok(())
}
