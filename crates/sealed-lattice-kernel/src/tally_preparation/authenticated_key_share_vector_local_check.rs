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
        })
    }

    pub(crate) fn verify_next_payload_chunks(
        &mut self,
        published_basis_payload_chunks: &[&[u8]],
        local_payload_chunk: &[u8],
    ) -> Result<LocallyCheckedAuthenticatedKeyFieldChunk, TallyPreparationError> {
        if published_basis_payload_chunks.len() != DEGREE_THREE_RECONSTRUCTION_THRESHOLD {
            return Err(
                TallyPreparationError::AuthenticatedKeyReleaseBasisCountMismatch {
                    expected: DEGREE_THREE_RECONSTRUCTION_THRESHOLD,
                    actual: published_basis_payload_chunks.len(),
                },
            );
        }
        if self.next_chunk_index >= self.chunk_count {
            return Err(
                TallyPreparationError::AuthenticatedKeyShareVectorLocalCheckAlreadyComplete,
            );
        }

        let published_basis_chunks = [
            self.published_basis_descriptors[0]
                .verify_payload_chunk(self.next_chunk_index, published_basis_payload_chunks[0])?,
            self.published_basis_descriptors[1]
                .verify_payload_chunk(self.next_chunk_index, published_basis_payload_chunks[1])?,
            self.published_basis_descriptors[2]
                .verify_payload_chunk(self.next_chunk_index, published_basis_payload_chunks[2])?,
            self.published_basis_descriptors[3]
                .verify_payload_chunk(self.next_chunk_index, published_basis_payload_chunks[3])?,
        ];
        let local_chunk = self
            .local_descriptor
            .verify_payload_chunk(self.next_chunk_index, local_payload_chunk)?;
        validate_matching_chunk_geometry(&published_basis_chunks, &local_chunk)?;
        if local_chunk.first_field_index() != self.checked_field_count {
            return Err(TallyPreparationError::AuthenticatedKeyShareVectorGeometryMismatch);
        }

        let field_count = local_chunk.field_count();
        let mut reconstructed_fields = Vec::with_capacity(
            usize::try_from(field_count).map_err(|_| TallyPreparationError::IntegerConversion)?,
        );
        for position_within_chunk in 0..field_count {
            let mut published_basis_values =
                [BinaryFieldElement256::ZERO; DEGREE_THREE_RECONSTRUCTION_THRESHOLD];
            for (basis_position, published_basis_chunk) in published_basis_chunks.iter().enumerate()
            {
                published_basis_values[basis_position] =
                    published_basis_chunk.field_value(position_within_chunk)?;
            }
            reconstructed_fields.push(self.field_checker.reconstruct_locally_checked_field(
                published_basis_values,
                local_chunk.field_value(position_within_chunk)?,
            )?);
        }

        let first_field_index = self.checked_field_count;
        self.checked_field_count = self
            .checked_field_count
            .checked_add(field_count)
            .ok_or(TallyPreparationError::ArithmeticOverflow)?;
        self.next_chunk_index = self
            .next_chunk_index
            .checked_add(1)
            .ok_or(TallyPreparationError::ArithmeticOverflow)?;
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
        {
            return Err(
                TallyPreparationError::AuthenticatedKeyShareVectorLocalCheckIncomplete {
                    expected_chunk_count: self.chunk_count,
                    checked_chunk_count: self.next_chunk_index,
                    expected_field_count: self.total_field_count,
                    checked_field_count: self.checked_field_count,
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

fn validate_matching_chunk_geometry(
    published_basis_chunks: &[AuthenticatedKeyShareVectorPayloadChunk<'_>;
         DEGREE_THREE_RECONSTRUCTION_THRESHOLD],
    local_chunk: &AuthenticatedKeyShareVectorPayloadChunk<'_>,
) -> Result<(), TallyPreparationError> {
    if published_basis_chunks.iter().any(|published_chunk| {
        published_chunk.first_field_index() != local_chunk.first_field_index()
            || published_chunk.field_count() != local_chunk.field_count()
    }) {
        return Err(TallyPreparationError::AuthenticatedKeyShareVectorGeometryMismatch);
    }
    Ok(())
}
