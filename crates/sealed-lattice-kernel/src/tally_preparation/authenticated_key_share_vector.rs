use crate::{
    encoding::{CanonicalReader, append_bytes, append_varuint, encode_varuint},
    foundation::{FOUNDATION_PROFILE, Hash512, derive_foundation_roster_parameters},
    hashing::{HASH512_PREIMAGE_PREFIX, StreamingHash512, hash_framed_parts_512},
    tally_circuit::CompiledTallyCircuit,
};

use super::{
    BinaryFieldElement256, TallyPreparationContext, TallyPreparationError,
    preparation_holder_record_catalog::{
        PreparationHolderRecord, PreparationHolderRecordCatalog, PreparationHolderRecordIter,
    },
};

const AUTHENTICATED_KEY_SHARE_VECTOR_SOURCE: &[u8] =
    include_bytes!("authenticated_key_share_vector.rs");
pub(super) const AUTHENTICATED_KEY_SHARE_VECTOR_DESCRIPTOR_MAGIC: &[u8] =
    b"sealed-lattice/authenticated-key-share-vector-descriptor";
pub(super) const AUTHENTICATED_KEY_SHARE_VECTOR_ARTIFACT_VERSION: u64 = 1;
const AUTHENTICATED_KEY_SHARE_VECTOR_COMPILER_IDENTITY_DOMAIN: &str =
    "sealed-lattice/authenticated-key-share-vector-compiler-identity/v1";
const AUTHENTICATED_KEY_SHARE_VECTOR_DESCRIPTOR_IDENTITY_DOMAIN: &str =
    "sealed-lattice/authenticated-key-share-vector-descriptor-identity/v1";
const AUTHENTICATED_KEY_SHARE_VECTOR_PAYLOAD_CHUNK_DOMAIN: &str =
    "sealed-lattice/authenticated-key-share-vector-payload-chunk/v1";

const FIELD_ELEMENT_BYTE_LENGTH: u64 = BinaryFieldElement256::CANONICAL_BYTE_LENGTH as u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthenticatedKeyFieldRole {
    Coefficient { value_limb_position: u64 },
    Offset,
}

/// The canonical flattened position of one delayed-authentication key field.
///
/// Records follow the holder-record catalog. Within each record all
/// coefficient fields occur in value-limb order, followed by the independent
/// offset. This mapping is bound by the share-vector compiler identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuthenticatedKeyFieldCoordinate {
    pub(crate) field_index: u64,
    pub(crate) record: PreparationHolderRecord,
    pub(crate) role: AuthenticatedKeyFieldRole,
}

pub(crate) struct AuthenticatedKeyFieldCoordinateIterator<'catalog> {
    records: PreparationHolderRecordIter<'catalog>,
    current_record: Option<PreparationHolderRecord>,
    next_record_field_position: u64,
    next_field_index: u64,
    remaining: usize,
}

impl Iterator for AuthenticatedKeyFieldCoordinateIterator<'_> {
    type Item = Result<AuthenticatedKeyFieldCoordinate, TallyPreparationError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        if self.current_record.is_none() {
            match self.records.next() {
                None => {
                    self.remaining = 0;
                    return Some(Err(TallyPreparationError::GeometryMismatch));
                }
                Some(Ok(record)) => {
                    self.current_record = Some(record);
                    self.next_record_field_position = 0;
                }
                Some(Err(error)) => {
                    self.remaining = 0;
                    return Some(Err(error));
                }
            }
        }

        let record = self.current_record?;
        let value_field_element_count = record.value_field_element_count();
        let role = if self.next_record_field_position < value_field_element_count {
            AuthenticatedKeyFieldRole::Coefficient {
                value_limb_position: self.next_record_field_position,
            }
        } else if self.next_record_field_position == value_field_element_count {
            AuthenticatedKeyFieldRole::Offset
        } else {
            self.remaining = 0;
            return Some(Err(TallyPreparationError::GeometryMismatch));
        };
        let coordinate = AuthenticatedKeyFieldCoordinate {
            field_index: self.next_field_index,
            record,
            role,
        };
        self.next_field_index = match checked_add(self.next_field_index, 1) {
            Ok(next_field_index) => next_field_index,
            Err(error) => {
                self.remaining = 0;
                return Some(Err(error));
            }
        };
        self.next_record_field_position = match checked_add(self.next_record_field_position, 1) {
            Ok(next_record_field_position) => next_record_field_position,
            Err(error) => {
                self.remaining = 0;
                return Some(Err(error));
            }
        };
        self.remaining -= 1;
        if self.next_record_field_position == record.verification_key_field_element_count() {
            self.current_record = None;
        }
        Some(Ok(coordinate))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for AuthenticatedKeyFieldCoordinateIterator<'_> {}

pub(crate) fn authenticated_key_field_coordinates(
    catalog: &PreparationHolderRecordCatalog,
) -> Result<AuthenticatedKeyFieldCoordinateIterator<'_>, TallyPreparationError> {
    Ok(AuthenticatedKeyFieldCoordinateIterator {
        records: catalog.records(),
        current_record: None,
        next_record_field_position: 0,
        next_field_index: 0,
        remaining: usize::try_from(catalog.verification_key_field_element_count())
            .map_err(|_| TallyPreparationError::IntegerConversion)?,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AuthenticatedKeyShareVectorGeometry {
    total_field_count: u64,
    total_payload_byte_length: u64,
    field_count_per_full_chunk: u64,
    chunk_count: u64,
    final_chunk_payload_byte_length: u64,
}

impl AuthenticatedKeyShareVectorGeometry {
    fn derive(total_field_count: u64) -> Result<Self, TallyPreparationError> {
        if total_field_count == 0 {
            return Err(TallyPreparationError::AuthenticatedKeyShareVectorGeometryMismatch);
        }
        let configured_chunk_payload_byte_length = configured_chunk_payload_byte_length()?;
        if !configured_chunk_payload_byte_length.is_multiple_of(FIELD_ELEMENT_BYTE_LENGTH) {
            return Err(TallyPreparationError::AuthenticatedKeyShareVectorGeometryMismatch);
        }
        let field_count_per_full_chunk = configured_chunk_payload_byte_length
            .checked_div(FIELD_ELEMENT_BYTE_LENGTH)
            .filter(|field_count| *field_count > 0)
            .ok_or(TallyPreparationError::AuthenticatedKeyShareVectorGeometryMismatch)?;
        let total_payload_byte_length =
            checked_multiply(total_field_count, FIELD_ELEMENT_BYTE_LENGTH)?;
        let chunk_count = checked_ceiling_divide(total_field_count, field_count_per_full_chunk)?;
        let complete_chunk_count = chunk_count
            .checked_sub(1)
            .ok_or(TallyPreparationError::AuthenticatedKeyShareVectorGeometryMismatch)?;
        let final_chunk_payload_byte_length = total_payload_byte_length
            .checked_sub(checked_multiply(
                complete_chunk_count,
                configured_chunk_payload_byte_length,
            )?)
            .filter(|byte_length| {
                *byte_length > 0 && *byte_length <= configured_chunk_payload_byte_length
            })
            .ok_or(TallyPreparationError::AuthenticatedKeyShareVectorGeometryMismatch)?;
        Ok(Self {
            total_field_count,
            total_payload_byte_length,
            field_count_per_full_chunk,
            chunk_count,
            final_chunk_payload_byte_length,
        })
    }

    fn payload_geometry(
        self,
        chunk_index: u64,
    ) -> Result<AuthenticatedKeyShareVectorPayloadGeometry, TallyPreparationError> {
        if chunk_index >= self.chunk_count {
            return Err(
                TallyPreparationError::AuthenticatedKeyShareVectorChunkOutOfRange {
                    chunk_index,
                    chunk_count: self.chunk_count,
                },
            );
        }
        let first_field_index = checked_multiply(chunk_index, self.field_count_per_full_chunk)?;
        let remaining_field_count = self
            .total_field_count
            .checked_sub(first_field_index)
            .ok_or(TallyPreparationError::AuthenticatedKeyShareVectorGeometryMismatch)?;
        let field_count = remaining_field_count.min(self.field_count_per_full_chunk);
        let payload_byte_length = checked_multiply(field_count, FIELD_ELEMENT_BYTE_LENGTH)?;
        Ok(AuthenticatedKeyShareVectorPayloadGeometry {
            first_field_index,
            field_count,
            payload_byte_length,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AuthenticatedKeyShareVectorPayloadGeometry {
    first_field_index: u64,
    field_count: u64,
    payload_byte_length: u64,
}

/// Certificate-free descriptor for one public Shamir share vector.
///
/// Its ordered payload digests bind raw chunks to the preparation context,
/// holder-record catalog, holder-commitment predecessor, sender, and complete
/// geometry. The descriptor proves neither sender authentication nor
/// preparation provenance and cannot mint a protocol capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthenticatedKeyShareVectorDescriptor {
    context_identity: Hash512,
    holder_record_catalog_identity: Hash512,
    compiler_identity: Hash512,
    holder_commitment_root: Hash512,
    participant_count: u16,
    sender_position: u16,
    geometry: AuthenticatedKeyShareVectorGeometry,
    ordered_payload_chunk_digests: Box<[Hash512]>,
}

impl AuthenticatedKeyShareVectorDescriptor {
    pub(crate) const fn participant_count(&self) -> u16 {
        self.participant_count
    }

    pub(crate) const fn sender_position(&self) -> u16 {
        self.sender_position
    }

    pub(crate) const fn total_field_count(&self) -> u64 {
        self.geometry.total_field_count
    }

    pub(crate) const fn total_payload_byte_length(&self) -> u64 {
        self.geometry.total_payload_byte_length
    }

    pub(crate) const fn chunk_count(&self) -> u64 {
        self.geometry.chunk_count
    }

    pub(crate) const fn final_chunk_payload_byte_length(&self) -> u64 {
        self.geometry.final_chunk_payload_byte_length
    }

    pub(crate) fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        append_bytes(&mut bytes, AUTHENTICATED_KEY_SHARE_VECTOR_DESCRIPTOR_MAGIC);
        append_varuint(&mut bytes, AUTHENTICATED_KEY_SHARE_VECTOR_ARTIFACT_VERSION);
        append_bytes(&mut bytes, self.context_identity.as_bytes());
        append_bytes(&mut bytes, self.holder_record_catalog_identity.as_bytes());
        append_bytes(&mut bytes, self.compiler_identity.as_bytes());
        append_bytes(&mut bytes, self.holder_commitment_root.as_bytes());
        append_varuint(&mut bytes, u64::from(self.participant_count));
        append_varuint(&mut bytes, u64::from(self.sender_position));
        append_varuint(&mut bytes, self.geometry.total_field_count);
        append_varuint(&mut bytes, FIELD_ELEMENT_BYTE_LENGTH);
        append_varuint(
            &mut bytes,
            configured_chunk_payload_byte_length()
                .expect("the foundation stream-chunk length is representable"),
        );
        append_varuint(&mut bytes, self.geometry.total_payload_byte_length);
        append_varuint(&mut bytes, self.geometry.chunk_count);
        append_varuint(&mut bytes, self.geometry.final_chunk_payload_byte_length);
        append_varuint(
            &mut bytes,
            u64::try_from(self.ordered_payload_chunk_digests.len())
                .expect("the descriptor digest count is representable"),
        );
        for digest in &self.ordered_payload_chunk_digests {
            append_bytes(&mut bytes, digest.as_bytes());
        }
        bytes
    }

    pub(crate) fn identity(&self) -> Hash512 {
        Hash512::from_bytes(hash_framed_parts_512(
            AUTHENTICATED_KEY_SHARE_VECTOR_DESCRIPTOR_IDENTITY_DOMAIN,
            &[&self.canonical_bytes()],
        ))
    }

    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, TallyPreparationError> {
        if bytes.is_empty() || bytes.len() > FOUNDATION_PROFILE.stream_chunk_byte_length {
            return Err(
                TallyPreparationError::AuthenticatedKeyShareVectorDescriptorByteLengthOutOfRange {
                    actual: bytes.len(),
                    maximum: FOUNDATION_PROFILE.stream_chunk_byte_length,
                },
            );
        }
        let mut reader = CanonicalReader::new(bytes);
        let magic_byte_length = usize::try_from(reader.read_varuint()?)
            .map_err(|_| TallyPreparationError::IntegerConversion)?;
        if magic_byte_length != AUTHENTICATED_KEY_SHARE_VECTOR_DESCRIPTOR_MAGIC.len()
            || reader.read_exact(magic_byte_length)?
                != AUTHENTICATED_KEY_SHARE_VECTOR_DESCRIPTOR_MAGIC
        {
            return Err(TallyPreparationError::AuthenticatedKeyShareVectorArtifactMagicMismatch);
        }
        let version = reader.read_varuint()?;
        if version != AUTHENTICATED_KEY_SHARE_VECTOR_ARTIFACT_VERSION {
            return Err(
                TallyPreparationError::UnsupportedAuthenticatedKeyShareVectorArtifactVersion {
                    version,
                },
            );
        }
        let context_identity = read_hash512(&mut reader, "context identity")?;
        let holder_record_catalog_identity =
            read_hash512(&mut reader, "holder-record catalog identity")?;
        let compiler_identity = read_hash512(&mut reader, "share-vector compiler identity")?;
        let expected_compiler_identity = authenticated_key_share_vector_compiler_identity()?;
        if compiler_identity != expected_compiler_identity {
            return Err(TallyPreparationError::AuthenticatedKeyShareVectorSourceMismatch);
        }
        let holder_commitment_root = read_hash512(&mut reader, "holder commitment root")?;
        let participant_count = read_u16(&mut reader)?;
        if derive_foundation_roster_parameters(participant_count).is_none() {
            return Err(TallyPreparationError::ParticipantCountOutOfRange { participant_count });
        }
        let sender_position = read_u16(&mut reader)?;
        if sender_position >= participant_count {
            return Err(
                TallyPreparationError::AuthenticatedKeyShareVectorSenderPositionOutOfRange {
                    sender_position,
                    participant_count,
                },
            );
        }
        let total_field_count = reader.read_varuint()?;
        let geometry = AuthenticatedKeyShareVectorGeometry::derive(total_field_count)?;
        if reader.read_varuint()? != FIELD_ELEMENT_BYTE_LENGTH
            || reader.read_varuint()? != configured_chunk_payload_byte_length()?
            || reader.read_varuint()? != geometry.total_payload_byte_length
            || reader.read_varuint()? != geometry.chunk_count
            || reader.read_varuint()? != geometry.final_chunk_payload_byte_length
        {
            return Err(TallyPreparationError::AuthenticatedKeyShareVectorGeometryMismatch);
        }
        let digest_count = reader.read_varuint()?;
        let maximum_digest_count_from_input =
            u64::try_from(bytes.len() / (Hash512::BYTE_LENGTH + 1))
                .map_err(|_| TallyPreparationError::IntegerConversion)?;
        if digest_count != geometry.chunk_count || digest_count > maximum_digest_count_from_input {
            return Err(TallyPreparationError::AuthenticatedKeyShareVectorGeometryMismatch);
        }
        let mut ordered_payload_chunk_digests = Vec::with_capacity(
            usize::try_from(digest_count).map_err(|_| TallyPreparationError::IntegerConversion)?,
        );
        for _ in 0..digest_count {
            ordered_payload_chunk_digests.push(read_hash512(&mut reader, "payload chunk digest")?);
        }
        if !reader.is_finished() {
            return Err(TallyPreparationError::TrailingAuthenticatedKeyShareVectorArtifactBytes);
        }
        Ok(Self {
            context_identity,
            holder_record_catalog_identity,
            compiler_identity,
            holder_commitment_root,
            participant_count,
            sender_position,
            geometry,
            ordered_payload_chunk_digests: ordered_payload_chunk_digests.into_boxed_slice(),
        })
    }

    pub(crate) fn verify_source(
        &self,
        context: TallyPreparationContext,
        circuit: &CompiledTallyCircuit,
        expected_holder_commitment_root: Hash512,
    ) -> Result<(), TallyPreparationError> {
        let catalog = PreparationHolderRecordCatalog::derive(context, circuit)?;
        if self.context_identity != context.identity()
            || self.holder_record_catalog_identity != catalog.identity()
            || self.compiler_identity != authenticated_key_share_vector_compiler_identity()?
            || self.holder_commitment_root != expected_holder_commitment_root
            || self.participant_count != context.participant_count()
            || self.geometry.total_field_count != catalog.verification_key_field_element_count()
        {
            return Err(TallyPreparationError::AuthenticatedKeyShareVectorSourceMismatch);
        }
        Ok(())
    }

    pub(crate) fn verify_payload_chunk<'payload>(
        &self,
        chunk_index: u64,
        payload: &'payload [u8],
    ) -> Result<AuthenticatedKeyShareVectorPayloadChunk<'payload>, TallyPreparationError> {
        let payload_geometry = self.geometry.payload_geometry(chunk_index)?;
        let actual_payload_byte_length =
            u64::try_from(payload.len()).map_err(|_| TallyPreparationError::IntegerConversion)?;
        if actual_payload_byte_length != payload_geometry.payload_byte_length {
            return Err(
                TallyPreparationError::AuthenticatedKeyShareVectorPayloadByteLengthMismatch {
                    expected: payload_geometry.payload_byte_length,
                    actual: actual_payload_byte_length,
                },
            );
        }
        let expected_digest = self
            .ordered_payload_chunk_digests
            .get(
                usize::try_from(chunk_index)
                    .map_err(|_| TallyPreparationError::IntegerConversion)?,
            )
            .ok_or(
                TallyPreparationError::AuthenticatedKeyShareVectorChunkOutOfRange {
                    chunk_index,
                    chunk_count: self.geometry.chunk_count,
                },
            )?;
        let actual_digest = derive_payload_chunk_digest(
            self.context_identity,
            self.holder_record_catalog_identity,
            self.compiler_identity,
            self.holder_commitment_root,
            self.participant_count,
            self.sender_position,
            self.geometry,
            chunk_index,
            payload_geometry,
            payload,
        );
        if *expected_digest != actual_digest {
            return Err(TallyPreparationError::AuthenticatedKeyShareVectorPayloadDigestMismatch);
        }
        Ok(AuthenticatedKeyShareVectorPayloadChunk {
            first_field_index: payload_geometry.first_field_index,
            field_count: payload_geometry.field_count,
            payload,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct AuthenticatedKeyShareVectorPayloadChunk<'payload> {
    first_field_index: u64,
    field_count: u64,
    payload: &'payload [u8],
}

impl AuthenticatedKeyShareVectorPayloadChunk<'_> {
    pub(crate) const fn first_field_index(&self) -> u64 {
        self.first_field_index
    }

    pub(crate) const fn field_count(&self) -> u64 {
        self.field_count
    }

    pub(crate) fn field_value(
        &self,
        position_within_chunk: u64,
    ) -> Result<BinaryFieldElement256, TallyPreparationError> {
        if position_within_chunk >= self.field_count {
            return Err(
                TallyPreparationError::AuthenticatedKeyShareVectorFieldPositionOutOfRange {
                    position_within_chunk,
                    field_count: self.field_count,
                },
            );
        }
        let start = usize::try_from(checked_multiply(
            position_within_chunk,
            FIELD_ELEMENT_BYTE_LENGTH,
        )?)
        .map_err(|_| TallyPreparationError::IntegerConversion)?;
        let end = start
            .checked_add(BinaryFieldElement256::CANONICAL_BYTE_LENGTH)
            .ok_or(TallyPreparationError::ArithmeticOverflow)?;
        BinaryFieldElement256::from_canonical_bytes(&self.payload[start..end])
    }
}

#[derive(Debug)]
pub(crate) struct AuthenticatedKeyShareVectorDescriptorBuilder {
    context_identity: Hash512,
    holder_record_catalog_identity: Hash512,
    compiler_identity: Hash512,
    holder_commitment_root: Hash512,
    participant_count: u16,
    sender_position: u16,
    geometry: AuthenticatedKeyShareVectorGeometry,
    ordered_payload_chunk_digests: Vec<Hash512>,
}

impl AuthenticatedKeyShareVectorDescriptorBuilder {
    pub(crate) fn new(
        context: TallyPreparationContext,
        circuit: &CompiledTallyCircuit,
        holder_commitment_root: Hash512,
        sender_position: u16,
    ) -> Result<Self, TallyPreparationError> {
        if sender_position >= context.participant_count() {
            return Err(
                TallyPreparationError::AuthenticatedKeyShareVectorSenderPositionOutOfRange {
                    sender_position,
                    participant_count: context.participant_count(),
                },
            );
        }
        let catalog = PreparationHolderRecordCatalog::derive(context, circuit)?;
        let geometry = AuthenticatedKeyShareVectorGeometry::derive(
            catalog.verification_key_field_element_count(),
        )?;
        Ok(Self {
            context_identity: context.identity(),
            holder_record_catalog_identity: catalog.identity(),
            compiler_identity: authenticated_key_share_vector_compiler_identity()?,
            holder_commitment_root,
            participant_count: context.participant_count(),
            sender_position,
            geometry,
            ordered_payload_chunk_digests: Vec::with_capacity(
                usize::try_from(geometry.chunk_count)
                    .map_err(|_| TallyPreparationError::IntegerConversion)?,
            ),
        })
    }

    pub(crate) const fn chunk_count(&self) -> u64 {
        self.geometry.chunk_count
    }

    pub(crate) fn expected_next_payload_byte_length(&self) -> Result<u64, TallyPreparationError> {
        self.geometry
            .payload_geometry(
                u64::try_from(self.ordered_payload_chunk_digests.len())
                    .map_err(|_| TallyPreparationError::IntegerConversion)?,
            )
            .map(|geometry| geometry.payload_byte_length)
    }

    pub(crate) fn absorb_next_payload_chunk(
        &mut self,
        payload: &[u8],
    ) -> Result<(), TallyPreparationError> {
        let chunk_index = u64::try_from(self.ordered_payload_chunk_digests.len())
            .map_err(|_| TallyPreparationError::IntegerConversion)?;
        let payload_geometry = self.geometry.payload_geometry(chunk_index)?;
        let actual_payload_byte_length =
            u64::try_from(payload.len()).map_err(|_| TallyPreparationError::IntegerConversion)?;
        if actual_payload_byte_length != payload_geometry.payload_byte_length {
            return Err(
                TallyPreparationError::AuthenticatedKeyShareVectorPayloadByteLengthMismatch {
                    expected: payload_geometry.payload_byte_length,
                    actual: actual_payload_byte_length,
                },
            );
        }
        self.ordered_payload_chunk_digests
            .push(derive_payload_chunk_digest(
                self.context_identity,
                self.holder_record_catalog_identity,
                self.compiler_identity,
                self.holder_commitment_root,
                self.participant_count,
                self.sender_position,
                self.geometry,
                chunk_index,
                payload_geometry,
                payload,
            ));
        Ok(())
    }

    pub(crate) fn finish(
        self,
    ) -> Result<AuthenticatedKeyShareVectorDescriptor, TallyPreparationError> {
        let actual_chunk_count = u64::try_from(self.ordered_payload_chunk_digests.len())
            .map_err(|_| TallyPreparationError::IntegerConversion)?;
        if actual_chunk_count != self.geometry.chunk_count {
            return Err(
                TallyPreparationError::AuthenticatedKeyShareVectorIncomplete {
                    expected_chunk_count: self.geometry.chunk_count,
                    actual_chunk_count,
                },
            );
        }
        Ok(AuthenticatedKeyShareVectorDescriptor {
            context_identity: self.context_identity,
            holder_record_catalog_identity: self.holder_record_catalog_identity,
            compiler_identity: self.compiler_identity,
            holder_commitment_root: self.holder_commitment_root,
            participant_count: self.participant_count,
            sender_position: self.sender_position,
            geometry: self.geometry,
            ordered_payload_chunk_digests: self.ordered_payload_chunk_digests.into_boxed_slice(),
        })
    }
}

pub(crate) fn authenticated_key_share_vector_descriptor_canonical_byte_length(
    participant_count: u16,
    sender_position: u16,
    total_field_count: u64,
) -> Result<u64, TallyPreparationError> {
    if derive_foundation_roster_parameters(participant_count).is_none() {
        return Err(TallyPreparationError::ParticipantCountOutOfRange { participant_count });
    }
    if sender_position >= participant_count {
        return Err(
            TallyPreparationError::AuthenticatedKeyShareVectorSenderPositionOutOfRange {
                sender_position,
                participant_count,
            },
        );
    }
    let geometry = AuthenticatedKeyShareVectorGeometry::derive(total_field_count)?;
    let mut byte_length = framed_byte_length(
        u64::try_from(AUTHENTICATED_KEY_SHARE_VECTOR_DESCRIPTOR_MAGIC.len())
            .map_err(|_| TallyPreparationError::IntegerConversion)?,
    )?;
    for value in [
        AUTHENTICATED_KEY_SHARE_VECTOR_ARTIFACT_VERSION,
        u64::from(participant_count),
        u64::from(sender_position),
        geometry.total_field_count,
        FIELD_ELEMENT_BYTE_LENGTH,
        configured_chunk_payload_byte_length()?,
        geometry.total_payload_byte_length,
        geometry.chunk_count,
        geometry.final_chunk_payload_byte_length,
        geometry.chunk_count,
    ] {
        byte_length = checked_add(byte_length, varuint_byte_length(value)?)?;
    }
    let framed_hash_byte_length = framed_byte_length(Hash512::BYTE_LENGTH as u64)?;
    byte_length = checked_add(byte_length, checked_multiply(4, framed_hash_byte_length)?)?;
    checked_add(
        byte_length,
        checked_multiply(geometry.chunk_count, framed_hash_byte_length)?,
    )
}

pub(crate) fn authenticated_key_share_vector_payload_chunk_preimage_byte_length(
    total_field_count: u64,
    chunk_index: u64,
) -> Result<u64, TallyPreparationError> {
    let geometry = AuthenticatedKeyShareVectorGeometry::derive(total_field_count)?;
    let payload_geometry = geometry.payload_geometry(chunk_index)?;
    let mut byte_length = u64::try_from(HASH512_PREIMAGE_PREFIX.len())
        .map_err(|_| TallyPreparationError::IntegerConversion)?;
    byte_length = checked_add(
        byte_length,
        framed_byte_length(
            u64::try_from(AUTHENTICATED_KEY_SHARE_VECTOR_PAYLOAD_CHUNK_DOMAIN.len())
                .map_err(|_| TallyPreparationError::IntegerConversion)?,
        )?,
    )?;
    byte_length = checked_add(byte_length, varuint_byte_length(13)?)?;
    byte_length = checked_add(
        byte_length,
        checked_multiply(4, framed_byte_length(Hash512::BYTE_LENGTH as u64)?)?,
    )?;
    byte_length = checked_add(
        byte_length,
        checked_multiply(2, framed_byte_length(u16::BITS.div_ceil(8).into())?)?,
    )?;
    byte_length = checked_add(
        byte_length,
        checked_multiply(6, framed_byte_length(u64::BITS.div_ceil(8).into())?)?,
    )?;
    checked_add(
        byte_length,
        framed_byte_length(payload_geometry.payload_byte_length)?,
    )
}

pub(crate) fn authenticated_key_share_vector_compiler_identity()
-> Result<Hash512, TallyPreparationError> {
    authenticated_key_share_vector_compiler_identity_from_source(
        AUTHENTICATED_KEY_SHARE_VECTOR_SOURCE,
    )
}

fn authenticated_key_share_vector_compiler_identity_from_source(
    source: &[u8],
) -> Result<Hash512, TallyPreparationError> {
    if core::str::from_utf8(source).is_err()
        || source.starts_with(&[0xef, 0xbb, 0xbf])
        || source.contains(&b'\r')
        || !source.ends_with(b"\n")
    {
        return Err(TallyPreparationError::NonCanonicalPreparationSourceEncoding);
    }
    Ok(Hash512::from_bytes(hash_framed_parts_512(
        AUTHENTICATED_KEY_SHARE_VECTOR_COMPILER_IDENTITY_DOMAIN,
        &[
            source,
            &AUTHENTICATED_KEY_SHARE_VECTOR_ARTIFACT_VERSION.to_le_bytes(),
        ],
    )))
}

#[allow(clippy::too_many_arguments)]
fn derive_payload_chunk_digest(
    context_identity: Hash512,
    holder_record_catalog_identity: Hash512,
    compiler_identity: Hash512,
    holder_commitment_root: Hash512,
    participant_count: u16,
    sender_position: u16,
    geometry: AuthenticatedKeyShareVectorGeometry,
    chunk_index: u64,
    payload_geometry: AuthenticatedKeyShareVectorPayloadGeometry,
    payload: &[u8],
) -> Hash512 {
    let participant_count_bytes = participant_count.to_le_bytes();
    let sender_position_bytes = sender_position.to_le_bytes();
    let total_field_count_bytes = geometry.total_field_count.to_le_bytes();
    let total_payload_byte_length_bytes = geometry.total_payload_byte_length.to_le_bytes();
    let chunk_index_bytes = chunk_index.to_le_bytes();
    let first_field_index_bytes = payload_geometry.first_field_index.to_le_bytes();
    let field_count_bytes = payload_geometry.field_count.to_le_bytes();
    let payload_byte_length_bytes = payload_geometry.payload_byte_length.to_le_bytes();
    let mut hasher = StreamingHash512::new(AUTHENTICATED_KEY_SHARE_VECTOR_PAYLOAD_CHUNK_DOMAIN, 13);
    for part in [
        context_identity.as_bytes().as_slice(),
        holder_record_catalog_identity.as_bytes().as_slice(),
        compiler_identity.as_bytes().as_slice(),
        holder_commitment_root.as_bytes().as_slice(),
        participant_count_bytes.as_slice(),
        sender_position_bytes.as_slice(),
        total_field_count_bytes.as_slice(),
        total_payload_byte_length_bytes.as_slice(),
        chunk_index_bytes.as_slice(),
        first_field_index_bytes.as_slice(),
        field_count_bytes.as_slice(),
        payload_byte_length_bytes.as_slice(),
        payload,
    ] {
        hasher.absorb_part(part);
    }
    Hash512::from_bytes(hasher.finalize())
}

fn configured_chunk_payload_byte_length() -> Result<u64, TallyPreparationError> {
    u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length)
        .map_err(|_| TallyPreparationError::IntegerConversion)
}

fn read_hash512(
    reader: &mut CanonicalReader<'_>,
    field: &'static str,
) -> Result<Hash512, TallyPreparationError> {
    let actual = usize::try_from(reader.read_varuint()?)
        .map_err(|_| TallyPreparationError::IntegerConversion)?;
    if actual != Hash512::BYTE_LENGTH {
        return Err(
            TallyPreparationError::AuthenticatedKeyShareVectorHashByteLength {
                field,
                expected: Hash512::BYTE_LENGTH,
                actual,
            },
        );
    }
    let fixed_bytes: [u8; Hash512::BYTE_LENGTH] = reader
        .read_exact(Hash512::BYTE_LENGTH)?
        .try_into()
        .expect("the exact hash byte length was checked");
    Ok(Hash512::from_bytes(fixed_bytes))
}

fn read_u16(reader: &mut CanonicalReader<'_>) -> Result<u16, TallyPreparationError> {
    u16::try_from(reader.read_varuint()?).map_err(|_| TallyPreparationError::IntegerConversion)
}

fn checked_multiply(left: u64, right: u64) -> Result<u64, TallyPreparationError> {
    left.checked_mul(right)
        .ok_or(TallyPreparationError::ArithmeticOverflow)
}

fn checked_add(left: u64, right: u64) -> Result<u64, TallyPreparationError> {
    left.checked_add(right)
        .ok_or(TallyPreparationError::ArithmeticOverflow)
}

fn varuint_byte_length(value: u64) -> Result<u64, TallyPreparationError> {
    u64::try_from(encode_varuint(value).len()).map_err(|_| TallyPreparationError::IntegerConversion)
}

fn framed_byte_length(payload_byte_length: u64) -> Result<u64, TallyPreparationError> {
    checked_add(
        varuint_byte_length(payload_byte_length)?,
        payload_byte_length,
    )
}

fn checked_ceiling_divide(dividend: u64, divisor: u64) -> Result<u64, TallyPreparationError> {
    if divisor == 0 {
        return Err(TallyPreparationError::AuthenticatedKeyShareVectorGeometryMismatch);
    }
    (dividend / divisor)
        .checked_add(u64::from(!dividend.is_multiple_of(divisor)))
        .ok_or(TallyPreparationError::ArithmeticOverflow)
}

#[cfg(test)]
pub(crate) fn compiler_identity_from_source_for_test(
    source: &[u8],
) -> Result<Hash512, TallyPreparationError> {
    authenticated_key_share_vector_compiler_identity_from_source(source)
}
