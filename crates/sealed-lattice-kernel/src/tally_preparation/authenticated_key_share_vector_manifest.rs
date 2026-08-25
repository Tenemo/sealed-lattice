use crate::{
    encoding::{CanonicalReader, append_bytes, append_varuint, encode_varuint},
    foundation::{FOUNDATION_PROFILE, Hash512, derive_foundation_roster_parameters},
    hashing::{StreamingHash512, hash_framed_parts_512},
    tally_circuit::CompiledTallyCircuit,
};

use super::{
    TallyPreparationContext, TallyPreparationError,
    authenticated_key_share_vector::{
        AuthenticatedKeyShareVectorDescriptor, authenticated_key_share_vector_compiler_identity,
    },
    preparation_holder_record_catalog::PreparationHolderRecordCatalog,
};

const AUTHENTICATED_KEY_SHARE_VECTOR_MANIFEST_SOURCE: &[u8] =
    include_bytes!("authenticated_key_share_vector_manifest.rs");
pub(super) const AUTHENTICATED_KEY_SHARE_VECTOR_MANIFEST_MAGIC: &[u8] =
    b"sealed-lattice/authenticated-key-share-vector-manifest";
pub(super) const AUTHENTICATED_KEY_SHARE_VECTOR_ACKNOWLEDGEMENT_MAGIC: &[u8] =
    b"sealed-lattice/authenticated-key-share-vector-acknowledgement";
pub(super) const AUTHENTICATED_KEY_SHARE_VECTOR_CONTROL_ARTIFACT_VERSION: u64 = 1;
const AUTHENTICATED_KEY_SHARE_VECTOR_MANIFEST_COMPILER_IDENTITY_DOMAIN: &str =
    "sealed-lattice/authenticated-key-share-vector-manifest-compiler-identity/v1";
const AUTHENTICATED_KEY_SHARE_VECTOR_MANIFEST_IDENTITY_DOMAIN: &str =
    "sealed-lattice/authenticated-key-share-vector-manifest-identity/v1";
const AUTHENTICATED_KEY_SHARE_VECTOR_ACKNOWLEDGEMENT_ROOT_DOMAIN: &str =
    "sealed-lattice/authenticated-key-share-vector-acknowledgement-root/v1";

/// Certificate-free fixed-basis manifest for delayed-authentication key
/// release.
///
/// Derivation verifies descriptor metadata against the exact preparation
/// source and fixes senders to roster positions zero through threshold minus
/// one. It does not verify payload chunks, signatures, one-shot state,
/// participant-local polynomial checks, or preparation provenance and cannot
/// mint a protocol capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthenticatedKeyShareVectorManifest {
    context_identity: Hash512,
    holder_record_catalog_identity: Hash512,
    share_vector_compiler_identity: Hash512,
    manifest_compiler_identity: Hash512,
    holder_commitment_root: Hash512,
    participant_count: u16,
    reconstruction_threshold: u16,
    total_field_count: u64,
    ordered_descriptor_identities: Box<[Hash512]>,
}

impl AuthenticatedKeyShareVectorManifest {
    pub(crate) fn derive(
        context: TallyPreparationContext,
        circuit: &CompiledTallyCircuit,
        holder_commitment_root: Hash512,
        descriptors: &[AuthenticatedKeyShareVectorDescriptor],
    ) -> Result<Self, TallyPreparationError> {
        let roster_parameters = derive_foundation_roster_parameters(context.participant_count())
            .ok_or(TallyPreparationError::ParticipantCountOutOfRange {
                participant_count: context.participant_count(),
            })?;
        let reconstruction_threshold = roster_parameters.reconstruction_threshold;
        if descriptors.len() != usize::from(reconstruction_threshold) {
            return Err(
                TallyPreparationError::AuthenticatedKeyShareVectorManifestDescriptorCountMismatch {
                    expected: usize::from(reconstruction_threshold),
                    actual: descriptors.len(),
                },
            );
        }
        let catalog = PreparationHolderRecordCatalog::derive(context, circuit)?;
        let total_field_count = catalog.verification_key_field_element_count();
        let mut ordered_descriptor_identities = Vec::with_capacity(descriptors.len());
        for (expected_sender_position, descriptor) in descriptors.iter().enumerate() {
            descriptor.verify_source(context, circuit, holder_commitment_root)?;
            let expected_sender_position = u16::try_from(expected_sender_position)
                .map_err(|_| TallyPreparationError::IntegerConversion)?;
            if descriptor.sender_position() != expected_sender_position
                || descriptor.participant_count() != context.participant_count()
                || descriptor.total_field_count() != total_field_count
            {
                return Err(TallyPreparationError::AuthenticatedKeyShareVectorManifestMismatch);
            }
            ordered_descriptor_identities.push(descriptor.identity());
        }
        Ok(Self {
            context_identity: context.identity(),
            holder_record_catalog_identity: catalog.identity(),
            share_vector_compiler_identity: authenticated_key_share_vector_compiler_identity()?,
            manifest_compiler_identity: authenticated_key_share_vector_manifest_compiler_identity(
            )?,
            holder_commitment_root,
            participant_count: context.participant_count(),
            reconstruction_threshold,
            total_field_count,
            ordered_descriptor_identities: ordered_descriptor_identities.into_boxed_slice(),
        })
    }

    pub(crate) const fn participant_count(&self) -> u16 {
        self.participant_count
    }

    pub(crate) const fn reconstruction_threshold(&self) -> u16 {
        self.reconstruction_threshold
    }

    pub(crate) const fn total_field_count(&self) -> u64 {
        self.total_field_count
    }

    pub(crate) fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        append_bytes(&mut bytes, AUTHENTICATED_KEY_SHARE_VECTOR_MANIFEST_MAGIC);
        append_varuint(
            &mut bytes,
            AUTHENTICATED_KEY_SHARE_VECTOR_CONTROL_ARTIFACT_VERSION,
        );
        append_bytes(&mut bytes, self.context_identity.as_bytes());
        append_bytes(&mut bytes, self.holder_record_catalog_identity.as_bytes());
        append_bytes(&mut bytes, self.share_vector_compiler_identity.as_bytes());
        append_bytes(&mut bytes, self.manifest_compiler_identity.as_bytes());
        append_bytes(&mut bytes, self.holder_commitment_root.as_bytes());
        append_varuint(&mut bytes, u64::from(self.participant_count));
        append_varuint(&mut bytes, u64::from(self.reconstruction_threshold));
        append_varuint(&mut bytes, self.total_field_count);
        append_varuint(
            &mut bytes,
            u64::try_from(self.ordered_descriptor_identities.len())
                .expect("the descriptor identity count is representable"),
        );
        for (sender_position, descriptor_identity) in
            self.ordered_descriptor_identities.iter().enumerate()
        {
            append_varuint(
                &mut bytes,
                u64::try_from(sender_position).expect("the sender position is representable"),
            );
            append_bytes(&mut bytes, descriptor_identity.as_bytes());
        }
        bytes
    }

    pub(crate) fn identity(&self) -> Hash512 {
        Hash512::from_bytes(hash_framed_parts_512(
            AUTHENTICATED_KEY_SHARE_VECTOR_MANIFEST_IDENTITY_DOMAIN,
            &[&self.canonical_bytes()],
        ))
    }

    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, TallyPreparationError> {
        validate_control_body_byte_length(bytes)?;
        let mut reader = CanonicalReader::new(bytes);
        read_magic(
            &mut reader,
            AUTHENTICATED_KEY_SHARE_VECTOR_MANIFEST_MAGIC,
            TallyPreparationError::AuthenticatedKeyShareVectorManifestMagicMismatch,
        )?;
        read_manifest_artifact_version(&mut reader)?;
        let context_identity = read_hash512(&mut reader, "manifest context identity")?;
        let holder_record_catalog_identity =
            read_hash512(&mut reader, "manifest holder-record catalog identity")?;
        let share_vector_compiler_identity =
            read_hash512(&mut reader, "manifest share-vector compiler identity")?;
        let manifest_compiler_identity = read_hash512(&mut reader, "manifest compiler identity")?;
        if share_vector_compiler_identity != authenticated_key_share_vector_compiler_identity()?
            || manifest_compiler_identity
                != authenticated_key_share_vector_manifest_compiler_identity()?
        {
            return Err(TallyPreparationError::AuthenticatedKeyShareVectorManifestMismatch);
        }
        let holder_commitment_root = read_hash512(&mut reader, "manifest holder commitment root")?;
        let participant_count = read_u16(&mut reader)?;
        let roster_parameters = derive_foundation_roster_parameters(participant_count)
            .ok_or(TallyPreparationError::ParticipantCountOutOfRange { participant_count })?;
        let reconstruction_threshold = read_u16(&mut reader)?;
        if reconstruction_threshold != roster_parameters.reconstruction_threshold {
            return Err(TallyPreparationError::AuthenticatedKeyShareVectorManifestMismatch);
        }
        let total_field_count = reader.read_varuint()?;
        if total_field_count == 0 {
            return Err(TallyPreparationError::AuthenticatedKeyShareVectorManifestMismatch);
        }
        let descriptor_count = reader.read_varuint()?;
        if descriptor_count != u64::from(reconstruction_threshold) {
            return Err(
                TallyPreparationError::AuthenticatedKeyShareVectorManifestDescriptorCountMismatch {
                    expected: usize::from(reconstruction_threshold),
                    actual: usize::try_from(descriptor_count)
                        .map_err(|_| TallyPreparationError::IntegerConversion)?,
                },
            );
        }
        let mut ordered_descriptor_identities = Vec::with_capacity(
            usize::try_from(descriptor_count)
                .map_err(|_| TallyPreparationError::IntegerConversion)?,
        );
        for expected_sender_position in 0..reconstruction_threshold {
            let sender_position = read_u16(&mut reader)?;
            if sender_position != expected_sender_position {
                return Err(TallyPreparationError::AuthenticatedKeyShareVectorManifestMismatch);
            }
            ordered_descriptor_identities
                .push(read_hash512(&mut reader, "manifest descriptor identity")?);
        }
        if !reader.is_finished() {
            return Err(TallyPreparationError::TrailingAuthenticatedKeyShareVectorManifestBytes);
        }
        Ok(Self {
            context_identity,
            holder_record_catalog_identity,
            share_vector_compiler_identity,
            manifest_compiler_identity,
            holder_commitment_root,
            participant_count,
            reconstruction_threshold,
            total_field_count,
            ordered_descriptor_identities: ordered_descriptor_identities.into_boxed_slice(),
        })
    }

    pub(crate) fn verify_source_and_descriptors(
        &self,
        context: TallyPreparationContext,
        circuit: &CompiledTallyCircuit,
        expected_holder_commitment_root: Hash512,
        descriptors: &[AuthenticatedKeyShareVectorDescriptor],
    ) -> Result<(), TallyPreparationError> {
        let expected = Self::derive(
            context,
            circuit,
            expected_holder_commitment_root,
            descriptors,
        )?;
        if *self != expected {
            return Err(TallyPreparationError::AuthenticatedKeyShareVectorManifestMismatch);
        }
        Ok(())
    }
}

/// Canonical unsigned acknowledgement body for one participant's complete
/// local check of the fixed-basis share vectors.
///
/// This body alone is only bytes. Honest creation must later consume the
/// verifier-owned all-field local-check result and one-shot state; public
/// acceptance additionally requires detached participant signatures for all
/// roster positions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuthenticatedKeyShareVectorAcknowledgementBody {
    manifest_identity: Hash512,
    participant_count: u16,
    participant_position: u16,
}

impl AuthenticatedKeyShareVectorAcknowledgementBody {
    pub(crate) fn unsigned_body_for_participant(
        manifest: &AuthenticatedKeyShareVectorManifest,
        participant_position: u16,
    ) -> Result<Self, TallyPreparationError> {
        if participant_position >= manifest.participant_count {
            return Err(TallyPreparationError::AuthenticatedKeyShareVectorAcknowledgementMismatch);
        }
        Ok(Self {
            manifest_identity: manifest.identity(),
            participant_count: manifest.participant_count,
            participant_position,
        })
    }

    pub(crate) const fn participant_position(self) -> u16 {
        self.participant_position
    }

    pub(crate) fn canonical_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::new();
        append_bytes(
            &mut bytes,
            AUTHENTICATED_KEY_SHARE_VECTOR_ACKNOWLEDGEMENT_MAGIC,
        );
        append_varuint(
            &mut bytes,
            AUTHENTICATED_KEY_SHARE_VECTOR_CONTROL_ARTIFACT_VERSION,
        );
        append_bytes(&mut bytes, self.manifest_identity.as_bytes());
        append_varuint(&mut bytes, u64::from(self.participant_count));
        append_varuint(&mut bytes, u64::from(self.participant_position));
        bytes
    }

    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, TallyPreparationError> {
        validate_control_body_byte_length(bytes)?;
        let mut reader = CanonicalReader::new(bytes);
        read_magic(
            &mut reader,
            AUTHENTICATED_KEY_SHARE_VECTOR_ACKNOWLEDGEMENT_MAGIC,
            TallyPreparationError::AuthenticatedKeyShareVectorAcknowledgementMagicMismatch,
        )?;
        read_acknowledgement_artifact_version(&mut reader)?;
        let manifest_identity = read_hash512(&mut reader, "acknowledgement manifest identity")?;
        let participant_count = read_u16(&mut reader)?;
        if derive_foundation_roster_parameters(participant_count).is_none() {
            return Err(TallyPreparationError::ParticipantCountOutOfRange { participant_count });
        }
        let participant_position = read_u16(&mut reader)?;
        if participant_position >= participant_count {
            return Err(TallyPreparationError::AuthenticatedKeyShareVectorAcknowledgementMismatch);
        }
        if !reader.is_finished() {
            return Err(
                TallyPreparationError::TrailingAuthenticatedKeyShareVectorAcknowledgementBytes,
            );
        }
        Ok(Self {
            manifest_identity,
            participant_count,
            participant_position,
        })
    }

    fn matches_manifest(self, manifest_identity: Hash512, participant_count: u16) -> bool {
        self.manifest_identity == manifest_identity && self.participant_count == participant_count
    }
}

/// Derives the common root of one exact all-roster acknowledgement-body set.
///
/// This function verifies canonical ordering and manifest binding only. It
/// verifies no detached signature, participant state, or honest local check
/// and returns no acceptance capability.
pub(crate) fn derive_authenticated_key_share_vector_acknowledgement_root(
    manifest: &AuthenticatedKeyShareVectorManifest,
    acknowledgement_bodies: &[AuthenticatedKeyShareVectorAcknowledgementBody],
) -> Result<Hash512, TallyPreparationError> {
    if acknowledgement_bodies.len() != usize::from(manifest.participant_count) {
        return Err(
            TallyPreparationError::AuthenticatedKeyShareVectorAcknowledgementCountMismatch {
                expected: usize::from(manifest.participant_count),
                actual: acknowledgement_bodies.len(),
            },
        );
    }
    let manifest_identity = manifest.identity();
    let mut hasher = StreamingHash512::new(
        AUTHENTICATED_KEY_SHARE_VECTOR_ACKNOWLEDGEMENT_ROOT_DOMAIN,
        2,
    );
    hasher.absorb_part(manifest_identity.as_bytes());
    let acknowledgement_payload_byte_length =
        acknowledgement_payload_byte_length(manifest.participant_count, manifest_identity)?;
    hasher.begin_part(acknowledgement_payload_byte_length);
    let encoded_acknowledgement_count = encode_varuint(
        u64::try_from(acknowledgement_bodies.len())
            .map_err(|_| TallyPreparationError::IntegerConversion)?,
    );
    hasher.absorb_raw(&encoded_acknowledgement_count);
    for (expected_participant_position, acknowledgement_body) in
        acknowledgement_bodies.iter().enumerate()
    {
        let expected_participant_position = u16::try_from(expected_participant_position)
            .map_err(|_| TallyPreparationError::IntegerConversion)?;
        if acknowledgement_body.participant_position != expected_participant_position
            || !acknowledgement_body.matches_manifest(manifest_identity, manifest.participant_count)
        {
            return Err(TallyPreparationError::AuthenticatedKeyShareVectorAcknowledgementMismatch);
        }
        let canonical_acknowledgement = acknowledgement_body.canonical_bytes();
        let framed_byte_length = encode_varuint(
            u64::try_from(canonical_acknowledgement.len())
                .map_err(|_| TallyPreparationError::IntegerConversion)?,
        );
        hasher.absorb_raw(&framed_byte_length);
        hasher.absorb_raw(&canonical_acknowledgement);
    }
    Ok(Hash512::from_bytes(hasher.finalize()))
}

pub(crate) fn authenticated_key_share_vector_manifest_canonical_byte_length(
    participant_count: u16,
    total_field_count: u64,
) -> Result<u64, TallyPreparationError> {
    let roster_parameters = derive_foundation_roster_parameters(participant_count)
        .ok_or(TallyPreparationError::ParticipantCountOutOfRange { participant_count })?;
    if total_field_count == 0 {
        return Err(TallyPreparationError::AuthenticatedKeyShareVectorManifestMismatch);
    }
    let reconstruction_threshold = u64::from(roster_parameters.reconstruction_threshold);
    let mut byte_length = framed_byte_length(
        u64::try_from(AUTHENTICATED_KEY_SHARE_VECTOR_MANIFEST_MAGIC.len())
            .map_err(|_| TallyPreparationError::IntegerConversion)?,
    )?;
    for value in [
        AUTHENTICATED_KEY_SHARE_VECTOR_CONTROL_ARTIFACT_VERSION,
        u64::from(participant_count),
        reconstruction_threshold,
        total_field_count,
        reconstruction_threshold,
    ] {
        byte_length = checked_add(byte_length, varuint_byte_length(value)?)?;
    }
    let framed_hash_byte_length = framed_byte_length(Hash512::BYTE_LENGTH as u64)?;
    byte_length = checked_add(byte_length, checked_multiply(5, framed_hash_byte_length)?)?;
    for sender_position in 0..reconstruction_threshold {
        byte_length = checked_add(
            byte_length,
            checked_add(
                varuint_byte_length(sender_position)?,
                framed_hash_byte_length,
            )?,
        )?;
    }
    Ok(byte_length)
}

pub(crate) fn authenticated_key_share_vector_acknowledgement_canonical_byte_length(
    participant_count: u16,
    participant_position: u16,
) -> Result<u64, TallyPreparationError> {
    if derive_foundation_roster_parameters(participant_count).is_none() {
        return Err(TallyPreparationError::ParticipantCountOutOfRange { participant_count });
    }
    if participant_position >= participant_count {
        return Err(TallyPreparationError::AuthenticatedKeyShareVectorAcknowledgementMismatch);
    }
    let mut byte_length = framed_byte_length(
        u64::try_from(AUTHENTICATED_KEY_SHARE_VECTOR_ACKNOWLEDGEMENT_MAGIC.len())
            .map_err(|_| TallyPreparationError::IntegerConversion)?,
    )?;
    byte_length = checked_add(
        byte_length,
        varuint_byte_length(AUTHENTICATED_KEY_SHARE_VECTOR_CONTROL_ARTIFACT_VERSION)?,
    )?;
    byte_length = checked_add(
        byte_length,
        framed_byte_length(Hash512::BYTE_LENGTH as u64)?,
    )?;
    byte_length = checked_add(
        byte_length,
        varuint_byte_length(u64::from(participant_count))?,
    )?;
    checked_add(
        byte_length,
        varuint_byte_length(u64::from(participant_position))?,
    )
}

pub(crate) fn authenticated_key_share_vector_manifest_compiler_identity()
-> Result<Hash512, TallyPreparationError> {
    authenticated_key_share_vector_manifest_compiler_identity_from_source(
        AUTHENTICATED_KEY_SHARE_VECTOR_MANIFEST_SOURCE,
    )
}

fn authenticated_key_share_vector_manifest_compiler_identity_from_source(
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
        AUTHENTICATED_KEY_SHARE_VECTOR_MANIFEST_COMPILER_IDENTITY_DOMAIN,
        &[
            source,
            &AUTHENTICATED_KEY_SHARE_VECTOR_CONTROL_ARTIFACT_VERSION.to_le_bytes(),
        ],
    )))
}

fn acknowledgement_payload_byte_length(
    participant_count: u16,
    manifest_identity: Hash512,
) -> Result<u64, TallyPreparationError> {
    let mut byte_length = varuint_byte_length(u64::from(participant_count))?;
    for participant_position in 0..participant_count {
        let acknowledgement = AuthenticatedKeyShareVectorAcknowledgementBody {
            manifest_identity,
            participant_count,
            participant_position,
        };
        byte_length = checked_add(
            byte_length,
            framed_byte_length(
                u64::try_from(acknowledgement.canonical_bytes().len())
                    .map_err(|_| TallyPreparationError::IntegerConversion)?,
            )?,
        )?;
    }
    Ok(byte_length)
}

fn validate_control_body_byte_length(bytes: &[u8]) -> Result<(), TallyPreparationError> {
    if bytes.is_empty() || bytes.len() > FOUNDATION_PROFILE.stream_chunk_byte_length {
        return Err(
            TallyPreparationError::AuthenticatedKeyShareVectorControlByteLengthOutOfRange {
                actual: bytes.len(),
                maximum: FOUNDATION_PROFILE.stream_chunk_byte_length,
            },
        );
    }
    Ok(())
}

fn read_magic(
    reader: &mut CanonicalReader<'_>,
    expected_magic: &[u8],
    mismatch_error: TallyPreparationError,
) -> Result<(), TallyPreparationError> {
    let actual_byte_length = usize::try_from(reader.read_varuint()?)
        .map_err(|_| TallyPreparationError::IntegerConversion)?;
    if actual_byte_length != expected_magic.len()
        || reader.read_exact(actual_byte_length)? != expected_magic
    {
        return Err(mismatch_error);
    }
    Ok(())
}

fn read_manifest_artifact_version(
    reader: &mut CanonicalReader<'_>,
) -> Result<(), TallyPreparationError> {
    let version = reader.read_varuint()?;
    if version != AUTHENTICATED_KEY_SHARE_VECTOR_CONTROL_ARTIFACT_VERSION {
        return Err(
            TallyPreparationError::UnsupportedAuthenticatedKeyShareVectorManifestVersion {
                version,
            },
        );
    }
    Ok(())
}

fn read_acknowledgement_artifact_version(
    reader: &mut CanonicalReader<'_>,
) -> Result<(), TallyPreparationError> {
    let version = reader.read_varuint()?;
    if version != AUTHENTICATED_KEY_SHARE_VECTOR_CONTROL_ARTIFACT_VERSION {
        return Err(
            TallyPreparationError::UnsupportedAuthenticatedKeyShareVectorAcknowledgementVersion {
                version,
            },
        );
    }
    Ok(())
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

fn checked_add(left: u64, right: u64) -> Result<u64, TallyPreparationError> {
    left.checked_add(right)
        .ok_or(TallyPreparationError::ArithmeticOverflow)
}

fn checked_multiply(left: u64, right: u64) -> Result<u64, TallyPreparationError> {
    left.checked_mul(right)
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

#[cfg(test)]
pub(crate) fn compiler_identity_from_source_for_test(
    source: &[u8],
) -> Result<Hash512, TallyPreparationError> {
    authenticated_key_share_vector_manifest_compiler_identity_from_source(source)
}
