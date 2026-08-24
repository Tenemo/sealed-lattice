use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use zeroize::Zeroizing;

use crate::{
    bgv::proof_suite::CommittedMaterialProfile,
    foundation::{
        ACTION_STORAGE_ROOT_BYTE_LENGTH, ActionPrivateRandomness, ActionStorageRoot,
        CanonicalDecodeLimits, Hash512, LocalRecordEnvelope, LocalRecordIdentifierInput,
        LocalRecordSealInput, LocalStorageBinding, ParticipantIdentity, RefusalReason,
    },
    hashing::hash_framed_parts_512,
    transcript_core::encode_hex,
};

use super::{
    generation_authority::SetupGeneratedCommittedMaterial,
    generation_population::SetupGenerationBindings,
};

const CHECKPOINT_DIRECTORY_NAME: &str = "selected-setup-source-generation-v1";
const CHECKPOINT_FILE_PREFIX: &str = "vss-material-";
const CHECKPOINT_FILE_SUFFIX: &str = ".record";
const CHECKPOINT_MAGIC: [u8; 8] = *b"SLVSSRC1";
const CHECKPOINT_VERSION: u16 = 1;
const CHECKPOINT_RECORD_VERSION: u64 = 0;
const PROFILE_COORDINATE_COUNT: usize = 6;
const CHECKPOINT_PLAINTEXT_BYTE_LENGTH: usize = CHECKPOINT_MAGIC.len()
    + size_of::<u16>()
    + size_of::<u32>()
    + PROFILE_COORDINATE_COUNT * size_of::<u64>()
    + 5 * Hash512::BYTE_LENGTH
    + size_of::<u64>();
const MAXIMUM_CHECKPOINT_ENVELOPE_BYTE_LENGTH: usize = 4_096;
const CHECKPOINT_BINDING_HASH_DOMAIN: &str =
    "sealed-lattice/test-evidence/setup-source-checkpoint-binding/v1";
const CHECKPOINT_MESSAGE_HASH_DOMAIN: &str =
    "sealed-lattice/test-evidence/setup-source-checkpoint-message/v1";
const CHECKPOINT_STORAGE_ROOT_HASH_DOMAIN: &str =
    "sealed-lattice/test-evidence/setup-source-checkpoint-storage-root/v1";
const CHECKPOINT_NONCE_HASH_DOMAIN: &str =
    "sealed-lattice/test-evidence/setup-source-checkpoint-nonce/v1";

pub(super) struct SetupVssEvidenceCheckpointStore {
    directory: Option<PathBuf>,
    action_storage_root: ActionStorageRoot,
    action_randomness_commitment: Hash512,
    checkpoint_binding_hash: [u8; Hash512::BYTE_LENGTH],
}

impl SetupVssEvidenceCheckpointStore {
    pub(super) fn open(
        bindings: &SetupGenerationBindings,
        action_private_randomness: &ActionPrivateRandomness,
        profile: CommittedMaterialProfile,
    ) -> Result<Self, String> {
        let repository_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| "resolve repository root for setup-source checkpoints".to_owned())?;
        let mut store = Self::from_binding(bindings, action_private_randomness, profile)?;
        let binding_directory_name = encode_hex(&store.checkpoint_binding_hash[..32]);
        let directory = repository_root
            .join("temp")
            .join("test-checkpoints")
            .join(CHECKPOINT_DIRECTORY_NAME)
            .join(binding_directory_name);
        fs::create_dir_all(&directory)
            .map_err(|error| format!("create setup-source checkpoint directory: {error}"))?;
        store.directory = Some(directory);
        Ok(store)
    }

    #[cfg(test)]
    pub(super) fn from_binding_without_filesystem(
        bindings: &SetupGenerationBindings,
        action_private_randomness: &ActionPrivateRandomness,
        profile: CommittedMaterialProfile,
    ) -> Result<Self, String> {
        Self::from_binding(bindings, action_private_randomness, profile)
    }

    fn from_binding(
        bindings: &SetupGenerationBindings,
        action_private_randomness: &ActionPrivateRandomness,
        profile: CommittedMaterialProfile,
    ) -> Result<Self, String> {
        let profile_coordinates = profile_coordinates(profile)?;
        let roster_position_bytes = bindings.roster_position.to_le_bytes();
        let checkpoint_binding_hash = hash_framed_parts_512(
            CHECKPOINT_BINDING_HASH_DOMAIN,
            &[
                &bindings.suite_identifier,
                &bindings.manifest_hash,
                &bindings.ceremony_context_hash,
                &bindings.action_context_hash,
                &bindings.roster_hash,
                &bindings.setup_proof_context_hash,
                &bindings.source_setup_intent_object_hash,
                &bindings.participant_identity,
                &roster_position_bytes,
                bindings.setup_attempt_identifier.as_bytes(),
                &bindings.action_randomness_authorization_hash,
                &bindings.public_setup_seed,
                &profile_coordinates,
            ],
        );
        let storage_root_digest = hash_framed_parts_512(
            CHECKPOINT_STORAGE_ROOT_HASH_DOMAIN,
            &[
                action_private_randomness.root().as_slice(),
                &checkpoint_binding_hash,
            ],
        );
        let mut storage_root_bytes = [0_u8; ACTION_STORAGE_ROOT_BYTE_LENGTH];
        storage_root_bytes.copy_from_slice(&storage_root_digest[..ACTION_STORAGE_ROOT_BYTE_LENGTH]);
        let local_storage_binding = LocalStorageBinding::new(
            Hash512::from_bytes(bindings.suite_identifier),
            Hash512::from_bytes(bindings.ceremony_context_hash),
            Hash512::from_bytes(bindings.action_context_hash),
            ParticipantIdentity::from_bytes(bindings.participant_identity),
        );
        let action_storage_root = ActionStorageRoot::from_verified_root(
            local_storage_binding,
            Zeroizing::new(storage_root_bytes),
        )
        .map_err(|error| {
            format!(
                "derive setup-source checkpoint storage root: {:?}",
                error.refusal_reason
            )
        })?;
        Ok(Self {
            directory: None,
            action_storage_root,
            action_randomness_commitment: action_private_randomness.action_randomness_commitment(),
            checkpoint_binding_hash,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn restore_or_construct(
        &self,
        material_ordinal: u32,
        profile: CommittedMaterialProfile,
        material_context_hash: [u8; Hash512::BYTE_LENGTH],
        material_seed: [u8; Hash512::BYTE_LENGTH],
        canonical_message: &[u64],
        canonical_modulus: u64,
        construct: impl FnOnce() -> Result<SetupGeneratedCommittedMaterial, RefusalReason>,
    ) -> Result<SetupGeneratedCommittedMaterial, String> {
        let path = self.checkpoint_path(material_ordinal)?;
        match path.try_exists() {
            Ok(true) => {
                let encoded = read_bounded_checkpoint_file(&path)?;
                let restored = self.restore_checkpoint_record(
                    &encoded,
                    material_ordinal,
                    profile,
                    material_context_hash,
                    material_seed,
                    canonical_message,
                    canonical_modulus,
                )?;
                println!(
                    "setup VSS material checkpoint restored: ordinal={material_ordinal}, path={}",
                    path.display()
                );
                Ok(restored)
            }
            Ok(false) => {
                let material = construct().map_err(|error| {
                    format!("construct setup VSS material {material_ordinal}: {error:?}")
                })?;
                let encoded = self.seal_checkpoint_record(
                    &material,
                    material_ordinal,
                    profile,
                    material_context_hash,
                    material_seed,
                    canonical_message,
                    canonical_modulus,
                )?;
                persist_exact_checkpoint_file_once(&path, &encoded)?;
                println!(
                    "setup VSS material checkpoint persisted: ordinal={material_ordinal}, path={}",
                    path.display()
                );
                Ok(material)
            }
            Err(error) => Err(format!(
                "inspect setup VSS material checkpoint {}: {error}",
                path.display()
            )),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn seal_checkpoint_record(
        &self,
        material: &SetupGeneratedCommittedMaterial,
        material_ordinal: u32,
        profile: CommittedMaterialProfile,
        material_context_hash: [u8; Hash512::BYTE_LENGTH],
        material_seed: [u8; Hash512::BYTE_LENGTH],
        canonical_message: &[u64],
        canonical_modulus: u64,
    ) -> Result<Vec<u8>, String> {
        let compact_source = material.compact_source();
        if compact_source.profile() != profile
            || compact_source.material_context_hash() != material_context_hash
            || compact_source.root() == [0_u8; Hash512::BYTE_LENGTH]
        {
            return Err(
                "constructed setup VSS material differs from its checkpoint coordinates".to_owned(),
            );
        }
        let plaintext = self.checkpoint_plaintext(
            material_ordinal,
            profile,
            material_context_hash,
            material_seed,
            compact_source.root(),
            canonical_message,
            canonical_modulus,
        )?;
        let nonce_digest = hash_framed_parts_512(
            CHECKPOINT_NONCE_HASH_DOMAIN,
            &[
                &self.checkpoint_binding_hash,
                &material_ordinal.to_le_bytes(),
                &material_context_hash,
            ],
        );
        let mut nonce = [0_u8; 12];
        nonce.copy_from_slice(&nonce_digest[..12]);
        let envelope = self
            .action_storage_root
            .seal_local_record(LocalRecordSealInput {
                action_randomness_commitment: self.action_randomness_commitment,
                identifier_input: LocalRecordIdentifierInput::SourceVssMaterial {
                    material_context_hash: Hash512::from_bytes(material_context_hash),
                },
                record_version: CHECKPOINT_RECORD_VERSION,
                predecessor_record_hash: None,
                nonce,
                plaintext: &plaintext,
            })
            .map_err(|error| {
                format!(
                    "seal setup VSS material checkpoint: {:?}",
                    error.refusal_reason
                )
            })?;
        envelope.encode().map_err(|error| {
            format!(
                "encode setup VSS material checkpoint: {:?}",
                error.refusal_reason
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn restore_checkpoint_record(
        &self,
        encoded: &[u8],
        material_ordinal: u32,
        profile: CommittedMaterialProfile,
        material_context_hash: [u8; Hash512::BYTE_LENGTH],
        material_seed: [u8; Hash512::BYTE_LENGTH],
        canonical_message: &[u64],
        canonical_modulus: u64,
    ) -> Result<SetupGeneratedCommittedMaterial, String> {
        if encoded.is_empty() || encoded.len() > MAXIMUM_CHECKPOINT_ENVELOPE_BYTE_LENGTH {
            return Err("setup VSS material checkpoint has a noncanonical extent".to_owned());
        }
        let envelope = LocalRecordEnvelope::decode(encoded, &CanonicalDecodeLimits::default())
            .map_err(|error| {
                format!(
                    "decode setup VSS material checkpoint: {:?}",
                    error.refusal_reason
                )
            })?;
        let plaintext = self
            .action_storage_root
            .open_local_record(
                self.action_randomness_commitment,
                LocalRecordIdentifierInput::SourceVssMaterial {
                    material_context_hash: Hash512::from_bytes(material_context_hash),
                },
                CHECKPOINT_RECORD_VERSION,
                None,
                &envelope,
            )
            .into_result()
            .map_err(|error| format!("authenticate setup VSS material checkpoint: {error:?}"))?;
        let decoded = decode_checkpoint_plaintext(&plaintext)?;
        let expected_profile_coordinates = profile_coordinates(profile)?;
        let expected_message_digest = checkpoint_message_digest(
            self.checkpoint_binding_hash,
            material_context_hash,
            material_seed,
            canonical_message,
            canonical_modulus,
        )?;
        if decoded.material_ordinal != material_ordinal
            || decoded.profile_coordinates != expected_profile_coordinates
            || decoded.checkpoint_binding_hash != self.checkpoint_binding_hash
            || decoded.material_context_hash != material_context_hash
            || decoded.material_seed != material_seed
            || decoded.canonical_modulus != canonical_modulus
            || decoded.canonical_message_digest != expected_message_digest
            || decoded.root == [0_u8; Hash512::BYTE_LENGTH]
        {
            return Err(
                "setup VSS material checkpoint differs from the deterministic source".to_owned(),
            );
        }
        SetupGeneratedCommittedMaterial::from_authenticated_evidence_record_and_canonical_message(
            profile,
            material_context_hash,
            material_seed,
            decoded.root,
            Zeroizing::new(canonical_message.to_vec().into_boxed_slice()),
            canonical_modulus,
        )
        .map_err(|error| format!("restore setup VSS material checkpoint source: {error:?}"))
    }

    #[allow(clippy::too_many_arguments)]
    fn checkpoint_plaintext(
        &self,
        material_ordinal: u32,
        profile: CommittedMaterialProfile,
        material_context_hash: [u8; Hash512::BYTE_LENGTH],
        material_seed: [u8; Hash512::BYTE_LENGTH],
        root: [u8; Hash512::BYTE_LENGTH],
        canonical_message: &[u64],
        canonical_modulus: u64,
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        let profile_coordinates = profile_coordinates(profile)?;
        let message_digest = checkpoint_message_digest(
            self.checkpoint_binding_hash,
            material_context_hash,
            material_seed,
            canonical_message,
            canonical_modulus,
        )?;
        let mut plaintext = Zeroizing::new(Vec::with_capacity(CHECKPOINT_PLAINTEXT_BYTE_LENGTH));
        plaintext.extend_from_slice(&CHECKPOINT_MAGIC);
        plaintext.extend_from_slice(&CHECKPOINT_VERSION.to_le_bytes());
        plaintext.extend_from_slice(&material_ordinal.to_le_bytes());
        plaintext.extend_from_slice(&profile_coordinates);
        plaintext.extend_from_slice(&self.checkpoint_binding_hash);
        plaintext.extend_from_slice(&material_context_hash);
        plaintext.extend_from_slice(&material_seed);
        plaintext.extend_from_slice(&root);
        plaintext.extend_from_slice(&canonical_modulus.to_le_bytes());
        plaintext.extend_from_slice(&message_digest);
        if plaintext.len() != CHECKPOINT_PLAINTEXT_BYTE_LENGTH {
            return Err("setup VSS material checkpoint length drifted".to_owned());
        }
        Ok(plaintext)
    }

    fn checkpoint_path(&self, material_ordinal: u32) -> Result<PathBuf, String> {
        let directory = self.directory.as_ref().ok_or_else(|| {
            "setup VSS material checkpoint store has no filesystem owner".to_owned()
        })?;
        Ok(directory.join(format!(
            "{CHECKPOINT_FILE_PREFIX}{material_ordinal:04}{CHECKPOINT_FILE_SUFFIX}"
        )))
    }
}

struct DecodedCheckpointPlaintext {
    material_ordinal: u32,
    profile_coordinates: [u8; PROFILE_COORDINATE_COUNT * size_of::<u64>()],
    checkpoint_binding_hash: [u8; Hash512::BYTE_LENGTH],
    material_context_hash: [u8; Hash512::BYTE_LENGTH],
    material_seed: [u8; Hash512::BYTE_LENGTH],
    root: [u8; Hash512::BYTE_LENGTH],
    canonical_modulus: u64,
    canonical_message_digest: [u8; Hash512::BYTE_LENGTH],
}

fn decode_checkpoint_plaintext(bytes: &[u8]) -> Result<DecodedCheckpointPlaintext, String> {
    if bytes.len() != CHECKPOINT_PLAINTEXT_BYTE_LENGTH
        || bytes[..CHECKPOINT_MAGIC.len()] != CHECKPOINT_MAGIC
    {
        return Err("setup VSS material checkpoint plaintext is malformed".to_owned());
    }
    let mut offset = CHECKPOINT_MAGIC.len();
    let version = read_array::<{ size_of::<u16>() }>(bytes, &mut offset)?;
    if u16::from_le_bytes(version) != CHECKPOINT_VERSION {
        return Err("setup VSS material checkpoint version is unsupported".to_owned());
    }
    let material_ordinal = u32::from_le_bytes(read_array(bytes, &mut offset)?);
    let profile_coordinates = read_array(bytes, &mut offset)?;
    let checkpoint_binding_hash = read_array(bytes, &mut offset)?;
    let material_context_hash = read_array(bytes, &mut offset)?;
    let material_seed = read_array(bytes, &mut offset)?;
    let root = read_array(bytes, &mut offset)?;
    let canonical_modulus = u64::from_le_bytes(read_array(bytes, &mut offset)?);
    let canonical_message_digest = read_array(bytes, &mut offset)?;
    if offset != bytes.len() {
        return Err("setup VSS material checkpoint has trailing plaintext".to_owned());
    }
    Ok(DecodedCheckpointPlaintext {
        material_ordinal,
        profile_coordinates,
        checkpoint_binding_hash,
        material_context_hash,
        material_seed,
        root,
        canonical_modulus,
        canonical_message_digest,
    })
}

fn read_array<const BYTE_LENGTH: usize>(
    bytes: &[u8],
    offset: &mut usize,
) -> Result<[u8; BYTE_LENGTH], String> {
    let end = offset
        .checked_add(BYTE_LENGTH)
        .ok_or_else(|| "setup VSS material checkpoint offset overflowed".to_owned())?;
    let value = bytes
        .get(*offset..end)
        .ok_or_else(|| "setup VSS material checkpoint is truncated".to_owned())?
        .try_into()
        .map_err(|_| "setup VSS material checkpoint field has the wrong length".to_owned())?;
    *offset = end;
    Ok(value)
}

fn profile_coordinates(
    profile: CommittedMaterialProfile,
) -> Result<[u8; PROFILE_COORDINATE_COUNT * size_of::<u64>()], String> {
    let coordinates = [
        profile.trace_domain_size(),
        profile.evaluation_domain_size(),
        usize::try_from(profile.evaluation_coset_offset())
            .map_err(|_| "setup VSS profile coset offset exceeds usize".to_owned())?,
        profile.masking_polynomial_maximum_degree(),
        profile.committed_polynomial_degree_bound_exclusive(),
        profile.material_column_degree_bound_exclusive(),
    ];
    let mut encoded = [0_u8; PROFILE_COORDINATE_COUNT * size_of::<u64>()];
    for (coordinate_index, coordinate) in coordinates.into_iter().enumerate() {
        let coordinate = u64::try_from(coordinate)
            .map_err(|_| "setup VSS checkpoint profile coordinate exceeds u64".to_owned())?;
        let start = coordinate_index * size_of::<u64>();
        encoded[start..start + size_of::<u64>()].copy_from_slice(&coordinate.to_le_bytes());
    }
    Ok(encoded)
}

fn checkpoint_message_digest(
    checkpoint_binding_hash: [u8; Hash512::BYTE_LENGTH],
    material_context_hash: [u8; Hash512::BYTE_LENGTH],
    material_seed: [u8; Hash512::BYTE_LENGTH],
    canonical_message: &[u64],
    canonical_modulus: u64,
) -> Result<[u8; Hash512::BYTE_LENGTH], String> {
    let byte_length = canonical_message
        .len()
        .checked_mul(size_of::<u64>())
        .ok_or_else(|| "setup VSS checkpoint message length overflowed".to_owned())?;
    let mut canonical_message_bytes = Zeroizing::new(Vec::with_capacity(byte_length));
    for coefficient in canonical_message {
        canonical_message_bytes.extend_from_slice(&coefficient.to_le_bytes());
    }
    Ok(hash_framed_parts_512(
        CHECKPOINT_MESSAGE_HASH_DOMAIN,
        &[
            &checkpoint_binding_hash,
            &material_context_hash,
            &material_seed,
            &canonical_modulus.to_le_bytes(),
            &canonical_message_bytes,
        ],
    ))
}

fn read_bounded_checkpoint_file(path: &Path) -> Result<Vec<u8>, String> {
    let file = File::open(path).map_err(|error| {
        format!(
            "open setup VSS material checkpoint {}: {error}",
            path.display()
        )
    })?;
    let declared_byte_length = usize::try_from(
        file.metadata()
            .map_err(|error| {
                format!(
                    "inspect setup VSS material checkpoint {}: {error}",
                    path.display()
                )
            })?
            .len(),
    )
    .map_err(|_| "setup VSS material checkpoint length exceeds usize".to_owned())?;
    if declared_byte_length == 0 || declared_byte_length > MAXIMUM_CHECKPOINT_ENVELOPE_BYTE_LENGTH {
        return Err("setup VSS material checkpoint has a noncanonical file length".to_owned());
    }
    let mut bytes = Vec::with_capacity(declared_byte_length);
    file.take((MAXIMUM_CHECKPOINT_ENVELOPE_BYTE_LENGTH + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            format!(
                "read setup VSS material checkpoint {}: {error}",
                path.display()
            )
        })?;
    if bytes.len() != declared_byte_length {
        return Err("setup VSS material checkpoint changed while it was read".to_owned());
    }
    Ok(bytes)
}

fn persist_exact_checkpoint_file_once(path: &Path, bytes: &[u8]) -> Result<(), String> {
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut file) => {
            file.write_all(bytes).map_err(|error| {
                format!(
                    "write setup VSS material checkpoint {}: {error}",
                    path.display()
                )
            })?;
            file.sync_all().map_err(|error| {
                format!(
                    "durably seal setup VSS material checkpoint {}: {error}",
                    path.display()
                )
            })
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = read_bounded_checkpoint_file(path)?;
            if existing != bytes {
                return Err(format!(
                    "existing setup VSS material checkpoint {} differs from deterministic replay",
                    path.display()
                ));
            }
            Ok(())
        }
        Err(error) => Err(format!(
            "create setup VSS material checkpoint {}: {error}",
            path.display()
        )),
    }
}
