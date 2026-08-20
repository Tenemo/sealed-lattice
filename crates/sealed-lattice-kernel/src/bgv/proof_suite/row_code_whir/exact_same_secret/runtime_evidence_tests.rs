use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    mem::size_of,
    path::{Path, PathBuf},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use super::super::{AUTOMATIC_ROW_CODE_WHIR_PROOF_ACCEPTANCE_BYTE_LENGTH, GOLDILOCKS_MODULUS};
use super::exact_proof::{
    ExactProofHostileMutationTarget, ExactProofHostileMutationTargetKind,
    ExactSameSecretVerificationMetrics, exact_same_secret_hostile_mutation_targets,
};
use super::*;
use crate::{
    bgv::{
        proof_suite::{
            AuthenticatedCommonProofGenerationCheckpoint,
            COMMON_PROOF_CHECKPOINT_STATE_BYTE_LENGTH, CommonProofGenerationSources,
            CommonProofGenerationStage, CommonProofGenerationWorkerPoll, CommonProofRuntimeLimits,
            CommonProofRuntimeRegistry, CommonProofVerificationWorkerPoll,
            ConsumedVerifiedCommonProofCapability, MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH,
            MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
            MAXIMUM_COMMON_PROOF_GENERATION_CURSOR_MANIFEST_BYTE_LENGTH, ProofExternalMemoryObject,
            ProofExternalMemoryProtection, ProofExternalMemoryTransactionOperation,
            ProofExternalMemoryTransactionRequest, RelationProofTreeInput, RelationTreeDescriptor,
            VerifiedCommonProofStatementSource, VerifiedStatementOwnedTree,
        },
        setup::{SetupKeyRelationProofFamily, VerifiedPublicRandomness},
    },
    foundation::{Hash512, ProofApplicationSlot, StreamDescriptor},
    hashing::hash_framed_parts_512,
};

const VSS_PREREQUISITE_CHECKPOINT_DIRECTORY_NAME: &str =
    "selected-vss-prerequisite-proof-generation-v1";
const EXACT_AGGREGATE_CHECKPOINT_DIRECTORY_NAME: &str =
    "exact-aggregate-wide-same-secret-proof-generation-v1";
const VSS_PREREQUISITE_CHECKPOINT_SEAL_MAGIC: [u8; 8] = *b"SLVSSCP1";
const EXACT_AGGREGATE_CHECKPOINT_SEAL_MAGIC: [u8; 8] = *b"SLEXACP1";
const COMMON_PROOF_CHECKPOINT_SEAL_VERSION: u16 = 1;
const COMMON_PROOF_CHECKPOINT_FILE_PREFIX: &str = "checkpoint-";
const COMMON_PROOF_CHECKPOINT_STATE_SUFFIX: &str = ".state";
const COMMON_PROOF_CHECKPOINT_CURSOR_SUFFIX: &str = ".cursor";
const COMMON_PROOF_CHECKPOINT_SEAL_SUFFIX: &str = ".seal";
const INITIAL_PHASE_COMMITMENT_LANE_CHECKPOINT_FILE_PREFIX: &str = "initial-phase-";
const INITIAL_PHASE_COMMITMENT_LANE_CHECKPOINT_STATE_SUFFIX: &str = ".state";
const INITIAL_PHASE_COMMITMENT_LANE_CHECKPOINT_SEAL_SUFFIX: &str = ".seal";
const INITIAL_PHASE_COMMITMENT_LANE_CHECKPOINT_SEAL_MAGIC: [u8; 8] = *b"SLPHLCP1";
const INITIAL_PHASE_COMMITMENT_LANE_CHECKPOINT_SEAL_VERSION: u16 = 1;
const INITIAL_PHASE_COMMITMENT_LANE_CHECKPOINT_INTERVAL: u32 = 4;
const MAXIMUM_INITIAL_PHASE_COMMITMENT_LANE_CHECKPOINT_BYTE_LENGTH: usize = 256 * 1_024 * 1_024;
const INITIAL_PHASE_COMMITMENT_LANE_CHECKPOINT_SEAL_BYTE_LENGTH: usize =
    INITIAL_PHASE_COMMITMENT_LANE_CHECKPOINT_SEAL_MAGIC.len()
        + size_of::<u16>()
        + 2 * size_of::<u8>()
        + size_of::<u32>()
        + Hash512::BYTE_LENGTH
        + 32
        + Hash512::BYTE_LENGTH;
const INITIAL_PHASE_COMMITMENT_LANE_CHECKPOINT_HASH_ROLE: &[u8] =
    b"initial-phase-commitment-lane-checkpoint";
const QUOTIENT_CONSTRAINT_CHECKPOINT_FILE_PREFIX: &str = "quotient-constraint-";
const QUOTIENT_CONSTRAINT_CHECKPOINT_STATE_SUFFIX: &str = ".state";
const QUOTIENT_CONSTRAINT_CHECKPOINT_SEAL_SUFFIX: &str = ".seal";
const QUOTIENT_CONSTRAINT_CHECKPOINT_SEAL_MAGIC: [u8; 8] = *b"SLQCNCP1";
const QUOTIENT_CONSTRAINT_CHECKPOINT_SEAL_VERSION: u16 = 1;
const QUOTIENT_CONSTRAINT_CHECKPOINT_INTERVAL: u32 = 64;
const MAXIMUM_QUOTIENT_CONSTRAINT_CHECKPOINT_BYTE_LENGTH: usize = 16 * 1_024 * 1_024;
const QUOTIENT_CONSTRAINT_CHECKPOINT_SEAL_BYTE_LENGTH: usize =
    QUOTIENT_CONSTRAINT_CHECKPOINT_SEAL_MAGIC.len()
        + 2 * size_of::<u16>()
        + size_of::<u32>()
        + Hash512::BYTE_LENGTH
        + 32
        + Hash512::BYTE_LENGTH;
const QUOTIENT_CONSTRAINT_CHECKPOINT_HASH_ROLE: &[u8] = b"quotient-constraint-checkpoint";
const CONTROLLED_QUOTIENT_CONSTRAINT_CHECKPOINT_STOP_OUTPUT_PREFIX: &str =
    "sealed-lattice-controlled-quotient-constraint-checkpoint-stop ";
const COMMON_PROOF_CHECKPOINT_SEAL_BYTE_LENGTH: usize = VSS_PREREQUISITE_CHECKPOINT_SEAL_MAGIC
    .len()
    + size_of::<u16>()
    + size_of::<u32>()
    + Hash512::BYTE_LENGTH
    + 32
    + Hash512::BYTE_LENGTH
    + Hash512::BYTE_LENGTH
    + Hash512::BYTE_LENGTH;
const VSS_PREREQUISITE_CHECKPOINT_STATE_HASH_DOMAIN: &str =
    "sealed-lattice/test-evidence/vss-prerequisite-checkpoint-state/v1";
const VSS_PREREQUISITE_CHECKPOINT_CURSOR_HASH_DOMAIN: &str =
    "sealed-lattice/test-evidence/vss-prerequisite-checkpoint-cursor/v1";
const EXACT_AGGREGATE_CHECKPOINT_STATE_HASH_DOMAIN: &str =
    "sealed-lattice/test-evidence/exact-aggregate-wide-checkpoint-state/v1";
const EXACT_AGGREGATE_CHECKPOINT_CURSOR_HASH_DOMAIN: &str =
    "sealed-lattice/test-evidence/exact-aggregate-wide-checkpoint-cursor/v1";

#[derive(Clone, Copy)]
struct DurableCommonProofCheckpointProfile {
    directory_name: &'static str,
    seal_magic: [u8; 8],
    state_hash_domain: &'static str,
    cursor_hash_domain: &'static str,
}

const VSS_PREREQUISITE_CHECKPOINT_PROFILE: DurableCommonProofCheckpointProfile =
    DurableCommonProofCheckpointProfile {
        directory_name: VSS_PREREQUISITE_CHECKPOINT_DIRECTORY_NAME,
        seal_magic: VSS_PREREQUISITE_CHECKPOINT_SEAL_MAGIC,
        state_hash_domain: VSS_PREREQUISITE_CHECKPOINT_STATE_HASH_DOMAIN,
        cursor_hash_domain: VSS_PREREQUISITE_CHECKPOINT_CURSOR_HASH_DOMAIN,
    };
const EXACT_AGGREGATE_CHECKPOINT_PROFILE: DurableCommonProofCheckpointProfile =
    DurableCommonProofCheckpointProfile {
        directory_name: EXACT_AGGREGATE_CHECKPOINT_DIRECTORY_NAME,
        seal_magic: EXACT_AGGREGATE_CHECKPOINT_SEAL_MAGIC,
        state_hash_domain: EXACT_AGGREGATE_CHECKPOINT_STATE_HASH_DOMAIN,
        cursor_hash_domain: EXACT_AGGREGATE_CHECKPOINT_CURSOR_HASH_DOMAIN,
    };

#[derive(Debug)]
struct FileBackedObject {
    path: PathBuf,
    exact_byte_length: u64,
    protection: ProofExternalMemoryProtection,
    sealed: bool,
}

struct FileBackedExternalMemory {
    directory: PathBuf,
    objects: BTreeMap<ProofExternalMemoryObject, FileBackedObject>,
    next_file_identifier: u64,
    current_declared_byte_length: u64,
    maximum_declared_byte_length: u64,
}

struct DurableCommonProofCheckpoint {
    authenticated: AuthenticatedCommonProofGenerationCheckpoint,
    boundary_ordinal: u32,
    state: Vec<u8>,
    cursor_manifest: Vec<u8>,
}

struct DurableInitialPhaseCommitmentLaneCheckpoint {
    phase_ordinal: u8,
    completed_lane_count: u32,
    state: Vec<u8>,
}

struct DurableQuotientConstraintCheckpoint {
    completed_constraint_count: u32,
    state: Vec<u8>,
}

struct DurableCommonProofCheckpointStore {
    directory: PathBuf,
    profile: DurableCommonProofCheckpointProfile,
    stable_attempt_binding_hash: [u8; Hash512::BYTE_LENGTH],
    checkpoint_lineage_identifier: [u8; 32],
}

impl DurableCommonProofCheckpointStore {
    fn open(
        prepared: &PreparedCommonProofGeneration,
        profile: DurableCommonProofCheckpointProfile,
    ) -> Result<Self, String> {
        let repository_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| "resolve repository root for proof checkpoint custody".to_owned())?;
        let stable_attempt_binding_hash = prepared.runtime_binding_hash();
        let binding_directory_name = stable_attempt_binding_hash
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let directory = repository_root
            .join("temp")
            .join("test-checkpoints")
            .join(profile.directory_name)
            .join(binding_directory_name);
        fs::create_dir_all(&directory)
            .map_err(|error| format!("create proof checkpoint custody directory: {error}"))?;
        Ok(Self {
            directory,
            profile,
            stable_attempt_binding_hash,
            checkpoint_lineage_identifier: prepared.checkpoint_lineage_identifier(),
        })
    }

    fn load_latest(&self) -> Result<Option<DurableCommonProofCheckpoint>, String> {
        let mut latest_boundary_ordinal = None;
        for entry in fs::read_dir(&self.directory)
            .map_err(|error| format!("enumerate retained proof checkpoints: {error}"))?
        {
            let entry =
                entry.map_err(|error| format!("read retained proof checkpoint entry: {error}"))?;
            if !entry
                .file_type()
                .map_err(|error| format!("classify retained proof checkpoint entry: {error}"))?
                .is_file()
            {
                return Err("proof checkpoint custody contains a non-file entry".to_owned());
            }
            let file_name = entry.file_name().into_string().map_err(|_| {
                "proof checkpoint custody contains a non-Unicode filename".to_owned()
            })?;
            if file_name.starts_with(INITIAL_PHASE_COMMITMENT_LANE_CHECKPOINT_FILE_PREFIX) {
                continue;
            }
            if file_name.starts_with(QUOTIENT_CONSTRAINT_CHECKPOINT_FILE_PREFIX) {
                continue;
            }
            if !file_name.ends_with(COMMON_PROOF_CHECKPOINT_SEAL_SUFFIX) {
                continue;
            }
            let boundary_ordinal =
                parse_common_proof_checkpoint_boundary(&file_name).ok_or_else(|| {
                    format!("proof checkpoint custody contains malformed seal {file_name}")
                })?;
            latest_boundary_ordinal = Some(
                latest_boundary_ordinal.map_or(boundary_ordinal, |current: u32| {
                    current.max(boundary_ordinal)
                }),
            );
        }
        latest_boundary_ordinal
            .map(|boundary_ordinal| self.load(boundary_ordinal))
            .transpose()
    }

    fn load(&self, boundary_ordinal: u32) -> Result<DurableCommonProofCheckpoint, String> {
        let state = read_exact_bounded_file(
            &self.checkpoint_path(boundary_ordinal, COMMON_PROOF_CHECKPOINT_STATE_SUFFIX),
            COMMON_PROOF_CHECKPOINT_STATE_BYTE_LENGTH,
            COMMON_PROOF_CHECKPOINT_STATE_BYTE_LENGTH,
            "proof checkpoint state",
        )?;
        let cursor_manifest = read_exact_bounded_file(
            &self.checkpoint_path(boundary_ordinal, COMMON_PROOF_CHECKPOINT_CURSOR_SUFFIX),
            1,
            MAXIMUM_COMMON_PROOF_GENERATION_CURSOR_MANIFEST_BYTE_LENGTH,
            "proof checkpoint cursor manifest",
        )?;
        let seal = read_exact_bounded_file(
            &self.checkpoint_path(boundary_ordinal, COMMON_PROOF_CHECKPOINT_SEAL_SUFFIX),
            COMMON_PROOF_CHECKPOINT_SEAL_BYTE_LENGTH,
            COMMON_PROOF_CHECKPOINT_SEAL_BYTE_LENGTH,
            "proof checkpoint seal",
        )?;
        let authenticated =
            AuthenticatedCommonProofGenerationCheckpoint::decode(&state, &cursor_manifest)
                .map_err(|error| format!("decode retained proof checkpoint: {error:?}"))?;
        self.require_checkpoint_binding(&authenticated, boundary_ordinal)?;
        let expected_seal = encode_common_proof_checkpoint_seal(
            self.profile,
            &authenticated,
            &state,
            &cursor_manifest,
        );
        if seal != expected_seal {
            return Err("retained proof checkpoint seal is stale or malformed".to_owned());
        }
        Ok(DurableCommonProofCheckpoint {
            authenticated,
            boundary_ordinal,
            state,
            cursor_manifest,
        })
    }

    fn persist(
        &self,
        boundary_ordinal: u32,
        state: &[u8],
        cursor_manifest: &[u8],
    ) -> Result<(), String> {
        if state.len() != COMMON_PROOF_CHECKPOINT_STATE_BYTE_LENGTH
            || cursor_manifest.is_empty()
            || cursor_manifest.len() > MAXIMUM_COMMON_PROOF_GENERATION_CURSOR_MANIFEST_BYTE_LENGTH
        {
            return Err("pending proof checkpoint exceeds its canonical custody bounds".to_owned());
        }
        let authenticated =
            AuthenticatedCommonProofGenerationCheckpoint::decode(state, cursor_manifest)
                .map_err(|error| format!("decode pending proof checkpoint: {error:?}"))?;
        self.require_checkpoint_binding(&authenticated, boundary_ordinal)?;
        persist_exact_file_once(
            &self.checkpoint_path(boundary_ordinal, COMMON_PROOF_CHECKPOINT_STATE_SUFFIX),
            state,
            "proof checkpoint state",
        )?;
        persist_exact_file_once(
            &self.checkpoint_path(boundary_ordinal, COMMON_PROOF_CHECKPOINT_CURSOR_SUFFIX),
            cursor_manifest,
            "proof checkpoint cursor manifest",
        )?;
        let seal = encode_common_proof_checkpoint_seal(
            self.profile,
            &authenticated,
            state,
            cursor_manifest,
        );
        persist_exact_file_once(
            &self.checkpoint_path(boundary_ordinal, COMMON_PROOF_CHECKPOINT_SEAL_SUFFIX),
            &seal,
            "proof checkpoint seal",
        )
    }

    fn load_initial_phase_commitment_lane_checkpoints(
        &self,
    ) -> Result<BTreeMap<u8, DurableInitialPhaseCommitmentLaneCheckpoint>, String> {
        let mut latest_coordinates = BTreeMap::<u8, u32>::new();
        for entry in fs::read_dir(&self.directory)
            .map_err(|error| format!("enumerate retained phase checkpoints: {error}"))?
        {
            let entry =
                entry.map_err(|error| format!("read retained phase checkpoint entry: {error}"))?;
            if !entry
                .file_type()
                .map_err(|error| format!("classify retained phase checkpoint entry: {error}"))?
                .is_file()
            {
                return Err("proof checkpoint custody contains a non-file entry".to_owned());
            }
            let file_name = entry.file_name().into_string().map_err(|_| {
                "proof checkpoint custody contains a non-Unicode filename".to_owned()
            })?;
            if !file_name.starts_with(INITIAL_PHASE_COMMITMENT_LANE_CHECKPOINT_FILE_PREFIX) {
                continue;
            }
            if !file_name.ends_with(INITIAL_PHASE_COMMITMENT_LANE_CHECKPOINT_SEAL_SUFFIX) {
                continue;
            }
            let (phase_ordinal, completed_lane_count) =
                parse_initial_phase_commitment_lane_checkpoint_coordinates(&file_name).ok_or_else(
                    || format!("proof checkpoint custody contains malformed seal {file_name}"),
                )?;
            latest_coordinates
                .entry(phase_ordinal)
                .and_modify(|current| *current = (*current).max(completed_lane_count))
                .or_insert(completed_lane_count);
        }
        latest_coordinates
            .into_iter()
            .map(|(phase_ordinal, completed_lane_count)| {
                self.load_initial_phase_commitment_lane_checkpoint(
                    phase_ordinal,
                    completed_lane_count,
                )
                .map(|checkpoint| (phase_ordinal, checkpoint))
            })
            .collect()
    }

    fn load_initial_phase_commitment_lane_checkpoint(
        &self,
        phase_ordinal: u8,
        completed_lane_count: u32,
    ) -> Result<DurableInitialPhaseCommitmentLaneCheckpoint, String> {
        validate_initial_phase_commitment_lane_checkpoint_coordinates(
            phase_ordinal,
            completed_lane_count,
        )?;
        let state = read_exact_bounded_file(
            &self.initial_phase_commitment_lane_checkpoint_path(
                phase_ordinal,
                completed_lane_count,
                INITIAL_PHASE_COMMITMENT_LANE_CHECKPOINT_STATE_SUFFIX,
            ),
            1,
            MAXIMUM_INITIAL_PHASE_COMMITMENT_LANE_CHECKPOINT_BYTE_LENGTH,
            "initial phase commitment lane checkpoint state",
        )?;
        let seal = read_exact_bounded_file(
            &self.initial_phase_commitment_lane_checkpoint_path(
                phase_ordinal,
                completed_lane_count,
                INITIAL_PHASE_COMMITMENT_LANE_CHECKPOINT_SEAL_SUFFIX,
            ),
            INITIAL_PHASE_COMMITMENT_LANE_CHECKPOINT_SEAL_BYTE_LENGTH,
            INITIAL_PHASE_COMMITMENT_LANE_CHECKPOINT_SEAL_BYTE_LENGTH,
            "initial phase commitment lane checkpoint seal",
        )?;
        let expected_seal = self.encode_initial_phase_commitment_lane_checkpoint_seal(
            phase_ordinal,
            completed_lane_count,
            &state,
        );
        if seal != expected_seal {
            return Err(
                "retained initial phase commitment lane checkpoint seal is stale or malformed"
                    .to_owned(),
            );
        }
        Ok(DurableInitialPhaseCommitmentLaneCheckpoint {
            phase_ordinal,
            completed_lane_count,
            state,
        })
    }

    fn persist_initial_phase_commitment_lane_checkpoint(
        &self,
        phase_ordinal: u8,
        completed_lane_count: u32,
        state: &[u8],
    ) -> Result<(), String> {
        validate_initial_phase_commitment_lane_checkpoint_coordinates(
            phase_ordinal,
            completed_lane_count,
        )?;
        if state.is_empty()
            || state.len() > MAXIMUM_INITIAL_PHASE_COMMITMENT_LANE_CHECKPOINT_BYTE_LENGTH
        {
            return Err("initial phase commitment lane checkpoint exceeds its bound".to_owned());
        }
        let state_path = self.initial_phase_commitment_lane_checkpoint_path(
            phase_ordinal,
            completed_lane_count,
            INITIAL_PHASE_COMMITMENT_LANE_CHECKPOINT_STATE_SUFFIX,
        );
        persist_exact_file_once(
            &state_path,
            state,
            "initial phase commitment lane checkpoint state",
        )?;
        let seal = self.encode_initial_phase_commitment_lane_checkpoint_seal(
            phase_ordinal,
            completed_lane_count,
            state,
        );
        let seal_path = self.initial_phase_commitment_lane_checkpoint_path(
            phase_ordinal,
            completed_lane_count,
            INITIAL_PHASE_COMMITMENT_LANE_CHECKPOINT_SEAL_SUFFIX,
        );
        persist_exact_file_once(
            &seal_path,
            &seal,
            "initial phase commitment lane checkpoint seal",
        )?;

        for entry in fs::read_dir(&self.directory)
            .map_err(|error| format!("enumerate superseded phase checkpoints: {error}"))?
        {
            let entry = entry
                .map_err(|error| format!("read superseded phase checkpoint entry: {error}"))?;
            let file_name = entry.file_name().into_string().map_err(|_| {
                "proof checkpoint custody contains a non-Unicode filename".to_owned()
            })?;
            let Some((stored_phase_ordinal, stored_completed_lane_count)) =
                parse_initial_phase_commitment_lane_checkpoint_coordinates_from_any_file(
                    &file_name,
                )
            else {
                continue;
            };
            if stored_phase_ordinal == phase_ordinal
                && stored_completed_lane_count < completed_lane_count
            {
                fs::remove_file(entry.path()).map_err(|error| {
                    format!("remove superseded phase checkpoint {file_name}: {error}")
                })?;
            }
        }
        Ok(())
    }

    fn encode_initial_phase_commitment_lane_checkpoint_seal(
        &self,
        phase_ordinal: u8,
        completed_lane_count: u32,
        state: &[u8],
    ) -> Vec<u8> {
        let mut seal =
            Vec::with_capacity(INITIAL_PHASE_COMMITMENT_LANE_CHECKPOINT_SEAL_BYTE_LENGTH);
        seal.extend_from_slice(&INITIAL_PHASE_COMMITMENT_LANE_CHECKPOINT_SEAL_MAGIC);
        seal.extend_from_slice(
            &INITIAL_PHASE_COMMITMENT_LANE_CHECKPOINT_SEAL_VERSION.to_le_bytes(),
        );
        seal.push(phase_ordinal);
        seal.push(0);
        seal.extend_from_slice(&completed_lane_count.to_le_bytes());
        seal.extend_from_slice(&self.stable_attempt_binding_hash);
        seal.extend_from_slice(&self.checkpoint_lineage_identifier);
        seal.extend_from_slice(&hash_framed_parts_512(
            self.profile.state_hash_domain,
            &[
                INITIAL_PHASE_COMMITMENT_LANE_CHECKPOINT_HASH_ROLE,
                &[phase_ordinal],
                &completed_lane_count.to_le_bytes(),
                state,
            ],
        ));
        debug_assert_eq!(
            seal.len(),
            INITIAL_PHASE_COMMITMENT_LANE_CHECKPOINT_SEAL_BYTE_LENGTH
        );
        seal
    }

    fn load_latest_quotient_constraint_checkpoint(
        &self,
    ) -> Result<Option<DurableQuotientConstraintCheckpoint>, String> {
        let mut latest_completed_constraint_count = None;
        for entry in fs::read_dir(&self.directory)
            .map_err(|error| format!("enumerate retained quotient checkpoints: {error}"))?
        {
            let entry = entry
                .map_err(|error| format!("read retained quotient checkpoint entry: {error}"))?;
            if !entry
                .file_type()
                .map_err(|error| format!("classify retained quotient checkpoint entry: {error}"))?
                .is_file()
            {
                return Err("proof checkpoint custody contains a non-file entry".to_owned());
            }
            let file_name = entry.file_name().into_string().map_err(|_| {
                "proof checkpoint custody contains a non-Unicode filename".to_owned()
            })?;
            if !file_name.starts_with(QUOTIENT_CONSTRAINT_CHECKPOINT_FILE_PREFIX) {
                continue;
            }
            if !file_name.ends_with(QUOTIENT_CONSTRAINT_CHECKPOINT_SEAL_SUFFIX) {
                continue;
            }
            let completed_constraint_count =
                parse_quotient_constraint_checkpoint_coordinate(&file_name).ok_or_else(|| {
                    format!("proof checkpoint custody contains malformed seal {file_name}")
                })?;
            latest_completed_constraint_count = Some(
                latest_completed_constraint_count
                    .map_or(completed_constraint_count, |current: u32| {
                        current.max(completed_constraint_count)
                    }),
            );
        }
        latest_completed_constraint_count
            .map(|completed_constraint_count| {
                self.load_quotient_constraint_checkpoint(completed_constraint_count)
            })
            .transpose()
    }

    fn load_quotient_constraint_checkpoint(
        &self,
        completed_constraint_count: u32,
    ) -> Result<DurableQuotientConstraintCheckpoint, String> {
        validate_quotient_constraint_checkpoint_coordinate(completed_constraint_count)?;
        let state = read_exact_bounded_file(
            &self.quotient_constraint_checkpoint_path(
                completed_constraint_count,
                QUOTIENT_CONSTRAINT_CHECKPOINT_STATE_SUFFIX,
            ),
            1,
            MAXIMUM_QUOTIENT_CONSTRAINT_CHECKPOINT_BYTE_LENGTH,
            "quotient constraint checkpoint state",
        )?;
        let seal = read_exact_bounded_file(
            &self.quotient_constraint_checkpoint_path(
                completed_constraint_count,
                QUOTIENT_CONSTRAINT_CHECKPOINT_SEAL_SUFFIX,
            ),
            QUOTIENT_CONSTRAINT_CHECKPOINT_SEAL_BYTE_LENGTH,
            QUOTIENT_CONSTRAINT_CHECKPOINT_SEAL_BYTE_LENGTH,
            "quotient constraint checkpoint seal",
        )?;
        let expected_seal =
            self.encode_quotient_constraint_checkpoint_seal(completed_constraint_count, &state);
        if seal != expected_seal {
            return Err(
                "retained quotient constraint checkpoint seal is stale or malformed".to_owned(),
            );
        }
        Ok(DurableQuotientConstraintCheckpoint {
            completed_constraint_count,
            state,
        })
    }

    fn persist_quotient_constraint_checkpoint(
        &self,
        completed_constraint_count: u32,
        state: &[u8],
    ) -> Result<(), String> {
        validate_quotient_constraint_checkpoint_coordinate(completed_constraint_count)?;
        if state.is_empty() || state.len() > MAXIMUM_QUOTIENT_CONSTRAINT_CHECKPOINT_BYTE_LENGTH {
            return Err("quotient constraint checkpoint exceeds its bound".to_owned());
        }
        persist_exact_file_once(
            &self.quotient_constraint_checkpoint_path(
                completed_constraint_count,
                QUOTIENT_CONSTRAINT_CHECKPOINT_STATE_SUFFIX,
            ),
            state,
            "quotient constraint checkpoint state",
        )?;
        let seal =
            self.encode_quotient_constraint_checkpoint_seal(completed_constraint_count, state);
        persist_exact_file_once(
            &self.quotient_constraint_checkpoint_path(
                completed_constraint_count,
                QUOTIENT_CONSTRAINT_CHECKPOINT_SEAL_SUFFIX,
            ),
            &seal,
            "quotient constraint checkpoint seal",
        )?;

        for entry in fs::read_dir(&self.directory)
            .map_err(|error| format!("enumerate superseded quotient checkpoints: {error}"))?
        {
            let entry = entry
                .map_err(|error| format!("read superseded quotient checkpoint entry: {error}"))?;
            let file_name = entry.file_name().into_string().map_err(|_| {
                "proof checkpoint custody contains a non-Unicode filename".to_owned()
            })?;
            let Some(stored_completed_constraint_count) =
                parse_quotient_constraint_checkpoint_coordinate_from_any_file(&file_name)
            else {
                continue;
            };
            if stored_completed_constraint_count < completed_constraint_count {
                fs::remove_file(entry.path()).map_err(|error| {
                    format!("remove superseded quotient checkpoint {file_name}: {error}")
                })?;
            }
        }
        Ok(())
    }

    fn encode_quotient_constraint_checkpoint_seal(
        &self,
        completed_constraint_count: u32,
        state: &[u8],
    ) -> Vec<u8> {
        let mut seal = Vec::with_capacity(QUOTIENT_CONSTRAINT_CHECKPOINT_SEAL_BYTE_LENGTH);
        seal.extend_from_slice(&QUOTIENT_CONSTRAINT_CHECKPOINT_SEAL_MAGIC);
        seal.extend_from_slice(&QUOTIENT_CONSTRAINT_CHECKPOINT_SEAL_VERSION.to_le_bytes());
        seal.extend_from_slice(&0_u16.to_le_bytes());
        seal.extend_from_slice(&completed_constraint_count.to_le_bytes());
        seal.extend_from_slice(&self.stable_attempt_binding_hash);
        seal.extend_from_slice(&self.checkpoint_lineage_identifier);
        seal.extend_from_slice(&hash_framed_parts_512(
            self.profile.state_hash_domain,
            &[
                QUOTIENT_CONSTRAINT_CHECKPOINT_HASH_ROLE,
                &completed_constraint_count.to_le_bytes(),
                state,
            ],
        ));
        debug_assert_eq!(seal.len(), QUOTIENT_CONSTRAINT_CHECKPOINT_SEAL_BYTE_LENGTH);
        seal
    }

    fn remove_phase_local_checkpoints_superseded_by_authenticated_boundary(
        &self,
        retained_initial_phase_checkpoints: &BTreeMap<
            u8,
            DurableInitialPhaseCommitmentLaneCheckpoint,
        >,
        retained_quotient_checkpoint: Option<&DurableQuotientConstraintCheckpoint>,
    ) -> Result<(), String> {
        for entry in fs::read_dir(&self.directory)
            .map_err(|error| format!("enumerate superseded phase-local checkpoints: {error}"))?
        {
            let entry = entry.map_err(|error| {
                format!("read superseded phase-local checkpoint entry: {error}")
            })?;
            if !entry
                .file_type()
                .map_err(|error| {
                    format!("classify superseded phase-local checkpoint entry: {error}")
                })?
                .is_file()
            {
                return Err("proof checkpoint custody contains a non-file entry".to_owned());
            }
            let file_name = entry.file_name().into_string().map_err(|_| {
                "proof checkpoint custody contains a non-Unicode filename".to_owned()
            })?;
            let remove_checkpoint = if file_name
                .starts_with(INITIAL_PHASE_COMMITMENT_LANE_CHECKPOINT_FILE_PREFIX)
            {
                let coordinates =
                    parse_initial_phase_commitment_lane_checkpoint_coordinates_from_any_file(
                        &file_name,
                    )
                    .ok_or_else(|| {
                        format!(
                            "proof checkpoint custody contains malformed phase-local file {file_name}"
                        )
                    })?;
                retained_initial_phase_checkpoints
                    .get(&coordinates.0)
                    .is_none_or(|checkpoint| checkpoint.completed_lane_count != coordinates.1)
            } else if file_name.starts_with(QUOTIENT_CONSTRAINT_CHECKPOINT_FILE_PREFIX) {
                let completed_constraint_count =
                    parse_quotient_constraint_checkpoint_coordinate_from_any_file(&file_name)
                        .ok_or_else(|| {
                            format!(
                                "proof checkpoint custody contains malformed phase-local file {file_name}"
                            )
                        })?;
                retained_quotient_checkpoint.is_none_or(|checkpoint| {
                    checkpoint.completed_constraint_count != completed_constraint_count
                })
            } else {
                false
            };
            if remove_checkpoint {
                fs::remove_file(entry.path()).map_err(|error| {
                    format!("remove superseded phase-local checkpoint {file_name}: {error}")
                })?;
            }
        }
        Ok(())
    }

    fn require_checkpoint_binding(
        &self,
        checkpoint: &AuthenticatedCommonProofGenerationCheckpoint,
        boundary_ordinal: u32,
    ) -> Result<(), String> {
        if checkpoint.stable_attempt_binding_hash() != self.stable_attempt_binding_hash
            || checkpoint.checkpoint_lineage_identifier() != self.checkpoint_lineage_identifier
            || checkpoint.safe_boundary_ordinal() != boundary_ordinal
        {
            return Err(
                "retained proof checkpoint differs from the exact proof attempt or boundary"
                    .to_owned(),
            );
        }
        Ok(())
    }

    fn checkpoint_path(&self, boundary_ordinal: u32, suffix: &str) -> PathBuf {
        self.directory.join(format!(
            "{COMMON_PROOF_CHECKPOINT_FILE_PREFIX}{boundary_ordinal:08}{suffix}"
        ))
    }

    fn initial_phase_commitment_lane_checkpoint_path(
        &self,
        phase_ordinal: u8,
        completed_lane_count: u32,
        suffix: &str,
    ) -> PathBuf {
        self.directory.join(format!(
            "{INITIAL_PHASE_COMMITMENT_LANE_CHECKPOINT_FILE_PREFIX}{phase_ordinal:02}-lane-{completed_lane_count:08}{suffix}"
        ))
    }

    fn quotient_constraint_checkpoint_path(
        &self,
        completed_constraint_count: u32,
        suffix: &str,
    ) -> PathBuf {
        self.directory.join(format!(
            "{QUOTIENT_CONSTRAINT_CHECKPOINT_FILE_PREFIX}{completed_constraint_count:08}{suffix}"
        ))
    }
}

fn parse_common_proof_checkpoint_boundary(file_name: &str) -> Option<u32> {
    let digits = file_name
        .strip_prefix(COMMON_PROOF_CHECKPOINT_FILE_PREFIX)?
        .strip_suffix(COMMON_PROOF_CHECKPOINT_SEAL_SUFFIX)?;
    if digits.len() != 8 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

fn validate_initial_phase_commitment_lane_checkpoint_coordinates(
    phase_ordinal: u8,
    completed_lane_count: u32,
) -> Result<(), String> {
    if phase_ordinal >= 3
        || completed_lane_count == 0
        || !completed_lane_count.is_multiple_of(INITIAL_PHASE_COMMITMENT_LANE_CHECKPOINT_INTERVAL)
    {
        return Err("initial phase commitment lane checkpoint has invalid coordinates".to_owned());
    }
    Ok(())
}

fn parse_initial_phase_commitment_lane_checkpoint_coordinates(
    file_name: &str,
) -> Option<(u8, u32)> {
    parse_initial_phase_commitment_lane_checkpoint_coordinates_with_suffix(
        file_name,
        INITIAL_PHASE_COMMITMENT_LANE_CHECKPOINT_SEAL_SUFFIX,
    )
}

fn parse_initial_phase_commitment_lane_checkpoint_coordinates_from_any_file(
    file_name: &str,
) -> Option<(u8, u32)> {
    [
        INITIAL_PHASE_COMMITMENT_LANE_CHECKPOINT_STATE_SUFFIX,
        INITIAL_PHASE_COMMITMENT_LANE_CHECKPOINT_SEAL_SUFFIX,
    ]
    .into_iter()
    .find_map(|suffix| {
        parse_initial_phase_commitment_lane_checkpoint_coordinates_with_suffix(file_name, suffix)
    })
}

fn parse_initial_phase_commitment_lane_checkpoint_coordinates_with_suffix(
    file_name: &str,
    suffix: &str,
) -> Option<(u8, u32)> {
    let coordinates = file_name
        .strip_prefix(INITIAL_PHASE_COMMITMENT_LANE_CHECKPOINT_FILE_PREFIX)?
        .strip_suffix(suffix)?;
    let (phase_digits, lane_digits) = coordinates.split_once("-lane-")?;
    if phase_digits.len() != 2
        || lane_digits.len() != 8
        || !phase_digits.bytes().all(|byte| byte.is_ascii_digit())
        || !lane_digits.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let phase_ordinal = phase_digits.parse().ok()?;
    let completed_lane_count = lane_digits.parse().ok()?;
    validate_initial_phase_commitment_lane_checkpoint_coordinates(
        phase_ordinal,
        completed_lane_count,
    )
    .ok()?;
    Some((phase_ordinal, completed_lane_count))
}

fn validate_quotient_constraint_checkpoint_coordinate(
    completed_constraint_count: u32,
) -> Result<(), String> {
    if completed_constraint_count == 0
        || !completed_constraint_count.is_multiple_of(QUOTIENT_CONSTRAINT_CHECKPOINT_INTERVAL)
    {
        return Err("quotient constraint checkpoint has invalid coordinates".to_owned());
    }
    Ok(())
}

fn retain_phase_local_checkpoints_reachable_after_resume(
    resumed_stage: CommonProofGenerationStage,
    retained_initial_phase_checkpoints: &mut BTreeMap<
        u8,
        DurableInitialPhaseCommitmentLaneCheckpoint,
    >,
    retained_quotient_checkpoint: &mut Option<DurableQuotientConstraintCheckpoint>,
) -> Result<(), String> {
    let resumed_stage_ordinal = resumed_stage as u8;
    let mut superseded_initial_phase_ordinals = Vec::new();
    for &phase_ordinal in retained_initial_phase_checkpoints.keys() {
        let phase_stage = match phase_ordinal {
            0 => CommonProofGenerationStage::MaterializingBaseTrees,
            1 => CommonProofGenerationStage::MaterializingAuxiliaryTrees,
            2 => CommonProofGenerationStage::MaterializingQuotientTrees,
            _ => {
                return Err(
                    "retained initial phase checkpoint has an unknown phase ordinal".to_owned(),
                );
            }
        };
        if resumed_stage_ordinal > phase_stage as u8 {
            superseded_initial_phase_ordinals.push(phase_ordinal);
        }
    }
    for phase_ordinal in superseded_initial_phase_ordinals {
        retained_initial_phase_checkpoints.remove(&phase_ordinal);
    }
    if resumed_stage_ordinal > CommonProofGenerationStage::ConstructingQuotient as u8 {
        retained_quotient_checkpoint.take();
    }

    Ok(())
}

fn parse_quotient_constraint_checkpoint_coordinate(file_name: &str) -> Option<u32> {
    parse_quotient_constraint_checkpoint_coordinate_with_suffix(
        file_name,
        QUOTIENT_CONSTRAINT_CHECKPOINT_SEAL_SUFFIX,
    )
}

fn parse_quotient_constraint_checkpoint_coordinate_from_any_file(file_name: &str) -> Option<u32> {
    [
        QUOTIENT_CONSTRAINT_CHECKPOINT_STATE_SUFFIX,
        QUOTIENT_CONSTRAINT_CHECKPOINT_SEAL_SUFFIX,
    ]
    .into_iter()
    .find_map(|suffix| {
        parse_quotient_constraint_checkpoint_coordinate_with_suffix(file_name, suffix)
    })
}

fn parse_quotient_constraint_checkpoint_coordinate_with_suffix(
    file_name: &str,
    suffix: &str,
) -> Option<u32> {
    let digits = file_name
        .strip_prefix(QUOTIENT_CONSTRAINT_CHECKPOINT_FILE_PREFIX)?
        .strip_suffix(suffix)?;
    if digits.len() != 8 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let completed_constraint_count = digits.parse().ok()?;
    validate_quotient_constraint_checkpoint_coordinate(completed_constraint_count).ok()?;
    Some(completed_constraint_count)
}

fn runner_enabled_checkpoint_resume() -> Result<bool, String> {
    exact_same_secret_evidence_checkpoint_resume_enabled()
}

fn runner_requested_stop_after_quotient_constraint_checkpoint() -> Result<bool, String> {
    exact_same_secret_evidence_stop_after_quotient_constraint_checkpoint_requested()
}

fn read_exact_bounded_file(
    path: &Path,
    minimum_byte_length: usize,
    maximum_byte_length: usize,
    label: &str,
) -> Result<Vec<u8>, String> {
    let mut file = File::open(path).map_err(|error| format!("open retained {label}: {error}"))?;
    let declared_byte_length = usize::try_from(
        file.metadata()
            .map_err(|error| format!("inspect retained {label}: {error}"))?
            .len(),
    )
    .map_err(|_| format!("retained {label} byte length exceeds usize"))?;
    if declared_byte_length < minimum_byte_length || declared_byte_length > maximum_byte_length {
        return Err(format!("retained {label} has a noncanonical byte length"));
    }
    let mut bytes = vec![0_u8; declared_byte_length];
    file.read_exact(&mut bytes)
        .map_err(|error| format!("read retained {label}: {error}"))?;
    let mut trailing = [0_u8; 1];
    if file
        .read(&mut trailing)
        .map_err(|error| format!("check retained {label} extent: {error}"))?
        != 0
    {
        return Err(format!("retained {label} changed while it was read"));
    }
    Ok(bytes)
}

fn persist_exact_file_once(path: &Path, bytes: &[u8], label: &str) -> Result<(), String> {
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut file) => {
            file.write_all(bytes)
                .map_err(|error| format!("write {label}: {error}"))?;
            file.sync_all()
                .map_err(|error| format!("durably seal {label}: {error}"))
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = read_exact_bounded_file(path, bytes.len(), bytes.len(), label)?;
            if existing != bytes {
                return Err(format!(
                    "existing {label} differs from deterministic replay"
                ));
            }
            Ok(())
        }
        Err(error) => Err(format!("create {label}: {error}")),
    }
}

fn encode_common_proof_checkpoint_seal(
    profile: DurableCommonProofCheckpointProfile,
    checkpoint: &AuthenticatedCommonProofGenerationCheckpoint,
    state: &[u8],
    cursor_manifest: &[u8],
) -> Vec<u8> {
    let mut seal = Vec::with_capacity(COMMON_PROOF_CHECKPOINT_SEAL_BYTE_LENGTH);
    seal.extend_from_slice(&profile.seal_magic);
    seal.extend_from_slice(&COMMON_PROOF_CHECKPOINT_SEAL_VERSION.to_le_bytes());
    seal.extend_from_slice(&checkpoint.safe_boundary_ordinal().to_le_bytes());
    seal.extend_from_slice(&checkpoint.stable_attempt_binding_hash());
    seal.extend_from_slice(&checkpoint.checkpoint_lineage_identifier());
    seal.extend_from_slice(&checkpoint.checkpoint_schedule_digest().into_bytes());
    seal.extend_from_slice(&hash_framed_parts_512(profile.state_hash_domain, &[state]));
    seal.extend_from_slice(&hash_framed_parts_512(
        profile.cursor_hash_domain,
        &[cursor_manifest],
    ));
    debug_assert_eq!(seal.len(), COMMON_PROOF_CHECKPOINT_SEAL_BYTE_LENGTH);
    seal
}

struct ExactVerificationPrerequisiteFactory {
    verified_public_randomness: VerifiedPublicRandomness,
    verified_vss_proof: ConsumedVerifiedCommonProofCapability,
}

impl ExactVerificationPrerequisiteFactory {
    fn new(
        verified_public_randomness: VerifiedPublicRandomness,
        verified_vss_proof: ConsumedVerifiedCommonProofCapability,
    ) -> Self {
        Self {
            verified_public_randomness,
            verified_vss_proof,
        }
    }

    fn build(&self) -> Result<VerifiedSameSecretLowDegreePrerequisite, String> {
        VerifiedSameSecretLowDegreePrerequisite::from_positive_verified_vss_evidence(
            &self.verified_public_randomness,
            self.verified_vss_proof.borrowed(),
        )
        .map_err(|error| format!("mint exact verified VSS prerequisite: {error:?}"))
    }
}

impl FileBackedExternalMemory {
    fn new() -> Result<Self, String> {
        let repository_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| "resolve repository root for exact proof scratch".to_owned())?;
        let parent = repository_root.join("temp").join("test-checkpoints");
        fs::create_dir_all(&parent)
            .map_err(|error| format!("create exact proof scratch parent: {error}"))?;
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| format!("derive exact proof scratch nonce: {error}"))?
            .as_nanos();
        let directory = parent.join(format!(
            "exact-same-secret-runtime-storage-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&directory)
            .map_err(|error| format!("create exact proof scratch directory: {error}"))?;
        Ok(Self {
            directory,
            objects: BTreeMap::new(),
            next_file_identifier: 0,
            current_declared_byte_length: 0,
            maximum_declared_byte_length: 0,
        })
    }

    fn execute_transaction(
        &mut self,
        request: &ProofExternalMemoryTransactionRequest,
    ) -> Result<Vec<u8>, String> {
        let mut read_results = Vec::new();
        for operation in request.operations() {
            match operation {
                ProofExternalMemoryTransactionOperation::Create {
                    object,
                    protection,
                    exact_byte_length,
                } => self.create_object(*object, *protection, *exact_byte_length)?,
                ProofExternalMemoryTransactionOperation::Append {
                    object,
                    expected_offset,
                    bytes,
                } => self.append_object(*object, *expected_offset, bytes)?,
                ProofExternalMemoryTransactionOperation::Seal { object } => {
                    self.seal_object(*object)?;
                }
                ProofExternalMemoryTransactionOperation::Read {
                    object,
                    offset,
                    byte_length,
                } => read_results.push(self.read_object(*object, *offset, *byte_length)?),
                ProofExternalMemoryTransactionOperation::Delete { object } => {
                    self.delete_object(*object)?;
                }
            }
        }
        request
            .encode_test_worker_response(&read_results)
            .map_err(|error| format!("encode exact storage response: {error:?}"))
    }

    fn create_object(
        &mut self,
        object: ProofExternalMemoryObject,
        protection: ProofExternalMemoryProtection,
        exact_byte_length: u64,
    ) -> Result<(), String> {
        if exact_byte_length == 0 || self.objects.contains_key(&object) {
            return Err("exact external object has invalid create coordinates".to_owned());
        }
        let file_identifier = self.next_file_identifier;
        self.next_file_identifier = self
            .next_file_identifier
            .checked_add(1)
            .ok_or_else(|| "exact external object file identifier overflowed".to_owned())?;
        let path = self
            .directory
            .join(format!("object-{}-{file_identifier}.bin", object.ordinal()));
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| {
                format!("create exact external object {}: {error}", object.ordinal())
            })?;
        self.current_declared_byte_length = self
            .current_declared_byte_length
            .checked_add(exact_byte_length)
            .ok_or_else(|| "exact external-memory accounting overflowed".to_owned())?;
        self.maximum_declared_byte_length = self
            .maximum_declared_byte_length
            .max(self.current_declared_byte_length);
        self.objects.insert(
            object,
            FileBackedObject {
                path,
                exact_byte_length,
                protection,
                sealed: false,
            },
        );
        Ok(())
    }

    fn append_object(
        &mut self,
        object: ProofExternalMemoryObject,
        expected_offset: u64,
        bytes: &[u8],
    ) -> Result<(), String> {
        let stored = self
            .objects
            .get(&object)
            .ok_or_else(|| format!("append missing exact external object {}", object.ordinal()))?;
        let current_byte_length = fs::metadata(&stored.path)
            .map_err(|error| format!("inspect exact external object: {error}"))?
            .len();
        let following_byte_length = current_byte_length
            .checked_add(
                u64::try_from(bytes.len())
                    .map_err(|_| "exact append length exceeds u64".to_owned())?,
            )
            .ok_or_else(|| "exact append end overflowed".to_owned())?;
        if stored.sealed
            || current_byte_length != expected_offset
            || following_byte_length > stored.exact_byte_length
        {
            return Err("exact external append has the wrong offset or length".to_owned());
        }
        let mut file = OpenOptions::new()
            .append(true)
            .open(&stored.path)
            .map_err(|error| format!("open exact external object for append: {error}"))?;
        file.write_all(bytes)
            .map_err(|error| format!("append exact external object: {error}"))
    }

    fn seal_object(&mut self, object: ProofExternalMemoryObject) -> Result<(), String> {
        let stored = self
            .objects
            .get_mut(&object)
            .ok_or_else(|| format!("seal missing exact external object {}", object.ordinal()))?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&stored.path)
            .map_err(|error| format!("open exact external object for seal: {error}"))?;
        if stored.sealed
            || file
                .metadata()
                .map_err(|error| format!("inspect exact object before seal: {error}"))?
                .len()
                != stored.exact_byte_length
        {
            return Err("exact external seal has the wrong object length".to_owned());
        }
        file.sync_all()
            .map_err(|error| format!("sync exact external object: {error}"))?;
        stored.sealed = true;
        Ok(())
    }

    fn read_object(
        &self,
        object: ProofExternalMemoryObject,
        offset: u64,
        byte_length: u32,
    ) -> Result<Vec<u8>, String> {
        let stored = self
            .objects
            .get(&object)
            .ok_or_else(|| format!("read missing exact external object {}", object.ordinal()))?;
        let range_end = offset
            .checked_add(u64::from(byte_length))
            .ok_or_else(|| "exact external read range overflowed".to_owned())?;
        if !stored.sealed || range_end > stored.exact_byte_length {
            return Err("exact external read has the wrong range or lifecycle".to_owned());
        }
        let mut file = File::open(&stored.path)
            .map_err(|error| format!("open exact external object for read: {error}"))?;
        file.seek(SeekFrom::Start(offset))
            .map_err(|error| format!("seek exact external object: {error}"))?;
        let mut bytes = vec![
            0_u8;
            usize::try_from(byte_length).map_err(|_| {
                "exact external read length exceeds usize".to_owned()
            })?
        ];
        file.read_exact(&mut bytes)
            .map_err(|error| format!("read exact external object: {error}"))?;
        Ok(bytes)
    }

    fn delete_object(&mut self, object: ProofExternalMemoryObject) -> Result<(), String> {
        let stored = self
            .objects
            .remove(&object)
            .ok_or_else(|| format!("delete missing exact external object {}", object.ordinal()))?;
        fs::remove_file(&stored.path)
            .map_err(|error| format!("delete exact external object: {error}"))?;
        self.current_declared_byte_length = self
            .current_declared_byte_length
            .checked_sub(stored.exact_byte_length)
            .ok_or_else(|| "exact external-memory accounting underflowed".to_owned())?;
        Ok(())
    }

    const fn maximum_declared_byte_length(&self) -> u64 {
        self.maximum_declared_byte_length
    }

    fn retained_secret_object_count(&self) -> usize {
        self.objects
            .values()
            .filter(|object| {
                object.protection == ProofExternalMemoryProtection::SecretAuthenticatedEncryption
            })
            .count()
    }
}

impl Drop for FileBackedExternalMemory {
    fn drop(&mut self) {
        for stored in self.objects.values() {
            let _ = fs::remove_file(&stored.path);
        }
        let _ = fs::remove_dir(&self.directory);
    }
}

fn verified_statement_owned_trees(
    relation_plan_variant: &crate::bgv::proof_suite::RelationPlanVariant,
    relation_trees: &[RelationProofTreeInput],
) -> Result<Vec<VerifiedStatementOwnedTree>, String> {
    if relation_plan_variant.ordered_trees().len() != relation_trees.len() {
        return Err("exact relation tree descriptor and input counts differ".to_owned());
    }
    relation_plan_variant
        .ordered_trees()
        .iter()
        .zip(relation_trees)
        .enumerate()
        .filter_map(
            |(tree_ordinal, (descriptor, input))| match (descriptor, input) {
                (
                    RelationTreeDescriptor::BoundPublic {
                        expected_root_source_ordinal,
                        ordered_column_ordinals,
                        ..
                    },
                    RelationProofTreeInput::BoundPublic(tree),
                ) => Some(
                    ordered_column_ordinals
                        .iter()
                        .map(|column_ordinal| {
                            relation_plan_variant
                                .ordered_columns()
                                .get(
                                    usize::try_from(*column_ordinal)
                                        .map_err(|_| "exact tree column ordinal exceeds usize")?,
                                )
                                .map(|column| column.canonical_residue_modulus())
                                .ok_or("exact tree column is absent from the relation")
                        })
                        .collect::<Result<Vec<_>, _>>()
                        .and_then(|ordered_canonical_residue_moduli| {
                            Ok(VerifiedStatementOwnedTree::from_test_relation_input(
                                u32::try_from(tree_ordinal)
                                    .map_err(|_| "exact tree ordinal exceeds u32")?,
                                *expected_root_source_ordinal,
                                tree.clone(),
                                ordered_canonical_residue_moduli,
                            ))
                        }),
                ),
                (
                    RelationTreeDescriptor::ProofCreated { .. },
                    RelationProofTreeInput::ProofCreated { .. },
                ) => None,
                _ => Some(Err(
                    "exact relation tree input has the wrong ownership class",
                )),
            },
        )
        .collect::<Result<Vec<_>, _>>()
        .map_err(str::to_owned)
}

fn exact_application_slot(
    sources: &PreparedExactSameSecretGenerationSources,
) -> Result<ProofApplicationSlot, String> {
    let request_context = sources
        .source_polynomials
        .exact_same_secret_evidence_request_context();
    let statement = decode_selected_same_secret_statement(
        &sources.canonical_application_statement_bytes,
        SelectedApplicationStatementContext::new(
            request_context.protocol_version(),
            request_context.suite_identifier(),
            None,
            None,
        ),
    )
    .map_err(|error| format!("decode exact runtime statement: {error:?}"))?;
    ProofApplicationSlot::new(
        Hash512::from_bytes(request_context.suite_identifier()),
        Hash512::from_bytes(sources.authorization.ceremony_context_hash()),
        Hash512::from_bytes(sources.action_context_hash),
        SetupKeyRelationProofFamily::SameSecret.statement_schema_identifier(),
        Some(statement.roster_position()),
        None,
        None,
    )
    .map_err(|error| format!("construct exact runtime application slot: {error:?}"))
}

struct GeneratedCommonProofEvidence {
    canonical_proof_bytes: Vec<u8>,
    stream_descriptor: StreamDescriptor,
    maximum_external_memory_byte_length: u64,
    checkpoint_count: usize,
    resumed_from_checkpoint_boundary: Option<u32>,
}

struct ControlledQuotientConstraintCheckpointStopEvidence {
    checkpoint_byte_length: usize,
    completed_constraint_count: u32,
    elapsed_milliseconds: u64,
    maximum_external_memory_byte_length: u64,
    resumed_from_checkpoint_boundary: Option<u32>,
    standard_checkpoint_count: usize,
}

enum CommonProofGenerationEvidenceOutcome {
    Complete(GeneratedCommonProofEvidence),
    ControlledQuotientConstraintCheckpointStop(ControlledQuotientConstraintCheckpointStopEvidence),
}

impl CommonProofGenerationEvidenceOutcome {
    fn require_complete(self) -> Result<GeneratedCommonProofEvidence, String> {
        match self {
            Self::Complete(generated) => Ok(generated),
            Self::ControlledQuotientConstraintCheckpointStop(_) => Err(
                "common-proof generation stopped at a quotient checkpoint where completion was required"
                    .to_owned(),
            ),
        }
    }
}

struct ExactTranscriptPrefixEvidence<'evidence> {
    prerequisite: &'evidence VerifiedSameSecretLowDegreePrerequisite,
    relation_plan: &'evidence CommonProofRelationPlanCapability,
}

#[allow(clippy::too_many_arguments)]
fn generate_prepared_common_proof(
    prepared: PreparedCommonProofGeneration,
    canonical_application_statement_bytes: &[u8],
    application_statement_schema_identifier: u16,
    roster_position: Option<u16>,
    schedule_position: Option<u32>,
    transcript_prefix: Option<ExactTranscriptPrefixEvidence<'_>>,
    family_label: &str,
    durable_checkpoint_store: Option<&DurableCommonProofCheckpointStore>,
    resume_checkpoint: Option<&DurableCommonProofCheckpoint>,
    stop_after_quotient_constraint_checkpoint: bool,
) -> Result<CommonProofGenerationEvidenceOutcome, String> {
    let mut registry = CommonProofRuntimeRegistry::default();
    let operation = match resume_checkpoint {
        Some(checkpoint) => {
            let operation = registry
                .preissue_generation_operation_handle()
                .map_err(|error| {
                    format!("reserve {family_label} generation operation: {error:?}")
                })?;
            registry
                .resume_owned_generation_with_handle(
                    prepared,
                    &checkpoint.state,
                    &checkpoint.cursor_manifest,
                    operation,
                )
                .map_err(|error| format!("resume {family_label} runtime generation: {error:?}"))?;
            operation
        }
        None => registry
            .begin_owned_generation(prepared)
            .map_err(|error| format!("begin {family_label} runtime generation: {error:?}"))?,
    };
    let mut storage = FileBackedExternalMemory::new()?;
    let mut output_chunks = BTreeMap::<usize, Vec<u8>>::new();
    let resumed_from_checkpoint_boundary =
        resume_checkpoint.map(|checkpoint| checkpoint.boundary_ordinal);
    let mut checkpoint_count = resumed_from_checkpoint_boundary
        .and_then(|boundary_ordinal| usize::try_from(boundary_ordinal).ok())
        .and_then(|boundary_ordinal| boundary_ordinal.checked_add(1))
        .unwrap_or(0);
    let mut resume_completion_observed = resume_checkpoint.is_none();
    let mut last_stage = None;
    let mut retained_initial_phase_commitment_lane_checkpoints = durable_checkpoint_store
        .map(DurableCommonProofCheckpointStore::load_initial_phase_commitment_lane_checkpoints)
        .transpose()?
        .unwrap_or_default();
    let mut retained_quotient_constraint_checkpoint = durable_checkpoint_store
        .map(DurableCommonProofCheckpointStore::load_latest_quotient_constraint_checkpoint)
        .transpose()?
        .flatten();
    let started_at = Instant::now();
    let mut controlled_quotient_constraint_checkpoint_stop = None;

    loop {
        let poll = registry
            .poll_owned_generation(operation)
            .map_err(|error| format!("poll exact runtime generation: {error:?}"))?;
        match poll {
            CommonProofGenerationWorkerPoll::Progress {
                stage,
                checkpoint_ready,
            } => {
                let mut restored_lane_checkpoint_coordinates = None;
                let mut restored_quotient_checkpoint_coordinate = None;
                if last_stage != Some(stage) {
                    eprintln!(
                        "{family_label} generation stage {stage:?}: {:?}",
                        started_at.elapsed()
                    );
                    last_stage = Some(stage);
                }
                if checkpoint_ready {
                    let checkpoint_state = registry
                        .generation_checkpoint_state(operation)
                        .map_err(|error| format!("read exact checkpoint state: {error:?}"))?
                        .to_vec();
                    let cursor_manifest = registry
                        .generation_checkpoint_cursor_manifest(operation)
                        .map_err(|error| format!("read exact checkpoint cursor: {error:?}"))?
                        .to_vec();
                    let boundary_ordinal = registry
                        .generation_checkpoint_safe_boundary_ordinal(operation)
                        .map_err(|error| format!("read exact checkpoint boundary: {error:?}"))?;
                    if checkpoint_state.is_empty()
                        || cursor_manifest.is_empty()
                        || usize::try_from(boundary_ordinal).ok() != Some(checkpoint_count)
                    {
                        return Err(
                            "exact checkpoint boundary is incomplete or out of order".to_owned()
                        );
                    }
                    if let Some(store) = durable_checkpoint_store {
                        store.persist(boundary_ordinal, &checkpoint_state, &cursor_manifest)?;
                        store.remove_phase_local_checkpoints_superseded_by_authenticated_boundary(
                            &retained_initial_phase_commitment_lane_checkpoints,
                            retained_quotient_constraint_checkpoint.as_ref(),
                        )?;
                    }
                    eprintln!(
                        "{family_label} authenticated checkpoint boundary {boundary_ordinal} at stage {stage:?}, persisted={}, {:?}",
                        durable_checkpoint_store.is_some(),
                        started_at.elapsed(),
                    );
                    checkpoint_count += 1;
                    registry
                        .acknowledge_generation_checkpoint(operation)
                        .map_err(|error| format!("advance exact checkpoint: {error:?}"))?;
                }
                if let Some(store) = durable_checkpoint_store {
                    let retained_lane_checkpoint = registry
                        .generation_initial_phase_commitment_lane_restore_target(operation)
                        .map_err(|error| {
                            format!("read initial phase lane restore target: {error:?}")
                        })?
                        .and_then(|phase_ordinal| {
                            retained_initial_phase_commitment_lane_checkpoints
                                .remove(&phase_ordinal)
                                .map(|checkpoint| (phase_ordinal, checkpoint))
                        });
                    if let Some((phase_ordinal, checkpoint)) = retained_lane_checkpoint {
                        if checkpoint.phase_ordinal != phase_ordinal {
                            return Err(
                                "retained phase checkpoint map has inconsistent coordinates"
                                    .to_owned(),
                            );
                        }
                        let restore_started_at = Instant::now();
                        registry
                            .restore_generation_initial_phase_commitment_lane_checkpoint(
                                operation,
                                checkpoint.phase_ordinal,
                                checkpoint.completed_lane_count,
                                &checkpoint.state,
                            )
                            .map_err(|error| {
                                format!(
                                    "restore initial phase {} lane {} checkpoint: {error:?}",
                                    checkpoint.phase_ordinal, checkpoint.completed_lane_count,
                                )
                            })?;
                        restored_lane_checkpoint_coordinates =
                            Some((checkpoint.phase_ordinal, checkpoint.completed_lane_count));
                        eprintln!(
                            "{family_label} restored bound initial phase {} lane {} checkpoint ({} bytes) in {:?}, total {:?}",
                            checkpoint.phase_ordinal,
                            checkpoint.completed_lane_count,
                            checkpoint.state.len(),
                            restore_started_at.elapsed(),
                            started_at.elapsed(),
                        );
                    }

                    if let Some((phase_ordinal, completed_lane_count)) = registry
                        .generation_initial_phase_commitment_lane_checkpoint_coordinates(operation)
                        .map_err(|error| {
                            format!("read initial phase lane checkpoint coordinates: {error:?}")
                        })?
                    {
                        let coordinates = (phase_ordinal, completed_lane_count);
                        if completed_lane_count
                            .is_multiple_of(INITIAL_PHASE_COMMITMENT_LANE_CHECKPOINT_INTERVAL)
                            && restored_lane_checkpoint_coordinates != Some(coordinates)
                        {
                            let checkpoint_state = registry
                                .generation_initial_phase_commitment_lane_checkpoint_bytes(
                                    operation,
                                )
                                .map_err(|error| {
                                    format!(
                                        "encode initial phase {phase_ordinal} lane {completed_lane_count} checkpoint: {error:?}"
                                    )
                                })?;
                            let persist_started_at = Instant::now();
                            store.persist_initial_phase_commitment_lane_checkpoint(
                                phase_ordinal,
                                completed_lane_count,
                                &checkpoint_state,
                            )?;
                            eprintln!(
                                "{family_label} persisted bound initial phase {phase_ordinal} lane {completed_lane_count} checkpoint ({} bytes) in {:?}, total {:?}",
                                checkpoint_state.len(),
                                persist_started_at.elapsed(),
                                started_at.elapsed(),
                            );
                        }
                    }

                    if retained_quotient_constraint_checkpoint.is_some()
                        && registry
                            .generation_quotient_constraint_checkpoint_restore_target(operation)
                            .map_err(|error| {
                                format!("read quotient constraint restore target: {error:?}")
                            })?
                    {
                        let checkpoint = retained_quotient_constraint_checkpoint
                            .take()
                            .ok_or_else(|| {
                                "quotient constraint restore target lost its retained checkpoint"
                                    .to_owned()
                            })?;
                        let restore_started_at = Instant::now();
                        registry
                            .restore_generation_quotient_constraint_checkpoint(
                                operation,
                                checkpoint.completed_constraint_count,
                                &checkpoint.state,
                            )
                            .map_err(|error| {
                                format!(
                                    "restore quotient constraint {} checkpoint: {error:?}",
                                    checkpoint.completed_constraint_count,
                                )
                            })?;
                        restored_quotient_checkpoint_coordinate =
                            Some(checkpoint.completed_constraint_count);
                        eprintln!(
                            "{family_label} restored quotient constraint {} checkpoint ({} bytes) in {:?}, total {:?}",
                            checkpoint.completed_constraint_count,
                            checkpoint.state.len(),
                            restore_started_at.elapsed(),
                            started_at.elapsed(),
                        );
                    }

                    if let Some(completed_constraint_count) = registry
                        .generation_quotient_constraint_checkpoint_coordinates(operation)
                        .map_err(|error| {
                            format!("read quotient constraint checkpoint coordinates: {error:?}")
                        })?
                        && completed_constraint_count
                            .is_multiple_of(QUOTIENT_CONSTRAINT_CHECKPOINT_INTERVAL)
                        && restored_quotient_checkpoint_coordinate
                            != Some(completed_constraint_count)
                    {
                        let checkpoint_state = registry
                            .generation_quotient_constraint_checkpoint_bytes(operation)
                            .map_err(|error| {
                                format!(
                                    "encode quotient constraint {completed_constraint_count} checkpoint: {error:?}"
                                )
                            })?;
                        let persist_started_at = Instant::now();
                        store.persist_quotient_constraint_checkpoint(
                            completed_constraint_count,
                            &checkpoint_state,
                        )?;
                        eprintln!(
                            "{family_label} persisted quotient constraint {completed_constraint_count} checkpoint ({} bytes) in {:?}, total {:?}",
                            checkpoint_state.len(),
                            persist_started_at.elapsed(),
                            started_at.elapsed(),
                        );
                        if stop_after_quotient_constraint_checkpoint {
                            let authenticated_checkpoint = store
                                .load_quotient_constraint_checkpoint(completed_constraint_count)?;
                            if authenticated_checkpoint.state != checkpoint_state {
                                return Err(
                                    "persisted quotient constraint checkpoint did not authenticate to the exact encoded state"
                                        .to_owned(),
                                );
                            }
                            controlled_quotient_constraint_checkpoint_stop =
                                Some(ControlledQuotientConstraintCheckpointStopEvidence {
                                    checkpoint_byte_length: checkpoint_state.len(),
                                    completed_constraint_count,
                                    elapsed_milliseconds: u64::try_from(
                                        started_at.elapsed().as_millis(),
                                    )
                                    .map_err(|_| {
                                        "controlled checkpoint-stop elapsed time exceeds u64"
                                            .to_owned()
                                    })?,
                                    maximum_external_memory_byte_length: storage
                                        .maximum_declared_byte_length(),
                                    resumed_from_checkpoint_boundary,
                                    standard_checkpoint_count: checkpoint_count,
                                });
                            registry
                                .request_generation_cancellation(operation)
                                .map_err(|error| {
                                    format!(
                                        "request controlled quotient checkpoint cancellation: {error:?}"
                                    )
                                })?;
                        }
                    }
                }
            }
            CommonProofGenerationWorkerPoll::ResumeComplete { stage } => {
                if resume_completion_observed {
                    return Err(
                        "exact generation reported an unexpected or duplicate resume boundary"
                            .to_owned(),
                    );
                }
                eprintln!(
                    "{family_label} resumed after authenticated boundary {} at stage {stage:?}: {:?}",
                    resumed_from_checkpoint_boundary
                        .ok_or_else(|| "resumed generation has no retained boundary".to_owned())?,
                    started_at.elapsed(),
                );
                if let Some(store) = durable_checkpoint_store {
                    retain_phase_local_checkpoints_reachable_after_resume(
                        stage,
                        &mut retained_initial_phase_commitment_lane_checkpoints,
                        &mut retained_quotient_constraint_checkpoint,
                    )?;
                    store.remove_phase_local_checkpoints_superseded_by_authenticated_boundary(
                        &retained_initial_phase_commitment_lane_checkpoints,
                        retained_quotient_constraint_checkpoint.as_ref(),
                    )?;
                }
                resume_completion_observed = true;
            }
            CommonProofGenerationWorkerPoll::StorageRequestReady { .. } => {
                let response = {
                    let request = registry
                        .generation_storage_transaction_request(operation)
                        .map_err(|error| format!("read exact storage request: {error:?}"))?;
                    storage.execute_transaction(request)?
                };
                let encoded_request_byte_length = registry
                    .generation_storage_request_byte_length(operation)
                    .map_err(|error| format!("size exact storage request: {error:?}"))?;
                let mut encoded_request = vec![0_u8; encoded_request_byte_length];
                registry
                    .encode_generation_storage_request_into(operation, &mut encoded_request)
                    .map_err(|error| format!("encode exact storage request: {error:?}"))?;
                registry
                    .supply_generation_storage_response(operation, &response)
                    .map_err(|error| format!("supply exact storage response: {error:?}"))?;
            }
            CommonProofGenerationWorkerPoll::AuthenticatedSourceReadReady { .. } => {
                return Err(
                    "the production setup source unexpectedly requested caller bytes".to_owned(),
                );
            }
            CommonProofGenerationWorkerPoll::AuthenticatedTranscriptPrefixRequired => {
                let transcript_prefix = transcript_prefix.as_ref().ok_or_else(|| {
                    format!("{family_label} unexpectedly requested an authenticated prefix")
                })?;
                let request = registry
                    .generation_authenticated_transcript_prefix_request(operation)
                    .map_err(|error| format!("read exact transcript-prefix request: {error:?}"))?;
                let prepared = PreparedExactSameSecretTranscriptPrefix::prepare(
                    request,
                    transcript_prefix.prerequisite,
                    transcript_prefix.relation_plan,
                )
                .map_err(|error| format!("prepare exact transcript prefix: {error:?}"))?;
                registry
                    .supply_generation_authenticated_transcript_prefix(operation, prepared)
                    .map_err(|error| format!("supply exact transcript prefix: {error:?}"))?;
            }
            CommonProofGenerationWorkerPoll::OutputChunkReady {
                chunk_index,
                chunk_byte_length,
            } => {
                let (pending_chunk_index, bytes) = registry
                    .generation_output_chunk(operation)
                    .map_err(|error| format!("read exact output chunk: {error:?}"))?;
                if pending_chunk_index != chunk_index as usize
                    || bytes.len() != chunk_byte_length as usize
                    || output_chunks
                        .insert(pending_chunk_index, bytes.to_vec())
                        .is_some()
                {
                    return Err("exact output chunk coordinates are noncanonical".to_owned());
                }
                registry
                    .acknowledge_generation_output_chunk(operation)
                    .map_err(|error| format!("acknowledge exact output chunk: {error:?}"))?;
            }
            CommonProofGenerationWorkerPoll::OutputReadbackRequired { chunk_index } => {
                let bytes = output_chunks
                    .get(&(chunk_index as usize))
                    .ok_or_else(|| "exact output readback chunk is absent".to_owned())?;
                registry
                    .confirm_generation_output_readback(operation, chunk_index as usize, bytes)
                    .map_err(|error| format!("confirm exact output readback: {error:?}"))?;
            }
            CommonProofGenerationWorkerPoll::Complete => {
                if controlled_quotient_constraint_checkpoint_stop.is_some() {
                    return Err(
                        "generation completed after a controlled checkpoint stop was requested"
                            .to_owned(),
                    );
                }
                break;
            }
            CommonProofGenerationWorkerPoll::Cancelled => {
                let controlled_stop = controlled_quotient_constraint_checkpoint_stop
                    .take()
                    .ok_or_else(|| "active exact generation unexpectedly cancelled".to_owned())?;
                registry
                    .release_cancelled_generation(operation)
                    .map_err(|error| {
                        format!("release controlled cancelled generation: {error:?}")
                    })?;
                if storage.retained_secret_object_count() != 0 {
                    return Err(
                        "controlled checkpoint cancellation retained secret external-memory objects"
                            .to_owned(),
                    );
                }
                return Ok(
                    CommonProofGenerationEvidenceOutcome::ControlledQuotientConstraintCheckpointStop(
                        controlled_stop,
                    ),
                );
            }
        }
    }

    if !resume_completion_observed {
        return Err(
            "exact generation completed without reaching its retained checkpoint".to_owned(),
        );
    }
    if !retained_initial_phase_commitment_lane_checkpoints.is_empty() {
        return Err(
            "exact generation completed without reaching every retained initial phase lane checkpoint"
                .to_owned(),
        );
    }
    if retained_quotient_constraint_checkpoint.is_some() {
        return Err(
            "exact generation completed without reaching its retained quotient constraint checkpoint"
                .to_owned(),
        );
    }
    let generated_proof = registry
        .finish_owned_generation(operation)
        .map_err(|error| format!("finish {family_label} runtime generation: {error:?}"))?;
    let stream_descriptor = registry
        .preflight_generated_proof_pending_statement(
            &generated_proof,
            application_statement_schema_identifier,
            roster_position,
            schedule_position,
            canonical_application_statement_bytes,
        )
        .map_err(|error| format!("bind {family_label} generated descriptor: {error:?}"))?;
    registry
        .release_generated_proof(generated_proof)
        .map_err(|error| format!("retire {family_label} generated authority: {error:?}"))?;
    if storage.retained_secret_object_count() != 0 {
        return Err(format!(
            "{family_label} generation retained secret external-memory objects"
        ));
    }
    Ok(CommonProofGenerationEvidenceOutcome::Complete(
        GeneratedCommonProofEvidence {
            canonical_proof_bytes: output_chunks.into_values().flatten().collect(),
            stream_descriptor,
            maximum_external_memory_byte_length: storage.maximum_declared_byte_length(),
            checkpoint_count,
            resumed_from_checkpoint_boundary,
        },
    ))
}

fn generate_exact_same_secret_proof(
    authority_handle: &SetupGenerationAuthorityHandle,
    action_private_randomness: &std::rc::Rc<crate::foundation::ActionPrivateRandomness>,
    fresh_sources: PreparedExactSameSecretGenerationSources,
    prerequisite: &VerifiedSameSecretLowDegreePrerequisite,
    checkpoint_resume_enabled: bool,
) -> Result<GeneratedCommonProofEvidence, String> {
    let prefix_relation_plan = production_same_secret_relation()?.0;
    let (fresh_prepared, canonical_application_statement_bytes, roster_position) =
        prepare_exact_same_secret_common_proof(fresh_sources)?;
    let checkpoint_store = checkpoint_resume_enabled
        .then(|| {
            DurableCommonProofCheckpointStore::open(
                &fresh_prepared,
                EXACT_AGGREGATE_CHECKPOINT_PROFILE,
            )
        })
        .transpose()?;
    let retained_checkpoint = checkpoint_store
        .as_ref()
        .map(DurableCommonProofCheckpointStore::load_latest)
        .transpose()?
        .flatten();
    let prepared = match retained_checkpoint.as_ref() {
        Some(checkpoint) => {
            let checkpoint_continuation = checkpoint.authenticated.continuation_source();
            drop(fresh_prepared);
            let resumed_sources = prepare_production_same_secret_sources(
                authority_handle,
                action_private_randomness,
                Some(checkpoint_continuation),
            )?;
            let (resumed_prepared, resumed_statement_bytes, resumed_roster_position) =
                prepare_exact_same_secret_common_proof(resumed_sources)?;
            if resumed_statement_bytes != canonical_application_statement_bytes
                || resumed_roster_position != roster_position
                || !resumed_prepared.matches_authenticated_checkpoint(&checkpoint.authenticated)
            {
                return Err(
                    "resumed exact aggregate preparation differs from its authenticated checkpoint"
                        .to_owned(),
                );
            }
            resumed_prepared
        }
        None => fresh_prepared,
    };
    generate_prepared_common_proof(
        prepared,
        &canonical_application_statement_bytes,
        SetupKeyRelationProofFamily::SameSecret.statement_schema_identifier(),
        Some(roster_position),
        None,
        Some(ExactTranscriptPrefixEvidence {
            prerequisite,
            relation_plan: &prefix_relation_plan,
        }),
        "exact aggregate-wide same-secret proof",
        checkpoint_store.as_ref(),
        retained_checkpoint.as_ref(),
        false,
    )
    .and_then(CommonProofGenerationEvidenceOutcome::require_complete)
}

fn prepare_exact_same_secret_common_proof(
    sources: PreparedExactSameSecretGenerationSources,
) -> Result<(PreparedCommonProofGeneration, Vec<u8>, u16), String> {
    let limits = CommonProofRuntimeLimits::new(
        AUTOMATIC_ROW_CODE_WHIR_PROOF_ACCEPTANCE_BYTE_LENGTH,
        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
        u64::try_from(MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH)
            .map_err(|_| "exact output chunk length exceeds u64".to_owned())?,
    )
    .map_err(|error| format!("construct exact generation limits: {error:?}"))?;
    let request_context = sources
        .source_polynomials
        .exact_same_secret_evidence_request_context();
    let statement = decode_selected_same_secret_statement(
        &sources.canonical_application_statement_bytes,
        SelectedApplicationStatementContext::new(
            request_context.protocol_version(),
            request_context.suite_identifier(),
            None,
            None,
        ),
    )
    .map_err(|error| format!("decode exact generation statement: {error:?}"))?;
    let roster_position = statement.roster_position();
    let PreparedExactSameSecretGenerationSources {
        authorization,
        relation_plan,
        relation_trees,
        source_polynomials,
        private_coins,
        canonical_application_statement_bytes,
        ..
    } = sources;
    let prepared = PreparedCommonProofGeneration::from_row_code_whir_sources(
        authorization,
        relation_plan,
        canonical_application_statement_bytes.clone(),
        relation_trees,
        limits,
        CommonProofGenerationSources::new(private_coins, source_polynomials),
    )
    .map_err(|error| format!("prepare exact runtime generation: {error:?}"))?;
    Ok((
        prepared,
        canonical_application_statement_bytes,
        roster_position,
    ))
}

fn generate_vss_prerequisite_proof(
    evidence_sources: &ProductionVssPrerequisiteEvidenceSources,
    checkpoint_resume_enabled: bool,
    stop_after_quotient_constraint_checkpoint: bool,
) -> Result<(CommonProofGenerationEvidenceOutcome, Vec<u8>), String> {
    let (fresh_prepared, canonical_application_statement_bytes) =
        prepare_production_vss_prerequisite_generation(evidence_sources)?;
    let checkpoint_store = checkpoint_resume_enabled
        .then(|| {
            DurableCommonProofCheckpointStore::open(
                &fresh_prepared,
                VSS_PREREQUISITE_CHECKPOINT_PROFILE,
            )
        })
        .transpose()?;
    let retained_checkpoint = checkpoint_store
        .as_ref()
        .map(DurableCommonProofCheckpointStore::load_latest)
        .transpose()?
        .flatten();
    let prepared = match retained_checkpoint.as_ref() {
        Some(checkpoint) => {
            let checkpoint_continuation = checkpoint.authenticated.continuation_source();
            drop(fresh_prepared);
            let (resumed_prepared, resumed_statement_bytes) =
                prepare_resumed_production_vss_prerequisite_generation(
                    evidence_sources,
                    checkpoint_continuation,
                )?;
            if resumed_statement_bytes != canonical_application_statement_bytes
                || !resumed_prepared.matches_authenticated_checkpoint(&checkpoint.authenticated)
            {
                return Err(
                    "resumed VSS preparation differs from its authenticated checkpoint".to_owned(),
                );
            }
            resumed_prepared
        }
        None => fresh_prepared,
    };
    let verified_context = evidence_sources.verified_public_randomness.context();
    let statement = crate::bgv::proof_suite::decode_selected_vss_share_linkage_statement(
        &canonical_application_statement_bytes,
        SelectedApplicationStatementContext::new(
            verified_context.protocol_version(),
            verified_context.suite_identifier().into_bytes(),
            None,
            None,
        ),
    )
    .map_err(|error| format!("decode VSS evidence statement: {error:?}"))?;
    let generated = generate_prepared_common_proof(
        prepared,
        &canonical_application_statement_bytes,
        ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
        Some(statement.roster_position()),
        None,
        None,
        "selected VSS prerequisite proof",
        checkpoint_store.as_ref(),
        retained_checkpoint.as_ref(),
        stop_after_quotient_constraint_checkpoint,
    )?;
    Ok((generated, canonical_application_statement_bytes))
}

fn verification_proof_chunk(proof: &[u8], chunk_index: usize) -> Result<&[u8], String> {
    let byte_start = chunk_index
        .checked_mul(MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH)
        .ok_or_else(|| "verification chunk offset overflowed".to_owned())?;
    let byte_end = byte_start
        .checked_add(MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH)
        .map(|end| end.min(proof.len()))
        .ok_or_else(|| "verification chunk extent overflowed".to_owned())?;
    proof
        .get(byte_start..byte_end)
        .filter(|chunk| !chunk.is_empty())
        .ok_or_else(|| format!("verification chunk {chunk_index} is absent"))
}

fn verify_vss_prerequisite_proof(
    canonical_proof_bytes: &[u8],
    stream_descriptor: StreamDescriptor,
    canonical_application_statement_bytes: Vec<u8>,
    verified_public_randomness: &VerifiedPublicRandomness,
) -> Result<ConsumedVerifiedCommonProofCapability, String> {
    let runtime_plan = selected_vss_proof_runtime_plan(&canonical_application_statement_bytes)
        .map_err(|error| format!("derive VSS verification runtime plan: {error:?}"))?;
    let statement_source =
        VerifiedCommonProofStatementSource::from_test_verified_vss_statement_source(
            verified_public_randomness,
            canonical_application_statement_bytes,
            stream_descriptor,
            runtime_plan.relation_plan,
            runtime_plan.limits,
        )
        .map_err(|error| format!("bind verified VSS statement source: {error:?}"))?;
    let statement_trees =
        VerifiedStatementOwnedTree::from_verified_committed_material_statement_source(
            &statement_source,
            verified_public_randomness,
        )
        .map_err(|error| format!("derive verified VSS statement trees: {error:?}"))?;
    let prepared = statement_source
        .prepare_exact_vss_evidence_verification(statement_trees)
        .map_err(|error| format!("prepare production VSS verifier: {error:?}"))?;
    let mut registry = CommonProofRuntimeRegistry::default();
    let operation = registry
        .preissue_verification_operation_handle()
        .map_err(|error| format!("reserve VSS verification operation: {error:?}"))?;
    registry
        .begin_owned_verification_with_handle(prepared, operation)
        .map_err(|error| format!("begin VSS verification: {error:?}"))?;
    for (chunk_index, chunk_bytes) in canonical_proof_bytes
        .chunks(MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH)
        .enumerate()
    {
        registry
            .absorb_verification_input_chunk(operation, chunk_index, chunk_bytes)
            .map_err(|error| format!("ingest VSS proof chunk {chunk_index}: {error:?}"))?;
    }
    registry
        .finish_verification_input(operation)
        .map_err(|error| format!("finish VSS proof ingestion: {error:?}"))?;
    while let CommonProofVerificationWorkerPoll::NeedsReadback {
        first_chunk_index,
        second_chunk_index,
    } = registry
        .poll_owned_verification(operation)
        .map_err(|error| format!("poll VSS verification: {error:?}"))?
    {
        for chunk_index in [Some(first_chunk_index), second_chunk_index]
            .into_iter()
            .flatten()
        {
            let chunk_index = usize::try_from(chunk_index)
                .map_err(|_| "VSS readback chunk index exceeds usize".to_owned())?;
            let chunk_bytes = verification_proof_chunk(canonical_proof_bytes, chunk_index)?;
            registry
                .supply_verification_readback_chunk(operation, chunk_index, chunk_bytes)
                .map_err(|error| format!("supply VSS readback chunk {chunk_index}: {error:?}"))?;
        }
    }
    let verified_proof_handle = registry
        .finish_owned_verification(operation)
        .map_err(|error| format!("finish VSS verification: {error:?}"))?;
    registry
        .consume_verified_proof_for_protocol(&verified_proof_handle)
        .map_err(|error| format!("retain verified VSS evidence authority: {error:?}"))
}

fn verify_exact_same_secret_proof(
    proof: &[u8],
    prerequisite: VerifiedSameSecretLowDegreePrerequisite,
    context: ExactSameSecretVerificationContext,
) -> Result<ExactSameSecretVerificationMetrics, String> {
    let canonical_header = context.canonical_proof_object_header_bytes.clone();
    let header_comparator = IncrementalExpectedProofObjectHeaderComparator::new(
        canonical_header,
        proof.len(),
        MAXIMUM_COMMON_PROOF_BYTE_LENGTH,
    )
    .map_err(|error| format!("prepare exact header comparator: {error:?}"))?;
    let prepared = PreparedExactSameSecretVerification {
        prerequisite,
        context,
        header_comparator,
    };
    let mut incremental = prepared.into_incremental()?;
    let mut available_end_offset = 0_usize;
    while available_end_offset < proof.len() {
        available_end_offset = proof
            .len()
            .min(available_end_offset + MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH);
        incremental.consume_available(proof, available_end_offset)?;
    }
    if !incremental.is_decoding_complete() || incremental.decoded_byte_length() != proof.len() {
        return Err(
            "exact incremental decoder did not consume the authenticated stream".to_owned(),
        );
    }
    let mut final_verification = incremental.finish_decoding()?;
    for chunk in proof.chunks(MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH) {
        final_verification.absorb(chunk)?;
    }
    final_verification.finish()
}

fn assert_exact_proof_refuses(
    proof: &[u8],
    prerequisite_factory: &ExactVerificationPrerequisiteFactory,
    verification_context: ExactSameSecretVerificationContext,
    label: &str,
) {
    let error = verify_exact_same_secret_proof(
        proof,
        prerequisite_factory
            .build()
            .expect("rebuild exact verification prerequisite"),
        verification_context,
    )
    .expect_err(label);
    eprintln!("exact hostile case refused ({label}): {error}");
}

fn flipped_exact_proof_target(proof: &[u8], target: &ExactProofHostileMutationTarget) -> Vec<u8> {
    assert!(
        !target.byte_range.is_empty() && target.byte_range.end <= proof.len(),
        "hostile mutation target {} is outside the proof",
        target.label
    );
    let mut mutated = proof.to_vec();
    mutated[target.byte_range.start] ^= 1;
    mutated
}

fn distinct_frontier_node_offsets(
    proof: &[u8],
    target: &ExactProofHostileMutationTarget,
) -> (usize, usize) {
    assert_eq!(target.kind, ExactProofHostileMutationTargetKind::Frontier);
    assert_eq!(target.byte_range.len() % 64, 0);
    let node_offsets = (target.byte_range.start..target.byte_range.end)
        .step_by(64)
        .collect::<Vec<_>>();
    for (first_ordinal, first_offset) in node_offsets.iter().enumerate() {
        for second_offset in &node_offsets[first_ordinal + 1..] {
            if proof[*first_offset..*first_offset + 64]
                != proof[*second_offset..*second_offset + 64]
            {
                return (*first_offset, *second_offset);
            }
        }
    }
    panic!(
        "hostile frontier {} has no two distinct nodes",
        target.label
    );
}

fn run_exact_proof_hostile_byte_cases(
    proof: &[u8],
    prerequisite_factory: &ExactVerificationPrerequisiteFactory,
    verification_context: &ExactSameSecretVerificationContext,
    targets: &[ExactProofHostileMutationTarget],
) {
    let mut labels = std::collections::BTreeSet::new();
    for target in targets {
        assert!(
            labels.insert(target.label.clone()),
            "duplicate hostile label"
        );
        if target.kind == ExactProofHostileMutationTargetKind::Count
            || target.label.contains("proof-of-work witness")
        {
            continue;
        }
        let mutated = flipped_exact_proof_target(proof, target);
        assert_exact_proof_refuses(
            &mutated,
            prerequisite_factory,
            verification_context.clone(),
            &format!("altered {}", target.label),
        );
    }

    for count_label in [
        "out-of-domain evaluation count",
        "quotient phase frontier count",
        "bound tree 10 frontier count",
        "aggregate-wide opening count",
        "WHIR terminal fresh-pad frontier count",
    ] {
        let target = targets
            .iter()
            .find(|target| target.label == count_label)
            .unwrap_or_else(|| panic!("missing hostile count target {count_label}"));
        assert_eq!(target.kind, ExactProofHostileMutationTargetKind::Count);
        assert_eq!(target.byte_range.len(), core::mem::size_of::<u32>());
        let mut mutated = proof.to_vec();
        mutated[target.byte_range.clone()].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_exact_proof_refuses(
            &mutated,
            prerequisite_factory,
            verification_context.clone(),
            &format!("oversized {count_label}"),
        );
    }

    let noncanonical_target = targets
        .iter()
        .find(|target| target.label == "terminal non-Boolean opening evaluation")
        .expect("terminal non-Boolean mutation target");
    assert_eq!(
        noncanonical_target.kind,
        ExactProofHostileMutationTargetKind::Field
    );
    let mut noncanonical = proof.to_vec();
    noncanonical[noncanonical_target.byte_range.start
        ..noncanonical_target.byte_range.start + core::mem::size_of::<u64>()]
        .copy_from_slice(&GOLDILOCKS_MODULUS.to_le_bytes());
    assert_exact_proof_refuses(
        &noncanonical,
        prerequisite_factory,
        verification_context.clone(),
        "noncanonical terminal field encoding",
    );

    for frontier_label in [
        "base phase compact frontier",
        "WHIR terminal source compact frontier",
    ] {
        let target = targets
            .iter()
            .find(|target| target.label == frontier_label)
            .unwrap_or_else(|| panic!("missing hostile frontier target {frontier_label}"));
        let (first_offset, second_offset) = distinct_frontier_node_offsets(proof, target);

        let mut duplicated = proof.to_vec();
        let first_node = duplicated[first_offset..first_offset + 64].to_vec();
        duplicated[second_offset..second_offset + 64].copy_from_slice(&first_node);
        assert_exact_proof_refuses(
            &duplicated,
            prerequisite_factory,
            verification_context.clone(),
            &format!("duplicated {frontier_label} node"),
        );

        let mut reordered = proof.to_vec();
        let first_node = reordered[first_offset..first_offset + 64].to_vec();
        let second_node = reordered[second_offset..second_offset + 64].to_vec();
        reordered[first_offset..first_offset + 64].copy_from_slice(&second_node);
        reordered[second_offset..second_offset + 64].copy_from_slice(&first_node);
        assert_exact_proof_refuses(
            &reordered,
            prerequisite_factory,
            verification_context.clone(),
            &format!("reordered {frontier_label} nodes"),
        );
    }

    let mut trailing = proof.to_vec();
    trailing.push(0);
    assert_exact_proof_refuses(
        &trailing,
        prerequisite_factory,
        verification_context.clone(),
        "trailing proof byte",
    );
    assert_exact_proof_refuses(
        &proof[..proof.len() - 1],
        prerequisite_factory,
        verification_context.clone(),
        "truncated terminal proof byte",
    );
    assert_exact_proof_refuses(
        &proof[..verification_context
            .canonical_proof_object_header_bytes
            .len()],
        prerequisite_factory,
        verification_context.clone(),
        "proof body omitted after canonical header",
    );
}

fn run_exact_context_hostile_cases(
    proof: &[u8],
    prerequisite_factory: &ExactVerificationPrerequisiteFactory,
    verification_context: &ExactSameSecretVerificationContext,
) {
    let application_slot = verification_context.application_slot;
    let rebuild_context =
        |protocol_version: u16,
         application_slot: ProofApplicationSlot,
         canonical_application_statement_bytes: Vec<u8>,
         statement_owned_trees: Vec<VerifiedStatementOwnedTree>| {
            ExactSameSecretVerificationContext::new(
                protocol_version,
                application_slot,
                canonical_application_statement_bytes,
                statement_owned_trees,
            )
        };

    let mut wrong_suite_identifier = application_slot.suite_identifier().into_bytes();
    wrong_suite_identifier[0] ^= 1;
    let wrong_suite_slot = ProofApplicationSlot::new(
        Hash512::from_bytes(wrong_suite_identifier),
        application_slot.ceremony_context_hash(),
        application_slot.action_context_hash(),
        application_slot.application_statement_schema_identifier(),
        application_slot.roster_position(),
        application_slot.schedule_position(),
        application_slot.producer_sequence(),
    )
    .expect("construct wrong-suite hostile slot");
    assert_exact_proof_refuses(
        proof,
        prerequisite_factory,
        rebuild_context(
            verification_context.protocol_version,
            wrong_suite_slot,
            verification_context
                .canonical_application_statement_bytes
                .clone(),
            verification_context.statement_owned_trees.clone(),
        )
        .expect("construct wrong-suite hostile context"),
        "wrong suite identity",
    );

    let mut wrong_ceremony_context_hash = application_slot.ceremony_context_hash().into_bytes();
    wrong_ceremony_context_hash[0] ^= 1;
    let wrong_ceremony_slot = ProofApplicationSlot::new(
        application_slot.suite_identifier(),
        Hash512::from_bytes(wrong_ceremony_context_hash),
        application_slot.action_context_hash(),
        application_slot.application_statement_schema_identifier(),
        application_slot.roster_position(),
        application_slot.schedule_position(),
        application_slot.producer_sequence(),
    )
    .expect("construct wrong-ceremony hostile slot");
    assert_exact_proof_refuses(
        proof,
        prerequisite_factory,
        rebuild_context(
            verification_context.protocol_version,
            wrong_ceremony_slot,
            verification_context
                .canonical_application_statement_bytes
                .clone(),
            verification_context.statement_owned_trees.clone(),
        )
        .expect("construct wrong-ceremony hostile context"),
        "wrong manifest-bound ceremony context",
    );

    let mut wrong_action_context_hash = application_slot.action_context_hash().into_bytes();
    wrong_action_context_hash[0] ^= 1;
    let wrong_action_slot = ProofApplicationSlot::new(
        application_slot.suite_identifier(),
        application_slot.ceremony_context_hash(),
        Hash512::from_bytes(wrong_action_context_hash),
        application_slot.application_statement_schema_identifier(),
        application_slot.roster_position(),
        application_slot.schedule_position(),
        application_slot.producer_sequence(),
    )
    .expect("construct wrong-action hostile slot");
    assert_exact_proof_refuses(
        proof,
        prerequisite_factory,
        rebuild_context(
            verification_context.protocol_version,
            wrong_action_slot,
            verification_context
                .canonical_application_statement_bytes
                .clone(),
            verification_context.statement_owned_trees.clone(),
        )
        .expect("construct wrong-action hostile context"),
        "wrong action context",
    );

    assert_exact_proof_refuses(
        proof,
        prerequisite_factory,
        rebuild_context(
            verification_context.protocol_version + 1,
            application_slot,
            verification_context
                .canonical_application_statement_bytes
                .clone(),
            verification_context.statement_owned_trees.clone(),
        )
        .expect("construct wrong-version hostile context"),
        "wrong protocol version",
    );

    let mut wrong_statement = verification_context
        .canonical_application_statement_bytes
        .clone();
    let final_statement_byte = wrong_statement
        .last_mut()
        .expect("exact application statement is nonempty");
    *final_statement_byte ^= 1;
    match rebuild_context(
        verification_context.protocol_version,
        application_slot,
        wrong_statement,
        verification_context.statement_owned_trees.clone(),
    ) {
        Ok(wrong_statement_context) => assert_exact_proof_refuses(
            proof,
            prerequisite_factory,
            wrong_statement_context,
            "altered canonical application statement",
        ),
        Err(error) => eprintln!("altered canonical application statement refused: {error}"),
    }

    for tree_ordinal in 0..verification_context.statement_owned_trees.len() {
        let mut wrong_trees = verification_context.statement_owned_trees.clone();
        let mut wrong_root = wrong_trees[tree_ordinal].expected_root();
        wrong_root[0] ^= 1;
        wrong_trees[tree_ordinal] = wrong_trees[tree_ordinal].with_test_expected_root(wrong_root);
        assert_exact_proof_refuses(
            proof,
            prerequisite_factory,
            rebuild_context(
                verification_context.protocol_version,
                application_slot,
                verification_context
                    .canonical_application_statement_bytes
                    .clone(),
                wrong_trees,
            )
            .expect("construct wrong-public-root hostile context"),
            &format!("wrong public input root {tree_ordinal}"),
        );
    }
}

struct ScopedPhaseCheckpointTestDirectory {
    path: PathBuf,
}

impl ScopedPhaseCheckpointTestDirectory {
    fn new(label: &str) -> Self {
        let repository_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("the checkpoint test repository root resolves");
        let parent = repository_root.join("temp").join("test-checkpoints");
        fs::create_dir_all(&parent).expect("the checkpoint test parent exists");
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("the checkpoint test clock is after the epoch")
            .as_nanos();
        let path = parent.join(format!(
            "initial-phase-checkpoint-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("the checkpoint test directory is unique");
        Self { path }
    }
}

impl Drop for ScopedPhaseCheckpointTestDirectory {
    fn drop(&mut self) {
        match fs::remove_dir_all(&self.path) {
            Err(error) if self.path.exists() => eprintln!(
                "failed to remove checkpoint test directory {}: {error}",
                self.path.display()
            ),
            Ok(()) | Err(_) => {}
        }
    }
}

fn phase_checkpoint_test_store(
    directory: &ScopedPhaseCheckpointTestDirectory,
    attempt_tag: u8,
) -> DurableCommonProofCheckpointStore {
    DurableCommonProofCheckpointStore {
        directory: directory.path.clone(),
        profile: VSS_PREREQUISITE_CHECKPOINT_PROFILE,
        stable_attempt_binding_hash: [attempt_tag; Hash512::BYTE_LENGTH],
        checkpoint_lineage_identifier: [attempt_tag.wrapping_add(1); 32],
    }
}

#[test]
fn initial_phase_commitment_lane_checkpoint_names_are_canonical_and_bounded() {
    for (file_name, expected) in [
        ("initial-phase-00-lane-00000004.seal", Some((0, 4))),
        ("initial-phase-01-lane-00000012.seal", Some((1, 12))),
        ("initial-phase-02-lane-99999996.seal", Some((2, 99_999_996))),
        ("initial-phase-00-lane-00000000.seal", None),
        ("initial-phase-00-lane-00000005.seal", None),
        ("initial-phase-03-lane-00000004.seal", None),
        ("initial-phase-0-lane-00000004.seal", None),
        ("initial-phase-00-lane-0000004.seal", None),
        ("initial-phase-00-lane-00000004.state", None),
        ("initial-phase-00-lane-00000004.seal.trailing", None),
    ] {
        assert_eq!(
            parse_initial_phase_commitment_lane_checkpoint_coordinates(file_name),
            expected,
            "unexpected phase checkpoint filename result for {file_name}",
        );
    }
    assert_eq!(
        parse_initial_phase_commitment_lane_checkpoint_coordinates_from_any_file(
            "initial-phase-02-lane-00000008.state"
        ),
        Some((2, 8)),
    );
    assert_eq!(
        validate_initial_phase_commitment_lane_checkpoint_coordinates(2, 8),
        Ok(()),
    );
    assert!(validate_initial_phase_commitment_lane_checkpoint_coordinates(2, 7).is_err());
    assert!(validate_initial_phase_commitment_lane_checkpoint_coordinates(3, 8).is_err());
}

#[test]
fn initial_phase_commitment_lane_checkpoint_custody_replaces_and_binds_state() {
    let directory = ScopedPhaseCheckpointTestDirectory::new("custody");
    let store = phase_checkpoint_test_store(&directory, 0x41);
    let phase_zero_lane_four_state = vec![0x14; 97];
    let phase_zero_lane_eight_state = (0_u8..=126).collect::<Vec<_>>();
    let phase_one_lane_four_state = vec![0x24; 193];

    store
        .persist_initial_phase_commitment_lane_checkpoint(0, 4, &phase_zero_lane_four_state)
        .expect("the first phase checkpoint persists");
    store
        .persist_initial_phase_commitment_lane_checkpoint(0, 8, &phase_zero_lane_eight_state)
        .expect("the replacement phase checkpoint persists");
    store
        .persist_initial_phase_commitment_lane_checkpoint(1, 4, &phase_one_lane_four_state)
        .expect("the independent phase checkpoint persists");

    for suffix in [
        INITIAL_PHASE_COMMITMENT_LANE_CHECKPOINT_STATE_SUFFIX,
        INITIAL_PHASE_COMMITMENT_LANE_CHECKPOINT_SEAL_SUFFIX,
    ] {
        assert!(
            !store
                .initial_phase_commitment_lane_checkpoint_path(0, 4, suffix)
                .exists(),
            "the superseded phase-zero lane-four {suffix} file must be removed",
        );
    }
    let loaded = store
        .load_initial_phase_commitment_lane_checkpoints()
        .expect("the newest checkpoint for each phase loads");
    assert!(
        store
            .load_latest()
            .expect("phase checkpoint seals do not masquerade as standard checkpoints")
            .is_none()
    );
    assert_eq!(loaded.len(), 2);
    assert_eq!(loaded[&0].phase_ordinal, 0);
    assert_eq!(loaded[&0].completed_lane_count, 8);
    assert_eq!(loaded[&0].state, phase_zero_lane_eight_state);
    assert_eq!(loaded[&1].phase_ordinal, 1);
    assert_eq!(loaded[&1].completed_lane_count, 4);
    assert_eq!(loaded[&1].state, phase_one_lane_four_state);

    store
        .persist_initial_phase_commitment_lane_checkpoint(0, 8, &loaded[&0].state)
        .expect("deterministic replay may persist the same checkpoint again");
    let mut different_same_coordinate = loaded[&0].state.clone();
    different_same_coordinate[0] ^= 1;
    assert!(
        store
            .persist_initial_phase_commitment_lane_checkpoint(0, 8, &different_same_coordinate,)
            .is_err(),
        "the same coordinate cannot be rebound to different state",
    );

    let wrong_attempt_store = phase_checkpoint_test_store(&directory, 0x42);
    assert!(
        wrong_attempt_store
            .load_initial_phase_commitment_lane_checkpoints()
            .is_err(),
        "another proof attempt cannot restore retained lane state",
    );

    let tampered_state_path = store.initial_phase_commitment_lane_checkpoint_path(
        1,
        4,
        INITIAL_PHASE_COMMITMENT_LANE_CHECKPOINT_STATE_SUFFIX,
    );
    let mut tampered_state = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&tampered_state_path)
        .expect("the retained phase-one state opens for hostile mutation");
    tampered_state
        .seek(SeekFrom::Start(0))
        .expect("the hostile mutation seeks to the first byte");
    tampered_state
        .write_all(&[0x25])
        .expect("the hostile mutation changes one retained byte");
    tampered_state
        .sync_all()
        .expect("the hostile mutation reaches durable storage");
    assert!(
        store
            .load_initial_phase_commitment_lane_checkpoint(1, 4)
            .is_err(),
        "a changed state must fail its retained seal",
    );

    let unknown_seal_path = directory.path.join("unexpected.seal");
    persist_exact_file_once(&unknown_seal_path, &[0x51], "hostile unknown seal")
        .expect("the hostile unknown seal persists");
    assert!(
        store.load_latest().is_err(),
        "an unknown custody seal must remain a loud failure",
    );
}

#[test]
fn quotient_constraint_checkpoint_names_are_canonical_and_bounded() {
    for (file_name, expected) in [
        ("quotient-constraint-00000064.seal", Some(64)),
        ("quotient-constraint-00000128.seal", Some(128)),
        ("quotient-constraint-99999936.seal", Some(99_999_936)),
        ("quotient-constraint-00000000.seal", None),
        ("quotient-constraint-00000065.seal", None),
        ("quotient-constraint-0000064.seal", None),
        ("quotient-constraint-00000064.state", None),
        ("quotient-constraint-00000064.seal.trailing", None),
    ] {
        assert_eq!(
            parse_quotient_constraint_checkpoint_coordinate(file_name),
            expected,
            "unexpected quotient checkpoint filename result for {file_name}",
        );
    }
    assert_eq!(
        parse_quotient_constraint_checkpoint_coordinate_from_any_file(
            "quotient-constraint-00000192.state"
        ),
        Some(192),
    );
    assert_eq!(
        validate_quotient_constraint_checkpoint_coordinate(64),
        Ok(())
    );
    assert!(validate_quotient_constraint_checkpoint_coordinate(0).is_err());
    assert!(validate_quotient_constraint_checkpoint_coordinate(63).is_err());
}

#[test]
fn authenticated_boundary_removes_only_superseded_phase_local_checkpoints() {
    let directory = ScopedPhaseCheckpointTestDirectory::new("phase-local-supersession");
    let store = phase_checkpoint_test_store(&directory, 0x60);
    store
        .persist_initial_phase_commitment_lane_checkpoint(0, 4, &[0x41; 17])
        .expect("the retained initial phase checkpoint persists");
    store
        .persist_initial_phase_commitment_lane_checkpoint(1, 4, &[0x43; 23])
        .expect("the future auxiliary phase checkpoint persists");
    store
        .persist_initial_phase_commitment_lane_checkpoint(2, 4, &[0x44; 29])
        .expect("the future quotient tree phase checkpoint persists");
    store
        .persist_quotient_constraint_checkpoint(64, &[0x42; 19])
        .expect("the retained quotient checkpoint persists");
    let mut retained_initial_phase_checkpoints = store
        .load_initial_phase_commitment_lane_checkpoints()
        .expect("the retained initial phase checkpoints load");
    let mut retained_quotient_checkpoint = Some(
        store
            .load_quotient_constraint_checkpoint(64)
            .expect("the retained quotient checkpoint loads"),
    );

    retain_phase_local_checkpoints_reachable_after_resume(
        CommonProofGenerationStage::MaterializingBaseTrees,
        &mut retained_initial_phase_checkpoints,
        &mut retained_quotient_checkpoint,
    )
    .expect("same-stage and future local checkpoints remain reachable");
    store
        .remove_phase_local_checkpoints_superseded_by_authenticated_boundary(
            &retained_initial_phase_checkpoints,
            retained_quotient_checkpoint.as_ref(),
        )
        .expect("future retained phase-local checkpoints remain available");
    assert_eq!(
        store
            .load_initial_phase_commitment_lane_checkpoints()
            .expect("the preserved initial phase checkpoint remains readable")
            .len(),
        3,
    );
    assert!(
        store
            .load_latest_quotient_constraint_checkpoint()
            .expect("the preserved quotient checkpoint remains readable")
            .is_some(),
    );

    retain_phase_local_checkpoints_reachable_after_resume(
        CommonProofGenerationStage::ConstructingQuotient,
        &mut retained_initial_phase_checkpoints,
        &mut retained_quotient_checkpoint,
    )
    .expect("the quotient stage supersedes both preceding commitment phases");
    store
        .remove_phase_local_checkpoints_superseded_by_authenticated_boundary(
            &retained_initial_phase_checkpoints,
            retained_quotient_checkpoint.as_ref(),
        )
        .expect("the quotient stage removes only preceding local checkpoints");
    assert_eq!(
        store
            .load_initial_phase_commitment_lane_checkpoints()
            .expect("only the future quotient tree checkpoint remains")
            .keys()
            .copied()
            .collect::<Vec<_>>(),
        vec![2],
    );
    assert!(
        store
            .load_latest_quotient_constraint_checkpoint()
            .expect("the same-stage quotient checkpoint remains readable")
            .is_some(),
    );

    retain_phase_local_checkpoints_reachable_after_resume(
        CommonProofGenerationStage::DerivingOutOfDomainOpenings,
        &mut retained_initial_phase_checkpoints,
        &mut retained_quotient_checkpoint,
    )
    .expect("the later authenticated boundary supersedes every local checkpoint");
    store
        .remove_phase_local_checkpoints_superseded_by_authenticated_boundary(
            &retained_initial_phase_checkpoints,
            retained_quotient_checkpoint.as_ref(),
        )
        .expect("the later authenticated boundary removes superseded local checkpoints");
    assert!(
        store
            .load_initial_phase_commitment_lane_checkpoints()
            .expect("no superseded initial phase checkpoint remains")
            .is_empty(),
    );
    assert!(
        store
            .load_latest_quotient_constraint_checkpoint()
            .expect("no superseded quotient checkpoint remains")
            .is_none(),
    );
}

#[test]
fn quotient_constraint_checkpoint_custody_replaces_and_binds_state() {
    let directory = ScopedPhaseCheckpointTestDirectory::new("quotient-custody");
    let store = phase_checkpoint_test_store(&directory, 0x61);
    let constraint_sixty_four_state = vec![0x64; 5_193];
    let constraint_one_hundred_twenty_eight_state =
        (0_u8..=250).cycle().take(7_211).collect::<Vec<_>>();

    store
        .persist_quotient_constraint_checkpoint(64, &constraint_sixty_four_state)
        .expect("the first quotient checkpoint persists");
    store
        .persist_quotient_constraint_checkpoint(128, &constraint_one_hundred_twenty_eight_state)
        .expect("the replacement quotient checkpoint persists");
    for suffix in [
        QUOTIENT_CONSTRAINT_CHECKPOINT_STATE_SUFFIX,
        QUOTIENT_CONSTRAINT_CHECKPOINT_SEAL_SUFFIX,
    ] {
        assert!(
            !store
                .quotient_constraint_checkpoint_path(64, suffix)
                .exists(),
            "the superseded constraint-sixty-four {suffix} file must be removed",
        );
    }
    let loaded = store
        .load_latest_quotient_constraint_checkpoint()
        .expect("the newest quotient checkpoint loads")
        .expect("one quotient checkpoint is retained");
    assert!(
        store
            .load_latest()
            .expect("a quotient checkpoint seal does not masquerade as a standard checkpoint")
            .is_none()
    );
    assert_eq!(loaded.completed_constraint_count, 128);
    assert_eq!(loaded.state, constraint_one_hundred_twenty_eight_state);

    store
        .persist_quotient_constraint_checkpoint(128, &loaded.state)
        .expect("deterministic replay may persist the same quotient checkpoint again");
    let mut different_same_coordinate = loaded.state.clone();
    different_same_coordinate[0] ^= 1;
    assert!(
        store
            .persist_quotient_constraint_checkpoint(128, &different_same_coordinate)
            .is_err(),
        "the same quotient coordinate cannot be rebound to different state",
    );

    let wrong_source_store = DurableCommonProofCheckpointStore {
        directory: directory.path.clone(),
        profile: store.profile,
        stable_attempt_binding_hash: [0x62; Hash512::BYTE_LENGTH],
        checkpoint_lineage_identifier: store.checkpoint_lineage_identifier,
    };
    assert!(
        wrong_source_store
            .load_latest_quotient_constraint_checkpoint()
            .is_err(),
        "another authenticated source binding cannot restore retained quotient state",
    );
    let wrong_attempt_store = DurableCommonProofCheckpointStore {
        directory: directory.path.clone(),
        profile: store.profile,
        stable_attempt_binding_hash: [0x63; Hash512::BYTE_LENGTH],
        checkpoint_lineage_identifier: store.checkpoint_lineage_identifier,
    };
    assert!(
        wrong_attempt_store
            .load_latest_quotient_constraint_checkpoint()
            .is_err(),
        "another proof-attempt binding cannot restore retained quotient state",
    );
    let wrong_profile_store = DurableCommonProofCheckpointStore {
        directory: directory.path.clone(),
        profile: EXACT_AGGREGATE_CHECKPOINT_PROFILE,
        stable_attempt_binding_hash: store.stable_attempt_binding_hash,
        checkpoint_lineage_identifier: store.checkpoint_lineage_identifier,
    };
    assert!(
        wrong_profile_store
            .load_latest_quotient_constraint_checkpoint()
            .is_err(),
        "another proof profile cannot restore retained quotient state",
    );
    let wrong_lineage_store = DurableCommonProofCheckpointStore {
        directory: directory.path.clone(),
        profile: store.profile,
        stable_attempt_binding_hash: store.stable_attempt_binding_hash,
        checkpoint_lineage_identifier: [0x71; 32],
    };
    assert!(
        wrong_lineage_store
            .load_latest_quotient_constraint_checkpoint()
            .is_err(),
        "another checkpoint lineage cannot restore retained quotient state",
    );

    let state_path =
        store.quotient_constraint_checkpoint_path(128, QUOTIENT_CONSTRAINT_CHECKPOINT_STATE_SUFFIX);
    let mut tampered_state = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&state_path)
        .expect("the retained quotient state opens for hostile mutation");
    tampered_state
        .seek(SeekFrom::Start(0))
        .expect("the hostile quotient mutation seeks to the first byte");
    tampered_state
        .write_all(&[0x63])
        .expect("the hostile quotient mutation changes one retained byte");
    tampered_state
        .sync_all()
        .expect("the hostile quotient mutation reaches durable storage");
    assert!(
        store.load_quotient_constraint_checkpoint(128).is_err(),
        "a changed quotient state must fail its retained seal",
    );
}

#[test]
#[ignore = "manual focused production VSS prerequisite proof round trip"]
fn exact_vss_prerequisite_proof_round_trip() {
    let started_at = Instant::now();
    let checkpoint_resume_enabled =
        runner_enabled_checkpoint_resume().expect("read guarded checkpoint-resume ownership");
    let stop_after_quotient_constraint_checkpoint =
        runner_requested_stop_after_quotient_constraint_checkpoint()
            .expect("read runner-owned quotient checkpoint stop request");
    assert!(
        checkpoint_resume_enabled || !stop_after_quotient_constraint_checkpoint,
        "a controlled quotient checkpoint stop requires authenticated checkpoint custody",
    );
    let evidence_sources =
        production_vss_prerequisite_sources().expect("production VSS prerequisite runtime source");
    let (generation_outcome, canonical_application_statement_bytes) =
        generate_vss_prerequisite_proof(
            &evidence_sources,
            checkpoint_resume_enabled,
            stop_after_quotient_constraint_checkpoint,
        )
        .expect("generate production VSS prerequisite proof");
    let generated_proof = match generation_outcome {
        CommonProofGenerationEvidenceOutcome::Complete(generated_proof) => {
            assert!(
                !stop_after_quotient_constraint_checkpoint,
                "the requested quotient checkpoint stop was not reached",
            );
            generated_proof
        }
        CommonProofGenerationEvidenceOutcome::ControlledQuotientConstraintCheckpointStop(
            controlled_stop,
        ) => {
            let record = serde_json::json!({
                "authenticatedAfterWrite": true,
                "cancellationCompleted": true,
                "checkpointByteLength": controlled_stop.checkpoint_byte_length,
                "completedConstraintCount": controlled_stop.completed_constraint_count,
                "elapsedMilliseconds": controlled_stop.elapsed_milliseconds,
                "familyIdentifier": "selected-vss-prerequisite-proof",
                "maximumDeclaredExternalMemoryByteLength": controlled_stop
                    .maximum_external_memory_byte_length,
                "resumedFromAuthenticatedBoundary": controlled_stop
                    .resumed_from_checkpoint_boundary,
                "standardCheckpointCount": controlled_stop.standard_checkpoint_count,
            });
            eprintln!("{CONTROLLED_QUOTIENT_CONSTRAINT_CHECKPOINT_STOP_OUTPUT_PREFIX}{record}");
            release_production_same_secret_authority(evidence_sources.authority_handle)
                .expect("release production VSS prerequisite runtime authority after stop");
            return;
        }
    };
    eprintln!(
        "selected VSS prerequisite proof generated: {} bytes, {} peak declared external bytes, {} checkpoints, resumed from {:?}, {:?}",
        generated_proof.canonical_proof_bytes.len(),
        generated_proof.maximum_external_memory_byte_length,
        generated_proof.checkpoint_count,
        generated_proof.resumed_from_checkpoint_boundary,
        started_at.elapsed(),
    );
    assert!(generated_proof.checkpoint_count > 0);

    let verified_vss_proof = verify_vss_prerequisite_proof(
        &generated_proof.canonical_proof_bytes,
        generated_proof.stream_descriptor.clone(),
        canonical_application_statement_bytes,
        &evidence_sources.verified_public_randomness,
    )
    .expect("production verifier accepts the transported VSS prerequisite proof");
    assert_eq!(
        verified_vss_proof.application_statement_schema_identifier(),
        ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
    );
    assert_eq!(
        verified_vss_proof.proof_stream_descriptor(),
        &generated_proof.stream_descriptor,
    );
    eprintln!(
        "selected VSS prerequisite proof verified from transported bytes: {:?}",
        started_at.elapsed(),
    );
    drop(verified_vss_proof);
    release_production_same_secret_authority(evidence_sources.authority_handle)
        .expect("release production VSS prerequisite runtime authority");
}

#[test]
#[ignore = "manual exact aggregate-wide production proof round trip"]
fn exact_aggregate_wide_same_secret_proof_round_trip() {
    let started_at = Instant::now();
    let checkpoint_resume_enabled =
        runner_enabled_checkpoint_resume().expect("read guarded checkpoint-resume ownership");
    let evidence_sources =
        production_same_secret_sources().expect("production exact runtime source");
    let (vss_proof, vss_canonical_application_statement_bytes) = generate_vss_prerequisite_proof(
        &evidence_sources.vss_prerequisite,
        checkpoint_resume_enabled,
        false,
    )
    .expect("generate production VSS prerequisite proof");
    let vss_proof = vss_proof
        .require_complete()
        .expect("the aggregate prerequisite proof must complete");
    eprintln!(
        "selected VSS prerequisite proof generated: {} bytes, {} peak declared external bytes, {} checkpoints, resumed from {:?}, {:?}",
        vss_proof.canonical_proof_bytes.len(),
        vss_proof.maximum_external_memory_byte_length,
        vss_proof.checkpoint_count,
        vss_proof.resumed_from_checkpoint_boundary,
        started_at.elapsed(),
    );
    let verified_vss_proof = verify_vss_prerequisite_proof(
        &vss_proof.canonical_proof_bytes,
        vss_proof.stream_descriptor,
        vss_canonical_application_statement_bytes,
        &evidence_sources.vss_prerequisite.verified_public_randomness,
    )
    .expect("production verifier accepts the VSS prerequisite proof");
    let ProductionSameSecretEvidenceSources {
        sources,
        vss_prerequisite:
            ProductionVssPrerequisiteEvidenceSources {
                authority_handle,
                action_private_randomness,
                verified_public_randomness,
            },
    } = evidence_sources;
    let prerequisite_factory =
        ExactVerificationPrerequisiteFactory::new(verified_public_randomness, verified_vss_proof);
    let prerequisite = prerequisite_factory
        .build()
        .expect("production exact VSS prerequisite");
    let verification_prerequisite = prerequisite_factory
        .build()
        .expect("independent production exact VSS prerequisite");
    let application_slot = exact_application_slot(&sources).expect("exact application slot");
    let verification_trees =
        verified_statement_owned_trees(&sources.relation_plan_variant, &sources.relation_trees)
            .expect("verified exact statement trees");
    let verification_context = ExactSameSecretVerificationContext::new(
        sources
            .source_polynomials
            .exact_same_secret_evidence_request_context()
            .protocol_version(),
        application_slot,
        sources.canonical_application_statement_bytes.clone(),
        verification_trees,
    )
    .expect("exact verification context");

    let generated_proof = generate_exact_same_secret_proof(
        &authority_handle,
        &action_private_randomness,
        sources,
        &prerequisite,
        checkpoint_resume_enabled,
    )
    .expect("generate exact aggregate-wide same-secret proof");
    let proof = &generated_proof.canonical_proof_bytes;
    eprintln!(
        "exact aggregate-wide proof generated: {} bytes, {} peak declared external bytes, {checkpoint_count} checkpoints, resumed from {:?}, {:?}",
        proof.len(),
        generated_proof.maximum_external_memory_byte_length,
        generated_proof.resumed_from_checkpoint_boundary,
        started_at.elapsed(),
        checkpoint_count = generated_proof.checkpoint_count,
    );
    assert!(proof.len() <= AUTOMATIC_ROW_CODE_WHIR_PROOF_ACCEPTANCE_BYTE_LENGTH);
    assert!(generated_proof.checkpoint_count >= 6);

    let metrics = verify_exact_same_secret_proof(
        proof,
        verification_prerequisite,
        verification_context.clone(),
    )
    .expect("fresh exact verifier accepts generated aggregate-wide proof");
    assert_eq!(metrics.proof_byte_length, proof.len());
    assert!(metrics.maximum_resident_decoded_payload_byte_length < 64 * 1_024 * 1_024);
    assert_eq!(metrics.query_count, 387);
    eprintln!(
        "exact aggregate-wide proof verified in {:?}",
        started_at.elapsed()
    );

    let layout_prerequisite = prerequisite_factory
        .build()
        .expect("build exact hostile-layout prerequisite");
    let hostile_targets = exact_same_secret_hostile_mutation_targets(
        &layout_prerequisite,
        verification_context.clone(),
        proof,
    )
    .expect("derive exact hostile mutation layout");
    run_exact_proof_hostile_byte_cases(
        proof,
        &prerequisite_factory,
        &verification_context,
        &hostile_targets,
    );
    run_exact_context_hostile_cases(proof, &prerequisite_factory, &verification_context);

    release_production_same_secret_authority(authority_handle)
        .expect("release production exact runtime authority");
}
