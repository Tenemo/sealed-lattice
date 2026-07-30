use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use super::super::AUTOMATIC_ROW_CODE_WHIR_PROOF_ACCEPTANCE_BYTE_LENGTH;
use super::exact_proof::ExactSameSecretVerificationMetrics;
use super::*;
use crate::{
    bgv::{
        proof_suite::{
            CommonProofGenerationSources, CommonProofGenerationWorkerPoll,
            CommonProofRuntimeLimits, CommonProofRuntimeRegistry,
            MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH,
            MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH, ProofExternalMemoryObject,
            ProofExternalMemoryProtection, ProofExternalMemoryTransactionOperation,
            ProofExternalMemoryTransactionRequest, RelationProofTreeInput, RelationTreeDescriptor,
            VerifiedStatementOwnedTree,
        },
        setup::SetupKeyRelationProofFamily,
    },
    foundation::{Hash512, ProofApplicationSlot},
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

fn generate_exact_same_secret_proof(
    sources: PreparedExactSameSecretGenerationSources,
    prerequisite: &VerifiedSameSecretLowDegreePrerequisite,
) -> Result<(Vec<u8>, u64, usize), String> {
    let prefix_relation_plan = production_same_secret_relation()?.0;
    let limits = CommonProofRuntimeLimits::new(
        AUTOMATIC_ROW_CODE_WHIR_PROOF_ACCEPTANCE_BYTE_LENGTH,
        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
        u64::try_from(MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH)
            .map_err(|_| "exact output chunk length exceeds u64".to_owned())?,
    )
    .map_err(|error| format!("construct exact generation limits: {error:?}"))?;
    let PreparedExactSameSecretGenerationSources {
        authorization,
        relation_plan,
        relation_trees,
        source_polynomials,
        private_coins,
        canonical_application_statement_bytes,
        ..
    } = sources;
    let prepared =
        crate::bgv::proof_suite::PreparedCommonProofGeneration::from_row_code_whir_sources(
            authorization,
            relation_plan,
            canonical_application_statement_bytes,
            relation_trees,
            limits,
            CommonProofGenerationSources::new(private_coins, source_polynomials),
        )
        .map_err(|error| format!("prepare exact runtime generation: {error:?}"))?;
    let mut registry = CommonProofRuntimeRegistry::default();
    let operation = registry
        .begin_owned_generation(prepared)
        .map_err(|error| format!("begin exact runtime generation: {error:?}"))?;
    let mut storage = FileBackedExternalMemory::new()?;
    let mut output_chunks = BTreeMap::<usize, Vec<u8>>::new();
    let mut checkpoint_count = 0_usize;
    let mut last_stage = None;
    let started_at = Instant::now();

    loop {
        let poll = registry
            .poll_owned_generation(operation)
            .map_err(|error| format!("poll exact runtime generation: {error:?}"))?;
        match poll {
            CommonProofGenerationWorkerPoll::Progress {
                stage,
                checkpoint_ready,
            } => {
                if last_stage != Some(stage) {
                    eprintln!(
                        "exact aggregate-wide generation stage {stage:?}: {:?}",
                        started_at.elapsed()
                    );
                    last_stage = Some(stage);
                }
                if checkpoint_ready {
                    let checkpoint_state = registry
                        .generation_checkpoint_state(operation)
                        .map_err(|error| format!("read exact checkpoint state: {error:?}"))?;
                    let cursor_manifest = registry
                        .generation_checkpoint_cursor_manifest(operation)
                        .map_err(|error| format!("read exact checkpoint cursor: {error:?}"))?;
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
                    checkpoint_count += 1;
                    registry
                        .discard_generation_checkpoint(operation)
                        .map_err(|error| format!("advance exact checkpoint: {error:?}"))?;
                }
            }
            CommonProofGenerationWorkerPoll::ResumeComplete { .. } => {
                return Err(
                    "fresh exact generation unexpectedly reported resume completion".to_owned(),
                );
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
                let request = registry
                    .generation_authenticated_transcript_prefix_request(operation)
                    .map_err(|error| format!("read exact transcript-prefix request: {error:?}"))?;
                let prepared = PreparedExactSameSecretTranscriptPrefix::prepare(
                    request,
                    prerequisite,
                    &prefix_relation_plan,
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
            CommonProofGenerationWorkerPoll::Complete => break,
            CommonProofGenerationWorkerPoll::Cancelled => {
                return Err("active exact generation unexpectedly cancelled".to_owned());
            }
        }
    }

    let _generated_proof = registry
        .finish_owned_generation(operation)
        .map_err(|error| format!("finish exact runtime generation: {error:?}"))?;
    if storage.retained_secret_object_count() != 0 {
        return Err("exact generation retained secret external-memory objects".to_owned());
    }
    Ok((
        output_chunks.into_values().flatten().collect(),
        storage.maximum_declared_byte_length(),
        checkpoint_count,
    ))
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

#[test]
#[ignore = "manual exact aggregate-wide production proof round trip"]
fn heavy_rust_kernel_exact_aggregate_wide_same_secret_proof_round_trip() {
    let started_at = Instant::now();
    let ProductionSameSecretEvidenceSources {
        sources,
        authority_handle,
    } = production_same_secret_sources().expect("production exact runtime source");
    let prerequisite =
        production_same_secret_prerequisite(&sources).expect("production exact VSS prerequisite");
    let verification_prerequisite = production_same_secret_prerequisite(&sources)
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

    let (proof, maximum_external_memory_byte_length, checkpoint_count) =
        generate_exact_same_secret_proof(sources, &prerequisite)
            .expect("generate exact aggregate-wide same-secret proof");
    eprintln!(
        "exact aggregate-wide proof generated: {} bytes, {} peak declared external bytes, {checkpoint_count} checkpoints, {:?}",
        proof.len(),
        maximum_external_memory_byte_length,
        started_at.elapsed(),
    );
    assert!(proof.len() <= AUTOMATIC_ROW_CODE_WHIR_PROOF_ACCEPTANCE_BYTE_LENGTH);
    assert!(checkpoint_count >= 6);

    let metrics =
        verify_exact_same_secret_proof(&proof, verification_prerequisite, verification_context)
            .expect("fresh exact verifier accepts generated aggregate-wide proof");
    assert_eq!(metrics.proof_byte_length, proof.len());
    assert!(metrics.maximum_resident_decoded_payload_byte_length < 64 * 1_024 * 1_024);
    assert_eq!(metrics.query_count, 387);
    eprintln!(
        "exact aggregate-wide proof verified in {:?}",
        started_at.elapsed()
    );

    release_production_same_secret_authority(authority_handle)
        .expect("release production exact runtime authority");
}
