//! Portable release-WASM proof-storage width evidence runtime.
//!
//! This explicit manual-evidence surface runs the real packed-DEEP-FRI
//! commit, opening, and fresh-verifier path at the fixed representative width.
//! Every external-memory operation is recorded, yielded to the browser, and
//! then replayed exactly before the cryptographic state advances.

use std::{cell::RefCell, collections::BTreeMap};

use zeroize::{Zeroize, Zeroizing};

use super::super::ProofExternalMemoryTransactionAdapterError;
use super::super::external_memory::{
    EXTERNAL_MEMORY_OPERATION_HEADER_BYTE_LENGTH, EXTERNAL_MEMORY_REQUEST_HEADER_BYTE_LENGTH,
};
use super::super::runtime::CommonProofStorageTransactionRuntime;
use super::*;
use crate::hashing::StreamingHash512;

const BROWSER_EVIDENCE_RESULT_FORMAT_VERSION: u32 = 1;
const BROWSER_EVIDENCE_RESULT_BYTE_LENGTH: usize = 456;
const BROWSER_EVIDENCE_MANIFEST_IDENTITY_BYTE_LENGTH: usize = 64;
const BROWSER_EVIDENCE_SOURCE_COLUMN_COUNT: usize = WIDTH_REPRESENTATIVE_BROWSER_COLUMN_COUNT;
const BROWSER_EVIDENCE_PROOF_OBJECT_ORDINAL: u32 = WIDTH_REPRESENTATIVE_BROWSER_COLUMN_COUNT as u32;
const BROWSER_MAXIMUM_ENCODED_REQUEST_BYTE_LENGTH: usize =
    EXTERNAL_MEMORY_REQUEST_HEADER_BYTE_LENGTH
        + EXTERNAL_MEMORY_OPERATION_HEADER_BYTE_LENGTH
        + EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH as usize;
const SOURCE_CHUNK_COUNT: usize = 3;
const SOURCE_READ_PASS_COUNT: u64 = 6;
const POLL_PROGRESS: u32 = 1;
const POLL_STORAGE_REQUEST_READY: u32 = 2;
const POLL_COMPLETE: u32 = 3;
const STATUS_INVALID_ARGUMENT: u32 = 1;
const STATUS_UNKNOWN_HANDLE: u32 = 2;
const STATUS_WRONG_PHASE: u32 = 3;
const STATUS_OPERATION_FAILED: u32 = 4;
const STORAGE_RUNTIME_BINDING_DOMAIN: &str =
    "sealed-lattice/proof-storage-width-browser/storage-runtime/v1";
const ARTIFACT_HASH_DOMAIN: &str = "proof-storage/public-width-canonical-artifact/v1";

const _: () = assert!(BROWSER_EVIDENCE_SOURCE_COLUMN_COUNT == 512);
const _: () = assert!(PUBLIC_SOURCE_REPLAY_BYTE_LENGTH_PER_COLUMN == 131_072);
const _: () = assert!(BROWSER_EVIDENCE_RESULT_BYTE_LENGTH == 8 + 4 * 64 + 24 * 8);
const _: () = assert!(BROWSER_MAXIMUM_ENCODED_REQUEST_BYTE_LENGTH == 49_340);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TransactionCompletion {
    Pending,
    Committed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BrowserEvidencePhase {
    SourceCreate,
    SourceAppend,
    SourceSeal,
    InitializeRoot,
    RootFirst,
    RootBeginOpposite,
    RootOpposite,
    FinalizeRootAndPrepareProof,
    OpeningFirst,
    OpeningBeginOpposite,
    OpeningOpposite,
    FinalizeOpeningAndProof,
    ProofCreate,
    ProofAppend,
    ProofSeal,
    ProofRead,
    InitializeVerifier,
    VerifierFirst,
    VerifierBeginOpposite,
    VerifierOpposite,
    Verify,
    ProofDelete,
    SourceDelete,
    Finalize,
    Complete,
    Cancelled,
}

struct RootReplayState {
    catalog: CompleteProofTreeCatalog,
    digest_builders: Vec<ProofOraclePhasePairLeafDigestBuilder>,
    retained_coefficients: Vec<Vec<ProofBaseFieldElement>>,
}

struct OpeningReplayState {
    digest_builders: Vec<ProofOraclePhasePairLeafDigestBuilder>,
    first_values: Vec<Vec<ProofTreeValue>>,
    opposite_values: Vec<Vec<ProofTreeValue>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FreshVerifierIdentityPass {
    First,
    Opposite,
}

struct FreshVerifierCustodyBinding {
    expected_identity: [u8; 64],
    expected_base_root: [u8; 64],
    first_pass_verified: bool,
    opposite_pass_verified: bool,
}

impl FreshVerifierCustodyBinding {
    fn new(expected_identity: [u8; 64], expected_base_root: [u8; 64]) -> Self {
        Self {
            expected_identity,
            expected_base_root,
            first_pass_verified: false,
            opposite_pass_verified: false,
        }
    }

    fn verify_identity_pass(
        &mut self,
        pass: FreshVerifierIdentityPass,
        replayed_identity: [u8; 64],
    ) -> ProofBackendBakeoffResult<()> {
        let pass_label = match pass {
            FreshVerifierIdentityPass::First => {
                if self.first_pass_verified || self.opposite_pass_verified {
                    return Err(
                        "fresh browser verifier first identity pass is out of order".to_owned()
                    );
                }
                "first"
            }
            FreshVerifierIdentityPass::Opposite => {
                if !self.first_pass_verified || self.opposite_pass_verified {
                    return Err(
                        "fresh browser verifier opposite identity pass is out of order".to_owned(),
                    );
                }
                "opposite"
            }
        };
        if replayed_identity != self.expected_identity {
            return Err(format!(
                "fresh browser verifier {pass_label} pass diverges from the bound input identity"
            ));
        }
        match pass {
            FreshVerifierIdentityPass::First => self.first_pass_verified = true,
            FreshVerifierIdentityPass::Opposite => self.opposite_pass_verified = true,
        }
        Ok(())
    }

    fn verify_base_root(&self, recomputed_base_root: [u8; 64]) -> ProofBackendBakeoffResult<()> {
        if !self.first_pass_verified || !self.opposite_pass_verified {
            return Err(
                "fresh browser verifier cannot bind the base root before both identity passes"
                    .to_owned(),
            );
        }
        if recomputed_base_root != self.expected_base_root {
            return Err(
                "fresh browser verifier base root diverges from the public statement".to_owned(),
            );
        }
        Ok(())
    }
}

struct BrowserSourceIdentityReplay {
    hasher: StreamingHash512,
}

impl BrowserSourceIdentityReplay {
    fn new(
        frozen_input_identity_shake256_hex: &str,
        public_base_leaf_column_count: usize,
    ) -> ProofBackendBakeoffResult<Self> {
        Ok(Self {
            hasher: public_source_identity_hasher(
                frozen_input_identity_shake256_hex,
                public_base_leaf_column_count,
            )?,
        })
    }

    fn absorb_exact_source_bytes(&mut self, bytes: &[u8]) {
        self.hasher.absorb_raw(bytes);
    }

    fn finalize(self) -> [u8; 64] {
        self.hasher.finalize()
    }

    fn finish_identity_pass(
        self,
        custody_binding: &mut FreshVerifierCustodyBinding,
        pass: FreshVerifierIdentityPass,
    ) -> ProofBackendBakeoffResult<()> {
        custody_binding.verify_identity_pass(pass, self.finalize())
    }
}

struct VerifierReplayState {
    profile: FrozenProofProfile,
    custody_binding: FreshVerifierCustodyBinding,
    digest_builders: Vec<ProofOraclePhasePairLeafDigestBuilder>,
    first_values: Vec<Vec<ProofChallengeExtensionElement>>,
    opposite_values: Vec<Vec<ProofChallengeExtensionElement>>,
}

struct PreparedPublicWidthProof {
    profile: FrozenProofProfile,
    canonical_statement: Vec<u8>,
    transcript: CommonProofTranscript,
    composition_challenges: Vec<ProofChallengeExtensionElement>,
    quotient_evaluations: Vec<ProofChallengeExtensionElement>,
    quotient_coefficients: Vec<ProofChallengeExtensionElement>,
    deep_point: ProofChallengeExtensionElement,
    deep_evaluations: Vec<ProofChallengeExtensionElement>,
    opening_batch_challenges: Vec<ProofChallengeExtensionElement>,
    tree_roots: Vec<[u8; 64]>,
    terminal_coefficients: Vec<ProofChallengeExtensionElement>,
    sorted_query_representatives: Vec<u64>,
    column_coefficients: ProofBaseFieldColumns,
    evaluation_domain: ProofEvaluationDomain,
}

struct GeneratedPublicWidthArtifact {
    canonical_artifact: Zeroizing<Vec<u8>>,
    canonical_statement: Vec<u8>,
    sorted_query_representatives: Vec<u64>,
    opened_leaf_element_ranges: Vec<(usize, usize)>,
    canonical_leaf_byte_length: u64,
    recomputed_canonical_artifact_byte_length: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ArtifactRangeCounts {
    opened_leaf: u64,
    preleaf: u64,
    postleaf: u64,
}

fn record_observed_count(
    counter: &mut u64,
    increment: usize,
    label: &str,
) -> ProofBackendBakeoffResult<()> {
    let increment = u64::try_from(increment)
        .map_err(|_| format!("browser {label} increment does not fit u64"))?;
    *counter = counter
        .checked_add(increment)
        .ok_or_else(|| format!("browser {label} count overflowed"))?;
    Ok(())
}

struct BrowserProofStorageWidthOperation {
    manifest_identity: [u8; BROWSER_EVIDENCE_MANIFEST_IDENTITY_BYTE_LENGTH],
    fixture: ProofBackendBakeoffFixture,
    storage: CommonProofStorageTransactionRuntime,
    encoded_pending_request: Zeroizing<Vec<u8>>,
    encoded_pending_request_ready: bool,
    phase: BrowserEvidencePhase,
    source_column_index: usize,
    source_chunk_index: usize,
    append_payload_scratch: Zeroizing<Vec<u8>>,
    read_payload_scratch: Zeroizing<Vec<u8>>,
    source_column_values: Vec<ProofBaseFieldElement>,
    source_identity_replay: Option<BrowserSourceIdentityReplay>,
    input_identity: Option<[u8; 64]>,
    root_state: Option<RootReplayState>,
    opening_state: Option<OpeningReplayState>,
    verifier_state: Option<VerifierReplayState>,
    prepared_proof: Option<PreparedPublicWidthProof>,
    base_root: Option<[u8; 64]>,
    proof_artifact: Option<Zeroizing<Vec<u8>>>,
    proof_readback: Option<Zeroizing<Vec<u8>>>,
    canonical_statement: Option<Vec<u8>>,
    sorted_query_representatives: Vec<u64>,
    artifact_ranges: Vec<(usize, usize)>,
    artifact_range_index: usize,
    artifact_range_counts: ArtifactRangeCounts,
    canonical_leaf_byte_length: u64,
    recomputed_canonical_artifact_byte_length: u64,
    observed_lde_transform_count: u64,
    observed_absorbed_leaf_value_count: u64,
    observed_opened_value_count: u64,
    committed_transaction_count: u64,
    external_read_byte_length: u64,
    external_written_byte_length: u64,
    result: Option<[u8; BROWSER_EVIDENCE_RESULT_BYTE_LENGTH]>,
}

impl BrowserProofStorageWidthOperation {
    fn new(manifest_identity: [u8; 64]) -> ProofBackendBakeoffResult<Self> {
        let fixture = super::super::proof_backend_bakeoff::frozen_fixture()?;
        if fixture
            .columns
            .iter()
            .any(|column| column.len() != TRACE_DOMAIN_SIZE)
        {
            return Err("frozen browser evidence source geometry changed".to_owned());
        }
        let runtime_binding_hash = hash_framed_parts_512(
            STORAGE_RUNTIME_BINDING_DOMAIN,
            &[
                PUBLIC_SOURCE_RECIPE_DOMAIN.as_bytes(),
                PUBLIC_SOURCE_DERIVATION_ALGORITHM_IDENTIFIER.as_bytes(),
                PUBLIC_SOURCE_SEED_HEX.as_bytes(),
                &(BROWSER_EVIDENCE_SOURCE_COLUMN_COUNT as u64).to_le_bytes(),
                &(TRACE_DOMAIN_SIZE as u64).to_le_bytes(),
            ],
        );
        let source_identity_replay = BrowserSourceIdentityReplay::new(
            &fixture.input_identity_shake256_hex,
            BROWSER_EVIDENCE_SOURCE_COLUMN_COUNT,
        )?;
        Ok(Self {
            manifest_identity,
            fixture,
            storage: CommonProofStorageTransactionRuntime::for_runtime_binding(
                runtime_binding_hash,
            ),
            encoded_pending_request: Zeroizing::new(Vec::with_capacity(
                BROWSER_MAXIMUM_ENCODED_REQUEST_BYTE_LENGTH,
            )),
            encoded_pending_request_ready: false,
            phase: BrowserEvidencePhase::SourceCreate,
            source_column_index: 0,
            source_chunk_index: 0,
            append_payload_scratch: Zeroizing::new(Vec::with_capacity(
                EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH as usize,
            )),
            read_payload_scratch: Zeroizing::new(Vec::with_capacity(
                EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH as usize,
            )),
            source_column_values: Vec::with_capacity(EVALUATION_DOMAIN_SIZE),
            source_identity_replay: Some(source_identity_replay),
            input_identity: None,
            root_state: None,
            opening_state: None,
            verifier_state: None,
            prepared_proof: None,
            base_root: None,
            proof_artifact: None,
            proof_readback: None,
            canonical_statement: None,
            sorted_query_representatives: Vec::new(),
            artifact_ranges: Vec::new(),
            artifact_range_index: 0,
            artifact_range_counts: ArtifactRangeCounts::default(),
            canonical_leaf_byte_length: 0,
            recomputed_canonical_artifact_byte_length: 0,
            observed_lde_transform_count: 0,
            observed_absorbed_leaf_value_count: 0,
            observed_opened_value_count: 0,
            committed_transaction_count: 0,
            external_read_byte_length: 0,
            external_written_byte_length: 0,
            result: None,
        })
    }

    fn ensure_pending_request_encoding(&mut self) -> ProofBackendBakeoffResult<Option<usize>> {
        if self.storage.pending_request().is_none() {
            if self.encoded_pending_request_ready || !self.encoded_pending_request.is_empty() {
                return Err("browser evidence retained an encoding without a request".to_owned());
            }
            return Ok(None);
        }
        if !self.encoded_pending_request_ready {
            self.storage
                .encode_pending_worker_request_into(&mut self.encoded_pending_request)
                .map_err(|error| failure("encode browser evidence storage request", error))?;
            if self.encoded_pending_request.len() > BROWSER_MAXIMUM_ENCODED_REQUEST_BYTE_LENGTH {
                return Err(
                    "browser evidence request exceeded its fixed encoding buffer".to_owned(),
                );
            }
            self.encoded_pending_request_ready = true;
        }
        Ok(Some(self.encoded_pending_request.len()))
    }

    fn cached_pending_request(&self) -> ProofBackendBakeoffResult<Option<&[u8]>> {
        if self.storage.pending_request().is_none() {
            if self.encoded_pending_request_ready || !self.encoded_pending_request.is_empty() {
                return Err("browser evidence retained an encoding without a request".to_owned());
            }
            return Ok(None);
        }
        if !self.encoded_pending_request_ready {
            return Err("browser evidence pending request was not sized before copy".to_owned());
        }
        Ok(Some(self.encoded_pending_request.as_slice()))
    }

    fn supply_storage_response(
        &mut self,
        encoded_response: &[u8],
    ) -> ProofBackendBakeoffResult<()> {
        if !self.encoded_pending_request_ready {
            return Err("browser evidence storage response arrived before request copy".to_owned());
        }
        self.encoded_pending_request.as_mut_slice().zeroize();
        self.encoded_pending_request.clear();
        self.encoded_pending_request_ready = false;
        self.storage
            .supply_worker_response(encoded_response)
            .map_err(|error| failure("supply browser evidence storage response", error))?;
        Ok(())
    }

    fn complete_transaction(
        &mut self,
        result: Result<(), ProofExternalMemoryTransactionAdapterError>,
    ) -> ProofBackendBakeoffResult<TransactionCompletion> {
        match result {
            Err(ProofExternalMemoryTransactionAdapterError::Yielded) => {
                self.storage
                    .capture_yielded_request()
                    .map_err(|error| failure("capture browser evidence storage request", error))?;
                if self.encoded_pending_request_ready || !self.encoded_pending_request.is_empty() {
                    return Err(
                        "browser evidence attempted to replace a pending request encoding"
                            .to_owned(),
                    );
                }
                Ok(TransactionCompletion::Pending)
            }
            Ok(()) => {
                if !self.storage.replay_is_active() {
                    return Err("browser evidence transaction completed without replay".to_owned());
                }
                self.storage
                    .transaction_completed()
                    .map_err(|error| failure("complete browser evidence storage replay", error))?;
                self.committed_transaction_count = self
                    .committed_transaction_count
                    .checked_add(1)
                    .ok_or_else(|| "browser evidence transaction count overflowed".to_owned())?;
                Ok(TransactionCompletion::Committed)
            }
            Err(error) => Err(failure(
                "execute browser evidence storage transaction",
                error,
            )),
        }
    }

    fn create_object(
        &mut self,
        object: ProofExternalMemoryObject,
        exact_byte_length: u64,
    ) -> ProofBackendBakeoffResult<TransactionCompletion> {
        let result = (|| {
            self.storage
                .begin_transaction(u64::from(EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH), 1)?;
            self.storage.create_object(
                object,
                ProofExternalMemoryProtection::PublicIntegrity,
                exact_byte_length,
            )?;
            self.storage.commit_transaction()
        })();
        self.complete_transaction(result)
    }

    fn append_object_bytes(
        &mut self,
        object: ProofExternalMemoryObject,
        expected_offset: u64,
        bytes: &[u8],
    ) -> ProofBackendBakeoffResult<TransactionCompletion> {
        let result = (|| {
            self.storage
                .begin_transaction(u64::from(EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH), 1)?;
            self.storage
                .append_object_bytes(object, expected_offset, bytes)?;
            self.storage.commit_transaction()
        })();
        self.complete_transaction(result)
    }

    fn read_object_bytes(
        &mut self,
        object: ProofExternalMemoryObject,
        offset: u64,
        byte_length: usize,
    ) -> ProofBackendBakeoffResult<Option<Zeroizing<Vec<u8>>>> {
        if byte_length > EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH as usize {
            return Err("browser read exceeded its persistent scratch bound".to_owned());
        }
        let mut destination = core::mem::take(&mut self.read_payload_scratch);
        destination.resize(byte_length, 0);
        let result = (|| {
            self.storage
                .begin_transaction(u64::from(EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH), 1)?;
            self.storage
                .read_object_bytes(object, offset, &mut destination)?;
            self.storage.commit_transaction()
        })();
        let outcome = self.complete_transaction(result);
        match outcome {
            Ok(TransactionCompletion::Pending) => {
                destination.clear();
                self.read_payload_scratch = destination;
                Ok(None)
            }
            Ok(TransactionCompletion::Committed) => {
                let updated_read_byte_length = u64::try_from(byte_length)
                    .map_err(|_| "browser read length does not fit u64".to_owned())
                    .and_then(|byte_length| {
                        self.external_read_byte_length
                            .checked_add(byte_length)
                            .ok_or_else(|| "browser evidence read-byte count overflowed".to_owned())
                    });
                let updated_read_byte_length = match updated_read_byte_length {
                    Ok(updated_read_byte_length) => updated_read_byte_length,
                    Err(error) => {
                        destination.clear();
                        self.read_payload_scratch = destination;
                        return Err(error);
                    }
                };
                self.external_read_byte_length = updated_read_byte_length;
                Ok(Some(destination))
            }
            Err(error) => {
                destination.clear();
                self.read_payload_scratch = destination;
                Err(error)
            }
        }
    }

    fn recycle_read_payload(
        &mut self,
        mut bytes: Zeroizing<Vec<u8>>,
    ) -> ProofBackendBakeoffResult<()> {
        if !self.read_payload_scratch.is_empty() || self.read_payload_scratch.capacity() != 0 {
            return Err("browser read scratch was replaced before recycling".to_owned());
        }
        bytes.clear();
        self.read_payload_scratch = bytes;
        Ok(())
    }

    fn seal_object(
        &mut self,
        object: ProofExternalMemoryObject,
    ) -> ProofBackendBakeoffResult<TransactionCompletion> {
        let result = (|| {
            self.storage
                .begin_transaction(u64::from(EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH), 1)?;
            self.storage.seal_object(object)?;
            self.storage.commit_transaction()
        })();
        self.complete_transaction(result)
    }

    fn delete_object(
        &mut self,
        object: ProofExternalMemoryObject,
    ) -> ProofBackendBakeoffResult<TransactionCompletion> {
        let result = (|| {
            self.storage
                .begin_transaction(u64::from(EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH), 1)?;
            self.storage.delete_object(object)?;
            self.storage.commit_transaction()
        })();
        self.complete_transaction(result)
    }

    fn poll(&mut self) -> ProofBackendBakeoffResult<u32> {
        if self.storage.pending_request().is_some() {
            return Ok(POLL_STORAGE_REQUEST_READY);
        }
        match self.phase {
            BrowserEvidencePhase::SourceCreate => self.poll_source_create(),
            BrowserEvidencePhase::SourceAppend => self.poll_source_append(),
            BrowserEvidencePhase::SourceSeal => self.poll_source_seal(),
            BrowserEvidencePhase::InitializeRoot => self.initialize_root(),
            BrowserEvidencePhase::RootFirst => self.poll_root_first(),
            BrowserEvidencePhase::RootBeginOpposite => self.begin_root_opposite(),
            BrowserEvidencePhase::RootOpposite => self.poll_root_opposite(),
            BrowserEvidencePhase::FinalizeRootAndPrepareProof => {
                self.finalize_root_and_prepare_proof()
            }
            BrowserEvidencePhase::OpeningFirst => self.poll_opening_first(),
            BrowserEvidencePhase::OpeningBeginOpposite => self.begin_opening_opposite(),
            BrowserEvidencePhase::OpeningOpposite => self.poll_opening_opposite(),
            BrowserEvidencePhase::FinalizeOpeningAndProof => self.finalize_opening_and_proof(),
            BrowserEvidencePhase::ProofCreate => self.poll_proof_create(),
            BrowserEvidencePhase::ProofAppend => self.poll_proof_append(),
            BrowserEvidencePhase::ProofSeal => self.poll_proof_seal(),
            BrowserEvidencePhase::ProofRead => self.poll_proof_read(),
            BrowserEvidencePhase::InitializeVerifier => self.initialize_verifier(),
            BrowserEvidencePhase::VerifierFirst => self.poll_verifier_first(),
            BrowserEvidencePhase::VerifierBeginOpposite => self.begin_verifier_opposite(),
            BrowserEvidencePhase::VerifierOpposite => self.poll_verifier_opposite(),
            BrowserEvidencePhase::Verify => self.verify(),
            BrowserEvidencePhase::ProofDelete => self.poll_proof_delete(),
            BrowserEvidencePhase::SourceDelete => self.poll_source_delete(),
            BrowserEvidencePhase::Finalize => self.finalize_result(),
            BrowserEvidencePhase::Complete => Ok(POLL_COMPLETE),
            BrowserEvidencePhase::Cancelled => {
                Err("browser evidence operation was cancelled".to_owned())
            }
        }
    }

    fn cancel(&mut self) {
        self.storage.cancel();
        self.encoded_pending_request.as_mut_slice().zeroize();
        self.encoded_pending_request.clear();
        self.encoded_pending_request_ready = false;
        self.source_column_values.clear();
        if let Some(bytes) = self.proof_artifact.as_mut() {
            bytes.zeroize();
        }
        if let Some(bytes) = self.proof_readback.as_mut() {
            bytes.zeroize();
        }
        self.phase = BrowserEvidencePhase::Cancelled;
    }

    fn source_object(&self) -> ProofBackendBakeoffResult<ProofExternalMemoryObject> {
        Ok(ProofExternalMemoryObject::new(
            u32::try_from(self.source_column_index)
                .map_err(|_| "browser source ordinal does not fit u32".to_owned())?,
        ))
    }

    fn source_chunk_range(&self) -> ProofBackendBakeoffResult<(usize, usize)> {
        source_chunk_range(self.source_chunk_index)
    }

    fn poll_source_create(&mut self) -> ProofBackendBakeoffResult<u32> {
        let object = self.source_object()?;
        match self.create_object(object, PUBLIC_SOURCE_REPLAY_BYTE_LENGTH_PER_COLUMN)? {
            TransactionCompletion::Pending => Ok(POLL_STORAGE_REQUEST_READY),
            TransactionCompletion::Committed => {
                self.source_chunk_index = 0;
                self.phase = BrowserEvidencePhase::SourceAppend;
                Ok(POLL_PROGRESS)
            }
        }
    }

    fn poll_source_append(&mut self) -> ProofBackendBakeoffResult<u32> {
        let (start, end) = self.source_chunk_range()?;
        let mut bytes = core::mem::take(&mut self.append_payload_scratch);
        let result = (|| {
            fill_source_column_range_bytes(
                &self.fixture,
                self.source_column_index,
                start,
                end,
                &mut bytes,
            )?;
            let object = self.source_object()?;
            match self.append_object_bytes(
                object,
                u64::try_from(start).map_err(|_| "source offset does not fit u64".to_owned())?,
                &bytes,
            )? {
                TransactionCompletion::Pending => Ok(POLL_STORAGE_REQUEST_READY),
                TransactionCompletion::Committed => {
                    self.source_identity_replay
                        .as_mut()
                        .ok_or_else(|| "initial source identity was already finalized".to_owned())?
                        .absorb_exact_source_bytes(&bytes);
                    self.external_written_byte_length = self
                        .external_written_byte_length
                        .checked_add(
                            u64::try_from(bytes.len())
                                .map_err(|_| "source append length does not fit u64".to_owned())?,
                        )
                        .ok_or_else(|| "source written-byte count overflowed".to_owned())?;
                    self.source_chunk_index += 1;
                    if self.source_chunk_index == SOURCE_CHUNK_COUNT {
                        self.phase = BrowserEvidencePhase::SourceSeal;
                    }
                    Ok(POLL_PROGRESS)
                }
            }
        })();
        bytes.clear();
        self.append_payload_scratch = bytes;
        result
    }

    fn poll_source_seal(&mut self) -> ProofBackendBakeoffResult<u32> {
        let object = self.source_object()?;
        match self.seal_object(object)? {
            TransactionCompletion::Pending => Ok(POLL_STORAGE_REQUEST_READY),
            TransactionCompletion::Committed => {
                self.source_column_index += 1;
                if self.source_column_index == BROWSER_EVIDENCE_SOURCE_COLUMN_COUNT {
                    let identity = self
                        .source_identity_replay
                        .take()
                        .ok_or_else(|| "initial source identity hasher is missing".to_owned())?
                        .finalize();
                    self.input_identity = Some(identity);
                    self.phase = BrowserEvidencePhase::InitializeRoot;
                } else {
                    self.phase = BrowserEvidencePhase::SourceCreate;
                }
                Ok(POLL_PROGRESS)
            }
        }
    }

    fn initialize_root(&mut self) -> ProofBackendBakeoffResult<u32> {
        let input_identity = self
            .input_identity
            .ok_or_else(|| "browser source identity is missing".to_owned())?;
        let input_identity_hex = to_hex(&input_identity);
        let canonical_core_statement = canonical_public_width_core_statement(
            &input_identity_hex,
            BROWSER_EVIDENCE_SOURCE_COLUMN_COUNT,
        )?;
        let schedule = transcript_schedule()?;
        let catalog = proof_catalog_with_public_base_width(
            &canonical_core_statement,
            &input_identity_hex,
            &schedule,
            BROWSER_EVIDENCE_SOURCE_COLUMN_COUNT,
        )?;
        let context = catalog.entries()[0]
            .common_context()
            .ok_or_else(|| "browser root catalog lost its common context".to_owned())?;
        if usize::try_from(context.row_width())
            .map_err(|_| "browser root width does not fit usize".to_owned())?
            != BROWSER_EVIDENCE_SOURCE_COLUMN_COUNT
            || context.leaf_visibility() != ProofLeafVisibility::Public
        {
            return Err("browser root catalog does not match public source custody".to_owned());
        }
        self.root_state = Some(RootReplayState {
            digest_builders: public_base_digest_builders(context)?,
            catalog,
            retained_coefficients: Vec::with_capacity(COLUMN_COUNT),
        });
        self.reset_source_pass();
        self.phase = BrowserEvidencePhase::RootFirst;
        Ok(POLL_PROGRESS)
    }

    fn reset_source_pass(&mut self) {
        self.source_column_index = 0;
        self.source_chunk_index = 0;
        self.source_column_values.clear();
    }

    fn poll_source_column(&mut self) -> ProofBackendBakeoffResult<Option<bool>> {
        let (start, end) = self.source_chunk_range()?;
        let object = self.source_object()?;
        let Some(bytes) = self.read_object_bytes(object, start as u64, end - start)? else {
            return Ok(None);
        };
        let result = (|| {
            if bytes.len() % 8 != 0 {
                return Err("browser source response is not field-element aligned".to_owned());
            }
            if let Some(identity_replay) = self.source_identity_replay.as_mut() {
                identity_replay.absorb_exact_source_bytes(&bytes);
            }
            for encoded in bytes.chunks_exact(8) {
                let value = u64::from_le_bytes(
                    encoded
                        .try_into()
                        .map_err(|_| "browser source value is not eight bytes".to_owned())?,
                );
                self.source_column_values.push(
                    ProofBaseFieldElement::from_canonical(value)
                        .map_err(|error| failure("convert browser source value", error))?,
                );
            }
            self.source_chunk_index += 1;
            if self.source_chunk_index != SOURCE_CHUNK_COUNT {
                return Ok(Some(false));
            }
            if self.source_column_values.len() != TRACE_DOMAIN_SIZE {
                return Err("browser source replay returned the wrong exact length".to_owned());
            }
            self.source_chunk_index = 0;
            Ok(Some(true))
        })();
        self.recycle_read_payload(bytes)?;
        result
    }

    fn poll_root_first(&mut self) -> ProofBackendBakeoffResult<u32> {
        let Some(source_complete) = self.poll_source_column()? else {
            return Ok(POLL_STORAGE_REQUEST_READY);
        };
        if !source_complete {
            return Ok(POLL_PROGRESS);
        }
        let coefficients = evaluate_source_column_in_place(
            &mut self.source_column_values,
            self.source_column_index < COLUMN_COUNT,
        )?;
        record_observed_count(&mut self.observed_lde_transform_count, 1, "LDE transform")?;
        let root_state = self
            .root_state
            .as_mut()
            .ok_or_else(|| "browser root replay state is missing".to_owned())?;
        let leaf_count = root_state.digest_builders.len();
        absorb_first_base_values(
            &mut root_state.digest_builders,
            &self.source_column_values[..leaf_count],
        )?;
        record_observed_count(
            &mut self.observed_absorbed_leaf_value_count,
            leaf_count,
            "absorbed leaf value",
        )?;
        if let Some(coefficients) = coefficients {
            root_state.retained_coefficients.push(coefficients);
        }
        self.source_column_values.clear();
        self.source_column_index += 1;
        if self.source_column_index == BROWSER_EVIDENCE_SOURCE_COLUMN_COUNT {
            self.phase = BrowserEvidencePhase::RootBeginOpposite;
        }
        Ok(POLL_PROGRESS)
    }

    fn begin_root_opposite(&mut self) -> ProofBackendBakeoffResult<u32> {
        let root_state = self
            .root_state
            .as_mut()
            .ok_or_else(|| "browser root replay state is missing".to_owned())?;
        begin_opposite_base_values(&mut root_state.digest_builders)?;
        self.reset_source_pass();
        self.phase = BrowserEvidencePhase::RootOpposite;
        Ok(POLL_PROGRESS)
    }

    fn poll_root_opposite(&mut self) -> ProofBackendBakeoffResult<u32> {
        let Some(source_complete) = self.poll_source_column()? else {
            return Ok(POLL_STORAGE_REQUEST_READY);
        };
        if !source_complete {
            return Ok(POLL_PROGRESS);
        }
        let retained = evaluate_source_column_in_place(&mut self.source_column_values, false)?;
        record_observed_count(&mut self.observed_lde_transform_count, 1, "LDE transform")?;
        if retained.is_some() {
            return Err("browser opposite root replay retained coefficients".to_owned());
        }
        let root_state = self
            .root_state
            .as_mut()
            .ok_or_else(|| "browser root replay state is missing".to_owned())?;
        let leaf_count = root_state.digest_builders.len();
        absorb_opposite_base_values(
            &mut root_state.digest_builders,
            &self.source_column_values[leaf_count..],
        )?;
        record_observed_count(
            &mut self.observed_absorbed_leaf_value_count,
            leaf_count,
            "absorbed leaf value",
        )?;
        self.source_column_values.clear();
        self.source_column_index += 1;
        if self.source_column_index == BROWSER_EVIDENCE_SOURCE_COLUMN_COUNT {
            self.phase = BrowserEvidencePhase::FinalizeRootAndPrepareProof;
        }
        Ok(POLL_PROGRESS)
    }

    fn finalize_root_and_prepare_proof(&mut self) -> ProofBackendBakeoffResult<u32> {
        let root_state = self
            .root_state
            .take()
            .ok_or_else(|| "browser root replay state is missing".to_owned())?;
        let context = root_state.catalog.entries()[0]
            .common_context()
            .ok_or_else(|| "browser root context is missing".to_owned())?;
        let base_root = finish_base_replay_root(context, root_state.digest_builders, &[], None)?.0;
        let column_coefficients: ProofBaseFieldColumns = root_state
            .retained_coefficients
            .try_into()
            .map_err(|_| "browser root replay did not retain eight columns".to_owned())?;
        let input_identity_hex = to_hex(
            &self
                .input_identity
                .ok_or_else(|| "browser source identity is missing".to_owned())?,
        );
        let prepared = prepare_public_width_proof(
            &input_identity_hex,
            base_root,
            column_coefficients,
            &root_state.catalog,
        )?;
        let context = prepared.profile.layout.catalog().entries()[0]
            .common_context()
            .ok_or_else(|| "browser proof profile lost its base context".to_owned())?;
        let query_count = prepared.sorted_query_representatives.len();
        self.opening_state = Some(OpeningReplayState {
            digest_builders: public_base_digest_builders(context)?,
            first_values: (0..query_count)
                .map(|_| Vec::with_capacity(BROWSER_EVIDENCE_SOURCE_COLUMN_COUNT))
                .collect(),
            opposite_values: (0..query_count)
                .map(|_| Vec::with_capacity(BROWSER_EVIDENCE_SOURCE_COLUMN_COUNT))
                .collect(),
        });
        self.base_root = Some(base_root);
        self.prepared_proof = Some(prepared);
        self.reset_source_pass();
        self.phase = BrowserEvidencePhase::OpeningFirst;
        Ok(POLL_PROGRESS)
    }

    fn poll_opening_first(&mut self) -> ProofBackendBakeoffResult<u32> {
        let Some(source_complete) = self.poll_source_column()? else {
            return Ok(POLL_STORAGE_REQUEST_READY);
        };
        if !source_complete {
            return Ok(POLL_PROGRESS);
        }
        let retained = evaluate_source_column_in_place(&mut self.source_column_values, false)?;
        record_observed_count(&mut self.observed_lde_transform_count, 1, "LDE transform")?;
        if retained.is_some() {
            return Err("browser base opening replay retained coefficients".to_owned());
        }
        let prepared = self
            .prepared_proof
            .as_ref()
            .ok_or_else(|| "browser proof preparation is missing".to_owned())?;
        let opening_state = self
            .opening_state
            .as_mut()
            .ok_or_else(|| "browser opening replay state is missing".to_owned())?;
        let leaf_count = opening_state.digest_builders.len();
        absorb_first_base_values(
            &mut opening_state.digest_builders,
            &self.source_column_values[..leaf_count],
        )?;
        record_observed_count(
            &mut self.observed_absorbed_leaf_value_count,
            leaf_count,
            "absorbed leaf value",
        )?;
        for (position, query_index) in prepared
            .sorted_query_representatives
            .iter()
            .copied()
            .enumerate()
        {
            opening_state.first_values[position].push(ProofTreeValue::Base(
                self.source_column_values[usize::try_from(query_index)
                    .map_err(|_| "browser query index does not fit usize".to_owned())?],
            ));
        }
        self.source_column_values.clear();
        self.source_column_index += 1;
        if self.source_column_index == BROWSER_EVIDENCE_SOURCE_COLUMN_COUNT {
            self.phase = BrowserEvidencePhase::OpeningBeginOpposite;
        }
        Ok(POLL_PROGRESS)
    }

    fn begin_opening_opposite(&mut self) -> ProofBackendBakeoffResult<u32> {
        let opening_state = self
            .opening_state
            .as_mut()
            .ok_or_else(|| "browser opening replay state is missing".to_owned())?;
        begin_opposite_base_values(&mut opening_state.digest_builders)?;
        self.reset_source_pass();
        self.phase = BrowserEvidencePhase::OpeningOpposite;
        Ok(POLL_PROGRESS)
    }

    fn poll_opening_opposite(&mut self) -> ProofBackendBakeoffResult<u32> {
        let Some(source_complete) = self.poll_source_column()? else {
            return Ok(POLL_STORAGE_REQUEST_READY);
        };
        if !source_complete {
            return Ok(POLL_PROGRESS);
        }
        let retained = evaluate_source_column_in_place(&mut self.source_column_values, false)?;
        record_observed_count(&mut self.observed_lde_transform_count, 1, "LDE transform")?;
        if retained.is_some() {
            return Err("browser opposite opening replay retained coefficients".to_owned());
        }
        let prepared = self
            .prepared_proof
            .as_ref()
            .ok_or_else(|| "browser proof preparation is missing".to_owned())?;
        let opening_state = self
            .opening_state
            .as_mut()
            .ok_or_else(|| "browser opening replay state is missing".to_owned())?;
        let leaf_count = opening_state.digest_builders.len();
        absorb_opposite_base_values(
            &mut opening_state.digest_builders,
            &self.source_column_values[leaf_count..],
        )?;
        record_observed_count(
            &mut self.observed_absorbed_leaf_value_count,
            leaf_count,
            "absorbed leaf value",
        )?;
        for (position, query_index) in prepared
            .sorted_query_representatives
            .iter()
            .copied()
            .enumerate()
        {
            let opposite_index = usize::try_from(query_index)
                .map_err(|_| "browser query index does not fit usize".to_owned())?
                .checked_add(leaf_count)
                .ok_or_else(|| "browser opposite query index overflowed".to_owned())?;
            opening_state.opposite_values[position].push(ProofTreeValue::Base(
                self.source_column_values[opposite_index],
            ));
        }
        self.source_column_values.clear();
        self.source_column_index += 1;
        if self.source_column_index == BROWSER_EVIDENCE_SOURCE_COLUMN_COUNT {
            self.phase = BrowserEvidencePhase::FinalizeOpeningAndProof;
        }
        Ok(POLL_PROGRESS)
    }

    fn finalize_opening_and_proof(&mut self) -> ProofBackendBakeoffResult<u32> {
        let prepared = self
            .prepared_proof
            .take()
            .ok_or_else(|| "browser proof preparation is missing".to_owned())?;
        let opening_state = self
            .opening_state
            .take()
            .ok_or_else(|| "browser opening replay state is missing".to_owned())?;
        let base_opening = finish_public_base_opening(
            &prepared.profile.layout.catalog().entries()[0],
            &prepared.sorted_query_representatives,
            self.base_root
                .ok_or_else(|| "browser base root is missing".to_owned())?,
            opening_state,
        )?;
        let generated = finish_public_width_proof(prepared, base_opening)?;
        self.canonical_leaf_byte_length = generated.canonical_leaf_byte_length;
        self.recomputed_canonical_artifact_byte_length =
            generated.recomputed_canonical_artifact_byte_length;
        self.sorted_query_representatives = generated.sorted_query_representatives;
        self.canonical_statement = Some(generated.canonical_statement);
        let (ranges, counts) = artifact_transaction_ranges(
            generated.canonical_artifact.len(),
            &generated.opened_leaf_element_ranges,
        )?;
        self.artifact_ranges = ranges;
        self.artifact_range_counts = counts;
        self.proof_artifact = Some(generated.canonical_artifact);
        self.artifact_range_index = 0;
        self.phase = BrowserEvidencePhase::ProofCreate;
        Ok(POLL_PROGRESS)
    }

    fn proof_object() -> ProofExternalMemoryObject {
        ProofExternalMemoryObject::new(BROWSER_EVIDENCE_PROOF_OBJECT_ORDINAL)
    }

    fn poll_proof_create(&mut self) -> ProofBackendBakeoffResult<u32> {
        let length = self
            .proof_artifact
            .as_ref()
            .ok_or_else(|| "browser proof artifact is missing".to_owned())?
            .len();
        match self.create_object(
            Self::proof_object(),
            u64::try_from(length).map_err(|_| "proof length does not fit u64".to_owned())?,
        )? {
            TransactionCompletion::Pending => Ok(POLL_STORAGE_REQUEST_READY),
            TransactionCompletion::Committed => {
                self.phase = BrowserEvidencePhase::ProofAppend;
                Ok(POLL_PROGRESS)
            }
        }
    }

    fn poll_proof_append(&mut self) -> ProofBackendBakeoffResult<u32> {
        let (start, end) = *self
            .artifact_ranges
            .get(self.artifact_range_index)
            .ok_or_else(|| "browser proof append range is missing".to_owned())?;
        let mut bytes = core::mem::take(&mut self.append_payload_scratch);
        let result = (|| {
            let artifact_range = self
                .proof_artifact
                .as_ref()
                .and_then(|artifact| artifact.get(start..end))
                .ok_or_else(|| "browser proof append range is outside the artifact".to_owned())?;
            bytes.clear();
            bytes
                .try_reserve(artifact_range.len())
                .map_err(|_| "browser proof append scratch allocation failed".to_owned())?;
            bytes.extend_from_slice(artifact_range);
            match self.append_object_bytes(Self::proof_object(), start as u64, &bytes)? {
                TransactionCompletion::Pending => Ok(POLL_STORAGE_REQUEST_READY),
                TransactionCompletion::Committed => {
                    self.external_written_byte_length = self
                        .external_written_byte_length
                        .checked_add(
                            u64::try_from(bytes.len())
                                .map_err(|_| "proof append length does not fit u64".to_owned())?,
                        )
                        .ok_or_else(|| "proof written-byte count overflowed".to_owned())?;
                    self.artifact_range_index += 1;
                    if self.artifact_range_index == self.artifact_ranges.len() {
                        self.phase = BrowserEvidencePhase::ProofSeal;
                    }
                    Ok(POLL_PROGRESS)
                }
            }
        })();
        bytes.clear();
        self.append_payload_scratch = bytes;
        result
    }

    fn poll_proof_seal(&mut self) -> ProofBackendBakeoffResult<u32> {
        match self.seal_object(Self::proof_object())? {
            TransactionCompletion::Pending => Ok(POLL_STORAGE_REQUEST_READY),
            TransactionCompletion::Committed => {
                let exact_length = self
                    .proof_artifact
                    .as_ref()
                    .ok_or_else(|| "browser proof artifact is missing".to_owned())?
                    .len();
                self.proof_artifact.take();
                self.proof_readback = Some(Zeroizing::new(vec![0_u8; exact_length]));
                self.artifact_range_index = 0;
                self.phase = BrowserEvidencePhase::ProofRead;
                Ok(POLL_PROGRESS)
            }
        }
    }

    fn poll_proof_read(&mut self) -> ProofBackendBakeoffResult<u32> {
        let (start, end) = *self
            .artifact_ranges
            .get(self.artifact_range_index)
            .ok_or_else(|| "browser proof read range is missing".to_owned())?;
        let Some(bytes) =
            self.read_object_bytes(Self::proof_object(), start as u64, end - start)?
        else {
            return Ok(POLL_STORAGE_REQUEST_READY);
        };
        let result = (|| {
            self.proof_readback
                .as_mut()
                .and_then(|artifact| artifact.get_mut(start..end))
                .ok_or_else(|| "browser proof read range is outside the artifact".to_owned())?
                .copy_from_slice(&bytes);
            self.artifact_range_index += 1;
            if self.artifact_range_index == self.artifact_ranges.len() {
                self.phase = BrowserEvidencePhase::InitializeVerifier;
            }
            Ok(POLL_PROGRESS)
        })();
        self.recycle_read_payload(bytes)?;
        result
    }

    fn initialize_verifier(&mut self) -> ProofBackendBakeoffResult<u32> {
        let canonical_statement = self
            .canonical_statement
            .as_ref()
            .ok_or_else(|| "browser canonical statement is missing".to_owned())?;
        let input_identity = self
            .input_identity
            .ok_or_else(|| "browser input identity is missing".to_owned())?;
        let profile = public_width_proof_profile_from_public_input(
            canonical_statement,
            &to_hex(&input_identity),
        )?;
        let context = profile.layout.catalog().entries()[0]
            .common_context()
            .ok_or_else(|| "fresh browser verifier lost its base context".to_owned())?;
        if usize::try_from(context.row_width())
            .map_err(|_| "fresh browser verifier width does not fit usize".to_owned())?
            != BROWSER_EVIDENCE_SOURCE_COLUMN_COUNT
            || context.leaf_visibility() != ProofLeafVisibility::Public
        {
            return Err("fresh browser verifier profile does not match public custody".to_owned());
        }
        let query_count = self.sorted_query_representatives.len();
        self.verifier_state = Some(VerifierReplayState {
            digest_builders: public_base_digest_builders(context)?,
            custody_binding: FreshVerifierCustodyBinding::new(
                input_identity,
                profile.expected_fri_base_root,
            ),
            profile,
            first_values: (0..query_count)
                .map(|_| Vec::with_capacity(BROWSER_EVIDENCE_SOURCE_COLUMN_COUNT))
                .collect(),
            opposite_values: (0..query_count)
                .map(|_| Vec::with_capacity(BROWSER_EVIDENCE_SOURCE_COLUMN_COUNT))
                .collect(),
        });
        self.begin_verifier_identity_pass()?;
        self.reset_source_pass();
        self.phase = BrowserEvidencePhase::VerifierFirst;
        Ok(POLL_PROGRESS)
    }

    fn begin_verifier_identity_pass(&mut self) -> ProofBackendBakeoffResult<()> {
        if self.source_identity_replay.is_some() {
            return Err("fresh browser verifier replaced an active identity pass".to_owned());
        }
        self.source_identity_replay = Some(BrowserSourceIdentityReplay::new(
            &self.fixture.input_identity_shake256_hex,
            BROWSER_EVIDENCE_SOURCE_COLUMN_COUNT,
        )?);
        Ok(())
    }

    fn finish_verifier_identity_pass(
        &mut self,
        pass: FreshVerifierIdentityPass,
    ) -> ProofBackendBakeoffResult<()> {
        let replay = self
            .source_identity_replay
            .take()
            .ok_or_else(|| "fresh browser verifier identity hasher is missing".to_owned())?;
        let verifier_state = self
            .verifier_state
            .as_mut()
            .ok_or_else(|| "browser verifier replay state is missing".to_owned())?;
        replay.finish_identity_pass(&mut verifier_state.custody_binding, pass)
    }

    fn poll_verifier_first(&mut self) -> ProofBackendBakeoffResult<u32> {
        let Some(source_complete) = self.poll_source_column()? else {
            return Ok(POLL_STORAGE_REQUEST_READY);
        };
        if !source_complete {
            return Ok(POLL_PROGRESS);
        }
        let retained = evaluate_source_column_in_place(&mut self.source_column_values, false)?;
        record_observed_count(&mut self.observed_lde_transform_count, 1, "LDE transform")?;
        if retained.is_some() {
            return Err("fresh browser verifier replay retained coefficients".to_owned());
        }
        let verifier_state = self
            .verifier_state
            .as_mut()
            .ok_or_else(|| "browser verifier replay state is missing".to_owned())?;
        let leaf_count = verifier_state.digest_builders.len();
        absorb_first_base_values(
            &mut verifier_state.digest_builders,
            &self.source_column_values[..leaf_count],
        )?;
        record_observed_count(
            &mut self.observed_absorbed_leaf_value_count,
            leaf_count,
            "absorbed leaf value",
        )?;
        for (position, query_index) in self
            .sorted_query_representatives
            .iter()
            .copied()
            .enumerate()
        {
            let query_index = usize::try_from(query_index)
                .map_err(|_| "fresh browser query index does not fit usize".to_owned())?;
            verifier_state.first_values[position].push(ProofChallengeExtensionElement::from_base(
                self.source_column_values[query_index],
            ));
        }
        record_observed_count(
            &mut self.observed_opened_value_count,
            self.sorted_query_representatives.len(),
            "opened value",
        )?;
        self.source_column_values.clear();
        self.source_column_index += 1;
        if self.source_column_index == BROWSER_EVIDENCE_SOURCE_COLUMN_COUNT {
            self.finish_verifier_identity_pass(FreshVerifierIdentityPass::First)?;
            self.phase = BrowserEvidencePhase::VerifierBeginOpposite;
        }
        Ok(POLL_PROGRESS)
    }

    fn begin_verifier_opposite(&mut self) -> ProofBackendBakeoffResult<u32> {
        let verifier_state = self
            .verifier_state
            .as_mut()
            .ok_or_else(|| "browser verifier replay state is missing".to_owned())?;
        begin_opposite_base_values(&mut verifier_state.digest_builders)?;
        self.begin_verifier_identity_pass()?;
        self.reset_source_pass();
        self.phase = BrowserEvidencePhase::VerifierOpposite;
        Ok(POLL_PROGRESS)
    }

    fn poll_verifier_opposite(&mut self) -> ProofBackendBakeoffResult<u32> {
        let Some(source_complete) = self.poll_source_column()? else {
            return Ok(POLL_STORAGE_REQUEST_READY);
        };
        if !source_complete {
            return Ok(POLL_PROGRESS);
        }
        let retained = evaluate_source_column_in_place(&mut self.source_column_values, false)?;
        record_observed_count(&mut self.observed_lde_transform_count, 1, "LDE transform")?;
        if retained.is_some() {
            return Err("fresh browser opposite verifier replay retained coefficients".to_owned());
        }
        let verifier_state = self
            .verifier_state
            .as_mut()
            .ok_or_else(|| "browser verifier replay state is missing".to_owned())?;
        let leaf_count = verifier_state.digest_builders.len();
        absorb_opposite_base_values(
            &mut verifier_state.digest_builders,
            &self.source_column_values[leaf_count..],
        )?;
        record_observed_count(
            &mut self.observed_absorbed_leaf_value_count,
            leaf_count,
            "absorbed leaf value",
        )?;
        for (position, query_index) in self
            .sorted_query_representatives
            .iter()
            .copied()
            .enumerate()
        {
            let opposite_index = usize::try_from(query_index)
                .map_err(|_| "fresh browser query index does not fit usize".to_owned())?
                .checked_add(leaf_count)
                .ok_or_else(|| "fresh browser opposite query index overflowed".to_owned())?;
            verifier_state.opposite_values[position].push(
                ProofChallengeExtensionElement::from_base(
                    self.source_column_values[opposite_index],
                ),
            );
        }
        record_observed_count(
            &mut self.observed_opened_value_count,
            self.sorted_query_representatives.len(),
            "opened value",
        )?;
        self.source_column_values.clear();
        self.source_column_index += 1;
        if self.source_column_index == BROWSER_EVIDENCE_SOURCE_COLUMN_COUNT {
            self.finish_verifier_identity_pass(FreshVerifierIdentityPass::Opposite)?;
            self.phase = BrowserEvidencePhase::Verify;
        }
        Ok(POLL_PROGRESS)
    }

    fn verify(&mut self) -> ProofBackendBakeoffResult<u32> {
        let verifier_state = self
            .verifier_state
            .take()
            .ok_or_else(|| "browser verifier replay state is missing".to_owned())?;
        let context = verifier_state.profile.layout.catalog().entries()[0]
            .common_context()
            .ok_or_else(|| "fresh browser verifier base context is missing".to_owned())?;
        let recomputed_base_root =
            finish_base_replay_root(context, verifier_state.digest_builders, &[], None)?.0;
        verifier_state
            .custody_binding
            .verify_base_root(recomputed_base_root)?;
        let expected_openings = self
            .sorted_query_representatives
            .iter()
            .copied()
            .zip(verifier_state.first_values)
            .zip(verifier_state.opposite_values)
            .map(|((leaf_index, first_values), opposite_values)| {
                (
                    leaf_index,
                    AuthenticatedPhasePair {
                        first_values,
                        opposite_values,
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        let artifact = self
            .proof_readback
            .as_ref()
            .ok_or_else(|| "browser proof readback is missing".to_owned())?;
        verify_packed_deep_fri_with_profile(
            &verifier_state.profile,
            artifact,
            Some(expected_openings),
        )?;
        self.phase = BrowserEvidencePhase::ProofDelete;
        Ok(POLL_PROGRESS)
    }

    fn poll_proof_delete(&mut self) -> ProofBackendBakeoffResult<u32> {
        match self.delete_object(Self::proof_object())? {
            TransactionCompletion::Pending => Ok(POLL_STORAGE_REQUEST_READY),
            TransactionCompletion::Committed => {
                self.source_column_index = 0;
                self.phase = BrowserEvidencePhase::SourceDelete;
                Ok(POLL_PROGRESS)
            }
        }
    }

    fn poll_source_delete(&mut self) -> ProofBackendBakeoffResult<u32> {
        let object = self.source_object()?;
        match self.delete_object(object)? {
            TransactionCompletion::Pending => Ok(POLL_STORAGE_REQUEST_READY),
            TransactionCompletion::Committed => {
                self.source_column_index += 1;
                if self.source_column_index == BROWSER_EVIDENCE_SOURCE_COLUMN_COUNT {
                    self.phase = BrowserEvidencePhase::Finalize;
                }
                Ok(POLL_PROGRESS)
            }
        }
    }

    fn finalize_result(&mut self) -> ProofBackendBakeoffResult<u32> {
        let artifact = self
            .proof_readback
            .as_ref()
            .ok_or_else(|| "browser proof readback is missing".to_owned())?;
        let canonical_statement = self
            .canonical_statement
            .as_ref()
            .ok_or_else(|| "browser canonical statement is missing".to_owned())?;
        let artifact_hash = hash_framed_parts_512(
            ARTIFACT_HASH_DOMAIN,
            &[artifact.as_slice(), canonical_statement.as_slice()],
        );
        let input_identity = self
            .input_identity
            .ok_or_else(|| "browser input identity is missing".to_owned())?;
        let base_root = self
            .base_root
            .ok_or_else(|| "browser base root is missing".to_owned())?;
        let width = BROWSER_EVIDENCE_SOURCE_COLUMN_COUNT as u64;
        let source_replay_byte_length = PUBLIC_SOURCE_REPLAY_BYTE_LENGTH_PER_COLUMN
            .checked_mul(width)
            .ok_or_else(|| "browser source replay byte length overflowed".to_owned())?;
        let canonical_artifact_byte_length = u64::try_from(artifact.len())
            .map_err(|_| "browser artifact length does not fit u64".to_owned())?;
        let stored_scratch_peak_byte_length = source_replay_byte_length
            .checked_add(canonical_artifact_byte_length)
            .ok_or_else(|| "browser stored scratch peak overflowed".to_owned())?;
        let nonleaf_range_count = self
            .artifact_range_counts
            .preleaf
            .checked_add(self.artifact_range_counts.postleaf)
            .ok_or_else(|| "browser nonleaf range count overflowed".to_owned())?;
        let expected_transaction_count = width
            .checked_mul(24)
            .and_then(|count| count.checked_add(3))
            .and_then(|count| {
                self.artifact_range_counts
                    .opened_leaf
                    .checked_add(nonleaf_range_count)
                    .and_then(|range_count| range_count.checked_mul(2))
                    .and_then(|range_transactions| count.checked_add(range_transactions))
            })
            .ok_or_else(|| "browser transaction formula overflowed".to_owned())?;
        let expected_lde_transform_count = PUBLIC_SOURCE_REPLAY_COUNT
            .checked_mul(width)
            .ok_or_else(|| "browser expected LDE count overflowed".to_owned())?;
        let expected_absorbed_leaf_value_count = 393_216_u64
            .checked_mul(width)
            .ok_or_else(|| "browser expected absorbed value count overflowed".to_owned())?;
        let expected_opened_value_count = 366_u64
            .checked_mul(width)
            .ok_or_else(|| "browser expected opened value count overflowed".to_owned())?;
        if self.committed_transaction_count != expected_transaction_count
            || self.observed_lde_transform_count != expected_lde_transform_count
            || self.observed_absorbed_leaf_value_count != expected_absorbed_leaf_value_count
            || self.observed_opened_value_count != expected_opened_value_count
            || self.external_written_byte_length
                != source_replay_byte_length + canonical_artifact_byte_length
            || self.external_read_byte_length
                != source_replay_byte_length
                    .checked_mul(SOURCE_READ_PASS_COUNT)
                    .and_then(|bytes| bytes.checked_add(canonical_artifact_byte_length))
                    .ok_or_else(|| "browser read-byte formula overflowed".to_owned())?
            || canonical_artifact_byte_length
                > u64::try_from(MAXIMUM_COMMON_PROOF_BYTE_LENGTH)
                    .map_err(|_| "common-proof cap does not fit u64".to_owned())?
            || canonical_artifact_byte_length > MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH
            || stored_scratch_peak_byte_length
                > MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH
            || width + 1
                > u64::try_from(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_OBJECT_COUNT)
                    .map_err(|_| "external object cap does not fit u64".to_owned())?
        {
            return Err("browser evidence accounting or absolute cap check failed".to_owned());
        }
        let counters = [
            canonical_artifact_byte_length,
            self.recomputed_canonical_artifact_byte_length,
            source_replay_byte_length,
            self.canonical_leaf_byte_length
                .checked_mul(u64::from(UNIQUE_QUERY_COUNT))
                .ok_or_else(|| "browser queried payload length overflowed".to_owned())?,
            self.canonical_leaf_byte_length,
            self.canonical_leaf_byte_length
                .checked_add(4)
                .ok_or_else(|| "browser opened leaf length overflowed".to_owned())?,
            self.artifact_range_counts.opened_leaf,
            self.artifact_range_counts.preleaf,
            self.artifact_range_counts.postleaf,
            nonleaf_range_count,
            width + 1,
            stored_scratch_peak_byte_length,
            self.observed_lde_transform_count,
            self.observed_absorbed_leaf_value_count,
            self.observed_opened_value_count,
            self.external_read_byte_length,
            self.external_written_byte_length,
            self.committed_transaction_count,
            width
                .checked_mul(24)
                .ok_or_else(|| "browser source transaction count overflowed".to_owned())?,
            width,
            1,
            0,
            0,
            1,
        ];
        let mut encoded = [0_u8; BROWSER_EVIDENCE_RESULT_BYTE_LENGTH];
        encoded[0..4].copy_from_slice(&BROWSER_EVIDENCE_RESULT_FORMAT_VERSION.to_le_bytes());
        encoded[4..8].copy_from_slice(&(BROWSER_EVIDENCE_SOURCE_COLUMN_COUNT as u32).to_le_bytes());
        let mut offset = 8;
        for digest in [
            self.manifest_identity,
            input_identity,
            base_root,
            artifact_hash,
        ] {
            encoded[offset..offset + 64].copy_from_slice(&digest);
            offset += 64;
        }
        for counter in counters {
            encoded[offset..offset + 8].copy_from_slice(&counter.to_le_bytes());
            offset += 8;
        }
        if offset != encoded.len() {
            return Err("browser evidence result layout changed".to_owned());
        }
        self.result = Some(encoded);
        self.phase = BrowserEvidencePhase::Complete;
        Ok(POLL_COMPLETE)
    }
}

fn source_chunk_range(chunk_index: usize) -> ProofBackendBakeoffResult<(usize, usize)> {
    if chunk_index >= SOURCE_CHUNK_COUNT {
        return Err("browser source chunk index is out of range".to_owned());
    }
    let total = usize::try_from(PUBLIC_SOURCE_REPLAY_BYTE_LENGTH_PER_COLUMN)
        .map_err(|_| "source column length does not fit usize".to_owned())?;
    let chunk = usize::try_from(EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH)
        .map_err(|_| "external-memory chunk length does not fit usize".to_owned())?;
    let start = chunk_index
        .checked_mul(chunk)
        .ok_or_else(|| "source chunk offset overflowed".to_owned())?;
    Ok((start, start.saturating_add(chunk).min(total)))
}

fn fill_source_column_range_bytes(
    fixture: &ProofBackendBakeoffFixture,
    column_index: usize,
    start: usize,
    end: usize,
    bytes: &mut Vec<u8>,
) -> ProofBackendBakeoffResult<()> {
    if start >= end
        || end > PUBLIC_SOURCE_REPLAY_BYTE_LENGTH_PER_COLUMN as usize
        || !start.is_multiple_of(8)
        || !end.is_multiple_of(8)
    {
        return Err("browser source range is not field-element aligned".to_owned());
    }
    bytes.clear();
    bytes
        .try_reserve(end - start)
        .map_err(|_| "browser source range allocation failed".to_owned())?;
    for row_index in start / 8..end / 8 {
        bytes.extend_from_slice(
            &public_source_value(fixture, column_index, row_index).to_le_bytes(),
        );
    }
    Ok(())
}

fn evaluate_source_column_in_place(
    working: &mut Vec<ProofBaseFieldElement>,
    retain_coefficients: bool,
) -> ProofBackendBakeoffResult<Option<Vec<ProofBaseFieldElement>>> {
    if working.len() != TRACE_DOMAIN_SIZE {
        return Err("browser source column has the wrong exact length".to_owned());
    }
    let trace_domain = ProofEvaluationDomain::new_subgroup(TRACE_DOMAIN_SIZE)
        .map_err(|error| failure("construct browser source trace subgroup", error))?;
    let evaluation_domain =
        ProofEvaluationDomain::new(EVALUATION_DOMAIN_SIZE, EVALUATION_COSET_OFFSET)
            .map_err(|error| failure("construct browser source evaluation coset", error))?;
    trace_domain
        .interpolate_base_polynomial_in_place(working)
        .map_err(|error| failure("interpolate browser source column", error))?;
    if working.is_empty() || working.len() > OPENING_DEGREE_BOUND_EXCLUSIVE {
        return Err("browser source column exceeded its degree bound".to_owned());
    }
    let retained = retain_coefficients.then(|| working.clone());
    evaluation_domain
        .evaluate_base_polynomial_in_place(working)
        .map_err(|error| failure("evaluate browser source LDE", error))?;
    if working.len() != EVALUATION_DOMAIN_SIZE {
        return Err("browser source LDE has the wrong length".to_owned());
    }
    Ok(retained)
}

fn absorb_first_base_values(
    digest_builders: &mut [ProofOraclePhasePairLeafDigestBuilder],
    evaluations: &[ProofBaseFieldElement],
) -> ProofBackendBakeoffResult<()> {
    if digest_builders.len() != evaluations.len() {
        return Err("browser first-value digest geometry changed".to_owned());
    }
    for (digest_builder, value) in digest_builders.iter_mut().zip(evaluations.iter().copied()) {
        digest_builder
            .absorb_first_value(ProofTreeValue::Base(value))
            .map_err(|error| failure("absorb browser base first value", error))?;
    }
    Ok(())
}

fn begin_opposite_base_values(
    digest_builders: &mut [ProofOraclePhasePairLeafDigestBuilder],
) -> ProofBackendBakeoffResult<()> {
    for digest_builder in digest_builders {
        digest_builder
            .begin_opposite_values()
            .map_err(|error| failure("begin browser base opposite values", error))?;
    }
    Ok(())
}

fn absorb_opposite_base_values(
    digest_builders: &mut [ProofOraclePhasePairLeafDigestBuilder],
    evaluations: &[ProofBaseFieldElement],
) -> ProofBackendBakeoffResult<()> {
    if digest_builders.len() != evaluations.len() {
        return Err("browser opposite-value digest geometry changed".to_owned());
    }
    for (digest_builder, value) in digest_builders.iter_mut().zip(evaluations.iter().copied()) {
        digest_builder
            .absorb_opposite_value(ProofTreeValue::Base(value))
            .map_err(|error| failure("absorb browser base opposite value", error))?;
    }
    Ok(())
}

type BrowserBaseReplayRoot = ([u8; 64], Vec<(u32, u64)>, Vec<[u8; 64]>);

fn finish_base_replay_root(
    context: &super::super::ProofMerkleTreeContext,
    digest_builders: Vec<ProofOraclePhasePairLeafDigestBuilder>,
    opened_leaf_indexes: &[u64],
    expected_root: Option<[u8; 64]>,
) -> ProofBackendBakeoffResult<BrowserBaseReplayRoot> {
    let mut replay = CommonProofMerklePathReplay::new(context, opened_leaf_indexes)
        .map_err(|error| failure("initialize browser base Merkle replay", error))?;
    for (leaf_index, digest_builder) in digest_builders.into_iter().enumerate() {
        replay
            .absorb_leaf_digest(
                u64::try_from(leaf_index)
                    .map_err(|_| "browser base leaf index does not fit u64".to_owned())?,
                digest_builder
                    .finish()
                    .map_err(|error| failure("finish browser base leaf digest", error))?,
            )
            .map_err(|error| failure("absorb browser base leaf digest", error))?;
    }
    replay
        .finish(expected_root)
        .map_err(|error| failure("finish browser base Merkle replay", error))
}

fn finish_public_base_opening(
    entry: &ProofTreeCatalogEntry,
    sorted_query_representatives: &[u64],
    expected_root: [u8; 64],
    state: OpeningReplayState,
) -> ProofBackendBakeoffResult<super::super::prover::PrefetchedCommonProofOpeningArtifact> {
    let context = entry
        .common_context()
        .ok_or_else(|| "browser base opening has no common context".to_owned())?;
    let leaf_count = context
        .leaf_count()
        .map_err(|error| failure("derive browser base leaf count", error))?;
    let (root, frontier_coordinates, frontier_digests) = finish_base_replay_root(
        context,
        state.digest_builders,
        sorted_query_representatives,
        Some(expected_root),
    )?;
    if root != expected_root {
        return Err("browser base opening changed its root".to_owned());
    }
    let mut opened_leaf_bytes = Vec::with_capacity(sorted_query_representatives.len());
    for ((leaf_index, first_values), opposite_values) in sorted_query_representatives
        .iter()
        .copied()
        .zip(state.first_values)
        .zip(state.opposite_values)
    {
        let leaf = super::super::ProofOraclePhasePairLeaf::new(
            context,
            leaf_index,
            None,
            first_values,
            opposite_values,
        )
        .map_err(|error| failure("construct browser base opening leaf", error))?;
        opened_leaf_bytes
            .push(Zeroizing::new(leaf.canonical_bytes().map_err(|error| {
                failure("encode browser base opening leaf", error)
            })?));
    }
    let canonical_leaf_byte_length = super::super::body::canonical_leaf_byte_length(entry)
        .map_err(|error| failure("derive browser base leaf length", error))?;
    super::super::prover::PrefetchedCommonProofOpeningArtifact::from_recomputed_common_tree(
        entry.tree_catalog_index(),
        leaf_count,
        canonical_leaf_byte_length,
        sorted_query_representatives.to_vec(),
        opened_leaf_bytes,
        frontier_coordinates,
        frontier_digests,
    )
    .map_err(|error| failure("construct browser base opening artifact", error))
}

fn artifact_transaction_ranges(
    artifact_byte_length: usize,
    opened_leaf_element_ranges: &[(usize, usize)],
) -> ProofBackendBakeoffResult<(Vec<(usize, usize)>, ArtifactRangeCounts)> {
    if artifact_byte_length == 0
        || opened_leaf_element_ranges.is_empty()
        || !opened_leaf_element_ranges
            .windows(2)
            .all(|pair| pair[0].1 == pair[1].0)
        || opened_leaf_element_ranges[0].0 == 0
        || opened_leaf_element_ranges
            .last()
            .is_none_or(|range| range.1 >= artifact_byte_length)
    {
        return Err("browser artifact semantic range plan is invalid".to_owned());
    }
    let maximum_chunk = usize::try_from(EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH)
        .map_err(|_| "external-memory chunk length does not fit usize".to_owned())?;
    let mut ranges = Vec::new();
    let mut counts = ArtifactRangeCounts::default();
    append_chunked_ranges(
        &mut ranges,
        0,
        opened_leaf_element_ranges[0].0,
        maximum_chunk,
        &mut counts.preleaf,
    )?;
    for &(start, end) in opened_leaf_element_ranges {
        append_chunked_ranges(
            &mut ranges,
            start,
            end,
            maximum_chunk,
            &mut counts.opened_leaf,
        )?;
    }
    append_chunked_ranges(
        &mut ranges,
        opened_leaf_element_ranges
            .last()
            .ok_or_else(|| "browser opened-leaf range is missing".to_owned())?
            .1,
        artifact_byte_length,
        maximum_chunk,
        &mut counts.postleaf,
    )?;
    if !ranges.windows(2).all(|pair| pair[0].1 == pair[1].0)
        || ranges.first().map(|range| range.0) != Some(0)
        || ranges.last().map(|range| range.1) != Some(artifact_byte_length)
    {
        return Err("browser artifact chunk plan is not contiguous".to_owned());
    }
    Ok((ranges, counts))
}

fn append_chunked_ranges(
    ranges: &mut Vec<(usize, usize)>,
    start: usize,
    end: usize,
    maximum_chunk: usize,
    count: &mut u64,
) -> ProofBackendBakeoffResult<()> {
    if start >= end || maximum_chunk == 0 {
        return Err("browser artifact range is empty".to_owned());
    }
    let mut offset = start;
    while offset < end {
        let next = offset.saturating_add(maximum_chunk).min(end);
        ranges.push((offset, next));
        *count = count
            .checked_add(1)
            .ok_or_else(|| "browser artifact range count overflowed".to_owned())?;
        offset = next;
    }
    Ok(())
}

// The two functions below are the arithmetic-only portion of the native width
// path. They receive the already replayed public columns and return the same
// compact proof and semantic opened-leaf ranges without owning storage.
fn prepare_public_width_proof(
    input_identity_shake256_hex: &str,
    base_root: [u8; 64],
    column_coefficients: ProofBaseFieldColumns,
    root_catalog: &CompleteProofTreeCatalog,
) -> ProofBackendBakeoffResult<PreparedPublicWidthProof> {
    let evaluation_domain =
        ProofEvaluationDomain::new(EVALUATION_DOMAIN_SIZE, EVALUATION_COSET_OFFSET)
            .map_err(|error| failure("construct browser evaluation coset", error))?;
    let (profile, canonical_statement) = public_width_proof_profile(
        input_identity_shake256_hex,
        BROWSER_EVIDENCE_SOURCE_COLUMN_COUNT,
        base_root,
    )?;
    if profile.layout.catalog().entries()[0]
        .common_context()
        .ok_or_else(|| "browser proof profile lost its base context".to_owned())?
        .context_hash()
        .map_err(|error| failure("hash browser profile base context", error))?
        != root_catalog.entries()[0]
            .common_context()
            .ok_or_else(|| "browser root catalog lost its base context".to_owned())?
            .context_hash()
            .map_err(|error| failure("hash browser root context", error))?
    {
        return Err("browser root catalog diverges from its proof profile".to_owned());
    }
    let mut transcript = CommonProofTranscript::new(
        PROTOCOL_VERSION,
        profile.suite_identifier,
        profile.application_statement_schema_identifier,
        &profile.canonical_header,
        profile.schedule.clone(),
    )
    .map_err(|error| failure("initialize browser proof transcript", error))?;
    transcript
        .absorb_base_root(0, base_root)
        .map_err(|error| failure("absorb browser base root", error))?;
    let composition_challenges = (0_u32..2)
        .map(|constraint_ordinal| {
            transcript
                .sample_composition_challenge(constraint_ordinal)
                .map_err(|error| failure("sample browser composition challenge", error))
        })
        .collect::<ProofBackendBakeoffResult<Vec<_>>>()?;
    let quotient_evaluations = vec![ProofChallengeExtensionElement::ZERO; EVALUATION_DOMAIN_SIZE];
    let quotient_coefficients = vec![ProofChallengeExtensionElement::ZERO];
    let quotient_root = recompute_extension_tree_root(
        &profile.layout.catalog().entries()[1],
        &quotient_evaluations,
    )?;
    transcript
        .absorb_quotient_root(0, quotient_root)
        .map_err(|error| failure("absorb browser quotient root", error))?;
    let deep_point = transcript
        .sample_deep_point(0, |candidate| {
            deep_point_is_forbidden(candidate, evaluation_domain)
        })
        .map_err(|error| failure("sample browser DEEP point", error))?;
    let mut source_deep_evaluations = column_coefficients
        .iter()
        .map(|coefficients| evaluate_base_coefficients_at(coefficients, deep_point))
        .collect::<Vec<_>>();
    source_deep_evaluations.push(ProofChallengeExtensionElement::ZERO);
    let mut deep_evaluations = Vec::with_capacity(BATCHED_FUNCTION_COUNT);
    deep_evaluations.extend_from_slice(&source_deep_evaluations);
    deep_evaluations.extend_from_slice(&source_deep_evaluations);
    verify_deep_quotient_identity(deep_point, &deep_evaluations, &composition_challenges)?;
    transcript
        .absorb_deep_evaluations(&deep_evaluations)
        .map_err(|error| failure("absorb browser DEEP evaluations", error))?;
    let opening_batch_challenges = (0_u32
        ..u32::try_from(BATCHED_FUNCTION_COUNT)
            .map_err(|_| "browser batch count does not fit u32".to_owned())?)
        .map(|claim_ordinal| {
            transcript
                .sample_opening_batch_challenge(claim_ordinal)
                .map_err(|error| failure("sample browser opening challenge", error))
        })
        .collect::<ProofBackendBakeoffResult<Vec<_>>>()?;
    let mut tree_roots = vec![base_root, quotient_root];
    let mut current_fri_evaluations = public_width_initial_fri_evaluations(
        &column_coefficients,
        &quotient_coefficients,
        evaluation_domain,
        deep_point,
        &deep_evaluations,
        &opening_batch_challenges,
    )?;
    let mut current_fri_domain = evaluation_domain;
    for fold_ordinal in 0..FRI_FOLD_COUNT {
        let fold_ordinal_u16 = u16::try_from(fold_ordinal)
            .map_err(|_| "browser FRI fold ordinal does not fit u16".to_owned())?;
        let fold_challenge = transcript
            .sample_fri_fold_challenge(fold_ordinal_u16)
            .map_err(|error| failure("sample browser FRI challenge", error))?;
        fold_extension_evaluations_in_place(
            &mut current_fri_evaluations,
            current_fri_domain,
            fold_challenge,
        )
        .map_err(|error| failure("fold browser FRI layer", error))?;
        current_fri_domain = current_fri_domain
            .folded()
            .map_err(|error| failure("derive browser folded domain", error))?;
        if fold_ordinal + 1 < FRI_FOLD_COUNT {
            let root = recompute_extension_tree_root(
                &profile.layout.catalog().entries()[fold_ordinal + 2],
                &current_fri_evaluations,
            )?;
            transcript
                .absorb_fri_layer_root(fold_ordinal_u16, root)
                .map_err(|error| failure("absorb browser FRI root", error))?;
            tree_roots.push(root);
        }
    }
    if tree_roots.len() != TREE_COUNT {
        return Err("browser proof root count diverged from its catalog".to_owned());
    }
    let mut terminal_coefficients = current_fri_evaluations;
    current_fri_domain
        .interpolate_extension_polynomial_in_place(&mut terminal_coefficients)
        .map_err(|error| failure("interpolate browser terminal polynomial", error))?;
    if terminal_coefficients.len() > TERMINAL_COEFFICIENT_COUNT {
        return Err("browser terminal polynomial exceeded degree 255".to_owned());
    }
    terminal_coefficients.resize(
        TERMINAL_COEFFICIENT_COUNT,
        ProofChallengeExtensionElement::ZERO,
    );
    transcript
        .absorb_fri_terminal_coefficients(&terminal_coefficients)
        .map_err(|error| failure("absorb browser terminal coefficients", error))?;
    let mut sampled_query_representatives = transcript
        .sample_query_representatives()
        .map_err(|error| failure("sample browser query representatives", error))?;
    let sorted_query_representatives = transcript
        .sorted_query_representatives()
        .map_err(|error| failure("sort browser query representatives", error))?;
    sampled_query_representatives.sort_unstable();
    if sampled_query_representatives != sorted_query_representatives {
        return Err("browser query representatives are not canonical".to_owned());
    }
    Ok(PreparedPublicWidthProof {
        profile,
        canonical_statement,
        transcript,
        composition_challenges,
        quotient_evaluations,
        quotient_coefficients,
        deep_point,
        deep_evaluations,
        opening_batch_challenges,
        tree_roots,
        terminal_coefficients,
        sorted_query_representatives,
        column_coefficients,
        evaluation_domain,
    })
}

fn finish_public_width_proof(
    mut prepared: PreparedPublicWidthProof,
    base_opening: super::super::prover::PrefetchedCommonProofOpeningArtifact,
) -> ProofBackendBakeoffResult<GeneratedPublicWidthArtifact> {
    let mut opening_artifacts = Vec::with_capacity(TREE_COUNT);
    opening_artifacts.push(base_opening);
    opening_artifacts.push(recompute_extension_tree_opening(
        &prepared.profile.layout.catalog().entries()[1],
        &prepared.quotient_evaluations,
        &prepared.sorted_query_representatives,
        prepared.tree_roots[1],
    )?);
    let mut replayed_fri_evaluations = public_width_initial_fri_evaluations(
        &prepared.column_coefficients,
        &prepared.quotient_coefficients,
        prepared.evaluation_domain,
        prepared.deep_point,
        &prepared.deep_evaluations,
        &prepared.opening_batch_challenges,
    )?;
    let mut replayed_fri_domain = prepared.evaluation_domain;
    let mut replay_transcript = CommonProofTranscript::new(
        PROTOCOL_VERSION,
        prepared.profile.suite_identifier,
        prepared.profile.application_statement_schema_identifier,
        &prepared.profile.canonical_header,
        prepared.profile.schedule.clone(),
    )
    .map_err(|error| failure("initialize browser opening replay transcript", error))?;
    replay_transcript
        .absorb_base_root(0, prepared.tree_roots[0])
        .map_err(|error| failure("replay browser base root", error))?;
    for constraint_ordinal in 0_u32..2 {
        let replayed = replay_transcript
            .sample_composition_challenge(constraint_ordinal)
            .map_err(|error| failure("replay browser composition challenge", error))?;
        if replayed
            != prepared.composition_challenges[usize::try_from(constraint_ordinal)
                .map_err(|_| "browser composition ordinal does not fit usize".to_owned())?]
        {
            return Err("browser composition challenge replay diverged".to_owned());
        }
    }
    replay_transcript
        .absorb_quotient_root(0, prepared.tree_roots[1])
        .map_err(|error| failure("replay browser quotient root", error))?;
    let replayed_deep_point = replay_transcript
        .sample_deep_point(0, |candidate| {
            deep_point_is_forbidden(candidate, prepared.evaluation_domain)
        })
        .map_err(|error| failure("replay browser DEEP point", error))?;
    if replayed_deep_point != prepared.deep_point {
        return Err("browser DEEP point replay diverged".to_owned());
    }
    replay_transcript
        .absorb_deep_evaluations(&prepared.deep_evaluations)
        .map_err(|error| failure("replay browser DEEP evaluations", error))?;
    for (claim_ordinal, expected) in prepared
        .opening_batch_challenges
        .iter()
        .copied()
        .enumerate()
    {
        let replayed = replay_transcript
            .sample_opening_batch_challenge(
                u32::try_from(claim_ordinal)
                    .map_err(|_| "browser opening ordinal does not fit u32".to_owned())?,
            )
            .map_err(|error| failure("replay browser opening challenge", error))?;
        if replayed != expected {
            return Err("browser opening challenge replay diverged".to_owned());
        }
    }
    for fold_ordinal in 0..FRI_FOLD_COUNT {
        let fold_ordinal_u16 = u16::try_from(fold_ordinal)
            .map_err(|_| "browser fold ordinal does not fit u16".to_owned())?;
        let fold_challenge = replay_transcript
            .sample_fri_fold_challenge(fold_ordinal_u16)
            .map_err(|error| failure("replay browser FRI challenge", error))?;
        fold_extension_evaluations_in_place(
            &mut replayed_fri_evaluations,
            replayed_fri_domain,
            fold_challenge,
        )
        .map_err(|error| failure("replay browser FRI fold", error))?;
        replayed_fri_domain = replayed_fri_domain
            .folded()
            .map_err(|error| failure("derive replayed browser FRI domain", error))?;
        if fold_ordinal + 1 < FRI_FOLD_COUNT {
            replay_transcript
                .absorb_fri_layer_root(fold_ordinal_u16, prepared.tree_roots[fold_ordinal + 2])
                .map_err(|error| failure("replay browser FRI root", error))?;
            opening_artifacts.push(recompute_extension_tree_opening(
                &prepared.profile.layout.catalog().entries()[fold_ordinal + 2],
                &replayed_fri_evaluations,
                &prepared.sorted_query_representatives,
                prepared.tree_roots[fold_ordinal + 2],
            )?);
        }
    }
    if opening_artifacts.len() != TREE_COUNT {
        return Err("browser opening artifact count changed".to_owned());
    }
    let canonical_leaf_byte_length =
        u64::try_from(opening_artifacts[0].canonical_leaf_byte_length())
            .map_err(|_| "browser base leaf length does not fit u64".to_owned())?;
    let geometries = opening_geometries(prepared.profile.layout.catalog())?;
    let query_section_byte_length = common_proof_query_section_byte_length(
        prepared.profile.layout.catalog(),
        &geometries,
        &prepared.sorted_query_representatives,
    )
    .map_err(|error| failure("derive browser query-section length", error))?;
    let mut sink = BoundedCommonProofByteSink::new(MAXIMUM_PROOF_BYTE_LENGTH)
        .map_err(|error| failure("initialize browser proof sink", error))?;
    write_common_proof_prefix(
        &mut sink,
        &prepared.profile.canonical_header,
        prepared.profile.layout.catalog(),
        &prepared.tree_roots,
        &prepared.deep_evaluations,
        &prepared.terminal_coefficients,
        &prepared.profile.schedule,
    )
    .map_err(|error| failure("encode browser proof prefix", error))?;
    let mut query_opening_absorber = prepared
        .transcript
        .begin_query_openings(query_section_byte_length)
        .map_err(|error| failure("begin browser query-opening round", error))?;
    let query_header =
        canonical_common_proof_query_section_header(prepared.profile.layout.catalog())
            .map_err(|error| failure("encode browser query header", error))?;
    sink.write_bytes(&query_header)
        .map_err(|error| failure("write browser query header", error))?;
    query_opening_absorber
        .absorb(&query_header)
        .map_err(|error| failure("absorb browser query header", error))?;
    let mut base_opened_leaf_local_ranges = None;
    for catalog_index in 0..TREE_COUNT {
        let exact_fragment_byte_length = proof_query_tree_byte_length(
            &prepared.profile.layout,
            catalog_index,
            &prepared.sorted_query_representatives,
        )
        .map_err(|error| failure("derive browser query fragment length", error))?;
        let (fragment, opened_leaf_local_ranges) =
            encode_common_proof_query_tree_fragment_with_layout(
                prepared.profile.layout.catalog(),
                catalog_index,
                geometries[catalog_index],
                &prepared.sorted_query_representatives,
                &opening_artifacts[catalog_index],
                exact_fragment_byte_length,
            )
            .map_err(|error| failure("encode browser query fragment", error))?
            .into_parts();
        if catalog_index == 0 {
            base_opened_leaf_local_ranges = Some(opened_leaf_local_ranges);
        }
        sink.write_bytes(&fragment)
            .map_err(|error| failure("write browser query fragment", error))?;
        query_opening_absorber
            .absorb(&fragment)
            .map_err(|error| failure("absorb browser query fragment", error))?;
    }
    drop(opening_artifacts);
    prepared
        .transcript
        .finish_query_openings(query_opening_absorber)
        .map_err(|error| failure("finish browser query-opening round", error))?;
    prepared
        .transcript
        .finish()
        .map_err(|error| failure("finish browser proof transcript", error))?;
    let canonical_full_proof = sink.finish();
    let canonical_artifact = Zeroizing::new(compact_canonical_proof(
        &prepared.profile,
        &canonical_full_proof,
    )?);
    let opened_leaf_element_ranges = base_opened_leaf_element_ranges(
        &prepared.profile,
        query_header.len(),
        base_opened_leaf_local_ranges
            .as_deref()
            .ok_or_else(|| "browser base query layout is missing".to_owned())?,
    )?;
    let recomputed_canonical_artifact_byte_length = prepared
        .profile
        .canonical_header
        .len()
        .checked_add(
            super::super::proof_body_prefix_byte_length(&prepared.profile.layout)
                .map_err(|error| failure("recompute browser proof prefix length", error))?,
        )
        .and_then(|length| length.checked_add(query_section_byte_length))
        .and_then(|length| length.checked_sub(MERKLE_DIGEST_BYTE_LENGTH))
        .and_then(|length| u64::try_from(length).ok())
        .ok_or_else(|| "recomputed browser artifact length overflowed".to_owned())?;
    if recomputed_canonical_artifact_byte_length != canonical_artifact.len() as u64 {
        return Err("browser canonical artifact length diverges from its layout".to_owned());
    }
    Ok(GeneratedPublicWidthArtifact {
        canonical_artifact,
        canonical_statement: prepared.canonical_statement,
        sorted_query_representatives: prepared.sorted_query_representatives,
        opened_leaf_element_ranges,
        canonical_leaf_byte_length,
        recomputed_canonical_artifact_byte_length,
    })
}

#[derive(Default)]
struct BrowserEvidenceRegistry {
    next_handle: u32,
    operations: BTreeMap<u32, BrowserProofStorageWidthOperation>,
}

#[cfg(all(
    test,
    not(target_arch = "wasm32"),
    feature = "proof-storage-width-evidence"
))]
pub(super) fn browser_operation_registry_byte_length_ceiling() -> ProofBackendBakeoffResult<u64> {
    let operation_byte_length =
        u64::try_from(core::mem::size_of::<BrowserProofStorageWidthOperation>())
            .map_err(|_| "browser operation container length does not fit u64".to_owned())?;
    let entry_byte_length = operation_byte_length
        .checked_add(
            u64::try_from(core::mem::size_of::<u32>())
                .map_err(|_| "browser operation handle length does not fit u64".to_owned())?,
        )
        .ok_or_else(|| "browser operation registry entry length overflowed".to_owned())?;
    let registry_container_byte_length = u64::try_from(core::mem::size_of::<
        RefCell<BrowserEvidenceRegistry>,
    >())
    .map_err(|_| "browser operation registry container length does not fit u64".to_owned())?;
    entry_byte_length
        .checked_mul(WIDTH_CONSERVATIVE_BTREE_ENTRY_STORAGE_MULTIPLIER)
        .and_then(|length| length.checked_add(registry_container_byte_length))
        .and_then(|length| {
            length.checked_add(WIDTH_CONSERVATIVE_HEAP_ALLOCATION_OVERHEAD_BYTE_LENGTH)
        })
        .ok_or_else(|| "browser operation registry memory ceiling overflowed".to_owned())
}

impl BrowserEvidenceRegistry {
    fn insert_with<ConstructOperation>(
        &mut self,
        construct_operation: ConstructOperation,
    ) -> ProofBackendBakeoffResult<u32>
    where
        ConstructOperation:
            FnOnce() -> ProofBackendBakeoffResult<BrowserProofStorageWidthOperation>,
    {
        if !self.operations.is_empty() {
            return Err("a browser width evidence operation is already active".to_owned());
        }
        let operation = construct_operation()?;
        self.next_handle = self.next_handle.checked_add(1).unwrap_or(1).max(1);
        let handle = self.next_handle;
        if self.operations.insert(handle, operation).is_some() {
            return Err("browser width evidence handle collision".to_owned());
        }
        Ok(handle)
    }
}

thread_local! {
    static BROWSER_EVIDENCE_REGISTRY: RefCell<BrowserEvidenceRegistry> =
        RefCell::new(BrowserEvidenceRegistry::default());
}

unsafe fn write_status(status_pointer: *mut u32, status: u32) {
    if !status_pointer.is_null() {
        unsafe { status_pointer.write_unaligned(status) };
    }
}

unsafe fn input_bytes<'input>(pointer: *const u8, byte_length: usize) -> Option<&'input [u8]> {
    if byte_length == 0 {
        return Some(&[]);
    }
    if pointer.is_null() {
        return None;
    }
    Some(unsafe { core::slice::from_raw_parts(pointer, byte_length) })
}

unsafe fn copy_exact(output_pointer: *mut u8, output_byte_length: usize, bytes: &[u8]) -> bool {
    if output_pointer.is_null() || output_byte_length != bytes.len() {
        return false;
    }
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), output_pointer, bytes.len()) };
    true
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_proof_storage_width_browser_begin(
    manifest_identity_pointer: *const u8,
    manifest_identity_byte_length: usize,
    status_pointer: *mut u32,
) -> u32 {
    let Some(manifest_identity_bytes) =
        (unsafe { input_bytes(manifest_identity_pointer, manifest_identity_byte_length) })
    else {
        unsafe { write_status(status_pointer, STATUS_INVALID_ARGUMENT) };
        return 0;
    };
    let Ok(manifest_identity) = manifest_identity_bytes.try_into() else {
        unsafe { write_status(status_pointer, STATUS_INVALID_ARGUMENT) };
        return 0;
    };
    let result = BROWSER_EVIDENCE_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .insert_with(|| BrowserProofStorageWidthOperation::new(manifest_identity))
    });
    match result {
        Ok(handle) => {
            unsafe { write_status(status_pointer, 0) };
            handle
        }
        Err(_) => {
            unsafe { write_status(status_pointer, STATUS_OPERATION_FAILED) };
            0
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_proof_storage_width_browser_poll(
    operation_handle: u32,
    status_pointer: *mut u32,
) -> u32 {
    let result = BROWSER_EVIDENCE_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .operations
            .get_mut(&operation_handle)
            .ok_or_else(|| "unknown browser evidence handle".to_owned())?
            .poll()
    });
    match result {
        Ok(poll) => {
            unsafe { write_status(status_pointer, 0) };
            poll
        }
        Err(_) => {
            unsafe { write_status(status_pointer, STATUS_OPERATION_FAILED) };
            0
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_proof_storage_width_browser_pending_storage_request_byte_length(
    operation_handle: u32,
    status_pointer: *mut u32,
) -> usize {
    let result = BROWSER_EVIDENCE_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .operations
            .get_mut(&operation_handle)
            .ok_or(STATUS_UNKNOWN_HANDLE)?
            .ensure_pending_request_encoding()
            .map_err(|_| STATUS_OPERATION_FAILED)?
            .ok_or(STATUS_WRONG_PHASE)
    });
    match result {
        Ok(byte_length) => {
            unsafe { write_status(status_pointer, 0) };
            byte_length
        }
        Err(status) => {
            unsafe { write_status(status_pointer, status) };
            0
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_proof_storage_width_browser_copy_pending_storage_request(
    operation_handle: u32,
    output_pointer: *mut u8,
    output_byte_length: usize,
    status_pointer: *mut u32,
) -> usize {
    let result = BROWSER_EVIDENCE_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let request = registry
            .operations
            .get(&operation_handle)
            .ok_or(STATUS_UNKNOWN_HANDLE)?
            .cached_pending_request()
            .map_err(|_| STATUS_OPERATION_FAILED)?
            .ok_or(STATUS_WRONG_PHASE)?;
        if unsafe { copy_exact(output_pointer, output_byte_length, request) } {
            Ok(request.len())
        } else {
            Err(STATUS_INVALID_ARGUMENT)
        }
    });
    match result {
        Ok(byte_length) => {
            unsafe { write_status(status_pointer, 0) };
            byte_length
        }
        Err(status) => {
            unsafe { write_status(status_pointer, status) };
            0
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_proof_storage_width_browser_supply_storage_response(
    operation_handle: u32,
    input_pointer: *const u8,
    input_byte_length: usize,
    status_pointer: *mut u32,
) -> usize {
    let Some(encoded_response) = (unsafe { input_bytes(input_pointer, input_byte_length) }) else {
        unsafe { write_status(status_pointer, STATUS_INVALID_ARGUMENT) };
        return 0;
    };
    let result = BROWSER_EVIDENCE_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .operations
            .get_mut(&operation_handle)
            .ok_or_else(|| "unknown browser evidence handle".to_owned())?
            .supply_storage_response(encoded_response)
    });
    match result {
        Ok(()) => {
            unsafe { write_status(status_pointer, 0) };
            input_byte_length
        }
        Err(_) => {
            unsafe { write_status(status_pointer, STATUS_OPERATION_FAILED) };
            0
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_proof_storage_width_browser_result_byte_length(
    operation_handle: u32,
    status_pointer: *mut u32,
) -> usize {
    let result = BROWSER_EVIDENCE_REGISTRY.with(|registry| {
        registry
            .borrow()
            .operations
            .get(&operation_handle)
            .ok_or(STATUS_UNKNOWN_HANDLE)
            .and_then(|operation| {
                operation
                    .result
                    .as_ref()
                    .map(|result| result.len())
                    .ok_or(STATUS_WRONG_PHASE)
            })
    });
    match result {
        Ok(byte_length) => {
            unsafe { write_status(status_pointer, 0) };
            byte_length
        }
        Err(status) => {
            unsafe { write_status(status_pointer, status) };
            0
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_proof_storage_width_browser_copy_result(
    operation_handle: u32,
    output_pointer: *mut u8,
    output_byte_length: usize,
    status_pointer: *mut u32,
) -> usize {
    let result = BROWSER_EVIDENCE_REGISTRY.with(|registry| {
        registry
            .borrow()
            .operations
            .get(&operation_handle)
            .ok_or(STATUS_UNKNOWN_HANDLE)
            .and_then(|operation| operation.result.as_ref().ok_or(STATUS_WRONG_PHASE))
            .copied()
    });
    match result {
        Ok(result) if unsafe { copy_exact(output_pointer, output_byte_length, &result) } => {
            unsafe { write_status(status_pointer, 0) };
            result.len()
        }
        Ok(_) => {
            unsafe { write_status(status_pointer, STATUS_INVALID_ARGUMENT) };
            0
        }
        Err(status) => {
            unsafe { write_status(status_pointer, status) };
            0
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_proof_storage_width_browser_cancel(operation_handle: u32) {
    BROWSER_EVIDENCE_REGISTRY.with(|registry| {
        if let Some(operation) = registry.borrow_mut().operations.get_mut(&operation_handle) {
            operation.cancel();
        }
    });
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_proof_storage_width_browser_release(operation_handle: u32) {
    BROWSER_EVIDENCE_REGISTRY.with(|registry| {
        registry.borrow_mut().operations.remove(&operation_handle);
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::external_memory::MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_APPEND_REQUEST_BYTE_LENGTH;

    fn supply_empty_response(operation: &mut BrowserProofStorageWidthOperation) {
        let response = operation
            .storage
            .pending_request()
            .expect("the operation must have a pending storage request")
            .encode_test_worker_response(&[])
            .expect("the empty response must encode");
        operation
            .supply_storage_response(&response)
            .expect("the empty response must enter replay");
    }

    #[test]
    fn pending_append_request_is_encoded_once_after_the_caller_chunk_is_released() {
        let mut operation = BrowserProofStorageWidthOperation::new([0x5a; 64])
            .expect("the fixed browser operation must initialize");
        let append_payload_pointer = operation.append_payload_scratch.as_ptr();
        let request_encoding_pointer = operation.encoded_pending_request.as_ptr();
        assert_eq!(
            operation.append_payload_scratch.capacity(),
            EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH as usize
        );
        assert_eq!(
            operation.encoded_pending_request.capacity(),
            BROWSER_MAXIMUM_ENCODED_REQUEST_BYTE_LENGTH
        );

        assert_eq!(
            operation.poll().expect("source create must yield"),
            POLL_STORAGE_REQUEST_READY
        );
        assert!(operation.cached_pending_request().is_err());
        let premature_response = operation
            .storage
            .pending_request()
            .expect("source create request must be pending")
            .encode_test_worker_response(&[])
            .expect("the source create response must encode");
        assert!(
            operation
                .supply_storage_response(&premature_response)
                .is_err()
        );
        operation
            .ensure_pending_request_encoding()
            .expect("source create request must encode")
            .expect("source create request must be present");
        supply_empty_response(&mut operation);
        assert!(!operation.encoded_pending_request_ready);
        assert!(operation.encoded_pending_request.is_empty());
        assert_eq!(
            operation.encoded_pending_request.as_ptr(),
            request_encoding_pointer
        );
        assert_eq!(
            operation.poll().expect("source create replay must commit"),
            POLL_PROGRESS
        );

        assert_eq!(
            operation.poll().expect("maximum source append must yield"),
            POLL_STORAGE_REQUEST_READY
        );
        assert_eq!(
            operation.append_payload_scratch.as_ptr(),
            append_payload_pointer
        );
        assert_eq!(
            operation.append_payload_scratch.capacity(),
            EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH as usize
        );
        assert!(!operation.encoded_pending_request_ready);
        assert!(operation.encoded_pending_request.is_empty());
        let request_byte_length = operation
            .ensure_pending_request_encoding()
            .expect("source append request must encode")
            .expect("source append request must be present");
        assert_eq!(
            request_byte_length as u64,
            MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_APPEND_REQUEST_BYTE_LENGTH
        );
        let first_pointer = operation
            .cached_pending_request()
            .expect("cached source append request must be valid")
            .expect("cached source append request must be present")
            .as_ptr();
        assert_eq!(
            operation
                .ensure_pending_request_encoding()
                .expect("repeated sizing must reuse the request")
                .expect("repeated sizing must retain the request"),
            request_byte_length
        );
        assert_eq!(
            operation
                .cached_pending_request()
                .expect("reused source append request must be valid")
                .expect("reused source append request must be present")
                .as_ptr(),
            first_pointer
        );

        supply_empty_response(&mut operation);
        assert!(!operation.encoded_pending_request_ready);
        assert!(operation.encoded_pending_request.is_empty());
        assert_eq!(
            operation.encoded_pending_request.as_ptr(),
            request_encoding_pointer
        );
        operation.cancel();
        assert!(!operation.encoded_pending_request_ready);
        assert!(operation.encoded_pending_request.is_empty());
    }

    #[test]
    fn fresh_verifier_refuses_cross_pass_identity_equivocation_and_wrong_base_root() {
        let frozen_input_identity_shake256_hex = "31".repeat(64);
        let source_byte_length = TRACE_DOMAIN_SIZE
            .checked_mul(8)
            .expect("one source column byte length must fit usize");
        let expected_source_bytes = vec![0x31; source_byte_length];
        let mut equivocated_source_bytes = expected_source_bytes.clone();
        equivocated_source_bytes[source_byte_length / 2] ^= 0x80;

        let mut expected_replay =
            BrowserSourceIdentityReplay::new(&frozen_input_identity_shake256_hex, 1)
                .expect("the expected replay identity hasher must initialize");
        expected_replay.absorb_exact_source_bytes(&expected_source_bytes);
        let expected_identity = expected_replay.finalize();
        let expected_base_root = [0x72; 64];
        let mut different_base_root = expected_base_root;
        different_base_root[11] ^= 1;

        let mut equivocated_custody =
            FreshVerifierCustodyBinding::new(expected_identity, expected_base_root);
        let mut first_pass_replay =
            BrowserSourceIdentityReplay::new(&frozen_input_identity_shake256_hex, 1)
                .expect("the first pass identity hasher must initialize");
        first_pass_replay.absorb_exact_source_bytes(&expected_source_bytes);
        first_pass_replay
            .finish_identity_pass(&mut equivocated_custody, FreshVerifierIdentityPass::First)
            .expect("the first pass must bind the expected source identity");
        let mut opposite_pass_replay =
            BrowserSourceIdentityReplay::new(&frozen_input_identity_shake256_hex, 1)
                .expect("the opposite pass identity hasher must initialize");
        opposite_pass_replay.absorb_exact_source_bytes(&equivocated_source_bytes);
        assert!(
            opposite_pass_replay
                .finish_identity_pass(
                    &mut equivocated_custody,
                    FreshVerifierIdentityPass::Opposite,
                )
                .is_err_and(|error| error.contains("opposite pass"))
        );
        assert!(
            equivocated_custody
                .verify_base_root(expected_base_root)
                .is_err_and(|error| error.contains("both identity passes"))
        );

        let mut wrong_root_custody =
            FreshVerifierCustodyBinding::new(expected_identity, expected_base_root);
        let mut repeated_first_pass =
            BrowserSourceIdentityReplay::new(&frozen_input_identity_shake256_hex, 1)
                .expect("the repeated first pass identity hasher must initialize");
        repeated_first_pass.absorb_exact_source_bytes(&expected_source_bytes);
        repeated_first_pass
            .finish_identity_pass(&mut wrong_root_custody, FreshVerifierIdentityPass::First)
            .expect("the first pass must bind the expected source identity");
        let mut repeated_opposite_pass =
            BrowserSourceIdentityReplay::new(&frozen_input_identity_shake256_hex, 1)
                .expect("the repeated opposite pass identity hasher must initialize");
        repeated_opposite_pass.absorb_exact_source_bytes(&expected_source_bytes);
        repeated_opposite_pass
            .finish_identity_pass(&mut wrong_root_custody, FreshVerifierIdentityPass::Opposite)
            .expect("the opposite pass must bind the same source identity");
        assert!(
            wrong_root_custody
                .verify_base_root(different_base_root)
                .is_err_and(|error| error.contains("base root"))
        );
        wrong_root_custody
            .verify_base_root(expected_base_root)
            .expect("matching custody and root must remain accepted");
    }

    #[test]
    fn occupied_registry_refuses_before_constructing_another_operation() {
        let mut registry = BrowserEvidenceRegistry::default();
        registry
            .insert_with(|| BrowserProofStorageWidthOperation::new([0x41; 64]))
            .expect("the first operation must occupy an empty registry");

        let constructor_called = core::cell::Cell::new(false);
        let result = registry.insert_with(|| {
            constructor_called.set(true);
            BrowserProofStorageWidthOperation::new([0x42; 64])
        });
        assert!(result.is_err_and(|error| error.contains("already active")));
        assert!(!constructor_called.get());
    }
}
