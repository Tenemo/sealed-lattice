use super::*;

#[cfg(not(target_arch = "wasm32"))]
use std::io::{BufWriter, Write};

use crate::bgv::setup_helpers::validate_hash_string;
#[cfg(not(target_arch = "wasm32"))]
use crate::foundation::FOUNDATION_PROFILE;
use crate::hashing::derive_canonical_object_hash;
#[cfg(not(target_arch = "wasm32"))]
use crate::hashing::hash512_hex;

pub(in crate::bgv::setup) fn evaluation_key_share_component_vector_root(
    proof_family: EvaluationKeyShareProofFamily,
    key_switch_domain: &str,
    key_switch_seed_hex: &str,
    level: usize,
    component_vectors_little_endian_hex_by_digit_and_limb: &[String],
) -> CanonicalResult<String> {
    derive_canonical_object_hash(&json!({
        "objectType": "EvaluationKeyShareComponentVectorSet",
        "proofFamily": proof_family.proof_family(),
        "keySwitchDomain": key_switch_domain,
        "keySwitchSeedHex": key_switch_seed_hex,
        "level": level,
        "componentVectorsLittleEndianHexByDigitAndLimb": component_vectors_little_endian_hex_by_digit_and_limb,
    }))
}

fn stored_verified_evaluation_key_share_component_material_chunks(
    accepted_setup_session: &crate::bgv::setup::AcceptedSetupProofBindingSession,
    material_root: &str,
    proof_family: &str,
) -> CanonicalResult<Vec<Vec<u8>>> {
    let store_entry = crate::bgv::setup::accepted_setup_component_material(
        accepted_setup_session.session_handle,
        proof_family,
        material_root,
    )?
    .ok_or_else(|| {
        invalid_evaluation_key_share_material(
            "evaluation-key component material is not owned by the accepted-setup session",
        )
    })?;
    read_verified_evaluation_key_share_component_material_chunks(store_entry)
}

fn read_verified_evaluation_key_share_component_material_chunks(
    store_entry: VerifiedEvaluationKeyShareComponentMaterialChunkStoreEntry,
) -> CanonicalResult<Vec<Vec<u8>>> {
    let VerifiedEvaluationKeyShareComponentMaterialChunkStoreEntry {
        backing,
        total_byte_length,
        ..
    } = store_entry;
    match backing {
        #[cfg(target_arch = "wasm32")]
        VerifiedComponentMaterialBacking::Memory(chunks) => {
            let mut staged_total = 0_u64;
            for chunk in &chunks {
                staged_total = staged_total
                    .checked_add(u64::try_from(chunk.len()).map_err(|_| {
                        invalid_evaluation_key_share_material(
                            "in-memory component material chunk length does not fit u64",
                        )
                    })?)
                    .ok_or_else(|| {
                        invalid_evaluation_key_share_material(
                            "in-memory component material byte length overflowed",
                        )
                    })?;
            }
            if staged_total != total_byte_length {
                return Err(invalid_evaluation_key_share_material(
                    "in-memory component material total byte length does not match the verified handle",
                ));
            }
            Ok(chunks)
        }
        #[cfg(not(target_arch = "wasm32"))]
        VerifiedComponentMaterialBacking::TempFile(path) => {
            let chunk_size = FOUNDATION_PROFILE.stream_chunk_byte_length;
            let chunk_size_u64 = u64::try_from(chunk_size).map_err(|_| {
                invalid_evaluation_key_share_material(
                    "evaluation-key component material chunk size does not fit u64",
                )
            })?;
            let mut remaining_byte_length = total_byte_length;
            let mut file = std::fs::File::open(&path).map_err(|error| {
                invalid_evaluation_key_share_material(format!(
                    "verified evaluation-key component material store entry could not be opened: {error}",
                ))
            })?;
            let mut chunks = Vec::new();
            while remaining_byte_length > 0 {
                let next_chunk_length = usize::try_from(remaining_byte_length.min(chunk_size_u64))
                    .map_err(|_| {
                        invalid_evaluation_key_share_material(
                            "evaluation-key component material chunk length does not fit usize",
                        )
                    })?;
                let mut chunk = vec![0_u8; next_chunk_length.min(chunk_size)];
                file.read_exact(&mut chunk).map_err(|error| {
                    invalid_evaluation_key_share_material(format!(
                        "verified evaluation-key component material store entry could not be read: {error}",
                    ))
                })?;
                remaining_byte_length -= u64::try_from(chunk.len()).map_err(|_| {
                    invalid_evaluation_key_share_material(
                        "evaluation-key component material chunk length does not fit u64",
                    )
                })?;
                chunks.push(chunk);
            }

            Ok(chunks)
        }
    }
}

// Drop the staged backing of an evicted store entry: on native this removes the
// temp file; on the browser wasm runtime the in-memory chunk bytes are freed when
// `backing` drops. Mirrors `discard_component_material_stream_sink`.
fn discard_verified_component_material_backing(
    backing: VerifiedComponentMaterialBacking,
) -> CanonicalResult<()> {
    match backing {
        #[cfg(not(target_arch = "wasm32"))]
        VerifiedComponentMaterialBacking::TempFile(path) => {
            std::fs::remove_file(path).map_err(|_| {
                invalid_evaluation_key_share_material(
                    "verified evaluation-key component material backing could not be removed",
                )
            })?;
        }
        #[cfg(target_arch = "wasm32")]
        VerifiedComponentMaterialBacking::Memory(_) => {}
    }
    Ok(())
}

pub(in crate::bgv::setup) fn discard_session_component_material(
    materials: BTreeMap<String, VerifiedEvaluationKeyShareComponentMaterialChunkStoreEntry>,
) -> CanonicalResult<()> {
    let mut first_cleanup_error = None;
    for material in materials.into_values() {
        if let Err(error) = discard_verified_component_material_backing(material.backing)
            && first_cleanup_error.is_none()
        {
            first_cleanup_error = Some(error);
        }
    }
    first_cleanup_error.map_or(Ok(()), Err)
}

#[derive(Clone, Copy)]
pub(in crate::bgv::setup) struct EvaluationKeyShareDerivedMaterialBinding<'a> {
    pub(in crate::bgv::setup) trustee_identity: &'a str,
    pub(in crate::bgv::setup) trustee_roster_position: u64,
    pub(in crate::bgv::setup) key_switch_domain: &'a str,
    pub(in crate::bgv::setup) key_switch_seed_hex: &'a str,
}

pub(in crate::bgv::setup) struct DecodedEvaluationKeyShareComponentMaterial {
    pub(in crate::bgv::setup) component_b_by_digit: Vec<Vec<Vec<u64>>>,
    pub(in crate::bgv::setup) ring_degree: usize,
    pub(in crate::bgv::setup) component_vector_root: String,
}

pub(in crate::bgv::setup) fn evaluation_key_share_component_material_reference_root(
    proof_family: EvaluationKeyShareProofFamily,
    level: usize,
    component_vector_root: &str,
    derived_binding: EvaluationKeyShareDerivedMaterialBinding<'_>,
) -> CanonicalResult<String> {
    derive_canonical_object_hash(&json!({
        "objectType": "EvaluationKeyShareComponentMaterialReference",
        "proofFamily": proof_family.proof_family(),
        "trusteeIdentity": derived_binding.trustee_identity,
        "trusteeRosterPosition": derived_binding.trustee_roster_position,
        "keySwitchDomain": derived_binding.key_switch_domain,
        "keySwitchSeedHex": derived_binding.key_switch_seed_hex,
        "level": level,
        "keySwitchComponentVectorRoot": component_vector_root,
    }))
}

pub(in crate::bgv::setup) fn component_b_vectors_from_root(
    proof_family: EvaluationKeyShareProofFamily,
    expected_material_root: &str,
    level: usize,
    expected_ring_degree: usize,
    derived_binding: EvaluationKeyShareDerivedMaterialBinding<'_>,
    accepted_setup_session: &crate::bgv::setup::AcceptedSetupProofBindingSession,
) -> CanonicalResult<DecodedEvaluationKeyShareComponentMaterial> {
    validate_hash_string(
        expected_material_root,
        "evaluationKeyShareRecord.keySwitchComponentMaterialRoot",
    )?;
    let chunks = stored_verified_evaluation_key_share_component_material_chunks(
        accepted_setup_session,
        expected_material_root,
        proof_family.proof_family(),
    )?;
    let decoded_material = decode_evaluation_key_share_component_vectors(
        proof_family,
        level,
        derived_binding,
        &chunks,
    )?;
    if decoded_material.ring_degree != expected_ring_degree {
        return Err(invalid_evaluation_key_share_material(
            "evaluation-key component material ring degree does not match the accepted setup",
        ));
    }
    let canonical_material_root = evaluation_key_share_component_material_reference_root(
        proof_family,
        level,
        &decoded_material.component_vector_root,
        derived_binding,
    )?;
    if expected_material_root != canonical_material_root {
        return Err(invalid_evaluation_key_share_material(
            "evaluation-key component material root must match the canonical material reference",
        ));
    }
    Ok(decoded_material)
}

// Canonical decode: fixed record order, in-range residues, and zero trailing
// bytes make the binary encoding injective and non-malleable against the bound
// component-vector root.
struct CanonicalComponentMaterialReader<'a> {
    chunks: &'a [Vec<u8>],
    chunk_index: usize,
    byte_index: usize,
}

impl<'a> CanonicalComponentMaterialReader<'a> {
    fn new(chunks: &'a [Vec<u8>]) -> CanonicalResult<Self> {
        if chunks.is_empty() || chunks.iter().any(Vec::is_empty) {
            return Err(invalid_evaluation_key_share_material(
                "canonical component material must contain nonempty chunks",
            ));
        }
        Ok(Self {
            chunks,
            chunk_index: 0,
            byte_index: 0,
        })
    }

    fn read_fixed<const LENGTH: usize>(&mut self) -> CanonicalResult<[u8; LENGTH]> {
        let mut output = [0_u8; LENGTH];
        let mut written = 0_usize;
        while written < LENGTH {
            let chunk = self.chunks.get(self.chunk_index).ok_or_else(|| {
                invalid_evaluation_key_share_material(
                    "evaluation-key component material ended early",
                )
            })?;
            let available = chunk.len().checked_sub(self.byte_index).ok_or_else(|| {
                invalid_evaluation_key_share_material(
                    "evaluation-key component material cursor overflowed",
                )
            })?;
            if available == 0 {
                self.chunk_index += 1;
                self.byte_index = 0;
                continue;
            }
            let copied = available.min(LENGTH - written);
            output[written..written + copied]
                .copy_from_slice(&chunk[self.byte_index..self.byte_index + copied]);
            self.byte_index += copied;
            written += copied;
        }
        Ok(output)
    }

    fn read_u64(&mut self) -> CanonicalResult<u64> {
        Ok(u64::from_le_bytes(self.read_fixed::<8>()?))
    }

    fn is_exhausted(&self) -> bool {
        let mut chunk_index = self.chunk_index;
        let mut byte_index = self.byte_index;
        while let Some(chunk) = self.chunks.get(chunk_index) {
            if byte_index < chunk.len() {
                return false;
            }
            chunk_index += 1;
            byte_index = 0;
        }
        true
    }
}

fn decode_evaluation_key_share_component_vectors(
    proof_family: EvaluationKeyShareProofFamily,
    level: usize,
    derived_binding: EvaluationKeyShareDerivedMaterialBinding<'_>,
    material_chunks: &[Vec<u8>],
) -> CanonicalResult<DecodedEvaluationKeyShareComponentMaterial> {
    let mut reader = CanonicalComponentMaterialReader::new(material_chunks)?;
    let magic = reader.read_fixed::<8>()?;
    if &magic != EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_MAGIC {
        return Err(invalid_evaluation_key_share_material(
            "evaluation-key component material has the wrong format marker",
        ));
    }
    let digit_count = level.checked_add(1).ok_or_else(|| {
        invalid_evaluation_key_share_material("evaluation-key digit count overflowed")
    })?;
    let limb_count = digit_count;
    if limb_count == 0 || limb_count > DATA_PRIMES.len() {
        return Err(invalid_evaluation_key_share_material(
            "evaluation-key component material shape does not match the proof record",
        ));
    }
    let total_byte_length = material_chunks.iter().try_fold(0_usize, |total, chunk| {
        total.checked_add(chunk.len()).ok_or_else(|| {
            invalid_evaluation_key_share_material(
                "evaluation-key component material byte length overflowed",
            )
        })
    })?;
    let payload_byte_length = total_byte_length.checked_sub(magic.len()).ok_or_else(|| {
        invalid_evaluation_key_share_material(
            "evaluation-key component material ended before its format marker",
        )
    })?;
    let bytes_per_coefficient_position = digit_count
        .checked_mul(limb_count)
        .and_then(|vector_count| vector_count.checked_mul(std::mem::size_of::<u64>()))
        .ok_or_else(|| {
            invalid_evaluation_key_share_material(
                "evaluation-key component material shape overflowed",
            )
        })?;
    if payload_byte_length == 0 || payload_byte_length % bytes_per_coefficient_position != 0 {
        return Err(invalid_evaluation_key_share_material(
            "evaluation-key component material byte length does not encode complete coefficient vectors",
        ));
    }
    let ring_degree = payload_byte_length / bytes_per_coefficient_position;
    validate_hex_string(derived_binding.key_switch_seed_hex, "keySwitchSeedHex")?;
    let mut component_b_by_digit = vec![vec![Vec::<u64>::new(); limb_count]; digit_count];
    let mut component_vectors_little_endian_hex_by_digit_and_limb =
        Vec::with_capacity(digit_count * limb_count);
    for component_b_limbs in &mut component_b_by_digit {
        for (component_b_limb, &rns_prime) in component_b_limbs.iter_mut().zip(DATA_PRIMES.iter()) {
            let mut coefficients = Vec::with_capacity(ring_degree);
            for _ in 0..ring_degree {
                let coefficient = reader.read_u64()?;
                if coefficient >= rns_prime {
                    return Err(invalid_evaluation_key_share_material(
                        "evaluation-key component material contains non-canonical Q_share residues",
                    ));
                }
                coefficients.push(coefficient);
            }
            component_vectors_little_endian_hex_by_digit_and_limb
                .push(coefficient_vector_le_hex(&coefficients));
            *component_b_limb = coefficients;
        }
    }
    if !reader.is_exhausted() {
        return Err(invalid_evaluation_key_share_material(
            "evaluation-key component material has trailing bytes",
        ));
    }
    let component_vector_root = evaluation_key_share_component_vector_root(
        proof_family,
        derived_binding.key_switch_domain,
        derived_binding.key_switch_seed_hex,
        level,
        &component_vectors_little_endian_hex_by_digit_and_limb,
    )?;

    Ok(DecodedEvaluationKeyShareComponentMaterial {
        component_b_by_digit,
        ring_degree,
        component_vector_root,
    })
}

#[derive(Debug, Clone)]
pub(in crate::bgv::setup) struct VerifiedEvaluationKeyShareComponentMaterialChunkStoreEntry {
    pub(in crate::bgv::setup) backing: VerifiedComponentMaterialBacking,
    pub(in crate::bgv::setup) proof_family: &'static str,
    pub(in crate::bgv::setup) total_byte_length: u64,
}

// Native builds stage verified component material in temporary files. Browser
// WASM has no filesystem and retains the chunks in memory; tests compile that
// backing on native targets to exercise it without a browser.
#[derive(Debug, Clone)]
pub(in crate::bgv::setup) enum VerifiedComponentMaterialBacking {
    #[cfg(not(target_arch = "wasm32"))]
    TempFile(PathBuf),
    #[cfg(target_arch = "wasm32")]
    Memory(Vec<Vec<u8>>),
}

// Stream lifecycle: begin validates the descriptor and opens a staging sink,
// absorb validates and stages each chunk, and finish authenticates the complete
// stream and registers its verified handle.
pub(crate) use component_material_stream::{
    CanonicalComponentMaterialStream, absorb_verified_canonical_component_material_chunk,
    begin_verified_canonical_component_material_stream,
    cancel_verified_canonical_component_material_stream,
    finish_verified_canonical_component_material_stream,
};

mod component_material_stream {
    use super::*;

    #[cfg(not(target_arch = "wasm32"))]
    const COMPONENT_MATERIAL_STREAM_TEMP_FILE_DOMAIN: &str =
        "sealed-lattice/setup/evaluation-key-share/component-material/stream-temp";
    #[cfg(not(target_arch = "wasm32"))]
    static NEXT_COMPONENT_MATERIAL_STREAM_TEMP_FILE_SEQUENCE: std::sync::atomic::AtomicU64 =
        std::sync::atomic::AtomicU64::new(1);

    // Native streams stage to a temporary file; browser WASM stages in memory.
    enum ComponentMaterialStreamSink {
        #[cfg(not(target_arch = "wasm32"))]
        TempFile {
            path: PathBuf,
            writer: BufWriter<File>,
        },
        #[cfg(target_arch = "wasm32")]
        Memory { chunks: Vec<Vec<u8>> },
    }

    pub(crate) struct CanonicalComponentMaterialStream {
        proof_family: &'static str,
        sink: Option<ComponentMaterialStreamSink>,
        total_byte_length: u64,
    }

    impl Drop for CanonicalComponentMaterialStream {
        fn drop(&mut self) {
            if let Some(sink) = self.sink.as_ref() {
                discard_component_material_stream_sink(sink);
            }
        }
    }

    fn open_component_material_stream_sink(
        verification_id: &str,
    ) -> CanonicalResult<ComponentMaterialStreamSink> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let (path, file) = create_component_material_stream_temp_file(verification_id)?;
            Ok(ComponentMaterialStreamSink::TempFile {
                path,
                writer: BufWriter::new(file),
            })
        }
        #[cfg(target_arch = "wasm32")]
        {
            let _ = verification_id;
            Ok(ComponentMaterialStreamSink::Memory { chunks: Vec::new() })
        }
    }

    fn stage_component_material_stream_chunk(
        sink: &mut ComponentMaterialStreamSink,
        chunk: &[u8],
    ) -> CanonicalResult<()> {
        match sink {
            #[cfg(not(target_arch = "wasm32"))]
            ComponentMaterialStreamSink::TempFile { writer, .. } => {
                writer.write_all(chunk).map_err(|error| {
                    invalid_evaluation_key_share_material(format!(
                        "evaluation-key component material chunk could not be written: {error}"
                    ))
                })
            }
            #[cfg(target_arch = "wasm32")]
            ComponentMaterialStreamSink::Memory { chunks } => {
                chunks.push(chunk.to_vec());
                Ok(())
            }
        }
    }

    // Finishing transfers ownership of the staged data to the verified store.
    fn component_material_stream_sink_into_backing(
        sink: ComponentMaterialStreamSink,
    ) -> VerifiedComponentMaterialBacking {
        match sink {
            #[cfg(not(target_arch = "wasm32"))]
            ComponentMaterialStreamSink::TempFile { path, .. } => {
                VerifiedComponentMaterialBacking::TempFile(path)
            }
            #[cfg(target_arch = "wasm32")]
            ComponentMaterialStreamSink::Memory { chunks } => {
                VerifiedComponentMaterialBacking::Memory(chunks)
            }
        }
    }

    // Failed native streams must remove their temporary file.
    fn discard_component_material_stream_sink(sink: &ComponentMaterialStreamSink) {
        match sink {
            #[cfg(not(target_arch = "wasm32"))]
            ComponentMaterialStreamSink::TempFile { path, .. } => {
                let _ = std::fs::remove_file(path);
            }
            #[cfg(target_arch = "wasm32")]
            ComponentMaterialStreamSink::Memory { .. } => {}
        }
    }

    pub(crate) fn begin_verified_canonical_component_material_stream(
        stream_handle: u32,
        proof_family: &'static str,
        total_byte_length: u64,
    ) -> CanonicalResult<CanonicalComponentMaterialStream> {
        if total_byte_length == 0 {
            return Err(invalid_evaluation_key_share_material(
                "canonical evaluation-key component material stream must be nonempty",
            ));
        }
        let sink = open_component_material_stream_sink(&format!(
            "canonical-component-material-{stream_handle}"
        ))?;
        Ok(CanonicalComponentMaterialStream {
            proof_family,
            sink: Some(sink),
            total_byte_length,
        })
    }

    pub(crate) fn absorb_verified_canonical_component_material_chunk(
        stream: &mut CanonicalComponentMaterialStream,
        chunk: &[u8],
    ) -> CanonicalResult<()> {
        let sink = stream.sink.as_mut().ok_or_else(|| {
            invalid_evaluation_key_share_material(
                "canonical evaluation-key component material stream is no longer active",
            )
        })?;
        stage_component_material_stream_chunk(sink, chunk)
    }

    pub(crate) fn finish_verified_canonical_component_material_stream(
        mut stream: CanonicalComponentMaterialStream,
        stream_summary: Arc<VerifiedCanonicalStreamSummary>,
    ) -> CanonicalResult<VerifiedEvaluationKeyShareComponentMaterialChunkStoreEntry> {
        if stream_summary.stream_domain()
            != crate::foundation::CanonicalStreamDomain::EvaluatorKeyStore
            || stream_summary.total_byte_length() != stream.total_byte_length
        {
            return Err(invalid_evaluation_key_share_material(
                "evaluation-key component material does not match its authenticated stream summary",
            ));
        }
        let sink = stream.sink.take().ok_or_else(|| {
            invalid_evaluation_key_share_material(
                "canonical evaluation-key component material stream is no longer active",
            )
        })?;
        let backing = component_material_stream_sink_into_backing(sink);
        Ok(VerifiedEvaluationKeyShareComponentMaterialChunkStoreEntry {
            backing,
            proof_family: stream.proof_family,
            total_byte_length: stream.total_byte_length,
        })
    }

    pub(crate) fn cancel_verified_canonical_component_material_stream(
        mut stream: CanonicalComponentMaterialStream,
    ) {
        if let Some(sink) = stream.sink.take() {
            discard_component_material_stream_sink(&sink);
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn create_component_material_stream_temp_file(
        verification_id: &str,
    ) -> CanonicalResult<(PathBuf, File)> {
        let mut directory = std::env::temp_dir();
        directory.push("sealed-lattice-evaluation-key-component-material");
        std::fs::create_dir_all(&directory).map_err(|error| {
            invalid_evaluation_key_share_material(format!(
            "evaluation-key component material stream temp directory could not be created: {error}"
        ))
        })?;
        let process_identifier = std::process::id().to_le_bytes();
        loop {
            let sequence = NEXT_COMPONENT_MATERIAL_STREAM_TEMP_FILE_SEQUENCE
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                .to_le_bytes();
            let file_name = hash512_hex(
                COMPONENT_MATERIAL_STREAM_TEMP_FILE_DOMAIN,
                &[verification_id.as_bytes(), &process_identifier, &sequence],
            );
            let path = directory.join(format!("{file_name}.bin"));
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(file) => return Ok((path, file)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(invalid_evaluation_key_share_material(format!(
                        "evaluation-key component material stream temp file could not be created: {error}"
                    )));
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::foundation::{
            CanonicalStreamDomain, CanonicalStreamVerifier, derive_canonical_stream_descriptor,
        };

        fn verified_stream_summary(
            stream_domain: CanonicalStreamDomain,
            bytes: &[u8],
        ) -> Arc<VerifiedCanonicalStreamSummary> {
            let descriptor = derive_canonical_stream_descriptor(stream_domain, bytes)
                .expect("component material stream descriptor");
            let mut verifier = CanonicalStreamVerifier::new(stream_domain, descriptor)
                .expect("component material stream verifier");
            assert!(verifier.absorb_chunk(0, bytes).is_valid());
            Arc::new(
                verifier
                    .finish_with_summary()
                    .into_result()
                    .expect("authenticated component material stream summary"),
            )
        }

        #[test]
        fn component_material_stream_rejects_a_mismatched_authenticated_summary() {
            let material_bytes = [0x5a; 17];
            let mut stream = begin_verified_canonical_component_material_stream(
                0xd100_0001,
                "relinearization-key-share",
                material_bytes.len() as u64,
            )
            .expect("component material stream begins");
            absorb_verified_canonical_component_material_chunk(&mut stream, &material_bytes)
                .expect("component material chunk stages");

            let error = finish_verified_canonical_component_material_stream(
                stream,
                verified_stream_summary(
                    CanonicalStreamDomain::PublicKeyShareProof,
                    &material_bytes,
                ),
            )
            .expect_err("a summary from another canonical stream domain must reject");

            assert_eq!(error.code, CanonicalErrorCode::InvalidProtocolObject);
            assert!(
                error
                    .message
                    .contains("does not match its authenticated stream summary")
            );
        }

        #[cfg(not(target_arch = "wasm32"))]
        #[test]
        fn component_material_temp_files_are_unique_for_a_repeated_stream_identifier() {
            let (first_path, mut first_file) =
                create_component_material_stream_temp_file("repeated-stream-identifier")
                    .expect("first component material temp file");
            first_file
                .write_all(b"first-stream-material")
                .expect("first component material temp file write");
            first_file
                .flush()
                .expect("first component material temp file flush");

            let (second_path, second_file) =
                create_component_material_stream_temp_file("repeated-stream-identifier")
                    .expect("second component material temp file");
            assert_ne!(first_path, second_path);
            assert_eq!(
                std::fs::read(&first_path).expect("first component material temp file read"),
                b"first-stream-material",
            );

            drop(first_file);
            drop(second_file);
            std::fs::remove_file(&first_path).expect("remove first component material temp file");
            std::fs::remove_file(&second_path).expect("remove second component material temp file");
        }
    }
}
