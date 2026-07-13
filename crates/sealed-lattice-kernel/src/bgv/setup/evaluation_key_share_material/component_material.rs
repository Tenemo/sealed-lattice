use super::*;
#[cfg(test)]
use std::collections::BTreeSet;

#[cfg(not(target_arch = "wasm32"))]
use std::io::{BufWriter, Write};

use crate::hashing::derive_canonical_object_hash;

pub(in crate::bgv::setup) fn evaluation_key_share_component_vector_hash(
    coefficients: &[u64],
) -> String {
    coefficient_vector_hash512(
        coefficients,
        EVALUATION_KEY_SHARE_COMPONENT_VECTOR_HASH_DOMAIN,
    )
}

pub(in crate::bgv::setup) fn evaluation_key_share_component_vector_root(
    proof_family: EvaluationKeyShareProofFamily,
    key_switch_domain: &str,
    key_switch_seed_hex: &str,
    level: usize,
    ring_degree: usize,
    component_vector_entries: &[Value],
) -> CanonicalResult<String> {
    derive_canonical_object_hash(&json!({
        "objectType": "EvaluationKeyShareComponentVectorSet",
        "proofFamily": proof_family.proof_family(),
        "keySwitchDomain": key_switch_domain,
        "keySwitchSeedHex": key_switch_seed_hex,
        "level": level,
        "ringDegree": ring_degree,
        // The gadget decomposition base is the RNS base itself: for a key at
        // this level there is exactly one digit per active prime, so the
        // component matrix is square with digitCount = rnsLimbCount = level + 1.
        "digitCount": level + 1,
        "rnsLimbCount": level + 1,
        "componentVectors": component_vector_entries,
    }))
}

fn verified_evaluation_key_share_component_material_chunks()
-> &'static Mutex<BTreeMap<String, VerifiedEvaluationKeyShareComponentMaterialChunkStoreEntry>> {
    VERIFIED_EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_CHUNKS
        .get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn stored_verified_evaluation_key_share_component_material_chunks(
    material_root: &str,
    proof_family: &str,
) -> CanonicalResult<Vec<Vec<u8>>> {
    let stored_chunks = verified_evaluation_key_share_component_material_chunks()
        .lock()
        .map_err(|_| {
            invalid_evaluation_key_share_material(
                "verified evaluation-key component material store is unavailable",
            )
        })?;
    let store_entry = stored_chunks.get(material_root).cloned().ok_or_else(|| {
        invalid_evaluation_key_share_material(
            "transported evaluation-key component material requires chunks or a live verified material handle",
        )
    })?;
    if store_entry.proof_family != proof_family {
        return Err(invalid_evaluation_key_share_material(
            "transported evaluation-key component material belongs to a different proof family",
        ));
    }
    // The entry is cloned once so the read (a native file read) never holds the
    // store lock; it is then consumed by value below, so the chunk bytes are moved
    // out rather than cloned a second time. The original stays in the store for the
    // verifier's repeated reads and is dropped by the eviction guard after verify.
    drop(stored_chunks);

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
            let chunk_size =
                usize::try_from(SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES).map_err(|_| {
                    invalid_evaluation_key_share_material(
                        "evaluation-key component material chunk size does not fit usize",
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
                let next_chunk_length = usize::try_from(
                    remaining_byte_length.min(SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES),
                )
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

// Collect the evaluation-key component material roots a verification request
// references, so the eviction guard drops exactly those store entries and leaves a
// concurrent verification's entries untouched.
#[cfg(test)]
fn request_component_material_roots(request: &Value) -> Vec<String> {
    let Some(material_sidecar) = request.get("transportedEvaluationKeyShareComponentMaterial")
    else {
        return Vec::new();
    };
    let mut material_roots = BTreeSet::new();
    collect_component_material_roots(material_sidecar, &mut material_roots);
    material_roots.into_iter().collect()
}

#[cfg(test)]
fn collect_component_material_roots(value: &Value, material_roots: &mut BTreeSet<String>) {
    let mut pending_values = vec![value];
    while let Some(current_value) = pending_values.pop() {
        match current_value {
            Value::Object(fields) => {
                if let Some(root) = fields
                    .get("keySwitchComponentMaterialRoot")
                    .and_then(Value::as_str)
                {
                    material_roots.insert(root.to_string());
                }
                pending_values.extend(fields.values());
            }
            Value::Array(items) => pending_values.extend(items),
            _ => {}
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

// Drop the verified component material entries a completed verification consumed,
// so the process-global store does not retain them. The verifier reads each entry
// several times (public-key reconstruction and evaluation-key proof checks), so
// eviction happens once, after verify returns, rather than on first read. Without
// it the store would grow with every verified package on the wasm runtime, whose
// linear memory never returns to the OS.
pub(in crate::bgv::setup) fn evict_verified_evaluation_key_share_component_material(
    material_roots: &[String],
) {
    let _ = drain_verified_evaluation_key_share_component_material(material_roots);
}

pub(in crate::bgv::setup) fn drain_verified_evaluation_key_share_component_material(
    material_roots: &[String],
) -> CanonicalResult<()> {
    let mut stored_chunks = verified_evaluation_key_share_component_material_chunks()
        .lock()
        .map_err(|_| {
            invalid_evaluation_key_share_material(
                "verified evaluation-key component material store is unavailable",
            )
        })?;
    let mut first_cleanup_error = None;
    for material_root in material_roots {
        if let Some(entry) = stored_chunks.remove(material_root) {
            if let Err(error) = discard_verified_component_material_backing(entry.backing)
                && first_cleanup_error.is_none()
            {
                first_cleanup_error = Some(error);
            }
        }
    }
    first_cleanup_error.map_or(Ok(()), Err)
}

// RAII guard that evicts a verification's streamed component material from the
// process-global store when verify returns by any path (acceptance, refusal, or
// error), scoped to the request's own material roots.
#[cfg(test)]
pub(in crate::bgv::setup) struct VerifiedComponentMaterialEvictionGuard {
    material_roots: Vec<String>,
}

#[cfg(test)]
impl VerifiedComponentMaterialEvictionGuard {
    pub(in crate::bgv::setup) fn for_request(request: &Value) -> Self {
        Self {
            material_roots: request_component_material_roots(request),
        }
    }
}

#[cfg(test)]
impl Drop for VerifiedComponentMaterialEvictionGuard {
    fn drop(&mut self) {
        evict_verified_evaluation_key_share_component_material(&self.material_roots);
    }
}

pub(in crate::bgv::setup) fn evaluation_key_share_component_material_reference_root(
    proof_family: EvaluationKeyShareProofFamily,
    proof_record: &Value,
) -> CanonicalResult<String> {
    let level = value_u64(proof_record, "level")?;
    let digit_count = level.checked_add(1).ok_or_else(|| {
        invalid_evaluation_key_share_material("evaluation-key digit count overflowed")
    })?;
    derive_canonical_object_hash(&json!({
        "objectType": "EvaluationKeyShareComponentMaterialReference",
        "proofFamily": proof_family.proof_family(),
        "keySwitchMaterialEncoding": EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ENCODING,
        "trusteeIdentity": string_field(proof_record, "trusteeIdentity")?,
        "trusteeRosterPosition": value_u64(proof_record, "trusteeRosterPosition")?,
        "keySwitchDomain": string_field(proof_record, "keySwitchDomain")?,
        "keySwitchSeedHex": string_field(proof_record, "keySwitchSeedHex")?,
        "level": level,
        "ringDegree": value_u64(proof_record, "ringDegree")?,
        "digitCount": digit_count,
        "rnsLimbCount": digit_count,
        "keySwitchComponentVectorRoot": string_field(
            proof_record,
            "keySwitchComponentVectorRoot",
        )?,
    }))
}

pub(in crate::bgv::setup) fn component_b_vectors_from_record(
    proof_family: EvaluationKeyShareProofFamily,
    record: &Value,
    transported_key_switch_component_material: Option<&Value>,
) -> CanonicalResult<Vec<Vec<Vec<u64>>>> {
    if string_field(record, "keySwitchMaterialEncoding")?
        != EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ENCODING
        || record.get("keySwitchComponentVectors").is_some()
    {
        return Err(invalid_evaluation_key_share_material(
            "evaluation-key component vectors require canonical streamed material",
        ));
    }
    let transported_material_set = transported_key_switch_component_material.ok_or_else(|| {
        invalid_evaluation_key_share_material(
            "transported evaluation-key component material is required",
        )
    })?;
    component_b_vectors_from_transported_material(proof_family, record, transported_material_set)
}

fn component_b_vectors_from_transported_material(
    proof_family: EvaluationKeyShareProofFamily,
    record: &Value,
    material_set: &Value,
) -> CanonicalResult<Vec<Vec<Vec<u64>>>> {
    if material_set.get("objectType").and_then(Value::as_str)
        != Some(EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_TRANSPORT_SET_OBJECT_TYPE)
    {
        return Err(invalid_evaluation_key_share_material(
            "transported evaluation-key component material set header is invalid",
        ));
    }
    let expected_material_root = string_field(record, "keySwitchComponentMaterialRoot")?;
    let component_materials = array_field(material_set, "componentMaterials")?;
    let mut matching_component_material = None;
    for component_material in component_materials {
        if string_field(component_material, "keySwitchComponentMaterialRoot")?
            != expected_material_root
        {
            continue;
        }
        if matching_component_material.is_some() {
            return Err(invalid_evaluation_key_share_material(
                "transported evaluation-key component material contains duplicate keySwitchComponentMaterialRoot entries",
            ));
        }
        matching_component_material = Some(component_material);
    }
    let component_material = matching_component_material.ok_or_else(|| {
        invalid_evaluation_key_share_material(
            "transported evaluation-key component material is missing the requested keySwitchComponentMaterialRoot",
        )
    })?;
    verify_evaluation_key_share_component_material_header(
        proof_family,
        record,
        component_material,
    )?;
    let chunks = evaluation_key_share_component_material_chunks(component_material)?;
    let canonical_material_root =
        evaluation_key_share_component_material_reference_root(proof_family, record)?;
    if expected_material_root != canonical_material_root {
        return Err(invalid_evaluation_key_share_material(
            "evaluation-key component material root must match the canonical transported material reference",
        ));
    }
    decode_evaluation_key_share_component_vectors(proof_family, record, &chunks)
}

fn verify_evaluation_key_share_component_material_header(
    proof_family: EvaluationKeyShareProofFamily,
    record: &Value,
    component_material: &Value,
) -> CanonicalResult<()> {
    if component_material.get("objectType").and_then(Value::as_str)
        != Some(EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_TRANSPORT_OBJECT_TYPE)
        || component_material
            .get("proofFamily")
            .and_then(Value::as_str)
            != Some(proof_family.proof_family())
        || component_material
            .get("keySwitchMaterialEncoding")
            .and_then(Value::as_str)
            != Some(EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ENCODING)
    {
        return Err(invalid_evaluation_key_share_material(
            "transported evaluation-key component material header is invalid",
        ));
    }
    for field_name in [
        "trusteeIdentity",
        "trusteeRosterPosition",
        "keySwitchDomain",
        "keySwitchSeedHex",
        "level",
        "ringDegree",
        "keySwitchComponentVectorRoot",
    ] {
        if component_material.get(field_name) != record.get(field_name) {
            return Err(invalid_evaluation_key_share_material(format!(
                "transported evaluation-key component material {field_name} must match the proof record"
            )));
        }
    }
    let level = value_u64(record, "level")?;
    let digit_count = level.checked_add(1).ok_or_else(|| {
        invalid_evaluation_key_share_material("evaluation-key digit count overflowed")
    })?;
    if component_material.get("digitCount").and_then(Value::as_u64) != Some(digit_count)
        || component_material
            .get("rnsLimbCount")
            .and_then(Value::as_u64)
            != Some(digit_count)
    {
        return Err(invalid_evaluation_key_share_material(
            "transported evaluation-key component material digit and limb counts must match the proof level",
        ));
    }

    Ok(())
}

fn evaluation_key_share_component_material_chunks(value: &Value) -> CanonicalResult<Vec<Vec<u8>>> {
    let material_root = string_field(value, "keySwitchComponentMaterialRoot")?;
    let proof_family = string_field(value, "proofFamily")?;
    stored_verified_evaluation_key_share_component_material_chunks(material_root, proof_family)
        .map_err(|_| {
            invalid_evaluation_key_share_material(
                "evaluation-key component material was not authenticated by the canonical binary stream",
            )
        })
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
    record: &Value,
    material_chunks: &[Vec<u8>],
) -> CanonicalResult<Vec<Vec<Vec<u64>>>> {
    let mut reader = CanonicalComponentMaterialReader::new(material_chunks)?;
    let magic = reader.read_fixed::<8>()?;
    if &magic != EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_MAGIC {
        return Err(invalid_evaluation_key_share_material(
            "evaluation-key component material has the wrong format marker",
        ));
    }
    let level = usize::try_from(reader.read_u64()?).map_err(|_| {
        invalid_evaluation_key_share_material(
            "evaluation-key component material level does not fit usize",
        )
    })?;
    let ring_degree = usize::try_from(reader.read_u64()?).map_err(|_| {
        invalid_evaluation_key_share_material(
            "evaluation-key component material ringDegree does not fit usize",
        )
    })?;
    let digit_count = usize::try_from(reader.read_u64()?).map_err(|_| {
        invalid_evaluation_key_share_material(
            "evaluation-key component material digit count does not fit usize",
        )
    })?;
    let limb_count = usize::try_from(reader.read_u64()?).map_err(|_| {
        invalid_evaluation_key_share_material(
            "evaluation-key component material limb count does not fit usize",
        )
    })?;
    if level != value_usize(record, "level")?
        || ring_degree != value_usize(record, "ringDegree")?
        || ring_degree == 0
        || ring_degree > POLYNOMIAL_DEGREE
        || digit_count
            != level.checked_add(1).ok_or_else(|| {
                invalid_evaluation_key_share_material("evaluation-key digit count overflowed")
            })?
        || limb_count != digit_count
        || limb_count == 0
        || limb_count > DATA_PRIMES.len()
    {
        return Err(invalid_evaluation_key_share_material(
            "evaluation-key component material shape does not match the proof record",
        ));
    }
    let key_switch_domain = string_field(record, "keySwitchDomain")?;
    let key_switch_seed_hex = string_field(record, "keySwitchSeedHex")?;
    validate_hex_string(key_switch_seed_hex, "keySwitchSeedHex")?;
    let mut component_b_by_digit = vec![vec![Vec::<u64>::new(); limb_count]; digit_count];
    let mut entries = Vec::with_capacity(digit_count * limb_count);
    for expected_digit_index in 0..digit_count {
        for expected_rns_limb_index in 0..limb_count {
            let digit_index = usize::try_from(reader.read_u64()?).map_err(|_| {
                invalid_evaluation_key_share_material(
                    "evaluation-key component material digit index does not fit usize",
                )
            })?;
            let rns_limb_index = usize::try_from(reader.read_u64()?).map_err(|_| {
                invalid_evaluation_key_share_material(
                    "evaluation-key component material RNS limb index does not fit usize",
                )
            })?;
            let rns_prime = reader.read_u64()?;
            let coefficient_count = usize::try_from(reader.read_u64()?).map_err(|_| {
                invalid_evaluation_key_share_material(
                    "evaluation-key component material coefficient count does not fit usize",
                )
            })?;
            if digit_index != expected_digit_index
                || rns_limb_index != expected_rns_limb_index
                || rns_limb_index >= DATA_PRIMES.len()
                || rns_prime != DATA_PRIMES[rns_limb_index]
                || coefficient_count != ring_degree
            {
                return Err(invalid_evaluation_key_share_material(
                    "evaluation-key component material record order or metadata is invalid",
                ));
            }
            let mut coefficients = Vec::with_capacity(ring_degree);
            for _ in 0..ring_degree {
                let coefficient = reader.read_u64()?;
                if coefficient >= DATA_PRIMES[rns_limb_index] {
                    return Err(invalid_evaluation_key_share_material(
                        "evaluation-key component material contains non-canonical Q_share residues",
                    ));
                }
                coefficients.push(coefficient);
            }
            entries.push(json!({
                "digitIndex": digit_index,
                "rnsLimbIndex": rns_limb_index,
                "rnsPrime": DATA_PRIMES[rns_limb_index],
                "component": "b",
                "coefficientByteLength": ring_degree.checked_mul(8).ok_or_else(|| {
                    invalid_evaluation_key_share_material(
                        "evaluation-key coefficient byte length overflowed",
                    )
                })?,
                "coefficientVectorHash512": evaluation_key_share_component_vector_hash(&coefficients),
                "coefficientsLeHex": coefficient_vector_le_hex(&coefficients),
            }));
            component_b_by_digit[digit_index][rns_limb_index] = coefficients;
        }
    }
    if !reader.is_exhausted() {
        return Err(invalid_evaluation_key_share_material(
            "evaluation-key component material has trailing bytes",
        ));
    }
    let expected_root = evaluation_key_share_component_vector_root(
        proof_family,
        key_switch_domain,
        key_switch_seed_hex,
        level,
        ring_degree,
        &entries,
    )?;
    if string_field(record, "keySwitchComponentVectorRoot")? != expected_root {
        return Err(invalid_evaluation_key_share_material(
            "evaluation-key component vector root does not match transported public material",
        ));
    }

    Ok(component_b_by_digit)
}

static VERIFIED_EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_CHUNKS: OnceLock<
    Mutex<BTreeMap<String, VerifiedEvaluationKeyShareComponentMaterialChunkStoreEntry>>,
> = OnceLock::new();

#[derive(Debug, Clone)]
struct VerifiedEvaluationKeyShareComponentMaterialChunkStoreEntry {
    backing: VerifiedComponentMaterialBacking,
    proof_family: &'static str,
    stream_summary: Arc<VerifiedCanonicalStreamSummary>,
    total_byte_length: u64,
}

#[cfg(test)]
pub(in crate::bgv::setup) fn authenticated_evaluation_key_component_stream_summary(
    proof_family: &str,
    material_root: &str,
) -> CanonicalResult<Option<Arc<VerifiedCanonicalStreamSummary>>> {
    authenticated_evaluation_key_component_stream_summary_in_session(
        None,
        proof_family,
        material_root,
    )
}

pub(in crate::bgv::setup) fn authenticated_evaluation_key_component_stream_summary_in_session(
    accepted_setup_session: Option<&crate::bgv::setup::AcceptedSetupProofBindingSession>,
    proof_family: &str,
    material_root: &str,
) -> CanonicalResult<Option<Arc<VerifiedCanonicalStreamSummary>>> {
    if let Some(accepted_setup_session) = accepted_setup_session
        && !crate::bgv::setup::accepted_setup_session_owns_material_root(
            accepted_setup_session.session_handle,
            &accepted_setup_session.capability,
            crate::bgv::setup::AcceptedSetupMaterialStore::Component,
            material_root,
        )?
    {
        return Ok(None);
    }
    let store = verified_evaluation_key_share_component_material_chunks()
        .lock()
        .map_err(|_| {
            invalid_evaluation_key_share_material(
                "verified evaluation-key component material store is unavailable",
            )
        })?;
    let Some(entry) = store.get(material_root) else {
        return Ok(None);
    };
    if entry.proof_family != proof_family {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "canonical evaluation-key component material root belongs to a different proof family",
        ));
    }
    Ok(Some(Arc::clone(&entry.stream_summary)))
}

// Where verified component material lives after a stream finishes. Native runs
// stage to a temp file so only one component (about 72.25 MiB) is resident at a
// time and CI memory stays bounded; the browser wasm runtime has no filesystem,
// so it holds the verified chunks in memory. The in-memory backing is also
// compiled under `test` so the native stream tests exercise it without a browser.
#[derive(Debug, Clone)]
enum VerifiedComponentMaterialBacking {
    #[cfg(not(target_arch = "wasm32"))]
    TempFile(PathBuf),
    #[cfg(target_arch = "wasm32")]
    Memory(Vec<Vec<u8>>),
}

// Streamed transport for evaluation-key component material. begin records the
// declared chunk manifest and opens a staging sink, absorb structurally
// validates each chunk (order, size, and running total) and stages it, and
// finish reads the staged chunks back, recomputes the component-material
// transport hashes, verifies them against the declared manifest, and registers
// the verified handle. One component is about 72.25 MiB and the whole per-roster
// class is tens of GB, so native stages to a temp file and keeps only one
// component resident; the browser wasm runtime has no filesystem and stages in
// memory. The accepted-setup verifier then reads the handle transiently through
// the shared read path. The material size, not the staging backend, is the open
// supported-phone runtime constraint (see SEC-008 and SEC-012).
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

    // Where an in-flight stream stages its chunks before finish verifies them.
    // Native stages to a temp file; the browser wasm runtime stages in memory.
    // Compiled under `test` so the native stream tests exercise the in-memory
    // path without a browser.
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
        material_root: String,
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

    // Open a staging sink for a new stream. Native opens a temp file; the wasm
    // runtime stages in memory.
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

    // Append one validated chunk to the staging sink.
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

    // Consume the staging sink into the verified store backing that persists for
    // downstream reads: native keeps the temp file, the wasm runtime keeps the
    // in-memory chunks.
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

    // Discard a staging sink whose stream failed, removing any temp file.
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
        material_root: String,
        proof_family: &'static str,
        total_byte_length: u64,
    ) -> CanonicalResult<CanonicalComponentMaterialStream> {
        validate_hex_string(&material_root, "keySwitchComponentMaterialRoot")?;
        if total_byte_length == 0 {
            return Err(invalid_evaluation_key_share_material(
                "canonical evaluation-key component material stream must be nonempty",
            ));
        }
        if verified_evaluation_key_share_component_material_chunks()
            .lock()
            .map_err(|_| {
                invalid_evaluation_key_share_material(
                    "verified evaluation-key component material store is unavailable",
                )
            })?
            .contains_key(&material_root)
        {
            return Err(invalid_evaluation_key_share_material(
                "canonical evaluation-key component material root is already staged",
            ));
        }
        let sink = open_component_material_stream_sink(&format!(
            "canonical-component-material-{stream_handle}"
        ))?;
        Ok(CanonicalComponentMaterialStream {
            material_root,
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
    ) -> CanonicalResult<()> {
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
        let store = verified_evaluation_key_share_component_material_chunks();
        let mut store = store.lock().map_err(|_| {
            invalid_evaluation_key_share_material(
                "verified evaluation-key component material store is unavailable",
            )
        })?;
        let material_root = std::mem::take(&mut stream.material_root);
        match store.entry(material_root) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(VerifiedEvaluationKeyShareComponentMaterialChunkStoreEntry {
                    backing,
                    proof_family: stream.proof_family,
                    stream_summary,
                    total_byte_length: stream.total_byte_length,
                });
            }
            std::collections::btree_map::Entry::Occupied(_) => {
                discard_verified_component_material_backing(backing)?;
                return Err(invalid_evaluation_key_share_material(
                    "canonical evaluation-key component material root was staged concurrently",
                ));
            }
        }
        Ok(())
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
            let material_root = "d1".repeat(64);
            let material_bytes = [0x5a; 17];
            let mut stream = begin_verified_canonical_component_material_stream(
                0xd100_0001,
                material_root.clone(),
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

            assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
            assert!(
                error
                    .message
                    .contains("does not match its authenticated stream summary")
            );
            assert!(
                super::super::authenticated_evaluation_key_component_stream_summary(
                    "relinearization-key-share",
                    &material_root,
                )
                .expect("component material store lookup")
                .is_none()
            );
        }

        #[test]
        fn component_material_stream_rejects_a_duplicate_material_root() {
            let material_root = "d2".repeat(64);
            let material_bytes = [0x6b; 19];
            super::super::evict_verified_evaluation_key_share_component_material(
                std::slice::from_ref(&material_root),
            );
            let mut stream = begin_verified_canonical_component_material_stream(
                0xd200_0001,
                material_root.clone(),
                "galois-key-share",
                material_bytes.len() as u64,
            )
            .expect("first component material stream begins");
            absorb_verified_canonical_component_material_chunk(&mut stream, &material_bytes)
                .expect("first component material chunk stages");
            finish_verified_canonical_component_material_stream(
                stream,
                verified_stream_summary(CanonicalStreamDomain::EvaluatorKeyStore, &material_bytes),
            )
            .expect("first component material stream authenticates");

            let error = match begin_verified_canonical_component_material_stream(
                0xd200_0002,
                material_root.clone(),
                "galois-key-share",
                material_bytes.len() as u64,
            ) {
                Ok(stream) => {
                    cancel_verified_canonical_component_material_stream(stream);
                    panic!("the same component material root must not be staged twice");
                }
                Err(error) => error,
            };

            assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
            assert!(error.message.contains("root is already staged"));
            super::super::evict_verified_evaluation_key_share_component_material(&[material_root]);
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
