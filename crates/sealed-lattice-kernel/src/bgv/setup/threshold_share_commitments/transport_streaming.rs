use super::*;

use crate::bgv::setup_helpers::setup_transport_chunk_manifest_root;
use crate::hashing::derive_canonical_object_hash;

static VSS_TRANSPORT_THRESHOLD_DERIVATION_SESSIONS: OnceLock<
    Mutex<BTreeMap<String, VssTransportThresholdDerivationSession>>,
> = OnceLock::new();
static VSS_TRANSPORT_VERIFIED_MATERIALS: OnceLock<
    Mutex<BTreeMap<String, VerifiedTransportedVssMaterial>>,
> = OnceLock::new();

pub(crate) struct VerifiedTransportedConstantVssCommitments {
    pub(crate) material_set: Value,
    pub(crate) constant_commitments_by_source_trustee:
        Arc<BTreeMap<u64, Vec<SetupCommitmentValue>>>,
}

pub(crate) struct VerifiedTransportedVssMaterial {
    pub(crate) reference: Value,
    pub(crate) setup_context: Value,
    pub(crate) public_matrix_seed_hash: String,
    pub(crate) vss_coefficient_commitment_root: String,
    pub(crate) material_set: Value,
    pub(crate) threshold_share_commitments: Value,
    pub(crate) constant_commitments_by_source_trustee:
        Arc<BTreeMap<u64, Vec<SetupCommitmentValue>>>,
}

pub(super) struct TransportThresholdDerivation {
    pub(super) ring_degree: usize,
    pub(super) ring_degree_status: &'static str,
    pub(super) observed_commitment_roots: BTreeMap<(u64, usize, u64), String>,
    pub(super) threshold_share_commitments: Value,
    pub(super) constant_commitments_by_source_trustee: BTreeMap<u64, Vec<SetupCommitmentValue>>,
}

pub(super) struct VssTransportThresholdDerivationSession {
    pub(super) setup_context: Value,
    pub(super) public_matrix_seed_hash: String,
    pub(super) transport_header: TransportedMaterialStreamHeader,
    pub(super) observed_chunk_hashes: Vec<String>,
    pub(super) full_object_hasher: Shake256,
    pub(super) next_chunk_index: usize,
    pub(super) observed_total_byte_length: u64,
    pub(super) parser: StreamingVssThresholdMaterialParser,
}

pub(super) struct TransportConstantVssMaterial {
    pub(super) ring_degree: usize,
    pub(super) ring_degree_status: &'static str,
    pub(super) constant_commitments_by_source_trustee: BTreeMap<u64, Vec<SetupCommitmentValue>>,
}

struct TransportThresholdAccumulator {
    coefficient_commitment_roots: Vec<String>,
    commitment: SetupCommitmentValue,
}

pub(super) fn vss_transport_derivation_sessions()
-> &'static Mutex<BTreeMap<String, VssTransportThresholdDerivationSession>> {
    VSS_TRANSPORT_THRESHOLD_DERIVATION_SESSIONS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

pub(super) fn vss_transport_verified_materials()
-> &'static Mutex<BTreeMap<String, VerifiedTransportedVssMaterial>> {
    VSS_TRANSPORT_VERIFIED_MATERIALS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

pub(crate) fn with_verified_transported_vss_material<T>(
    verified_material_reference: &Value,
    callback: impl FnOnce(&VerifiedTransportedVssMaterial) -> CanonicalResult<T>,
) -> CanonicalResult<T> {
    if verified_material_reference
        .get("objectType")
        .and_then(Value::as_str)
        != Some(VERIFIED_VSS_MATERIAL_OBJECT_TYPE)
    {
        return Err(invalid_threshold_commitment_input(
            "verifiedVssCoefficientCommitmentMaterial.objectType must be VerifiedVssCoefficientCommitmentMaterial",
        ));
    }
    if verified_material_reference
        .get("objectVersion")
        .and_then(Value::as_u64)
        != Some(1)
    {
        return Err(invalid_threshold_commitment_input(
            "verifiedVssCoefficientCommitmentMaterial.objectVersion must be 1",
        ));
    }
    let verification_id =
        derivation_stream_id_field(verified_material_reference, "verificationId")?;
    for field_name in [
        "publicMatrixSeedHash",
        "vssCoefficientCommitmentRoot",
        "vssCoefficientCommitmentMaterialRoot",
        "thresholdShareCommitmentRoot",
        "transportFullObjectHash",
        "transportChunkRoot",
    ] {
        validate_hash_string(
            hash_string_field(verified_material_reference, field_name)?,
            &format!("verifiedVssCoefficientCommitmentMaterial.{field_name}"),
        )?;
    }
    if u64_field(verified_material_reference, "transportChunkSizeBytes")?
        != SETUP_TRANSPORT_CHUNK_SIZE_BYTES
    {
        return Err(invalid_threshold_commitment_input(
            "verified VSS material transportChunkSizeBytes must match the setup transport parameters",
        ));
    }
    if u64_field(verified_material_reference, "transportChunkCount")? == 0 {
        return Err(invalid_threshold_commitment_input(
            "verified VSS material transportChunkCount must be positive",
        ));
    }
    if u64_field(verified_material_reference, "transportTotalByteLength")? == 0 {
        return Err(invalid_threshold_commitment_input(
            "verified VSS material transportTotalByteLength must be positive",
        ));
    }
    let verified_materials = vss_transport_verified_materials();
    let verified_materials = verified_materials.lock().map_err(|_| {
        invalid_threshold_commitment_input("verified material store is unavailable")
    })?;
    let verified_material = verified_materials.get(verification_id).ok_or_else(|| {
        invalid_threshold_commitment_input(
            "verified VSS material reference does not match a live stream-verified material",
        )
    })?;
    if &verified_material.reference != verified_material_reference {
        return Err(invalid_threshold_commitment_input(
            "verified VSS material reference does not match the stream-verified material metadata",
        ));
    }

    callback(verified_material)
}

pub(super) fn verified_transported_vss_material_reference_value(
    verification_id: &str,
    public_matrix_seed_hash: &str,
    vss_coefficient_commitment_root: &str,
    vss_coefficient_commitment_material_root: &str,
    threshold_share_commitment_root: &str,
    hashes: &SetupVssMaterialTransportHashes,
) -> Value {
    json!({
        "objectType": VERIFIED_VSS_MATERIAL_OBJECT_TYPE,
        "objectVersion": 1,
        "verificationId": verification_id,
        "materialBinaryFormat": VSS_MATERIAL_BINARY_FORMAT,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "vssCoefficientCommitmentRoot": vss_coefficient_commitment_root,
        "vssCoefficientCommitmentMaterialRoot": vss_coefficient_commitment_material_root,
        "thresholdShareCommitmentRoot": threshold_share_commitment_root,
        "transportChunkSizeBytes": SETUP_TRANSPORT_CHUNK_SIZE_BYTES,
        "transportChunkCount": hashes.chunk_hashes.len(),
        "transportTotalByteLength": hashes.total_byte_length,
        "transportFullObjectHash": hashes.full_object_hash,
        "transportChunkRoot": hashes.chunk_root,
    })
}

pub(super) fn absorb_threshold_share_commitment_transport_chunk(
    session: &mut VssTransportThresholdDerivationSession,
    chunk_index: usize,
    chunk: &[u8],
) -> CanonicalResult<Value> {
    if chunk_index != session.next_chunk_index {
        return Err(invalid_threshold_commitment_input(
            "transport stream chunks must be absorbed in ascending chunk-index order",
        ));
    }
    if chunk_index >= session.transport_header.chunk_count {
        return Err(invalid_threshold_commitment_input(
            "transport stream received more chunks than declared",
        ));
    }
    validate_transport_stream_chunk_shape(
        chunk_index,
        chunk,
        &session.transport_header,
        session.observed_total_byte_length,
    )?;
    let observed_chunk_hash = setup_vss_material_chunk_hash(chunk_index, chunk)?;
    if let Some(expected_manifest) = &session.transport_header.expected_manifest {
        let expected_chunk_hash =
            expected_manifest
                .chunk_hashes
                .get(chunk_index)
                .ok_or_else(|| {
                    invalid_threshold_commitment_input("transport stream chunk hash is missing")
                })?;
        if &observed_chunk_hash != expected_chunk_hash {
            return Err(invalid_threshold_commitment_input(
                "transport stream chunk bytes do not match the declared chunk hash",
            ));
        }
    }
    session.observed_chunk_hashes.push(observed_chunk_hash);
    session.full_object_hasher.update(chunk);
    session.observed_total_byte_length = session
        .observed_total_byte_length
        .checked_add(u64::try_from(chunk.len()).map_err(|_| {
            invalid_threshold_commitment_input("transport chunk length does not fit u64")
        })?)
        .ok_or_else(|| invalid_threshold_commitment_input("transport byte length overflowed"))?;
    session.parser.append_chunk(
        &session.setup_context,
        &session.public_matrix_seed_hash,
        chunk,
    )?;
    session.next_chunk_index += 1;

    Ok(json!({
        "operation": "absorbThresholdShareCommitmentsFromTransportStreamChunk",
        "absorbedChunkIndex": chunk_index,
        "absorbedByteLength": chunk.len(),
        "nextChunkIndex": session.next_chunk_index,
        "observedTotalByteLength": session.observed_total_byte_length,
    }))
}

fn validate_transport_stream_chunk_shape(
    chunk_index: usize,
    chunk: &[u8],
    header: &TransportedMaterialStreamHeader,
    observed_total_byte_length: u64,
) -> CanonicalResult<()> {
    if chunk.is_empty() {
        return Err(invalid_threshold_commitment_input(
            "setup transport chunks must be non-empty",
        ));
    }
    let chunk_size_usize = usize::try_from(SETUP_TRANSPORT_CHUNK_SIZE_BYTES).map_err(|_| {
        invalid_threshold_commitment_input("setup transport chunk size does not fit usize")
    })?;
    if chunk.len() > chunk_size_usize {
        return Err(invalid_threshold_commitment_input(
            "setup transport chunk exceeds the accepted chunk size",
        ));
    }
    let is_final_chunk = chunk_index + 1 == header.chunk_count;
    if !is_final_chunk && chunk.len() != chunk_size_usize {
        return Err(invalid_threshold_commitment_input(
            "setup transport contains a short non-final chunk",
        ));
    }
    let chunk_length = u64::try_from(chunk.len()).map_err(|_| {
        invalid_threshold_commitment_input("transport chunk length does not fit u64")
    })?;
    let new_total = observed_total_byte_length
        .checked_add(chunk_length)
        .ok_or_else(|| invalid_threshold_commitment_input("transport byte length overflowed"))?;
    if new_total > header.total_byte_length {
        return Err(invalid_threshold_commitment_input(
            "transport stream chunk bytes exceed declared totalByteLength",
        ));
    }
    if is_final_chunk && new_total != header.total_byte_length {
        return Err(invalid_threshold_commitment_input(
            "final transport stream chunk must finish at declared totalByteLength",
        ));
    }

    Ok(())
}

pub(super) fn finish_threshold_share_commitment_transport_stream(
    derivation_id: &str,
    session: VssTransportThresholdDerivationSession,
    vss_coefficient_commitment_root: &str,
    source_trustee_record_values: &[Value],
) -> CanonicalResult<Value> {
    validate_hash_string(
        vss_coefficient_commitment_root,
        "vssCoefficientCommitmentRoot",
    )?;
    let roster = accepted_roster_from_setup_context(&session.setup_context);
    let source_trustee_bindings = verify_source_trustee_commitment_records(
        source_trustee_record_values,
        &session.setup_context,
        &session.public_matrix_seed_hash,
        &roster,
    )?;
    if session.next_chunk_index != session.transport_header.chunk_count {
        return Err(invalid_threshold_commitment_input(
            "transport stream is missing declared chunks",
        ));
    }
    if session.observed_total_byte_length != session.transport_header.total_byte_length {
        return Err(invalid_threshold_commitment_input(
            "transport stream totalByteLength does not match absorbed chunk bytes",
        ));
    }
    let full_object_hash = finalize_streaming_hash512_hex(session.full_object_hasher);
    let chunk_root = setup_transport_chunk_manifest_root(
        SETUP_TRANSPORT_CHUNK_SIZE_BYTES,
        u64::try_from(session.transport_header.chunk_count).map_err(|_| {
            invalid_threshold_commitment_input("setup transport chunk count does not fit u64")
        })?,
        session.transport_header.total_byte_length,
        &session.observed_chunk_hashes,
        &full_object_hash,
    )?;
    if let Some(expected_manifest) = &session.transport_header.expected_manifest {
        let observed_hashes = SetupVssMaterialTransportHashes {
            full_object_hash: full_object_hash.clone(),
            chunk_hashes: session.observed_chunk_hashes.clone(),
            chunk_root: chunk_root.clone(),
            total_byte_length: session.transport_header.total_byte_length,
        };
        compare_transport_manifest_hashes(expected_manifest, &observed_hashes)?;
    }
    let derivation = session.parser.finish(
        &session.setup_context,
        &session.public_matrix_seed_hash,
        &source_trustee_bindings,
    )?;
    verify_observed_transport_commitment_roots(
        &roster,
        &source_trustee_bindings,
        &derivation.observed_commitment_roots,
    )?;
    let material_record_count = vss_material_record_count(
        roster.participant_count,
        roster.decryption_threshold as usize,
    );
    let hashes = SetupVssMaterialTransportHashes {
        full_object_hash,
        chunk_hashes: session.observed_chunk_hashes,
        chunk_root,
        total_byte_length: session.transport_header.total_byte_length,
    };
    let material_set = transported_vss_material_set_value(
        &session.setup_context,
        &session.public_matrix_seed_hash,
        derivation.ring_degree,
        derivation.ring_degree_status,
        &roster,
        material_record_count,
        vss_coefficient_commitment_root,
        &hashes,
    )?;
    let material_root = material_set
        .get("vssCoefficientCommitmentMaterialRoot")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            invalid_threshold_commitment_input(
                "transport stream derivation did not return a material root",
            )
        })?;
    let threshold_share_commitment_root = derivation
        .threshold_share_commitments
        .get("thresholdShareCommitmentRoot")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            invalid_threshold_commitment_input(
                "transport stream derivation did not return a threshold root",
            )
        })?;
    let verified_material_reference = verified_transported_vss_material_reference_value(
        derivation_id,
        &session.public_matrix_seed_hash,
        vss_coefficient_commitment_root,
        material_root,
        threshold_share_commitment_root,
        &hashes,
    );
    let constant_commitments_by_source_trustee =
        Arc::new(derivation.constant_commitments_by_source_trustee);
    let verified_materials = vss_transport_verified_materials();
    let mut verified_materials = verified_materials.lock().map_err(|_| {
        invalid_threshold_commitment_input("verified material store is unavailable")
    })?;
    if !verified_materials.contains_key(derivation_id)
        && verified_materials.len() >= VSS_TRANSPORT_MAX_VERIFIED_MATERIALS
    {
        return Err(invalid_threshold_commitment_input(
            "verified material store is full; release older verified material handles before finishing another stream",
        ));
    }
    verified_materials.insert(
        derivation_id.to_string(),
        VerifiedTransportedVssMaterial {
            reference: verified_material_reference.clone(),
            setup_context: session.setup_context.clone(),
            public_matrix_seed_hash: session.public_matrix_seed_hash.clone(),
            vss_coefficient_commitment_root: vss_coefficient_commitment_root.to_string(),
            material_set: material_set.clone(),
            threshold_share_commitments: derivation.threshold_share_commitments.clone(),
            constant_commitments_by_source_trustee,
        },
    );

    Ok(json!({
        "operation": "finishThresholdShareCommitmentsFromTransportStream",
        "derivationId": derivation_id,
        "materialBinaryFormat": VSS_MATERIAL_BINARY_FORMAT,
        "ringDegree": derivation.ring_degree,
        "ringDegreeStatus": derivation.ring_degree_status,
        "participantCount": roster.participant_count,
        "rnsLimbCount": DATA_PRIMES.len(),
        "thresholdDegree": roster.decryption_threshold,
        "derivedLimbCommitmentCount": roster.participant_count as usize * DATA_PRIMES.len(),
        "transport": {
            "transportSchemeId": SETUP_TRANSPORT_SCHEME_ID,
            "chunkSizeBytes": SETUP_TRANSPORT_CHUNK_SIZE_BYTES,
            "chunkCount": session.transport_header.chunk_count,
            "totalByteLength": hashes.total_byte_length,
            "fullObjectHash": hashes.full_object_hash,
            "chunkRoot": hashes.chunk_root,
            "chunkHashes": hashes.chunk_hashes,
        },
        "vssCoefficientCommitmentMaterial": material_set,
        "verifiedVssCoefficientCommitmentMaterial": verified_material_reference,
        "thresholdShareCommitmentRoot": threshold_share_commitment_root,
        "thresholdShareCommitments": derivation.threshold_share_commitments,
    }))
}

fn verify_observed_transport_commitment_roots(
    roster: &AcceptedRosterParameters,
    source_trustee_bindings: &BTreeMap<u64, SourceTrusteeCommitmentBinding>,
    observed_commitment_roots: &BTreeMap<(u64, usize, u64), String>,
) -> CanonicalResult<()> {
    if observed_commitment_roots.len()
        != vss_material_record_count(
            roster.participant_count,
            roster.decryption_threshold as usize,
        )
    {
        return Err(invalid_threshold_commitment_input(
            "transport stream did not observe every accepted VSS commitment coordinate",
        ));
    }
    for source_trustee_roster_position in 0..roster.participant_count {
        let source_trustee_binding = source_trustee_bindings
            .get(&source_trustee_roster_position)
            .ok_or_else(|| {
                invalid_threshold_commitment_input(
                    "transport stream finish is missing a source trustee binding",
                )
            })?;
        for rns_limb_index in 0..DATA_PRIMES.len() {
            for shamir_coefficient_index in 0..roster.decryption_threshold {
                let observed_commitment_root = observed_commitment_roots
                    .get(&(
                        source_trustee_roster_position,
                        rns_limb_index,
                        shamir_coefficient_index,
                    ))
                    .ok_or_else(|| {
                        invalid_threshold_commitment_input(
                            "transport stream is missing an observed VSS commitment coordinate",
                        )
                    })?;
                let expected_commitment_root = source_trustee_binding
                    .coefficient_commitment_roots
                    .get(&(rns_limb_index, shamir_coefficient_index))
                    .ok_or_else(|| {
                        invalid_threshold_commitment_input(
                            "transport stream finish source record is missing a VSS commitment coordinate",
                        )
                    })?;
                if observed_commitment_root != expected_commitment_root {
                    return Err(invalid_threshold_commitment_input(
                        "transported setup commitment material does not match the source trustee commitment root",
                    ));
                }
            }
        }
    }

    Ok(())
}

pub(super) struct StreamingVssThresholdMaterialParser {
    roster: AcceptedRosterParameters,
    pending_bytes: Vec<u8>,
    pending_offset: usize,
    ring_degree: Option<usize>,
    completed_record_count: usize,
    observed_commitment_roots: BTreeMap<(u64, usize, u64), String>,
    accumulators: BTreeMap<(u64, usize), TransportThresholdAccumulator>,
    constant_commitments_by_source_trustee: BTreeMap<u64, Vec<SetupCommitmentValue>>,
}

impl StreamingVssThresholdMaterialParser {
    pub(super) fn new(roster: AcceptedRosterParameters) -> Self {
        Self {
            roster,
            pending_bytes: Vec::new(),
            pending_offset: 0,
            ring_degree: None,
            completed_record_count: 0,
            observed_commitment_roots: BTreeMap::new(),
            accumulators: BTreeMap::new(),
            constant_commitments_by_source_trustee: BTreeMap::new(),
        }
    }

    pub(super) fn append_chunk(
        &mut self,
        setup_context: &Value,
        public_matrix_seed_hash: &str,
        chunk: &[u8],
    ) -> CanonicalResult<()> {
        self.pending_bytes.extend_from_slice(chunk);
        self.process_available(setup_context, public_matrix_seed_hash)
    }

    pub(super) fn finish(
        mut self,
        setup_context: &Value,
        public_matrix_seed_hash: &str,
        source_trustee_bindings: &BTreeMap<u64, SourceTrusteeCommitmentBinding>,
    ) -> CanonicalResult<TransportThresholdDerivation> {
        self.process_available(setup_context, public_matrix_seed_hash)?;
        let ring_degree = self.ring_degree.ok_or_else(|| {
            invalid_threshold_commitment_input(
                "transported VSS material ended before the binary header was complete",
            )
        })?;
        let expected_record_count = vss_material_record_count(
            self.roster.participant_count,
            self.roster.decryption_threshold as usize,
        );
        if self.completed_record_count != expected_record_count {
            return Err(invalid_threshold_commitment_input(
                "transported VSS material ended before every commitment record was supplied",
            ));
        }
        if self.available_byte_count() != 0 {
            return Err(invalid_threshold_commitment_input(
                "transported VSS material has trailing bytes after the final commitment record",
            ));
        }
        for source_trustee_roster_position in 0..self.roster.participant_count {
            if self
                .constant_commitments_by_source_trustee
                .get(&source_trustee_roster_position)
                .map(Vec::len)
                != Some(DATA_PRIMES.len())
            {
                return Err(invalid_threshold_commitment_input(
                    "transported VSS material is missing a constant commitment limb",
                ));
            }
        }

        let ring_degree_status = if ring_degree == POLYNOMIAL_DEGREE {
            "full-ring"
        } else {
            "development-reduced-ring"
        };
        let threshold_share_commitments =
            threshold_share_commitment_set_from_transport_accumulators(
                setup_context,
                public_matrix_seed_hash,
                ring_degree,
                ring_degree_status,
                &self.roster,
                source_trustee_bindings,
                &self.accumulators,
            )?;

        Ok(TransportThresholdDerivation {
            ring_degree,
            ring_degree_status,
            observed_commitment_roots: self.observed_commitment_roots,
            threshold_share_commitments,
            constant_commitments_by_source_trustee: self.constant_commitments_by_source_trustee,
        })
    }

    fn process_available(
        &mut self,
        setup_context: &Value,
        public_matrix_seed_hash: &str,
    ) -> CanonicalResult<()> {
        if self.ring_degree.is_none() {
            self.try_parse_header()?;
        }
        let Some(ring_degree) = self.ring_degree else {
            return Ok(());
        };
        let record_length = vss_material_binary_record_length(ring_degree)?;
        let expected_record_count = vss_material_record_count(
            self.roster.participant_count,
            self.roster.decryption_threshold as usize,
        );
        while self.completed_record_count < expected_record_count
            && self.available_byte_count() >= record_length
        {
            let record_end = self
                .pending_offset
                .checked_add(record_length)
                .ok_or_else(|| {
                    invalid_threshold_commitment_input("transport parser offset overflowed")
                })?;
            let (source_trustee_roster_position, rns_limb_index, shamir_coefficient_index) =
                expected_vss_material_record_coordinates(
                    self.completed_record_count,
                    self.roster.decryption_threshold as usize,
                )?;
            let rns_prime = DATA_PRIMES[rns_limb_index];
            let mut reader =
                SliceMaterialReader::new(&self.pending_bytes[self.pending_offset..record_end]);
            let commitment = read_binary_setup_commitment(
                &mut reader,
                source_trustee_roster_position,
                rns_limb_index,
                rns_prime,
                shamir_coefficient_index,
                ring_degree,
            )?;
            if !reader.is_finished() {
                return Err(invalid_threshold_commitment_input(
                    "transported VSS material record has trailing bytes",
                ));
            }
            let commitment_root = setup_commitment_root(&commitment)?;
            if self
                .observed_commitment_roots
                .insert(
                    (
                        source_trustee_roster_position,
                        rns_limb_index,
                        shamir_coefficient_index,
                    ),
                    commitment_root.clone(),
                )
                .is_some()
            {
                return Err(invalid_threshold_commitment_input(
                    "transported VSS material contains duplicate commitment coordinates",
                ));
            }
            accumulate_transport_threshold_commitments(
                setup_context,
                public_matrix_seed_hash,
                source_trustee_roster_position,
                rns_limb_index,
                rns_prime,
                shamir_coefficient_index,
                &self.roster,
                &commitment_root,
                &commitment,
                &mut self.accumulators,
            )?;
            if shamir_coefficient_index == 0 {
                self.constant_commitments_by_source_trustee
                    .entry(source_trustee_roster_position)
                    .or_default()
                    .push(commitment);
            }
            self.pending_offset = record_end;
            self.completed_record_count += 1;
            self.drain_consumed_bytes();
        }

        Ok(())
    }

    fn try_parse_header(&mut self) -> CanonicalResult<()> {
        let pending_slice = &self.pending_bytes[self.pending_offset..];
        if pending_slice.len() < VSS_MATERIAL_BINARY_MAGIC.len() {
            return Ok(());
        }
        if &pending_slice[..VSS_MATERIAL_BINARY_MAGIC.len()] != VSS_MATERIAL_BINARY_MAGIC {
            return Err(invalid_threshold_commitment_input(
                "transported VSS material binary magic does not match",
            ));
        }
        let mut cursor = self.pending_offset + VSS_MATERIAL_BINARY_MAGIC.len();
        let version = match try_read_varuint_from_pending(&self.pending_bytes, &mut cursor)? {
            PendingRead::Ready(value) => value,
            PendingRead::NeedMore => return Ok(()),
        };
        let participant_count =
            match try_read_varuint_from_pending(&self.pending_bytes, &mut cursor)? {
                PendingRead::Ready(value) => value,
                PendingRead::NeedMore => return Ok(()),
            };
        let threshold_degree =
            match try_read_varuint_from_pending(&self.pending_bytes, &mut cursor)? {
                PendingRead::Ready(value) => value,
                PendingRead::NeedMore => return Ok(()),
            };
        let rns_limb_count = match try_read_varuint_from_pending(&self.pending_bytes, &mut cursor)?
        {
            PendingRead::Ready(value) => value,
            PendingRead::NeedMore => return Ok(()),
        };
        // A forged ring degree mis-frames every subsequent fixed-length record, but it cannot survive the per-coordinate commitment-root match; varuints are also required to be minimally encoded so the byte stream is canonical.
        let ring_degree = match try_read_varuint_from_pending(&self.pending_bytes, &mut cursor)? {
            PendingRead::Ready(value) => usize::try_from(value)
                .map_err(|_| invalid_threshold_commitment_input("ringDegree does not fit usize"))?,
            PendingRead::NeedMore => return Ok(()),
        };
        let commitment_limb_count =
            match try_read_varuint_from_pending(&self.pending_bytes, &mut cursor)? {
                PendingRead::Ready(value) => value,
                PendingRead::NeedMore => return Ok(()),
            };
        let commitment_row_count =
            match try_read_varuint_from_pending(&self.pending_bytes, &mut cursor)? {
                PendingRead::Ready(value) => value,
                PendingRead::NeedMore => return Ok(()),
            };

        if version != VSS_MATERIAL_BINARY_VERSION {
            return Err(invalid_threshold_commitment_input(
                "transported VSS material binary version is unsupported",
            ));
        }
        if participant_count != self.roster.participant_count {
            return Err(invalid_threshold_commitment_input(
                "transported VSS material participant count does not match the accepted parameters",
            ));
        }
        if threshold_degree != self.roster.decryption_threshold {
            return Err(invalid_threshold_commitment_input(
                "transported VSS material threshold degree does not match the accepted parameters",
            ));
        }
        if rns_limb_count != DATA_PRIMES.len() as u64 {
            return Err(invalid_threshold_commitment_input(
                "transported VSS material RNS limb count does not match Q_share",
            ));
        }
        if commitment_limb_count != SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len() as u64 {
            return Err(invalid_threshold_commitment_input(
                "transported VSS material commitment limb count does not match the commitment parameters",
            ));
        }
        if commitment_row_count != SETUP_COMMITMENT_ROW_COUNT as u64 {
            return Err(invalid_threshold_commitment_input(
                "transported VSS material row count does not match the commitment parameters",
            ));
        }

        self.ring_degree = Some(ring_degree);
        self.pending_offset = cursor;
        self.drain_consumed_bytes();

        Ok(())
    }

    fn available_byte_count(&self) -> usize {
        self.pending_bytes.len().saturating_sub(self.pending_offset)
    }

    fn drain_consumed_bytes(&mut self) {
        if self.pending_offset == 0 {
            return;
        }
        self.pending_bytes.drain(0..self.pending_offset);
        self.pending_offset = 0;
    }
}

pub(super) fn read_constant_vss_commitments_from_transport_bytes(
    roster: &AcceptedRosterParameters,
    source_trustee_bindings: &BTreeMap<u64, SourceTrusteeCommitmentBinding>,
    chunks: &[Vec<u8>],
) -> CanonicalResult<TransportConstantVssMaterial> {
    let mut reader = ChunkedMaterialReader::new(chunks)?;
    let magic = reader.read_exact_vec(VSS_MATERIAL_BINARY_MAGIC.len())?;
    if magic != VSS_MATERIAL_BINARY_MAGIC {
        return Err(invalid_threshold_commitment_input(
            "transported VSS material binary magic does not match",
        ));
    }
    if reader.read_varuint()? != VSS_MATERIAL_BINARY_VERSION {
        return Err(invalid_threshold_commitment_input(
            "transported VSS material binary version is unsupported",
        ));
    }
    if reader.read_varuint()? != roster.participant_count {
        return Err(invalid_threshold_commitment_input(
            "transported VSS material participant count does not match the accepted parameters",
        ));
    }
    if reader.read_varuint()? != roster.decryption_threshold {
        return Err(invalid_threshold_commitment_input(
            "transported VSS material threshold degree does not match the accepted parameters",
        ));
    }
    if reader.read_varuint()? != DATA_PRIMES.len() as u64 {
        return Err(invalid_threshold_commitment_input(
            "transported VSS material RNS limb count does not match Q_share",
        ));
    }
    let ring_degree = reader.read_usize("ringDegree")?;
    if reader.read_varuint()? != SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len() as u64 {
        return Err(invalid_threshold_commitment_input(
            "transported VSS material commitment limb count does not match the commitment parameters",
        ));
    }
    if reader.read_varuint()? != SETUP_COMMITMENT_ROW_COUNT as u64 {
        return Err(invalid_threshold_commitment_input(
            "transported VSS material row count does not match the commitment parameters",
        ));
    }

    let mut constant_commitments_by_source_trustee =
        BTreeMap::<u64, Vec<SetupCommitmentValue>>::new();
    for source_trustee_roster_position in 0..roster.participant_count {
        let source_trustee_binding = source_trustee_bindings
            .get(&source_trustee_roster_position)
            .ok_or_else(|| {
                invalid_threshold_commitment_input(
                    "transport material is missing a source trustee binding",
                )
            })?;
        for (rns_limb_index, rns_prime) in DATA_PRIMES.iter().copied().enumerate() {
            for shamir_coefficient_index in 0..roster.decryption_threshold {
                let commitment = read_binary_setup_commitment(
                    &mut reader,
                    source_trustee_roster_position,
                    rns_limb_index,
                    rns_prime,
                    shamir_coefficient_index,
                    ring_degree,
                )?;
                let commitment_root = setup_commitment_root(&commitment)?;
                let expected_commitment_root = source_trustee_binding
                    .coefficient_commitment_roots
                    .get(&(rns_limb_index, shamir_coefficient_index))
                    .ok_or_else(|| {
                        invalid_threshold_commitment_input(
                            "transport material coordinate is absent from the source trustee record",
                        )
                    })?;
                if &commitment_root != expected_commitment_root {
                    return Err(invalid_threshold_commitment_input(
                        "transported setup commitment material does not match the source trustee commitment root",
                    ));
                }
                if shamir_coefficient_index == 0 {
                    constant_commitments_by_source_trustee
                        .entry(source_trustee_roster_position)
                        .or_default()
                        .push(commitment);
                }
            }
        }
    }
    if !reader.is_finished() {
        return Err(invalid_threshold_commitment_input(
            "transported VSS material has trailing bytes after the final commitment record",
        ));
    }
    for source_trustee_roster_position in 0..roster.participant_count {
        if constant_commitments_by_source_trustee
            .get(&source_trustee_roster_position)
            .map(Vec::len)
            != Some(DATA_PRIMES.len())
        {
            return Err(invalid_threshold_commitment_input(
                "transported VSS material is missing a constant commitment limb",
            ));
        }
    }

    Ok(TransportConstantVssMaterial {
        ring_degree,
        ring_degree_status: if ring_degree == POLYNOMIAL_DEGREE {
            "full-ring"
        } else {
            "development-reduced-ring"
        },
        constant_commitments_by_source_trustee,
    })
}

pub(super) fn derive_threshold_share_commitment_set_from_transport_bytes(
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    roster: &AcceptedRosterParameters,
    source_trustee_bindings: &BTreeMap<u64, SourceTrusteeCommitmentBinding>,
    chunks: &[Vec<u8>],
) -> CanonicalResult<TransportThresholdDerivation> {
    let mut reader = ChunkedMaterialReader::new(chunks)?;
    let magic = reader.read_exact_vec(VSS_MATERIAL_BINARY_MAGIC.len())?;
    if magic != VSS_MATERIAL_BINARY_MAGIC {
        return Err(invalid_threshold_commitment_input(
            "transported VSS material binary magic does not match",
        ));
    }
    if reader.read_varuint()? != VSS_MATERIAL_BINARY_VERSION {
        return Err(invalid_threshold_commitment_input(
            "transported VSS material binary version is unsupported",
        ));
    }
    if reader.read_varuint()? != roster.participant_count {
        return Err(invalid_threshold_commitment_input(
            "transported VSS material participant count does not match the accepted parameters",
        ));
    }
    if reader.read_varuint()? != roster.decryption_threshold {
        return Err(invalid_threshold_commitment_input(
            "transported VSS material threshold degree does not match the accepted parameters",
        ));
    }
    if reader.read_varuint()? != DATA_PRIMES.len() as u64 {
        return Err(invalid_threshold_commitment_input(
            "transported VSS material RNS limb count does not match Q_share",
        ));
    }
    let ring_degree = reader.read_usize("ringDegree")?;
    if reader.read_varuint()? != SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len() as u64 {
        return Err(invalid_threshold_commitment_input(
            "transported VSS material commitment limb count does not match the commitment parameters",
        ));
    }
    if reader.read_varuint()? != SETUP_COMMITMENT_ROW_COUNT as u64 {
        return Err(invalid_threshold_commitment_input(
            "transported VSS material row count does not match the commitment parameters",
        ));
    }

    let mut accumulators = BTreeMap::<(u64, usize), TransportThresholdAccumulator>::new();
    let mut observed_commitment_roots = BTreeMap::<(u64, usize, u64), String>::new();
    let mut constant_commitments_by_source_trustee =
        BTreeMap::<u64, Vec<SetupCommitmentValue>>::new();
    for source_trustee_roster_position in 0..roster.participant_count {
        let source_trustee_binding = source_trustee_bindings
            .get(&source_trustee_roster_position)
            .ok_or_else(|| {
                invalid_threshold_commitment_input(
                    "transport material is missing a source trustee binding",
                )
            })?;
        for (rns_limb_index, rns_prime) in DATA_PRIMES.iter().copied().enumerate() {
            for shamir_coefficient_index in 0..roster.decryption_threshold {
                let commitment = read_binary_setup_commitment(
                    &mut reader,
                    source_trustee_roster_position,
                    rns_limb_index,
                    rns_prime,
                    shamir_coefficient_index,
                    ring_degree,
                )?;
                let commitment_root = setup_commitment_root(&commitment)?;
                let expected_commitment_root = source_trustee_binding
                    .coefficient_commitment_roots
                    .get(&(rns_limb_index, shamir_coefficient_index))
                    .ok_or_else(|| {
                        invalid_threshold_commitment_input(
                            "transport material coordinate is absent from the source trustee record",
                        )
                    })?;
                if &commitment_root != expected_commitment_root {
                    return Err(invalid_threshold_commitment_input(
                        "transported setup commitment material does not match the source trustee commitment root",
                    ));
                }
                observed_commitment_roots.insert(
                    (
                        source_trustee_roster_position,
                        rns_limb_index,
                        shamir_coefficient_index,
                    ),
                    commitment_root.clone(),
                );
                accumulate_transport_threshold_commitments(
                    setup_context,
                    public_matrix_seed_hash,
                    source_trustee_roster_position,
                    rns_limb_index,
                    rns_prime,
                    shamir_coefficient_index,
                    roster,
                    &commitment_root,
                    &commitment,
                    &mut accumulators,
                )?;
                if shamir_coefficient_index == 0 {
                    constant_commitments_by_source_trustee
                        .entry(source_trustee_roster_position)
                        .or_default()
                        .push(commitment);
                }
            }
        }
    }
    if !reader.is_finished() {
        return Err(invalid_threshold_commitment_input(
            "transported VSS material has trailing bytes after the final commitment record",
        ));
    }
    let ring_degree_status = if ring_degree == POLYNOMIAL_DEGREE {
        "full-ring"
    } else {
        "development-reduced-ring"
    };
    let threshold_share_commitments = threshold_share_commitment_set_from_transport_accumulators(
        setup_context,
        public_matrix_seed_hash,
        ring_degree,
        ring_degree_status,
        roster,
        source_trustee_bindings,
        &accumulators,
    )?;

    Ok(TransportThresholdDerivation {
        ring_degree,
        ring_degree_status,
        observed_commitment_roots,
        threshold_share_commitments,
        constant_commitments_by_source_trustee,
    })
}

#[allow(clippy::too_many_arguments)]
// Feldman-style homomorphic evaluation: scaling coefficient commitment k by alpha_j^k and summing yields the public commitment to f_i(alpha_j), the recipient's threshold share, summed across source trustees.
fn accumulate_transport_threshold_commitments(
    _setup_context: &Value,
    _public_matrix_seed_hash: &str,
    _source_trustee_roster_position: u64,
    rns_limb_index: usize,
    rns_prime: u64,
    shamir_coefficient_index: u64,
    roster: &AcceptedRosterParameters,
    commitment_root: &str,
    commitment: &SetupCommitmentValue,
    accumulators: &mut BTreeMap<(u64, usize), TransportThresholdAccumulator>,
) -> CanonicalResult<()> {
    for recipient_roster_position in 0..roster.participant_count {
        let recipient_roster_position_usize =
            usize::try_from(recipient_roster_position).map_err(|_| {
                invalid_threshold_commitment_input("recipient roster position does not fit usize")
            })?;
        let trustee_point = canonical_trustee_point(recipient_roster_position_usize, rns_prime)?;
        let scalar =
            shamir_coefficient_scalars(trustee_point, roster.decryption_threshold as usize)?
                [shamir_coefficient_index as usize];
        let accumulator_key = (recipient_roster_position, rns_limb_index);
        match accumulators.get_mut(&accumulator_key) {
            Some(accumulator) => {
                accumulator
                    .coefficient_commitment_roots
                    .push(commitment_root.to_string());
                add_scaled_setup_commitment_in_place(
                    &mut accumulator.commitment,
                    commitment,
                    scalar,
                )?;
            }
            None => {
                let mut scaled_commitment =
                    linear_combination_setup_commitments(&[(commitment, scalar)])?;
                scaled_commitment.shamir_coefficient_index = 0;
                accumulators.insert(
                    accumulator_key,
                    TransportThresholdAccumulator {
                        coefficient_commitment_roots: vec![commitment_root.to_string()],
                        commitment: scaled_commitment,
                    },
                );
            }
        }
    }

    Ok(())
}

fn threshold_share_commitment_set_from_transport_accumulators(
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    ring_degree: usize,
    ring_degree_status: &str,
    roster: &AcceptedRosterParameters,
    source_trustee_bindings: &BTreeMap<u64, SourceTrusteeCommitmentBinding>,
    accumulators: &BTreeMap<(u64, usize), TransportThresholdAccumulator>,
) -> CanonicalResult<Value> {
    let mut recipient_records = Vec::with_capacity(roster.participant_count as usize);
    for recipient_roster_position in 0..roster.participant_count {
        let recipient_identity = recipient_identity_from_source_bindings(
            source_trustee_bindings,
            recipient_roster_position,
        )?;
        let recipient_roster_position_usize =
            usize::try_from(recipient_roster_position).map_err(|_| {
                invalid_threshold_commitment_input("recipient roster position does not fit usize")
            })?;
        let mut limb_commitments = Vec::with_capacity(DATA_PRIMES.len());
        for (rns_limb_index, rns_prime) in DATA_PRIMES.iter().copied().enumerate() {
            let accumulator = accumulators
                .get(&(recipient_roster_position, rns_limb_index))
                .ok_or_else(|| {
                    invalid_threshold_commitment_input(
                        "transport derivation is missing a threshold accumulator",
                    )
                })?;
            let expected_root_count =
                roster.participant_count as usize * roster.decryption_threshold as usize;
            if accumulator.coefficient_commitment_roots.len() != expected_root_count {
                return Err(invalid_threshold_commitment_input(
                    "transport threshold accumulator does not contain every coefficient root",
                ));
            }
            let threshold_limb_without_root = ThresholdLimbCommitment {
                rns_limb_index,
                rns_prime,
                threshold_share_commitment_root: String::new(),
                coefficient_commitment_roots: accumulator.coefficient_commitment_roots.clone(),
                commitment: accumulator.commitment.clone(),
            };
            let threshold_share_commitment_root =
                derive_canonical_object_hash(&threshold_limb_commitment_root_payload(
                    setup_context,
                    public_matrix_seed_hash,
                    &recipient_identity,
                    recipient_roster_position,
                    recipient_roster_position_usize,
                    roster.decryption_threshold as usize,
                    &threshold_limb_without_root,
                )?)?;
            let threshold_limb = ThresholdLimbCommitment {
                threshold_share_commitment_root,
                ..threshold_limb_without_root
            };
            limb_commitments.push(threshold_limb_commitment_value(
                setup_context,
                public_matrix_seed_hash,
                &recipient_identity,
                recipient_roster_position,
                recipient_roster_position_usize,
                roster.decryption_threshold as usize,
                ring_degree_status,
                &threshold_limb,
            )?);
        }
        let trustee_point =
            canonical_trustee_point(recipient_roster_position_usize, DATA_PRIMES[0])?;
        let mut recipient_record = json!({
            "objectType": THRESHOLD_SHARE_RECIPIENT_COMMITMENT_OBJECT_TYPE,
            "objectVersion": 1,
            "derivationRule": THRESHOLD_SHARE_DERIVATION_RULE,
            "publicMatrixSeedHash": public_matrix_seed_hash,
            "recipientIdentity": recipient_identity,
            "recipientRosterPosition": recipient_roster_position,
            "trusteePoint": trustee_point,
            "ringDegree": ring_degree,
            "ringDegreeStatus": ring_degree_status,
            "limbCommitments": limb_commitments,
        });
        copy_context_fields(&mut recipient_record, setup_context)?;
        let recipient_commitment_root = derive_canonical_object_hash(&recipient_record)?;
        recipient_record["recipientCommitmentRoot"] = json!(recipient_commitment_root);
        recipient_records.push(recipient_record);
    }

    let mut commitment_set = json!({
        "objectType": THRESHOLD_SHARE_COMMITMENT_SET_OBJECT_TYPE,
        "objectVersion": 1,
        "derivationRule": THRESHOLD_SHARE_DERIVATION_RULE,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "participantCount": roster.participant_count,
        "thresholdDegree": roster.decryption_threshold,
        "rnsLimbCount": DATA_PRIMES.len(),
        "ringDegree": ring_degree,
        "ringDegreeStatus": ring_degree_status,
        "recipientRecords": recipient_records,
    });
    copy_context_fields(&mut commitment_set, setup_context)?;
    let commitment_set_root = derive_canonical_object_hash(&commitment_set)?;
    commitment_set["thresholdShareCommitmentRoot"] = json!(commitment_set_root);

    Ok(commitment_set)
}
