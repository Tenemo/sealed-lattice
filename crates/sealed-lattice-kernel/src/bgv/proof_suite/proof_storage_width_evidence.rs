//! Guarded native evidence for bounded public-column replay custody.

use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde::Serialize;

use crate::{
    foundation::{
        MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH,
        MAXIMUM_LOCAL_RECORD_SEAL_INVOCATIONS_PER_ACTIVE_ROOT,
        MAXIMUM_LOCAL_RECORD_SEALED_PLAINTEXT_BYTES_PER_ACTIVE_ROOT,
    },
    hashing::to_hex,
};

use super::{
    MAXIMUM_COMMON_PROOF_BYTE_LENGTH, MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
    MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH,
    external_memory::{
        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_OBJECT_COUNT,
        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH,
    },
    proof_backend_bakeoff::{
        FROZEN_INPUT_IDENTITY_HASH_DOMAIN, FROZEN_INPUT_IDENTITY_SHAKE256_HEX,
        FROZEN_INPUT_RECIPE_IDENTIFIER, ProofBackendBakeoffResult, frozen_fixture,
    },
    proof_backend_bakeoff_fri::{
        PUBLIC_SOURCE_DERIVATION_ALGORITHM_IDENTIFIER, PUBLIC_SOURCE_INPUT_IDENTITY_HASH_DOMAIN,
        PUBLIC_SOURCE_RECIPE_DOMAIN, PUBLIC_SOURCE_SEED_HEX, ProofStorageWidthEvidenceOutput,
        ProofStorageWidthStaticPoint, WIDTH_ACTIVE_COLUMN_LDE_SCRATCH_BYTE_LENGTH,
        WIDTH_BACKEND_PROFILE_IDENTIFIER, WIDTH_CUSTODY_SCHEMA_IDENTIFIER,
        WIDTH_MAXIMUM_NATIVE_CUSTODY_PATH_BYTE_LENGTH, WIDTH_RELEASE_PROFILE_IDENTIFIER,
        WIDTH_REPRESENTATIVE_BROWSER_COLUMN_COUNT, derive_public_source_input_identity,
        execute_proof_storage_width_evidence, proof_storage_width_static_point,
        validate_native_custody_path_byte_length, width_maximum_copied_buffer_byte_length,
    },
};

const WIDTH_ENVIRONMENT_VARIABLE: &str = "SEALED_LATTICE_PROOF_STORAGE_WIDTH";
const RESULT_PATH_ENVIRONMENT_VARIABLE: &str = "SEALED_LATTICE_PROOF_STORAGE_WIDTH_RESULT_PATH";
const CUSTODY_DIRECTORY_PATH_ENVIRONMENT_VARIABLE: &str =
    "SEALED_LATTICE_PROOF_STORAGE_WIDTH_CUSTODY_DIRECTORY_PATH";
const STATIC_PREFLIGHT_RESULT_PATH_ENVIRONMENT_VARIABLE: &str =
    "SEALED_LATTICE_PROOF_STORAGE_WIDTH_STATIC_PREFLIGHT_RESULT_PATH";
const MANIFEST_IDENTITY_ENVIRONMENT_VARIABLE: &str =
    "SEALED_LATTICE_PROOF_STORAGE_WIDTH_MANIFEST_IDENTITY_SHAKE256_HEX";
const ABSOLUTE_CAP_TABLE_IDENTIFIER: &str = "sealed-lattice/absolute-resource-caps/v1";
const NATIVE_MEASUREMENT_RUNTIME: &str = "native-rust";
const INTENDED_RELEASE_RUNTIME: &str = "desktop-browser-wasm";
const SCHEDULED_WIDTHS: [usize; 7] = [8, 32, 128, 512, 1_024, 2_048, 3_451];

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExactCandidate {
    roster_size: u64,
    ring_dimension: u64,
    plaintext_modulus: u64,
    first_data_modulus: u64,
    material_radix: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProofStorageWidthRecord {
    format_version: u8,
    measurement_runtime: &'static str,
    intended_release_runtime: &'static str,
    backend: &'static str,
    backend_profile_identifier: &'static str,
    public_column_derivation_algorithm: &'static str,
    public_column_seed_hex: &'static str,
    public_column_input_domain: &'static str,
    frozen_input_recipe_identifier: &'static str,
    frozen_input_identity_hash_domain: &'static str,
    frozen_input_identity_shake256_hex: &'static str,
    width_input_identity_hash_domain: &'static str,
    custody_schema_identifier: &'static str,
    custody_schema_version: u8,
    maximum_native_custody_path_byte_length: usize,
    release_profile_identifier: &'static str,
    representative_browser_width: usize,
    absolute_cap_table_identifier: &'static str,
    manifest_identity_shake256_hex: String,
    width: usize,
    public_base_leaf_column_count: usize,
    algebraic_base_column_count: usize,
    source_opening_claim_count: usize,
    batching_function_count: usize,
    trace_row_count: usize,
    evaluation_domain_size: usize,
    custody_model: &'static str,
    exact_candidate: ExactCandidate,
    operation_started_at_unix_milliseconds: u64,
    operation_finished_at_unix_milliseconds: u64,
    elapsed_nanoseconds_decimal: String,
    source_replay_byte_length_decimal: String,
    public_base_leaf_byte_length_decimal: String,
    opened_leaf_element_byte_length_decimal: String,
    queried_leaf_payload_byte_length_decimal: String,
    width_dependent_queried_base_opening_byte_length_decimal: String,
    opened_leaf_range_chunk_count_decimal: String,
    canonical_artifact_preleaf_range_chunk_count_decimal: String,
    canonical_artifact_postleaf_range_chunk_count_decimal: String,
    canonical_artifact_nonleaf_range_chunk_count_decimal: String,
    canonical_artifact_byte_length_decimal: String,
    recomputed_canonical_artifact_byte_length_decimal: String,
    proof_byte_length_decimal: String,
    persisted_lde_byte_length_decimal: String,
    persisted_base_leaf_byte_length_decimal: String,
    base_leaf_object_read_byte_length_decimal: String,
    base_leaf_object_written_byte_length_decimal: String,
    active_column_lde_scratch_byte_length_decimal: String,
    physical_object_peak_decimal: String,
    stored_scratch_peak_byte_length_decimal: String,
    maximum_transaction_payload_byte_length_decimal: String,
    lde_transform_count_decimal: String,
    absorbed_leaf_value_count_decimal: String,
    opened_value_count_decimal: String,
    external_read_byte_length_decimal: String,
    external_written_byte_length_decimal: String,
    external_committed_transaction_count_decimal: String,
    source_committed_transaction_count_decimal: String,
    source_physical_object_count_decimal: String,
    proof_physical_object_count_decimal: String,
    source_object_seal_transaction_count_decimal: String,
    proof_object_seal_transaction_count_decimal: String,
    local_record_seal_invocation_count_decimal: String,
    sealed_secret_plaintext_byte_length_decimal: String,
    custody_cleanup_completed: bool,
    input_identity_shake256_hex: String,
    base_root_shake256_hex: String,
    artifact_shake256_hex: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProofStorageWidthAbsoluteCaps {
    maximum_common_proof_byte_length_decimal: String,
    maximum_copied_buffer_byte_length_decimal: String,
    maximum_local_record_seal_invocation_count_decimal: String,
    maximum_local_record_sealed_plaintext_byte_length_decimal: String,
    maximum_physical_object_count_decimal: String,
    maximum_stored_scratch_byte_length_decimal: String,
    maximum_transport_byte_length_decimal: String,
    maximum_wasm_memory_byte_length_decimal: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProofStorageWidthStaticPreflightPoint {
    public_base_leaf_column_count: usize,
    input_identity_shake256_hex: String,
    source_replay_byte_length_decimal: String,
    public_base_leaf_byte_length_decimal: String,
    opened_leaf_element_byte_length_decimal: String,
    legacy_base_leaf_object_byte_length_decimal: String,
    queried_leaf_payload_byte_length_decimal: String,
    width_dependent_queried_base_opening_byte_length_decimal: String,
    opened_leaf_range_chunk_count_decimal: String,
    source_physical_object_count_decimal: String,
    proof_physical_object_count_decimal: String,
    physical_object_peak_decimal: String,
    source_committed_transaction_count_decimal: String,
    source_object_seal_transaction_count_decimal: String,
    proof_object_seal_transaction_count_decimal: String,
    local_record_seal_invocation_count_decimal: String,
    sealed_secret_plaintext_byte_length_decimal: String,
    active_column_lde_scratch_byte_length_decimal: String,
    persisted_lde_byte_length_decimal: String,
    base_leaf_object_read_byte_length_decimal: String,
    base_leaf_object_written_byte_length_decimal: String,
    lde_transform_count_decimal: String,
    absorbed_leaf_value_count_decimal: String,
    opened_value_count_decimal: String,
    maximum_transaction_payload_byte_length_decimal: String,
    canonical_proof_byte_length_ceiling_decimal: String,
    canonical_artifact_nonleaf_range_chunk_count_ceiling_decimal: String,
    transport_byte_length_ceiling_decimal: String,
    external_read_byte_length_ceiling_decimal: String,
    external_written_byte_length_ceiling_decimal: String,
    external_io_byte_length_ceiling_decimal: String,
    committed_transaction_count_ceiling_decimal: String,
    stored_scratch_peak_byte_length_ceiling_decimal: String,
    copied_buffer_byte_length_ceiling_decimal: String,
    digest_state_byte_length_ceiling_decimal: String,
    digest_state_container_byte_length_ceiling_decimal: String,
    frozen_fixture_and_container_byte_length_ceiling_decimal: String,
    retained_algebraic_coefficient_byte_length_ceiling_decimal: String,
    extension_domain_working_byte_length_ceiling_decimal: String,
    canonical_artifact_live_copy_byte_length_ceiling_decimal: String,
    canonical_artifact_container_byte_length_ceiling_decimal: String,
    opening_artifact_and_transcript_byte_length_ceiling_decimal: String,
    prover_public_opening_workspace_byte_length_ceiling_decimal: String,
    fresh_verifier_public_opening_workspace_byte_length_ceiling_decimal: String,
    fresh_verifier_outer_vector_container_byte_length_ceiling_decimal: String,
    boundary_transfer_byte_length_ceiling_decimal: String,
    raw_abi_request_copy_workspace_byte_length_ceiling_decimal: String,
    raw_abi_response_decode_workspace_byte_length_ceiling_decimal: String,
    raw_abi_transfer_workspace_byte_length_ceiling_decimal: String,
    browser_operation_registry_byte_length_ceiling_decimal: String,
    native_custody_metadata_byte_length_ceiling_decimal: String,
    wasm_memory_byte_length_ceiling_decimal: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProofStorageWidthStaticPreflightRecord {
    format_version: u8,
    measurement_runtime: &'static str,
    intended_release_runtime: &'static str,
    backend: &'static str,
    backend_profile_identifier: &'static str,
    public_column_derivation_algorithm: &'static str,
    public_column_seed_hex: &'static str,
    public_column_input_domain: &'static str,
    frozen_input_recipe_identifier: &'static str,
    frozen_input_identity_hash_domain: &'static str,
    frozen_input_identity_shake256_hex: &'static str,
    width_input_identity_hash_domain: &'static str,
    custody_schema_identifier: &'static str,
    custody_schema_version: u8,
    maximum_native_custody_path_byte_length: usize,
    release_profile_identifier: &'static str,
    representative_browser_width: usize,
    absolute_cap_table_identifier: &'static str,
    trace_row_count: usize,
    evaluation_domain_size: usize,
    exact_candidate: ExactCandidate,
    algebraic_base_column_count: usize,
    source_opening_claim_count: usize,
    batching_function_count: usize,
    widths: [usize; 7],
    absolute_caps: ProofStorageWidthAbsoluteCaps,
    points: Vec<ProofStorageWidthStaticPreflightPoint>,
}

fn required_environment_variable(name: &str) -> ProofBackendBakeoffResult<String> {
    let value =
        env::var(name).map_err(|_| format!("missing required environment variable {name}"))?;
    if value.is_empty() {
        return Err(format!("environment variable {name} must not be empty"));
    }
    Ok(value)
}

fn selected_width() -> ProofBackendBakeoffResult<usize> {
    let canonical = required_environment_variable(WIDTH_ENVIRONMENT_VARIABLE)?;
    if canonical.starts_with('0') || !canonical.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!(
            "{WIDTH_ENVIRONMENT_VARIABLE} must be a canonical scheduled decimal width"
        ));
    }
    let width = canonical
        .parse::<usize>()
        .map_err(|error| format!("parse {WIDTH_ENVIRONMENT_VARIABLE}: {error}"))?;
    if !SCHEDULED_WIDTHS.contains(&width) {
        return Err(format!(
            "{WIDTH_ENVIRONMENT_VARIABLE} must be one of {SCHEDULED_WIDTHS:?}"
        ));
    }
    Ok(width)
}

fn manifest_identity_shake256_hex() -> ProofBackendBakeoffResult<String> {
    let identity = required_environment_variable(MANIFEST_IDENTITY_ENVIRONMENT_VARIABLE)?;
    if identity.len() != 128
        || !identity
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "{MANIFEST_IDENTITY_ENVIRONMENT_VARIABLE} must be canonical lowercase 64-byte hexadecimal"
        ));
    }
    Ok(identity)
}

fn new_absolute_result_path(
    environment_variable: &str,
    description: &str,
) -> ProofBackendBakeoffResult<PathBuf> {
    let path = PathBuf::from(required_environment_variable(environment_variable)?);
    if !path.is_absolute() {
        return Err(format!("{environment_variable} must be an absolute path"));
    }
    let parent = path
        .parent()
        .ok_or_else(|| format!("{description} result path must have a parent"))?;
    if !parent.is_dir() || path.exists() {
        return Err(format!(
            "{description} result parent must exist and result must be new"
        ));
    }
    Ok(path)
}

fn result_path() -> ProofBackendBakeoffResult<PathBuf> {
    new_absolute_result_path(RESULT_PATH_ENVIRONMENT_VARIABLE, "width-evidence")
}

fn static_preflight_result_path() -> ProofBackendBakeoffResult<PathBuf> {
    new_absolute_result_path(
        STATIC_PREFLIGHT_RESULT_PATH_ENVIRONMENT_VARIABLE,
        "width-evidence static preflight",
    )
}

pub(super) fn validate_custody_directory_path(
    result_path: &Path,
    custody_directory_path: PathBuf,
) -> ProofBackendBakeoffResult<PathBuf> {
    validate_native_custody_path_byte_length(
        &custody_directory_path,
        CUSTODY_DIRECTORY_PATH_ENVIRONMENT_VARIABLE,
    )?;
    if !custody_directory_path.is_absolute() {
        return Err(format!(
            "{CUSTODY_DIRECTORY_PATH_ENVIRONMENT_VARIABLE} must be an absolute path"
        ));
    }
    let result_parent = result_path
        .parent()
        .ok_or_else(|| "width-evidence result path must have a parent".to_owned())?;
    if custody_directory_path.parent() != Some(result_parent) {
        return Err(format!(
            "{CUSTODY_DIRECTORY_PATH_ENVIRONMENT_VARIABLE} must be a direct child of the result parent"
        ));
    }
    if custody_directory_path.exists() {
        return Err(format!(
            "{CUSTODY_DIRECTORY_PATH_ENVIRONMENT_VARIABLE} must not already exist"
        ));
    }
    Ok(custody_directory_path.into_boxed_path().into_path_buf())
}

fn custody_directory_path(result_path: &Path) -> ProofBackendBakeoffResult<PathBuf> {
    validate_custody_directory_path(
        result_path,
        PathBuf::from(required_environment_variable(
            CUSTODY_DIRECTORY_PATH_ENVIRONMENT_VARIABLE,
        )?),
    )
}

fn unix_milliseconds() -> ProofBackendBakeoffResult<u64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock precedes the Unix epoch".to_owned())?;
    u64::try_from(duration.as_millis())
        .map_err(|_| "Unix timestamp milliseconds do not fit u64".to_owned())
}

fn atomic_write_json<T: Serialize>(path: &Path, value: &T) -> ProofBackendBakeoffResult<()> {
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| "width-evidence result filename must be Unicode".to_owned())?;
    let temporary_path = path.with_file_name(format!(".{file_name}.{}.tmp", std::process::id()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary_path)
            .map_err(|error| format!("create width-evidence temporary result: {error}"))?;
        serde_json::to_writer_pretty(&mut file, value)
            .map_err(|error| format!("encode width-evidence result: {error}"))?;
        file.write_all(b"\n")
            .map_err(|error| format!("finish width-evidence result: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("sync width-evidence result: {error}"))?;
        fs::rename(&temporary_path, path)
            .map_err(|error| format!("publish width-evidence result: {error}"))?;
        Ok(())
    })();
    if result.is_err() && temporary_path.exists() {
        let _ = fs::remove_file(&temporary_path);
    }
    result
}

fn static_preflight_point(
    scheduled_width: usize,
    input_identity_shake256_hex: String,
) -> ProofBackendBakeoffResult<ProofStorageWidthStaticPreflightPoint> {
    let point = proof_storage_width_static_point(scheduled_width)?;
    let ProofStorageWidthStaticPoint {
        width,
        source_replay_byte_length,
        public_base_leaf_byte_length,
        opened_leaf_element_byte_length,
        legacy_base_leaf_object_byte_length,
        queried_leaf_payload_byte_length,
        base_opening_column_payload_byte_length,
        opened_leaf_range_chunk_count,
        source_physical_object_count,
        proof_physical_object_count,
        physical_object_peak,
        source_committed_transaction_count,
        source_object_seal_transaction_count,
        proof_object_seal_transaction_count,
        local_record_seal_invocation_count,
        sealed_secret_plaintext_byte_length,
        active_column_lde_scratch_byte_length,
        lde_transform_count,
        absorbed_leaf_value_count,
        opened_value_count,
        canonical_proof_byte_length_ceiling,
        canonical_artifact_nonleaf_range_chunk_count_ceiling,
        transport_byte_length_ceiling,
        external_read_byte_length_ceiling,
        external_written_byte_length_ceiling,
        external_io_byte_length_ceiling,
        committed_transaction_count_ceiling,
        stored_scratch_peak_byte_length_ceiling,
        copied_buffer_byte_length_ceiling,
        digest_state_byte_length_ceiling,
        digest_state_container_byte_length_ceiling,
        frozen_fixture_and_container_byte_length_ceiling,
        retained_algebraic_coefficient_byte_length_ceiling,
        extension_domain_working_byte_length_ceiling,
        canonical_artifact_live_copy_byte_length_ceiling,
        canonical_artifact_container_byte_length_ceiling,
        opening_artifact_and_transcript_byte_length_ceiling,
        prover_public_opening_workspace_byte_length_ceiling,
        fresh_verifier_public_opening_workspace_byte_length_ceiling,
        fresh_verifier_outer_vector_container_byte_length_ceiling,
        boundary_transfer_byte_length_ceiling,
        raw_abi_request_copy_workspace_byte_length_ceiling,
        raw_abi_response_decode_workspace_byte_length_ceiling,
        raw_abi_transfer_workspace_byte_length_ceiling,
        browser_operation_registry_byte_length_ceiling,
        native_custody_metadata_byte_length_ceiling,
        wasm_memory_byte_length_ceiling,
    } = point;
    if width
        != u64::try_from(scheduled_width)
            .map_err(|_| "scheduled width does not fit u64".to_owned())?
    {
        return Err("static preflight reordered a scheduled width".to_owned());
    }
    Ok(ProofStorageWidthStaticPreflightPoint {
        public_base_leaf_column_count: scheduled_width,
        input_identity_shake256_hex,
        source_replay_byte_length_decimal: source_replay_byte_length.to_string(),
        public_base_leaf_byte_length_decimal: public_base_leaf_byte_length.to_string(),
        opened_leaf_element_byte_length_decimal: opened_leaf_element_byte_length.to_string(),
        legacy_base_leaf_object_byte_length_decimal: legacy_base_leaf_object_byte_length
            .to_string(),
        queried_leaf_payload_byte_length_decimal: queried_leaf_payload_byte_length.to_string(),
        width_dependent_queried_base_opening_byte_length_decimal:
            base_opening_column_payload_byte_length.to_string(),
        opened_leaf_range_chunk_count_decimal: opened_leaf_range_chunk_count.to_string(),
        source_physical_object_count_decimal: source_physical_object_count.to_string(),
        proof_physical_object_count_decimal: proof_physical_object_count.to_string(),
        physical_object_peak_decimal: physical_object_peak.to_string(),
        source_committed_transaction_count_decimal: source_committed_transaction_count.to_string(),
        source_object_seal_transaction_count_decimal: source_object_seal_transaction_count
            .to_string(),
        proof_object_seal_transaction_count_decimal: proof_object_seal_transaction_count
            .to_string(),
        local_record_seal_invocation_count_decimal: local_record_seal_invocation_count.to_string(),
        sealed_secret_plaintext_byte_length_decimal: sealed_secret_plaintext_byte_length
            .to_string(),
        active_column_lde_scratch_byte_length_decimal: active_column_lde_scratch_byte_length
            .to_string(),
        persisted_lde_byte_length_decimal: "0".to_owned(),
        base_leaf_object_read_byte_length_decimal: "0".to_owned(),
        base_leaf_object_written_byte_length_decimal: "0".to_owned(),
        lde_transform_count_decimal: lde_transform_count.to_string(),
        absorbed_leaf_value_count_decimal: absorbed_leaf_value_count.to_string(),
        opened_value_count_decimal: opened_value_count.to_string(),
        maximum_transaction_payload_byte_length_decimal:
            MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH.to_string(),
        canonical_proof_byte_length_ceiling_decimal: canonical_proof_byte_length_ceiling
            .to_string(),
        canonical_artifact_nonleaf_range_chunk_count_ceiling_decimal:
            canonical_artifact_nonleaf_range_chunk_count_ceiling.to_string(),
        transport_byte_length_ceiling_decimal: transport_byte_length_ceiling.to_string(),
        external_read_byte_length_ceiling_decimal: external_read_byte_length_ceiling.to_string(),
        external_written_byte_length_ceiling_decimal: external_written_byte_length_ceiling
            .to_string(),
        external_io_byte_length_ceiling_decimal: external_io_byte_length_ceiling.to_string(),
        committed_transaction_count_ceiling_decimal: committed_transaction_count_ceiling
            .to_string(),
        stored_scratch_peak_byte_length_ceiling_decimal: stored_scratch_peak_byte_length_ceiling
            .to_string(),
        copied_buffer_byte_length_ceiling_decimal: copied_buffer_byte_length_ceiling.to_string(),
        digest_state_byte_length_ceiling_decimal: digest_state_byte_length_ceiling.to_string(),
        digest_state_container_byte_length_ceiling_decimal:
            digest_state_container_byte_length_ceiling.to_string(),
        frozen_fixture_and_container_byte_length_ceiling_decimal:
            frozen_fixture_and_container_byte_length_ceiling.to_string(),
        retained_algebraic_coefficient_byte_length_ceiling_decimal:
            retained_algebraic_coefficient_byte_length_ceiling.to_string(),
        extension_domain_working_byte_length_ceiling_decimal:
            extension_domain_working_byte_length_ceiling.to_string(),
        canonical_artifact_live_copy_byte_length_ceiling_decimal:
            canonical_artifact_live_copy_byte_length_ceiling.to_string(),
        canonical_artifact_container_byte_length_ceiling_decimal:
            canonical_artifact_container_byte_length_ceiling.to_string(),
        opening_artifact_and_transcript_byte_length_ceiling_decimal:
            opening_artifact_and_transcript_byte_length_ceiling.to_string(),
        prover_public_opening_workspace_byte_length_ceiling_decimal:
            prover_public_opening_workspace_byte_length_ceiling.to_string(),
        fresh_verifier_public_opening_workspace_byte_length_ceiling_decimal:
            fresh_verifier_public_opening_workspace_byte_length_ceiling.to_string(),
        fresh_verifier_outer_vector_container_byte_length_ceiling_decimal:
            fresh_verifier_outer_vector_container_byte_length_ceiling.to_string(),
        boundary_transfer_byte_length_ceiling_decimal: boundary_transfer_byte_length_ceiling
            .to_string(),
        raw_abi_request_copy_workspace_byte_length_ceiling_decimal:
            raw_abi_request_copy_workspace_byte_length_ceiling.to_string(),
        raw_abi_response_decode_workspace_byte_length_ceiling_decimal:
            raw_abi_response_decode_workspace_byte_length_ceiling.to_string(),
        raw_abi_transfer_workspace_byte_length_ceiling_decimal:
            raw_abi_transfer_workspace_byte_length_ceiling.to_string(),
        browser_operation_registry_byte_length_ceiling_decimal:
            browser_operation_registry_byte_length_ceiling.to_string(),
        native_custody_metadata_byte_length_ceiling_decimal:
            native_custody_metadata_byte_length_ceiling.to_string(),
        wasm_memory_byte_length_ceiling_decimal: wasm_memory_byte_length_ceiling.to_string(),
    })
}

fn execute_static_preflight() -> ProofBackendBakeoffResult<()> {
    if !SCHEDULED_WIDTHS.contains(&WIDTH_REPRESENTATIVE_BROWSER_COLUMN_COUNT) {
        return Err("representative browser width is outside the scheduled curve".to_owned());
    }
    let result_path = static_preflight_result_path()?;
    let fixture = frozen_fixture()?;
    if fixture.input_identity_shake256_hex != FROZEN_INPUT_IDENTITY_SHAKE256_HEX {
        return Err("static preflight frozen input identity changed".to_owned());
    }
    let mut points = Vec::new();
    points
        .try_reserve_exact(SCHEDULED_WIDTHS.len())
        .map_err(|_| "static preflight point allocation failed".to_owned())?;
    for width in SCHEDULED_WIDTHS {
        let input_identity_shake256_hex = derive_public_source_input_identity(&fixture, width)?;
        points.push(static_preflight_point(width, input_identity_shake256_hex)?);
    }
    let record = ProofStorageWidthStaticPreflightRecord {
        format_version: 1,
        measurement_runtime: NATIVE_MEASUREMENT_RUNTIME,
        intended_release_runtime: INTENDED_RELEASE_RUNTIME,
        backend: "packed-deep-fri",
        backend_profile_identifier: WIDTH_BACKEND_PROFILE_IDENTIFIER,
        public_column_derivation_algorithm: PUBLIC_SOURCE_DERIVATION_ALGORITHM_IDENTIFIER,
        public_column_seed_hex: PUBLIC_SOURCE_SEED_HEX,
        public_column_input_domain: PUBLIC_SOURCE_RECIPE_DOMAIN,
        frozen_input_recipe_identifier: FROZEN_INPUT_RECIPE_IDENTIFIER,
        frozen_input_identity_hash_domain: FROZEN_INPUT_IDENTITY_HASH_DOMAIN,
        frozen_input_identity_shake256_hex: FROZEN_INPUT_IDENTITY_SHAKE256_HEX,
        width_input_identity_hash_domain: PUBLIC_SOURCE_INPUT_IDENTITY_HASH_DOMAIN,
        custody_schema_identifier: WIDTH_CUSTODY_SCHEMA_IDENTIFIER,
        custody_schema_version: 1,
        maximum_native_custody_path_byte_length: WIDTH_MAXIMUM_NATIVE_CUSTODY_PATH_BYTE_LENGTH,
        release_profile_identifier: WIDTH_RELEASE_PROFILE_IDENTIFIER,
        representative_browser_width: WIDTH_REPRESENTATIVE_BROWSER_COLUMN_COUNT,
        absolute_cap_table_identifier: ABSOLUTE_CAP_TABLE_IDENTIFIER,
        trace_row_count: 16_384,
        evaluation_domain_size: 131_072,
        exact_candidate: ExactCandidate {
            roster_size: 10,
            ring_dimension: 32_768,
            plaintext_modulus: 257,
            first_data_modulus: 1_953_759_233,
            material_radix: 129_140_163,
        },
        algebraic_base_column_count: 8,
        source_opening_claim_count: 9,
        batching_function_count: 18,
        widths: SCHEDULED_WIDTHS,
        absolute_caps: ProofStorageWidthAbsoluteCaps {
            maximum_common_proof_byte_length_decimal: MAXIMUM_COMMON_PROOF_BYTE_LENGTH.to_string(),
            maximum_copied_buffer_byte_length_decimal: width_maximum_copied_buffer_byte_length()?
                .to_string(),
            maximum_local_record_seal_invocation_count_decimal:
                MAXIMUM_LOCAL_RECORD_SEAL_INVOCATIONS_PER_ACTIVE_ROOT.to_string(),
            maximum_local_record_sealed_plaintext_byte_length_decimal:
                MAXIMUM_LOCAL_RECORD_SEALED_PLAINTEXT_BYTES_PER_ACTIVE_ROOT.to_string(),
            maximum_physical_object_count_decimal:
                MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_OBJECT_COUNT.to_string(),
            maximum_stored_scratch_byte_length_decimal:
                MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH.to_string(),
            maximum_transport_byte_length_decimal: MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH.to_string(),
            maximum_wasm_memory_byte_length_decimal: MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
                .to_string(),
        },
        points,
    };
    atomic_write_json(&result_path, &record)
}

fn execute_width_record() -> ProofBackendBakeoffResult<()> {
    let width = selected_width()?;
    let manifest_identity_shake256_hex = manifest_identity_shake256_hex()?;
    let result_path = result_path()?;
    let custody_directory_path = custody_directory_path(&result_path)?;
    let fixture = frozen_fixture()?;

    // The external process guard requires one strict pre-operation sample.
    thread::sleep(Duration::from_millis(250));
    let operation_started_at_unix_milliseconds = unix_milliseconds()?;
    let started = Instant::now();
    let output = execute_proof_storage_width_evidence(&fixture, width, custody_directory_path)?;
    let elapsed = started.elapsed();
    let operation_finished_at_unix_milliseconds = unix_milliseconds()?;
    let elapsed_nanoseconds = u64::try_from(elapsed.as_nanos())
        .map_err(|_| "width-evidence elapsed nanoseconds do not fit u64".to_owned())?;
    let ProofStorageWidthEvidenceOutput {
        public_base_leaf_column_count,
        input_identity_shake256_hex,
        base_root,
        canonical_artifact_byte_length,
        recomputed_canonical_artifact_byte_length,
        artifact_shake256_hex,
        source_replay_byte_length,
        public_base_leaf_byte_length,
        opened_leaf_element_byte_length,
        queried_leaf_payload_byte_length,
        opened_leaf_range_chunk_count,
        canonical_artifact_preleaf_range_chunk_count,
        canonical_artifact_postleaf_range_chunk_count,
        canonical_artifact_nonleaf_range_chunk_count,
        physical_object_peak,
        stored_scratch_peak_byte_length,
        lde_transform_count,
        absorbed_leaf_value_count,
        opened_value_count,
        external_read_byte_length,
        external_written_byte_length,
        external_committed_transaction_count,
        source_committed_transaction_count,
        source_object_seal_transaction_count,
        proof_object_seal_transaction_count,
        local_record_seal_invocation_count,
        sealed_secret_plaintext_byte_length,
        custody_cleanup_completed,
    } = output;
    let record = ProofStorageWidthRecord {
        format_version: 1,
        measurement_runtime: NATIVE_MEASUREMENT_RUNTIME,
        intended_release_runtime: INTENDED_RELEASE_RUNTIME,
        backend: "packed-deep-fri",
        backend_profile_identifier: WIDTH_BACKEND_PROFILE_IDENTIFIER,
        public_column_derivation_algorithm: PUBLIC_SOURCE_DERIVATION_ALGORITHM_IDENTIFIER,
        public_column_seed_hex: PUBLIC_SOURCE_SEED_HEX,
        public_column_input_domain: PUBLIC_SOURCE_RECIPE_DOMAIN,
        frozen_input_recipe_identifier: FROZEN_INPUT_RECIPE_IDENTIFIER,
        frozen_input_identity_hash_domain: FROZEN_INPUT_IDENTITY_HASH_DOMAIN,
        frozen_input_identity_shake256_hex: FROZEN_INPUT_IDENTITY_SHAKE256_HEX,
        width_input_identity_hash_domain: PUBLIC_SOURCE_INPUT_IDENTITY_HASH_DOMAIN,
        custody_schema_identifier: WIDTH_CUSTODY_SCHEMA_IDENTIFIER,
        custody_schema_version: 1,
        maximum_native_custody_path_byte_length: WIDTH_MAXIMUM_NATIVE_CUSTODY_PATH_BYTE_LENGTH,
        release_profile_identifier: WIDTH_RELEASE_PROFILE_IDENTIFIER,
        representative_browser_width: WIDTH_REPRESENTATIVE_BROWSER_COLUMN_COUNT,
        absolute_cap_table_identifier: ABSOLUTE_CAP_TABLE_IDENTIFIER,
        manifest_identity_shake256_hex,
        width,
        public_base_leaf_column_count,
        algebraic_base_column_count: 8,
        source_opening_claim_count: 9,
        batching_function_count: 18,
        trace_row_count: 16_384,
        evaluation_domain_size: 131_072,
        custody_model: "bounded-external-storage-replay",
        exact_candidate: ExactCandidate {
            roster_size: 10,
            ring_dimension: 32_768,
            plaintext_modulus: 257,
            first_data_modulus: 1_953_759_233,
            material_radix: 129_140_163,
        },
        operation_started_at_unix_milliseconds,
        operation_finished_at_unix_milliseconds,
        elapsed_nanoseconds_decimal: elapsed_nanoseconds.to_string(),
        source_replay_byte_length_decimal: source_replay_byte_length.to_string(),
        public_base_leaf_byte_length_decimal: public_base_leaf_byte_length.to_string(),
        opened_leaf_element_byte_length_decimal: opened_leaf_element_byte_length.to_string(),
        queried_leaf_payload_byte_length_decimal: queried_leaf_payload_byte_length.to_string(),
        width_dependent_queried_base_opening_byte_length_decimal: 2_928_u64
            .checked_mul(
                u64::try_from(width)
                    .map_err(|_| "public base width does not fit u64".to_owned())?,
            )
            .ok_or_else(|| "queried base-opening byte length overflowed".to_owned())?
            .to_string(),
        opened_leaf_range_chunk_count_decimal: opened_leaf_range_chunk_count.to_string(),
        canonical_artifact_preleaf_range_chunk_count_decimal:
            canonical_artifact_preleaf_range_chunk_count.to_string(),
        canonical_artifact_postleaf_range_chunk_count_decimal:
            canonical_artifact_postleaf_range_chunk_count.to_string(),
        canonical_artifact_nonleaf_range_chunk_count_decimal:
            canonical_artifact_nonleaf_range_chunk_count.to_string(),
        canonical_artifact_byte_length_decimal: canonical_artifact_byte_length.to_string(),
        recomputed_canonical_artifact_byte_length_decimal:
            recomputed_canonical_artifact_byte_length.to_string(),
        proof_byte_length_decimal: canonical_artifact_byte_length.to_string(),
        persisted_lde_byte_length_decimal: "0".to_owned(),
        persisted_base_leaf_byte_length_decimal: "0".to_owned(),
        base_leaf_object_read_byte_length_decimal: "0".to_owned(),
        base_leaf_object_written_byte_length_decimal: "0".to_owned(),
        active_column_lde_scratch_byte_length_decimal: WIDTH_ACTIVE_COLUMN_LDE_SCRATCH_BYTE_LENGTH
            .to_string(),
        physical_object_peak_decimal: physical_object_peak.to_string(),
        stored_scratch_peak_byte_length_decimal: stored_scratch_peak_byte_length.to_string(),
        maximum_transaction_payload_byte_length_decimal:
            MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH.to_string(),
        lde_transform_count_decimal: lde_transform_count.to_string(),
        absorbed_leaf_value_count_decimal: absorbed_leaf_value_count.to_string(),
        opened_value_count_decimal: opened_value_count.to_string(),
        external_read_byte_length_decimal: external_read_byte_length.to_string(),
        external_written_byte_length_decimal: external_written_byte_length.to_string(),
        external_committed_transaction_count_decimal: external_committed_transaction_count
            .to_string(),
        source_committed_transaction_count_decimal: source_committed_transaction_count.to_string(),
        source_physical_object_count_decimal: width.to_string(),
        proof_physical_object_count_decimal: "1".to_owned(),
        source_object_seal_transaction_count_decimal: source_object_seal_transaction_count
            .to_string(),
        proof_object_seal_transaction_count_decimal: proof_object_seal_transaction_count
            .to_string(),
        local_record_seal_invocation_count_decimal: local_record_seal_invocation_count.to_string(),
        sealed_secret_plaintext_byte_length_decimal: sealed_secret_plaintext_byte_length
            .to_string(),
        custody_cleanup_completed,
        input_identity_shake256_hex,
        base_root_shake256_hex: to_hex(&base_root),
        artifact_shake256_hex,
    };
    atomic_write_json(&result_path, &record)
}

#[cfg(test)]
mod tests {
    #[test]
    fn proof_storage_width_evidence_static_preflight_checks_every_scheduled_width() {
        super::execute_static_preflight().expect("record proof-storage width static preflight");
    }

    #[test]
    #[ignore = "manual guarded packed-DEEP-FRI public-column width evidence"]
    fn proof_storage_width_evidence_records_incumbent_curve() {
        super::execute_width_record().expect("record guarded proof-storage width evidence");
    }
}
