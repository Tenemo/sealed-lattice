//! Frozen synthetic-fragment driver for the manual proof-backend bakeoff.

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
    foundation::{CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple},
    hashing::hash512_hex,
};

use super::{
    proof_backend_bakeoff_fri::{
        derive_frozen_fri_base_root, execute_packed_deep_fri, verify_packed_deep_fri_mutations,
    },
    proof_backend_bakeoff_sumcheck::{
        derive_frozen_sumcheck_commitment, execute_sumcheck_class,
        validate_canonical_sumcheck_commitment, verify_sumcheck_class_mutations,
    },
};

const BACKEND_ENVIRONMENT_VARIABLE: &str = "SEALED_LATTICE_PROOF_BACKEND_BAKEOFF_BACKEND";
const SAMPLE_ORDINAL_ENVIRONMENT_VARIABLE: &str =
    "SEALED_LATTICE_PROOF_BACKEND_BAKEOFF_SAMPLE_ORDINAL";
const RESULT_PATH_ENVIRONMENT_VARIABLE: &str = "SEALED_LATTICE_PROOF_BACKEND_BAKEOFF_RESULT_PATH";

const FROZEN_ROSTER_SIZE: u64 = 10;
const FROZEN_RING_DEGREE: u64 = 32_768;
const FROZEN_PLAINTEXT_MODULUS: u64 = 257;
const FROZEN_RELATION_ROW_COUNT: usize = 16_384;
const FROZEN_RELATION_COLUMN_COUNT: usize = 8;
const FROZEN_CIPHERTEXT_MODULUS: u64 = 1_953_759_233;
const FROZEN_MATERIAL_RADIX: u64 = 129_140_163;
const FROZEN_FRI_STATEMENT_DOMAIN: &str =
    "sealed-lattice/proof-backend-bakeoff/packed-deep-fri-statement/v1";
const FROZEN_SUMCHECK_STATEMENT_DOMAIN: &str =
    "sealed-lattice/proof-backend-bakeoff/sumcheck-class-statement/v1";
// Fail-closed placeholders: the ignored exact-binding owner below must regenerate both values,
// after which these constants must be replaced before any bakeoff sample can pass. Keeping the
// derivation out of `frozen_fixture` prevents either backend from warming allocator or commitment
// state before a measured sample starts.
const FROZEN_EXPECTED_FRI_BASE_ROOT: [u8; 64] = [0; 64];
const FROZEN_EXPECTED_SUMCHECK_COMMITMENT: &[u8] = &[0];

pub(super) type ProofBackendBakeoffResult<T> = Result<T, String>;

#[derive(Clone, Debug)]
pub(super) struct ProofBackendBakeoffFixture {
    pub(super) canonical_core_statement: Vec<u8>,
    pub(super) canonical_fri_statement: Vec<u8>,
    pub(super) canonical_sumcheck_statement: Vec<u8>,
    pub(super) columns: [Vec<u64>; FROZEN_RELATION_COLUMN_COUNT],
    pub(super) expected_fri_base_root: [u8; 64],
    pub(super) expected_sumcheck_commitment: Vec<u8>,
    pub(super) input_identity_shake256_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct FrozenFriPublicStatementBindings {
    pub(super) canonical_core_statement: Vec<u8>,
    pub(super) expected_fri_base_root: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct FrozenSumcheckPublicStatementBindings {
    pub(super) canonical_core_statement: Vec<u8>,
    pub(super) expected_sumcheck_commitment: Vec<u8>,
}

#[derive(Clone, Debug)]
struct FrozenRelationFragment {
    canonical_core_statement: Vec<u8>,
    columns: [Vec<u64>; FROZEN_RELATION_COLUMN_COUNT],
    input_identity_shake256_hex: String,
}

#[derive(Clone, Debug)]
pub(super) struct ProofBackendBakeoffArmOutput {
    pub(super) canonical_artifact: Vec<u8>,
    pub(super) proof_shake256_hex: String,
    pub(super) external_read_byte_length: u64,
    pub(super) external_written_byte_length: u64,
    pub(super) external_committed_transaction_count: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum ProofBackendBakeoffBackend {
    PackedDeepFri,
    SumcheckClass,
}

impl ProofBackendBakeoffBackend {
    fn parse(value: &str) -> ProofBackendBakeoffResult<Self> {
        match value {
            "packed-deep-fri" => Ok(Self::PackedDeepFri),
            "sumcheck-class" => Ok(Self::SumcheckClass),
            _ => Err(format!(
                "{BACKEND_ENVIRONMENT_VARIABLE} must be packed-deep-fri or sumcheck-class"
            )),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProofBackendBakeoffSampleRecord {
    format_version: u8,
    backend: ProofBackendBakeoffBackend,
    sample_ordinal: u8,
    frozen_input_identity_shake256_hex: String,
    operation_started_at_unix_milliseconds: u64,
    operation_finished_at_unix_milliseconds: u64,
    elapsed_nanoseconds_decimal: String,
    canonical_proof_byte_length_decimal: String,
    proof_shake256_hex: String,
    external_read_byte_length_decimal: String,
    external_written_byte_length_decimal: String,
    external_committed_transaction_count_decimal: String,
}

pub(super) fn frozen_fixture() -> ProofBackendBakeoffResult<ProofBackendBakeoffFixture> {
    let fragment = frozen_relation_fragment()?;
    let (expected_fri_base_root, expected_sumcheck_commitment) = checked_frozen_backend_bindings()?;
    let canonical_fri_statement = canonical_frozen_fri_public_statement(
        &fragment.input_identity_shake256_hex,
        expected_fri_base_root,
    )?;
    let canonical_sumcheck_statement = canonical_frozen_sumcheck_public_statement(
        &fragment.input_identity_shake256_hex,
        &expected_sumcheck_commitment,
    )?;

    Ok(ProofBackendBakeoffFixture {
        canonical_core_statement: fragment.canonical_core_statement,
        canonical_fri_statement,
        canonical_sumcheck_statement,
        columns: fragment.columns,
        expected_fri_base_root,
        expected_sumcheck_commitment,
        input_identity_shake256_hex: fragment.input_identity_shake256_hex,
    })
}

fn frozen_relation_fragment() -> ProofBackendBakeoffResult<FrozenRelationFragment> {
    let mut columns: [Vec<u64>; FROZEN_RELATION_COLUMN_COUNT] =
        std::array::from_fn(|_| Vec::with_capacity(FROZEN_RELATION_ROW_COUNT));

    for row_index in 0..FROZEN_RELATION_ROW_COUNT {
        append_half_witness(&mut columns, 0, row_index % 3)?;
        append_half_witness(&mut columns, 4, (row_index + 1) % 3)?;
    }

    validate_frozen_columns(&columns)?;
    let input_identity_shake256_hex = recompute_frozen_input_identity(&columns)?;
    let canonical_core_statement = canonical_frozen_core_statement(&input_identity_shake256_hex)?;

    Ok(FrozenRelationFragment {
        canonical_core_statement,
        columns,
        input_identity_shake256_hex,
    })
}

fn checked_frozen_backend_bindings() -> ProofBackendBakeoffResult<([u8; 64], Vec<u8>)> {
    Ok((
        checked_frozen_fri_base_root()?,
        checked_frozen_sumcheck_commitment()?,
    ))
}

fn checked_frozen_fri_base_root() -> ProofBackendBakeoffResult<[u8; 64]> {
    if FROZEN_EXPECTED_FRI_BASE_ROOT == [0; 64] {
        return Err("frozen expected FRI base root is still the zero placeholder".to_owned());
    }
    Ok(FROZEN_EXPECTED_FRI_BASE_ROOT)
}

fn checked_frozen_sumcheck_commitment() -> ProofBackendBakeoffResult<Vec<u8>> {
    if FROZEN_EXPECTED_SUMCHECK_COMMITMENT == [0] {
        return Err(
            "frozen expected sumcheck commitment is still the one-byte placeholder".to_owned(),
        );
    }
    validate_canonical_sumcheck_commitment(FROZEN_EXPECTED_SUMCHECK_COMMITMENT)?;
    Ok(FROZEN_EXPECTED_SUMCHECK_COMMITMENT.to_vec())
}

fn validate_frozen_input_identity(
    input_identity_shake256_hex: &str,
) -> ProofBackendBakeoffResult<()> {
    if input_identity_shake256_hex.len() != 128
        || !input_identity_shake256_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(
            "frozen input identity is not a canonical 512-bit lowercase hex digest".to_owned(),
        );
    }
    Ok(())
}

fn canonical_frozen_core_statement_tuple(
    input_identity_shake256_hex: &str,
) -> ProofBackendBakeoffResult<CanonicalTuple> {
    validate_frozen_input_identity(input_identity_shake256_hex)?;
    Ok(CanonicalTuple::new(
        u16::MAX,
        1,
        vec![
            CanonicalItem::unsigned64(FROZEN_ROSTER_SIZE),
            CanonicalItem::unsigned64(FROZEN_RING_DEGREE),
            CanonicalItem::unsigned64(FROZEN_PLAINTEXT_MODULUS),
            CanonicalItem::unsigned64(
                u64::try_from(FROZEN_RELATION_ROW_COUNT)
                    .map_err(|_| "frozen relation row count does not fit u64".to_owned())?,
            ),
            CanonicalItem::unsigned64(
                u64::try_from(FROZEN_RELATION_COLUMN_COUNT)
                    .map_err(|_| "frozen relation column count does not fit u64".to_owned())?,
            ),
            CanonicalItem::unsigned64(FROZEN_CIPHERTEXT_MODULUS),
            CanonicalItem::unsigned64(FROZEN_MATERIAL_RADIX),
            CanonicalItem::nonempty_ascii(input_identity_shake256_hex)
                .map_err(|error| format!("encode frozen input identity: {error}"))?,
        ],
    ))
}

pub(super) fn canonical_frozen_core_statement(
    input_identity_shake256_hex: &str,
) -> ProofBackendBakeoffResult<Vec<u8>> {
    canonical_frozen_core_statement_tuple(input_identity_shake256_hex)?
        .encode()
        .map_err(|error| format!("encode frozen canonical core statement: {error}"))
}

pub(super) fn canonical_frozen_fri_public_statement(
    input_identity_shake256_hex: &str,
    expected_fri_base_root: [u8; 64],
) -> ProofBackendBakeoffResult<Vec<u8>> {
    let core_statement = canonical_frozen_core_statement_tuple(input_identity_shake256_hex)?;
    CanonicalTuple::new(
        u16::MAX,
        2,
        vec![
            CanonicalItem::nonempty_ascii(FROZEN_FRI_STATEMENT_DOMAIN)
                .map_err(|error| format!("encode frozen FRI statement domain: {error}"))?,
            CanonicalItem::nested_tuple(&core_statement)
                .map_err(|error| format!("encode frozen core statement binding: {error}"))?,
            CanonicalItem::hash512(expected_fri_base_root),
        ],
    )
    .encode()
    .map_err(|error| format!("encode frozen canonical FRI statement: {error}"))
}

pub(super) fn canonical_frozen_sumcheck_public_statement(
    input_identity_shake256_hex: &str,
    expected_sumcheck_commitment: &[u8],
) -> ProofBackendBakeoffResult<Vec<u8>> {
    if expected_sumcheck_commitment.is_empty() {
        return Err("frozen expected sumcheck commitment is empty".to_owned());
    }
    let core_statement = canonical_frozen_core_statement_tuple(input_identity_shake256_hex)?;
    CanonicalTuple::new(
        u16::MAX,
        2,
        vec![
            CanonicalItem::nonempty_ascii(FROZEN_SUMCHECK_STATEMENT_DOMAIN)
                .map_err(|error| format!("encode frozen sumcheck statement domain: {error}"))?,
            CanonicalItem::nested_tuple(&core_statement)
                .map_err(|error| format!("encode frozen core statement binding: {error}"))?,
            CanonicalItem::variable_bytes(expected_sumcheck_commitment)
                .map_err(|error| format!("encode frozen expected sumcheck commitment: {error}"))?,
        ],
    )
    .encode()
    .map_err(|error| format!("encode frozen canonical sumcheck statement: {error}"))
}

pub(super) fn validate_frozen_core_statement(
    canonical_core_statement: &[u8],
    input_identity_shake256_hex: &str,
) -> ProofBackendBakeoffResult<()> {
    let expected_core_statement = canonical_frozen_core_statement(input_identity_shake256_hex)?;
    if canonical_core_statement != expected_core_statement {
        return Err(
            "frozen canonical core statement does not bind the exact input identity".to_owned(),
        );
    }
    let decoded =
        CanonicalTuple::decode(canonical_core_statement, &CanonicalDecodeLimits::default())
            .map_err(|error| format!("decode frozen canonical core statement: {error}"))?;
    if decoded.schema_identifier != u16::MAX || decoded.schema_version != 1 {
        return Err("frozen core statement schema identifier or version changed".to_owned());
    }
    let reencoded = decoded
        .encode()
        .map_err(|error| format!("re-encode frozen canonical core statement: {error}"))?;
    if reencoded != canonical_core_statement {
        return Err("frozen canonical core statement encoding is not canonical".to_owned());
    }
    Ok(())
}

pub(super) fn validated_frozen_fri_public_statement(
    canonical_statement: &[u8],
    input_identity_shake256_hex: &str,
) -> ProofBackendBakeoffResult<FrozenFriPublicStatementBindings> {
    let decoded = CanonicalTuple::decode(canonical_statement, &CanonicalDecodeLimits::default())
        .map_err(|error| format!("decode frozen canonical FRI statement: {error}"))?;
    if decoded.schema_identifier != u16::MAX || decoded.schema_version != 2 {
        return Err("frozen FRI statement schema identifier or version changed".to_owned());
    }
    if decoded.items.len() != 3
        || decoded.items[0].item_type() != CanonicalItemType::Ascii
        || decoded.items[1].item_type() != CanonicalItemType::NestedTuple
        || decoded.items[2].item_type() != CanonicalItemType::Hash512
    {
        return Err("frozen FRI statement binding shape changed".to_owned());
    }
    let statement_domain = decoded.items[0]
        .variable_value_bytes()
        .map_err(|error| format!("decode frozen FRI statement domain: {error}"))?;
    if statement_domain != FROZEN_FRI_STATEMENT_DOMAIN.as_bytes() {
        return Err("frozen FRI statement domain changed".to_owned());
    }
    let canonical_core_statement = decoded.items[1].canonical_bytes().to_vec();
    validate_frozen_core_statement(&canonical_core_statement, input_identity_shake256_hex)?;
    let expected_fri_base_root: [u8; 64] = decoded.items[2]
        .canonical_bytes()
        .try_into()
        .map_err(|_| "frozen expected FRI base root is not 512 bits".to_owned())?;
    let checked_fri_base_root = checked_frozen_fri_base_root()?;
    if expected_fri_base_root != checked_fri_base_root {
        return Err("frozen FRI statement does not carry the checked base root".to_owned());
    }
    let reencoded = decoded
        .encode()
        .map_err(|error| format!("re-encode frozen canonical FRI statement: {error}"))?;
    if reencoded != canonical_statement {
        return Err("frozen canonical FRI statement encoding is not canonical".to_owned());
    }
    let expected_statement =
        canonical_frozen_fri_public_statement(input_identity_shake256_hex, checked_fri_base_root)?;
    if canonical_statement != expected_statement {
        return Err("frozen canonical FRI statement does not bind the exact fragment".to_owned());
    }
    Ok(FrozenFriPublicStatementBindings {
        canonical_core_statement,
        expected_fri_base_root: checked_fri_base_root,
    })
}

pub(super) fn validated_frozen_sumcheck_public_statement(
    canonical_statement: &[u8],
    input_identity_shake256_hex: &str,
) -> ProofBackendBakeoffResult<FrozenSumcheckPublicStatementBindings> {
    let decoded = CanonicalTuple::decode(canonical_statement, &CanonicalDecodeLimits::default())
        .map_err(|error| format!("decode frozen canonical sumcheck statement: {error}"))?;
    if decoded.schema_identifier != u16::MAX || decoded.schema_version != 2 {
        return Err("frozen sumcheck statement schema identifier or version changed".to_owned());
    }
    if decoded.items.len() != 3
        || decoded.items[0].item_type() != CanonicalItemType::Ascii
        || decoded.items[1].item_type() != CanonicalItemType::NestedTuple
        || decoded.items[2].item_type() != CanonicalItemType::RawBytes
    {
        return Err("frozen sumcheck statement binding shape changed".to_owned());
    }
    let statement_domain = decoded.items[0]
        .variable_value_bytes()
        .map_err(|error| format!("decode frozen sumcheck statement domain: {error}"))?;
    if statement_domain != FROZEN_SUMCHECK_STATEMENT_DOMAIN.as_bytes() {
        return Err("frozen sumcheck statement domain changed".to_owned());
    }
    let canonical_core_statement = decoded.items[1].canonical_bytes().to_vec();
    validate_frozen_core_statement(&canonical_core_statement, input_identity_shake256_hex)?;
    let expected_sumcheck_commitment = decoded.items[2]
        .variable_value_bytes()
        .map_err(|error| format!("decode frozen expected sumcheck commitment: {error}"))?
        .to_vec();
    let checked_sumcheck_commitment = checked_frozen_sumcheck_commitment()?;
    if expected_sumcheck_commitment != checked_sumcheck_commitment {
        return Err("frozen sumcheck statement does not carry the checked commitment".to_owned());
    }
    let reencoded = decoded
        .encode()
        .map_err(|error| format!("re-encode frozen canonical sumcheck statement: {error}"))?;
    if reencoded != canonical_statement {
        return Err("frozen canonical sumcheck statement encoding is not canonical".to_owned());
    }
    let expected_statement = canonical_frozen_sumcheck_public_statement(
        input_identity_shake256_hex,
        &checked_sumcheck_commitment,
    )?;
    if canonical_statement != expected_statement {
        return Err(
            "frozen canonical sumcheck statement does not bind the exact fragment".to_owned(),
        );
    }
    Ok(FrozenSumcheckPublicStatementBindings {
        canonical_core_statement,
        expected_sumcheck_commitment: checked_sumcheck_commitment,
    })
}

fn append_half_witness(
    columns: &mut [Vec<u64>; FROZEN_RELATION_COLUMN_COUNT],
    first_column_index: usize,
    cycle_position: usize,
) -> ProofBackendBakeoffResult<()> {
    let (digit_zero, digit_one, shifted_secret, negative_indicator) = match cycle_position {
        0 => (16_656_787, 15, 0, 1),
        1 => (0, 0, 1, 0),
        2 => (1, 0, 2, 0),
        _ => return Err("synthetic secret cycle position must be in 0..3".to_owned()),
    };
    let destination = columns
        .get_mut(first_column_index..first_column_index + 4)
        .ok_or_else(|| "synthetic half-column range is invalid".to_owned())?;
    destination[0].push(digit_zero);
    destination[1].push(digit_one);
    destination[2].push(shifted_secret);
    destination[3].push(negative_indicator);
    Ok(())
}

fn validate_frozen_columns(
    columns: &[Vec<u64>; FROZEN_RELATION_COLUMN_COUNT],
) -> ProofBackendBakeoffResult<()> {
    if columns
        .iter()
        .any(|column| column.len() != FROZEN_RELATION_ROW_COUNT)
    {
        return Err("every frozen relation column must contain exactly 16,384 rows".to_owned());
    }
    for row_index in 0..FROZEN_RELATION_ROW_COUNT {
        validate_half_witness(columns, row_index, 0)?;
        validate_half_witness(columns, row_index, 4)?;
    }
    Ok(())
}

fn validate_half_witness(
    columns: &[Vec<u64>; FROZEN_RELATION_COLUMN_COUNT],
    row_index: usize,
    first_column_index: usize,
) -> ProofBackendBakeoffResult<()> {
    let digit_zero = columns[first_column_index][row_index];
    let digit_one = columns[first_column_index + 1][row_index];
    let shifted_secret = columns[first_column_index + 2][row_index];
    let negative_indicator = columns[first_column_index + 3][row_index];
    if digit_zero >= FROZEN_MATERIAL_RADIX
        || digit_one > 15
        || shifted_secret > 2
        || negative_indicator > 1
    {
        return Err(format!(
            "synthetic witness range check failed at row {row_index}, half {}",
            first_column_index / 4
        ));
    }
    let positive =
        u128::from(digit_zero) + u128::from(FROZEN_MATERIAL_RADIX) * u128::from(digit_one) + 1;
    let negative = u128::from(shifted_secret)
        + u128::from(FROZEN_CIPHERTEXT_MODULUS) * u128::from(negative_indicator);
    if positive != negative {
        return Err(format!(
            "synthetic affine relation failed at row {row_index}, half {}",
            first_column_index / 4
        ));
    }
    Ok(())
}

fn canonical_frozen_input(
    columns: &[Vec<u64>; FROZEN_RELATION_COLUMN_COUNT],
) -> ProofBackendBakeoffResult<Vec<u8>> {
    let element_count = FROZEN_RELATION_COLUMN_COUNT
        .checked_mul(FROZEN_RELATION_ROW_COUNT)
        .ok_or_else(|| "frozen input element count overflowed".to_owned())?;
    let byte_capacity = element_count
        .checked_mul(size_of::<u64>())
        .and_then(|value| value.checked_add(128))
        .ok_or_else(|| "frozen input byte capacity overflowed".to_owned())?;
    let mut encoded = Vec::with_capacity(byte_capacity);
    append_length_prefixed_bytes(
        &mut encoded,
        b"sealed-lattice/proof-backend-bakeoff/frozen-fragment-input/v1",
    )?;
    append_u64(&mut encoded, FROZEN_ROSTER_SIZE);
    append_u64(&mut encoded, FROZEN_RING_DEGREE);
    append_u64(&mut encoded, FROZEN_PLAINTEXT_MODULUS);
    append_u64(&mut encoded, FROZEN_CIPHERTEXT_MODULUS);
    append_u64(&mut encoded, FROZEN_MATERIAL_RADIX);
    for column in columns {
        append_u64(
            &mut encoded,
            u64::try_from(column.len())
                .map_err(|_| "frozen column length does not fit u64".to_owned())?,
        );
        for &value in column {
            append_u64(&mut encoded, value);
        }
    }
    Ok(encoded)
}

pub(super) fn recompute_frozen_input_identity(
    columns: &[Vec<u64>; FROZEN_RELATION_COLUMN_COUNT],
) -> ProofBackendBakeoffResult<String> {
    validate_frozen_columns(columns)?;
    let canonical_input = canonical_frozen_input(columns)?;
    Ok(hash512_hex(
        "proof-backend-bakeoff/frozen-fragment-input/v1",
        &[canonical_input.as_slice()],
    ))
}

fn append_length_prefixed_bytes(
    destination: &mut Vec<u8>,
    value: &[u8],
) -> ProofBackendBakeoffResult<()> {
    append_u64(
        destination,
        u64::try_from(value.len()).map_err(|_| "byte string length does not fit u64".to_owned())?,
    );
    destination.extend_from_slice(value);
    Ok(())
}

fn append_u64(destination: &mut Vec<u8>, value: u64) {
    destination.extend_from_slice(&value.to_le_bytes());
}

fn required_environment_variable(name: &str) -> ProofBackendBakeoffResult<String> {
    let value =
        env::var(name).map_err(|_| format!("missing required environment variable {name}"))?;
    if value.is_empty() {
        return Err(format!("environment variable {name} must not be empty"));
    }
    Ok(value)
}

fn sample_ordinal() -> ProofBackendBakeoffResult<u8> {
    let value = required_environment_variable(SAMPLE_ORDINAL_ENVIRONMENT_VARIABLE)?;
    if value.len() != 1 || !matches!(value.as_bytes()[0], b'1'..=b'3') {
        return Err(format!(
            "{SAMPLE_ORDINAL_ENVIRONMENT_VARIABLE} must be the canonical decimal integer 1, 2, or 3"
        ));
    }
    Ok(value.as_bytes()[0] - b'0')
}

fn result_path() -> ProofBackendBakeoffResult<PathBuf> {
    let path = PathBuf::from(required_environment_variable(
        RESULT_PATH_ENVIRONMENT_VARIABLE,
    )?);
    if !path.is_absolute() {
        return Err(format!(
            "{RESULT_PATH_ENVIRONMENT_VARIABLE} must be an absolute path"
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| "bakeoff result path must have a parent directory".to_owned())?;
    if !parent.is_dir() {
        return Err("bakeoff result parent directory must already exist".to_owned());
    }
    if path.exists() {
        return Err("bakeoff result path already exists".to_owned());
    }
    Ok(path)
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
        .ok_or_else(|| "bakeoff result filename must be Unicode".to_owned())?;
    let temporary_path = path.with_file_name(format!(".{file_name}.{}.tmp", std::process::id()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary_path)
            .map_err(|error| format!("create bakeoff temporary result: {error}"))?;
        serde_json::to_writer_pretty(&mut file, value)
            .map_err(|error| format!("encode bakeoff result: {error}"))?;
        file.write_all(b"\n")
            .map_err(|error| format!("finish bakeoff result: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("sync bakeoff result: {error}"))?;
        fs::rename(&temporary_path, path)
            .map_err(|error| format!("publish bakeoff result: {error}"))?;
        Ok(())
    })();
    if result.is_err() && temporary_path.exists() {
        let _ = fs::remove_file(&temporary_path);
    }
    result
}

fn execute_sample() -> ProofBackendBakeoffResult<()> {
    let backend = ProofBackendBakeoffBackend::parse(&required_environment_variable(
        BACKEND_ENVIRONMENT_VARIABLE,
    )?)?;
    let sample_ordinal = sample_ordinal()?;
    let result_path = result_path()?;
    let fixture = frozen_fixture()?;

    // Let the process-memory guard capture a strict pre-operation RSS baseline.
    thread::sleep(Duration::from_millis(250));
    let operation_started_at_unix_milliseconds = unix_milliseconds()?;
    let started = Instant::now();
    let output = match backend {
        ProofBackendBakeoffBackend::PackedDeepFri => execute_packed_deep_fri(&fixture),
        ProofBackendBakeoffBackend::SumcheckClass => execute_sumcheck_class(&fixture),
    }?;
    let elapsed = started.elapsed();
    let operation_finished_at_unix_milliseconds = unix_milliseconds()?;

    if output.canonical_artifact.is_empty() {
        return Err("backend returned an empty canonical artifact".to_owned());
    }
    let recomputed_proof_hash = hash512_hex(
        "proof-backend-bakeoff/canonical-artifact/v1",
        &[output.canonical_artifact.as_slice()],
    );
    if output.proof_shake256_hex != recomputed_proof_hash {
        return Err("backend proof digest does not match its canonical artifact".to_owned());
    }
    let canonical_proof_byte_length = u64::try_from(output.canonical_artifact.len())
        .map_err(|_| "canonical proof byte length does not fit u64".to_owned())?;
    let elapsed_nanoseconds = u64::try_from(elapsed.as_nanos())
        .map_err(|_| "bakeoff elapsed nanoseconds do not fit u64".to_owned())?;
    let record = ProofBackendBakeoffSampleRecord {
        format_version: 1,
        backend,
        sample_ordinal,
        frozen_input_identity_shake256_hex: fixture.input_identity_shake256_hex,
        operation_started_at_unix_milliseconds,
        operation_finished_at_unix_milliseconds,
        elapsed_nanoseconds_decimal: elapsed_nanoseconds.to_string(),
        canonical_proof_byte_length_decimal: canonical_proof_byte_length.to_string(),
        proof_shake256_hex: output.proof_shake256_hex,
        external_read_byte_length_decimal: output.external_read_byte_length.to_string(),
        external_written_byte_length_decimal: output.external_written_byte_length.to_string(),
        external_committed_transaction_count_decimal: output
            .external_committed_transaction_count
            .to_string(),
    };
    atomic_write_json(&result_path, &record)
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroize;

    use crate::foundation::{CanonicalDecodeLimits, CanonicalItem, CanonicalTuple};

    use super::{
        canonical_frozen_core_statement, canonical_frozen_fri_public_statement,
        canonical_frozen_sumcheck_public_statement, checked_frozen_backend_bindings,
        derive_frozen_fri_base_root, derive_frozen_sumcheck_commitment, execute_packed_deep_fri,
        execute_sumcheck_class, frozen_fixture, frozen_relation_fragment,
        recompute_frozen_input_identity, validate_frozen_columns,
        validated_frozen_fri_public_statement, validated_frozen_sumcheck_public_statement,
        verify_packed_deep_fri_mutations, verify_sumcheck_class_mutations,
    };

    #[test]
    fn frozen_fragment_has_exact_geometry_and_refuses_each_affine_half_mutation() {
        let fixture = frozen_fixture().expect("frozen fixture");
        assert_eq!(fixture.columns.len(), 8);
        assert!(fixture.columns.iter().all(|column| column.len() == 16_384));
        assert_eq!(fixture.input_identity_shake256_hex.len(), 128);
        let decoded_fri_statement = CanonicalTuple::decode(
            &fixture.canonical_fri_statement,
            &CanonicalDecodeLimits::default(),
        )
        .expect("frozen canonical FRI statement decodes");
        assert_eq!(decoded_fri_statement.schema_identifier, u16::MAX);
        assert_eq!(decoded_fri_statement.schema_version, 2);
        assert_eq!(decoded_fri_statement.items.len(), 3);
        assert_eq!(
            decoded_fri_statement
                .encode()
                .expect("canonical FRI round trip"),
            fixture.canonical_fri_statement
        );
        let fri_bindings = validated_frozen_fri_public_statement(
            &fixture.canonical_fri_statement,
            &fixture.input_identity_shake256_hex,
        )
        .expect("frozen FRI public bindings validate");
        assert_eq!(
            fri_bindings.canonical_core_statement,
            fixture.canonical_core_statement
        );
        assert_eq!(
            fri_bindings.expected_fri_base_root,
            fixture.expected_fri_base_root
        );

        let decoded_sumcheck_statement = CanonicalTuple::decode(
            &fixture.canonical_sumcheck_statement,
            &CanonicalDecodeLimits::default(),
        )
        .expect("frozen canonical sumcheck statement decodes");
        assert_eq!(decoded_sumcheck_statement.schema_identifier, u16::MAX);
        assert_eq!(decoded_sumcheck_statement.schema_version, 2);
        assert_eq!(decoded_sumcheck_statement.items.len(), 3);
        assert_eq!(
            decoded_sumcheck_statement
                .encode()
                .expect("canonical sumcheck round trip"),
            fixture.canonical_sumcheck_statement
        );
        let sumcheck_bindings = validated_frozen_sumcheck_public_statement(
            &fixture.canonical_sumcheck_statement,
            &fixture.input_identity_shake256_hex,
        )
        .expect("frozen sumcheck public bindings validate");
        assert_eq!(
            sumcheck_bindings.canonical_core_statement,
            fixture.canonical_core_statement
        );
        assert_eq!(
            sumcheck_bindings.expected_sumcheck_commitment,
            fixture.expected_sumcheck_commitment
        );
        assert!(
            validated_frozen_fri_public_statement(
                &fixture.canonical_sumcheck_statement,
                &fixture.input_identity_shake256_hex,
            )
            .is_err()
        );
        assert!(
            validated_frozen_sumcheck_public_statement(
                &fixture.canonical_fri_statement,
                &fixture.input_identity_shake256_hex,
            )
            .is_err()
        );

        let mut alternate_fri_base_root = fixture.expected_fri_base_root;
        alternate_fri_base_root[0] ^= 1;
        let alternate_fri_statement = canonical_frozen_fri_public_statement(
            &fixture.input_identity_shake256_hex,
            alternate_fri_base_root,
        )
        .expect("alternate FRI binding encodes canonically");
        assert!(
            validated_frozen_fri_public_statement(
                &alternate_fri_statement,
                &fixture.input_identity_shake256_hex,
            )
            .is_err()
        );

        let mut alternate_sumcheck_commitment = fixture.expected_sumcheck_commitment.clone();
        alternate_sumcheck_commitment[0] ^= 1;
        let alternate_sumcheck_statement = canonical_frozen_sumcheck_public_statement(
            &fixture.input_identity_shake256_hex,
            &alternate_sumcheck_commitment,
        )
        .expect("alternate sumcheck binding encodes canonically");
        assert!(
            validated_frozen_sumcheck_public_statement(
                &alternate_sumcheck_statement,
                &fixture.input_identity_shake256_hex,
            )
            .is_err()
        );

        let decoded_core_statement = CanonicalTuple::decode(
            &fixture.canonical_core_statement,
            &CanonicalDecodeLimits::default(),
        )
        .expect("frozen canonical core statement decodes");
        let expected_core_statement = CanonicalTuple::new(
            u16::MAX,
            1,
            vec![
                CanonicalItem::unsigned64(10),
                CanonicalItem::unsigned64(32_768),
                CanonicalItem::unsigned64(257),
                CanonicalItem::unsigned64(16_384),
                CanonicalItem::unsigned64(8),
                CanonicalItem::unsigned64(1_953_759_233),
                CanonicalItem::unsigned64(129_140_163),
                CanonicalItem::nonempty_ascii(&fixture.input_identity_shake256_hex)
                    .expect("frozen identity is canonical ASCII"),
            ],
        );
        assert_eq!(decoded_core_statement.schema_identifier, u16::MAX);
        assert_eq!(decoded_core_statement.schema_version, 1);
        assert_eq!(decoded_core_statement, expected_core_statement);
        assert_eq!(
            decoded_core_statement
                .encode()
                .expect("canonical core round trip"),
            fixture.canonical_core_statement
        );

        for column_index in 0..8 {
            let mut mutated = fixture.columns.clone();
            mutated[column_index][9] = mutated[column_index][9]
                .checked_add(1)
                .expect("small mutation");
            assert!(validate_frozen_columns(&mutated).is_err());
        }
    }

    #[test]
    fn frozen_checked_backend_bindings_are_nonplaceholder_and_canonical() {
        checked_frozen_backend_bindings()
            .expect("checked backend bindings are nonplaceholder and canonical");
    }

    #[test]
    #[ignore = "manual guarded exact public-binding regeneration"]
    fn frozen_backend_binding_vectors_regenerate_from_exact_columns_and_profiles() {
        let fragment = frozen_relation_fragment().expect("raw frozen relation fragment");
        let regenerated_fri_base_root = derive_frozen_fri_base_root(
            &fragment.canonical_core_statement,
            &fragment.input_identity_shake256_hex,
            &fragment.columns,
        )
        .expect("regenerate exact frozen FRI base root");
        let regenerated_sumcheck_commitment = derive_frozen_sumcheck_commitment(&fragment.columns)
            .expect("regenerate exact frozen sumcheck commitment");

        if regenerated_fri_base_root != super::FROZEN_EXPECTED_FRI_BASE_ROOT
            || regenerated_sumcheck_commitment != super::FROZEN_EXPECTED_SUMCHECK_COMMITMENT
        {
            panic!(
                "checked backend bindings are stale; regenerated FRI base root: {regenerated_fri_base_root:?}; regenerated sumcheck commitment: {regenerated_sumcheck_commitment:?}; checked FRI base root: {:?}; checked sumcheck commitment: {:?}",
                super::FROZEN_EXPECTED_FRI_BASE_ROOT,
                super::FROZEN_EXPECTED_SUMCHECK_COMMITMENT
            );
        }
    }

    #[test]
    #[ignore = "manual guarded synthetic proof-backend bakeoff sample"]
    fn proof_backend_bakeoff_frozen_fragment() {
        super::execute_sample().expect("proof backend bakeoff sample");
    }

    #[test]
    #[ignore = "manual guarded packed-DEEP-FRI fresh-verifier preflight"]
    fn packed_deep_fri_fresh_verifier_has_no_witness_side_channel() {
        let mut fixture = frozen_fixture().expect("frozen fixture");
        let alternate_affine_valid_columns: [Vec<u64>; 8] = std::array::from_fn(|column_index| {
            let constant_value = if column_index == 2 || column_index == 6 {
                1
            } else {
                0
            };
            vec![constant_value; 16_384]
        });
        validate_frozen_columns(&alternate_affine_valid_columns)
            .expect("alternate FRI columns satisfy both affine equations");
        let alternate_input_identity =
            recompute_frozen_input_identity(&alternate_affine_valid_columns)
                .expect("derive alternate FRI input identity");
        let alternate_core_statement = canonical_frozen_core_statement(&alternate_input_identity)
            .expect("derive alternate FRI core statement");
        let alternate_affine_valid_base_root = derive_frozen_fri_base_root(
            &alternate_core_statement,
            &alternate_input_identity,
            &alternate_affine_valid_columns,
        )
        .expect("derive alternate affine-valid FRI base root");
        assert_ne!(
            alternate_affine_valid_base_root,
            fixture.expected_fri_base_root
        );
        drop(alternate_affine_valid_columns);
        drop(alternate_core_statement);
        drop(alternate_input_identity);
        let output = execute_packed_deep_fri(&fixture).expect("generate canonical FRI proof");
        let canonical_statement = std::mem::take(&mut fixture.canonical_fri_statement);
        let input_identity_shake256_hex = std::mem::take(&mut fixture.input_identity_shake256_hex);
        fixture.columns.zeroize();
        assert!(
            fixture
                .columns
                .iter()
                .all(|column| column.iter().all(|value| *value == 0))
        );
        drop(fixture);

        verify_packed_deep_fri_mutations(
            &canonical_statement,
            &input_identity_shake256_hex,
            &output.canonical_artifact,
            alternate_affine_valid_base_root,
        )
        .expect("fresh verifier rejects every canonical-proof mutation without witness state");
    }

    #[test]
    #[ignore = "manual guarded sumcheck-class fresh-verifier preflight"]
    fn sumcheck_class_fresh_verifier_has_no_witness_side_channel() {
        let mut fixture = frozen_fixture().expect("frozen fixture");
        let output = execute_sumcheck_class(&fixture).expect("generate canonical sumcheck proof");
        let canonical_statement = std::mem::take(&mut fixture.canonical_sumcheck_statement);
        let input_identity_shake256_hex = std::mem::take(&mut fixture.input_identity_shake256_hex);
        fixture.columns.zeroize();
        assert!(
            fixture
                .columns
                .iter()
                .all(|column| column.iter().all(|value| *value == 0))
        );
        drop(fixture);

        verify_sumcheck_class_mutations(
            &canonical_statement,
            &input_identity_shake256_hex,
            &output.canonical_artifact,
        )
        .expect("fresh verifier rejects every canonical-proof mutation without witness state");
    }
}
