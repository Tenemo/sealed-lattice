//! Frozen synthetic-fragment fixtures and fresh-verifier preflights.

#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
use crate::foundation::{CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple};
use crate::hashing::{hash_framed_parts_512, to_hex};

#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
use super::{
    proof_backend_bakeoff_fri::{
        derive_frozen_fri_base_root, execute_packed_deep_fri, verify_packed_deep_fri_mutations,
    },
    proof_backend_bakeoff_sumcheck::{
        derive_frozen_sumcheck_commitment, execute_sumcheck_class,
        validate_canonical_sumcheck_commitment, verify_sumcheck_class_mutations,
    },
};

const FROZEN_ROSTER_SIZE: u64 = 10;
const FROZEN_RING_DEGREE: u64 = 32_768;
const FROZEN_PLAINTEXT_MODULUS: u64 = 257;
const FROZEN_RELATION_ROW_COUNT: usize = 16_384;
const FROZEN_RELATION_COLUMN_COUNT: usize = 8;
const FROZEN_CIPHERTEXT_MODULUS: u64 = 1_953_759_233;
const FROZEN_MATERIAL_RADIX: u64 = 129_140_163;
pub(super) const FROZEN_INPUT_RECIPE_IDENTIFIER: &str =
    "sealed-lattice/proof-backend-bakeoff/frozen-fragment-input/v1";
pub(super) const FROZEN_INPUT_IDENTITY_HASH_DOMAIN: &str =
    "proof-backend-bakeoff/frozen-fragment-input/v1";
pub(super) const FROZEN_INPUT_IDENTITY_SHAKE256_HEX: &str = "930c501295b47a502f01dd8475291d43c2a93fe8198cbe91904218eeefc68a44dd517d167b35e154853241e215255b35646a52d732edddce650777d9a0a52dec";
#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
const FROZEN_FRI_STATEMENT_DOMAIN: &str =
    "sealed-lattice/proof-backend-bakeoff/packed-deep-fri-statement/v1";
#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
const FROZEN_SUMCHECK_STATEMENT_DOMAIN: &str =
    "sealed-lattice/proof-backend-bakeoff/sumcheck-class-statement/v1";
// The ignored exact-binding owner regenerates both values from the frozen columns and profiles.
// Keeping the derivation out of `frozen_fixture` prevents either backend from warming allocator or
// commitment state before a measured sample starts.
#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
const FROZEN_EXPECTED_FRI_BASE_ROOT: [u8; 64] = [
    105, 66, 13, 132, 207, 215, 32, 167, 45, 114, 159, 94, 129, 40, 150, 244, 1, 85, 134, 190, 196,
    198, 32, 236, 144, 96, 195, 181, 180, 48, 171, 252, 177, 189, 73, 177, 158, 23, 154, 31, 71,
    31, 237, 156, 116, 231, 222, 26, 147, 72, 117, 184, 211, 55, 122, 155, 249, 95, 178, 61, 249,
    79, 122, 173,
];
#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
const FROZEN_EXPECTED_SUMCHECK_COMMITMENT: &[u8] = &[
    1, 191, 172, 221, 150, 198, 254, 172, 182, 100, 137, 171, 249, 218, 137, 177, 246, 187, 52,
    177, 222, 184, 188, 183, 161, 211, 131, 21, 200, 241, 194, 212, 147, 153, 176, 219, 174, 1,
    172, 147, 129, 184, 226, 234, 137, 142, 244, 1, 237, 170, 166, 172, 245, 191, 239, 147, 240, 1,
    214, 195, 180, 145, 186, 255, 203, 186, 59, 165, 202, 184, 246, 217, 216, 193, 203, 245, 1,
];

pub(super) type ProofBackendBakeoffResult<T> = Result<T, String>;

#[derive(Clone, Debug)]
pub(super) struct ProofBackendBakeoffFixture {
    #[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
    pub(super) canonical_core_statement: Vec<u8>,
    #[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
    pub(super) canonical_fri_statement: Vec<u8>,
    #[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
    pub(super) canonical_sumcheck_statement: Vec<u8>,
    pub(super) columns: [Vec<u64>; FROZEN_RELATION_COLUMN_COUNT],
    #[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
    pub(super) expected_fri_base_root: [u8; 64],
    #[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
    pub(super) expected_sumcheck_commitment: Vec<u8>,
    pub(super) input_identity_shake256_hex: String,
}

#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct FrozenFriPublicStatementBindings {
    pub(super) canonical_core_statement: Vec<u8>,
    pub(super) expected_fri_base_root: [u8; 64],
}

#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct FrozenSumcheckPublicStatementBindings {
    pub(super) canonical_core_statement: Vec<u8>,
    pub(super) expected_sumcheck_commitment: Vec<u8>,
}

#[derive(Clone, Debug)]
struct FrozenRelationFragment {
    #[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
    canonical_core_statement: Vec<u8>,
    columns: [Vec<u64>; FROZEN_RELATION_COLUMN_COUNT],
    input_identity_shake256_hex: String,
}

#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
#[derive(Clone, Debug)]
pub(super) struct ProofBackendBakeoffArmOutput {
    pub(super) canonical_artifact: Vec<u8>,
}

pub(super) fn frozen_fixture() -> ProofBackendBakeoffResult<ProofBackendBakeoffFixture> {
    let fragment = frozen_relation_fragment()?;
    #[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
    let expected_fri_base_root = checked_frozen_fri_base_root()?;
    #[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
    let expected_sumcheck_commitment = checked_frozen_sumcheck_commitment()?;
    #[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
    let canonical_fri_statement = canonical_frozen_fri_public_statement(
        &fragment.input_identity_shake256_hex,
        expected_fri_base_root,
    )?;
    #[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
    let canonical_sumcheck_statement = canonical_frozen_sumcheck_public_statement(
        &fragment.input_identity_shake256_hex,
        &expected_sumcheck_commitment,
    )?;

    Ok(ProofBackendBakeoffFixture {
        #[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
        canonical_core_statement: fragment.canonical_core_statement,
        #[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
        canonical_fri_statement,
        #[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
        canonical_sumcheck_statement,
        columns: fragment.columns,
        #[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
        expected_fri_base_root,
        #[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
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
    if input_identity_shake256_hex != FROZEN_INPUT_IDENTITY_SHAKE256_HEX {
        return Err("frozen eight-column input identity changed".to_owned());
    }
    #[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
    let canonical_core_statement = canonical_frozen_core_statement(&input_identity_shake256_hex)?;

    Ok(FrozenRelationFragment {
        #[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
        canonical_core_statement,
        columns,
        input_identity_shake256_hex,
    })
}

#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
fn checked_frozen_backend_bindings() -> ProofBackendBakeoffResult<([u8; 64], Vec<u8>)> {
    Ok((
        checked_frozen_fri_base_root()?,
        checked_frozen_sumcheck_commitment()?,
    ))
}

#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
fn checked_frozen_fri_base_root() -> ProofBackendBakeoffResult<[u8; 64]> {
    if FROZEN_EXPECTED_FRI_BASE_ROOT == [0; 64] {
        return Err("frozen expected FRI base root is still the zero placeholder".to_owned());
    }
    Ok(FROZEN_EXPECTED_FRI_BASE_ROOT)
}

#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
fn checked_frozen_sumcheck_commitment() -> ProofBackendBakeoffResult<Vec<u8>> {
    if FROZEN_EXPECTED_SUMCHECK_COMMITMENT == [0] {
        return Err(
            "frozen expected sumcheck commitment is still the one-byte placeholder".to_owned(),
        );
    }
    validate_canonical_sumcheck_commitment(FROZEN_EXPECTED_SUMCHECK_COMMITMENT)?;
    Ok(FROZEN_EXPECTED_SUMCHECK_COMMITMENT.to_vec())
}

#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
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

#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
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

#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
pub(super) fn canonical_frozen_core_statement(
    input_identity_shake256_hex: &str,
) -> ProofBackendBakeoffResult<Vec<u8>> {
    canonical_frozen_core_statement_tuple(input_identity_shake256_hex)?
        .encode()
        .map_err(|error| format!("encode frozen canonical core statement: {error}"))
}

#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
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

#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
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

#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
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

#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
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

#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
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
    append_length_prefixed_bytes(&mut encoded, FROZEN_INPUT_RECIPE_IDENTIFIER.as_bytes())?;
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
    Ok(to_hex(&hash_framed_parts_512(
        FROZEN_INPUT_IDENTITY_HASH_DOMAIN,
        &[canonical_input.as_slice()],
    )))
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

#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
mod tests {
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use zeroize::Zeroize;

    use crate::foundation::{CanonicalDecodeLimits, CanonicalItem, CanonicalTuple};

    use super::super::bounded_proof_storage::{
        BoundedProofStorageCustody, BoundedProofStorageUsage,
    };

    use super::{
        ProofBackendBakeoffArmOutput, ProofBackendBakeoffFixture, ProofBackendBakeoffResult,
        canonical_frozen_core_statement, canonical_frozen_fri_public_statement,
        canonical_frozen_sumcheck_public_statement, checked_frozen_backend_bindings,
        derive_frozen_fri_base_root, derive_frozen_sumcheck_commitment, execute_packed_deep_fri,
        execute_sumcheck_class, frozen_fixture, frozen_relation_fragment,
        recompute_frozen_input_identity, validate_frozen_columns,
        validated_frozen_fri_public_statement, validated_frozen_sumcheck_public_statement,
        verify_packed_deep_fri_mutations, verify_sumcheck_class_mutations,
    };

    static CUSTODY_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn unique_custody_directory(backend_name: &str) -> PathBuf {
        let scratch_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("temp");
        std::fs::create_dir_all(&scratch_root)
            .expect("create repository-local custody scratch directory");
        let sequence = CUSTODY_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        scratch_root.join(format!(
            "proof-backend-preflight-{backend_name}-{}-{sequence}",
            std::process::id()
        ))
    }

    fn execute_with_bounded_preflight_custody(
        fixture: &ProofBackendBakeoffFixture,
        backend_name: &str,
        execute_arm: fn(
            &ProofBackendBakeoffFixture,
        ) -> ProofBackendBakeoffResult<ProofBackendBakeoffArmOutput>,
    ) -> ProofBackendBakeoffResult<(ProofBackendBakeoffArmOutput, BoundedProofStorageUsage)> {
        let directory_path = unique_custody_directory(backend_name);
        let mut custody = BoundedProofStorageCustody::new(directory_path.clone())?;
        let operation_result = (|| {
            let mut replayed_columns: [Vec<u64>; 8] = std::array::from_fn(|_| Vec::new());
            for (column_index, column) in fixture.columns.iter().enumerate() {
                let source_object =
                    custody.create_object(&format!("source-column-{column_index:02}.bin"))?;
                let mut canonical_column = Vec::with_capacity(column.len() * 8);
                for value in column {
                    canonical_column.extend_from_slice(&value.to_le_bytes());
                }
                custody.append_object(source_object, &canonical_column)?;
                custody.seal_object(source_object)?;
                canonical_column.zeroize();
                let replayed_canonical_column = custody.read_complete_object(source_object)?;
                if replayed_canonical_column.len() != column.len() * 8 {
                    return Err("bounded preflight source column length changed".to_owned());
                }
                let replayed_column = &mut replayed_columns[column_index];
                replayed_column
                    .try_reserve_exact(column.len())
                    .map_err(|_| "bounded preflight replay column allocation failed".to_owned())?;
                for encoded_value in replayed_canonical_column.chunks_exact(8) {
                    replayed_column.push(u64::from_le_bytes(encoded_value.try_into().map_err(
                        |_| "bounded preflight source value is not eight bytes".to_owned(),
                    )?));
                }
            }
            validate_frozen_columns(&replayed_columns)?;
            if recompute_frozen_input_identity(&replayed_columns)?
                != fixture.input_identity_shake256_hex
            {
                return Err("bounded preflight source identity changed after replay".to_owned());
            }

            let mut replayed_fixture = fixture.clone();
            replayed_fixture.columns = replayed_columns;
            let mut output = execute_arm(&replayed_fixture);
            replayed_fixture.columns.zeroize();
            let output = output.as_mut().map_err(|error| error.to_owned())?;
            if output.canonical_artifact.is_empty() {
                return Err("bounded preflight proof artifact is empty".to_owned());
            }
            let artifact_byte_length = output.canonical_artifact.len();
            let proof_object = custody.create_object("canonical-proof.bin")?;
            custody.append_object(proof_object, &output.canonical_artifact)?;
            custody.seal_object(proof_object)?;
            if custody.object_byte_length(proof_object)?
                != u64::try_from(artifact_byte_length)
                    .map_err(|_| "bounded preflight proof length does not fit u64".to_owned())?
            {
                return Err("bounded preflight proof length changed in custody".to_owned());
            }
            output.canonical_artifact.zeroize();
            let canonical_artifact = custody.read_complete_object(proof_object)?;
            if canonical_artifact.len() != artifact_byte_length {
                return Err("bounded preflight proof readback length changed".to_owned());
            }
            Ok(ProofBackendBakeoffArmOutput { canonical_artifact })
        })();
        let cleanup_result = custody.finish();
        match (operation_result, cleanup_result) {
            (Ok(output), Ok(usage)) => {
                if !usage.cleanup_complete
                    || usage.total_read_byte_length == 0
                    || usage.total_written_byte_length == 0
                    || usage.transaction_count == 0
                    || usage.created_object_count != 9
                    || usage.deleted_object_count != 9
                    || usage.active_object_count != 0
                    || usage.active_stored_byte_length != 0
                    || directory_path.exists()
                {
                    return Err(
                        "bounded preflight custody telemetry or cleanup is incomplete".to_owned(),
                    );
                }
                Ok((output, usage))
            }
            (Err(operation_error), Ok(_)) => Err(operation_error),
            (Ok(_), Err(cleanup_error)) => Err(cleanup_error),
            (Err(operation_error), Err(cleanup_error)) => Err(format!(
                "{operation_error}; bounded preflight cleanup also failed: {cleanup_error}"
            )),
        }
    }

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
        let (output, custody_usage) = execute_with_bounded_preflight_custody(
            &fixture,
            "packed-deep-fri",
            execute_packed_deep_fri,
        )
        .expect("generate and read back canonical FRI proof through bounded custody");
        assert!(custody_usage.cleanup_complete);
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
        let (output, custody_usage) = execute_with_bounded_preflight_custody(
            &fixture,
            "sumcheck-class",
            execute_sumcheck_class,
        )
        .expect("generate and read back canonical sumcheck proof through bounded custody");
        assert!(custody_usage.cleanup_complete);
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
