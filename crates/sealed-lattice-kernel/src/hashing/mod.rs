use serde_json::Value;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::{borrow::Cow, cmp::Ordering};
use unicode_normalization::UnicodeNormalization;

use crate::encoding::{
    CanonicalError, CanonicalErrorCode, CanonicalResult, append_bytes, append_varuint,
};

#[cfg(test)]
pub const MODULE_MARKER: &str = "hashing";
pub const HASH512_PREIMAGE_PREFIX: &[u8] = b"sealed.vote/v1/hash512";

macro_rules! reserved_root_namespaces {
    ($( $constant_name:ident => $namespace:literal, )+) => {
        $(pub const $constant_name: &str = $namespace;)+
        pub const RESERVED_ROOT_NAMESPACES: &[&str] = &[$($constant_name),+];
    };
}

reserved_root_namespaces! {
    BOARD_ENTRY_HASH_NAMESPACE => "sealed-lattice-root/board-entry-hash-v1",
    BOARD_ROOT_HASH_NAMESPACE => "sealed-lattice-root/board-root-hash-v1",
    POLL_SPEC_HASH_NAMESPACE => "sealed-lattice-root/poll-spec-hash-v1",
    PUBLIC_KEY_HASH_NAMESPACE => "sealed-lattice-root/public-key-hash-v1",
    REGISTRATION_ENTRY_HASH_NAMESPACE => "sealed-lattice-root/registration-entry-hash-v1",
    RECEIVER_KEY_REGISTRATION_HASH_NAMESPACE => "sealed-lattice-root/receiver-key-registration-hash-v1",
    TRUSTEE_SETUP_ENTRY_HASH_NAMESPACE => "sealed-lattice-root/trustee-setup-entry-hash-v1",
    ELECTION_MANIFEST_HASH_NAMESPACE => "sealed-lattice-root/election-manifest-hash-v1",
    ROSTER_HASH_NAMESPACE => "sealed-lattice-root/roster-hash-v1",
    ROSTER_EXTERNAL_ACCEPTANCE_HASH_NAMESPACE => "sealed-lattice-root/roster-external-acceptance-hash-v1",
    BOARD_HEAD_HASH_NAMESPACE => "sealed-lattice-root/board-head-hash-v1",
    RECOVERY_EPOCH_UPDATE_HASH_NAMESPACE => "sealed-lattice-root/recovery-epoch-update-hash-v1",
    ACTION_CONTEXT_HASH_NAMESPACE => "sealed-lattice-root/action-context-hash-v1",
    BALLOT_PACKAGE_HASH_NAMESPACE => "sealed-lattice-root/ballot-package-hash-v1",
    BALLOT_SET_HASH_NAMESPACE => "sealed-lattice-root/ballot-set-hash-v1",
    CAST_RECEIPT_HASH_NAMESPACE => "sealed-lattice-root/cast-receipt-hash-v1",
    CLOSE_RECORD_HASH_NAMESPACE => "sealed-lattice-root/close-record-hash-v1",
    WITNESS_CHECKPOINT_HASH_NAMESPACE => "sealed-lattice-root/witness-checkpoint-hash-v1",
    CONFLICTING_HEAD_EVIDENCE_HASH_NAMESPACE => "sealed-lattice-root/conflicting-head-evidence-hash-v1",
    WITNESS_EQUIVOCATION_EVIDENCE_HASH_NAMESPACE => "sealed-lattice-root/witness-equivocation-evidence-hash-v1",
    INCLUSION_PROOF_HASH_NAMESPACE => "sealed-lattice-root/inclusion-proof-hash-v1",
    FIRST_VALID_ORDER_HASH_NAMESPACE => "sealed-lattice-root/first-valid-order-hash-v1",
    TARGET_FINALITY_POLICY_HASH_NAMESPACE => "sealed-lattice-root/target-finality-policy-hash-v1",
    WITNESS_POLICY_HASH_NAMESPACE => "sealed-lattice-root/witness-policy-hash-v1",
    SIGNED_ROOT_HASH_NAMESPACE => "sealed-lattice-root/signed-root-hash-v1",
    PROTOCOL_SIGNATURE_ENVELOPE_HASH_NAMESPACE => "sealed-lattice-root/protocol-signature-envelope-hash-v1",
    PROVIDER_BUILD_HASH_NAMESPACE => "sealed-lattice-root/provider-build-hash-v1",
    THRESHOLD_PROFILE_HASH_NAMESPACE => "sealed-lattice-root/threshold-profile-hash-v1",
    BGV_PROFILE_HASH_NAMESPACE => "sealed-lattice-root/bgv-profile-hash-v1",
    RUST_BGV_BACKEND_PROFILE_HASH_NAMESPACE => "sealed-lattice-root/rust-bgv-backend-profile-hash-v1",
    ENCRYPTED_AGGREGATE_BRIDGE_HASH_NAMESPACE => "sealed-lattice-root/encrypted-aggregate-bridge-hash-v1",
    ENCRYPTED_AGGREGATE_SHARE_CIPHERTEXT_ROOT_NAMESPACE => "sealed-lattice-root/encrypted-aggregate-share-ciphertext-root-v1",
    ENCRYPTED_AGGREGATE_TARGET_BASIS_ROOT_NAMESPACE => "sealed-lattice-root/encrypted-aggregate-target-basis-root-v1",
    ENCRYPTED_AGGREGATE_RECONSTRUCTION_HASH_NAMESPACE => "sealed-lattice-root/encrypted-aggregate-reconstruction-hash-v1",
    SCORE_BIT_DERIVATION_CIRCUIT_HASH_NAMESPACE => "sealed-lattice-root/score-bit-derivation-circuit-hash-v1",
    COMPARISON_INPUT_DERIVATION_CIRCUIT_HASH_NAMESPACE => "sealed-lattice-root/comparison-input-derivation-circuit-hash-v1",
    ENCRYPTED_SCORE_BIT_INPUT_HASH_NAMESPACE => "sealed-lattice-root/encrypted-score-bit-input-hash-v1",
    ENCRYPTED_COMPARISON_INPUT_HASH_NAMESPACE => "sealed-lattice-root/encrypted-comparison-input-hash-v1",
    BIT_SLICED_COMPARATOR_HASH_NAMESPACE => "sealed-lattice-root/bit-sliced-comparator-hash-v1",
    ENCRYPTED_SPARSE_TARGET_PROJECTION_HASH_NAMESPACE => "sealed-lattice-root/encrypted-sparse-target-projection-hash-v1",
    CIPHERTEXT_ROOT_NAMESPACE => "sealed-lattice-root/ciphertext-root-v1",
    PLAINTEXT_ROOT_NAMESPACE => "sealed-lattice-root/plaintext-root-v1",
    PLAINTEXT_TALLY_HASH_NAMESPACE => "sealed-lattice-root/plaintext-tally-hash-v1",
    PLAINTEXT_TOP_K_ORACLE_HASH_NAMESPACE => "sealed-lattice-root/plaintext-top-k-oracle-hash-v1",
    INTERPOLATION_COEFFICIENT_REPORT_HASH_NAMESPACE => "sealed-lattice-root/interpolation-coefficient-report-hash-v1",
    WORST_CASE_INTERPOLATION_COEFFICIENT_REPORT_HASH_NAMESPACE => "sealed-lattice-root/worst-case-interpolation-coefficient-report-hash-v1",
    SPARSE_TOP_K_TARGET_HASH_NAMESPACE => "sealed-lattice-root/sparse-top-k-target-hash-v1",
    BGV_PASSIVE_SETUP_PACKAGE_HASH_NAMESPACE => "sealed-lattice-root/bgv-passive-setup-package-hash-v1",
    PARTICIPANT_BGV_SETUP_RECORD_HASH_NAMESPACE => "sealed-lattice-root/participant-bgv-setup-record-hash-v1",
    PUBLIC_KEY_SHARE_ROOT_NAMESPACE => "sealed-lattice-root/public-key-share-root-v1",
    BGV_PUBLIC_COMMON_RANDOM_POLYNOMIAL_ROOT_NAMESPACE => "sealed-lattice-root/bgv-public-common-random-polynomial-root-v1",
    BGV_PUBLIC_KEY_ROOT_NAMESPACE => "sealed-lattice-root/bgv-public-key-root-v1",
    COLLECTIVE_PUBLIC_KEY_ROOT_NAMESPACE => "sealed-lattice-root/collective-public-key-root-v1",
    RELINEARIZATION_KEY_ROOT_NAMESPACE => "sealed-lattice-root/relinearization-key-root-v1",
    ROTATION_KEY_ROOT_NAMESPACE => "sealed-lattice-root/rotation-key-root-v1",
    KEY_SWITCH_KEY_ROOT_NAMESPACE => "sealed-lattice-root/key-switch-key-root-v1",
    KEY_SWITCH_DECOMPOSITION_HASH_NAMESPACE => "sealed-lattice-root/key-switch-decomposition-hash-v1",
    EVAL_KEY_ROOT_NAMESPACE => "sealed-lattice-root/eval-key-root-v1",
    EVALUATION_KEY_SIZE_PROFILE_HASH_NAMESPACE => "sealed-lattice-root/evaluation-key-size-profile-hash-v1",
    COLLECTIVE_SECRET_DISTRIBUTION_CERTIFICATE_HASH_NAMESPACE => "sealed-lattice-root/collective-secret-distribution-certificate-hash-v1",
    ERROR_DISTRIBUTION_CERTIFICATE_HASH_NAMESPACE => "sealed-lattice-root/error-distribution-certificate-hash-v1",
    BGV_SETUP_PARAMETER_CERTIFICATE_HASH_NAMESPACE => "sealed-lattice-root/bgv-setup-parameter-certificate-hash-v1",
    BGV_DEVELOPMENT_ENCRYPTION_FIXTURE_HASH_NAMESPACE => "sealed-lattice-root/bgv-development-encryption-fixture-hash-v1",
    TOP_K_CIRCUIT_HASH_NAMESPACE => "sealed-lattice-root/top-k-circuit-hash-v1",
    ROT_SET_HASH_NAMESPACE => "sealed-lattice-root/rot-set-hash-v1",
    TARGET_LAYOUT_HASH_NAMESPACE => "sealed-lattice-root/target-layout-hash-v1",
    AGGREGATE_DERIVATION_COMPONENT_HASH_NAMESPACE => "sealed-lattice-root/aggregate-derivation-component-hash-v1",
    AGGREGATE_CONTRIBUTION_HASH_NAMESPACE => "sealed-lattice-root/aggregate-contribution-hash-v1",
    AGGREGATE_READY_RECORD_HASH_NAMESPACE => "sealed-lattice-root/aggregate-ready-record-hash-v1",
    POST_VOTING_CLOSED_CONTEXT_HASH_NAMESPACE => "sealed-lattice-root/post-voting-closed-context-hash-v1",
    PASSIVE_SETUP_EVALUATOR_BINDING_CONTEXT_HASH_NAMESPACE => "sealed-lattice-root/passive-setup-evaluator-binding-context-hash-v1",
    EVALUATION_CONTEXT_HASH_NAMESPACE => "sealed-lattice-root/evaluation-context-hash-v1",
    TARGET_PROPOSAL_HASH_NAMESPACE => "sealed-lattice-root/target-proposal-hash-v1",
    TARGET_FINALITY_CHECKPOINT_HASH_NAMESPACE => "sealed-lattice-root/target-finality-checkpoint-hash-v1",
    TARGET_FINALITY_RECORD_HASH_NAMESPACE => "sealed-lattice-root/target-finality-record-hash-v1",
    TARGET_ACCEPTED_RECORD_HASH_NAMESPACE => "sealed-lattice-root/target-accepted-record-hash-v1",
    LOCAL_REPLAY_RECORD_HASH_NAMESPACE => "sealed-lattice-root/local-replay-record-hash-v1",
    TOP_K_DECRYPTION_SHARE_HASH_NAMESPACE => "sealed-lattice-root/top-k-decryption-share-hash-v1",
    THRESHOLD_DECRYPTION_PROFILE_HASH_NAMESPACE => "sealed-lattice-root/threshold-decryption-profile-hash-v1",
    KLLPS_TARGET_DECRYPTION_PROFILE_HASH_NAMESPACE => "sealed-lattice-root/kllps-target-decryption-profile-hash-v1",
    BRIDGE_PROOF_PROFILE_HASH_NAMESPACE => "sealed-lattice-root/bridge-proof-profile-hash-v1",
    BRIDGE_PROOF_RECORD_HASH_NAMESPACE => "sealed-lattice-root/bridge-proof-record-hash-v1",
    CANONICAL_CIPHERTEXT_CONVENTION_HASH_NAMESPACE => "sealed-lattice-root/canonical-ciphertext-convention-hash-v1",
    BGV_BATCH_ENCODER_HASH_NAMESPACE => "sealed-lattice-root/bgv-batch-encoder-hash-v1",
    BGV_BATCH_ENCODER_LAYOUT_BINDING_HASH_NAMESPACE => "sealed-lattice-root/bgv-batch-encoder-layout-binding-hash-v1",
    ALLOWED_EVALUATOR_OPS_HASH_NAMESPACE => "sealed-lattice-root/allowed-evaluator-ops-hash-v1",
    AGGREGATE_SHARE_COMMITMENT_HASH_NAMESPACE => "sealed-lattice-root/aggregate-share-commitment-hash-v1",
    SHARE_COMMITMENT_HASH_NAMESPACE => "sealed-lattice-root/share-commitment-hash-v1",
    BALLOT_POLYNOMIAL_SET_HASH_NAMESPACE => "sealed-lattice-root/ballot-polynomial-set-hash-v1",
    THRESHOLD_SHARE_VERIFICATION_KEY_ROOT_NAMESPACE => "sealed-lattice-root/threshold-share-verification-key-root-v1",
    THRESHOLD_SHARE_VERIFICATION_KEY_HASH_NAMESPACE => "sealed-lattice-root/threshold-share-verification-key-hash-v1",
    TRUSTEE_THRESHOLD_VERIFICATION_KEY_HASH_NAMESPACE => "sealed-lattice-root/trustee-threshold-verification-key-hash-v1",
    TARGET_BASIS_HASH_NAMESPACE => "sealed-lattice-root/target-basis-hash-v1",
    RECEIVER_ENCRYPTION_PROFILE_HASH_NAMESPACE => "sealed-lattice-root/receiver-encryption-profile-hash-v1",
    SHARE_COMMITMENT_PROFILE_HASH_NAMESPACE => "sealed-lattice-root/share-commitment-profile-hash-v1",
    BALLOT_PROOF_PROFILE_HASH_NAMESPACE => "sealed-lattice-root/ballot-proof-profile-hash-v1",
    BALLOT_PRIVACY_ROSTER_PROFILE_EVIDENCE_HASH_NAMESPACE => "sealed-lattice-root/ballot-privacy-roster-profile-evidence-hash-v1",
    SCORE_MEMBERSHIP_PROFILE_HASH_NAMESPACE => "sealed-lattice-root/score-membership-profile-hash-v1",
    BALLOT_SCORE_ENCODING_PROFILE_HASH_NAMESPACE => "sealed-lattice-root/ballot-score-encoding-profile-hash-v1",
    BALLOT_SHARE_LAYOUT_PROFILE_HASH_NAMESPACE => "sealed-lattice-root/ballot-share-layout-profile-hash-v1",
    AGGREGATE_INPUT_ENCODING_PROFILE_HASH_NAMESPACE => "sealed-lattice-root/aggregate-input-encoding-profile-hash-v1",
    ENCODED_SHARE_VECTOR_LAYOUT_HASH_NAMESPACE => "sealed-lattice-root/encoded-share-vector-layout-hash-v1",
    ENCODED_AGGREGATE_LAYOUT_HASH_NAMESPACE => "sealed-lattice-root/encoded-aggregate-layout-hash-v1",
    TOP_K_EVALUATOR_INPUT_LAYOUT_HASH_NAMESPACE => "sealed-lattice-root/top-k-evaluator-input-layout-hash-v1",
    SHARE_COMMITMENT_MESSAGE_BOUND_CERT_HASH_NAMESPACE => "sealed-lattice-root/share-commitment-message-bound-cert-hash-v1",
    RECEIVER_PAYLOAD_HASH_NAMESPACE => "sealed-lattice-root/receiver-payload-hash-v1",
    RECEIVER_PAYLOAD_CIPHERTEXT_ROOT_NAMESPACE => "sealed-lattice-root/receiver-payload-ciphertext-root-v1",
    RECEIVER_KEY_PROOF_ROOT_NAMESPACE => "sealed-lattice-root/receiver-key-proof-root-v1",
    BALLOT_PROOF_STATEMENT_HASH_NAMESPACE => "sealed-lattice-root/ballot-proof-statement-hash-v1",
    BALLOT_PROOF_RECORD_HASH_NAMESPACE => "sealed-lattice-root/ballot-proof-record-hash-v1",
    PROOF_BYTES_HASH_NAMESPACE => "sealed-lattice-root/proof-bytes-hash-v1",
    CHALLENGE_DOMAIN_HASH_NAMESPACE => "sealed-lattice-root/challenge-domain-hash-v1",
}

pub fn to_hex(bytes: &[u8]) -> String {
    const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(LOWER_HEX[(byte >> 4) as usize] as char);
        output.push(LOWER_HEX[(byte & 0x0f) as usize] as char);
    }

    output
}
/// Computes the protocol's domain-separated 64-byte SHAKE256 hash output.
///
/// The `Hash512` name describes the output length. Security is bounded by
/// SHAKE256, not by a generic 512-bit random-oracle claim.
///
/// This helper frames the `sealed.vote/v1/hash512` prefix, a caller-supplied
/// protocol step domain, and each supplied part. Claim-bearing protocol objects
/// must pass the frozen ceremony, statement, and encoded object material as
/// explicit framed parts rather than using an informal parallel convention.
pub fn hash512(domain: &str, parts: &[&[u8]]) -> [u8; 64] {
    let mut preimage = Vec::new();
    preimage.extend(HASH512_PREIMAGE_PREFIX);
    append_bytes(&mut preimage, domain.as_bytes());
    append_varuint(&mut preimage, parts.len() as u64);
    for part in parts {
        append_bytes(&mut preimage, part);
    }

    let mut hasher = Shake256::default();
    hasher.update(&preimage);
    let mut reader = hasher.finalize_xof();
    let mut output = [0_u8; 64];
    reader.read(&mut output);

    output
}

pub fn hash512_hex(domain: &str, parts: &[&[u8]]) -> String {
    to_hex(&hash512(domain, parts))
}

fn update_varuint(hasher: &mut Shake256, value: u64) {
    for byte in encode_varuint_for_hash(value) {
        hasher.update(&[byte]);
    }
}

fn encode_varuint_for_hash(mut value: u64) -> Vec<u8> {
    let mut output = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        output.push(byte);
        if value == 0 {
            break;
        }
    }

    output
}

fn update_bytes_prefix(hasher: &mut Shake256, value_length: usize) -> CanonicalResult<()> {
    let length = u64::try_from(value_length).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "hash input length does not fit u64",
        )
    })?;
    update_varuint(hasher, length);

    Ok(())
}

fn finalize_hash512_hex(hasher: Shake256) -> String {
    let mut reader = hasher.finalize_xof();
    let mut output = [0_u8; 64];
    reader.read(&mut output);

    to_hex(&output)
}

pub fn canonical_root(type_id: u64, version: u64, canonical_bytes: &[u8]) -> String {
    let mut type_id_bytes = Vec::new();
    append_varuint(&mut type_id_bytes, type_id);
    let mut version_bytes = Vec::new();
    append_varuint(&mut version_bytes, version);

    hash512_hex(
        "sealed-lattice-root/canonical-root-v1",
        &[&type_id_bytes, &version_bytes, canonical_bytes],
    )
}

pub fn object_root(canonical_bytes: &[u8]) -> String {
    canonical_root(1, 1, canonical_bytes)
}

pub fn namespace_root(namespace: &str, canonical_bytes: &[u8]) -> String {
    hash512_hex(namespace, &[canonical_bytes])
}

fn compare_utf16(left: &str, right: &str) -> Ordering {
    let mut left_units = left.encode_utf16();
    let mut right_units = right.encode_utf16();

    loop {
        match (left_units.next(), right_units.next()) {
            (Some(left_unit), Some(right_unit)) => match left_unit.cmp(&right_unit) {
                Ordering::Equal => {}
                ordering => return ordering,
            },
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (None, None) => return Ordering::Equal,
        }
    }
}

fn normalize_json_string(value: &str) -> Cow<'_, str> {
    if value.is_ascii() {
        Cow::Borrowed(value)
    } else {
        Cow::Owned(value.nfc().collect())
    }
}

fn serialize_json_string(value: &str) -> CanonicalResult<String> {
    serde_json::to_string(value).map_err(|error| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("canonical JSON string serialization failed: {error}"),
        )
    })
}

fn serialize_json_number(value: &serde_json::Number) -> CanonicalResult<String> {
    const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

    if let Some(unsigned_value) = value.as_u64() {
        if unsigned_value > MAX_SAFE_INTEGER {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "canonical JSON integers must be JavaScript-safe",
            ));
        }

        return Ok(unsigned_value.to_string());
    }
    if let Some(signed_value) = value.as_i64() {
        if signed_value.unsigned_abs() > MAX_SAFE_INTEGER {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "canonical JSON integers must be JavaScript-safe",
            ));
        }

        return Ok(signed_value.to_string());
    }

    Err(CanonicalError::new(
        CanonicalErrorCode::InvalidFixture,
        "canonical JSON values must not contain fractional numbers",
    ))
}

trait CanonicalJsonSink {
    fn write_str(&mut self, value: &str) -> CanonicalResult<()>;

    fn write_char(&mut self, value: char) -> CanonicalResult<()> {
        let mut buffer = [0_u8; 4];
        self.write_str(value.encode_utf8(&mut buffer))
    }
}

impl CanonicalJsonSink for String {
    fn write_str(&mut self, value: &str) -> CanonicalResult<()> {
        self.push_str(value);

        Ok(())
    }
}

struct HashingCanonicalJsonSink<'hasher> {
    hasher: &'hasher mut Shake256,
}

impl CanonicalJsonSink for HashingCanonicalJsonSink<'_> {
    fn write_str(&mut self, value: &str) -> CanonicalResult<()> {
        self.hasher.update(value.as_bytes());

        Ok(())
    }
}

struct ByteComparisonCanonicalJsonSink<'expected> {
    expected_bytes: &'expected [u8],
    offset: usize,
    matches: bool,
}

impl<'expected> ByteComparisonCanonicalJsonSink<'expected> {
    fn new(expected_bytes: &'expected [u8]) -> Self {
        Self {
            expected_bytes,
            offset: 0,
            matches: true,
        }
    }

    fn complete(self) -> bool {
        self.matches && self.offset == self.expected_bytes.len()
    }
}

impl CanonicalJsonSink for ByteComparisonCanonicalJsonSink<'_> {
    fn write_str(&mut self, value: &str) -> CanonicalResult<()> {
        if !self.matches {
            return Ok(());
        }

        let value_bytes = value.as_bytes();
        let end = self.offset.saturating_add(value_bytes.len());
        if self.expected_bytes.get(self.offset..end) != Some(value_bytes) {
            self.matches = false;
            return Ok(());
        }
        self.offset = end;

        Ok(())
    }
}

fn checked_len_add(left: usize, right: usize) -> CanonicalResult<usize> {
    left.checked_add(right).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "canonical JSON length overflowed usize",
        )
    })
}

fn serialized_json_string_len(value: &str) -> CanonicalResult<usize> {
    Ok(serialize_json_string(value)?.len())
}

fn canonical_json_len(value: &Value) -> CanonicalResult<usize> {
    match value {
        Value::Null => Ok(4),
        Value::Bool(boolean) => Ok(boolean.to_string().len()),
        Value::Number(number) => Ok(serialize_json_number(number)?.len()),
        Value::String(string) => serialized_json_string_len(&normalize_json_string(string)),
        Value::Array(items) => {
            let mut length = 2_usize;
            for (item_index, item) in items.iter().enumerate() {
                if item_index > 0 {
                    length = checked_len_add(length, 1)?;
                }
                length = checked_len_add(length, canonical_json_len(item)?)?;
            }

            Ok(length)
        }
        Value::Object(map) => {
            let mut entries = Vec::<String>::with_capacity(map.len());
            let mut length = 2_usize;
            for (key, entry_value) in map {
                let normalized_key = normalize_json_string(key).into_owned();
                if entries
                    .iter()
                    .any(|existing_key| existing_key == &normalized_key)
                {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::DuplicateField,
                        "canonical JSON object keys collide after normalization",
                    ));
                }
                entries.push(normalized_key.clone());
                if entries.len() > 1 {
                    length = checked_len_add(length, 1)?;
                }
                length = checked_len_add(length, serialized_json_string_len(&normalized_key)?)?;
                length = checked_len_add(length, 1)?;
                length = checked_len_add(length, canonical_json_len(entry_value)?)?;
            }

            Ok(length)
        }
    }
}

fn write_canonical_json(value: &Value, sink: &mut impl CanonicalJsonSink) -> CanonicalResult<()> {
    match value {
        Value::Null => sink.write_str("null"),
        Value::Bool(boolean) => sink.write_str(&boolean.to_string()),
        Value::Number(number) => sink.write_str(&serialize_json_number(number)?),
        Value::String(string) => {
            sink.write_str(&serialize_json_string(&normalize_json_string(string))?)
        }
        Value::Array(items) => {
            sink.write_char('[')?;
            for (item_index, item) in items.iter().enumerate() {
                if item_index > 0 {
                    sink.write_char(',')?;
                }
                write_canonical_json(item, sink)?;
            }
            sink.write_char(']')
        }
        Value::Object(map) => {
            let mut entries = Vec::<(String, &Value)>::with_capacity(map.len());
            for (key, entry_value) in map {
                let normalized_key = normalize_json_string(key).into_owned();
                if entries
                    .iter()
                    .any(|(existing_key, _)| existing_key == &normalized_key)
                {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::DuplicateField,
                        "canonical JSON object keys collide after normalization",
                    ));
                }
                entries.push((normalized_key, entry_value));
            }
            entries.sort_by(|left, right| compare_utf16(&left.0, &right.0));

            sink.write_char('{')?;
            for (entry_index, (key, entry_value)) in entries.iter().enumerate() {
                if entry_index > 0 {
                    sink.write_char(',')?;
                }
                sink.write_str(&serialize_json_string(key)?)?;
                sink.write_char(':')?;
                write_canonical_json(entry_value, sink)?;
            }
            sink.write_char('}')
        }
    }
}

pub fn canonical_json(value: &Value) -> CanonicalResult<String> {
    let mut output = String::with_capacity(canonical_json_len(value)?);
    write_canonical_json(value, &mut output)?;

    Ok(output)
}

pub fn canonical_json_matches_bytes(value: &Value, expected_bytes: &[u8]) -> CanonicalResult<bool> {
    if canonical_json_len(value)? != expected_bytes.len() {
        return Ok(false);
    }
    let mut sink = ByteComparisonCanonicalJsonSink::new(expected_bytes);
    write_canonical_json(value, &mut sink)?;

    Ok(sink.complete())
}

fn is_pascal_case_namespace(namespace: &str) -> bool {
    let mut chars = namespace.chars();
    let Some(first_char) = chars.next() else {
        return false;
    };

    first_char.is_ascii_uppercase() && chars.all(|character| character.is_ascii_alphanumeric())
}

fn pascal_case_to_kebab_case(namespace: &str) -> String {
    let chars: Vec<char> = namespace.chars().collect();
    let mut output = String::new();

    for (index, character) in chars.iter().copied().enumerate() {
        if character.is_ascii_uppercase() {
            let has_previous = index > 0;
            let previous_is_lower_or_digit = chars
                .get(index.saturating_sub(1))
                .is_some_and(|previous| previous.is_ascii_lowercase() || previous.is_ascii_digit());
            let previous_is_upper = chars
                .get(index.saturating_sub(1))
                .is_some_and(|previous| previous.is_ascii_uppercase());
            let next_is_lower = chars
                .get(index + 1)
                .is_some_and(|next| next.is_ascii_lowercase());

            if has_previous && (previous_is_lower_or_digit || (previous_is_upper && next_is_lower))
            {
                output.push('-');
            }
            output.push(character.to_ascii_lowercase());
        } else {
            output.push(character.to_ascii_lowercase());
        }
    }

    output
}

pub fn resolve_protocol_hash_domain(namespace: &str) -> CanonicalResult<String> {
    if namespace.starts_with("sealed-lattice-root/") {
        if RESERVED_ROOT_NAMESPACES.contains(&namespace) {
            return Ok(namespace.to_string());
        }

        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "protocol hash namespace domain is not reserved",
        ));
    }

    if !is_pascal_case_namespace(namespace) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "protocol hash namespace must be a reserved PascalCase name",
        ));
    }

    let domain = format!(
        "sealed-lattice-root/{}-v1",
        pascal_case_to_kebab_case(namespace)
    );
    if !RESERVED_ROOT_NAMESPACES.contains(&domain.as_str()) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "protocol hash namespace is not reserved",
        ));
    }

    Ok(domain)
}

pub fn derive_protocol_hash(namespace: &str, value: &Value) -> CanonicalResult<String> {
    let domain = resolve_protocol_hash_domain(namespace)?;
    let canonical_json_length = canonical_json_len(value)?;
    let mut hasher = Shake256::default();
    hasher.update(HASH512_PREIMAGE_PREFIX);
    update_bytes_prefix(&mut hasher, domain.len())?;
    hasher.update(domain.as_bytes());
    update_varuint(&mut hasher, 1);
    update_bytes_prefix(&mut hasher, canonical_json_length)?;
    write_canonical_json(
        value,
        &mut HashingCanonicalJsonSink {
            hasher: &mut hasher,
        },
    )?;

    Ok(finalize_hash512_hex(hasher))
}

fn write_ascii_json_string(value: &str, sink: &mut impl CanonicalJsonSink) -> CanonicalResult<()> {
    if !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte < 0x20 || byte == b'"' || byte == b'\\')
    {
        sink.write_str(&serialize_json_string(value)?)?;
        return Ok(());
    }

    sink.write_char('"')?;
    sink.write_str(value)?;
    sink.write_char('"')
}

fn ascii_json_string_len(value: &str) -> CanonicalResult<usize> {
    if !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte < 0x20 || byte == b'"' || byte == b'\\')
    {
        return serialized_json_string_len(value);
    }

    checked_len_add(value.len(), 2)
}

pub fn derive_protocol_hash_for_ascii_string_payload(
    namespace: &str,
    purpose: &str,
    field_name: &str,
    field_value: &str,
) -> CanonicalResult<String> {
    let domain = resolve_protocol_hash_domain(namespace)?;
    let mut entries = [(field_name, field_value), ("purpose", purpose)];
    entries.sort_by(|left, right| compare_utf16(left.0, right.0));

    let mut canonical_json_length = 2_usize;
    for (entry_index, (key, value)) in entries.iter().enumerate() {
        if entry_index > 0 {
            canonical_json_length = checked_len_add(canonical_json_length, 1)?;
        }
        canonical_json_length =
            checked_len_add(canonical_json_length, ascii_json_string_len(key)?)?;
        canonical_json_length = checked_len_add(canonical_json_length, 1)?;
        canonical_json_length =
            checked_len_add(canonical_json_length, ascii_json_string_len(value)?)?;
    }

    let mut hasher = Shake256::default();
    hasher.update(HASH512_PREIMAGE_PREFIX);
    update_bytes_prefix(&mut hasher, domain.len())?;
    hasher.update(domain.as_bytes());
    update_varuint(&mut hasher, 1);
    update_bytes_prefix(&mut hasher, canonical_json_length)?;
    let mut sink = HashingCanonicalJsonSink {
        hasher: &mut hasher,
    };
    sink.write_char('{')?;
    for (entry_index, (key, value)) in entries.iter().enumerate() {
        if entry_index > 0 {
            sink.write_char(',')?;
        }
        write_ascii_json_string(key, &mut sink)?;
        sink.write_char(':')?;
        write_ascii_json_string(value, &mut sink)?;
    }
    sink.write_char('}')?;

    Ok(finalize_hash512_hex(hasher))
}

pub fn derive_protocol_hash_for_proof_bytes_payload(
    proof_bytes_hex: &str,
    proof_size_bytes: u64,
) -> CanonicalResult<String> {
    const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
    if proof_size_bytes > MAX_SAFE_INTEGER {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "canonical JSON integers must be JavaScript-safe",
        ));
    }

    let domain = resolve_protocol_hash_domain("ProofBytesHash")?;
    let proof_size_bytes_string = proof_size_bytes.to_string();
    let fixed_prefix = "{\"objectType\":\"ProofBytes\",\"objectVersion\":1,\"proofBytesHex\":";
    let fixed_middle = ",\"proofSizeBytes\":";
    let fixed_suffix = "}";
    let canonical_json_length = checked_len_add(
        checked_len_add(
            checked_len_add(
                checked_len_add(fixed_prefix.len(), ascii_json_string_len(proof_bytes_hex)?)?,
                fixed_middle.len(),
            )?,
            proof_size_bytes_string.len(),
        )?,
        fixed_suffix.len(),
    )?;

    let mut hasher = Shake256::default();
    hasher.update(HASH512_PREIMAGE_PREFIX);
    update_bytes_prefix(&mut hasher, domain.len())?;
    hasher.update(domain.as_bytes());
    update_varuint(&mut hasher, 1);
    update_bytes_prefix(&mut hasher, canonical_json_length)?;
    let mut sink = HashingCanonicalJsonSink {
        hasher: &mut hasher,
    };
    sink.write_str(fixed_prefix)?;
    write_ascii_json_string(proof_bytes_hex, &mut sink)?;
    sink.write_str(fixed_middle)?;
    sink.write_str(&proof_size_bytes_string)?;
    sink.write_str(fixed_suffix)?;

    Ok(finalize_hash512_hex(hasher))
}

fn chunk_leaf(index: u64, chunk: &[u8]) -> [u8; 64] {
    let mut index_bytes = Vec::new();
    append_varuint(&mut index_bytes, index);

    hash512("transcript-core/chunk-leaf", &[&index_bytes, chunk])
}

fn chunk_node(left: &[u8], right: &[u8]) -> [u8; 64] {
    hash512("transcript-core/chunk-node", &[left, right])
}

pub fn chunk_root(input: &[u8], chunk_size: usize) -> CanonicalResult<String> {
    if chunk_size == 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidChunkSize,
            "chunk size must be greater than zero",
        ));
    }

    let mut leaves: Vec<[u8; 64]> = input
        .chunks(chunk_size)
        .enumerate()
        .map(|(index, chunk)| chunk_leaf(index as u64, chunk))
        .collect();

    if leaves.is_empty() {
        leaves.push(hash512("transcript-core/chunk-empty", &[]));
    }

    while leaves.len() > 1 {
        let mut next_level = Vec::with_capacity(leaves.len().div_ceil(2));
        let mut index = 0;
        while index < leaves.len() {
            let left = leaves[index];
            let right = if index + 1 < leaves.len() {
                leaves[index + 1]
            } else {
                left
            };
            next_level.push(chunk_node(&left, &right));
            index += 2;
        }
        leaves = next_level;
    }

    let mut chunk_size_bytes = Vec::new();
    append_varuint(&mut chunk_size_bytes, chunk_size as u64);
    let mut input_length_bytes = Vec::new();
    append_varuint(&mut input_length_bytes, input.len() as u64);

    Ok(hash512_hex(
        "transcript-core/chunk-root",
        &[&chunk_size_bytes, &input_length_bytes, &leaves[0]],
    ))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{
        POLL_SPEC_HASH_NAMESPACE, RESERVED_ROOT_NAMESPACES, canonical_json,
        canonical_json_matches_bytes, canonical_root, chunk_root, derive_protocol_hash,
        derive_protocol_hash_for_ascii_string_payload,
        derive_protocol_hash_for_proof_bytes_payload, hash512, hash512_hex, namespace_root,
        resolve_protocol_hash_domain,
    };

    #[test]
    fn hash512_outputs_sixty_four_bytes() {
        assert_eq!(hash512("transcript-core/test", &[b"input"]).len(), 64);
    }

    #[test]
    fn hash512_is_domain_separated() {
        let left = hash512_hex("transcript-core/a", &[b"same"]);
        let right = hash512_hex("transcript-core/b", &[b"same"]);

        assert_ne!(left, right);
    }

    #[test]
    fn canonical_json_matches_the_typescript_reference_shape() {
        let canonical = canonical_json(&serde_json::json!({
            "b": [2, 1],
            "a": {
                "z": true
            }
        }))
        .expect("canonical JSON should serialize supported values");

        assert_eq!(canonical, "{\"a\":{\"z\":true},\"b\":[2,1]}");
        assert!(canonical_json(&serde_json::json!({ "fraction": 1.5 })).is_err());
    }

    #[test]
    fn canonical_json_byte_comparison_matches_streamed_encoding() {
        let value = serde_json::json!({
            "z": [true, null, "plain-ascii"],
            "a": { "nested": 17 }
        });
        let canonical = canonical_json(&value).expect("canonical JSON should serialize");

        assert!(
            canonical_json_matches_bytes(&value, canonical.as_bytes())
                .expect("byte comparison should run")
        );
        assert!(
            !canonical_json_matches_bytes(&value, b"{\"a\":0}")
                .expect("byte comparison should reject mismatched bytes")
        );
    }

    #[test]
    fn ascii_string_payload_hash_matches_canonical_json_hash() {
        let specialized = derive_protocol_hash_for_ascii_string_payload(
            "ProofBytesHash",
            "sealed-lattice-test-proof-bytes-v1",
            "proofBytesHex",
            "abcdef012345",
        )
        .expect("specialized hash should derive");
        let generic = derive_protocol_hash(
            "ProofBytesHash",
            &serde_json::json!({
                "purpose": "sealed-lattice-test-proof-bytes-v1",
                "proofBytesHex": "abcdef012345",
            }),
        )
        .expect("generic hash should derive");

        assert_eq!(specialized, generic);
    }

    #[test]
    fn proof_bytes_payload_hash_matches_canonical_json_hash() {
        let proof_bytes_hex = "abcdef012345";
        let specialized = derive_protocol_hash_for_proof_bytes_payload(
            proof_bytes_hex,
            proof_bytes_hex.len() as u64 / 2,
        )
        .expect("specialized hash should derive");
        let generic = derive_protocol_hash(
            "ProofBytesHash",
            &serde_json::json!({
                "objectType": "ProofBytes",
                "objectVersion": 1,
                "proofBytesHex": proof_bytes_hex,
                "proofSizeBytes": proof_bytes_hex.len() / 2,
            }),
        )
        .expect("generic hash should derive");

        assert_eq!(specialized, generic);
    }

    #[test]
    fn derives_protocol_hash_from_reserved_pascal_case_namespaces() {
        assert_eq!(
            resolve_protocol_hash_domain("PollSpecHash").expect("namespace should resolve"),
            POLL_SPEC_HASH_NAMESPACE
        );
        assert_eq!(
            derive_protocol_hash(
                "PollSpecHash",
                &serde_json::json!({
                    "poll": "main"
                }),
            )
            .expect("protocol hash should derive"),
            "43b28c9a3dcb3e34d75c9936a9930b68fb9f2010b87d43a6a61cbaa85d343d9fd0be2b312a90f404367b9c68793b0dcf02c4dae7351f6e96ded894b92f898cb4"
        );
        assert!(resolve_protocol_hash_domain("AuxiliaryHash").is_err());
    }

    #[test]
    fn canonical_root_binds_object_type_and_version() {
        let canonical_bytes = b"canonical";

        assert_ne!(
            canonical_root(1, 1, canonical_bytes),
            canonical_root(2, 1, canonical_bytes),
        );
        assert_ne!(
            canonical_root(1, 1, canonical_bytes),
            canonical_root(1, 2, canonical_bytes),
        );
    }

    #[test]
    fn reserved_root_namespaces_are_unique_and_domain_separated() {
        let namespace_set: BTreeSet<&str> = RESERVED_ROOT_NAMESPACES.iter().copied().collect();
        assert_eq!(namespace_set.len(), RESERVED_ROOT_NAMESPACES.len());

        let input = b"same canonical bytes";
        let root_set: BTreeSet<String> = RESERVED_ROOT_NAMESPACES
            .iter()
            .map(|namespace| namespace_root(namespace, input))
            .collect();

        assert_eq!(root_set.len(), RESERVED_ROOT_NAMESPACES.len());
    }

    #[test]
    fn chunk_root_changes_with_chunk_size() {
        let input = b"0123456789abcdef";

        assert_ne!(
            chunk_root(input, 4).expect("chunk root should compute"),
            chunk_root(input, 8).expect("chunk root should compute"),
        );
    }

    #[test]
    fn chunk_root_separates_empty_input_from_zero_leaf_input() {
        assert_ne!(
            chunk_root(&[], 1).expect("empty chunk root should compute"),
            chunk_root(&[0], 1).expect("single zero chunk root should compute"),
        );
        assert_ne!(
            chunk_root(&[], 64).expect("empty chunk root should compute"),
            chunk_root(&[0; 64], 64).expect("full zero chunk root should compute"),
        );
    }
}
