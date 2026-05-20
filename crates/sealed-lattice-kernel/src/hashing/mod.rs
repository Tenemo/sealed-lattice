use serde_json::Value;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::cmp::Ordering;
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
    POLL_SPEC_DIGEST_NAMESPACE => "sealed-lattice-root/poll-spec-digest-v1",
    BOARD_ENTRY_DIGEST_NAMESPACE => "sealed-lattice-root/board-entry-digest-v1",
    BOARD_ROOT_DIGEST_NAMESPACE => "sealed-lattice-root/board-root-digest-v1",
    BOARD_POLICY_DIGEST_NAMESPACE => "sealed-lattice-root/board-policy-digest-v1",
    PUBLIC_KEY_DIGEST_NAMESPACE => "sealed-lattice-root/public-key-digest-v1",
    REGISTRATION_ENTRY_DIGEST_NAMESPACE => "sealed-lattice-root/registration-entry-digest-v1",
    RECEIVER_KEY_REGISTRATION_DIGEST_NAMESPACE => "sealed-lattice-root/receiver-key-registration-digest-v1",
    TRUSTEE_SETUP_ENTRY_DIGEST_NAMESPACE => "sealed-lattice-root/trustee-setup-entry-digest-v1",
    ELECTION_MANIFEST_DIGEST_NAMESPACE => "sealed-lattice-root/election-manifest-digest-v1",
    ROSTER_DIGEST_NAMESPACE => "sealed-lattice-root/roster-digest-v1",
    ROSTER_EXTERNAL_ACCEPTANCE_DIGEST_NAMESPACE => "sealed-lattice-root/roster-external-acceptance-digest-v1",
    BOARD_HEAD_DIGEST_NAMESPACE => "sealed-lattice-root/board-head-digest-v1",
    RECOVERY_EPOCH_UPDATE_DIGEST_NAMESPACE => "sealed-lattice-root/recovery-epoch-update-digest-v1",
    ACTION_CONTEXT_DIGEST_NAMESPACE => "sealed-lattice-root/action-context-digest-v1",
    BALLOT_PACKAGE_DIGEST_NAMESPACE => "sealed-lattice-root/ballot-package-digest-v1",
    BALLOT_SET_DIGEST_NAMESPACE => "sealed-lattice-root/ballot-set-digest-v1",
    CAST_RECEIPT_DIGEST_NAMESPACE => "sealed-lattice-root/cast-receipt-digest-v1",
    CLOSE_RECORD_DIGEST_NAMESPACE => "sealed-lattice-root/close-record-digest-v1",
    WITNESS_CHECKPOINT_DIGEST_NAMESPACE => "sealed-lattice-root/witness-checkpoint-digest-v1",
    CONFLICTING_HEAD_EVIDENCE_DIGEST_NAMESPACE => "sealed-lattice-root/conflicting-head-evidence-digest-v1",
    WITNESS_EQUIVOCATION_EVIDENCE_DIGEST_NAMESPACE => "sealed-lattice-root/witness-equivocation-evidence-digest-v1",
    INCLUSION_PROOF_DIGEST_NAMESPACE => "sealed-lattice-root/inclusion-proof-digest-v1",
    FIRST_VALID_ORDER_DIGEST_NAMESPACE => "sealed-lattice-root/first-valid-order-digest-v1",
    DUPLICATE_BALLOT_POLICY_DIGEST_NAMESPACE => "sealed-lattice-root/duplicate-ballot-policy-digest-v1",
    FIRST_VALID_POLICY_DIGEST_NAMESPACE => "sealed-lattice-root/first-valid-policy-digest-v1",
    TARGET_FINALITY_POLICY_DIGEST_NAMESPACE => "sealed-lattice-root/target-finality-policy-digest-v1",
    WITNESS_POLICY_DIGEST_NAMESPACE => "sealed-lattice-root/witness-policy-digest-v1",
    RECOVERY_POLICY_DIGEST_NAMESPACE => "sealed-lattice-root/recovery-policy-digest-v1",
    SIGNED_ROOT_DIGEST_NAMESPACE => "sealed-lattice-root/signed-root-digest-v1",
    PROTOCOL_SIGNATURE_ENVELOPE_DIGEST_NAMESPACE => "sealed-lattice-root/protocol-signature-envelope-digest-v1",
    PROVIDER_BUILD_DIGEST_NAMESPACE => "sealed-lattice-root/provider-build-digest-v1",
    ML_DSA_FIXTURE_SEED_DIGEST_NAMESPACE => "sealed-lattice-root/ml-dsa-fixture-seed-digest-v1",
    THRESHOLD_PROFILE_DIGEST_NAMESPACE => "sealed-lattice-root/threshold-profile-digest-v1",
    HE_PARAM_DIGEST_NAMESPACE => "sealed-lattice-root/he-param-digest-v1",
    BGV_PROFILE_DIGEST_NAMESPACE => "sealed-lattice-root/bgv-profile-digest-v1",
    CIPHERTEXT_ROOT_NAMESPACE => "sealed-lattice-root/ciphertext-root-v1",
    PLAINTEXT_ROOT_NAMESPACE => "sealed-lattice-root/plaintext-root-v1",
    PLAINTEXT_TALLY_DIGEST_NAMESPACE => "sealed-lattice-root/plaintext-tally-digest-v1",
    PLAINTEXT_TOP_K_ORACLE_DIGEST_NAMESPACE => "sealed-lattice-root/plaintext-top-k-oracle-digest-v1",
    INTERPOLATION_COEFFICIENT_REPORT_DIGEST_NAMESPACE => "sealed-lattice-root/interpolation-coefficient-report-digest-v1",
    WORST_CASE_INTERPOLATION_COEFFICIENT_REPORT_DIGEST_NAMESPACE => "sealed-lattice-root/worst-case-interpolation-coefficient-report-digest-v1",
    SPARSE_TOP_K_TARGET_DIGEST_NAMESPACE => "sealed-lattice-root/sparse-top-k-target-digest-v1",
    BGV_PUBLIC_KEY_ROOT_NAMESPACE => "sealed-lattice-root/bgv-public-key-root-v1",
    COLLECTIVE_PUBLIC_KEY_ROOT_NAMESPACE => "sealed-lattice-root/collective-public-key-root-v1",
    EVAL_KEY_ROOT_NAMESPACE => "sealed-lattice-root/eval-key-root-v1",
    TOP_K_CIRCUIT_DIGEST_NAMESPACE => "sealed-lattice-root/top-k-circuit-digest-v1",
    ROT_SET_DIGEST_NAMESPACE => "sealed-lattice-root/rot-set-digest-v1",
    TARGET_LAYOUT_DIGEST_NAMESPACE => "sealed-lattice-root/target-layout-digest-v1",
    PUBLIC_SLOT_MASK_DIGEST_NAMESPACE => "sealed-lattice-root/public-slot-mask-digest-v1",
    AGGREGATE_DERIVATION_COMPONENT_DIGEST_NAMESPACE => "sealed-lattice-root/aggregate-derivation-component-digest-v1",
    AGGREGATE_CONTRIBUTION_DIGEST_NAMESPACE => "sealed-lattice-root/aggregate-contribution-digest-v1",
    AGGREGATE_READY_RECORD_DIGEST_NAMESPACE => "sealed-lattice-root/aggregate-ready-record-digest-v1",
    AGGREGATE_SELECTION_POLICY_DIGEST_NAMESPACE => "sealed-lattice-root/aggregate-selection-policy-digest-v1",
    POST_VOTING_CLOSED_CONTEXT_DIGEST_NAMESPACE => "sealed-lattice-root/post-voting-closed-context-digest-v1",
    EVALUATION_CONTEXT_DIGEST_NAMESPACE => "sealed-lattice-root/evaluation-context-digest-v1",
    TOP_K_EVALUATION_RECORD_DIGEST_NAMESPACE => "sealed-lattice-root/top-k-evaluation-record-digest-v1",
    TARGET_PROPOSAL_DIGEST_NAMESPACE => "sealed-lattice-root/target-proposal-digest-v1",
    TARGET_FINALITY_CHECKPOINT_DIGEST_NAMESPACE => "sealed-lattice-root/target-finality-checkpoint-digest-v1",
    TARGET_FINALITY_RECORD_DIGEST_NAMESPACE => "sealed-lattice-root/target-finality-record-digest-v1",
    EVALUATION_PROOF_RECORD_DIGEST_NAMESPACE => "sealed-lattice-root/evaluation-proof-record-digest-v1",
    EVALUATION_PROOF_PROFILE_DIGEST_NAMESPACE => "sealed-lattice-root/evaluation-proof-profile-digest-v1",
    TARGET_ACCEPTED_RECORD_DIGEST_NAMESPACE => "sealed-lattice-root/target-accepted-record-digest-v1",
    TARGET_PREIMAGE_DIGEST_NAMESPACE => "sealed-lattice-root/target-preimage-digest-v1",
    TARGET_CONTEXT_DIGEST_NAMESPACE => "sealed-lattice-root/target-context-digest-v1",
    LOCAL_REPLAY_RECORD_DIGEST_NAMESPACE => "sealed-lattice-root/local-replay-record-digest-v1",
    MOBILE_REPLAY_CERT_DIGEST_NAMESPACE => "sealed-lattice-root/mobile-replay-cert-digest-v1",
    CPAD_PROFILE_DIGEST_NAMESPACE => "sealed-lattice-root/cpad-profile-digest-v1",
    CPAD_PROFILE_VERIFICATION_DIGEST_NAMESPACE => "sealed-lattice-root/cpad-profile-verification-digest-v1",
    THRESHOLD_DECRYPTION_PROFILE_DIGEST_NAMESPACE => "sealed-lattice-root/threshold-decryption-profile-digest-v1",
    BGV_ASYNC_THRESHOLD_CPAD_PROFILE_DIGEST_NAMESPACE => "sealed-lattice-root/bgv-async-threshold-cpad-profile-digest-v1",
    TOP_K_DECRYPTION_SHARE_DIGEST_NAMESPACE => "sealed-lattice-root/top-k-decryption-share-digest-v1",
    VERIFIED_TOP_K_RESULT_DIGEST_NAMESPACE => "sealed-lattice-root/verified-top-k-result-digest-v1",
    BRIDGE_PROOF_RECORD_DIGEST_NAMESPACE => "sealed-lattice-root/bridge-proof-record-digest-v1",
    BRIDGE_PROOF_PROFILE_DIGEST_NAMESPACE => "sealed-lattice-root/bridge-proof-profile-digest-v1",
    DIRECT_TARGET_BASIS_DATA_BRIDGE_PROFILE_DIGEST_NAMESPACE => "sealed-lattice-root/direct-target-basis-data-bridge-profile-digest-v1",
    ACTUAL_AGGREGATE_CIPHERTEXT_ROOT_NAMESPACE => "sealed-lattice-root/actual-aggregate-ciphertext-root-v1",
    CANONICAL_CIPHERTEXT_CONVENTION_DIGEST_NAMESPACE => "sealed-lattice-root/canonical-ciphertext-convention-digest-v1",
    BGV_BATCH_ENCODER_DIGEST_NAMESPACE => "sealed-lattice-root/bgv-batch-encoder-digest-v1",
    EVALUATION_NOISE_PROFILE_DIGEST_NAMESPACE => "sealed-lattice-root/evaluation-noise-profile-digest-v1",
    HE_EVALUATION_NOISE_CERT_DIGEST_NAMESPACE => "sealed-lattice-root/he-evaluation-noise-cert-digest-v1",
    ALLOWED_EVALUATOR_OPS_DIGEST_NAMESPACE => "sealed-lattice-root/allowed-evaluator-ops-digest-v1",
    EVALUATOR_PROGRAM_DIGEST_NAMESPACE => "sealed-lattice-root/evaluator-program-digest-v1",
    BRIDGE_LAYOUT_DIGEST_NAMESPACE => "sealed-lattice-root/bridge-layout-digest-v1",
    AGGREGATE_SHARE_COMMITMENT_DIGEST_NAMESPACE => "sealed-lattice-root/aggregate-share-commitment-digest-v1",
    SHARE_COMMITMENT_DIGEST_NAMESPACE => "sealed-lattice-root/share-commitment-digest-v1",
    BALLOT_POLYNOMIAL_SET_DIGEST_NAMESPACE => "sealed-lattice-root/ballot-polynomial-set-digest-v1",
    TEST_RECEIVER_SHARE_OPENING_PAYLOAD_DIGEST_NAMESPACE => "sealed-lattice-root/test-receiver-share-opening-payload-digest-v1",
    THRESHOLD_SHARE_VERIFICATION_KEY_ROOT_NAMESPACE => "sealed-lattice-root/threshold-share-verification-key-root-v1",
    THRESHOLD_SHARE_VERIFICATION_KEY_DIGEST_NAMESPACE => "sealed-lattice-root/threshold-share-verification-key-digest-v1",
    TRUSTEE_THRESHOLD_VERIFICATION_KEY_DIGEST_NAMESPACE => "sealed-lattice-root/trustee-threshold-verification-key-digest-v1",
    TARGET_DECRYPTION_PREPARATION_RECORD_DIGEST_NAMESPACE => "sealed-lattice-root/target-decryption-preparation-record-digest-v1",
    TARGET_DECRYPTION_CIPHERTEXT_DIGEST_NAMESPACE => "sealed-lattice-root/target-decryption-ciphertext-digest-v1",
    SHARE_REPLAY_EVIDENCE_DIGEST_NAMESPACE => "sealed-lattice-root/share-replay-evidence-digest-v1",
    SHARE_REPLAY_REFUSAL_DIGEST_NAMESPACE => "sealed-lattice-root/share-replay-refusal-digest-v1",
    TARGET_BASIS_DIGEST_NAMESPACE => "sealed-lattice-root/target-basis-digest-v1",
    MOBILE_PROFILE_CERT_DIGEST_NAMESPACE => "sealed-lattice-root/mobile-profile-cert-digest-v1",
    BRIDGE_MOBILE_CERT_DIGEST_NAMESPACE => "sealed-lattice-root/bridge-mobile-cert-digest-v1",
    BRIDGE_BATCHING_CERT_DIGEST_NAMESPACE => "sealed-lattice-root/bridge-batching-cert-digest-v1",
    AGGREGATE_BRIDGE_PROVER_CERT_DIGEST_NAMESPACE => "sealed-lattice-root/aggregate-bridge-prover-cert-digest-v1",
    ENCRYPTED_ENVELOPE_ROOT_NAMESPACE => "sealed-lattice-root/encrypted-envelope-root-v1",
    RECEIVER_ENCRYPTION_PROFILE_DIGEST_NAMESPACE => "sealed-lattice-root/receiver-encryption-profile-digest-v1",
    SHARE_COMMITMENT_PROFILE_DIGEST_NAMESPACE => "sealed-lattice-root/share-commitment-profile-digest-v1",
    BALLOT_PROOF_PROFILE_DIGEST_NAMESPACE => "sealed-lattice-root/ballot-proof-profile-digest-v1",
    SCORE_MEMBERSHIP_PROFILE_DIGEST_NAMESPACE => "sealed-lattice-root/score-membership-profile-digest-v1",
    BALLOT_SCORE_ENCODING_PROFILE_DIGEST_NAMESPACE => "sealed-lattice-root/ballot-score-encoding-profile-digest-v1",
    BALLOT_SHARE_LAYOUT_PROFILE_DIGEST_NAMESPACE => "sealed-lattice-root/ballot-share-layout-profile-digest-v1",
    AGGREGATE_INPUT_ENCODING_PROFILE_DIGEST_NAMESPACE => "sealed-lattice-root/aggregate-input-encoding-profile-digest-v1",
    ENCODED_SHARE_VECTOR_LAYOUT_DIGEST_NAMESPACE => "sealed-lattice-root/encoded-share-vector-layout-digest-v1",
    ENCODED_AGGREGATE_LAYOUT_DIGEST_NAMESPACE => "sealed-lattice-root/encoded-aggregate-layout-digest-v1",
    SHARE_COMMITMENT_MESSAGE_BOUND_CERT_DIGEST_NAMESPACE => "sealed-lattice-root/share-commitment-message-bound-cert-digest-v1",
    RECEIVER_PAYLOAD_DIGEST_NAMESPACE => "sealed-lattice-root/receiver-payload-digest-v1",
    RECEIVER_PAYLOAD_CIPHERTEXT_ROOT_NAMESPACE => "sealed-lattice-root/receiver-payload-ciphertext-root-v1",
    RECEIVER_KEY_PROOF_ROOT_NAMESPACE => "sealed-lattice-root/receiver-key-proof-root-v1",
    BALLOT_PROOF_STATEMENT_DIGEST_NAMESPACE => "sealed-lattice-root/ballot-proof-statement-digest-v1",
    BALLOT_PROOF_RECORD_DIGEST_NAMESPACE => "sealed-lattice-root/ballot-proof-record-digest-v1",
    PROOF_BYTES_DIGEST_NAMESPACE => "sealed-lattice-root/proof-bytes-digest-v1",
    CHALLENGE_DOMAIN_DIGEST_NAMESPACE => "sealed-lattice-root/challenge-domain-digest-v1",
}

pub fn to_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
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

fn normalize_json_string(value: &str) -> String {
    value.nfc().collect()
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

pub fn canonical_json(value: &Value) -> CanonicalResult<String> {
    match value {
        Value::Null => Ok("null".to_string()),
        Value::Bool(boolean) => Ok(boolean.to_string()),
        Value::Number(number) => serialize_json_number(number),
        Value::String(string) => serialize_json_string(&normalize_json_string(string)),
        Value::Array(items) => {
            let mut output = String::from("[");
            for (item_index, item) in items.iter().enumerate() {
                if item_index > 0 {
                    output.push(',');
                }
                output.push_str(&canonical_json(item)?);
            }
            output.push(']');

            Ok(output)
        }
        Value::Object(map) => {
            let mut entries = Vec::<(String, String)>::with_capacity(map.len());
            for (key, entry_value) in map {
                let normalized_key = normalize_json_string(key);
                if entries
                    .iter()
                    .any(|(existing_key, _)| existing_key == &normalized_key)
                {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::DuplicateField,
                        "canonical JSON object keys collide after normalization",
                    ));
                }
                entries.push((normalized_key, canonical_json(entry_value)?));
            }
            entries.sort_by(|left, right| compare_utf16(&left.0, &right.0));

            let mut output = String::from("{");
            for (entry_index, (key, entry_value)) in entries.iter().enumerate() {
                if entry_index > 0 {
                    output.push(',');
                }
                output.push_str(&serialize_json_string(key)?);
                output.push(':');
                output.push_str(entry_value);
            }
            output.push('}');

            Ok(output)
        }
    }
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

pub fn resolve_protocol_digest_domain(namespace: &str) -> CanonicalResult<String> {
    if namespace.starts_with("sealed-lattice-root/") {
        if RESERVED_ROOT_NAMESPACES.contains(&namespace) {
            return Ok(namespace.to_string());
        }

        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "protocol digest namespace domain is not reserved",
        ));
    }

    if !is_pascal_case_namespace(namespace) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "protocol digest namespace must be a reserved PascalCase name",
        ));
    }

    let domain = format!(
        "sealed-lattice-root/{}-v1",
        pascal_case_to_kebab_case(namespace)
    );
    if !RESERVED_ROOT_NAMESPACES.contains(&domain.as_str()) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "protocol digest namespace is not reserved",
        ));
    }

    Ok(domain)
}

pub fn derive_protocol_digest(namespace: &str, value: &Value) -> CanonicalResult<String> {
    let domain = resolve_protocol_digest_domain(namespace)?;
    let canonical_json = canonical_json(value)?;

    Ok(namespace_root(&domain, canonical_json.as_bytes()))
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
        POLL_SPEC_DIGEST_NAMESPACE, RESERVED_ROOT_NAMESPACES, canonical_json, canonical_root,
        chunk_root, derive_protocol_digest, hash512, hash512_hex, namespace_root,
        resolve_protocol_digest_domain,
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
    fn derives_protocol_digest_from_reserved_pascal_case_namespaces() {
        assert_eq!(
            resolve_protocol_digest_domain("PollSpecDigest").expect("namespace should resolve"),
            POLL_SPEC_DIGEST_NAMESPACE
        );
        assert_eq!(
            derive_protocol_digest(
                "PollSpecDigest",
                &serde_json::json!({
                    "poll": "main"
                }),
            )
            .expect("protocol digest should derive"),
            "423c71de65abadb5adc05d9b6b704252420bb738af888c62614c8afc53a2be808662585305e76738b23e4f20154f8779e3827c0c8f313455d84675924f4a2c83"
        );
        assert!(resolve_protocol_digest_domain("AuxiliaryDigest").is_err());
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
