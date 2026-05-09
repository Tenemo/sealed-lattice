use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use crate::encoding::{
    CanonicalError, CanonicalErrorCode, CanonicalResult, append_bytes, append_varuint,
};

pub const MODULE_MARKER: &str = "hashing";
pub const HASH512_PREIMAGE_PREFIX: &[u8] = b"sealed.vote/v1/hash512";

pub const MANIFEST_DIGEST_NAMESPACE: &str = "sealed-lattice-root/manifest-digest-v1";
pub const ROSTER_DIGEST_NAMESPACE: &str = "sealed-lattice-root/roster-digest-v1";
pub const BOARD_HEAD_HASH_NAMESPACE: &str = "sealed-lattice-root/board-head-hash-v1";
pub const RECOVERY_EPOCH_UPDATE_DIGEST_NAMESPACE: &str =
    "sealed-lattice-root/recovery-epoch-update-digest-v1";
pub const ACTION_CONTEXT_DIGEST_NAMESPACE: &str = "sealed-lattice-root/action-context-digest-v1";
pub const CANONICAL_BALLOT_SET_DIGEST_NAMESPACE: &str =
    "sealed-lattice-root/canonical-ballot-set-digest-v1";
pub const HE_PARAM_DIGEST_NAMESPACE: &str = "sealed-lattice-root/he-param-digest-v1";
pub const CIPHERTEXT_ROOT_NAMESPACE: &str = "sealed-lattice-root/ciphertext-root-v1";
pub const PLAINTEXT_ROOT_NAMESPACE: &str = "sealed-lattice-root/plaintext-root-v1";
pub const EVAL_KEY_ROOT_NAMESPACE: &str = "sealed-lattice-root/eval-key-root-v1";
pub const TOP_K_CIRCUIT_DIGEST_NAMESPACE: &str = "sealed-lattice-root/top-k-circuit-digest-v1";
pub const AGGREGATE_CONTRIBUTION_DIGEST_NAMESPACE: &str =
    "sealed-lattice-root/aggregate-contribution-digest-v1";
pub const AGGREGATE_READY_RECORD_DIGEST_NAMESPACE: &str =
    "sealed-lattice-root/aggregate-ready-record-digest-v1";
pub const EVALUATION_CONTEXT_DIGEST_NAMESPACE: &str =
    "sealed-lattice-root/evaluation-context-digest-v1";
pub const TOP_K_EVALUATION_RECORD_DIGEST_NAMESPACE: &str =
    "sealed-lattice-root/top-k-evaluation-record-digest-v1";
pub const ROT_SET_DIGEST_NAMESPACE: &str = "sealed-lattice-root/rot-set-digest-v1";
pub const TARGET_LAYOUT_DIGEST_NAMESPACE: &str = "sealed-lattice-root/target-layout-digest-v1";
pub const PUBLIC_SLOT_MASK_DIGEST_NAMESPACE: &str =
    "sealed-lattice-root/public-slot-mask-digest-v1";
pub const TARGET_FINALITY_RECORD_NAMESPACE: &str = "sealed-lattice-root/target-finality-record-v1";
pub const ACCEPTED_TARGET_FINALITY_CHECKPOINT_DIGEST_NAMESPACE: &str =
    "sealed-lattice-root/accepted-target-finality-checkpoint-digest-v1";
pub const EVALUATION_REPLAY_ATTESTATION_DIGEST_NAMESPACE: &str =
    "sealed-lattice-root/evaluation-replay-attestation-digest-v1";
pub const TARGET_ACCEPTED_RECORD_DIGEST_NAMESPACE: &str =
    "sealed-lattice-root/target-accepted-record-digest-v1";
pub const TARGET_PREIMAGE_DIGEST_NAMESPACE: &str = "sealed-lattice-root/target-preimage-digest-v1";
pub const CPAD_PROFILE_DIGEST_NAMESPACE: &str = "sealed-lattice-root/cpad-profile-digest-v1";
pub const THRESHOLD_DECRYPTION_PROFILE_DIGEST_NAMESPACE: &str =
    "sealed-lattice-root/threshold-decryption-profile-digest-v1";
pub const TOP_K_DECRYPTION_SHARE_DIGEST_NAMESPACE: &str =
    "sealed-lattice-root/top-k-decryption-share-digest-v1";
pub const VERIFIED_TOP_K_RESULT_DIGEST_NAMESPACE: &str =
    "sealed-lattice-root/verified-top-k-result-digest-v1";
pub const ENCRYPTED_ENVELOPE_ROOT_NAMESPACE: &str =
    "sealed-lattice-root/encrypted-envelope-root-v1";
pub const EVALUATION_PROOF_ROOT_NAMESPACE: &str = "sealed-lattice-root/evaluation-proof-root-v1";

pub const RESERVED_ROOT_NAMESPACES: [&str; 29] = [
    MANIFEST_DIGEST_NAMESPACE,
    ROSTER_DIGEST_NAMESPACE,
    BOARD_HEAD_HASH_NAMESPACE,
    RECOVERY_EPOCH_UPDATE_DIGEST_NAMESPACE,
    ACTION_CONTEXT_DIGEST_NAMESPACE,
    CANONICAL_BALLOT_SET_DIGEST_NAMESPACE,
    HE_PARAM_DIGEST_NAMESPACE,
    CIPHERTEXT_ROOT_NAMESPACE,
    PLAINTEXT_ROOT_NAMESPACE,
    EVAL_KEY_ROOT_NAMESPACE,
    TOP_K_CIRCUIT_DIGEST_NAMESPACE,
    AGGREGATE_CONTRIBUTION_DIGEST_NAMESPACE,
    AGGREGATE_READY_RECORD_DIGEST_NAMESPACE,
    EVALUATION_CONTEXT_DIGEST_NAMESPACE,
    TOP_K_EVALUATION_RECORD_DIGEST_NAMESPACE,
    ROT_SET_DIGEST_NAMESPACE,
    TARGET_LAYOUT_DIGEST_NAMESPACE,
    PUBLIC_SLOT_MASK_DIGEST_NAMESPACE,
    TARGET_FINALITY_RECORD_NAMESPACE,
    ACCEPTED_TARGET_FINALITY_CHECKPOINT_DIGEST_NAMESPACE,
    EVALUATION_REPLAY_ATTESTATION_DIGEST_NAMESPACE,
    TARGET_ACCEPTED_RECORD_DIGEST_NAMESPACE,
    TARGET_PREIMAGE_DIGEST_NAMESPACE,
    CPAD_PROFILE_DIGEST_NAMESPACE,
    THRESHOLD_DECRYPTION_PROFILE_DIGEST_NAMESPACE,
    TOP_K_DECRYPTION_SHARE_DIGEST_NAMESPACE,
    VERIFIED_TOP_K_RESULT_DIGEST_NAMESPACE,
    ENCRYPTED_ENVELOPE_ROOT_NAMESPACE,
    EVALUATION_PROOF_ROOT_NAMESPACE,
];

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
        RESERVED_ROOT_NAMESPACES, canonical_root, chunk_root, hash512, hash512_hex, namespace_root,
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
}
