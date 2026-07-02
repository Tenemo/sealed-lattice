use super::super::*;

// Checkpoint subdirectories for the inline anchor proof families. The trustee
// evaluation-key family already persists its transported proof material under a
// sibling directory; these two cover the other expensive prover outputs so a
// resumed run skips re-proving every family, not just the trustee one.
pub(in super::super) const SAME_SECRET_ANCHOR_PROOF_CHECKPOINT_DIRECTORY: &str =
    "same-secret-anchor-proof-material";
pub(in super::super) const PUBLIC_KEY_SHARE_PROOF_CHECKPOINT_DIRECTORY: &str =
    "public-key-share-proof-material";
// The trustee evaluation-key family also persists transported proof material
// under `trustee-evaluation-key-proof-material` during the final-package transport
// flow. This sibling directory is the statement-keyed raw-proof store used by the
// non-transport container build that the heavy accepted-setup tests consume,
// which never enters the transported-material resume path.
pub(in super::super) const TRUSTEE_EVALUATION_KEY_ANCHOR_PROOF_CHECKPOINT_DIRECTORY: &str =
    "trustee-evaluation-key-anchor-proof-material";

fn anchor_proof_checkpoint_path(
    family_directory: &str,
    statement_hash_hex: &str,
) -> std::path::PathBuf {
    crate::bgv::setup::accepted_setup_final_package_material_store_checkpoint_directory()
        .join(family_directory)
        .join(format!("{statement_hash_hex}.bin"))
}

pub(in super::super) fn anchor_proof_checkpoint_exists(
    family_directory: &str,
    statement_hash_hex: &str,
) -> bool {
    anchor_proof_checkpoint_path(family_directory, statement_hash_hex).exists()
}

pub(in super::super) fn persist_checkpointed_anchor_proof_bytes(
    family_directory: &str,
    statement_hash_hex: &str,
    proof_bytes: &[u8],
) {
    if !final_package_checkpoint_resume_enabled() {
        return;
    }
    let path = anchor_proof_checkpoint_path(family_directory, statement_hash_hex);
    persist_anchor_proof_checkpoint(&path, statement_hash_hex, proof_bytes);
}

// Returns the deterministic encoded proof bytes for one inline anchor proof,
// loading them from an on-disk checkpoint when checkpoint resume is enabled and a
// matching file exists, and otherwise generating them and persisting them so a
// later run can skip the prover. The statement hash content-addresses the proof:
// a changed statement yields a new filename, so a stale proof is never reused,
// and a witness-only divergence surfaces as a loud verifier rejection rather than
// a silently accepted wrong proof.
pub(in super::super) fn checkpointed_anchor_proof_bytes(
    family_directory: &str,
    statement_hash_hex: &str,
    generate_proof_bytes: impl FnOnce() -> Vec<u8>,
) -> Vec<u8> {
    if !final_package_checkpoint_resume_enabled() {
        return generate_proof_bytes();
    }
    let path = anchor_proof_checkpoint_path(family_directory, statement_hash_hex);
    if let Ok(proof_bytes) = std::fs::read(&path) {
        final_package_phase(&format!(
            "resumed {family_directory} proof checkpoint {statement_hash_hex}"
        ));
        return proof_bytes;
    }
    let proof_bytes = generate_proof_bytes();
    persist_checkpointed_anchor_proof_bytes(family_directory, statement_hash_hex, &proof_bytes);

    proof_bytes
}

fn persist_anchor_proof_checkpoint(
    path: &std::path::Path,
    statement_hash_hex: &str,
    proof_bytes: &[u8],
) {
    let Some(parent) = path.parent() else {
        return;
    };
    std::fs::create_dir_all(parent).expect("anchor proof checkpoint directory");
    // Publish atomically through a process-unique temporary file so a concurrent
    // reader never observes a torn write and parallel writers never collide. If a
    // sibling process published the identical content first, the rename fails and
    // the temporary is discarded.
    let temporary_path = parent.join(format!(
        "{statement_hash_hex}.{}.partial",
        std::process::id()
    ));
    std::fs::write(&temporary_path, proof_bytes).expect("anchor proof checkpoint write");
    if std::fs::rename(&temporary_path, path).is_err() {
        let _ = std::fs::remove_file(&temporary_path);
    }
}

pub(in super::super) fn final_package_checkpoint_resume_enabled() -> bool {
    matches!(
        std::env::var("SEALED_LATTICE_RESUME_TEST_CHECKPOINTS").as_deref(),
        Ok("1")
    )
}
