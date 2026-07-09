//! Direct encrypted ballot statement and package schema freeze.
//!
//! The stable object is `BallotValidityStatement-v1`: the relation is locked
//! rather than the backend. This module freezes the statement field
//! order, its canonical length-prefixed byte encoding, the statement hash, and
//! the kernel-recomputed identity fields (BGV parameters, batch encoder,
//! encrypted-ballot layout, and the relation proof profile). Because the
//! statement binds the voter identity, roster position, and action context, an
//! accepting proof cannot be transplanted into another voter's package. The
//! functions are frozen here ahead of the proof backend that
//! produces and verifies proofs against this statement.

use super::layout::{batch_encoder_hash, encrypted_ballot_layout_hash};
use super::{MAXIMUM_SCORE, MINIMUM_SCORE, OPTION_COUNT, SCORE_BUCKET_COUNT};
use crate::bgv::parameters::{
    DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE, bgv_parameters_hash,
};
use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};
use crate::hashing::hash512_hex;

// A canonical protocol hash is the lowercase hex encoding of a 512-bit
// (64-byte) `hash512` digest: exactly 128 lowercase hex characters. Statement
// hash fields are validated against this before they enter the encoding.
const PROTOCOL_HASH_HEX_LENGTH: usize = 128;

fn validate_protocol_hash(value: &str, field_name: &str) -> CanonicalResult<()> {
    if value.len() != PROTOCOL_HASH_HEX_LENGTH
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid_statement(&format!(
            "ballot validity statement {field_name} must be a canonical lowercase 512-bit hash"
        )));
    }
    Ok(())
}

const BALLOT_VALIDITY_STATEMENT_VERSION: u32 = 1;
const BALLOT_VALIDITY_STATEMENT_DOMAIN: &str =
    "sealed-lattice/direct-ballot/ballot-validity-statement";
const BALLOT_VALIDITY_PROOF_PROFILE_DOMAIN: &str =
    "sealed-lattice/direct-ballot/ballot-validity-proof-profile";

fn invalid_statement(message: &str) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

// The kernel-recomputed identity fields the statement binds. Phase A is
// relation locked and backend agnostic, so the proof profile is the fixed
// relation shape (score domain, ring, plaintext field, data basis) folded with
// the encoder and layout identities; Phase C extends it with the selected
// backend without changing the schema.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) struct BallotValidityKernelIdentity {
    pub(super) bgv_parameters_hash: String,
    pub(super) batch_encoder_hash: String,
    pub(super) encrypted_ballot_layout_hash: String,
    pub(super) proof_profile_hash: String,
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn ballot_validity_proof_profile_hash(
    batch_encoder_hash: &str,
    encrypted_ballot_layout_hash: &str,
) -> String {
    // The relation profile locks what an accepted proof is a proof OF: the
    // fixed score-validity and HE relation shape plus the encoder and layout
    // identities. It is backend agnostic by construction.
    hash512_hex(
        BALLOT_VALIDITY_PROOF_PROFILE_DOMAIN,
        &[
            &BALLOT_VALIDITY_STATEMENT_VERSION.to_le_bytes(),
            &(OPTION_COUNT as u64).to_le_bytes(),
            &(SCORE_BUCKET_COUNT as u64).to_le_bytes(),
            &MINIMUM_SCORE.to_le_bytes(),
            &MAXIMUM_SCORE.to_le_bytes(),
            &(POLYNOMIAL_DEGREE as u64).to_le_bytes(),
            &PLAINTEXT_MODULUS.to_le_bytes(),
            &(DATA_PRIMES.len() as u64).to_le_bytes(),
            batch_encoder_hash.as_bytes(),
            encrypted_ballot_layout_hash.as_bytes(),
        ],
    )
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn ballot_validity_kernel_identity() -> CanonicalResult<BallotValidityKernelIdentity> {
    let batch_encoder_hash = batch_encoder_hash()?;
    let encrypted_ballot_layout_hash = encrypted_ballot_layout_hash()?;
    let proof_profile_hash =
        ballot_validity_proof_profile_hash(&batch_encoder_hash, &encrypted_ballot_layout_hash);
    Ok(BallotValidityKernelIdentity {
        bgv_parameters_hash: bgv_parameters_hash()?,
        batch_encoder_hash,
        encrypted_ballot_layout_hash,
        proof_profile_hash,
    })
}

// The frozen `BallotValidityStatement-v1`. Externally supplied fields (the
// voter binding, the setup and public-key roots, the ciphertext roots) plus the
// kernel-recomputed identity fields. The proof backend binds this statement; a
// proof accepted against a statement built for one voter cannot move to another.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) struct BallotValidityStatement {
    pub(super) setup_package_hash: String,
    pub(super) voter_identity: String,
    pub(super) voter_roster_position: u64,
    pub(super) action_context_hash: String,
    pub(super) collective_public_key_root: String,
    pub(super) ciphertext_root: String,
    pub(super) ciphertext_limb_roots: Vec<String>,
    pub(super) public_key_limb_roots: Vec<String>,
    pub(super) kernel_identity: BallotValidityKernelIdentity,
}

fn append_length_prefixed(bytes: &mut Vec<u8>, part: &[u8]) {
    bytes.extend_from_slice(&(part.len() as u64).to_le_bytes());
    bytes.extend_from_slice(part);
}

fn append_hash_field(bytes: &mut Vec<u8>, field_name: &str, value: &str) -> CanonicalResult<()> {
    validate_protocol_hash(value, field_name)?;
    append_length_prefixed(bytes, value.as_bytes());
    Ok(())
}

impl BallotValidityStatement {
    // The canonical statement bytes: every field in a fixed order, every
    // variable-length field length-prefixed, every hash field validated as a
    // canonical protocol hash before it enters the encoding. Deterministic and
    // injective, so the statement hash binds exactly these fields.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn canonical_bytes(&self) -> CanonicalResult<Vec<u8>> {
        if self.ciphertext_limb_roots.len() != DATA_PRIMES.len()
            || self.public_key_limb_roots.len() != DATA_PRIMES.len()
        {
            return Err(invalid_statement(
                "ballot validity statement limb roots must cover every data prime",
            ));
        }
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&BALLOT_VALIDITY_STATEMENT_VERSION.to_le_bytes());
        append_hash_field(&mut bytes, "setupPackageHash", &self.setup_package_hash)?;
        append_length_prefixed(&mut bytes, self.voter_identity.as_bytes());
        bytes.extend_from_slice(&self.voter_roster_position.to_le_bytes());
        append_hash_field(&mut bytes, "actionContextHash", &self.action_context_hash)?;
        append_hash_field(
            &mut bytes,
            "collectivePublicKeyRoot",
            &self.collective_public_key_root,
        )?;
        append_hash_field(
            &mut bytes,
            "bgvParametersHash",
            &self.kernel_identity.bgv_parameters_hash,
        )?;
        append_hash_field(
            &mut bytes,
            "batchEncoderHash",
            &self.kernel_identity.batch_encoder_hash,
        )?;
        append_hash_field(
            &mut bytes,
            "encryptedBallotLayoutHash",
            &self.kernel_identity.encrypted_ballot_layout_hash,
        )?;
        append_hash_field(&mut bytes, "ciphertextRoot", &self.ciphertext_root)?;
        append_hash_field(
            &mut bytes,
            "proofProfileHash",
            &self.kernel_identity.proof_profile_hash,
        )?;
        bytes.extend_from_slice(&(self.ciphertext_limb_roots.len() as u64).to_le_bytes());
        for (limb_index, root) in self.ciphertext_limb_roots.iter().enumerate() {
            append_hash_field(
                &mut bytes,
                &format!("ciphertextLimbRoot.{limb_index}"),
                root,
            )?;
        }
        bytes.extend_from_slice(&(self.public_key_limb_roots.len() as u64).to_le_bytes());
        for (limb_index, root) in self.public_key_limb_roots.iter().enumerate() {
            append_hash_field(&mut bytes, &format!("publicKeyLimbRoot.{limb_index}"), root)?;
        }
        Ok(bytes)
    }

    // The statement hash over the canonical bytes.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn statement_hash(&self) -> CanonicalResult<String> {
        Ok(hash512_hex(
            BALLOT_VALIDITY_STATEMENT_DOMAIN,
            &[&self.canonical_bytes()?],
        ))
    }

    // Rebuild the kernel identity from the kernel's own constants and require it
    // to match the statement's bound identity, so a statement whose encoder,
    // layout, BGV parameters, or proof profile drifted from this kernel is
    // refused before any proof work.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn verify_kernel_identity(&self) -> CanonicalResult<()> {
        let expected = ballot_validity_kernel_identity()?;
        if self.kernel_identity.bgv_parameters_hash != expected.bgv_parameters_hash {
            return Err(invalid_statement(
                "ballot validity statement bgvParametersHash does not match this kernel",
            ));
        }
        if self.kernel_identity.batch_encoder_hash != expected.batch_encoder_hash {
            return Err(invalid_statement(
                "ballot validity statement batchEncoderHash does not match this kernel",
            ));
        }
        if self.kernel_identity.encrypted_ballot_layout_hash
            != expected.encrypted_ballot_layout_hash
        {
            return Err(invalid_statement(
                "ballot validity statement encryptedBallotLayoutHash does not match this kernel",
            ));
        }
        if self.kernel_identity.proof_profile_hash != expected.proof_profile_hash {
            return Err(invalid_statement(
                "ballot validity statement proofProfileHash does not match this kernel",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_statement() -> BallotValidityStatement {
        let hash = |seed: &str| hash512_hex("ballot-validity-statement-test", &[seed.as_bytes()]);
        BallotValidityStatement {
            setup_package_hash: hash("setup-package"),
            voter_identity: "voter-0".to_string(),
            voter_roster_position: 0,
            action_context_hash: hash("action-context"),
            collective_public_key_root: hash("collective-public-key"),
            ciphertext_root: hash("ciphertext"),
            ciphertext_limb_roots: (0..DATA_PRIMES.len())
                .map(|limb_index| hash(&format!("ciphertext-limb-{limb_index}")))
                .collect(),
            public_key_limb_roots: (0..DATA_PRIMES.len())
                .map(|limb_index| hash(&format!("public-key-limb-{limb_index}")))
                .collect(),
            kernel_identity: ballot_validity_kernel_identity().expect("kernel identity"),
        }
    }

    #[test]
    fn statement_hash_is_deterministic_and_binds_the_voter() {
        let statement = sample_statement();
        let first = statement.statement_hash().expect("statement hash");
        let second = statement.statement_hash().expect("statement hash");
        assert_eq!(first, second, "the statement hash is deterministic");

        // Transplanting the proof to another voter changes the statement hash,
        // so an accepting proof cannot move between voters.
        let mut other_voter = sample_statement();
        other_voter.voter_identity = "voter-1".to_string();
        assert_ne!(
            first,
            other_voter.statement_hash().expect("statement hash"),
            "a different voter identity must change the statement hash"
        );

        let mut other_roster = sample_statement();
        other_roster.voter_roster_position = 1;
        assert_ne!(
            first,
            other_roster.statement_hash().expect("statement hash"),
            "a different roster position must change the statement hash"
        );

        let mut other_action = sample_statement();
        other_action.action_context_hash =
            hash512_hex("ballot-validity-statement-test", &[b"other-action"]);
        assert_ne!(
            first,
            other_action.statement_hash().expect("statement hash"),
            "a different action context must change the statement hash"
        );
    }

    #[test]
    fn kernel_identity_verification_accepts_recomputed_and_rejects_drift() {
        let statement = sample_statement();
        statement
            .verify_kernel_identity()
            .expect("recomputed kernel identity is accepted");

        let mut drifted_encoder = sample_statement();
        drifted_encoder.kernel_identity.batch_encoder_hash =
            hash512_hex("ballot-validity-statement-test", &[b"wrong-encoder"]);
        assert!(
            drifted_encoder.verify_kernel_identity().is_err(),
            "a statement encoded under a different batch encoder must be refused"
        );

        let mut drifted_layout = sample_statement();
        drifted_layout.kernel_identity.encrypted_ballot_layout_hash =
            hash512_hex("ballot-validity-statement-test", &[b"wrong-layout"]);
        assert!(
            drifted_layout.verify_kernel_identity().is_err(),
            "a statement bound to a different layout must be refused"
        );
    }

    #[test]
    fn canonical_bytes_reject_a_wrong_limb_count() {
        let mut statement = sample_statement();
        statement.ciphertext_limb_roots.pop();
        assert!(
            statement.canonical_bytes().is_err(),
            "a ciphertext limb-root vector that does not cover every data prime must be refused"
        );
    }

    #[test]
    fn canonical_bytes_reject_a_noncanonical_hash_field() {
        let mut statement = sample_statement();
        statement.setup_package_hash = "not-a-canonical-hash".to_string();
        assert!(
            statement.canonical_bytes().is_err(),
            "a non-canonical hash field must be refused before it enters the encoding"
        );
    }

    #[test]
    fn proof_profile_binds_the_encoder_and_layout() {
        let identity = ballot_validity_kernel_identity().expect("kernel identity");
        let rebound = ballot_validity_proof_profile_hash(
            &identity.batch_encoder_hash,
            &hash512_hex("ballot-validity-statement-test", &[b"other-layout"]),
        );
        assert_ne!(
            identity.proof_profile_hash, rebound,
            "the proof profile must fold in the layout identity"
        );
    }
}
