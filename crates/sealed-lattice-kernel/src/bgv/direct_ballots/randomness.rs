use super::*;

pub(super) const PROOF_MASK_RANDOMNESS_HEX_BYTES: usize = 32;
pub(super) const ENCRYPTION_RANDOMNESS_HEX_BYTES: usize = 32;

pub(super) struct DirectBallotProofMaskRandomness {
    pub(super) ballot_proof_randomness_hexes: Vec<String>,
}

pub(super) struct DirectBallotEncryptionRandomness {
    pub(super) encryption_seed_hexes: Vec<String>,
}

impl DirectBallotProofMaskRandomness {
    pub(super) fn ballot_proof_randomness_hex(&self, ballot_index: usize) -> CanonicalResult<&str> {
        self.ballot_proof_randomness_hexes
            .get(ballot_index)
            .map(String::as_str)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "proofMaskRandomness.ballotProofRandomnessHexes does not cover every ballot proof",
                )
            })
    }
}

impl DirectBallotEncryptionRandomness {
    pub(super) fn encryption_seed_hex(&self, ballot_index: usize) -> CanonicalResult<&str> {
        self.encryption_seed_hexes
            .get(ballot_index)
            .map(String::as_str)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "ballotEncryptionRandomness.encryptionSeedHexes does not cover every ballot",
                )
            })
    }
}
