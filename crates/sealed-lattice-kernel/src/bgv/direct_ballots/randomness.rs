use super::*;

pub(super) const DIRECT_BALLOT_PROOF_MASK_RANDOMNESS_FRESH_CSPRNG: &str = "fresh-csprng";
pub(super) const DIRECT_BALLOT_PROOF_MASK_RANDOMNESS_DEVELOPMENT_FIXTURE: &str =
    "development-deterministic-fixture";
pub(super) const DIRECT_BALLOT_PROOF_MASK_RANDOMNESS_HEX_BYTES: usize = 32;
pub(super) const DIRECT_BALLOT_ENCRYPTION_RANDOMNESS_FRESH_CSPRNG: &str = "fresh-csprng";
pub(super) const DIRECT_BALLOT_ENCRYPTION_RANDOMNESS_DEVELOPMENT_FIXTURE: &str =
    "development-deterministic-fixture";
pub(super) const DIRECT_BALLOT_ENCRYPTION_RANDOMNESS_HEX_BYTES: usize = 32;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum DirectBallotProofMaskRandomnessSource {
    FreshCsprng,
    DevelopmentDeterministicFixture,
}

pub(super) struct DirectBallotProofMaskRandomness {
    pub(super) source: DirectBallotProofMaskRandomnessSource,
    pub(super) ballot_proof_randomness_hexes: Vec<String>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum DirectBallotEncryptionRandomnessSource {
    FreshCsprng,
    DevelopmentDeterministicFixture,
}

pub(super) struct DirectBallotEncryptionRandomness {
    pub(super) source: DirectBallotEncryptionRandomnessSource,
    pub(super) encryption_seed_hexes: Vec<String>,
}

impl DirectBallotProofMaskRandomnessSource {
    pub(super) fn from_str(value: &str) -> CanonicalResult<Self> {
        match value {
            DIRECT_BALLOT_PROOF_MASK_RANDOMNESS_FRESH_CSPRNG => Ok(Self::FreshCsprng),
            DIRECT_BALLOT_PROOF_MASK_RANDOMNESS_DEVELOPMENT_FIXTURE => {
                Ok(Self::DevelopmentDeterministicFixture)
            }
            _ => Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "proofMaskRandomness.source must be fresh-csprng or development-deterministic-fixture",
            )),
        }
    }

    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::FreshCsprng => DIRECT_BALLOT_PROOF_MASK_RANDOMNESS_FRESH_CSPRNG,
            Self::DevelopmentDeterministicFixture => {
                DIRECT_BALLOT_PROOF_MASK_RANDOMNESS_DEVELOPMENT_FIXTURE
            }
        }
    }
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

    pub(super) fn report_value(&self) -> Value {
        let source_statement = match self.source {
            DirectBallotProofMaskRandomnessSource::FreshCsprng => {
                "proof masks use caller-supplied fresh CSPRNG randomness; the Rust command validates shape and records only the source and counts"
            }
            DirectBallotProofMaskRandomnessSource::DevelopmentDeterministicFixture => {
                "proof masks use caller-supplied deterministic fixture randomness; this is development evidence only"
            }
        };

        json!({
            "source": self.source.as_str(),
            "ballotProofRandomnessCount": self.ballot_proof_randomness_hexes.len(),
            "randomnessBytesPerProof": DIRECT_BALLOT_PROOF_MASK_RANDOMNESS_HEX_BYTES,
            "retention": "proof-mask randomness is consumed to expand proof masks and is not returned in the report",
            "sourceStatement": source_statement
        })
    }
}

impl DirectBallotEncryptionRandomnessSource {
    pub(super) fn from_str(value: &str) -> CanonicalResult<Self> {
        match value {
            DIRECT_BALLOT_ENCRYPTION_RANDOMNESS_FRESH_CSPRNG => Ok(Self::FreshCsprng),
            DIRECT_BALLOT_ENCRYPTION_RANDOMNESS_DEVELOPMENT_FIXTURE => {
                Ok(Self::DevelopmentDeterministicFixture)
            }
            _ => Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "ballotEncryptionRandomness.source must be fresh-csprng or development-deterministic-fixture",
            )),
        }
    }

    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::FreshCsprng => DIRECT_BALLOT_ENCRYPTION_RANDOMNESS_FRESH_CSPRNG,
            Self::DevelopmentDeterministicFixture => {
                DIRECT_BALLOT_ENCRYPTION_RANDOMNESS_DEVELOPMENT_FIXTURE
            }
        }
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

    pub(super) fn report_value(&self) -> Value {
        let source_statement = match self.source {
            DirectBallotEncryptionRandomnessSource::FreshCsprng => {
                "ballot encryption randomness uses caller-supplied fresh CSPRNG seed material; the Rust command validates shape and records only the source and count"
            }
            DirectBallotEncryptionRandomnessSource::DevelopmentDeterministicFixture => {
                "ballot encryption randomness uses caller-supplied deterministic fixture seed material; this is development evidence only"
            }
        };

        json!({
            "source": self.source.as_str(),
            "ballotEncryptionRandomnessCount": self.encryption_seed_hexes.len(),
            "randomnessBytesPerBallot": DIRECT_BALLOT_ENCRYPTION_RANDOMNESS_HEX_BYTES,
            "retention": "ballot encryption seed material is consumed for encryption and is not returned in the report",
            "sourceStatement": source_statement
        })
    }
}
