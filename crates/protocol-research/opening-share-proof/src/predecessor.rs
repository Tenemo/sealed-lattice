use parallel_work::ProtocolHash;
use seed_sharing_proof::{statement::Statement, verification};
use std::io::Read;
use word_verifier::{HEADER_LENGTH, Refusal, engine::CHUNK_LIMIT};

/// This holder establishes only the exact bounded seed-sharing proof. It
/// does not authenticate registration, selection or the synthetic body hash.
pub struct VerifiedSeedSharingRecord {
    statement: Statement,
    identity: [u8; 64],
}
impl VerifiedSeedSharingRecord {
    pub fn identity(&self) -> [u8; 64] {
        self.identity
    }
    pub fn statement(&self) -> &Statement {
        &self.statement
    }
}

/// A pending proof stream cannot be used as a predecessor. Only consuming
/// its successful finish creates the owning verifier's immutable result.
pub struct RecordVerifier {
    expected: Statement,
    verifier: Option<verification::Verifier>,
    hash: ProtocolHash,
}
fn check_statement(expected: &Statement, supplied: &[u8]) -> Result<(), Refusal> {
    if supplied.len() != seed_sharing_proof::statement::encoded_bytes() {
        return Err(Refusal::Length);
    }
    if expected.encode().map_err(|_| Refusal::Encoding)? != supplied {
        return Err(Refusal::Context);
    }
    Ok(())
}
impl RecordVerifier {
    pub fn open(expected: &Statement, supplied: &[u8], header: &[u8]) -> Result<Self, Refusal> {
        check_statement(expected, supplied)?;
        let verifier =
            verification::Verifier::open(expected, supplied, verification::ROLE, header)?;
        let mut hash = ProtocolHash::new();
        word_proof::transcript::part(&mut hash, b"bounded-seed-sharing-record/v1");
        word_proof::transcript::part(&mut hash, supplied);
        // The last component is the complete canonical proof. Include the
        // accepted header exactly once, independent of subsequent chunking.
        hash.update(header);
        Ok(Self {
            expected: expected.clone(),
            verifier: Some(verifier),
            hash,
        })
    }
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), Refusal> {
        let result = self.verifier.as_mut().ok_or(Refusal::Stage)?.push(bytes);
        if result.is_err() {
            self.verifier = None;
            return result;
        }
        self.hash.update(bytes);
        Ok(())
    }
    pub fn finish(mut self) -> Result<VerifiedSeedSharingRecord, Refusal> {
        self.verifier.take().ok_or(Refusal::Stage)?.finish()?;
        Ok(VerifiedSeedSharingRecord {
            statement: self.expected,
            identity: self.hash.finalize(),
        })
    }
}

/// The expected operands come from the independently fixed fixture roster,
/// not from parsing the supplied statement and trusting it as its own scope.
pub fn verify(
    input: &mut impl Read,
    expected: &Statement,
    supplied: &[u8],
) -> Result<VerifiedSeedSharingRecord, verification::VerificationError> {
    // Reject a wrong statement before touching a caller's proof source.
    check_statement(expected, supplied)?;
    let mut header = vec![0; HEADER_LENGTH];
    input.read_exact(&mut header).map_err(|error| {
        if error.kind() == std::io::ErrorKind::UnexpectedEof {
            verification::VerificationError::Refused(Refusal::Length)
        } else {
            verification::VerificationError::Read(error)
        }
    })?;
    let mut verifier = RecordVerifier::open(expected, supplied, &header)?;
    let mut buffer = vec![0; CHUNK_LIMIT];
    loop {
        let length = input
            .read(&mut buffer)
            .map_err(verification::VerificationError::Read)?;
        if length == 0 {
            break;
        }
        verifier.push(&buffer[..length])?;
    }
    verifier
        .finish()
        .map_err(verification::VerificationError::Refused)
}
