use crate::foundation::{CanonicalDecodeLimits, ProofObjectHeader};

use super::CommonProofProverError;

/// Streaming destination for the canonical header and proof body.
pub(crate) trait CommonProofByteSink {
    type Error;

    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), Self::Error>;
}

pub(crate) fn canonical_proof_object_header_bytes(
    canonical_application_statement_bytes: &[u8],
) -> Result<Vec<u8>, CommonProofProverError> {
    if canonical_application_statement_bytes.is_empty() {
        return Err(CommonProofProverError::InvalidInput);
    }
    ProofObjectHeader::from_canonical_application_statement(
        canonical_application_statement_bytes.to_vec(),
        &CanonicalDecodeLimits::default(),
    )
    .and_then(|header| header.encode())
    .map_err(|_| CommonProofProverError::CanonicalEncoding)
}
