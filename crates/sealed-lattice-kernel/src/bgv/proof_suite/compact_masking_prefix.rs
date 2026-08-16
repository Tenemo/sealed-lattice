//! Opaque bindings for one adaptive compact-masking transcript prefix.
//!
//! The prefix owns the exact verifier messages and canonical exposed proof
//! bytes that precede a carried public covector. It is never serialized as a
//! proof field and cannot be reconstructed from a caller-supplied digest.

use super::fixed_uniform_verifier_message::DecodedFixedUniformVerifierMessage;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CompactMaskingAttemptIdentity {
    attempt_identifier: [u8; 32],
    reset_ordinal: u32,
    transcript_prefix_binding: [u8; 64],
}

impl CompactMaskingAttemptIdentity {
    pub(crate) const fn new(
        attempt_identifier: [u8; 32],
        reset_ordinal: u32,
        transcript_prefix_binding: [u8; 64],
    ) -> Self {
        Self {
            attempt_identifier,
            reset_ordinal,
            transcript_prefix_binding,
        }
    }

    pub(crate) fn binding_bytes(self) -> [u8; 100] {
        let mut bytes = [0_u8; 100];
        bytes[..32].copy_from_slice(&self.attempt_identifier);
        bytes[32..36].copy_from_slice(&self.reset_ordinal.to_le_bytes());
        bytes[36..].copy_from_slice(&self.transcript_prefix_binding);
        bytes
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactMaskingPrefixError {
    InvalidChronology,
}

/// Exact prefix consumed by the public-only carried-covector derivation.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct CompactMaskingSemanticPrefix {
    attempt_identity: CompactMaskingAttemptIdentity,
    verifier_move_ordinal: u32,
    epoch: u8,
    contract_source_hash: [u8; 64],
    canonical_exposed_move_prefix: Box<[u8]>,
    completed_messages: Box<[DecodedFixedUniformVerifierMessage]>,
}

impl CompactMaskingSemanticPrefix {
    pub(in crate::bgv::proof_suite) fn from_validated_transcript(
        attempt_identity: CompactMaskingAttemptIdentity,
        verifier_move_ordinal: u32,
        epoch: u8,
        contract_source_hash: [u8; 64],
        canonical_exposed_move_prefix: Box<[u8]>,
        completed_messages: Box<[DecodedFixedUniformVerifierMessage]>,
    ) -> Result<Self, CompactMaskingPrefixError> {
        if epoch == 0
            || usize::try_from(verifier_move_ordinal).ok() != Some(completed_messages.len())
            || canonical_exposed_move_prefix.is_empty()
        {
            return Err(CompactMaskingPrefixError::InvalidChronology);
        }
        Ok(Self {
            attempt_identity,
            verifier_move_ordinal,
            epoch,
            contract_source_hash,
            canonical_exposed_move_prefix,
            completed_messages,
        })
    }

    pub(crate) const fn attempt_identity(&self) -> CompactMaskingAttemptIdentity {
        self.attempt_identity
    }

    pub(crate) const fn verifier_move_ordinal(&self) -> u32 {
        self.verifier_move_ordinal
    }

    pub(crate) const fn epoch(&self) -> u8 {
        self.epoch
    }

    pub(crate) const fn contract_source_hash(&self) -> [u8; 64] {
        self.contract_source_hash
    }

    pub(crate) fn canonical_exposed_move_prefix(&self) -> &[u8] {
        &self.canonical_exposed_move_prefix
    }

    pub(crate) fn completed_messages(&self) -> &[DecodedFixedUniformVerifierMessage] {
        &self.completed_messages
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semantic_prefix_requires_exact_completed_message_chronology() {
        assert_eq!(
            CompactMaskingSemanticPrefix::from_validated_transcript(
                CompactMaskingAttemptIdentity::new([1; 32], 0, [2; 64]),
                1,
                1,
                [3; 64],
                vec![4].into_boxed_slice(),
                Vec::new().into_boxed_slice(),
            ),
            Err(CompactMaskingPrefixError::InvalidChronology),
        );
    }
}
