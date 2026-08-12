//! Exact concrete transcript workload for the compact public-key slice.
//!
//! The production transcript binds each response ordinal to the independently
//! derived commitment-oracle identifier and accounts for the concrete
//! Fiat-Shamir hash-query census consumed by the soundness calculation.

use super::uniform_verifier_randomness::PackingUniformVerifierRandomness;
use super::{CompactStaticCatalogError, checked_add};
use crate::bgv::proof_suite::compact_proof_wire::CompactProofWireGeometry;
use crate::bgv::proof_suite::compact_transcript::compact_vector_commitment_oracle_identifier;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PackingTranscriptBindingLedger {
    fixed_message_seed_and_block_hash_query_count: u64,
    total_concrete_fiat_shamir_hash_query_count: u64,
}

impl PackingTranscriptBindingLedger {
    pub(super) const fn total_concrete_fiat_shamir_hash_query_count(&self) -> u64 {
        self.total_concrete_fiat_shamir_hash_query_count
    }

    pub(super) const fn fixed_message_seed_and_block_hash_query_count(&self) -> u64 {
        self.fixed_message_seed_and_block_hash_query_count
    }

    pub(super) fn derive(
        proof_geometry: &CompactProofWireGeometry,
        uniform_verifier_randomness: &PackingUniformVerifierRandomness,
    ) -> Result<Self, CompactStaticCatalogError> {
        let logical_round_count = u64::try_from(proof_geometry.responses().len())
            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
        if logical_round_count == 0
            || proof_geometry.responses().len() != uniform_verifier_randomness.move_count()
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        for (response_ordinal, response) in proof_geometry.responses().iter().enumerate() {
            let response_ordinal = u32::try_from(response_ordinal)
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
            if response.ordinal() != response_ordinal
                || compact_vector_commitment_oracle_identifier(response_ordinal)
                    .map_err(map_transcript_error)?
                    != response_ordinal + 1
            {
                return Err(CompactStaticCatalogError::InvalidGeometry);
            }
        }
        let fixed_message_seed_and_block_hash_query_count =
            uniform_verifier_randomness.concrete_challenge_stream_hash_query_count();
        Ok(Self {
            fixed_message_seed_and_block_hash_query_count,
            total_concrete_fiat_shamir_hash_query_count: checked_add(
                logical_round_count,
                fixed_message_seed_and_block_hash_query_count,
            )?,
        })
    }
}

fn map_transcript_error(
    error: crate::bgv::proof_suite::compact_transcript::CompactTranscriptError,
) -> CompactStaticCatalogError {
    match error {
        crate::bgv::proof_suite::compact_transcript::CompactTranscriptError::LengthOverflow => {
            CompactStaticCatalogError::ArithmeticOverflow
        }
        _ => CompactStaticCatalogError::InvalidGeometry,
    }
}

#[cfg(test)]
mod tests {
    use crate::bgv::proof_suite::compact_public_key_static_catalog::CompactPublicKeyStaticCatalog;

    #[test]
    fn factor_one_accounts_for_concrete_fiat_shamir_queries() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");
        let selected = &catalog.selected;
        assert_eq!(
            (
                selected
                    .transcript_binding
                    .fixed_message_seed_and_block_hash_query_count,
                selected
                    .transcript_binding
                    .total_concrete_fiat_shamir_hash_query_count,
            ),
            (181_522, 181_604),
        );
    }
}
