//! Exact concrete transcript workload for the compact public-key slice.
//!
//! The production transcript hashes the complete canonical public input once
//! per logical round and appends the triangular prefix of verifier-derived
//! commitment-oracle identifiers, response roots, and independent round
//! salts. This ledger calls the production prefix-length owner for every round
//! and separately retains the fixed-message seed-and-block call census. It is
//! a work and correspondence record, not a QROM proof for that multi-call
//! graph.

use super::uniform_verifier_randomness::PackingUniformVerifierRandomness;
use super::{CompactStaticCatalogError, checked_add, checked_product};
use crate::bgv::proof_suite::compact_proof_wire::{
    COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH, CompactProofWireGeometry,
    CompactPublicInputWireGeometry,
};
use crate::bgv::proof_suite::compact_transcript::{
    compact_fiat_shamir_prefix_payload_byte_length, compact_vector_commitment_oracle_identifier,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PackingTranscriptBindingLedger {
    logical_round_count: u64,
    fiat_shamir_round_salt_byte_length: u64,
    public_input_byte_length: u64,
    public_input_hash_pass_count: u64,
    total_public_input_rehash_byte_length: u64,
    commitment_prefix_entry_absorption_count: u64,
    total_prefix_payload_byte_length: u64,
    maximum_prefix_payload_byte_length: u64,
    prefix_hash_query_count: u64,
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
        public_input_geometry: CompactPublicInputWireGeometry,
        uniform_verifier_randomness: &PackingUniformVerifierRandomness,
    ) -> Result<Self, CompactStaticCatalogError> {
        let logical_round_count = u64::try_from(proof_geometry.responses().len())
            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
        if logical_round_count == 0
            || proof_geometry.responses().len() != uniform_verifier_randomness.move_count()
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        let public_input_byte_length =
            u64::try_from(public_input_geometry.exact_canonical_byte_length())
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
        let mut total_prefix_payload_byte_length = 0_u64;
        for prefix_response_count in 1..=proof_geometry.responses().len() {
            let prefix_payload_byte_length = compact_fiat_shamir_prefix_payload_byte_length(
                public_input_geometry.exact_canonical_byte_length(),
                prefix_response_count,
            )
            .map_err(map_transcript_error)?;
            total_prefix_payload_byte_length = checked_add(
                total_prefix_payload_byte_length,
                u64::try_from(prefix_payload_byte_length)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
            )?;
        }
        let maximum_prefix_payload_byte_length = u64::try_from(
            compact_fiat_shamir_prefix_payload_byte_length(
                public_input_geometry.exact_canonical_byte_length(),
                proof_geometry.responses().len(),
            )
            .map_err(map_transcript_error)?,
        )
        .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
        let commitment_prefix_entry_absorption_count = logical_round_count
            .checked_mul(
                logical_round_count
                    .checked_add(1)
                    .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?,
            )
            .and_then(|count| count.checked_div(2))
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
        let total_public_input_rehash_byte_length =
            checked_product(&[public_input_byte_length, logical_round_count])?;
        let fixed_message_seed_and_block_hash_query_count =
            uniform_verifier_randomness.concrete_challenge_stream_hash_query_count();
        let total_concrete_fiat_shamir_hash_query_count = checked_add(
            logical_round_count,
            fixed_message_seed_and_block_hash_query_count,
        )?;
        let ledger = Self {
            logical_round_count,
            fiat_shamir_round_salt_byte_length: u64::try_from(
                COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH,
            )
            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
            public_input_byte_length,
            public_input_hash_pass_count: logical_round_count,
            total_public_input_rehash_byte_length,
            commitment_prefix_entry_absorption_count,
            total_prefix_payload_byte_length,
            maximum_prefix_payload_byte_length,
            prefix_hash_query_count: logical_round_count,
            fixed_message_seed_and_block_hash_query_count,
            total_concrete_fiat_shamir_hash_query_count,
        };
        ledger.check(
            proof_geometry,
            public_input_geometry,
            uniform_verifier_randomness,
        )?;
        Ok(ledger)
    }

    fn check(
        &self,
        proof_geometry: &CompactProofWireGeometry,
        public_input_geometry: CompactPublicInputWireGeometry,
        uniform_verifier_randomness: &PackingUniformVerifierRandomness,
    ) -> Result<(), CompactStaticCatalogError> {
        let expected = Self::derive_without_check(
            proof_geometry,
            public_input_geometry,
            uniform_verifier_randomness,
        )?;
        if self != &expected
            || self.logical_round_count == 0
            || self.fiat_shamir_round_salt_byte_length
                != COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH as u64
            || self.public_input_hash_pass_count != self.logical_round_count
            || self.prefix_hash_query_count != self.logical_round_count
            || self.maximum_prefix_payload_byte_length == 0
            || self.total_prefix_payload_byte_length < self.maximum_prefix_payload_byte_length
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
        Ok(())
    }

    fn derive_without_check(
        proof_geometry: &CompactProofWireGeometry,
        public_input_geometry: CompactPublicInputWireGeometry,
        uniform_verifier_randomness: &PackingUniformVerifierRandomness,
    ) -> Result<Self, CompactStaticCatalogError> {
        let logical_round_count = u64::try_from(proof_geometry.responses().len())
            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
        if logical_round_count == 0
            || proof_geometry.responses().len() != uniform_verifier_randomness.move_count()
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        let public_input_byte_length =
            u64::try_from(public_input_geometry.exact_canonical_byte_length())
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
        let total_prefix_payload_byte_length =
            (1..=proof_geometry.responses().len()).try_fold(0_u64, |total, prefix_count| {
                let byte_length = compact_fiat_shamir_prefix_payload_byte_length(
                    public_input_geometry.exact_canonical_byte_length(),
                    prefix_count,
                )
                .map_err(map_transcript_error)?;
                checked_add(
                    total,
                    u64::try_from(byte_length)
                        .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
                )
            })?;
        let maximum_prefix_payload_byte_length = u64::try_from(
            compact_fiat_shamir_prefix_payload_byte_length(
                public_input_geometry.exact_canonical_byte_length(),
                proof_geometry.responses().len(),
            )
            .map_err(map_transcript_error)?,
        )
        .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
        let commitment_prefix_entry_absorption_count = logical_round_count
            .checked_mul(
                logical_round_count
                    .checked_add(1)
                    .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?,
            )
            .and_then(|count| count.checked_div(2))
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
        let fixed_message_seed_and_block_hash_query_count =
            uniform_verifier_randomness.concrete_challenge_stream_hash_query_count();
        Ok(Self {
            logical_round_count,
            fiat_shamir_round_salt_byte_length: u64::try_from(
                COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH,
            )
            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
            public_input_byte_length,
            public_input_hash_pass_count: logical_round_count,
            total_public_input_rehash_byte_length: checked_product(&[
                public_input_byte_length,
                logical_round_count,
            ])?,
            commitment_prefix_entry_absorption_count,
            total_prefix_payload_byte_length,
            maximum_prefix_payload_byte_length,
            prefix_hash_query_count: logical_round_count,
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

    #[derive(Debug, PartialEq, Eq)]
    struct TranscriptWorkSnapshot {
        packing_factor: u64,
        logical_round_count: u64,
        total_public_input_rehash_byte_length: u64,
        commitment_prefix_entry_absorption_count: u64,
        total_prefix_payload_byte_length: u64,
        maximum_prefix_payload_byte_length: u64,
        total_concrete_fiat_shamir_hash_query_count: u64,
    }

    #[test]
    fn every_factor_accounts_for_complete_cdhz_prefix_inputs() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");
        let snapshots = catalog
            .factor_catalogs
            .iter()
            .map(|factor| TranscriptWorkSnapshot {
                packing_factor: factor.packing_factor,
                logical_round_count: factor.transcript_binding.logical_round_count,
                total_public_input_rehash_byte_length: factor
                    .transcript_binding
                    .total_public_input_rehash_byte_length,
                commitment_prefix_entry_absorption_count: factor
                    .transcript_binding
                    .commitment_prefix_entry_absorption_count,
                total_prefix_payload_byte_length: factor
                    .transcript_binding
                    .total_prefix_payload_byte_length,
                maximum_prefix_payload_byte_length: factor
                    .transcript_binding
                    .maximum_prefix_payload_byte_length,
                total_concrete_fiat_shamir_hash_query_count: factor
                    .transcript_binding
                    .total_concrete_fiat_shamir_hash_query_count,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            snapshots,
            vec![
                TranscriptWorkSnapshot {
                    packing_factor: 1,
                    logical_round_count: 82,
                    total_public_input_rehash_byte_length: 1_311_267_084,
                    commitment_prefix_entry_absorption_count: 3_403,
                    total_prefix_payload_byte_length: 1_311_716_936,
                    maximum_prefix_payload_byte_length: 16_001_894,
                    total_concrete_fiat_shamir_hash_query_count: 162_692,
                },
                TranscriptWorkSnapshot {
                    packing_factor: 2,
                    logical_round_count: 80,
                    total_public_input_rehash_byte_length: 1_279_284_960,
                    commitment_prefix_entry_absorption_count: 3_240,
                    total_prefix_payload_byte_length: 1_279_713_280,
                    maximum_prefix_payload_byte_length: 16_001_630,
                    total_concrete_fiat_shamir_hash_query_count: 164_928,
                },
                TranscriptWorkSnapshot {
                    packing_factor: 4,
                    logical_round_count: 78,
                    total_public_input_rehash_byte_length: 1_247_302_836,
                    commitment_prefix_entry_absorption_count: 3_081,
                    total_prefix_payload_byte_length: 1_247_710_152,
                    maximum_prefix_payload_byte_length: 16_001_366,
                    total_concrete_fiat_shamir_hash_query_count: 165_084,
                },
                TranscriptWorkSnapshot {
                    packing_factor: 8,
                    logical_round_count: 76,
                    total_public_input_rehash_byte_length: 1_215_320_712,
                    commitment_prefix_entry_absorption_count: 2_926,
                    total_prefix_payload_byte_length: 1_215_707_552,
                    maximum_prefix_payload_byte_length: 16_001_102,
                    total_concrete_fiat_shamir_hash_query_count: 165_752,
                },
            ]
        );
    }
}
