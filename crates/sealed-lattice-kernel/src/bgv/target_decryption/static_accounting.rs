//! Static accounting for the selected paired target-release path.

use core::mem::size_of;

use serde::{Deserialize, Serialize};

use crate::{
    bgv::{
        evaluator::top_k::CANONICAL_TARGET_CIPHERTEXT_LEVEL,
        parameters::{DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE},
        proof_suite::{
            MAXIMUM_COMMON_PROOF_BYTE_LENGTH, MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH,
            target_release_checkpoint_lineage_identifier_byte_length,
        },
        serialization::two_component_data_ciphertext_canonical_byte_length_ceiling_at_level,
    },
    foundation::{
        FOUNDATION_PROFILE, Hash512, MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH,
        SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT, StreamDescriptor,
        TargetReleaseOutputBundleByteLengths,
        canonical_target_release_output_bundle_byte_lengths_for_accounting,
    },
};

use super::{
    canonical_partial_stream::{
        selected_target_data_prime_count, selected_target_partial_decryption_stream_byte_length,
    },
    kllps_release::{
        KLLPS_PAIRED_TARGET_ROLE_COUNT, KLLPS_PARTICIPANT_COUNT, KLLPS_POINT_STRIDE,
        KLLPS_RECONSTRUCTION_THRESHOLD, authorized_scaled_lagrange_coefficient_at_zero,
        selected_kllps_target_release_source_provider_memory_accounting,
    },
};

const TARGET_CIPHERTEXT_COMPONENT_COUNT: u64 = 2;
const CANONICAL_RESIDUE_BYTE_LENGTH: u64 = size_of::<u64>() as u64;
const WASM_WORD_BYTE_LENGTH: u64 = size_of::<u32>() as u64;
const TARGET_SHARE_RESOLVER_CALL_COUNT: u64 = 1;
const PARTIAL_OUTPUT_STORE_RESOLVER_CALL_COUNT: u64 = 2;
const TARGET_SPECIFIC_CHECKPOINT_BYTE_LENGTH: u64 = 0;
const TARGET_SPECIFIC_CHECKPOINT_TRANSACTION_COUNT: u64 = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SelectedTargetReleaseStaticAccountingError {
    EmptyProof,
    ProofOutsideSupportedProfile,
    InvalidSelectedProfile,
    CanonicalEncoding,
    SourceProviderMemory,
    InvalidReconstructionInput,
    CountOverflow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum SelectedTargetReleaseStaticAccountingGap {
    InjectedProofOutputStorePersistenceAndRetainedCopyLiveness,
    InjectedPartialOutputStorePersistenceAndRetainedCopyLiveness,
    CallbackOwnedStateCertificationTraffic,
    PublicTargetShareDistributionFanout,
    ReconstructedResultStateAndTransportTransition,
}

impl SelectedTargetReleaseStaticAccountingGap {
    pub(crate) const fn dimension(self) -> &'static str {
        match self {
            Self::InjectedProofOutputStorePersistenceAndRetainedCopyLiveness => {
                "target-release-proof-output-store"
            }
            Self::InjectedPartialOutputStorePersistenceAndRetainedCopyLiveness => {
                "target-release-partial-output-store"
            }
            Self::CallbackOwnedStateCertificationTraffic => {
                "target-release-state-certification-traffic"
            }
            Self::PublicTargetShareDistributionFanout => "target-release-public-share-distribution",
            Self::ReconstructedResultStateAndTransportTransition => {
                "target-release-result-transition"
            }
        }
    }

    pub(crate) const fn reason_code(self) -> &'static str {
        match self {
            Self::InjectedProofOutputStorePersistenceAndRetainedCopyLiveness => {
                "proof-output-store-lifetime-not-production-fixed"
            }
            Self::InjectedPartialOutputStorePersistenceAndRetainedCopyLiveness => {
                "partial-output-store-lifetime-not-production-fixed"
            }
            Self::CallbackOwnedStateCertificationTraffic => {
                "state-certification-traffic-not-production-fixed"
            }
            Self::PublicTargetShareDistributionFanout => {
                "public-share-distribution-fanout-not-production-fixed"
            }
            Self::ReconstructedResultStateAndTransportTransition => {
                "reconstructed-result-transition-not-production-fixed"
            }
        }
    }

    pub(crate) const fn required_carrier(self) -> &'static str {
        match self {
            Self::InjectedProofOutputStorePersistenceAndRetainedCopyLiveness => {
                "production proof-output store persistence, copy, and release lifetime"
            }
            Self::InjectedPartialOutputStorePersistenceAndRetainedCopyLiveness => {
                "production partial-output store persistence, copy, and release lifetime"
            }
            Self::CallbackOwnedStateCertificationTraffic => {
                "production target-share state certification transport and lifetime"
            }
            Self::PublicTargetShareDistributionFanout => {
                "production target-share public distribution topology and recipient fanout"
            }
            Self::ReconstructedResultStateAndTransportTransition => {
                "production reconstructed-result state or transport transition"
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SelectedTargetReleaseCanonicalMaterialAccounting {
    pub(crate) one_target_ciphertext_canonical_byte_length_ceiling: u64,
    pub(crate) paired_target_ciphertext_canonical_byte_length_ceiling: u64,
    pub(crate) one_target_ciphertext_decoded_coefficient_payload_byte_length: u64,
    pub(crate) paired_target_ciphertext_decoded_coefficient_payload_byte_length: u64,
    pub(crate) one_partial_stream_byte_length: u64,
    pub(crate) one_partial_stream_chunk_count: u64,
    pub(crate) one_partial_stream_descriptor_byte_length: u64,
    pub(crate) paired_partial_stream_byte_length: u64,
    pub(crate) paired_partial_stream_chunk_count: u64,
    pub(crate) paired_partial_coefficient_payload_byte_length: u64,
    pub(crate) ceremony_partial_stream_byte_length: u64,
    pub(crate) target_share_proof_byte_length_ceiling: u64,
    pub(crate) target_share_proof_chunk_count_ceiling: u64,
    pub(crate) target_share_proof_descriptor_byte_length_ceiling: u64,
    pub(crate) target_share_bundle_header_byte_length_ceiling: u64,
    pub(crate) target_share_signed_carrier_byte_length_ceiling: u64,
    pub(crate) one_target_share_bundle_byte_length_ceiling: u64,
    pub(crate) one_target_share_bundle_chunk_count_ceiling: u64,
    pub(crate) complete_action_target_share_bundle_byte_length_ceiling: u64,
    pub(crate) complete_action_target_share_bundle_chunk_count_ceiling: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SelectedTargetReleasePreparationOperationAccounting {
    pub(crate) preparation_count: u64,
    pub(crate) flooding_polynomial_count: u64,
    pub(crate) flooding_coefficient_sample_count: u64,
    pub(crate) minimum_private_randomness_candidate_draw_count: u64,
    pub(crate) maximum_private_randomness_candidate_draw_count: u64,
    pub(crate) threshold_share_forward_negacyclic_transform_count: u64,
    pub(crate) target_component_forward_negacyclic_transform_count: u64,
    pub(crate) partial_inverse_negacyclic_transform_count: u64,
    pub(crate) positive_message_conversion_modular_inverse_count: u64,
    pub(crate) partial_constant_scale_multiplication_count: u64,
    pub(crate) converted_target_coefficient_multiplication_count: u64,
    pub(crate) pointwise_product_coefficient_multiplication_count: u64,
    pub(crate) partial_scaling_coefficient_multiplication_count: u64,
    pub(crate) partial_scaling_coefficient_addition_count: u64,
    pub(crate) flooding_big_integer_residue_reduction_count: u64,
    pub(crate) partial_stream_encode_count: u64,
    pub(crate) partial_stream_encoded_byte_length: u64,
    pub(crate) partial_stream_descriptor_derivation_count: u64,
    pub(crate) partial_stream_hash_scan_byte_length: u64,
    pub(crate) ciphertext_multiplication_count: u64,
    pub(crate) rotation_count: u64,
    pub(crate) modulus_switch_count: u64,
}

impl SelectedTargetReleasePreparationOperationAccounting {
    fn scaled(
        self,
        preparation_count: u64,
    ) -> Result<Self, SelectedTargetReleaseStaticAccountingError> {
        Ok(Self {
            preparation_count,
            flooding_polynomial_count: checked_multiply(
                self.flooding_polynomial_count,
                preparation_count,
            )?,
            flooding_coefficient_sample_count: checked_multiply(
                self.flooding_coefficient_sample_count,
                preparation_count,
            )?,
            minimum_private_randomness_candidate_draw_count: checked_multiply(
                self.minimum_private_randomness_candidate_draw_count,
                preparation_count,
            )?,
            maximum_private_randomness_candidate_draw_count: checked_multiply(
                self.maximum_private_randomness_candidate_draw_count,
                preparation_count,
            )?,
            threshold_share_forward_negacyclic_transform_count: checked_multiply(
                self.threshold_share_forward_negacyclic_transform_count,
                preparation_count,
            )?,
            target_component_forward_negacyclic_transform_count: checked_multiply(
                self.target_component_forward_negacyclic_transform_count,
                preparation_count,
            )?,
            partial_inverse_negacyclic_transform_count: checked_multiply(
                self.partial_inverse_negacyclic_transform_count,
                preparation_count,
            )?,
            positive_message_conversion_modular_inverse_count: checked_multiply(
                self.positive_message_conversion_modular_inverse_count,
                preparation_count,
            )?,
            partial_constant_scale_multiplication_count: checked_multiply(
                self.partial_constant_scale_multiplication_count,
                preparation_count,
            )?,
            converted_target_coefficient_multiplication_count: checked_multiply(
                self.converted_target_coefficient_multiplication_count,
                preparation_count,
            )?,
            pointwise_product_coefficient_multiplication_count: checked_multiply(
                self.pointwise_product_coefficient_multiplication_count,
                preparation_count,
            )?,
            partial_scaling_coefficient_multiplication_count: checked_multiply(
                self.partial_scaling_coefficient_multiplication_count,
                preparation_count,
            )?,
            partial_scaling_coefficient_addition_count: checked_multiply(
                self.partial_scaling_coefficient_addition_count,
                preparation_count,
            )?,
            flooding_big_integer_residue_reduction_count: checked_multiply(
                self.flooding_big_integer_residue_reduction_count,
                preparation_count,
            )?,
            partial_stream_encode_count: checked_multiply(
                self.partial_stream_encode_count,
                preparation_count,
            )?,
            partial_stream_encoded_byte_length: checked_multiply(
                self.partial_stream_encoded_byte_length,
                preparation_count,
            )?,
            partial_stream_descriptor_derivation_count: checked_multiply(
                self.partial_stream_descriptor_derivation_count,
                preparation_count,
            )?,
            partial_stream_hash_scan_byte_length: checked_multiply(
                self.partial_stream_hash_scan_byte_length,
                preparation_count,
            )?,
            ciphertext_multiplication_count: checked_multiply(
                self.ciphertext_multiplication_count,
                preparation_count,
            )?,
            rotation_count: checked_multiply(self.rotation_count, preparation_count)?,
            modulus_switch_count: checked_multiply(self.modulus_switch_count, preparation_count)?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SelectedTargetReleaseGenerationModeAccounting {
    pub(crate) operations: SelectedTargetReleasePreparationOperationAccounting,
    pub(crate) retained_output_partial_stream_byte_length: u64,
    pub(crate) regenerated_comparison_partial_stream_byte_length: u64,
    pub(crate) maximum_simultaneously_live_partial_stream_payload_byte_length: u64,
    pub(crate) generation_owned_javascript_input_copy_byte_length_ceiling: u64,
    pub(crate) generation_wasm_input_copy_byte_length_ceiling: u64,
    pub(crate) generation_additional_input_copy_live_set_byte_length_ceiling: u64,
    pub(crate) proof_output_store_commit_byte_length_ceiling: u64,
    pub(crate) proof_output_store_commit_count_ceiling: u64,
    pub(crate) proof_output_descriptor_store_read_byte_length_ceiling: u64,
    pub(crate) proof_output_descriptor_store_read_count_ceiling: u64,
    pub(crate) proof_output_descriptor_javascript_copy_byte_length_ceiling: u64,
    pub(crate) proof_output_descriptor_javascript_to_wasm_copy_byte_length_ceiling: u64,
    pub(crate) proof_output_descriptor_wasm_to_javascript_copy_byte_length_ceiling: u64,
    pub(crate) partial_output_store_resolver_call_count: u64,
    pub(crate) partial_output_store_commit_byte_length: u64,
    pub(crate) partial_output_store_commit_count: u64,
    pub(crate) partial_stream_rust_to_wasm_copy_byte_length: u64,
    pub(crate) partial_stream_wasm_to_javascript_copy_byte_length: u64,
    pub(crate) partial_descriptor_rust_to_wasm_copy_byte_length: u64,
    pub(crate) partial_descriptor_wasm_to_javascript_copy_byte_length: u64,
    pub(crate) partial_descriptor_store_resolver_copy_byte_length: u64,
    pub(crate) target_share_resolver_call_count: u64,
    pub(crate) target_share_resolver_descriptor_copy_byte_length_ceiling: u64,
    pub(crate) required_store_owned_payload_byte_length_ceiling: u64,
    pub(crate) maximum_partial_output_boundary_copy_live_set_byte_length: u64,
    pub(crate) maximum_proof_descriptor_derivation_copy_live_set_byte_length_ceiling: u64,
    pub(crate) target_specific_checkpoint_byte_length: u64,
    pub(crate) target_specific_checkpoint_transaction_count: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SelectedTargetReleaseSourceProviderResidentAccounting {
    pub(crate) loading_persistent_resident_byte_length: u64,
    pub(crate) post_source_polynomial_finish_persistent_resident_byte_length: u64,
    pub(crate) additional_loading_transient_byte_length: u64,
    pub(crate) maximum_returned_source_polynomial_byte_length: u64,
    pub(crate) fresh_loading_with_retained_partial_streams_byte_length: u64,
    pub(crate) resumed_preparation_with_both_partial_stream_pairs_byte_length: u64,
    pub(crate) resumed_loading_with_retained_partial_streams_byte_length: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SelectedTargetReleaseVerificationAccounting {
    pub(crate) owned_javascript_input_copy_byte_length_ceiling: u64,
    pub(crate) wasm_input_copy_byte_length_ceiling: u64,
    pub(crate) additional_input_copy_live_set_byte_length_ceiling: u64,
    pub(crate) proof_input_store_read_byte_length_ceiling: u64,
    pub(crate) proof_input_store_read_count_ceiling: u64,
    pub(crate) retained_partial_wire_byte_length: u64,
    pub(crate) retained_decoded_target_coefficient_payload_byte_length: u64,
    pub(crate) terminal_retained_wire_and_target_payload_byte_length: u64,
    pub(crate) verified_share_decoded_partial_coefficient_payload_byte_length: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SelectedTargetReleaseReconstructionBufferAccounting {
    pub(crate) supplied_verified_share_count: u64,
    pub(crate) selected_verified_share_count: u64,
    pub(crate) verified_share_handle_byte_length: u64,
    pub(crate) retained_verified_share_coefficient_payload_byte_length: u64,
    pub(crate) owned_javascript_input_copy_byte_length_ceiling: u64,
    pub(crate) wasm_input_copy_byte_length_ceiling: u64,
    pub(crate) additional_input_copy_live_set_byte_length_ceiling: u64,
    pub(crate) reconstructed_result_byte_length: u64,
    pub(crate) reconstructed_result_boundary_copy_live_set_byte_length: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SelectedTargetReleaseReconstructionOperationAccounting {
    pub(crate) selected_roster_positions: [u16; KLLPS_RECONSTRUCTION_THRESHOLD],
    pub(crate) lagrange_coefficient_derivation_count: u64,
    pub(crate) lagrange_subring_polynomial_multiplication_count: u64,
    pub(crate) lagrange_subring_linear_solve_count: u64,
    pub(crate) nonzero_lagrange_subring_coefficient_count: u64,
    pub(crate) ciphertext_component_scale_multiplication_count: u64,
    pub(crate) full_ring_accumulation_multiplication_count: u64,
    pub(crate) full_ring_accumulation_addition_count: u64,
    pub(crate) full_ring_accumulation_subtraction_count: u64,
    pub(crate) full_modulus_centered_lift_count: u64,
    pub(crate) plaintext_decode_coefficient_count: u64,
    pub(crate) forward_negacyclic_transform_count: u64,
    pub(crate) inverse_negacyclic_transform_count: u64,
    pub(crate) ciphertext_multiplication_count: u64,
    pub(crate) rotation_count: u64,
    pub(crate) modulus_switch_count: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SelectedTargetReleaseReconstructionOperationCounts {
    pub(crate) lagrange_coefficient_derivation_count: u64,
    pub(crate) lagrange_subring_polynomial_multiplication_count: u64,
    pub(crate) lagrange_subring_linear_solve_count: u64,
    pub(crate) nonzero_lagrange_subring_coefficient_count: u64,
    pub(crate) ciphertext_component_scale_multiplication_count: u64,
    pub(crate) full_ring_accumulation_multiplication_count: u64,
    pub(crate) full_ring_accumulation_addition_count: u64,
    pub(crate) full_ring_accumulation_subtraction_count: u64,
    pub(crate) full_modulus_centered_lift_count: u64,
    pub(crate) plaintext_decode_coefficient_count: u64,
    pub(crate) forward_negacyclic_transform_count: u64,
    pub(crate) inverse_negacyclic_transform_count: u64,
    pub(crate) ciphertext_multiplication_count: u64,
    pub(crate) rotation_count: u64,
    pub(crate) modulus_switch_count: u64,
}

impl SelectedTargetReleaseReconstructionOperationAccounting {
    pub(crate) const fn counts(self) -> SelectedTargetReleaseReconstructionOperationCounts {
        SelectedTargetReleaseReconstructionOperationCounts {
            lagrange_coefficient_derivation_count: self.lagrange_coefficient_derivation_count,
            lagrange_subring_polynomial_multiplication_count: self
                .lagrange_subring_polynomial_multiplication_count,
            lagrange_subring_linear_solve_count: self.lagrange_subring_linear_solve_count,
            nonzero_lagrange_subring_coefficient_count: self
                .nonzero_lagrange_subring_coefficient_count,
            ciphertext_component_scale_multiplication_count: self
                .ciphertext_component_scale_multiplication_count,
            full_ring_accumulation_multiplication_count: self
                .full_ring_accumulation_multiplication_count,
            full_ring_accumulation_addition_count: self.full_ring_accumulation_addition_count,
            full_ring_accumulation_subtraction_count: self.full_ring_accumulation_subtraction_count,
            full_modulus_centered_lift_count: self.full_modulus_centered_lift_count,
            plaintext_decode_coefficient_count: self.plaintext_decode_coefficient_count,
            forward_negacyclic_transform_count: self.forward_negacyclic_transform_count,
            inverse_negacyclic_transform_count: self.inverse_negacyclic_transform_count,
            ciphertext_multiplication_count: self.ciphertext_multiplication_count,
            rotation_count: self.rotation_count,
            modulus_switch_count: self.modulus_switch_count,
        }
    }
}

impl SelectedTargetReleaseReconstructionOperationCounts {
    fn componentwise_minimum(self, other: Self) -> Self {
        Self {
            lagrange_coefficient_derivation_count: self
                .lagrange_coefficient_derivation_count
                .min(other.lagrange_coefficient_derivation_count),
            lagrange_subring_polynomial_multiplication_count: self
                .lagrange_subring_polynomial_multiplication_count
                .min(other.lagrange_subring_polynomial_multiplication_count),
            lagrange_subring_linear_solve_count: self
                .lagrange_subring_linear_solve_count
                .min(other.lagrange_subring_linear_solve_count),
            nonzero_lagrange_subring_coefficient_count: self
                .nonzero_lagrange_subring_coefficient_count
                .min(other.nonzero_lagrange_subring_coefficient_count),
            ciphertext_component_scale_multiplication_count: self
                .ciphertext_component_scale_multiplication_count
                .min(other.ciphertext_component_scale_multiplication_count),
            full_ring_accumulation_multiplication_count: self
                .full_ring_accumulation_multiplication_count
                .min(other.full_ring_accumulation_multiplication_count),
            full_ring_accumulation_addition_count: self
                .full_ring_accumulation_addition_count
                .min(other.full_ring_accumulation_addition_count),
            full_ring_accumulation_subtraction_count: self
                .full_ring_accumulation_subtraction_count
                .min(other.full_ring_accumulation_subtraction_count),
            full_modulus_centered_lift_count: self
                .full_modulus_centered_lift_count
                .min(other.full_modulus_centered_lift_count),
            plaintext_decode_coefficient_count: self
                .plaintext_decode_coefficient_count
                .min(other.plaintext_decode_coefficient_count),
            forward_negacyclic_transform_count: self
                .forward_negacyclic_transform_count
                .min(other.forward_negacyclic_transform_count),
            inverse_negacyclic_transform_count: self
                .inverse_negacyclic_transform_count
                .min(other.inverse_negacyclic_transform_count),
            ciphertext_multiplication_count: self
                .ciphertext_multiplication_count
                .min(other.ciphertext_multiplication_count),
            rotation_count: self.rotation_count.min(other.rotation_count),
            modulus_switch_count: self.modulus_switch_count.min(other.modulus_switch_count),
        }
    }

    fn componentwise_maximum(self, other: Self) -> Self {
        Self {
            lagrange_coefficient_derivation_count: self
                .lagrange_coefficient_derivation_count
                .max(other.lagrange_coefficient_derivation_count),
            lagrange_subring_polynomial_multiplication_count: self
                .lagrange_subring_polynomial_multiplication_count
                .max(other.lagrange_subring_polynomial_multiplication_count),
            lagrange_subring_linear_solve_count: self
                .lagrange_subring_linear_solve_count
                .max(other.lagrange_subring_linear_solve_count),
            nonzero_lagrange_subring_coefficient_count: self
                .nonzero_lagrange_subring_coefficient_count
                .max(other.nonzero_lagrange_subring_coefficient_count),
            ciphertext_component_scale_multiplication_count: self
                .ciphertext_component_scale_multiplication_count
                .max(other.ciphertext_component_scale_multiplication_count),
            full_ring_accumulation_multiplication_count: self
                .full_ring_accumulation_multiplication_count
                .max(other.full_ring_accumulation_multiplication_count),
            full_ring_accumulation_addition_count: self
                .full_ring_accumulation_addition_count
                .max(other.full_ring_accumulation_addition_count),
            full_ring_accumulation_subtraction_count: self
                .full_ring_accumulation_subtraction_count
                .max(other.full_ring_accumulation_subtraction_count),
            full_modulus_centered_lift_count: self
                .full_modulus_centered_lift_count
                .max(other.full_modulus_centered_lift_count),
            plaintext_decode_coefficient_count: self
                .plaintext_decode_coefficient_count
                .max(other.plaintext_decode_coefficient_count),
            forward_negacyclic_transform_count: self
                .forward_negacyclic_transform_count
                .max(other.forward_negacyclic_transform_count),
            inverse_negacyclic_transform_count: self
                .inverse_negacyclic_transform_count
                .max(other.inverse_negacyclic_transform_count),
            ciphertext_multiplication_count: self
                .ciphertext_multiplication_count
                .max(other.ciphertext_multiplication_count),
            rotation_count: self.rotation_count.max(other.rotation_count),
            modulus_switch_count: self.modulus_switch_count.max(other.modulus_switch_count),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SelectedTargetReleaseReconstructionSubsetAccounting {
    pub(crate) valid_subset_count: u64,
    pub(crate) all_operation_counts_equal: bool,
    pub(crate) minimum_operation_counts: SelectedTargetReleaseReconstructionOperationCounts,
    pub(crate) maximum_operation_counts: SelectedTargetReleaseReconstructionOperationCounts,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SelectedTargetReleaseStaticAccounting {
    pub(crate) participant_count: u64,
    pub(crate) target_role_count: u64,
    pub(crate) target_data_prime_count: u64,
    pub(crate) polynomial_degree: u64,
    pub(crate) plaintext_modulus: u64,
    pub(crate) reconstruction_threshold: u64,
    pub(crate) canonical_material: SelectedTargetReleaseCanonicalMaterialAccounting,
    pub(crate) fresh_generation: SelectedTargetReleaseGenerationModeAccounting,
    pub(crate) resumed_generation: SelectedTargetReleaseGenerationModeAccounting,
    pub(crate) source_provider_resident: SelectedTargetReleaseSourceProviderResidentAccounting,
    pub(crate) verification: SelectedTargetReleaseVerificationAccounting,
    pub(crate) complete_action_reconstruction_buffers:
        SelectedTargetReleaseReconstructionBufferAccounting,
    pub(crate) complete_action_reconstruction_operations:
        SelectedTargetReleaseReconstructionOperationAccounting,
    pub(crate) reconstruction_subset_operations:
        SelectedTargetReleaseReconstructionSubsetAccounting,
    pub(crate) gaps: Box<[SelectedTargetReleaseStaticAccountingGap]>,
}

impl SelectedTargetReleaseStaticAccounting {
    pub(crate) fn reconstruction_buffer_accounting(
        &self,
        supplied_verified_share_count: u16,
        selected_option_count: u16,
    ) -> Result<
        SelectedTargetReleaseReconstructionBufferAccounting,
        SelectedTargetReleaseStaticAccountingError,
    > {
        derive_reconstruction_buffer_accounting(
            self.canonical_material,
            supplied_verified_share_count,
            selected_option_count,
        )
    }
}

pub(crate) fn derive_selected_target_release_static_accounting(
    one_target_share_proof_byte_length_ceiling: u64,
) -> Result<SelectedTargetReleaseStaticAccounting, SelectedTargetReleaseStaticAccountingError> {
    validate_selected_profile()?;
    if one_target_share_proof_byte_length_ceiling == 0 {
        return Err(SelectedTargetReleaseStaticAccountingError::EmptyProof);
    }
    let maximum_common_proof_byte_length = u64::try_from(MAXIMUM_COMMON_PROOF_BYTE_LENGTH)
        .map_err(|_| SelectedTargetReleaseStaticAccountingError::CountOverflow)?;
    if one_target_share_proof_byte_length_ceiling > maximum_common_proof_byte_length
        || one_target_share_proof_byte_length_ceiling > MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH
    {
        return Err(SelectedTargetReleaseStaticAccountingError::ProofOutsideSupportedProfile);
    }

    let participant_count = u64::from(FOUNDATION_PROFILE.participant_count);
    let target_role_count = u64::try_from(KLLPS_PAIRED_TARGET_ROLE_COUNT)
        .map_err(|_| SelectedTargetReleaseStaticAccountingError::CountOverflow)?;
    let target_data_prime_count = u64::try_from(selected_target_data_prime_count())
        .map_err(|_| SelectedTargetReleaseStaticAccountingError::CountOverflow)?;
    let polynomial_degree = u64::try_from(POLYNOMIAL_DEGREE)
        .map_err(|_| SelectedTargetReleaseStaticAccountingError::CountOverflow)?;
    let reconstruction_threshold = u64::try_from(KLLPS_RECONSTRUCTION_THRESHOLD)
        .map_err(|_| SelectedTargetReleaseStaticAccountingError::CountOverflow)?;
    let stream_chunk_byte_length = u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length)
        .map_err(|_| SelectedTargetReleaseStaticAccountingError::CountOverflow)?;
    let proof_chunk_byte_length = u64::try_from(MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH)
        .map_err(|_| SelectedTargetReleaseStaticAccountingError::CountOverflow)?;
    if proof_chunk_byte_length != stream_chunk_byte_length {
        return Err(SelectedTargetReleaseStaticAccountingError::InvalidSelectedProfile);
    }

    let one_target_ciphertext_canonical_byte_length_ceiling =
        two_component_data_ciphertext_canonical_byte_length_ceiling_at_level(
            CANONICAL_TARGET_CIPHERTEXT_LEVEL,
        )
        .map_err(|_| SelectedTargetReleaseStaticAccountingError::CanonicalEncoding)?;
    let paired_target_ciphertext_canonical_byte_length_ceiling = checked_multiply(
        one_target_ciphertext_canonical_byte_length_ceiling,
        target_role_count,
    )?;
    let one_target_ciphertext_decoded_coefficient_payload_byte_length = [
        TARGET_CIPHERTEXT_COMPONENT_COUNT,
        target_data_prime_count,
        polynomial_degree,
        CANONICAL_RESIDUE_BYTE_LENGTH,
    ]
    .into_iter()
    .try_fold(1_u64, checked_multiply)?;
    let paired_target_ciphertext_decoded_coefficient_payload_byte_length = checked_multiply(
        one_target_ciphertext_decoded_coefficient_payload_byte_length,
        target_role_count,
    )?;
    let one_partial_stream_byte_length = u64::try_from(
        selected_target_partial_decryption_stream_byte_length()
            .map_err(|_| SelectedTargetReleaseStaticAccountingError::InvalidSelectedProfile)?,
    )
    .map_err(|_| SelectedTargetReleaseStaticAccountingError::CountOverflow)?;
    let one_partial_stream_chunk_count =
        one_partial_stream_byte_length.div_ceil(stream_chunk_byte_length);
    let paired_partial_stream_byte_length =
        checked_multiply(one_partial_stream_byte_length, target_role_count)?;
    let paired_partial_stream_chunk_count =
        checked_multiply(one_partial_stream_chunk_count, target_role_count)?;
    let one_partial_coefficient_payload_byte_length = [
        target_data_prime_count,
        polynomial_degree,
        CANONICAL_RESIDUE_BYTE_LENGTH,
    ]
    .into_iter()
    .try_fold(1_u64, checked_multiply)?;
    let paired_partial_coefficient_payload_byte_length = checked_multiply(
        one_partial_coefficient_payload_byte_length,
        target_role_count,
    )?;
    let ceremony_partial_stream_byte_length =
        checked_multiply(paired_partial_stream_byte_length, participant_count)?;

    let target_identifier_descriptor =
        descriptor_for_byte_length(one_partial_stream_byte_length, 0x21)?;
    let target_order_descriptor = descriptor_for_byte_length(one_partial_stream_byte_length, 0x22)?;
    let proof_descriptor =
        descriptor_for_byte_length(one_target_share_proof_byte_length_ceiling, 0x23)?;
    let one_partial_stream_descriptor_byte_length =
        encoded_descriptor_byte_length(&target_identifier_descriptor)?;
    if encoded_descriptor_byte_length(&target_order_descriptor)?
        != one_partial_stream_descriptor_byte_length
    {
        return Err(SelectedTargetReleaseStaticAccountingError::InvalidSelectedProfile);
    }
    let target_share_proof_descriptor_byte_length_ceiling =
        encoded_descriptor_byte_length(&proof_descriptor)?;
    let target_share_bundle_lengths: TargetReleaseOutputBundleByteLengths =
        canonical_target_release_output_bundle_byte_lengths_for_accounting(
            &target_identifier_descriptor,
            &target_order_descriptor,
            &proof_descriptor,
        )
        .map_err(|_| SelectedTargetReleaseStaticAccountingError::CanonicalEncoding)?;
    if target_share_bundle_lengths.target_identifier() != one_partial_stream_byte_length
        || target_share_bundle_lengths.target_order() != one_partial_stream_byte_length
        || target_share_bundle_lengths.malicious_share_proof()
            != one_target_share_proof_byte_length_ceiling
    {
        return Err(SelectedTargetReleaseStaticAccountingError::InvalidSelectedProfile);
    }
    let one_target_share_bundle_byte_length_ceiling = target_share_bundle_lengths.total();
    let one_target_share_bundle_chunk_count_ceiling =
        one_target_share_bundle_byte_length_ceiling.div_ceil(stream_chunk_byte_length);
    let complete_action_target_share_bundle_byte_length_ceiling = checked_multiply(
        one_target_share_bundle_byte_length_ceiling,
        participant_count,
    )?;
    let complete_action_target_share_bundle_chunk_count_ceiling = checked_multiply(
        one_target_share_bundle_chunk_count_ceiling,
        participant_count,
    )?;
    let target_share_proof_chunk_count_ceiling =
        one_target_share_proof_byte_length_ceiling.div_ceil(proof_chunk_byte_length);
    let canonical_material = SelectedTargetReleaseCanonicalMaterialAccounting {
        one_target_ciphertext_canonical_byte_length_ceiling,
        paired_target_ciphertext_canonical_byte_length_ceiling,
        one_target_ciphertext_decoded_coefficient_payload_byte_length,
        paired_target_ciphertext_decoded_coefficient_payload_byte_length,
        one_partial_stream_byte_length,
        one_partial_stream_chunk_count,
        one_partial_stream_descriptor_byte_length,
        paired_partial_stream_byte_length,
        paired_partial_stream_chunk_count,
        paired_partial_coefficient_payload_byte_length,
        ceremony_partial_stream_byte_length,
        target_share_proof_byte_length_ceiling: one_target_share_proof_byte_length_ceiling,
        target_share_proof_chunk_count_ceiling,
        target_share_proof_descriptor_byte_length_ceiling,
        target_share_bundle_header_byte_length_ceiling: target_share_bundle_lengths.header(),
        target_share_signed_carrier_byte_length_ceiling: target_share_bundle_lengths
            .signed_carrier(),
        one_target_share_bundle_byte_length_ceiling,
        one_target_share_bundle_chunk_count_ceiling,
        complete_action_target_share_bundle_byte_length_ceiling,
        complete_action_target_share_bundle_chunk_count_ceiling,
    };

    let one_preparation_operations = derive_one_preparation_operations(
        target_role_count,
        target_data_prime_count,
        polynomial_degree,
        paired_partial_stream_byte_length,
    )?;
    let fresh_operations = one_preparation_operations.scaled(1)?;
    let resumed_operations = one_preparation_operations.scaled(2)?;
    let fresh_generation =
        derive_generation_mode_accounting(canonical_material, fresh_operations, 0)?;
    let resumed_generation = derive_generation_mode_accounting(
        canonical_material,
        resumed_operations,
        paired_partial_stream_byte_length,
    )?;
    let source_provider_resident =
        derive_source_provider_resident_accounting(paired_partial_stream_byte_length)?;
    let verification = derive_verification_accounting(canonical_material)?;
    let complete_action_reconstruction_buffers = derive_reconstruction_buffer_accounting(
        canonical_material,
        FOUNDATION_PROFILE.participant_count,
        FOUNDATION_PROFILE.option_count,
    )?;
    let complete_action_reconstruction_operations =
        derive_selected_target_release_reconstruction_operation_accounting([0, 1, 2, 3])?;
    let reconstruction_subset_operations =
        derive_selected_target_release_reconstruction_subset_accounting()?;

    Ok(SelectedTargetReleaseStaticAccounting {
        participant_count,
        target_role_count,
        target_data_prime_count,
        polynomial_degree,
        plaintext_modulus: PLAINTEXT_MODULUS,
        reconstruction_threshold,
        canonical_material,
        fresh_generation,
        resumed_generation,
        source_provider_resident,
        verification,
        complete_action_reconstruction_buffers,
        complete_action_reconstruction_operations,
        reconstruction_subset_operations,
        gaps: Box::new([
            SelectedTargetReleaseStaticAccountingGap::InjectedProofOutputStorePersistenceAndRetainedCopyLiveness,
            SelectedTargetReleaseStaticAccountingGap::InjectedPartialOutputStorePersistenceAndRetainedCopyLiveness,
            SelectedTargetReleaseStaticAccountingGap::CallbackOwnedStateCertificationTraffic,
            SelectedTargetReleaseStaticAccountingGap::PublicTargetShareDistributionFanout,
            SelectedTargetReleaseStaticAccountingGap::ReconstructedResultStateAndTransportTransition,
        ]),
    })
}

fn derive_selected_target_release_reconstruction_subset_accounting() -> Result<
    SelectedTargetReleaseReconstructionSubsetAccounting,
    SelectedTargetReleaseStaticAccountingError,
> {
    let mut valid_subset_count = 0_u64;
    let mut minimum_operation_counts: Option<SelectedTargetReleaseReconstructionOperationCounts> =
        None;
    let mut maximum_operation_counts: Option<SelectedTargetReleaseReconstructionOperationCounts> =
        None;
    for first_position in 0..KLLPS_PARTICIPANT_COUNT {
        for second_position in (first_position + 1)..KLLPS_PARTICIPANT_COUNT {
            for third_position in (second_position + 1)..KLLPS_PARTICIPANT_COUNT {
                for fourth_position in (third_position + 1)..KLLPS_PARTICIPANT_COUNT {
                    let counts =
                        derive_selected_target_release_reconstruction_operation_accounting([
                            first_position,
                            second_position,
                            third_position,
                            fourth_position,
                        ])?
                        .counts();
                    valid_subset_count = checked_add(valid_subset_count, 1)?;
                    minimum_operation_counts = Some(match minimum_operation_counts {
                        Some(current) => current.componentwise_minimum(counts),
                        None => counts,
                    });
                    maximum_operation_counts = Some(match maximum_operation_counts {
                        Some(current) => current.componentwise_maximum(counts),
                        None => counts,
                    });
                }
            }
        }
    }
    let expected_subset_count = checked_binomial_coefficient(
        u64::try_from(KLLPS_PARTICIPANT_COUNT)
            .map_err(|_| SelectedTargetReleaseStaticAccountingError::CountOverflow)?,
        u64::try_from(KLLPS_RECONSTRUCTION_THRESHOLD)
            .map_err(|_| SelectedTargetReleaseStaticAccountingError::CountOverflow)?,
    )?;
    if valid_subset_count != expected_subset_count {
        return Err(SelectedTargetReleaseStaticAccountingError::InvalidSelectedProfile);
    }
    let minimum_operation_counts = minimum_operation_counts
        .ok_or(SelectedTargetReleaseStaticAccountingError::InvalidSelectedProfile)?;
    let maximum_operation_counts = maximum_operation_counts
        .ok_or(SelectedTargetReleaseStaticAccountingError::InvalidSelectedProfile)?;
    Ok(SelectedTargetReleaseReconstructionSubsetAccounting {
        valid_subset_count,
        all_operation_counts_equal: minimum_operation_counts == maximum_operation_counts,
        minimum_operation_counts,
        maximum_operation_counts,
    })
}

pub(crate) fn derive_selected_target_release_reconstruction_operation_accounting(
    selected_roster_positions: [usize; KLLPS_RECONSTRUCTION_THRESHOLD],
) -> Result<
    SelectedTargetReleaseReconstructionOperationAccounting,
    SelectedTargetReleaseStaticAccountingError,
> {
    validate_selected_profile()?;
    let target_role_count = u64::try_from(KLLPS_PAIRED_TARGET_ROLE_COUNT)
        .map_err(|_| SelectedTargetReleaseStaticAccountingError::CountOverflow)?;
    let target_data_prime_count = u64::try_from(selected_target_data_prime_count())
        .map_err(|_| SelectedTargetReleaseStaticAccountingError::CountOverflow)?;
    let polynomial_degree = u64::try_from(POLYNOMIAL_DEGREE)
        .map_err(|_| SelectedTargetReleaseStaticAccountingError::CountOverflow)?;
    let threshold = u64::try_from(KLLPS_RECONSTRUCTION_THRESHOLD)
        .map_err(|_| SelectedTargetReleaseStaticAccountingError::CountOverflow)?;
    let mut encoded_selected_roster_positions = [0_u16; KLLPS_RECONSTRUCTION_THRESHOLD];
    for (encoded_position, selected_roster_position) in encoded_selected_roster_positions
        .iter_mut()
        .zip(selected_roster_positions)
    {
        *encoded_position = u16::try_from(selected_roster_position)
            .map_err(|_| SelectedTargetReleaseStaticAccountingError::InvalidReconstructionInput)?;
    }
    let mut nonzero_lagrange_subring_coefficient_count = 0_u64;
    let mut full_ring_accumulation_multiplication_count = 0_u64;
    let mut full_ring_accumulation_addition_count = 0_u64;
    let mut full_ring_accumulation_subtraction_count = 0_u64;
    for modulus in DATA_PRIMES
        .iter()
        .take(selected_target_data_prime_count())
        .copied()
    {
        for selected_index in 0..KLLPS_RECONSTRUCTION_THRESHOLD {
            let coefficient = authorized_scaled_lagrange_coefficient_at_zero(
                &selected_roster_positions,
                selected_index,
                modulus,
            )
            .map_err(|_| SelectedTargetReleaseStaticAccountingError::InvalidReconstructionInput)?;
            for (subring_index, subring_coefficient) in coefficient.into_iter().enumerate() {
                if subring_coefficient == 0 {
                    continue;
                }
                nonzero_lagrange_subring_coefficient_count =
                    checked_add(nonzero_lagrange_subring_coefficient_count, 1)?;
                full_ring_accumulation_multiplication_count = checked_add(
                    full_ring_accumulation_multiplication_count,
                    checked_multiply(target_role_count, polynomial_degree)?,
                )?;
                let shift = u64::try_from(
                    subring_index
                        .checked_mul(KLLPS_POINT_STRIDE)
                        .ok_or(SelectedTargetReleaseStaticAccountingError::CountOverflow)?,
                )
                .map_err(|_| SelectedTargetReleaseStaticAccountingError::CountOverflow)?;
                full_ring_accumulation_addition_count = checked_add(
                    full_ring_accumulation_addition_count,
                    checked_multiply(
                        target_role_count,
                        polynomial_degree
                            .checked_sub(shift)
                            .ok_or(SelectedTargetReleaseStaticAccountingError::CountOverflow)?,
                    )?,
                )?;
                full_ring_accumulation_subtraction_count = checked_add(
                    full_ring_accumulation_subtraction_count,
                    checked_multiply(target_role_count, shift)?,
                )?;
            }
        }
    }
    let lagrange_coefficient_derivation_count =
        checked_multiply(target_data_prime_count, threshold)?;
    let other_selected_share_count = threshold
        .checked_sub(1)
        .ok_or(SelectedTargetReleaseStaticAccountingError::CountOverflow)?;
    let numerator_and_denominator_subring_multiplications =
        checked_multiply(other_selected_share_count, 2)?;
    let subring_degree = u64::try_from((2 * POLYNOMIAL_DEGREE) / KLLPS_POINT_STRIDE / 2)
        .map_err(|_| SelectedTargetReleaseStaticAccountingError::CountOverflow)?;
    let lagrange_subring_polynomial_multiplication_count = checked_multiply(
        lagrange_coefficient_derivation_count,
        checked_add(
            numerator_and_denominator_subring_multiplications,
            subring_degree,
        )?,
    )?;
    let ciphertext_component_scale_multiplication_count = [
        target_role_count,
        target_data_prime_count,
        polynomial_degree,
    ]
    .into_iter()
    .try_fold(1_u64, checked_multiply)?;
    let full_modulus_centered_lift_count = checked_multiply(target_role_count, polynomial_degree)?;
    Ok(SelectedTargetReleaseReconstructionOperationAccounting {
        selected_roster_positions: encoded_selected_roster_positions,
        lagrange_coefficient_derivation_count,
        lagrange_subring_polynomial_multiplication_count,
        lagrange_subring_linear_solve_count: lagrange_coefficient_derivation_count,
        nonzero_lagrange_subring_coefficient_count,
        ciphertext_component_scale_multiplication_count,
        full_ring_accumulation_multiplication_count,
        full_ring_accumulation_addition_count,
        full_ring_accumulation_subtraction_count,
        full_modulus_centered_lift_count,
        plaintext_decode_coefficient_count: full_modulus_centered_lift_count,
        forward_negacyclic_transform_count: 0,
        inverse_negacyclic_transform_count: 0,
        ciphertext_multiplication_count: 0,
        rotation_count: 0,
        modulus_switch_count: 0,
    })
}

fn validate_selected_profile() -> Result<(), SelectedTargetReleaseStaticAccountingError> {
    if usize::from(FOUNDATION_PROFILE.participant_count) != KLLPS_PARTICIPANT_COUNT
        || KLLPS_PARTICIPANT_COUNT != 10
        || POLYNOMIAL_DEGREE != 32_768
        || PLAINTEXT_MODULUS != 257
        || CANONICAL_TARGET_CIPHERTEXT_LEVEL + 1 != selected_target_data_prime_count()
        || selected_target_data_prime_count() != 8
        || KLLPS_PAIRED_TARGET_ROLE_COUNT != 2
        || KLLPS_RECONSTRUCTION_THRESHOLD != 4
    {
        return Err(SelectedTargetReleaseStaticAccountingError::InvalidSelectedProfile);
    }
    Ok(())
}

fn derive_one_preparation_operations(
    target_role_count: u64,
    target_data_prime_count: u64,
    polynomial_degree: u64,
    paired_partial_stream_byte_length: u64,
) -> Result<
    SelectedTargetReleasePreparationOperationAccounting,
    SelectedTargetReleaseStaticAccountingError,
> {
    let role_limb_count = checked_multiply(target_role_count, target_data_prime_count)?;
    let role_limb_coefficient_count = checked_multiply(role_limb_count, polynomial_degree)?;
    let flooding_coefficient_sample_count = checked_multiply(target_role_count, polynomial_degree)?;
    Ok(SelectedTargetReleasePreparationOperationAccounting {
        preparation_count: 1,
        flooding_polynomial_count: target_role_count,
        flooding_coefficient_sample_count,
        minimum_private_randomness_candidate_draw_count: flooding_coefficient_sample_count,
        maximum_private_randomness_candidate_draw_count: checked_multiply(
            flooding_coefficient_sample_count,
            u64::from(SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT),
        )?,
        threshold_share_forward_negacyclic_transform_count: target_data_prime_count,
        target_component_forward_negacyclic_transform_count: role_limb_count,
        partial_inverse_negacyclic_transform_count: role_limb_count,
        positive_message_conversion_modular_inverse_count: checked_multiply(role_limb_count, 2)?,
        partial_constant_scale_multiplication_count: role_limb_count,
        converted_target_coefficient_multiplication_count: role_limb_coefficient_count,
        pointwise_product_coefficient_multiplication_count: role_limb_coefficient_count,
        partial_scaling_coefficient_multiplication_count: checked_multiply(
            role_limb_coefficient_count,
            2,
        )?,
        partial_scaling_coefficient_addition_count: role_limb_coefficient_count,
        flooding_big_integer_residue_reduction_count: role_limb_coefficient_count,
        partial_stream_encode_count: target_role_count,
        partial_stream_encoded_byte_length: paired_partial_stream_byte_length,
        partial_stream_descriptor_derivation_count: checked_multiply(target_role_count, 2)?,
        partial_stream_hash_scan_byte_length: checked_multiply(
            paired_partial_stream_byte_length,
            3,
        )?,
        ciphertext_multiplication_count: 0,
        rotation_count: 0,
        modulus_switch_count: 0,
    })
}

fn derive_generation_mode_accounting(
    canonical_material: SelectedTargetReleaseCanonicalMaterialAccounting,
    operations: SelectedTargetReleasePreparationOperationAccounting,
    regenerated_comparison_partial_stream_byte_length: u64,
) -> Result<SelectedTargetReleaseGenerationModeAccounting, SelectedTargetReleaseStaticAccountingError>
{
    let checkpoint_lineage_identifier_byte_length =
        u64::try_from(target_release_checkpoint_lineage_identifier_byte_length())
            .map_err(|_| SelectedTargetReleaseStaticAccountingError::CountOverflow)?;
    let generation_input_copy_byte_length_ceiling = checked_add(
        canonical_material.paired_target_ciphertext_canonical_byte_length_ceiling,
        checkpoint_lineage_identifier_byte_length,
    )?;
    let paired_partial_descriptor_byte_length = checked_multiply(
        canonical_material.one_partial_stream_descriptor_byte_length,
        2,
    )?;
    let resolver_descriptor_copy_byte_length = checked_add(
        paired_partial_descriptor_byte_length,
        canonical_material.target_share_proof_descriptor_byte_length_ceiling,
    )?;
    let maximum_partial_chunk_byte_length = canonical_material.one_partial_stream_byte_length.min(
        u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length)
            .map_err(|_| SelectedTargetReleaseStaticAccountingError::CountOverflow)?,
    );
    let maximum_proof_chunk_byte_length = canonical_material
        .target_share_proof_byte_length_ceiling
        .min(
            u64::try_from(MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH)
                .map_err(|_| SelectedTargetReleaseStaticAccountingError::CountOverflow)?,
        );
    Ok(SelectedTargetReleaseGenerationModeAccounting {
        operations,
        retained_output_partial_stream_byte_length: canonical_material
            .paired_partial_stream_byte_length,
        regenerated_comparison_partial_stream_byte_length,
        maximum_simultaneously_live_partial_stream_payload_byte_length: checked_add(
            canonical_material.paired_partial_stream_byte_length,
            regenerated_comparison_partial_stream_byte_length,
        )?,
        generation_owned_javascript_input_copy_byte_length_ceiling:
            generation_input_copy_byte_length_ceiling,
        generation_wasm_input_copy_byte_length_ceiling: generation_input_copy_byte_length_ceiling,
        generation_additional_input_copy_live_set_byte_length_ceiling: checked_multiply(
            generation_input_copy_byte_length_ceiling,
            2,
        )?,
        proof_output_store_commit_byte_length_ceiling: canonical_material
            .target_share_proof_byte_length_ceiling,
        proof_output_store_commit_count_ceiling: canonical_material
            .target_share_proof_chunk_count_ceiling,
        proof_output_descriptor_store_read_byte_length_ceiling: canonical_material
            .target_share_proof_byte_length_ceiling,
        proof_output_descriptor_store_read_count_ceiling: canonical_material
            .target_share_proof_chunk_count_ceiling,
        proof_output_descriptor_javascript_copy_byte_length_ceiling: canonical_material
            .target_share_proof_byte_length_ceiling,
        proof_output_descriptor_javascript_to_wasm_copy_byte_length_ceiling: canonical_material
            .target_share_proof_byte_length_ceiling,
        proof_output_descriptor_wasm_to_javascript_copy_byte_length_ceiling: canonical_material
            .target_share_proof_descriptor_byte_length_ceiling,
        partial_output_store_resolver_call_count: PARTIAL_OUTPUT_STORE_RESOLVER_CALL_COUNT,
        partial_output_store_commit_byte_length: canonical_material
            .paired_partial_stream_byte_length,
        partial_output_store_commit_count: canonical_material.paired_partial_stream_chunk_count,
        partial_stream_rust_to_wasm_copy_byte_length: canonical_material
            .paired_partial_stream_byte_length,
        partial_stream_wasm_to_javascript_copy_byte_length: canonical_material
            .paired_partial_stream_byte_length,
        partial_descriptor_rust_to_wasm_copy_byte_length: paired_partial_descriptor_byte_length,
        partial_descriptor_wasm_to_javascript_copy_byte_length:
            paired_partial_descriptor_byte_length,
        partial_descriptor_store_resolver_copy_byte_length: paired_partial_descriptor_byte_length,
        target_share_resolver_call_count: TARGET_SHARE_RESOLVER_CALL_COUNT,
        target_share_resolver_descriptor_copy_byte_length_ceiling:
            resolver_descriptor_copy_byte_length,
        required_store_owned_payload_byte_length_ceiling: checked_add(
            canonical_material.target_share_proof_byte_length_ceiling,
            canonical_material.paired_partial_stream_byte_length,
        )?,
        maximum_partial_output_boundary_copy_live_set_byte_length: checked_multiply(
            maximum_partial_chunk_byte_length,
            2,
        )?,
        maximum_proof_descriptor_derivation_copy_live_set_byte_length_ceiling: checked_multiply(
            maximum_proof_chunk_byte_length,
            3,
        )?,
        target_specific_checkpoint_byte_length: TARGET_SPECIFIC_CHECKPOINT_BYTE_LENGTH,
        target_specific_checkpoint_transaction_count: TARGET_SPECIFIC_CHECKPOINT_TRANSACTION_COUNT,
    })
}

fn derive_source_provider_resident_accounting(
    paired_partial_stream_byte_length: u64,
) -> Result<
    SelectedTargetReleaseSourceProviderResidentAccounting,
    SelectedTargetReleaseStaticAccountingError,
> {
    let accounting = selected_kllps_target_release_source_provider_memory_accounting()
        .map_err(|_| SelectedTargetReleaseStaticAccountingError::SourceProviderMemory)?;
    let loading_persistent_resident_byte_length =
        accounting.loading_persistent_resident_byte_length();
    let post_source_polynomial_finish_persistent_resident_byte_length =
        accounting.post_source_polynomial_finish_persistent_resident_byte_length();
    let additional_loading_transient_byte_length =
        accounting.additional_loading_transient_byte_length();
    let maximum_returned_source_polynomial_byte_length =
        accounting.maximum_returned_source_polynomial_byte_length();
    Ok(SelectedTargetReleaseSourceProviderResidentAccounting {
        loading_persistent_resident_byte_length,
        post_source_polynomial_finish_persistent_resident_byte_length,
        additional_loading_transient_byte_length,
        maximum_returned_source_polynomial_byte_length,
        fresh_loading_with_retained_partial_streams_byte_length: checked_add(
            checked_add(
                loading_persistent_resident_byte_length,
                additional_loading_transient_byte_length,
            )?,
            paired_partial_stream_byte_length,
        )?,
        resumed_preparation_with_both_partial_stream_pairs_byte_length: checked_add(
            loading_persistent_resident_byte_length,
            checked_multiply(paired_partial_stream_byte_length, 2)?,
        )?,
        resumed_loading_with_retained_partial_streams_byte_length: checked_add(
            checked_add(
                loading_persistent_resident_byte_length,
                additional_loading_transient_byte_length,
            )?,
            paired_partial_stream_byte_length,
        )?,
    })
}

fn derive_verification_accounting(
    canonical_material: SelectedTargetReleaseCanonicalMaterialAccounting,
) -> Result<SelectedTargetReleaseVerificationAccounting, SelectedTargetReleaseStaticAccountingError>
{
    let input_copy_byte_length_ceiling = checked_add(
        canonical_material.paired_target_ciphertext_canonical_byte_length_ceiling,
        canonical_material.paired_partial_stream_byte_length,
    )?;
    Ok(SelectedTargetReleaseVerificationAccounting {
        owned_javascript_input_copy_byte_length_ceiling: input_copy_byte_length_ceiling,
        wasm_input_copy_byte_length_ceiling: input_copy_byte_length_ceiling,
        additional_input_copy_live_set_byte_length_ceiling: checked_multiply(
            input_copy_byte_length_ceiling,
            2,
        )?,
        proof_input_store_read_byte_length_ceiling: canonical_material
            .target_share_proof_byte_length_ceiling,
        proof_input_store_read_count_ceiling: canonical_material
            .target_share_proof_chunk_count_ceiling,
        retained_partial_wire_byte_length: canonical_material.paired_partial_stream_byte_length,
        retained_decoded_target_coefficient_payload_byte_length: canonical_material
            .paired_target_ciphertext_decoded_coefficient_payload_byte_length,
        terminal_retained_wire_and_target_payload_byte_length: checked_add(
            canonical_material.paired_partial_stream_byte_length,
            canonical_material.paired_target_ciphertext_decoded_coefficient_payload_byte_length,
        )?,
        verified_share_decoded_partial_coefficient_payload_byte_length: canonical_material
            .paired_partial_coefficient_payload_byte_length,
    })
}

fn derive_reconstruction_buffer_accounting(
    canonical_material: SelectedTargetReleaseCanonicalMaterialAccounting,
    supplied_verified_share_count: u16,
    selected_option_count: u16,
) -> Result<
    SelectedTargetReleaseReconstructionBufferAccounting,
    SelectedTargetReleaseStaticAccountingError,
> {
    let supplied_verified_share_count_u64 = u64::from(supplied_verified_share_count);
    let selected_verified_share_count = u64::try_from(KLLPS_RECONSTRUCTION_THRESHOLD)
        .map_err(|_| SelectedTargetReleaseStaticAccountingError::CountOverflow)?;
    if supplied_verified_share_count_u64 < selected_verified_share_count
        || supplied_verified_share_count > FOUNDATION_PROFILE.participant_count
        || selected_option_count == 0
        || selected_option_count > FOUNDATION_PROFILE.option_count
    {
        return Err(SelectedTargetReleaseStaticAccountingError::InvalidReconstructionInput);
    }
    let verified_share_handle_byte_length =
        checked_multiply(supplied_verified_share_count_u64, WASM_WORD_BYTE_LENGTH)?;
    let retained_verified_share_coefficient_payload_byte_length = checked_multiply(
        supplied_verified_share_count_u64,
        canonical_material.paired_partial_coefficient_payload_byte_length,
    )?;
    let input_copy_byte_length_ceiling = checked_add(
        canonical_material.paired_target_ciphertext_canonical_byte_length_ceiling,
        verified_share_handle_byte_length,
    )?;
    let reconstructed_result_byte_length =
        checked_multiply(u64::from(selected_option_count), WASM_WORD_BYTE_LENGTH)?;
    Ok(SelectedTargetReleaseReconstructionBufferAccounting {
        supplied_verified_share_count: supplied_verified_share_count_u64,
        selected_verified_share_count,
        verified_share_handle_byte_length,
        retained_verified_share_coefficient_payload_byte_length,
        owned_javascript_input_copy_byte_length_ceiling: input_copy_byte_length_ceiling,
        wasm_input_copy_byte_length_ceiling: input_copy_byte_length_ceiling,
        additional_input_copy_live_set_byte_length_ceiling: checked_multiply(
            input_copy_byte_length_ceiling,
            2,
        )?,
        reconstructed_result_byte_length,
        reconstructed_result_boundary_copy_live_set_byte_length: checked_multiply(
            reconstructed_result_byte_length,
            2,
        )?,
    })
}

fn descriptor_for_byte_length(
    byte_length: u64,
    marker: u8,
) -> Result<StreamDescriptor, SelectedTargetReleaseStaticAccountingError> {
    if byte_length == 0 || byte_length > MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH {
        return Err(SelectedTargetReleaseStaticAccountingError::CanonicalEncoding);
    }
    let chunk_byte_length = u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length)
        .map_err(|_| SelectedTargetReleaseStaticAccountingError::CountOverflow)?;
    let chunk_count = usize::try_from(byte_length.div_ceil(chunk_byte_length))
        .map_err(|_| SelectedTargetReleaseStaticAccountingError::CountOverflow)?;
    let mut ordered_chunk_digests = Vec::new();
    ordered_chunk_digests
        .try_reserve_exact(chunk_count)
        .map_err(|_| SelectedTargetReleaseStaticAccountingError::CountOverflow)?;
    for chunk_index in 0..chunk_count {
        let mut digest = [marker; Hash512::BYTE_LENGTH];
        let chunk_index = u64::try_from(chunk_index)
            .map_err(|_| SelectedTargetReleaseStaticAccountingError::CountOverflow)?;
        digest[..size_of::<u64>()].copy_from_slice(&chunk_index.to_le_bytes());
        ordered_chunk_digests.push(Hash512::from_bytes(digest));
    }
    StreamDescriptor::new(
        byte_length,
        ordered_chunk_digests,
        Hash512::from_bytes([marker.wrapping_add(1); Hash512::BYTE_LENGTH]),
    )
    .map_err(|_| SelectedTargetReleaseStaticAccountingError::CanonicalEncoding)
}

fn encoded_descriptor_byte_length(
    descriptor: &StreamDescriptor,
) -> Result<u64, SelectedTargetReleaseStaticAccountingError> {
    let encoded = descriptor
        .encode()
        .map_err(|_| SelectedTargetReleaseStaticAccountingError::CanonicalEncoding)?;
    u64::try_from(encoded.len())
        .map_err(|_| SelectedTargetReleaseStaticAccountingError::CountOverflow)
}

fn checked_add(left: u64, right: u64) -> Result<u64, SelectedTargetReleaseStaticAccountingError> {
    left.checked_add(right)
        .ok_or(SelectedTargetReleaseStaticAccountingError::CountOverflow)
}

fn checked_multiply(
    left: u64,
    right: u64,
) -> Result<u64, SelectedTargetReleaseStaticAccountingError> {
    left.checked_mul(right)
        .ok_or(SelectedTargetReleaseStaticAccountingError::CountOverflow)
}

fn checked_binomial_coefficient(
    item_count: u64,
    selected_count: u64,
) -> Result<u64, SelectedTargetReleaseStaticAccountingError> {
    if selected_count > item_count {
        return Err(SelectedTargetReleaseStaticAccountingError::InvalidSelectedProfile);
    }
    let selected_count = selected_count.min(item_count - selected_count);
    let mut coefficient = 1_u64;
    for selected_index in 1..=selected_count {
        coefficient = checked_multiply(coefficient, item_count - selected_count + selected_index)?;
        coefficient /= selected_index;
    }
    Ok(coefficient)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TWO_CHUNK_PROOF_BYTE_LENGTH_CEILING: u64 = 1_048_577;

    #[test]
    fn selected_target_release_accounting_derives_fixed_material_and_resume_work() {
        let accounting =
            derive_selected_target_release_static_accounting(TWO_CHUNK_PROOF_BYTE_LENGTH_CEILING)
                .expect("selected target-release accounting derives");
        let material = accounting.canonical_material;
        assert_eq!(accounting.participant_count, 10);
        assert_eq!(accounting.target_role_count, 2);
        assert_eq!(accounting.target_data_prime_count, 8);
        assert_eq!(accounting.polynomial_degree, 32_768);
        assert_eq!(accounting.plaintext_modulus, 257);
        assert_eq!(accounting.reconstruction_threshold, 4);
        assert_eq!(
            material.one_target_ciphertext_decoded_coefficient_payload_byte_length,
            4_194_304
        );
        assert_eq!(
            material.paired_target_ciphertext_decoded_coefficient_payload_byte_length,
            8_388_608
        );
        assert_eq!(material.one_partial_stream_byte_length, 2_097_218);
        assert_eq!(material.one_partial_stream_chunk_count, 3);
        assert_eq!(material.one_partial_stream_descriptor_byte_length, 296);
        assert_eq!(material.paired_partial_stream_byte_length, 4_194_436);
        assert_eq!(material.paired_partial_stream_chunk_count, 6);
        assert_eq!(
            material.paired_partial_coefficient_payload_byte_length,
            4_194_304
        );
        assert_eq!(material.ceremony_partial_stream_byte_length, 41_944_360);
        assert_eq!(material.target_share_proof_chunk_count_ceiling, 2);
        assert_eq!(
            material.target_share_proof_descriptor_byte_length_ceiling,
            232
        );
        assert_eq!(
            material.one_target_share_bundle_byte_length_ceiling,
            material.target_share_bundle_header_byte_length_ceiling
                + material.target_share_signed_carrier_byte_length_ceiling
                + material.paired_partial_stream_byte_length
                + material.target_share_proof_byte_length_ceiling
        );
        assert_eq!(
            material.complete_action_target_share_bundle_byte_length_ceiling,
            material.one_target_share_bundle_byte_length_ceiling * 10
        );

        let fresh = accounting.fresh_generation;
        let resumed = accounting.resumed_generation;
        assert_eq!(fresh.operations.preparation_count, 1);
        assert_eq!(resumed.operations.preparation_count, 2);
        assert_eq!(fresh.operations.flooding_polynomial_count, 2);
        assert_eq!(resumed.operations.flooding_polynomial_count, 4);
        assert_eq!(
            fresh
                .operations
                .threshold_share_forward_negacyclic_transform_count,
            8
        );
        assert_eq!(
            fresh
                .operations
                .target_component_forward_negacyclic_transform_count,
            16
        );
        assert_eq!(
            fresh.operations.partial_inverse_negacyclic_transform_count,
            16
        );
        assert_eq!(
            fresh
                .operations
                .pointwise_product_coefficient_multiplication_count,
            524_288
        );
        assert_eq!(
            fresh
                .operations
                .partial_scaling_coefficient_multiplication_count,
            1_048_576
        );
        assert_eq!(
            fresh.operations.partial_stream_hash_scan_byte_length,
            12_583_308
        );
        assert_eq!(
            resumed.operations.partial_stream_hash_scan_byte_length,
            25_166_616
        );
        assert_eq!(
            fresh.maximum_simultaneously_live_partial_stream_payload_byte_length,
            4_194_436
        );
        assert_eq!(
            resumed.maximum_simultaneously_live_partial_stream_payload_byte_length,
            8_388_872
        );
        assert_eq!(fresh.target_specific_checkpoint_byte_length, 0);
        assert_eq!(fresh.target_specific_checkpoint_transaction_count, 0);
        assert_eq!(fresh.partial_output_store_resolver_call_count, 2);
        assert_eq!(fresh.partial_output_store_commit_count, 6);
        assert_eq!(fresh.target_share_resolver_call_count, 1);
        assert_eq!(
            fresh.required_store_owned_payload_byte_length_ceiling,
            TWO_CHUNK_PROOF_BYTE_LENGTH_CEILING + 4_194_436
        );
        assert_eq!(
            accounting.gaps.as_ref(),
            [
                SelectedTargetReleaseStaticAccountingGap::InjectedProofOutputStorePersistenceAndRetainedCopyLiveness,
                SelectedTargetReleaseStaticAccountingGap::InjectedPartialOutputStorePersistenceAndRetainedCopyLiveness,
                SelectedTargetReleaseStaticAccountingGap::CallbackOwnedStateCertificationTraffic,
                SelectedTargetReleaseStaticAccountingGap::PublicTargetShareDistributionFanout,
                SelectedTargetReleaseStaticAccountingGap::ReconstructedResultStateAndTransportTransition,
            ]
        );
        let subset_accounting = accounting.reconstruction_subset_operations;
        assert_eq!(subset_accounting.valid_subset_count, 210);
        assert!(
            subset_accounting
                .maximum_operation_counts
                .full_ring_accumulation_multiplication_count
                >= subset_accounting
                    .minimum_operation_counts
                    .full_ring_accumulation_multiplication_count
        );
        assert_eq!(
            subset_accounting
                .maximum_operation_counts
                .lagrange_coefficient_derivation_count,
            32
        );
        assert_eq!(
            subset_accounting
                .minimum_operation_counts
                .ciphertext_component_scale_multiplication_count,
            524_288
        );
    }

    #[test]
    fn selected_target_release_accounting_rejects_invalid_proof_and_reconstruction_lengths() {
        assert_eq!(
            derive_selected_target_release_static_accounting(0),
            Err(SelectedTargetReleaseStaticAccountingError::EmptyProof)
        );
        assert_eq!(
            derive_selected_target_release_static_accounting(
                u64::try_from(MAXIMUM_COMMON_PROOF_BYTE_LENGTH).expect("proof cap fits") + 1,
            ),
            Err(SelectedTargetReleaseStaticAccountingError::ProofOutsideSupportedProfile)
        );
        let accounting = derive_selected_target_release_static_accounting(1)
            .expect("minimal nonempty proof accounts");
        for (share_count, top_count) in [(3, 1), (11, 1), (4, 0), (4, 21)] {
            assert_eq!(
                accounting.reconstruction_buffer_accounting(share_count, top_count),
                Err(SelectedTargetReleaseStaticAccountingError::InvalidReconstructionInput)
            );
        }
        let threshold = accounting
            .reconstruction_buffer_accounting(4, 1)
            .expect("threshold reconstruction accounts");
        let complete = accounting
            .reconstruction_buffer_accounting(10, 20)
            .expect("complete-action reconstruction accounts");
        assert_eq!(threshold.verified_share_handle_byte_length, 16);
        assert_eq!(threshold.reconstructed_result_byte_length, 4);
        assert_eq!(complete.verified_share_handle_byte_length, 40);
        assert_eq!(complete.reconstructed_result_byte_length, 80);
        assert_eq!(complete.selected_verified_share_count, 4);
        assert_eq!(
            complete.retained_verified_share_coefficient_payload_byte_length,
            41_943_040
        );
    }

    #[test]
    fn reconstruction_accounting_uses_the_production_lagrange_catalog() {
        let accounting =
            derive_selected_target_release_reconstruction_operation_accounting([0, 1, 2, 3])
                .expect("complete-action reconstruction operations derive");
        assert_eq!(accounting.selected_roster_positions, [0, 1, 2, 3]);
        assert_eq!(accounting.lagrange_coefficient_derivation_count, 32);
        assert_eq!(
            accounting.lagrange_subring_polynomial_multiplication_count,
            448
        );
        assert_eq!(accounting.lagrange_subring_linear_solve_count, 32);
        assert!(accounting.nonzero_lagrange_subring_coefficient_count > 0);
        assert_eq!(
            accounting.full_ring_accumulation_multiplication_count,
            accounting.full_ring_accumulation_addition_count
                + accounting.full_ring_accumulation_subtraction_count
        );
        assert_eq!(
            accounting.ciphertext_component_scale_multiplication_count,
            524_288
        );
        assert_eq!(accounting.full_modulus_centered_lift_count, 65_536);
        assert_eq!(accounting.forward_negacyclic_transform_count, 0);
        assert_eq!(accounting.inverse_negacyclic_transform_count, 0);
        assert_eq!(accounting.ciphertext_multiplication_count, 0);
        assert_eq!(accounting.rotation_count, 0);
        assert_eq!(accounting.modulus_switch_count, 0);

        assert_eq!(
            derive_selected_target_release_reconstruction_operation_accounting([0, 0, 1, 2]),
            Err(SelectedTargetReleaseStaticAccountingError::InvalidReconstructionInput)
        );
        assert_eq!(
            derive_selected_target_release_reconstruction_operation_accounting([0, 1, 2, 10]),
            Err(SelectedTargetReleaseStaticAccountingError::InvalidReconstructionInput)
        );
    }
}
