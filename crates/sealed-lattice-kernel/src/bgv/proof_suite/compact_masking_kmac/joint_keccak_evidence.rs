//! Test-only source and mode correspondence for the shared Keccak interface.
//!
//! The certificate binds the selected compact contract to every operative
//! KMAC256 domain and to the exact SHAKE256/KMAC256 mode parameters. Independent
//! SP 800-185 encoding and known-answer checks cover the pinned implementations.
//! The certificate also records why the two reviewed ideal-permutation results
//! do not instantiate the fixed public Keccak-f[1600] joint-interface premise.
//! It is development evidence only and is not a proof-verification authority.

use std::mem::size_of;

use num_bigint::BigUint;
use num_traits::One;
use sha3::{
    CShake256, CShake256Core, Shake256,
    digest::{ExtendableOutput, Update as Sha3Update, XofReader},
};
use tiny_keccak::{Hasher as TinyKeccakHasher, Kmac};

use super::*;
use crate::bgv::proof_suite::compact_fixed_tape_source_correspondence::CompactFixedTapeSourceCorrespondence;
use crate::hashing::{framed_hash512_preimage, hash_framed_parts_512};

const ACMT25_SPONGE_THEOREM_IDENTIFIER: &str = "acmt25-sponge-theorem-7.22";
const HOS25_OUTER_KEYED_SPONGE_THEOREM_IDENTIFIER: &str = "hos25-outer-keyed-sponge-theorem-7";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompactJointKeccakInterfaceField {
    KeccakStateBitLength,
    KeccakPermutationRoundCount,
    RateBitLength,
    CapacityBitLength,
    BytepadWidth,
    ShakeDelimitedSuffix,
    ShakeFixedHashOutputBitLength,
    FiatShamirVerifierMessageXofCallCount,
    MinimumFiatShamirVerifierMessageOutputBitLength,
    MaximumFiatShamirVerifierMessageOutputBitLength,
    TotalFiatShamirVerifierMessageOutputByteLength,
    CshakeDelimitedSuffix,
    KmacFunctionName,
    KmacFixedOutputMode,
    KmacKeyBitLength,
    KmacOutputBitLengths,
    KmacCustomizationDomain { row_index: usize },
    MinimumKmacCallCount,
    MaximumKmacCallCount,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompactJointKeccakCallRowField {
    Family,
    Customization,
    KeyBitLength,
    OutputBitLength,
    MinimumCallCount,
    MaximumCallCount,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompactJointKeccakEvidenceError {
    ProductionDerivation,
    SelectedContractSourceHash,
    Interface(CompactJointKeccakInterfaceField),
    DuplicateCustomization {
        first_row_index: usize,
        second_row_index: usize,
    },
    KmacCallRow {
        row_index: usize,
        field: CompactJointKeccakCallRowField,
    },
    QuantumQueryBudget,
    Acmt25Applicability,
    Hos25Applicability,
    FixedKeccakJointReductionBoundary,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactSourceVerifiedJointKeccakError {
    ProductionDerivation,
    ContractSourceHash,
    OutputWidth,
    HashCensus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CompactJointKeccakCallRow {
    family: CompactMaskingKmacCallFamily,
    customization: &'static [u8],
    key_bit_length: u32,
    output_bit_length: u32,
    minimum_call_count: u64,
    maximum_call_count: u64,
}

impl From<CompactMaskingKmacCallRow> for CompactJointKeccakCallRow {
    fn from(row: CompactMaskingKmacCallRow) -> Self {
        Self {
            family: row.family,
            customization: row.customization,
            key_bit_length: row.key_bit_length,
            output_bit_length: row.output_bit_length,
            minimum_call_count: row.minimum_call_count,
            maximum_call_count: row.maximum_call_count,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompactJointKeccakPermutationModel {
    IdealRandomPermutation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompactJointKeccakConstructionQueryAccess {
    Quantum,
    Classical,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Acmt25SpongeApplicability {
    theorem_identifier: &'static str,
    permutation_model: CompactJointKeccakPermutationModel,
    construction_query_access: CompactJointKeccakConstructionQueryAccess,
    sponge_layer_count: u8,
    declared_query_budget: u128,
    minimum_rate_capacity_bit_length: u16,
    first_monomial_inside_square_root_numerator: BigUint,
    first_monomial_inside_square_root_denominator: BigUint,
    first_monomial_exceeds_one: bool,
    has_explicit_concrete_constant: bool,
    applies_to_fixed_keccak_f1600: bool,
    supplies_nonvacuous_selected_bound: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Hos25OuterKeyedSpongeApplicability {
    theorem_identifier: &'static str,
    permutation_model: CompactJointKeccakPermutationModel,
    construction_query_access: CompactJointKeccakConstructionQueryAccess,
    selected_key_bit_length: u32,
    rate_bit_length: u16,
    requires_key_strictly_longer_than_rate: bool,
    key_length_condition_holds: bool,
    applies_to_fixed_keccak_f1600: bool,
    applies_to_quantum_construction_queries: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompactFixedKeccakJointReductionBoundary {
    UnresolvedJointFixedPermutationAdvantage,
    ClaimedResolved,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CompactJointKeccakEvidenceCertificate {
    selected_contract_source_hash: Hash512,
    interface: CompactMaskingJointKeccakInterface,
    call_rows: [CompactJointKeccakCallRow; 7],
    quantum_query_budget: u128,
    acmt25_applicability: Acmt25SpongeApplicability,
    hos25_applicability: Hos25OuterKeyedSpongeApplicability,
    fixed_keccak_joint_reduction_boundary: CompactFixedKeccakJointReductionBoundary,
}

/// Test-only join between the production-derived KMAC catalog and one complete
/// source-verified direct verifier-message SHAKE256 graph. The retained bindings prevent a
/// certificate from being transplanted to another proof or public input. This
/// record supplies source correspondence only; its fixed-permutation reduction
/// boundary remains unresolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactSourceVerifiedJointKeccakEvidence {
    pub(crate) selected_contract_source_hash: Hash512,
    pub(crate) canonical_proof_binding: [u8; Hash512::BYTE_LENGTH],
    pub(crate) canonical_public_input_binding: [u8; Hash512::BYTE_LENGTH],
    pub(crate) minimum_kmac_call_count: u64,
    pub(crate) maximum_kmac_call_count: u64,
    pub(crate) verifier_message_xof_call_count: u64,
    pub(crate) total_verifier_message_input_byte_length: u64,
    pub(crate) minimum_verifier_message_input_byte_length: u64,
    pub(crate) maximum_verifier_message_input_byte_length: u64,
    pub(crate) minimum_verifier_message_output_bit_length: u64,
    pub(crate) maximum_verifier_message_output_bit_length: u64,
    pub(crate) total_verifier_message_output_byte_length: u64,
    fixed_keccak_joint_reduction_boundary: CompactFixedKeccakJointReductionBoundary,
}

impl CompactSourceVerifiedJointKeccakEvidence {
    pub(crate) const fn fixed_keccak_joint_reduction_is_resolved(&self) -> bool {
        matches!(
            self.fixed_keccak_joint_reduction_boundary,
            CompactFixedKeccakJointReductionBoundary::ClaimedResolved
        )
    }
}

pub(crate) fn derive_source_verified_compact_joint_keccak_evidence(
    correspondence: &CompactFixedTapeSourceCorrespondence,
) -> Result<CompactSourceVerifiedJointKeccakEvidence, CompactSourceVerifiedJointKeccakError> {
    let certificate = derive_selected_joint_keccak_evidence_certificate()
        .map_err(|_| CompactSourceVerifiedJointKeccakError::ProductionDerivation)?;
    if correspondence.selected_contract_source_hash != certificate.selected_contract_source_hash {
        return Err(CompactSourceVerifiedJointKeccakError::ContractSourceHash);
    }
    let minimum_input_byte_length = correspondence
        .rounds
        .iter()
        .map(|round| round.input_byte_length)
        .min()
        .ok_or(CompactSourceVerifiedJointKeccakError::OutputWidth)?;
    let maximum_input_byte_length = correspondence
        .rounds
        .iter()
        .map(|round| round.input_byte_length)
        .max()
        .ok_or(CompactSourceVerifiedJointKeccakError::OutputWidth)?;
    let minimum_output_byte_length = correspondence
        .rounds
        .iter()
        .map(|round| round.message_byte_length)
        .min()
        .ok_or(CompactSourceVerifiedJointKeccakError::OutputWidth)?;
    let maximum_output_byte_length = correspondence
        .rounds
        .iter()
        .map(|round| round.message_byte_length)
        .max()
        .ok_or(CompactSourceVerifiedJointKeccakError::OutputWidth)?;
    let minimum_output_bit_length = minimum_output_byte_length
        .checked_mul(u64::from(u8::BITS))
        .ok_or(CompactSourceVerifiedJointKeccakError::OutputWidth)?;
    let maximum_output_bit_length = maximum_output_byte_length
        .checked_mul(u64::from(u8::BITS))
        .ok_or(CompactSourceVerifiedJointKeccakError::OutputWidth)?;
    if correspondence.logical_round_count == 0
        || correspondence.direct_xof_call_count != correspondence.logical_round_count
        || correspondence.direct_xof_call_count
            != certificate
                .interface
                .fiat_shamir_verifier_message_xof_call_count
        || minimum_output_bit_length
            != certificate
                .interface
                .minimum_fiat_shamir_verifier_message_output_bit_length
        || maximum_output_bit_length
            != certificate
                .interface
                .maximum_fiat_shamir_verifier_message_output_bit_length
        || correspondence.total_fixed_tape_byte_length
            != certificate
                .interface
                .total_fiat_shamir_verifier_message_output_byte_length
        || minimum_input_byte_length != correspondence.minimum_verifier_message_input_byte_length
        || maximum_input_byte_length != correspondence.maximum_verifier_message_input_byte_length
        || correspondence
            .rounds
            .iter()
            .try_fold(0_u64, |total, round| {
                total.checked_add(round.input_byte_length)
            })
            != Some(correspondence.total_verifier_message_input_byte_length)
        || maximum_output_byte_length != correspondence.maximum_message_byte_length_per_round
    {
        return Err(CompactSourceVerifiedJointKeccakError::HashCensus);
    }
    Ok(CompactSourceVerifiedJointKeccakEvidence {
        selected_contract_source_hash: certificate.selected_contract_source_hash,
        canonical_proof_binding: correspondence.canonical_proof_binding,
        canonical_public_input_binding: correspondence.canonical_public_input_binding,
        minimum_kmac_call_count: certificate.interface.minimum_kmac_call_count,
        maximum_kmac_call_count: certificate.interface.maximum_kmac_call_count,
        verifier_message_xof_call_count: correspondence.direct_xof_call_count,
        total_verifier_message_input_byte_length: correspondence
            .total_verifier_message_input_byte_length,
        minimum_verifier_message_input_byte_length: minimum_input_byte_length,
        maximum_verifier_message_input_byte_length: maximum_input_byte_length,
        minimum_verifier_message_output_bit_length: minimum_output_bit_length,
        maximum_verifier_message_output_bit_length: maximum_output_bit_length,
        total_verifier_message_output_byte_length: correspondence.total_fixed_tape_byte_length,
        fixed_keccak_joint_reduction_boundary:
            CompactFixedKeccakJointReductionBoundary::UnresolvedJointFixedPermutationAdvantage,
    })
}

fn derive_acmt25_applicability() -> Acmt25SpongeApplicability {
    let declared_query_budget = DECLARED_ADVERSARIAL_QUERY_BUDGET;
    let minimum_rate_capacity_bit_length =
        SHAKE256_RATE_BIT_LENGTH.min(SHAKE256_CAPACITY_BIT_LENGTH);
    let numerator = BigUint::from(declared_query_budget).pow(9);
    let denominator = BigUint::one() << usize::from(minimum_rate_capacity_bit_length);
    let first_monomial_exceeds_one = numerator > denominator;
    Acmt25SpongeApplicability {
        theorem_identifier: ACMT25_SPONGE_THEOREM_IDENTIFIER,
        permutation_model: CompactJointKeccakPermutationModel::IdealRandomPermutation,
        construction_query_access: CompactJointKeccakConstructionQueryAccess::Quantum,
        sponge_layer_count: 1,
        declared_query_budget,
        minimum_rate_capacity_bit_length,
        first_monomial_inside_square_root_numerator: numerator,
        first_monomial_inside_square_root_denominator: denominator,
        first_monomial_exceeds_one,
        has_explicit_concrete_constant: false,
        applies_to_fixed_keccak_f1600: false,
        supplies_nonvacuous_selected_bound: false,
    }
}

fn derive_hos25_applicability() -> Hos25OuterKeyedSpongeApplicability {
    Hos25OuterKeyedSpongeApplicability {
        theorem_identifier: HOS25_OUTER_KEYED_SPONGE_THEOREM_IDENTIFIER,
        permutation_model: CompactJointKeccakPermutationModel::IdealRandomPermutation,
        construction_query_access: CompactJointKeccakConstructionQueryAccess::Classical,
        selected_key_bit_length: SELECTED_KMAC_KEY_BIT_LENGTH,
        rate_bit_length: SHAKE256_RATE_BIT_LENGTH,
        requires_key_strictly_longer_than_rate: true,
        key_length_condition_holds: SELECTED_KMAC_KEY_BIT_LENGTH
            > u32::from(SHAKE256_RATE_BIT_LENGTH),
        applies_to_fixed_keccak_f1600: false,
        applies_to_quantum_construction_queries: false,
    }
}

fn derive_selected_joint_keccak_evidence_certificate()
-> Result<CompactJointKeccakEvidenceCertificate, CompactJointKeccakEvidenceError> {
    let contract = CompactPublicKeyProofContract::decode_selected()
        .map_err(|_| CompactJointKeccakEvidenceError::ProductionDerivation)?;
    let selected_contract_source_hash = contract
        .verifier_inputs()
        .canonical_source_hash()
        .map_err(|_| CompactJointKeccakEvidenceError::ProductionDerivation)?;
    let census = derive_compact_masking_kmac_census(&contract)
        .map_err(|_| CompactJointKeccakEvidenceError::ProductionDerivation)?;
    let interface = derive_selected_joint_keccak_interface()
        .map_err(|_| CompactJointKeccakEvidenceError::ProductionDerivation)?;
    let certificate = CompactJointKeccakEvidenceCertificate {
        selected_contract_source_hash,
        interface,
        call_rows: census.call_rows.map(CompactJointKeccakCallRow::from),
        quantum_query_budget: DECLARED_ADVERSARIAL_QUERY_BUDGET,
        acmt25_applicability: derive_acmt25_applicability(),
        hos25_applicability: derive_hos25_applicability(),
        fixed_keccak_joint_reduction_boundary:
            CompactFixedKeccakJointReductionBoundary::UnresolvedJointFixedPermutationAdvantage,
    };
    Ok(certificate)
}

impl CompactJointKeccakEvidenceCertificate {
    fn validate_against(&self, expected: &Self) -> Result<(), CompactJointKeccakEvidenceError> {
        if self.selected_contract_source_hash != expected.selected_contract_source_hash {
            return Err(CompactJointKeccakEvidenceError::SelectedContractSourceHash);
        }

        let interface_checks = [
            (
                self.interface.keccak_state_bit_length
                    == expected.interface.keccak_state_bit_length,
                CompactJointKeccakInterfaceField::KeccakStateBitLength,
            ),
            (
                self.interface.keccak_permutation_round_count
                    == expected.interface.keccak_permutation_round_count,
                CompactJointKeccakInterfaceField::KeccakPermutationRoundCount,
            ),
            (
                self.interface.rate_bit_length == expected.interface.rate_bit_length,
                CompactJointKeccakInterfaceField::RateBitLength,
            ),
            (
                self.interface.capacity_bit_length == expected.interface.capacity_bit_length,
                CompactJointKeccakInterfaceField::CapacityBitLength,
            ),
            (
                self.interface.bytepad_width == expected.interface.bytepad_width,
                CompactJointKeccakInterfaceField::BytepadWidth,
            ),
            (
                self.interface.shake_delimited_suffix == expected.interface.shake_delimited_suffix,
                CompactJointKeccakInterfaceField::ShakeDelimitedSuffix,
            ),
            (
                self.interface.shake_fixed_hash_output_bit_length
                    == expected.interface.shake_fixed_hash_output_bit_length,
                CompactJointKeccakInterfaceField::ShakeFixedHashOutputBitLength,
            ),
            (
                self.interface.fiat_shamir_verifier_message_xof_call_count
                    == expected
                        .interface
                        .fiat_shamir_verifier_message_xof_call_count,
                CompactJointKeccakInterfaceField::FiatShamirVerifierMessageXofCallCount,
            ),
            (
                self.interface
                    .minimum_fiat_shamir_verifier_message_output_bit_length
                    == expected
                        .interface
                        .minimum_fiat_shamir_verifier_message_output_bit_length,
                CompactJointKeccakInterfaceField::MinimumFiatShamirVerifierMessageOutputBitLength,
            ),
            (
                self.interface
                    .maximum_fiat_shamir_verifier_message_output_bit_length
                    == expected
                        .interface
                        .maximum_fiat_shamir_verifier_message_output_bit_length,
                CompactJointKeccakInterfaceField::MaximumFiatShamirVerifierMessageOutputBitLength,
            ),
            (
                self.interface
                    .total_fiat_shamir_verifier_message_output_byte_length
                    == expected
                        .interface
                        .total_fiat_shamir_verifier_message_output_byte_length,
                CompactJointKeccakInterfaceField::TotalFiatShamirVerifierMessageOutputByteLength,
            ),
            (
                self.interface.cshake_delimited_suffix
                    == expected.interface.cshake_delimited_suffix,
                CompactJointKeccakInterfaceField::CshakeDelimitedSuffix,
            ),
            (
                self.interface.kmac_function_name == expected.interface.kmac_function_name,
                CompactJointKeccakInterfaceField::KmacFunctionName,
            ),
            (
                self.interface.kmac_uses_fixed_output_mode
                    == expected.interface.kmac_uses_fixed_output_mode,
                CompactJointKeccakInterfaceField::KmacFixedOutputMode,
            ),
            (
                self.interface.kmac_key_bit_length == expected.interface.kmac_key_bit_length,
                CompactJointKeccakInterfaceField::KmacKeyBitLength,
            ),
            (
                self.interface.kmac_output_bit_lengths
                    == expected.interface.kmac_output_bit_lengths,
                CompactJointKeccakInterfaceField::KmacOutputBitLengths,
            ),
            (
                self.interface.minimum_kmac_call_count
                    == expected.interface.minimum_kmac_call_count,
                CompactJointKeccakInterfaceField::MinimumKmacCallCount,
            ),
            (
                self.interface.maximum_kmac_call_count
                    == expected.interface.maximum_kmac_call_count,
                CompactJointKeccakInterfaceField::MaximumKmacCallCount,
            ),
        ];
        for (matches, field) in interface_checks {
            if !matches {
                return Err(CompactJointKeccakEvidenceError::Interface(field));
            }
        }
        for (first_row_index, customization) in
            self.interface.kmac_customization_domains.iter().enumerate()
        {
            if let Some(second_offset) = self.interface.kmac_customization_domains
                [first_row_index + 1..]
                .iter()
                .position(|candidate| candidate == customization)
            {
                return Err(CompactJointKeccakEvidenceError::DuplicateCustomization {
                    first_row_index,
                    second_row_index: first_row_index + 1 + second_offset,
                });
            }
            if customization != &expected.interface.kmac_customization_domains[first_row_index] {
                return Err(CompactJointKeccakEvidenceError::Interface(
                    CompactJointKeccakInterfaceField::KmacCustomizationDomain {
                        row_index: first_row_index,
                    },
                ));
            }
        }

        for (row_index, (actual, expected)) in self
            .call_rows
            .iter()
            .zip(expected.call_rows.iter())
            .enumerate()
        {
            let row_checks = [
                (
                    actual.family == expected.family,
                    CompactJointKeccakCallRowField::Family,
                ),
                (
                    actual.customization == expected.customization,
                    CompactJointKeccakCallRowField::Customization,
                ),
                (
                    actual.key_bit_length == expected.key_bit_length,
                    CompactJointKeccakCallRowField::KeyBitLength,
                ),
                (
                    actual.output_bit_length == expected.output_bit_length,
                    CompactJointKeccakCallRowField::OutputBitLength,
                ),
                (
                    actual.minimum_call_count == expected.minimum_call_count,
                    CompactJointKeccakCallRowField::MinimumCallCount,
                ),
                (
                    actual.maximum_call_count == expected.maximum_call_count,
                    CompactJointKeccakCallRowField::MaximumCallCount,
                ),
            ];
            for (matches, field) in row_checks {
                if !matches {
                    return Err(CompactJointKeccakEvidenceError::KmacCallRow { row_index, field });
                }
            }
        }
        if self.quantum_query_budget != expected.quantum_query_budget {
            return Err(CompactJointKeccakEvidenceError::QuantumQueryBudget);
        }
        if self.acmt25_applicability != expected.acmt25_applicability {
            return Err(CompactJointKeccakEvidenceError::Acmt25Applicability);
        }
        if self.hos25_applicability != expected.hos25_applicability {
            return Err(CompactJointKeccakEvidenceError::Hos25Applicability);
        }
        if self.fixed_keccak_joint_reduction_boundary
            != expected.fixed_keccak_joint_reduction_boundary
        {
            return Err(CompactJointKeccakEvidenceError::FixedKeccakJointReductionBoundary);
        }
        Ok(())
    }
}

fn left_encode(value: u64) -> Vec<u8> {
    let encoded_byte_length = ((u64::BITS - value.leading_zeros()).max(1) as usize).div_ceil(8);
    let mut encoded = Vec::with_capacity(encoded_byte_length + 1);
    encoded.push(u8::try_from(encoded_byte_length).expect("u64 length encoding fits u8"));
    encoded.extend_from_slice(&value.to_be_bytes()[size_of::<u64>() - encoded_byte_length..]);
    encoded
}

fn right_encode(value: u64) -> Vec<u8> {
    let encoded_byte_length = ((u64::BITS - value.leading_zeros()).max(1) as usize).div_ceil(8);
    let mut encoded = Vec::with_capacity(encoded_byte_length + 1);
    encoded.extend_from_slice(&value.to_be_bytes()[size_of::<u64>() - encoded_byte_length..]);
    encoded.push(u8::try_from(encoded_byte_length).expect("u64 length encoding fits u8"));
    encoded
}

fn encode_string(value: &[u8]) -> Vec<u8> {
    let bit_length = u64::try_from(value.len())
        .expect("test input length fits u64")
        .checked_mul(8)
        .expect("test bit length fits u64");
    let mut encoded = left_encode(bit_length);
    encoded.extend_from_slice(value);
    encoded
}

fn bytepad(value: &[u8], width: usize) -> Vec<u8> {
    assert!(width > 0);
    let mut encoded = left_encode(u64::try_from(width).expect("test width fits u64"));
    encoded.extend_from_slice(value);
    let padded_length = encoded.len().div_ceil(width) * width;
    encoded.resize(padded_length, 0);
    encoded
}

fn independent_sp800_185_kmac256(
    key: &[u8],
    message: &[u8],
    customization: &[u8],
    output_byte_length: usize,
) -> Vec<u8> {
    let mut state = CShake256::from_core(CShake256Core::new_with_function_name(
        KMAC_FUNCTION_NAME,
        customization,
    ));
    Sha3Update::update(
        &mut state,
        &bytepad(&encode_string(key), usize::from(SHAKE256_RATE_BYTE_LENGTH)),
    );
    Sha3Update::update(&mut state, message);
    Sha3Update::update(
        &mut state,
        &right_encode(
            u64::try_from(output_byte_length)
                .expect("test output length fits u64")
                .checked_mul(8)
                .expect("test output bit length fits u64"),
        ),
    );
    let mut output = vec![0_u8; output_byte_length];
    state.finalize_xof().read(&mut output);
    output
}

fn operative_kmac256(
    key: &[u8],
    message: &[u8],
    customization: &[u8],
    output_byte_length: usize,
) -> Vec<u8> {
    let mut output = vec![0_u8; output_byte_length];
    let mut state = Kmac::v256(key, customization);
    TinyKeccakHasher::update(&mut state, message);
    TinyKeccakHasher::finalize(state, &mut output);
    output
}

fn raw_shake256(input: &[u8], output_byte_length: usize) -> Vec<u8> {
    let mut state = Shake256::default();
    Sha3Update::update(&mut state, input);
    let mut output = vec![0_u8; output_byte_length];
    state.finalize_xof().read(&mut output);
    output
}

fn fixed_lowercase_hex<const BYTE_LENGTH: usize>(value: &str) -> [u8; BYTE_LENGTH] {
    assert_eq!(value.len(), BYTE_LENGTH * 2);
    let mut bytes = [0_u8; BYTE_LENGTH];
    for (byte_index, byte) in bytes.iter_mut().enumerate() {
        let hexadecimal_pair = &value[byte_index * 2..byte_index * 2 + 2];
        *byte = u8::from_str_radix(hexadecimal_pair, 16).expect("test hexadecimal byte");
    }
    bytes
}

fn assert_certificate_mutation(
    baseline: &CompactJointKeccakEvidenceCertificate,
    expected: CompactJointKeccakEvidenceError,
    mutate: impl FnOnce(&mut CompactJointKeccakEvidenceCertificate),
) {
    let mut mutated = baseline.clone();
    mutate(&mut mutated);
    assert_eq!(mutated.validate_against(baseline), Err(expected));
}

type CompactJointKeccakInterfaceMutation = (
    CompactJointKeccakInterfaceField,
    fn(&mut CompactMaskingJointKeccakInterface),
);

#[test]
fn selected_joint_interface_binds_the_complete_kmac_catalog_and_theorem_boundaries() {
    let certificate = derive_selected_joint_keccak_evidence_certificate()
        .expect("selected joint Keccak evidence derives");
    let independently_rederived = derive_selected_joint_keccak_evidence_certificate()
        .expect("selected joint Keccak evidence independently rederives");
    assert_eq!(
        certificate.validate_against(&independently_rederived),
        Ok(())
    );
    assert_eq!(
        certificate.call_rows.map(|row| row.family),
        [
            CompactMaskingKmacCallFamily::ActionKeyHierarchy,
            CompactMaskingKmacCallFamily::PersistentProofPreparation,
            CompactMaskingKmacCallFamily::PersistentWitnessAttempt,
            CompactMaskingKmacCallFamily::PrivateSeedBlocks,
            CompactMaskingKmacCallFamily::CompactWhirRandomBlocks,
            CompactMaskingKmacCallFamily::SecretLeafSalts,
            CompactMaskingKmacCallFamily::FiatShamirRoundSalts,
        ]
    );
    assert_eq!(certificate.interface.kmac_key_bit_length, 512);
    assert_eq!(
        certificate.interface.kmac_output_bit_lengths,
        [256, 512, 1_024, 1_536]
    );
    let expected_customization_domains: [&[u8]; 7] = [
        b"sealed-lattice/private-randomness/action-key-hierarchy/v1",
        b"sealed-lattice/proof/persistent-preparation/v1",
        b"sealed-lattice/proof/persistent-canonical-witness-attempt/v1",
        b"sealed-lattice/private-randomness/v1",
        b"sealed-lattice/compact-proof/whir-private-randomness/v1",
        b"sealed-lattice/compact-proof/private-leaf-salt/v1",
        b"sealed-lattice/compact-proof/fiat-shamir-round-salt/v1",
    ];
    assert_eq!(
        certificate.interface.kmac_customization_domains,
        expected_customization_domains,
    );
    assert_eq!(certificate.interface.minimum_kmac_call_count, 862_323);
    assert_eq!(certificate.interface.maximum_kmac_call_count, 9_938_187);
    assert!(certificate.acmt25_applicability.first_monomial_exceeds_one);
    assert!(
        !certificate
            .acmt25_applicability
            .has_explicit_concrete_constant
    );
    assert!(
        !certificate
            .acmt25_applicability
            .applies_to_fixed_keccak_f1600
    );
    assert!(!certificate.hos25_applicability.key_length_condition_holds);
    assert_eq!(certificate.hos25_applicability.selected_key_bit_length, 512);
    assert_eq!(certificate.hos25_applicability.rate_bit_length, 1_088);
    assert!(
        !certificate
            .hos25_applicability
            .applies_to_quantum_construction_queries
    );
}

#[test]
fn operative_modes_match_nist_vectors_and_independent_sp800_185_encoding() {
    let expected_empty_shake256: [u8; 64] = fixed_lowercase_hex(concat!(
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f",
        "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be",
    ));
    assert_eq!(raw_shake256(&[], 64), expected_empty_shake256);

    let nist_key: [u8; 32] =
        fixed_lowercase_hex("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
    let expected_nist_kmac256: [u8; 64] = fixed_lowercase_hex(concat!(
        "20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7",
        "f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd",
    ));
    let nist_message = [0x00, 0x01, 0x02, 0x03];
    let nist_customization = b"My Tagged Application";
    assert_eq!(
        operative_kmac256(&nist_key, &nist_message, nist_customization, 64),
        expected_nist_kmac256
    );
    assert_eq!(
        independent_sp800_185_kmac256(&nist_key, &nist_message, nist_customization, 64),
        expected_nist_kmac256
    );

    let certificate = derive_selected_joint_keccak_evidence_certificate()
        .expect("selected joint Keccak evidence derives");
    let key = [0x5a_u8; 64];
    for (row_index, row) in certificate.call_rows.iter().enumerate() {
        let message_byte_length = [0, 1, 135, 136, 137, 271, 400][row_index];
        let message = (0..message_byte_length)
            .map(|byte_index| (byte_index as u8).wrapping_add(row_index as u8))
            .collect::<Vec<_>>();
        let output_byte_length = usize::try_from(row.output_bit_length / 8)
            .expect("selected KMAC output length fits usize");
        assert_eq!(
            operative_kmac256(&key, &message, row.customization, output_byte_length),
            independent_sp800_185_kmac256(&key, &message, row.customization, output_byte_length,),
            "KMAC correspondence diverged at call row {row_index}",
        );
    }

    let domain = "sealed-lattice/test/joint-keccak-interface/v1";
    let parts: [&[u8]; 3] = [b"", b"one", &[0x7f; 137]];
    let preimage = framed_hash512_preimage(domain, &parts);
    assert_eq!(
        hash_framed_parts_512(domain, &parts),
        raw_shake256(&preimage, 64).as_slice(),
    );
    assert_eq!(left_encode(136), [0x01, 0x88]);
    assert_eq!(right_encode(256), [0x01, 0x00, 0x02]);
    assert_eq!(right_encode(512), [0x02, 0x00, 0x02]);
    assert_eq!(right_encode(1_024), [0x04, 0x00, 0x02]);
    assert_eq!(right_encode(1_536), [0x06, 0x00, 0x02]);
}

#[test]
fn hostile_joint_interface_mutations_report_the_first_divergent_binding() {
    let certificate = derive_selected_joint_keccak_evidence_certificate()
        .expect("selected joint Keccak evidence derives");
    assert_certificate_mutation(
        &certificate,
        CompactJointKeccakEvidenceError::SelectedContractSourceHash,
        |candidate| candidate.selected_contract_source_hash = Hash512::from_bytes([0xa5; 64]),
    );

    let interface_mutations: [CompactJointKeccakInterfaceMutation; 18] = [
        (
            CompactJointKeccakInterfaceField::KeccakStateBitLength,
            |value| value.keccak_state_bit_length -= 1,
        ),
        (
            CompactJointKeccakInterfaceField::KeccakPermutationRoundCount,
            |value| value.keccak_permutation_round_count -= 1,
        ),
        (CompactJointKeccakInterfaceField::RateBitLength, |value| {
            value.rate_bit_length -= 1
        }),
        (
            CompactJointKeccakInterfaceField::CapacityBitLength,
            |value| value.capacity_bit_length -= 1,
        ),
        (CompactJointKeccakInterfaceField::BytepadWidth, |value| {
            value.bytepad_width -= 1
        }),
        (
            CompactJointKeccakInterfaceField::ShakeDelimitedSuffix,
            |value| value.shake_delimited_suffix ^= 1,
        ),
        (
            CompactJointKeccakInterfaceField::ShakeFixedHashOutputBitLength,
            |value| value.shake_fixed_hash_output_bit_length -= 1,
        ),
        (
            CompactJointKeccakInterfaceField::FiatShamirVerifierMessageXofCallCount,
            |value| value.fiat_shamir_verifier_message_xof_call_count -= 1,
        ),
        (
            CompactJointKeccakInterfaceField::MinimumFiatShamirVerifierMessageOutputBitLength,
            |value| value.minimum_fiat_shamir_verifier_message_output_bit_length -= 1,
        ),
        (
            CompactJointKeccakInterfaceField::MaximumFiatShamirVerifierMessageOutputBitLength,
            |value| value.maximum_fiat_shamir_verifier_message_output_bit_length -= 1,
        ),
        (
            CompactJointKeccakInterfaceField::TotalFiatShamirVerifierMessageOutputByteLength,
            |value| value.total_fiat_shamir_verifier_message_output_byte_length -= 1,
        ),
        (
            CompactJointKeccakInterfaceField::CshakeDelimitedSuffix,
            |value| value.cshake_delimited_suffix ^= 1,
        ),
        (
            CompactJointKeccakInterfaceField::KmacFunctionName,
            |value| value.kmac_function_name = b"KMAQ",
        ),
        (
            CompactJointKeccakInterfaceField::KmacFixedOutputMode,
            |value| value.kmac_uses_fixed_output_mode = false,
        ),
        (
            CompactJointKeccakInterfaceField::KmacKeyBitLength,
            |value| value.kmac_key_bit_length -= 1,
        ),
        (
            CompactJointKeccakInterfaceField::KmacOutputBitLengths,
            |value| value.kmac_output_bit_lengths[0] -= 1,
        ),
        (
            CompactJointKeccakInterfaceField::MinimumKmacCallCount,
            |value| value.minimum_kmac_call_count -= 1,
        ),
        (
            CompactJointKeccakInterfaceField::MaximumKmacCallCount,
            |value| value.maximum_kmac_call_count -= 1,
        ),
    ];
    for (field, mutate) in interface_mutations {
        assert_certificate_mutation(
            &certificate,
            CompactJointKeccakEvidenceError::Interface(field),
            |candidate| mutate(&mut candidate.interface),
        );
    }
    for row_index in 0..certificate.interface.kmac_customization_domains.len() {
        assert_certificate_mutation(
            &certificate,
            CompactJointKeccakEvidenceError::Interface(
                CompactJointKeccakInterfaceField::KmacCustomizationDomain { row_index },
            ),
            |candidate| {
                candidate.interface.kmac_customization_domains[row_index] =
                    b"sealed-lattice/test/hostile-kmac-domain/v1";
            },
        );
    }
    assert_certificate_mutation(
        &certificate,
        CompactJointKeccakEvidenceError::DuplicateCustomization {
            first_row_index: 0,
            second_row_index: 1,
        },
        |candidate| {
            candidate.interface.kmac_customization_domains[1] =
                candidate.interface.kmac_customization_domains[0];
        },
    );

    let row_fields = [
        CompactJointKeccakCallRowField::Family,
        CompactJointKeccakCallRowField::Customization,
        CompactJointKeccakCallRowField::KeyBitLength,
        CompactJointKeccakCallRowField::OutputBitLength,
        CompactJointKeccakCallRowField::MinimumCallCount,
        CompactJointKeccakCallRowField::MaximumCallCount,
    ];
    for row_index in 0..certificate.call_rows.len() {
        for field in row_fields {
            assert_certificate_mutation(
                &certificate,
                CompactJointKeccakEvidenceError::KmacCallRow { row_index, field },
                |candidate| match field {
                    CompactJointKeccakCallRowField::Family => {
                        candidate.call_rows[row_index].family =
                            CompactMaskingKmacCallFamily::ActionKeyHierarchy;
                        if row_index == 0 {
                            candidate.call_rows[row_index].family =
                                CompactMaskingKmacCallFamily::FiatShamirRoundSalts;
                        }
                    }
                    CompactJointKeccakCallRowField::Customization => {
                        candidate.call_rows[row_index].customization =
                            b"sealed-lattice/test/hostile-call-row/v1";
                    }
                    CompactJointKeccakCallRowField::KeyBitLength => {
                        candidate.call_rows[row_index].key_bit_length -= 1;
                    }
                    CompactJointKeccakCallRowField::OutputBitLength => {
                        candidate.call_rows[row_index].output_bit_length -= 1;
                    }
                    CompactJointKeccakCallRowField::MinimumCallCount => {
                        candidate.call_rows[row_index].minimum_call_count -= 1;
                    }
                    CompactJointKeccakCallRowField::MaximumCallCount => {
                        candidate.call_rows[row_index].maximum_call_count -= 1;
                    }
                },
            );
        }
    }

    assert_certificate_mutation(
        &certificate,
        CompactJointKeccakEvidenceError::QuantumQueryBudget,
        |candidate| candidate.quantum_query_budget -= 1,
    );
    assert_certificate_mutation(
        &certificate,
        CompactJointKeccakEvidenceError::Acmt25Applicability,
        |candidate| candidate.acmt25_applicability.declared_query_budget -= 1,
    );
    assert_certificate_mutation(
        &certificate,
        CompactJointKeccakEvidenceError::Hos25Applicability,
        |candidate| candidate.hos25_applicability.selected_key_bit_length -= 1,
    );
    assert_certificate_mutation(
        &certificate,
        CompactJointKeccakEvidenceError::FixedKeccakJointReductionBoundary,
        |candidate| {
            candidate.fixed_keccak_joint_reduction_boundary =
                CompactFixedKeccakJointReductionBoundary::ClaimedResolved;
        },
    );
}
