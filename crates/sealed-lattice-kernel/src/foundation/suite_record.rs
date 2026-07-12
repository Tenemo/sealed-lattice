use std::collections::BTreeSet;

use super::schemas::{
    SchemaResult, read_list_header, read_nested_tuple_list, read_u16, read_u32, read_u64,
    require_header,
};
use super::{
    ArtifactReference, CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple,
    DistributionRecord, FOUNDATION_PROFILE, FoundationSchemaError, Hash512, RefusalReason,
    SUITE_RECORD_SCHEMA_IDENTIFIER, hash512,
};

pub const SUITE_RECORD_MAXIMUM_BYTE_LENGTH: usize = 65_536;

const SUITE_RECORD_VERSION: u16 = 1;
const SUITE_RECORD_ITEM_COUNT: usize = 28;
const KEY_SWITCH_METHOD_HYBRID_QP_RNS: u16 = 1;
const KEY_SWITCH_BASIS_CONVERTER_CENTERED_INTEGER_RNS: u16 = 1;
const REQUIRED_DISTRIBUTION_COUNT: usize = 12;
const REQUIRED_ARTIFACT_COUNT: usize = 6;

/// The intrinsic, canonical suite record.
///
/// Intrinsic validation checks only relations decidable from these fields. It
/// does not establish that artifact bytes match their references, that the
/// implied ballot-package byte ceiling equals the generated package maximum,
/// that proof caps equal generated proof-family sums, or that an external
/// suite allowlist accepts the derived suite identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuiteRecord {
    pub suite_record_version: u16,
    pub roster_size: u16,
    pub byzantine_bound: u16,
    pub reconstruction_threshold: u16,
    pub finality_quorum: u16,
    pub polynomial_degree: u32,
    pub plaintext_modulus: u64,
    pub ordered_data_primes: Vec<u64>,
    pub ordered_special_primes: Vec<u64>,
    pub ordered_target_data_prime_indexes: Vec<u16>,
    pub ordered_sharing_data_prime_indexes: Vec<u16>,
    pub key_switch_method: u16,
    pub key_switch_data_primes_per_block: u16,
    pub key_switch_basis_converter: u16,
    pub maximum_ballot_attempts_per_participant: u16,
    pub maximum_recovery_transitions_per_state_key: u16,
    pub maximum_target_share_submissions: u16,
    pub maximum_candidate_packages_per_action: u32,
    pub maximum_proof_objects_per_action: u32,
    pub maximum_candidate_bytes_per_participant: u64,
    pub maximum_candidate_bytes_per_action: u64,
    pub maximum_setup_bytes_per_participant: u64,
    pub maximum_proof_bytes_per_action: u64,
    pub maximum_public_corpus_bytes: u64,
    pub maximum_participant_upload_bytes: u64,
    pub maximum_ceremony_upload_bytes: u64,
    pub distributions: Vec<DistributionRecord>,
    pub artifacts: Vec<ArtifactReference>,
}

impl SuiteRecord {
    pub fn validate_intrinsic(&self) -> SchemaResult<()> {
        require_suite_record_byte_bound(intrinsic_suite_record_encoded_byte_length(self)?)?;
        self.validate_profile_constants()?;
        self.validate_ring_parameters()?;
        self.validate_basis_indexes()?;
        self.validate_key_switch_profile()?;
        self.validate_intrinsic_caps()?;
        self.validate_distributions_and_artifacts()?;
        Ok(())
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        self.validate_intrinsic()?;
        let distribution_items = self
            .distributions
            .iter()
            .map(|distribution| {
                distribution
                    .canonical_tuple()
                    .and_then(|tuple| CanonicalItem::nested_tuple(&tuple).map_err(Into::into))
            })
            .collect::<SchemaResult<Vec<_>>>()?;
        let artifact_items = self
            .artifacts
            .iter()
            .map(|artifact| {
                artifact
                    .canonical_tuple()
                    .and_then(|tuple| CanonicalItem::nested_tuple(&tuple).map_err(Into::into))
            })
            .collect::<SchemaResult<Vec<_>>>()?;
        let encoded = CanonicalTuple::new(
            SUITE_RECORD_SCHEMA_IDENTIFIER,
            SUITE_RECORD_VERSION,
            vec![
                CanonicalItem::unsigned16(self.suite_record_version),
                CanonicalItem::unsigned16(self.roster_size),
                CanonicalItem::unsigned16(self.byzantine_bound),
                CanonicalItem::unsigned16(self.reconstruction_threshold),
                CanonicalItem::unsigned16(self.finality_quorum),
                CanonicalItem::unsigned32(self.polynomial_degree),
                CanonicalItem::unsigned64(self.plaintext_modulus),
                encode_u64_list(&self.ordered_data_primes)?,
                encode_u64_list(&self.ordered_special_primes)?,
                encode_u16_list(&self.ordered_target_data_prime_indexes)?,
                encode_u16_list(&self.ordered_sharing_data_prime_indexes)?,
                CanonicalItem::unsigned16(self.key_switch_method),
                CanonicalItem::unsigned16(self.key_switch_data_primes_per_block),
                CanonicalItem::unsigned16(self.key_switch_basis_converter),
                CanonicalItem::unsigned16(self.maximum_ballot_attempts_per_participant),
                CanonicalItem::unsigned16(self.maximum_recovery_transitions_per_state_key),
                CanonicalItem::unsigned16(self.maximum_target_share_submissions),
                CanonicalItem::unsigned32(self.maximum_candidate_packages_per_action),
                CanonicalItem::unsigned32(self.maximum_proof_objects_per_action),
                CanonicalItem::unsigned64(self.maximum_candidate_bytes_per_participant),
                CanonicalItem::unsigned64(self.maximum_candidate_bytes_per_action),
                CanonicalItem::unsigned64(self.maximum_setup_bytes_per_participant),
                CanonicalItem::unsigned64(self.maximum_proof_bytes_per_action),
                CanonicalItem::unsigned64(self.maximum_public_corpus_bytes),
                CanonicalItem::unsigned64(self.maximum_participant_upload_bytes),
                CanonicalItem::unsigned64(self.maximum_ceremony_upload_bytes),
                CanonicalItem::homogeneous_list(
                    CanonicalItemType::NestedTuple,
                    &distribution_items,
                )?,
                CanonicalItem::homogeneous_list(CanonicalItemType::NestedTuple, &artifact_items)?,
            ],
        )
        .encode()?;
        require_suite_record_byte_bound(encoded.len())?;
        Ok(encoded)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        require_suite_record_byte_bound(bytes.len())?;
        let mut bounded_limits = *limits;
        bounded_limits.maximum_tuple_byte_length = bounded_limits
            .maximum_tuple_byte_length
            .min(SUITE_RECORD_MAXIMUM_BYTE_LENGTH);
        bounded_limits.maximum_item_byte_length = bounded_limits
            .maximum_item_byte_length
            .min(SUITE_RECORD_MAXIMUM_BYTE_LENGTH);
        let tuple = CanonicalTuple::decode(bytes, &bounded_limits)?;
        require_header(
            &tuple,
            SUITE_RECORD_SCHEMA_IDENTIFIER,
            SUITE_RECORD_ITEM_COUNT,
        )?;

        require_exact_nested_tuple_count(
            &tuple.items[26],
            REQUIRED_DISTRIBUTION_COUNT,
            "suite record must contain exactly twelve distribution records",
        )?;
        require_exact_nested_tuple_count(
            &tuple.items[27],
            REQUIRED_ARTIFACT_COUNT,
            "suite record must contain exactly six artifact references",
        )?;
        let distributions = read_nested_tuple_list(&tuple.items[26], &bounded_limits)?
            .iter()
            .map(DistributionRecord::from_tuple)
            .collect::<SchemaResult<Vec<_>>>()?;
        let artifacts = read_nested_tuple_list(&tuple.items[27], &bounded_limits)?
            .iter()
            .map(ArtifactReference::from_tuple)
            .collect::<SchemaResult<Vec<_>>>()?;

        let record = Self {
            suite_record_version: read_u16(&tuple.items[0])?,
            roster_size: read_u16(&tuple.items[1])?,
            byzantine_bound: read_u16(&tuple.items[2])?,
            reconstruction_threshold: read_u16(&tuple.items[3])?,
            finality_quorum: read_u16(&tuple.items[4])?,
            polynomial_degree: read_u32(&tuple.items[5])?,
            plaintext_modulus: read_u64(&tuple.items[6])?,
            ordered_data_primes: read_u64_list(&tuple.items[7])?,
            ordered_special_primes: read_u64_list(&tuple.items[8])?,
            ordered_target_data_prime_indexes: read_u16_list(&tuple.items[9])?,
            ordered_sharing_data_prime_indexes: read_u16_list(&tuple.items[10])?,
            key_switch_method: read_u16(&tuple.items[11])?,
            key_switch_data_primes_per_block: read_u16(&tuple.items[12])?,
            key_switch_basis_converter: read_u16(&tuple.items[13])?,
            maximum_ballot_attempts_per_participant: read_u16(&tuple.items[14])?,
            maximum_recovery_transitions_per_state_key: read_u16(&tuple.items[15])?,
            maximum_target_share_submissions: read_u16(&tuple.items[16])?,
            maximum_candidate_packages_per_action: read_u32(&tuple.items[17])?,
            maximum_proof_objects_per_action: read_u32(&tuple.items[18])?,
            maximum_candidate_bytes_per_participant: read_u64(&tuple.items[19])?,
            maximum_candidate_bytes_per_action: read_u64(&tuple.items[20])?,
            maximum_setup_bytes_per_participant: read_u64(&tuple.items[21])?,
            maximum_proof_bytes_per_action: read_u64(&tuple.items[22])?,
            maximum_public_corpus_bytes: read_u64(&tuple.items[23])?,
            maximum_participant_upload_bytes: read_u64(&tuple.items[24])?,
            maximum_ceremony_upload_bytes: read_u64(&tuple.items[25])?,
            distributions,
            artifacts,
        };
        record.validate_intrinsic()?;
        Ok(record)
    }

    pub fn suite_id(&self) -> SchemaResult<Hash512> {
        Ok(hash512(
            "sealed-lattice/foundation/suite/v1",
            &[CanonicalItem::variable_bytes(self.encode()?)?],
        )?)
    }

    fn validate_profile_constants(&self) -> SchemaResult<()> {
        if self.suite_record_version != SUITE_RECORD_VERSION {
            return Err(FoundationSchemaError::new(
                RefusalReason::UnsupportedVersionOrSuite,
                "suite record version is unsupported",
            ));
        }
        if self.roster_size != FOUNDATION_PROFILE.participant_count
            || self.byzantine_bound != FOUNDATION_PROFILE.active_fault_bound
            || self.reconstruction_threshold != FOUNDATION_PROFILE.reconstruction_threshold
            || self.finality_quorum != FOUNDATION_PROFILE.finality_quorum
        {
            return Err(FoundationSchemaError::new(
                RefusalReason::OutsideSupportedProfile,
                "suite record quorum constants do not match the foundation profile",
            ));
        }
        Ok(())
    }

    fn validate_ring_parameters(&self) -> SchemaResult<()> {
        if self.polynomial_degree == 0 || !self.polynomial_degree.is_power_of_two() {
            return Err(FoundationSchemaError::new(
                RefusalReason::OutsideSupportedProfile,
                "suite polynomial degree must be a positive power of two",
            ));
        }
        let twice_polynomial_degree = u64::from(self.polynomial_degree)
            .checked_mul(2)
            .ok_or_else(|| {
                FoundationSchemaError::new(
                    RefusalReason::OutsideSupportedProfile,
                    "twice the suite polynomial degree overflows u64",
                )
            })?;
        if !is_prime_u64(self.plaintext_modulus)
            || !(self.plaintext_modulus - 1).is_multiple_of(twice_polynomial_degree)
        {
            return Err(FoundationSchemaError::new(
                RefusalReason::OutsideSupportedProfile,
                "suite plaintext modulus is not prime with the required scalar-batching order",
            ));
        }
        if self.ordered_data_primes.is_empty() || self.ordered_special_primes.is_empty() {
            return Err(FoundationSchemaError::new(
                RefusalReason::OutsideSupportedProfile,
                "suite data and special prime lists must both be nonempty",
            ));
        }
        if self.ordered_data_primes.len() > usize::from(u16::MAX) + 1 {
            return Err(FoundationSchemaError::new(
                RefusalReason::OutsideSupportedProfile,
                "suite data-prime count cannot be indexed canonically",
            ));
        }

        let mut distinct_primes = BTreeSet::new();
        for prime in self
            .ordered_data_primes
            .iter()
            .chain(self.ordered_special_primes.iter())
            .copied()
        {
            if !is_prime_u64(prime)
                || !(prime - 1).is_multiple_of(twice_polynomial_degree)
                || greatest_common_divisor(prime, self.plaintext_modulus) != 1
            {
                return Err(FoundationSchemaError::new(
                    RefusalReason::OutsideSupportedProfile,
                    "suite ring prime is not prime, ring-compatible, and coprime to plaintext",
                ));
            }
            if !distinct_primes.insert(prime) {
                return Err(FoundationSchemaError::new(
                    RefusalReason::DuplicateIdentity,
                    "suite data and special primes must be pairwise distinct",
                ));
            }
        }
        Ok(())
    }

    fn validate_basis_indexes(&self) -> SchemaResult<()> {
        if self.ordered_sharing_data_prime_indexes.is_empty()
            || self.ordered_target_data_prime_indexes.is_empty()
        {
            return Err(FoundationSchemaError::new(
                RefusalReason::OutsideSupportedProfile,
                "suite sharing and target data-prime index lists must be nonempty",
            ));
        }
        let mut previous_sharing_index = None;
        for sharing_index in self.ordered_sharing_data_prime_indexes.iter().copied() {
            if usize::from(sharing_index) >= self.ordered_data_primes.len() {
                return Err(FoundationSchemaError::new(
                    RefusalReason::WrongTypeOrLength,
                    "suite sharing data-prime index is out of range",
                ));
            }
            if previous_sharing_index.is_some_and(|previous| sharing_index <= previous) {
                return Err(FoundationSchemaError::new(
                    RefusalReason::WrongTypeOrLength,
                    "suite sharing data-prime indexes must be strictly increasing",
                ));
            }
            previous_sharing_index = Some(sharing_index);
        }

        for (target_position, target_index) in self
            .ordered_target_data_prime_indexes
            .iter()
            .copied()
            .enumerate()
        {
            let expected_index = u16::try_from(target_position).map_err(|_| {
                FoundationSchemaError::new(
                    RefusalReason::OutsideSupportedProfile,
                    "suite target data-prime prefix cannot be represented canonically",
                )
            })?;
            if target_index != expected_index
                || self
                    .ordered_sharing_data_prime_indexes
                    .binary_search(&target_index)
                    .is_err()
            {
                return Err(FoundationSchemaError::new(
                    RefusalReason::WrongTypeOrLength,
                    "suite target indexes must be a contiguous prefix contained in the sharing basis",
                ));
            }
        }
        Ok(())
    }

    fn validate_key_switch_profile(&self) -> SchemaResult<()> {
        if self.key_switch_method != KEY_SWITCH_METHOD_HYBRID_QP_RNS
            || self.key_switch_basis_converter != KEY_SWITCH_BASIS_CONVERTER_CENTERED_INTEGER_RNS
            || self.key_switch_data_primes_per_block == 0
            || usize::from(self.key_switch_data_primes_per_block) > self.ordered_data_primes.len()
        {
            return Err(FoundationSchemaError::new(
                RefusalReason::OutsideSupportedProfile,
                "suite key-switch profile is unsupported or inconsistent with its data basis",
            ));
        }
        Ok(())
    }

    fn validate_intrinsic_caps(&self) -> SchemaResult<()> {
        if [
            self.maximum_ballot_attempts_per_participant,
            self.maximum_recovery_transitions_per_state_key,
            self.maximum_target_share_submissions,
        ]
        .contains(&0)
            || [
                self.maximum_candidate_packages_per_action,
                self.maximum_proof_objects_per_action,
            ]
            .contains(&0)
            || [
                self.maximum_candidate_bytes_per_participant,
                self.maximum_candidate_bytes_per_action,
                self.maximum_setup_bytes_per_participant,
                self.maximum_proof_bytes_per_action,
                self.maximum_public_corpus_bytes,
                self.maximum_participant_upload_bytes,
                self.maximum_ceremony_upload_bytes,
            ]
            .contains(&0)
        {
            return Err(FoundationSchemaError::new(
                RefusalReason::OutsideSupportedProfile,
                "every suite operational maximum must be positive",
            ));
        }
        if self.maximum_target_share_submissions != self.roster_size {
            return Err(FoundationSchemaError::new(
                RefusalReason::OutsideSupportedProfile,
                "suite target-share maximum must equal the roster size",
            ));
        }
        let maximum_candidate_packages_from_attempts = u32::from(self.roster_size)
            .checked_mul(u32::from(self.maximum_ballot_attempts_per_participant))
            .ok_or_else(|| {
                FoundationSchemaError::new(
                    RefusalReason::OutsideSupportedProfile,
                    "suite candidate count bound overflows u32",
                )
            })?;
        if self.maximum_candidate_packages_per_action < u32::from(self.roster_size)
            || self.maximum_candidate_packages_per_action > maximum_candidate_packages_from_attempts
        {
            return Err(FoundationSchemaError::new(
                RefusalReason::OutsideSupportedProfile,
                "suite candidate-package maximum is inconsistent with roster attempts",
            ));
        }

        let ballot_attempt_count = u64::from(self.maximum_ballot_attempts_per_participant);
        let candidate_package_count = u64::from(self.maximum_candidate_packages_per_action);
        let implied_participant_package_ceiling = self
            .maximum_candidate_bytes_per_participant
            .checked_div(ballot_attempt_count)
            .filter(|ceiling| {
                *ceiling > 0
                    && ballot_attempt_count.checked_mul(*ceiling)
                        == Some(self.maximum_candidate_bytes_per_participant)
            })
            .ok_or_else(|| {
                FoundationSchemaError::new(
                    RefusalReason::OutsideSupportedProfile,
                    "suite participant candidate-byte cap is not an exact attempt multiple",
                )
            })?;
        let implied_action_package_ceiling = self
            .maximum_candidate_bytes_per_action
            .checked_div(candidate_package_count)
            .filter(|ceiling| {
                *ceiling > 0
                    && candidate_package_count.checked_mul(*ceiling)
                        == Some(self.maximum_candidate_bytes_per_action)
            })
            .ok_or_else(|| {
                FoundationSchemaError::new(
                    RefusalReason::OutsideSupportedProfile,
                    "suite action candidate-byte cap is not an exact package-count multiple",
                )
            })?;
        if implied_participant_package_ceiling != implied_action_package_ceiling {
            return Err(FoundationSchemaError::new(
                RefusalReason::OutsideSupportedProfile,
                "suite candidate-byte caps do not imply one common package ceiling",
            ));
        }

        if self.maximum_candidate_bytes_per_participant > self.maximum_candidate_bytes_per_action
            || self.maximum_candidate_bytes_per_participant > self.maximum_participant_upload_bytes
            || self.maximum_setup_bytes_per_participant > self.maximum_participant_upload_bytes
            || self.maximum_participant_upload_bytes > self.maximum_ceremony_upload_bytes
            || self.maximum_candidate_bytes_per_action > self.maximum_public_corpus_bytes
            || self.maximum_candidate_bytes_per_action > self.maximum_ceremony_upload_bytes
            || self.maximum_proof_bytes_per_action > self.maximum_public_corpus_bytes
            || self.maximum_proof_bytes_per_action > self.maximum_ceremony_upload_bytes
        {
            return Err(FoundationSchemaError::new(
                RefusalReason::OutsideSupportedProfile,
                "suite byte maxima violate an intrinsic upload or corpus containment",
            ));
        }
        Ok(())
    }

    fn validate_distributions_and_artifacts(&self) -> SchemaResult<()> {
        if self.distributions.len() != REQUIRED_DISTRIBUTION_COUNT {
            return Err(FoundationSchemaError::new(
                RefusalReason::OutsideSupportedProfile,
                "suite record must contain exactly twelve distribution records",
            ));
        }
        for (distribution_index, distribution) in self.distributions.iter().enumerate() {
            let expected_purpose = u16::try_from(distribution_index + 1).map_err(|_| {
                FoundationSchemaError::new(
                    RefusalReason::OutsideSupportedProfile,
                    "suite distribution purpose does not fit u16",
                )
            })?;
            if distribution.purpose != expected_purpose {
                return Err(FoundationSchemaError::new(
                    RefusalReason::WrongTypeOrLength,
                    "suite distributions must appear once each in purpose order",
                ));
            }
            DistributionRecord::new(
                distribution.purpose,
                distribution.kind,
                distribution.parameter,
            )?;
        }

        if self.artifacts.len() != REQUIRED_ARTIFACT_COUNT {
            return Err(FoundationSchemaError::new(
                RefusalReason::OutsideSupportedProfile,
                "suite record must contain exactly six artifact references",
            ));
        }
        for (artifact_index, artifact) in self.artifacts.iter().enumerate() {
            let expected_code = u16::try_from(artifact_index + 1).map_err(|_| {
                FoundationSchemaError::new(
                    RefusalReason::OutsideSupportedProfile,
                    "suite artifact kind does not fit u16",
                )
            })?;
            if artifact.artifact_kind.canonical_code() != expected_code {
                return Err(FoundationSchemaError::new(
                    RefusalReason::WrongTypeOrLength,
                    "suite artifacts must appear once each in kind order",
                ));
            }
            ArtifactReference::new(
                artifact.artifact_kind,
                artifact.byte_length,
                artifact.artifact_hash,
            )?;
        }
        Ok(())
    }
}

fn require_suite_record_byte_bound(byte_length: usize) -> SchemaResult<()> {
    if byte_length > SUITE_RECORD_MAXIMUM_BYTE_LENGTH {
        return Err(FoundationSchemaError::new(
            RefusalReason::OutsideSupportedProfile,
            "suite record exceeds the 65,536-byte decode bound",
        ));
    }
    Ok(())
}

fn intrinsic_suite_record_encoded_byte_length(record: &SuiteRecord) -> SchemaResult<usize> {
    const TUPLE_HEADER_BYTE_LENGTH: usize = 8;
    const ITEM_HEADER_BYTE_LENGTH: usize = 6;
    const FIXED_U16_PAYLOAD_BYTE_LENGTH: usize = 11 * 2;
    const FIXED_U32_PAYLOAD_BYTE_LENGTH: usize = 3 * 4;
    const FIXED_U64_PAYLOAD_BYTE_LENGTH: usize = 8 * 8;
    const HOMOGENEOUS_LIST_HEADER_BYTE_LENGTH: usize = 6;
    const DISTRIBUTION_RECORD_TUPLE_BYTE_LENGTH: usize = 38;
    const ARTIFACT_REFERENCE_TUPLE_BYTE_LENGTH: usize = 100;

    let mut byte_length = TUPLE_HEADER_BYTE_LENGTH
        .checked_add(
            SUITE_RECORD_ITEM_COUNT
                .checked_mul(ITEM_HEADER_BYTE_LENGTH)
                .ok_or_else(suite_record_byte_length_overflow)?,
        )
        .and_then(|length| length.checked_add(FIXED_U16_PAYLOAD_BYTE_LENGTH))
        .and_then(|length| length.checked_add(FIXED_U32_PAYLOAD_BYTE_LENGTH))
        .and_then(|length| length.checked_add(FIXED_U64_PAYLOAD_BYTE_LENGTH))
        .ok_or_else(suite_record_byte_length_overflow)?;
    for (element_count, element_byte_length) in [
        (record.ordered_data_primes.len(), 8usize),
        (record.ordered_special_primes.len(), 8usize),
        (record.ordered_target_data_prime_indexes.len(), 2usize),
        (record.ordered_sharing_data_prime_indexes.len(), 2usize),
        (
            record.distributions.len(),
            DISTRIBUTION_RECORD_TUPLE_BYTE_LENGTH,
        ),
        (record.artifacts.len(), ARTIFACT_REFERENCE_TUPLE_BYTE_LENGTH),
    ] {
        byte_length = byte_length
            .checked_add(HOMOGENEOUS_LIST_HEADER_BYTE_LENGTH)
            .and_then(|length| {
                element_count
                    .checked_mul(element_byte_length)
                    .and_then(|payload_byte_length| length.checked_add(payload_byte_length))
            })
            .ok_or_else(suite_record_byte_length_overflow)?;
    }
    Ok(byte_length)
}

fn suite_record_byte_length_overflow() -> FoundationSchemaError {
    FoundationSchemaError::new(
        RefusalReason::OutsideSupportedProfile,
        "suite record canonical byte length overflows the platform",
    )
}

fn require_exact_nested_tuple_count(
    item: &CanonicalItem,
    expected_count: usize,
    message: &'static str,
) -> SchemaResult<()> {
    let (count, _) = read_list_header(item, CanonicalItemType::NestedTuple)?;
    if count != expected_count {
        return Err(FoundationSchemaError::new(
            RefusalReason::OutsideSupportedProfile,
            message,
        ));
    }
    Ok(())
}

fn encode_u16_list(values: &[u16]) -> SchemaResult<CanonicalItem> {
    let items = values
        .iter()
        .copied()
        .map(CanonicalItem::unsigned16)
        .collect::<Vec<_>>();
    Ok(CanonicalItem::homogeneous_list(
        CanonicalItemType::Unsigned16,
        &items,
    )?)
}

fn encode_u64_list(values: &[u64]) -> SchemaResult<CanonicalItem> {
    let items = values
        .iter()
        .copied()
        .map(CanonicalItem::unsigned64)
        .collect::<Vec<_>>();
    Ok(CanonicalItem::homogeneous_list(
        CanonicalItemType::Unsigned64,
        &items,
    )?)
}

fn read_u16_list(item: &CanonicalItem) -> SchemaResult<Vec<u16>> {
    let (count, bytes) = read_list_header(item, CanonicalItemType::Unsigned16)?;
    let expected_byte_length = count.checked_mul(2).ok_or_else(|| {
        FoundationSchemaError::new(
            RefusalReason::MalformedEncoding,
            "suite u16-list byte length overflows",
        )
    })?;
    if bytes.len() != expected_byte_length {
        return Err(FoundationSchemaError::new(
            RefusalReason::MalformedEncoding,
            "suite u16-list byte length is malformed",
        ));
    }
    bytes
        .chunks_exact(2)
        .map(|chunk| {
            let value: [u8; 2] = chunk.try_into().map_err(|_| {
                FoundationSchemaError::new(
                    RefusalReason::MalformedEncoding,
                    "suite u16-list element length is malformed",
                )
            })?;
            Ok(u16::from_le_bytes(value))
        })
        .collect()
}

fn read_u64_list(item: &CanonicalItem) -> SchemaResult<Vec<u64>> {
    let (count, bytes) = read_list_header(item, CanonicalItemType::Unsigned64)?;
    let expected_byte_length = count.checked_mul(8).ok_or_else(|| {
        FoundationSchemaError::new(
            RefusalReason::MalformedEncoding,
            "suite u64-list byte length overflows",
        )
    })?;
    if bytes.len() != expected_byte_length {
        return Err(FoundationSchemaError::new(
            RefusalReason::MalformedEncoding,
            "suite u64-list byte length is malformed",
        ));
    }
    bytes
        .chunks_exact(8)
        .map(|chunk| {
            let value: [u8; 8] = chunk.try_into().map_err(|_| {
                FoundationSchemaError::new(
                    RefusalReason::MalformedEncoding,
                    "suite u64-list element length is malformed",
                )
            })?;
            Ok(u64::from_le_bytes(value))
        })
        .collect()
}

fn greatest_common_divisor(mut left: u64, mut right: u64) -> u64 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

pub(super) fn is_prime_u64(value: u64) -> bool {
    const SMALL_PRIMES: [u64; 12] = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];
    const DETERMINISTIC_BASES: [u64; 7] =
        [2, 325, 9_375, 28_178, 450_775, 9_780_504, 1_795_265_022];

    if value < 2 {
        return false;
    }
    for prime in SMALL_PRIMES {
        if value.is_multiple_of(prime) {
            return value == prime;
        }
    }

    let factor_of_two_count = (value - 1).trailing_zeros();
    let odd_factor = (value - 1) >> factor_of_two_count;
    'base: for base in DETERMINISTIC_BASES {
        let reduced_base = base % value;
        if reduced_base == 0 {
            continue;
        }
        let mut witness = modular_power(reduced_base, odd_factor, value);
        if witness == 1 || witness == value - 1 {
            continue;
        }
        for _ in 1..factor_of_two_count {
            witness = modular_product(witness, witness, value);
            if witness == value - 1 {
                continue 'base;
            }
        }
        return false;
    }
    true
}

pub(super) fn modular_power(mut base: u64, mut exponent: u64, modulus: u64) -> u64 {
    let mut result = 1;
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = modular_product(result, base, modulus);
        }
        base = modular_product(base, base, modulus);
        exponent >>= 1;
    }
    result
}

pub(super) fn modular_product(left: u64, right: u64, modulus: u64) -> u64 {
    ((u128::from(left) * u128::from(right)) % u128::from(modulus)) as u64
}

#[cfg(test)]
mod tests;
