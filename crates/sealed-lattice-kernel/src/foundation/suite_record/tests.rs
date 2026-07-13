use super::*;
use crate::foundation::{ArtifactKind, DistributionKind, hash512};

fn valid_suite_record() -> SuiteRecord {
    let distributions = (1..=12)
        .map(|purpose| {
            let kind = match purpose {
                1 | 3 | 8 | 11 => DistributionKind::Ternary,
                _ => DistributionKind::CenteredBinomial,
            };
            let parameter = match kind {
                DistributionKind::Ternary => 0,
                DistributionKind::CenteredBinomial => 2,
            };
            DistributionRecord::new(purpose, kind, parameter)
                .expect("test distribution is assigned")
        })
        .collect();
    let artifacts = (1..=6)
        .map(|artifact_code| {
            let artifact_kind = ArtifactKind::from_canonical_code(artifact_code)
                .expect("test artifact code is assigned");
            let artifact_byte = u8::try_from(artifact_code).expect("artifact code fits u8");
            ArtifactReference::new(
                artifact_kind,
                100 + u64::from(artifact_code),
                Hash512::from_bytes([artifact_byte; 64]),
            )
            .expect("test artifact reference is valid")
        })
        .collect();

    SuiteRecord {
        suite_record_version: 1,
        roster_size: FOUNDATION_PROFILE.participant_count,
        byzantine_bound: FOUNDATION_PROFILE.active_fault_bound,
        reconstruction_threshold: FOUNDATION_PROFILE.reconstruction_threshold,
        finality_quorum: FOUNDATION_PROFILE.finality_quorum,
        polynomial_degree: 2,
        plaintext_modulus: 5,
        ordered_data_primes: vec![41, 61, 13],
        ordered_special_primes: vec![17, 29],
        ordered_target_data_prime_indexes: vec![0, 1],
        ordered_sharing_data_prime_indexes: vec![0, 1, 2],
        key_switch_method: 1,
        key_switch_data_primes_per_block: 2,
        key_switch_basis_converter: 1,
        maximum_ballot_attempts_per_participant: 3,
        maximum_recovery_transitions_per_state_key: 4,
        maximum_target_share_submissions: FOUNDATION_PROFILE.participant_count,
        maximum_candidate_packages_per_action: 20,
        maximum_proof_objects_per_action: 100,
        maximum_candidate_bytes_per_participant: 3_000,
        maximum_candidate_bytes_per_action: 20_000,
        maximum_setup_bytes_per_participant: 4_000,
        maximum_proof_bytes_per_action: 25_000,
        maximum_public_corpus_bytes: 50_000,
        maximum_participant_upload_bytes: 5_000,
        maximum_ceremony_upload_bytes: 100_000,
        distributions,
        artifacts,
    }
}

fn expect_intrinsic_refusal(record: SuiteRecord, expected_refusal_reason: RefusalReason) {
    let validation_error = record
        .validate_intrinsic()
        .expect_err("invalid suite record unexpectedly validated");
    assert_eq!(validation_error.refusal_reason, expected_refusal_reason);
    let encoding_error = record
        .encode()
        .expect_err("invalid suite record unexpectedly encoded");
    assert_eq!(encoding_error.refusal_reason, expected_refusal_reason);
}

fn outer_item_header_offset(encoded: &[u8], requested_item_index: usize) -> usize {
    let mut offset = 8usize;
    for item_index in 0..SUITE_RECORD_ITEM_COUNT {
        if item_index == requested_item_index {
            return offset;
        }
        let byte_length = usize::try_from(u32::from_le_bytes(
            encoded[offset + 2..offset + 6]
                .try_into()
                .expect("test item header is complete"),
        ))
        .expect("test item length fits usize");
        offset = offset
            .checked_add(6 + byte_length)
            .expect("test item offset does not overflow");
    }
    panic!("requested suite item index is out of range")
}

#[test]
fn suite_record_round_trips_canonically_and_derives_its_only_identifier() {
    let record = valid_suite_record();
    record
        .validate_intrinsic()
        .expect("valid suite record passes intrinsic validation");
    let encoded = record.encode().expect("suite record encodes");
    assert!(encoded.len() <= SUITE_RECORD_MAXIMUM_BYTE_LENGTH);
    assert_eq!(
        intrinsic_suite_record_encoded_byte_length(&record)
            .expect("intrinsic suite length derives"),
        encoded.len()
    );
    assert_eq!(
        u16::from_le_bytes(encoded[0..2].try_into().expect("schema identifier bytes")),
        SUITE_RECORD_SCHEMA_IDENTIFIER
    );
    assert_eq!(
        u16::from_le_bytes(encoded[2..4].try_into().expect("schema version bytes")),
        1
    );
    assert_eq!(
        u32::from_le_bytes(encoded[4..8].try_into().expect("item count bytes")),
        u32::try_from(SUITE_RECORD_ITEM_COUNT).expect("item count fits u32")
    );
    assert_eq!(
        SuiteRecord::decode(&encoded, &CanonicalDecodeLimits::default())
            .expect("suite record decodes"),
        record
    );

    let expected_suite_id = hash512(
        "sealed-lattice/foundation/suite/v1",
        &[CanonicalItem::variable_bytes(&encoded).expect("suite bytes fit canonical item")],
    )
    .expect("expected suite identifier derives");
    assert_eq!(record.suite_id().expect("suite identifier derives"), expected_suite_id);
    let mut different_record = record.clone();
    different_record.maximum_recovery_transitions_per_state_key += 1;
    assert_ne!(
        different_record
            .suite_id()
            .expect("different suite identifier derives"),
        expected_suite_id
    );
}

#[test]
fn deterministic_u64_primality_and_ring_validation_cover_adversarial_boundaries() {
    for prime in [2, 3, 5, 37, 65_537, 18_446_744_073_709_551_557] {
        assert!(is_prime_u64(prime), "{prime} must reproduce as prime");
    }
    for composite in [
        0,
        1,
        4,
        9,
        561,
        1_105,
        3_215_031_751,
        341_550_071_728_321,
        u64::MAX,
    ] {
        assert!(
            !is_prime_u64(composite),
            "{composite} must reproduce as composite"
        );
    }

    let mut smallest_degree_record = valid_suite_record();
    smallest_degree_record.polynomial_degree = 1;
    smallest_degree_record.plaintext_modulus = 3;
    smallest_degree_record.ordered_data_primes = vec![7];
    smallest_degree_record.ordered_special_primes = vec![5];
    smallest_degree_record.ordered_target_data_prime_indexes = vec![0];
    smallest_degree_record.ordered_sharing_data_prime_indexes = vec![0];
    smallest_degree_record.key_switch_data_primes_per_block = 1;
    smallest_degree_record
        .validate_intrinsic()
        .expect("degree-one algebraic boundary is intrinsically valid");

    let mut invalid_cases = Vec::new();
    let mut zero_degree = valid_suite_record();
    zero_degree.polynomial_degree = 0;
    invalid_cases.push((zero_degree, RefusalReason::OutsideSupportedProfile));
    let mut non_power_degree = valid_suite_record();
    non_power_degree.polynomial_degree = 3;
    invalid_cases.push((non_power_degree, RefusalReason::OutsideSupportedProfile));
    let mut composite_plaintext = valid_suite_record();
    composite_plaintext.plaintext_modulus = 9;
    invalid_cases.push((composite_plaintext, RefusalReason::OutsideSupportedProfile));
    let mut wrong_plaintext_order = valid_suite_record();
    wrong_plaintext_order.plaintext_modulus = 7;
    invalid_cases.push((wrong_plaintext_order, RefusalReason::OutsideSupportedProfile));
    let mut composite_data_prime = valid_suite_record();
    composite_data_prime.ordered_data_primes[0] = 49;
    invalid_cases.push((composite_data_prime, RefusalReason::OutsideSupportedProfile));
    let mut incompatible_data_prime = valid_suite_record();
    incompatible_data_prime.ordered_data_primes[0] = 19;
    invalid_cases.push((incompatible_data_prime, RefusalReason::OutsideSupportedProfile));
    let mut composite_special_prime = valid_suite_record();
    composite_special_prime.ordered_special_primes[0] = 25;
    invalid_cases.push((composite_special_prime, RefusalReason::OutsideSupportedProfile));
    let mut duplicate_data_prime = valid_suite_record();
    duplicate_data_prime.ordered_data_primes[1] = duplicate_data_prime.ordered_data_primes[0];
    invalid_cases.push((duplicate_data_prime, RefusalReason::DuplicateIdentity));
    let mut duplicate_cross_basis_prime = valid_suite_record();
    duplicate_cross_basis_prime.ordered_special_primes[0] =
        duplicate_cross_basis_prime.ordered_data_primes[2];
    invalid_cases.push((
        duplicate_cross_basis_prime,
        RefusalReason::DuplicateIdentity,
    ));
    let mut empty_data_basis = valid_suite_record();
    empty_data_basis.ordered_data_primes.clear();
    invalid_cases.push((empty_data_basis, RefusalReason::OutsideSupportedProfile));
    let mut empty_special_basis = valid_suite_record();
    empty_special_basis.ordered_special_primes.clear();
    invalid_cases.push((empty_special_basis, RefusalReason::OutsideSupportedProfile));

    for (record, refusal_reason) in invalid_cases {
        expect_intrinsic_refusal(record, refusal_reason);
    }
}

#[test]
fn suite_basis_indexes_and_key_switch_profile_refuse_every_invalid_shape() {
    let mut empty_sharing = valid_suite_record();
    empty_sharing.ordered_sharing_data_prime_indexes.clear();
    expect_intrinsic_refusal(empty_sharing, RefusalReason::OutsideSupportedProfile);

    let mut duplicate_sharing = valid_suite_record();
    duplicate_sharing.ordered_sharing_data_prime_indexes = vec![0, 1, 1];
    expect_intrinsic_refusal(duplicate_sharing, RefusalReason::WrongTypeOrLength);
    let mut unordered_sharing = valid_suite_record();
    unordered_sharing.ordered_sharing_data_prime_indexes = vec![0, 2, 1];
    expect_intrinsic_refusal(unordered_sharing, RefusalReason::WrongTypeOrLength);
    let mut out_of_range_sharing = valid_suite_record();
    out_of_range_sharing.ordered_sharing_data_prime_indexes = vec![0, 1, 3];
    expect_intrinsic_refusal(out_of_range_sharing, RefusalReason::WrongTypeOrLength);

    let mut empty_target = valid_suite_record();
    empty_target.ordered_target_data_prime_indexes.clear();
    expect_intrinsic_refusal(empty_target, RefusalReason::OutsideSupportedProfile);
    let mut nonprefix_target = valid_suite_record();
    nonprefix_target.ordered_target_data_prime_indexes = vec![0, 2];
    expect_intrinsic_refusal(nonprefix_target, RefusalReason::WrongTypeOrLength);
    let mut target_outside_sharing = valid_suite_record();
    target_outside_sharing.ordered_sharing_data_prime_indexes = vec![0, 2];
    expect_intrinsic_refusal(target_outside_sharing, RefusalReason::WrongTypeOrLength);
    let mut incompatible_target_prime = valid_suite_record();
    incompatible_target_prime.ordered_data_primes[0] = 37;
    expect_intrinsic_refusal(
        incompatible_target_prime,
        RefusalReason::OutsideSupportedProfile,
    );

    for profile_mutation in 0..4 {
        let mut record = valid_suite_record();
        match profile_mutation {
            0 => record.key_switch_method = 2,
            1 => record.key_switch_basis_converter = 2,
            2 => record.key_switch_data_primes_per_block = 0,
            3 => record.key_switch_data_primes_per_block = 4,
            _ => unreachable!("test mutation index is bounded"),
        }
        expect_intrinsic_refusal(record, RefusalReason::OutsideSupportedProfile);
    }
}

#[test]
fn suite_caps_enforce_positive_exact_multiples_overflow_and_containment() {
    for cap_index in 0..12 {
        let mut record = valid_suite_record();
        match cap_index {
            0 => record.maximum_ballot_attempts_per_participant = 0,
            1 => record.maximum_recovery_transitions_per_state_key = 0,
            2 => record.maximum_target_share_submissions = 0,
            3 => record.maximum_candidate_packages_per_action = 0,
            4 => record.maximum_proof_objects_per_action = 0,
            5 => record.maximum_candidate_bytes_per_participant = 0,
            6 => record.maximum_candidate_bytes_per_action = 0,
            7 => record.maximum_setup_bytes_per_participant = 0,
            8 => record.maximum_proof_bytes_per_action = 0,
            9 => record.maximum_public_corpus_bytes = 0,
            10 => record.maximum_participant_upload_bytes = 0,
            11 => record.maximum_ceremony_upload_bytes = 0,
            _ => unreachable!("test cap index is bounded"),
        }
        expect_intrinsic_refusal(record, RefusalReason::OutsideSupportedProfile);
    }

    let mut wrong_target_share_count = valid_suite_record();
    wrong_target_share_count.maximum_target_share_submissions -= 1;
    expect_intrinsic_refusal(
        wrong_target_share_count,
        RefusalReason::OutsideSupportedProfile,
    );
    for candidate_count in [9, 31] {
        let mut record = valid_suite_record();
        record.maximum_candidate_packages_per_action = candidate_count;
        expect_intrinsic_refusal(record, RefusalReason::OutsideSupportedProfile);
    }

    let mut inexact_participant_multiple = valid_suite_record();
    inexact_participant_multiple.maximum_candidate_bytes_per_participant = 3_001;
    expect_intrinsic_refusal(
        inexact_participant_multiple,
        RefusalReason::OutsideSupportedProfile,
    );
    let mut inexact_action_multiple = valid_suite_record();
    inexact_action_multiple.maximum_candidate_bytes_per_action = 20_001;
    expect_intrinsic_refusal(
        inexact_action_multiple,
        RefusalReason::OutsideSupportedProfile,
    );
    let mut inconsistent_package_ceiling = valid_suite_record();
    inconsistent_package_ceiling.maximum_candidate_bytes_per_participant = 3_300;
    expect_intrinsic_refusal(
        inconsistent_package_ceiling,
        RefusalReason::OutsideSupportedProfile,
    );

    let mut participant_candidate_over_upload = valid_suite_record();
    participant_candidate_over_upload.maximum_candidate_bytes_per_participant = 18_000;
    participant_candidate_over_upload.maximum_candidate_bytes_per_action = 120_000;
    expect_intrinsic_refusal(
        participant_candidate_over_upload,
        RefusalReason::OutsideSupportedProfile,
    );
    let mut setup_over_upload = valid_suite_record();
    setup_over_upload.maximum_setup_bytes_per_participant = 5_001;
    expect_intrinsic_refusal(setup_over_upload, RefusalReason::OutsideSupportedProfile);
    let mut participant_over_ceremony = valid_suite_record();
    participant_over_ceremony.maximum_participant_upload_bytes = 100_001;
    expect_intrinsic_refusal(
        participant_over_ceremony,
        RefusalReason::OutsideSupportedProfile,
    );
    let mut candidates_over_corpus = valid_suite_record();
    candidates_over_corpus.maximum_public_corpus_bytes = 19_999;
    expect_intrinsic_refusal(candidates_over_corpus, RefusalReason::OutsideSupportedProfile);
    let mut proof_over_corpus = valid_suite_record();
    proof_over_corpus.maximum_proof_bytes_per_action = 50_001;
    expect_intrinsic_refusal(proof_over_corpus, RefusalReason::OutsideSupportedProfile);
}

#[test]
fn exact_distribution_and_artifact_registries_reject_missing_reordered_or_invalid_entries() {
    let mut missing_distribution = valid_suite_record();
    missing_distribution.distributions.pop();
    expect_intrinsic_refusal(
        missing_distribution,
        RefusalReason::OutsideSupportedProfile,
    );
    let mut reordered_distributions = valid_suite_record();
    reordered_distributions.distributions.swap(0, 1);
    expect_intrinsic_refusal(reordered_distributions, RefusalReason::WrongTypeOrLength);
    let mut wrong_distribution = valid_suite_record();
    wrong_distribution.distributions[0].kind = DistributionKind::CenteredBinomial;
    wrong_distribution.distributions[0].parameter = 2;
    expect_intrinsic_refusal(
        wrong_distribution,
        RefusalReason::OutsideSupportedProfile,
    );

    let mut missing_artifact = valid_suite_record();
    missing_artifact.artifacts.pop();
    expect_intrinsic_refusal(missing_artifact, RefusalReason::OutsideSupportedProfile);
    let mut reordered_artifacts = valid_suite_record();
    reordered_artifacts.artifacts.swap(0, 1);
    expect_intrinsic_refusal(reordered_artifacts, RefusalReason::WrongTypeOrLength);
    let mut empty_artifact = valid_suite_record();
    empty_artifact.artifacts[0].byte_length = 0;
    expect_intrinsic_refusal(empty_artifact, RefusalReason::WrongTypeOrLength);
}

#[test]
fn suite_decode_refuses_hostile_bounds_types_versions_counts_and_nested_substitutions() {
    let encoded = valid_suite_record().encode().expect("suite record encodes");

    let oversized = vec![0u8; SUITE_RECORD_MAXIMUM_BYTE_LENGTH + 1];
    assert_eq!(
        SuiteRecord::decode(&oversized, &CanonicalDecodeLimits::default())
            .expect_err("oversized suite record refuses")
            .refusal_reason,
        RefusalReason::OutsideSupportedProfile
    );
    let mut intrinsically_oversized = valid_suite_record();
    intrinsically_oversized.ordered_data_primes = vec![41; 9_000];
    expect_intrinsic_refusal(
        intrinsically_oversized,
        RefusalReason::OutsideSupportedProfile,
    );
    let mut smaller_limits = CanonicalDecodeLimits::default();
    smaller_limits.maximum_tuple_byte_length = encoded.len() - 1;
    assert_eq!(
        SuiteRecord::decode(&encoded, &smaller_limits)
            .expect_err("caller decode bound remains operative")
            .refusal_reason,
        RefusalReason::OutsideSupportedProfile
    );

    let mut wrong_schema = encoded.clone();
    wrong_schema[0..2].copy_from_slice(&0x0117_u16.to_le_bytes());
    assert_eq!(
        SuiteRecord::decode(&wrong_schema, &CanonicalDecodeLimits::default())
            .expect_err("wrong suite schema refuses")
            .refusal_reason,
        RefusalReason::WrongTypeOrLength
    );
    let mut wrong_schema_version = encoded.clone();
    wrong_schema_version[2..4].copy_from_slice(&2_u16.to_le_bytes());
    assert_eq!(
        SuiteRecord::decode(&wrong_schema_version, &CanonicalDecodeLimits::default())
            .expect_err("wrong outer schema version refuses")
            .refusal_reason,
        RefusalReason::UnsupportedVersionOrSuite
    );
    let mut wrong_record_version = encoded.clone();
    let version_payload_offset = outer_item_header_offset(&encoded, 0) + 6;
    wrong_record_version[version_payload_offset..version_payload_offset + 2]
        .copy_from_slice(&2_u16.to_le_bytes());
    assert_eq!(
        SuiteRecord::decode(&wrong_record_version, &CanonicalDecodeLimits::default())
            .expect_err("wrong suite-record version refuses")
            .refusal_reason,
        RefusalReason::UnsupportedVersionOrSuite
    );

    let mut wrong_data_list_type = encoded.clone();
    let data_list_header_offset = outer_item_header_offset(&encoded, 7);
    wrong_data_list_type[data_list_header_offset..data_list_header_offset + 2]
        .copy_from_slice(&CanonicalItemType::RawBytes.canonical_code().to_le_bytes());
    assert_eq!(
        SuiteRecord::decode(&wrong_data_list_type, &CanonicalDecodeLimits::default())
            .expect_err("wrong data-prime list type refuses")
            .refusal_reason,
        RefusalReason::WrongTypeOrLength
    );

    let distribution_payload_offset = outer_item_header_offset(&encoded, 26) + 6;
    let mut hostile_distribution_count = encoded.clone();
    hostile_distribution_count
        [distribution_payload_offset + 2..distribution_payload_offset + 6]
        .copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        SuiteRecord::decode(
            &hostile_distribution_count,
            &CanonicalDecodeLimits::default(),
        )
        .expect_err("hostile distribution count refuses")
        .refusal_reason,
        RefusalReason::OutsideSupportedProfile
    );

    let mut substituted_distribution = encoded.clone();
    let first_distribution_purpose_offset = distribution_payload_offset + 6 + 8 + 6;
    substituted_distribution
        [first_distribution_purpose_offset..first_distribution_purpose_offset + 2]
        .copy_from_slice(&2_u16.to_le_bytes());
    assert_eq!(
        SuiteRecord::decode(
            &substituted_distribution,
            &CanonicalDecodeLimits::default(),
        )
        .expect_err("substituted distribution refuses")
        .refusal_reason,
        RefusalReason::OutsideSupportedProfile
    );

    let artifact_payload_offset = outer_item_header_offset(&encoded, 27) + 6;
    let mut substituted_artifact_kind = encoded.clone();
    let first_artifact_kind_offset = artifact_payload_offset + 6 + 8 + 6;
    substituted_artifact_kind[first_artifact_kind_offset..first_artifact_kind_offset + 2]
        .copy_from_slice(&2_u16.to_le_bytes());
    assert_eq!(
        SuiteRecord::decode(
            &substituted_artifact_kind,
            &CanonicalDecodeLimits::default(),
        )
        .expect_err("substituted artifact kind refuses")
        .refusal_reason,
        RefusalReason::WrongTypeOrLength
    );

    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_eq!(
        SuiteRecord::decode(&trailing, &CanonicalDecodeLimits::default())
            .expect_err("trailing suite bytes refuse")
            .refusal_reason,
        RefusalReason::MalformedEncoding
    );
    assert_eq!(
        SuiteRecord::decode(&encoded[..encoded.len() - 1], &CanonicalDecodeLimits::default())
            .expect_err("truncated suite bytes refuse")
            .refusal_reason,
        RefusalReason::MalformedEncoding
    );
}
