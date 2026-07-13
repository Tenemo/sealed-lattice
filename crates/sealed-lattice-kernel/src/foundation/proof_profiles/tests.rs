use super::*;
use crate::foundation::{
    ArtifactKind, DistributionKind, DistributionRecord, FOUNDATION_PROFILE,
    FoundationSchemaIdentifier, Hash512,
};

fn valid_suite_record() -> SuiteRecord {
    let distributions = (1..=12)
        .map(|purpose| {
            let kind = match purpose {
                1 | 3 | 8 | 11 => DistributionKind::Ternary,
                _ => DistributionKind::CenteredBinomial,
            };
            DistributionRecord::new(
                purpose,
                kind,
                if kind == DistributionKind::Ternary {
                    0
                } else {
                    2
                },
            )
            .expect("test distribution")
        })
        .collect();
    let artifacts = (1..=6)
        .map(|artifact_code| {
            ArtifactReference::new(
                ArtifactKind::from_canonical_code(artifact_code).expect("artifact kind"),
                100 + u64::from(artifact_code),
                Hash512::from_bytes([u8::try_from(artifact_code).expect("artifact byte"); 64]),
            )
            .expect("artifact reference")
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
        maximum_private_sampler_candidate_draws_per_output: 5,
        maximum_public_sampler_candidate_draws_per_output: 7,
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

fn proof_field_97() -> ProofFieldProfile {
    ProofFieldProfile::new(97, 28, vec![5, 0])
        .expect("97, its order-32 generator, and Y^2 + 5 form a valid test field")
}

fn proof_field_193() -> ProofFieldProfile {
    let modulus = 193u64;
    let maximum_two_adic_order = 1u64 << (modulus - 1).trailing_zeros();
    let generator = (2..modulus)
        .find(|candidate| {
            modular_power(*candidate, maximum_two_adic_order, modulus) == 1
                && modular_power(*candidate, maximum_two_adic_order / 2, modulus) != 1
        })
        .expect("a finite field contains a generator of its maximum two-adic subgroup");
    let irreducible_constant = (1..modulus)
        .find(|constant| is_monic_polynomial_irreducible(&[*constant, 0], modulus))
        .expect("an irreducible quadratic exists over the test field");
    ProofFieldProfile::new(modulus, generator, vec![irreducible_constant, 0])
        .expect("derived second test field is valid")
}

fn proof_field_769() -> ProofFieldProfile {
    ProofFieldProfile::new(769, 7, vec![0])
        .expect("769, its order-256 generator, and a linear extension polynomial are valid")
}

fn proof_field_1153() -> ProofFieldProfile {
    ProofFieldProfile::new(1_153, 38, vec![0])
        .expect("1153, its order-128 generator, and a linear extension polynomial are valid")
}

fn schedule(proof_field_index: u16) -> ProofFieldSchedule {
    ProofFieldSchedule::new(proof_field_index, 4, 3, 2, 8, 4, 3, 6)
        .expect("test schedule is intrinsically valid")
}

fn ordered_family_profiles(proof_field_index: u16) -> Vec<ProofFamilyProfile> {
    ORDERED_PROOF_PROFILE_FAMILIES
        .into_iter()
        .map(|proof_family| {
            ProofFamilyProfile::new(proof_family, schedule(proof_field_index))
                .expect("closed proof family accepts the test schedule")
        })
        .collect()
}

fn valid_profile_set() -> ProofProfileSet {
    ProofProfileSet::new(
        vec![proof_field_769()],
        ordered_family_profiles(0),
        &valid_suite_record(),
    )
    .expect("test profile set is intrinsically valid")
}

#[test]
fn generated_profile_artifact_matches_the_independent_typescript_vector_identity() {
    let canonical_bytes = valid_profile_set()
        .encode()
        .expect("valid proof profile set encodes");
    let artifact_reference =
        ArtifactReference::from_artifact_bytes(ArtifactKind::ProofProfileSet, &canonical_bytes)
            .expect("proof profile artifact reference");

    assert_eq!(canonical_bytes.len(), 26_727);
    assert_eq!(
        artifact_reference.artifact_hash.to_lowercase_hex(),
        "f91152852e2fa0406a65a9b99eebb6afb44358e8b93dd3b8865e424e2543039fc0eea85ed687c2fd35a703797f3d4b6b8a961b6b38bb7222911df832d4ae4339"
    );
}

fn expect_validation_and_encoding_refusal(
    profile_set: &ProofProfileSet,
    expected_refusal_reason: RefusalReason,
) {
    assert_eq!(
        profile_set
            .validate_intrinsic()
            .expect_err("invalid profile set unexpectedly validated")
            .refusal_reason,
        expected_refusal_reason
    );
    assert_eq!(
        profile_set
            .encode()
            .expect_err("invalid profile set unexpectedly encoded")
            .refusal_reason,
        expected_refusal_reason
    );
}

fn expect_field_validation_and_encoding_refusal(
    profile: &ProofFieldProfile,
    expected_refusal_reason: RefusalReason,
) {
    assert_eq!(
        profile
            .validate_intrinsic()
            .expect_err("invalid proof field unexpectedly validated")
            .refusal_reason,
        expected_refusal_reason
    );
    assert_eq!(
        profile
            .encode()
            .expect_err("invalid proof field unexpectedly encoded")
            .refusal_reason,
        expected_refusal_reason
    );
}

fn base_field_digits(mut encoded: u64, digit_count: usize, modulus: u64) -> Vec<u64> {
    (0..digit_count)
        .map(|_| {
            let digit = encoded % modulus;
            encoded /= modulus;
            digit
        })
        .collect()
}

fn is_irreducible_by_exhaustive_monic_division(coefficients: &[u64], modulus: u64) -> bool {
    let mut polynomial = coefficients.to_vec();
    polynomial.push(1);
    for divisor_degree in 1..=coefficients.len() / 2 {
        let divisor_count = modulus.pow(
            u32::try_from(divisor_degree).expect("small exhaustive degree fits a u32 exponent"),
        );
        for encoded_divisor in 0..divisor_count {
            let mut divisor = base_field_digits(encoded_divisor, divisor_degree, modulus);
            divisor.push(1);
            if polynomial_is_zero(&polynomial_remainder(&polynomial, &divisor, modulus)) {
                return false;
            }
        }
    }
    true
}

#[test]
fn all_four_schema_identifiers_and_canonical_item_orders_are_exact() {
    assert_eq!(PROOF_PROFILE_SET_SCHEMA_IDENTIFIER, 0x2200);
    assert_eq!(PROOF_FIELD_PROFILE_SCHEMA_IDENTIFIER, 0x2201);
    assert_eq!(PROOF_FAMILY_PROFILE_SCHEMA_IDENTIFIER, 0x2202);
    assert_eq!(PROOF_FIELD_SCHEDULE_SCHEMA_IDENTIFIER, 0x2203);
    assert_eq!(FoundationSchemaIdentifier::ProofProfileSet as u16, 0x2200);
    assert_eq!(FoundationSchemaIdentifier::ProofFieldProfile as u16, 0x2201);
    assert_eq!(
        FoundationSchemaIdentifier::ProofFamilyProfile as u16,
        0x2202
    );
    assert_eq!(
        FoundationSchemaIdentifier::ProofFieldSchedule as u16,
        0x2203
    );

    let field_tuple = proof_field_97().canonical_tuple().expect("field tuple");
    assert_eq!(field_tuple.schema_identifier, 0x2201);
    assert_eq!(field_tuple.schema_version, 1);
    assert_eq!(field_tuple.items.len(), 3);
    assert_eq!(
        field_tuple.items[0].item_type(),
        CanonicalItemType::Unsigned64
    );
    assert_eq!(
        field_tuple.items[1].item_type(),
        CanonicalItemType::Unsigned64
    );
    assert_eq!(
        field_tuple.items[2].item_type(),
        CanonicalItemType::HomogeneousList
    );
    let (coefficient_count, coefficient_bytes) =
        read_list_header(&field_tuple.items[2], CanonicalItemType::Unsigned64)
            .expect("coefficient list header");
    assert_eq!(coefficient_count, 2);
    assert_eq!(
        coefficient_bytes,
        &[5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    );

    let schedule_tuple = schedule(0).canonical_tuple().expect("schedule tuple");
    assert_eq!(schedule_tuple.schema_identifier, 0x2203);
    assert_eq!(schedule_tuple.schema_version, 1);
    assert_eq!(schedule_tuple.items.len(), 8);
    assert_eq!(
        schedule_tuple
            .encode()
            .expect("schedule tuple encodes")
            .len(),
        PROOF_FIELD_SCHEDULE_MAXIMUM_BYTE_LENGTH
    );
    assert_eq!(
        schedule_tuple
            .items
            .iter()
            .map(CanonicalItem::item_type)
            .collect::<Vec<_>>(),
        vec![
            CanonicalItemType::Unsigned16,
            CanonicalItemType::Unsigned32,
            CanonicalItemType::Unsigned64,
            CanonicalItemType::Unsigned16,
            CanonicalItemType::Unsigned32,
            CanonicalItemType::Unsigned32,
            CanonicalItemType::Unsigned16,
            CanonicalItemType::Unsigned32,
        ]
    );

    let family_tuple = ProofFamilyProfile::new(ProofFamily::BallotValidity, schedule(0))
        .expect("family profile")
        .canonical_tuple()
        .expect("family tuple");
    assert_eq!(family_tuple.schema_identifier, 0x2202);
    assert_eq!(family_tuple.schema_version, 1);
    assert_eq!(family_tuple.items.len(), 2);
    assert_eq!(
        family_tuple.encode().expect("family tuple encodes").len(),
        PROOF_FAMILY_PROFILE_MAXIMUM_BYTE_LENGTH
    );
    assert_eq!(
        family_tuple.items[0].item_type(),
        CanonicalItemType::Unsigned16
    );
    assert_eq!(
        family_tuple.items[1].item_type(),
        CanonicalItemType::NestedTuple
    );

    let set_tuple = valid_profile_set()
        .canonical_tuple()
        .expect("profile-set tuple");
    assert_eq!(set_tuple.schema_identifier, 0x2200);
    assert_eq!(set_tuple.schema_version, 1);
    assert_eq!(set_tuple.items.len(), 4);
    assert!(
        set_tuple
            .items
            .iter()
            .all(|item| item.item_type() == CanonicalItemType::HomogeneousList)
    );
}

#[test]
fn every_schema_round_trips_to_identical_canonical_bytes() {
    let limits = CanonicalDecodeLimits::default();
    let field = proof_field_97();
    let field_bytes = field.encode().expect("field encodes");
    let decoded_field = ProofFieldProfile::decode(&field_bytes, &limits).expect("field decodes");
    assert_eq!(decoded_field, field);
    assert_eq!(
        decoded_field.encode().expect("decoded field re-encodes"),
        field_bytes
    );

    let field_schedule = schedule(0);
    let schedule_bytes = field_schedule.encode().expect("schedule encodes");
    let decoded_schedule =
        ProofFieldSchedule::decode(&schedule_bytes, &limits).expect("schedule decodes");
    assert_eq!(decoded_schedule, field_schedule);
    assert_eq!(
        decoded_schedule
            .encode()
            .expect("decoded schedule re-encodes"),
        schedule_bytes
    );

    let family = ProofFamilyProfile::new(ProofFamily::AggregateThresholdShare, field_schedule)
        .expect("family profile");
    let family_bytes = family.encode().expect("family encodes");
    let decoded_family =
        ProofFamilyProfile::decode(&family_bytes, &limits).expect("family decodes");
    assert_eq!(decoded_family, family);
    assert_eq!(
        decoded_family.encode().expect("decoded family re-encodes"),
        family_bytes
    );

    let profile_set = valid_profile_set();
    let profile_set_bytes = profile_set.encode().expect("profile set encodes");
    let decoded_profile_set =
        ProofProfileSet::decode(&profile_set_bytes, &limits).expect("profile set decodes");
    assert_eq!(decoded_profile_set, profile_set);
    assert_eq!(
        decoded_profile_set
            .encode()
            .expect("decoded profile set re-encodes"),
        profile_set_bytes
    );
}

#[test]
fn proof_field_validation_reproduces_prime_generator_and_irreducibility_requirements() {
    let valid = proof_field_97();
    assert_eq!(valid.maximum_two_adic_subgroup_order(), 32);
    assert_eq!(modular_power(28, 32, 97), 1);
    assert_ne!(modular_power(28, 16, 97), 1);
    assert!(is_monic_polynomial_irreducible(&[5, 0], 97));
    assert!(!is_monic_polynomial_irreducible(&[96, 0], 97));

    let invalid_cases = [
        (
            ProofFieldProfile {
                base_field_modulus: 9,
                ..valid.clone()
            },
            RefusalReason::OutsideSupportedProfile,
        ),
        (
            ProofFieldProfile {
                base_field_modulus: 2,
                ..valid.clone()
            },
            RefusalReason::OutsideSupportedProfile,
        ),
        (
            ProofFieldProfile {
                maximum_two_adic_subgroup_generator: 0,
                ..valid.clone()
            },
            RefusalReason::MalformedEncoding,
        ),
        (
            ProofFieldProfile {
                maximum_two_adic_subgroup_generator: 97,
                ..valid.clone()
            },
            RefusalReason::MalformedEncoding,
        ),
        (
            ProofFieldProfile {
                maximum_two_adic_subgroup_generator: 1,
                ..valid.clone()
            },
            RefusalReason::OutsideSupportedProfile,
        ),
        (
            ProofFieldProfile {
                monic_challenge_extension_polynomial_coefficients: Vec::new(),
                ..valid.clone()
            },
            RefusalReason::OutsideSupportedProfile,
        ),
        (
            ProofFieldProfile {
                monic_challenge_extension_polynomial_coefficients: vec![0; 65],
                ..valid.clone()
            },
            RefusalReason::OutsideSupportedProfile,
        ),
        (
            ProofFieldProfile {
                monic_challenge_extension_polynomial_coefficients: vec![97],
                ..valid.clone()
            },
            RefusalReason::MalformedEncoding,
        ),
        (
            ProofFieldProfile {
                monic_challenge_extension_polynomial_coefficients: vec![96, 0],
                ..valid
            },
            RefusalReason::OutsideSupportedProfile,
        ),
    ];
    for (invalid, expected_refusal_reason) in invalid_cases {
        expect_field_validation_and_encoding_refusal(&invalid, expected_refusal_reason);
    }
}

#[test]
fn irreducibility_test_handles_linear_quadratic_cubic_and_repeated_factor_boundaries() {
    assert!(is_monic_polynomial_irreducible(&[0], 3));
    assert!(is_monic_polynomial_irreducible(&[1, 0], 3));
    assert!(!is_monic_polynomial_irreducible(&[2, 0], 3));
    assert!(is_monic_polynomial_irreducible(&[1, 2, 0], 3));
    assert!(!is_monic_polynomial_irreducible(&[1, 0, 2, 0], 3));
    assert!(!is_monic_polynomial_irreducible(&[0, 1], 97));
}

#[test]
fn rabin_irreducibility_matches_exhaustive_factor_search_over_small_fields() {
    for modulus in [3u64, 5] {
        for degree in 1..=5usize {
            let polynomial_count = modulus
                .pow(u32::try_from(degree).expect("small exhaustive degree fits a u32 exponent"));
            for encoded_polynomial in 0..polynomial_count {
                let coefficients = base_field_digits(encoded_polynomial, degree, modulus);
                assert_eq!(
                    is_monic_polynomial_irreducible(&coefficients, modulus),
                    is_irreducible_by_exhaustive_monic_division(&coefficients, modulus),
                    "irreducibility mismatch for modulus {modulus}, coefficients {coefficients:?}",
                );
            }
        }
    }
}

#[test]
fn standalone_schedule_requires_canonical_positive_counts_and_power_of_two_blowup() {
    let valid = schedule(0);
    let invalid_schedules = [
        ProofFieldSchedule {
            evaluation_blowup_factor: 0,
            ..valid
        },
        ProofFieldSchedule {
            evaluation_blowup_factor: 3,
            ..valid
        },
        ProofFieldSchedule {
            evaluation_coset_offset: 0,
            ..valid
        },
        ProofFieldSchedule {
            evaluation_coset_offset: 1,
            ..valid
        },
        ProofFieldSchedule {
            deep_point_count: 0,
            ..valid
        },
        ProofFieldSchedule {
            final_polynomial_degree_bound_exclusive: 0,
            ..valid
        },
        ProofFieldSchedule {
            unique_query_count: 0,
            ..valid
        },
        ProofFieldSchedule {
            non_native_modular_identity_challenge_count: 0,
            ..valid
        },
        ProofFieldSchedule {
            maximum_fiat_shamir_candidate_draws_per_output: 0,
            ..valid
        },
    ];
    for invalid in invalid_schedules {
        assert_eq!(
            invalid
                .validate_intrinsic()
                .expect_err("invalid schedule unexpectedly validated")
                .refusal_reason,
            RefusalReason::OutsideSupportedProfile
        );
        assert_eq!(
            invalid
                .encode()
                .expect_err("invalid schedule unexpectedly encoded")
                .refusal_reason,
            RefusalReason::OutsideSupportedProfile
        );
    }
}

#[test]
fn profile_set_requires_exact_family_membership_and_increasing_statement_order() {
    let valid = valid_profile_set();

    let mut missing = valid.clone();
    missing.proof_families.pop();
    expect_validation_and_encoding_refusal(&missing, RefusalReason::OutsideSupportedProfile);

    let mut swapped = valid.clone();
    swapped.proof_families.swap(0, 1);
    expect_validation_and_encoding_refusal(&swapped, RefusalReason::DuplicateIdentity);

    let mut duplicate = valid.clone();
    duplicate.proof_families[1] = duplicate.proof_families[0].clone();
    expect_validation_and_encoding_refusal(&duplicate, RefusalReason::DuplicateIdentity);

    assert_eq!(
        valid
            .proof_families
            .iter()
            .map(ProofFamilyProfile::application_statement_schema_identifier)
            .collect::<Vec<_>>(),
        vec![
            0x1211, 0x1212, 0x1213, 0x1214, 0x1215, 0x1216, 0x1217, 0x1218, 0x1302, 0x1621, 0x2110,
            0x2111,
        ]
    );
}

#[test]
fn proof_field_catalog_is_bounded_increasing_referenced_and_index_checked() {
    let valid = valid_profile_set();

    let mut empty = valid.clone();
    empty.proof_fields.clear();
    expect_validation_and_encoding_refusal(&empty, RefusalReason::OutsideSupportedProfile);

    let mut too_many = valid.clone();
    too_many.proof_fields = vec![proof_field_97(); MAXIMUM_PROOF_FIELD_COUNT + 1];
    expect_validation_and_encoding_refusal(&too_many, RefusalReason::OutsideSupportedProfile);

    let mut duplicate = valid.clone();
    duplicate.proof_fields.push(proof_field_769());
    expect_validation_and_encoding_refusal(&duplicate, RefusalReason::DuplicateIdentity);

    let mut decreasing = valid.clone();
    decreasing.proof_fields = vec![proof_field_193(), proof_field_97()];
    expect_validation_and_encoding_refusal(&decreasing, RefusalReason::DuplicateIdentity);

    let mut missing_index = valid.clone();
    missing_index.proof_families[0]
        .field_schedule
        .proof_field_index = 1;
    expect_validation_and_encoding_refusal(&missing_index, RefusalReason::WrongTypeOrLength);

    let mut unreferenced = valid.clone();
    unreferenced.proof_fields.push(proof_field_1153());
    expect_validation_and_encoding_refusal(&unreferenced, RefusalReason::OutsideSupportedProfile);

    let mut two_fields = valid;
    two_fields.proof_fields.push(proof_field_1153());
    two_fields
        .proof_families
        .last_mut()
        .expect("the exact family list is nonempty")
        .field_schedule
        .proof_field_index = 1;
    two_fields
        .validate_intrinsic()
        .expect("both increasing fields are referenced by exact families");
    assert_eq!(
        ProofProfileSet::decode(
            &two_fields.encode().expect("two-field profile encodes"),
            &CanonicalDecodeLimits::default(),
        )
        .expect("two-field profile decodes"),
        two_fields
    );
}

#[test]
fn cross_field_validation_checks_only_intrinsic_field_capacity_constraints() {
    let valid = valid_profile_set();
    let mut invalid_cases = Vec::new();

    let mut noncanonical_coset = valid.clone();
    noncanonical_coset.proof_families[0]
        .field_schedule
        .evaluation_coset_offset = 769;
    invalid_cases.push((noncanonical_coset, RefusalReason::MalformedEncoding));

    let mut excessive_blowup = valid.clone();
    excessive_blowup.proof_families[0]
        .field_schedule
        .evaluation_blowup_factor = 512;
    invalid_cases.push((excessive_blowup, RefusalReason::OutsideSupportedProfile));

    let mut excessive_terminal_capacity = valid.clone();
    excessive_terminal_capacity.proof_families[0]
        .field_schedule
        .final_polynomial_degree_bound_exclusive = 257;
    invalid_cases.push((
        excessive_terminal_capacity,
        RefusalReason::OutsideSupportedProfile,
    ));

    let mut excessive_queries = valid;
    excessive_queries.proof_families[0]
        .field_schedule
        .unique_query_count = 257;
    invalid_cases.push((excessive_queries, RefusalReason::OutsideSupportedProfile));

    for (invalid, expected_refusal_reason) in invalid_cases {
        expect_validation_and_encoding_refusal(&invalid, expected_refusal_reason);
    }

    let tiny_field = ProofFieldProfile::new(3, 2, vec![0]).expect("linear extension over F_3");
    let excessive_deep_schedule = ProofFieldSchedule::new(0, 1, 2, 4, 1, 1, 1, 1)
        .expect("DEEP count is not a standalone schedule property");
    let tiny_field_families = ORDERED_PROOF_PROFILE_FAMILIES
        .into_iter()
        .map(|family| {
            ProofFamilyProfile::new(family, excessive_deep_schedule)
                .expect("closed family accepts standalone schedule")
        })
        .collect();
    let error = ProofProfileSet::new(vec![tiny_field], tiny_field_families, &valid_suite_record())
        .expect_err("DEEP count cannot exceed extension-field cardinality");
    assert_eq!(error.refusal_reason, RefusalReason::OutsideSupportedProfile);
}

#[test]
fn family_lookup_derives_the_suite_selected_field_without_proof_selected_algorithms() {
    let profile_set = valid_profile_set();
    for family in ORDERED_PROOF_PROFILE_FAMILIES {
        let (field, selected_schedule) = profile_set
            .field_and_schedule_for_family(family)
            .expect("every closed family has one suite-selected schedule");
        assert_eq!(field, &proof_field_769());
        assert_eq!(selected_schedule, &schedule(0));
    }

    let unknown_family_tuple = CanonicalTuple::new(
        PROOF_FAMILY_PROFILE_SCHEMA_IDENTIFIER,
        1,
        vec![
            CanonicalItem::unsigned16(0xffff),
            CanonicalItem::nested_tuple(&schedule(0).canonical_tuple().expect("schedule tuple"))
                .expect("nested schedule"),
        ],
    );
    let error = ProofFamilyProfile::decode(
        &unknown_family_tuple
            .encode()
            .expect("hostile family tuple encodes canonically"),
        &CanonicalDecodeLimits::default(),
    )
    .expect_err("proof bytes cannot select an unassigned statement family");
    assert_eq!(error.refusal_reason, RefusalReason::WrongTypeOrLength);
}

#[test]
fn wrong_headers_types_nested_schema_lengths_and_trailing_bytes_refuse() {
    let limits = CanonicalDecodeLimits::default();
    let encoded = valid_profile_set().encode().expect("profile set encodes");

    let mut wrong_schema = encoded.clone();
    wrong_schema[0..2].copy_from_slice(&0x22ffu16.to_le_bytes());
    assert_eq!(
        ProofProfileSet::decode(&wrong_schema, &limits)
            .expect_err("wrong schema must refuse")
            .refusal_reason,
        RefusalReason::WrongTypeOrLength
    );

    let mut wrong_version = encoded.clone();
    wrong_version[2..4].copy_from_slice(&2u16.to_le_bytes());
    assert_eq!(
        ProofProfileSet::decode(&wrong_version, &limits)
            .expect_err("wrong version must refuse")
            .refusal_reason,
        RefusalReason::UnsupportedVersionOrSuite
    );

    let mut wrong_outer_item_type = encoded.clone();
    wrong_outer_item_type[8..10]
        .copy_from_slice(&CanonicalItemType::Unsigned64.canonical_code().to_le_bytes());
    assert_eq!(
        ProofProfileSet::decode(&wrong_outer_item_type, &limits)
            .expect_err("wrong outer item type must refuse")
            .refusal_reason,
        RefusalReason::MalformedEncoding
    );

    let mut inconsistent_list_count = encoded.clone();
    inconsistent_list_count[16..20].copy_from_slice(&2u32.to_le_bytes());
    assert_eq!(
        ProofProfileSet::decode(&inconsistent_list_count, &limits)
            .expect_err("inconsistent homogeneous-list count must refuse")
            .refusal_reason,
        RefusalReason::MalformedEncoding
    );

    let mut trailing_bytes = encoded;
    trailing_bytes.push(0);
    assert_eq!(
        ProofProfileSet::decode(&trailing_bytes, &limits)
            .expect_err("trailing bytes must refuse")
            .refusal_reason,
        RefusalReason::MalformedEncoding
    );

    let wrong_nested_schedule = CanonicalTuple::new(
        PROOF_FIELD_PROFILE_SCHEMA_IDENTIFIER,
        1,
        schedule(0).canonical_tuple().expect("schedule tuple").items,
    );
    let hostile_family = CanonicalTuple::new(
        PROOF_FAMILY_PROFILE_SCHEMA_IDENTIFIER,
        1,
        vec![
            CanonicalItem::unsigned16(ProofFamily::BallotValidity.statement_schema_identifier()),
            CanonicalItem::nested_tuple(&wrong_nested_schedule).expect("nested hostile tuple"),
        ],
    );
    assert_eq!(
        ProofFamilyProfile::decode(
            &hostile_family.encode().expect("hostile family encodes"),
            &limits,
        )
        .expect_err("nested schedule schema substitution must refuse")
        .refusal_reason,
        RefusalReason::WrongTypeOrLength
    );
}

#[test]
fn profile_set_bounds_apply_before_allocation_and_preserve_caller_decode_limits() {
    let encoded = valid_profile_set().encode().expect("profile set encodes");
    assert!(encoded.len() <= PROOF_PROFILE_SET_MAXIMUM_BYTE_LENGTH);

    let restrictive_limits = CanonicalDecodeLimits {
        maximum_tuple_byte_length: encoded.len() - 1,
        ..CanonicalDecodeLimits::default()
    };
    assert_eq!(
        ProofProfileSet::decode(&encoded, &restrictive_limits)
            .expect_err("caller tuple limit must remain authoritative")
            .refusal_reason,
        RefusalReason::OutsideSupportedProfile
    );

    let oversized = vec![0u8; PROOF_PROFILE_SET_MAXIMUM_BYTE_LENGTH + 1];
    assert_eq!(
        ProofProfileSet::decode(&oversized, &CanonicalDecodeLimits::default())
            .expect_err("oversized profile must refuse before tuple parsing")
            .refusal_reason,
        RefusalReason::OutsideSupportedProfile
    );
}

#[test]
fn standalone_schema_bounds_apply_before_canonical_allocation() {
    let limits = CanonicalDecodeLimits::default();
    assert_eq!(
        ProofFieldProfile::decode(
            &vec![0u8; PROOF_FIELD_PROFILE_MAXIMUM_BYTE_LENGTH + 1],
            &limits,
        )
        .expect_err("oversized field profile must refuse before tuple parsing")
        .refusal_reason,
        RefusalReason::OutsideSupportedProfile
    );
    assert_eq!(
        ProofFieldSchedule::decode(
            &[0u8; PROOF_FIELD_SCHEDULE_MAXIMUM_BYTE_LENGTH + 1],
            &limits,
        )
        .expect_err("oversized field schedule must refuse before tuple parsing")
        .refusal_reason,
        RefusalReason::OutsideSupportedProfile
    );
    assert_eq!(
        ProofFamilyProfile::decode(
            &[0u8; PROOF_FAMILY_PROFILE_MAXIMUM_BYTE_LENGTH + 1],
            &limits,
        )
        .expect_err("oversized family profile must refuse before tuple parsing")
        .refusal_reason,
        RefusalReason::OutsideSupportedProfile
    );

    let encoded_field = proof_field_97().encode().expect("field profile encodes");
    let restrictive_limits = CanonicalDecodeLimits {
        maximum_tuple_byte_length: encoded_field.len() - 1,
        ..limits
    };
    assert_eq!(
        ProofFieldProfile::decode(&encoded_field, &restrictive_limits)
            .expect_err("caller field-profile limit must remain authoritative")
            .refusal_reason,
        RefusalReason::OutsideSupportedProfile
    );
}

#[test]
fn profile_set_artifact_reference_checks_kind_length_hash_and_schema() {
    let suite_record = valid_suite_record();
    let profile_set = valid_profile_set();
    let encoded = profile_set.encode().expect("profile set encodes");
    let reference = profile_set
        .artifact_reference()
        .expect("artifact reference derives");
    assert_eq!(reference.artifact_kind, ArtifactKind::ProofProfileSet);
    assert_eq!(reference.byte_length, encoded.len() as u64);
    assert_eq!(
        ProofProfileSet::decode_verified_artifact(
            &reference,
            &encoded,
            &CanonicalDecodeLimits::default(),
            &suite_record,
        )
        .expect("bound profile-set artifact decodes"),
        profile_set
    );

    let wrong_kind =
        ArtifactReference::from_artifact_bytes(ArtifactKind::EvaluatorProgramSet, &encoded)
            .expect("wrong-kind reference is otherwise canonical");
    assert_eq!(
        ProofProfileSet::decode_verified_artifact(
            &wrong_kind,
            &encoded,
            &CanonicalDecodeLimits::default(),
            &suite_record,
        )
        .expect_err("wrong artifact kind must refuse")
        .refusal_reason,
        RefusalReason::WrongTypeOrLength
    );

    let shorter = &encoded[..encoded.len() - 1];
    assert_eq!(
        ProofProfileSet::decode_verified_artifact(
            &reference,
            shorter,
            &CanonicalDecodeLimits::default(),
            &suite_record,
        )
        .expect_err("artifact length mismatch must refuse")
        .refusal_reason,
        RefusalReason::WrongTypeOrLength
    );

    let mut same_length_tampering = encoded;
    let last = same_length_tampering
        .last_mut()
        .expect("encoded profile is nonempty");
    *last ^= 1;
    assert_eq!(
        ProofProfileSet::decode_verified_artifact(
            &reference,
            &same_length_tampering,
            &CanonicalDecodeLimits::default(),
            &suite_record,
        )
        .expect_err("artifact hash mismatch must refuse before schema acceptance")
        .refusal_reason,
        RefusalReason::WrongHashOrRoot
    );
}

#[test]
fn relation_plan_mutation_changes_the_profile_artifact_and_suite_identifier() {
    let suite_record = valid_suite_record();
    let profile_set = valid_profile_set();
    let mut mutated_profile_set = profile_set.clone();
    let mut variants = read_nested_tuple_list(
        &mutated_profile_set.relation_plans[0].items[1],
        &CanonicalDecodeLimits::default(),
    )
    .expect("relation-plan variants decode");
    variants[0].items[3] = CanonicalItem::unsigned64(4);
    let variant_items = variants
        .iter()
        .map(|variant| CanonicalItem::nested_tuple(variant).expect("variant nests"))
        .collect::<Vec<_>>();
    mutated_profile_set.relation_plans[0].items[1] =
        CanonicalItem::homogeneous_list(CanonicalItemType::NestedTuple, &variant_items)
            .expect("variant list encodes");

    let canonical_profile = profile_set.encode().expect("profile set encodes");
    let mutated_profile = mutated_profile_set
        .encode()
        .expect("structurally canonical mutation encodes");
    assert_ne!(canonical_profile, mutated_profile);
    assert_eq!(
        ProofProfileSet::decode_for_suite(
            &mutated_profile,
            &CanonicalDecodeLimits::default(),
            &suite_record,
        )
        .expect_err("suite-aware validation must reject changed relation bytes")
        .refusal_reason,
        RefusalReason::WrongContext
    );

    let mut canonical_suite = suite_record.clone();
    canonical_suite.artifacts[3] = profile_set
        .artifact_reference()
        .expect("canonical profile reference");
    let mut mutated_suite = suite_record;
    mutated_suite.artifacts[3] = mutated_profile_set
        .artifact_reference()
        .expect("mutated profile reference");
    assert_ne!(
        canonical_suite
            .suite_id()
            .expect("canonical suite identifier"),
        mutated_suite.suite_id().expect("mutated suite identifier")
    );
}

#[test]
fn malformed_coefficient_list_length_and_wrong_scalar_types_refuse_without_panics() {
    let limits = CanonicalDecodeLimits::default();
    let valid = proof_field_97();

    let wrong_scalar_type = CanonicalTuple::new(
        PROOF_FIELD_PROFILE_SCHEMA_IDENTIFIER,
        1,
        vec![
            CanonicalItem::unsigned32(97),
            CanonicalItem::unsigned64(28),
            encode_u64_list(&[5, 0]).expect("coefficient list"),
        ],
    );
    assert_eq!(
        ProofFieldProfile::decode(
            &wrong_scalar_type
                .encode()
                .expect("wrong-type tuple encodes"),
            &limits,
        )
        .expect_err("wrong scalar item type must refuse")
        .refusal_reason,
        RefusalReason::WrongTypeOrLength
    );

    let mut field_bytes = valid.encode().expect("field encodes");
    let coefficient_item_header_offset = 8 + (6 + 8) + (6 + 8);
    let coefficient_list_count_offset = coefficient_item_header_offset + 6 + 2;
    field_bytes[coefficient_list_count_offset..coefficient_list_count_offset + 4]
        .copy_from_slice(&3u32.to_le_bytes());
    assert_eq!(
        ProofFieldProfile::decode(&field_bytes, &limits)
            .expect_err("coefficient list count/length mismatch must refuse")
            .refusal_reason,
        RefusalReason::MalformedEncoding
    );
}
