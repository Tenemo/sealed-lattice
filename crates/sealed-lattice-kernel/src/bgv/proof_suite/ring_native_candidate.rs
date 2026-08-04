//! Static correspondence for the ring-native common-proof candidate.
//!
//! This module is test-only evidence. It does not select a proof backend or
//! authorize any proof bytes. Its purpose is to keep the candidate relation
//! inventory, dependency barriers, direct-RNS arithmetic strategy, and exact
//! BGV modulus geometry derived from the same production constants as the
//! incumbent proof inventory.

use num_bigint::BigUint;

use crate::{
    bgv::parameters::{DATA_PRIMES, POLYNOMIAL_DEGREE, SPECIAL_PRIMES},
    foundation::{
        FOUNDATION_PROFILE, ProofApplicationSlotCeilings,
        SELECTED_MAXIMUM_CANDIDATE_PACKAGES_PER_ACTION,
    },
};

use super::selected_target_decryption_flooding_bound;

const RETIRED_EXAMPLE_PROOF_FIELD_BASE: u64 = 3_611_623_616;
const RETIRED_EXAMPLE_PROOF_FIELD_EXPONENT: u32 = 8;
const CANDIDATE_PROOF_FIELD_BASE: u64 = 181_765_148;
const CANDIDATE_PROOF_FIELD_EXPONENT: u32 = 16;
const CANDIDATE_TRANSCRIPT_ORACLE_OUTPUT_BIT_LENGTH: u32 = 512;
const CANDIDATE_TOTAL_QROM_QUERY_PARAMETER_BIT_LENGTH: u32 = 81;
const MOBILE_PROTOTYPE_INVALID_ACCEPTANCE_BIT_LENGTH: u32 = 80;
const CANDIDATE_OUTER_PACKET_SCHEDULE_COUNT: u32 = 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RingNativeConstraintCapability {
    ArbitraryLinearMap,
    CanonicalCoefficientEncoding,
    NegacyclicRingArithmetic,
    CoefficientInfinityNorm,
    CyclotomicAutomorphism,
    SmallSetMembership,
    ExactRnsLimbIntegerLift,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RingNativeCandidateDisposition {
    /// The family remains a logical relation inside a secret-bearing proof.
    SecretBearingRelation,
    /// No independent proof is emitted. The successor must bind the aggregate
    /// through a canonical linear commitment derived from already verified
    /// source commitments and a streaming commitment to the aggregate bytes.
    PublicLinearAggregate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RingNativeCandidateEpoch {
    DealerVss,
    AfterVerifiedVss,
    AfterFrozenRoundOneAggregate,
    BallotAttempt,
    TargetRelease,
    PublicRecomputation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RingNativeCandidateFamily {
    application_statement_schema_identifier: u16,
    disposition: RingNativeCandidateDisposition,
    epoch: RingNativeCandidateEpoch,
    required_capabilities: &'static [RingNativeConstraintCapability],
}

const COMMITTED_MATERIAL: &[RingNativeConstraintCapability] = &[
    RingNativeConstraintCapability::ArbitraryLinearMap,
    RingNativeConstraintCapability::CanonicalCoefficientEncoding,
    RingNativeConstraintCapability::CoefficientInfinityNorm,
    RingNativeConstraintCapability::ExactRnsLimbIntegerLift,
];

const SAME_SECRET: &[RingNativeConstraintCapability] = &[
    RingNativeConstraintCapability::ArbitraryLinearMap,
    RingNativeConstraintCapability::CanonicalCoefficientEncoding,
    RingNativeConstraintCapability::CoefficientInfinityNorm,
    RingNativeConstraintCapability::SmallSetMembership,
    RingNativeConstraintCapability::ExactRnsLimbIntegerLift,
];

const RING_SAMPLE: &[RingNativeConstraintCapability] = &[
    RingNativeConstraintCapability::ArbitraryLinearMap,
    RingNativeConstraintCapability::CanonicalCoefficientEncoding,
    RingNativeConstraintCapability::NegacyclicRingArithmetic,
    RingNativeConstraintCapability::CoefficientInfinityNorm,
    RingNativeConstraintCapability::SmallSetMembership,
    RingNativeConstraintCapability::ExactRnsLimbIntegerLift,
];

const GALOIS_SAMPLE: &[RingNativeConstraintCapability] = &[
    RingNativeConstraintCapability::ArbitraryLinearMap,
    RingNativeConstraintCapability::CanonicalCoefficientEncoding,
    RingNativeConstraintCapability::NegacyclicRingArithmetic,
    RingNativeConstraintCapability::CoefficientInfinityNorm,
    RingNativeConstraintCapability::CyclotomicAutomorphism,
    RingNativeConstraintCapability::SmallSetMembership,
    RingNativeConstraintCapability::ExactRnsLimbIntegerLift,
];

const BALLOT_SAMPLE: &[RingNativeConstraintCapability] = &[
    RingNativeConstraintCapability::ArbitraryLinearMap,
    RingNativeConstraintCapability::CanonicalCoefficientEncoding,
    RingNativeConstraintCapability::NegacyclicRingArithmetic,
    RingNativeConstraintCapability::CoefficientInfinityNorm,
    RingNativeConstraintCapability::SmallSetMembership,
    RingNativeConstraintCapability::ExactRnsLimbIntegerLift,
];

const TARGET_SAMPLE: &[RingNativeConstraintCapability] = &[
    RingNativeConstraintCapability::ArbitraryLinearMap,
    RingNativeConstraintCapability::CanonicalCoefficientEncoding,
    RingNativeConstraintCapability::NegacyclicRingArithmetic,
    RingNativeConstraintCapability::CoefficientInfinityNorm,
    RingNativeConstraintCapability::SmallSetMembership,
    RingNativeConstraintCapability::ExactRnsLimbIntegerLift,
];

const PUBLIC_AGGREGATE: &[RingNativeConstraintCapability] = &[
    RingNativeConstraintCapability::ArbitraryLinearMap,
    RingNativeConstraintCapability::CanonicalCoefficientEncoding,
];

const RING_NATIVE_CANDIDATE_FAMILIES: [RingNativeCandidateFamily; 12] = [
    RingNativeCandidateFamily {
        application_statement_schema_identifier:
            ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
        disposition: RingNativeCandidateDisposition::SecretBearingRelation,
        epoch: RingNativeCandidateEpoch::DealerVss,
        required_capabilities: COMMITTED_MATERIAL,
    },
    RingNativeCandidateFamily {
        application_statement_schema_identifier:
            ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
        disposition: RingNativeCandidateDisposition::SecretBearingRelation,
        epoch: RingNativeCandidateEpoch::AfterVerifiedVss,
        required_capabilities: COMMITTED_MATERIAL,
    },
    RingNativeCandidateFamily {
        application_statement_schema_identifier:
            ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
        disposition: RingNativeCandidateDisposition::SecretBearingRelation,
        epoch: RingNativeCandidateEpoch::AfterVerifiedVss,
        required_capabilities: SAME_SECRET,
    },
    RingNativeCandidateFamily {
        application_statement_schema_identifier:
            ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
        disposition: RingNativeCandidateDisposition::SecretBearingRelation,
        epoch: RingNativeCandidateEpoch::AfterVerifiedVss,
        required_capabilities: RING_SAMPLE,
    },
    RingNativeCandidateFamily {
        application_statement_schema_identifier: ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        disposition: RingNativeCandidateDisposition::PublicLinearAggregate,
        epoch: RingNativeCandidateEpoch::PublicRecomputation,
        required_capabilities: PUBLIC_AGGREGATE,
    },
    RingNativeCandidateFamily {
        application_statement_schema_identifier:
            ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER,
        disposition: RingNativeCandidateDisposition::SecretBearingRelation,
        epoch: RingNativeCandidateEpoch::AfterVerifiedVss,
        required_capabilities: RING_SAMPLE,
    },
    RingNativeCandidateFamily {
        application_statement_schema_identifier: ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        disposition: RingNativeCandidateDisposition::PublicLinearAggregate,
        epoch: RingNativeCandidateEpoch::PublicRecomputation,
        required_capabilities: PUBLIC_AGGREGATE,
    },
    RingNativeCandidateFamily {
        application_statement_schema_identifier:
            ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER,
        disposition: RingNativeCandidateDisposition::SecretBearingRelation,
        epoch: RingNativeCandidateEpoch::AfterFrozenRoundOneAggregate,
        required_capabilities: RING_SAMPLE,
    },
    RingNativeCandidateFamily {
        application_statement_schema_identifier:
            ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
        disposition: RingNativeCandidateDisposition::SecretBearingRelation,
        epoch: RingNativeCandidateEpoch::AfterVerifiedVss,
        required_capabilities: GALOIS_SAMPLE,
    },
    RingNativeCandidateFamily {
        application_statement_schema_identifier: ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        disposition: RingNativeCandidateDisposition::PublicLinearAggregate,
        epoch: RingNativeCandidateEpoch::PublicRecomputation,
        required_capabilities: PUBLIC_AGGREGATE,
    },
    RingNativeCandidateFamily {
        application_statement_schema_identifier:
            ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
        disposition: RingNativeCandidateDisposition::SecretBearingRelation,
        epoch: RingNativeCandidateEpoch::BallotAttempt,
        required_capabilities: BALLOT_SAMPLE,
    },
    RingNativeCandidateFamily {
        application_statement_schema_identifier:
            ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER,
        disposition: RingNativeCandidateDisposition::SecretBearingRelation,
        epoch: RingNativeCandidateEpoch::TargetRelease,
        required_capabilities: TARGET_SAMPLE,
    },
];

fn modulus_product_bit_length(moduli: &[u64]) -> u64 {
    moduli
        .iter()
        .fold(BigUint::from(1_u8), |product, modulus| {
            product * BigUint::from(*modulus)
        })
        .bits()
}

fn direct_rns_candidate_field_modulus() -> BigUint {
    BigUint::from(CANDIDATE_PROOF_FIELD_BASE).pow(CANDIDATE_PROOF_FIELD_EXPONENT)
        + BigUint::from(1_u8)
}

fn retired_example_field_modulus() -> BigUint {
    BigUint::from(RETIRED_EXAMPLE_PROOF_FIELD_BASE).pow(RETIRED_EXAMPLE_PROOF_FIELD_EXPONENT)
        + BigUint::from(1_u8)
}

fn greatest_common_divisor(mut left: BigUint, mut right: BigUint) -> BigUint {
    while right != BigUint::from(0_u8) {
        let remainder = &left % &right;
        left = right;
        right = remainder;
    }
    left
}

fn assert_pocklington_witness(modulus: &BigUint, prime_factor: u64, witness: u64) {
    let modulus_minus_one = modulus - BigUint::from(1_u8);
    let witness = BigUint::from(witness);
    assert_eq!(
        witness.modpow(&modulus_minus_one, modulus),
        BigUint::from(1_u8)
    );
    let factor_exponent = &modulus_minus_one / BigUint::from(prime_factor);
    let nontrivial_residue = witness.modpow(&factor_exponent, modulus) - BigUint::from(1_u8);
    assert_eq!(
        greatest_common_divisor(nontrivial_residue, modulus.clone()),
        BigUint::from(1_u8)
    );
}

fn assert_small_prime(candidate: u64) {
    assert!(candidate >= 2);
    let mut divisor = 2_u64;
    while divisor <= candidate / divisor {
        assert_ne!(candidate % divisor, 0, "factor must itself be prime");
        divisor += if divisor == 2 { 1 } else { 2 };
    }
}

#[test]
fn candidate_maps_the_complete_production_inventory_without_dropping_a_secret_relation() {
    const SELECTED_GALOIS_RELATION_INSTANCE_COUNT_PER_BATCH: u32 = 6;
    const SELECTED_EVALUATOR_AGGREGATE_RELATION_INSTANCE_COUNT: u32 = 7;

    let ceilings = ProofApplicationSlotCeilings::derive(
        FOUNDATION_PROFILE.participant_count,
        1,
        1,
        SELECTED_MAXIMUM_CANDIDATE_PACKAGES_PER_ACTION,
    )
    .expect("selected proof-family ceilings derive");
    let incumbent_inventory = ceilings
        .derive_proof_family_application_inventory(
            SELECTED_GALOIS_RELATION_INSTANCE_COUNT_PER_BATCH,
            SELECTED_EVALUATOR_AGGREGATE_RELATION_INSTANCE_COUNT,
        )
        .expect("selected proof-family inventory derives");

    let mut incumbent_physical_proof_count = 0_u32;
    let mut incumbent_logical_relation_count = 0_u32;
    let mut public_aggregate_physical_proof_count = 0_u32;
    let mut public_aggregate_logical_relation_count = 0_u32;
    let mut secret_bearing_logical_relation_count = 0_u32;

    for incumbent_family in incumbent_inventory.ordered_family_entries() {
        let mappings = RING_NATIVE_CANDIDATE_FAMILIES
            .iter()
            .filter(|candidate| {
                candidate.application_statement_schema_identifier
                    == incumbent_family.application_statement_schema_identifier()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            mappings.len(),
            1,
            "every incumbent family must have exactly one candidate disposition"
        );

        incumbent_physical_proof_count = incumbent_physical_proof_count
            .checked_add(incumbent_family.physical_proof_application_count())
            .expect("incumbent physical count fits");
        incumbent_logical_relation_count = incumbent_logical_relation_count
            .checked_add(incumbent_family.logical_relation_instance_count())
            .expect("incumbent logical count fits");

        match mappings[0].disposition {
            RingNativeCandidateDisposition::SecretBearingRelation => {
                assert!(
                    mappings[0]
                        .required_capabilities
                        .contains(&RingNativeConstraintCapability::CanonicalCoefficientEncoding)
                );
                assert!(
                    mappings[0]
                        .required_capabilities
                        .contains(&RingNativeConstraintCapability::CoefficientInfinityNorm)
                );
                assert!(
                    mappings[0]
                        .required_capabilities
                        .contains(&RingNativeConstraintCapability::ExactRnsLimbIntegerLift)
                );
                secret_bearing_logical_relation_count = secret_bearing_logical_relation_count
                    .checked_add(incumbent_family.logical_relation_instance_count())
                    .expect("secret-bearing logical count fits");
            }
            RingNativeCandidateDisposition::PublicLinearAggregate => {
                assert_eq!(
                    mappings[0].epoch,
                    RingNativeCandidateEpoch::PublicRecomputation
                );
                assert!(
                    mappings[0]
                        .required_capabilities
                        .contains(&RingNativeConstraintCapability::CanonicalCoefficientEncoding)
                );
                public_aggregate_physical_proof_count = public_aggregate_physical_proof_count
                    .checked_add(incumbent_family.physical_proof_application_count())
                    .expect("public aggregate physical count fits");
                public_aggregate_logical_relation_count = public_aggregate_logical_relation_count
                    .checked_add(incumbent_family.logical_relation_instance_count())
                    .expect("public aggregate logical count fits");
            }
        }
    }

    assert_eq!(incumbent_physical_proof_count, 103);
    assert_eq!(incumbent_logical_relation_count, 159);
    assert_eq!(public_aggregate_physical_proof_count, 3);
    assert_eq!(public_aggregate_logical_relation_count, 9);
    assert_eq!(secret_bearing_logical_relation_count, 150);

    let vss = RING_NATIVE_CANDIDATE_FAMILIES
        .iter()
        .find(|family| {
            family.application_statement_schema_identifier
                == ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER
        })
        .expect("the VSS candidate mapping exists");
    assert!(
        vss.required_capabilities
            .contains(&RingNativeConstraintCapability::CanonicalCoefficientEncoding)
    );
    assert!(
        vss.required_capabilities
            .contains(&RingNativeConstraintCapability::CoefficientInfinityNorm)
    );
}

#[test]
fn candidate_outer_packet_schedule_follows_the_three_setup_dependency_barriers() {
    let participant_count = u32::from(FOUNDATION_PROFILE.participant_count);

    let setup_packet_count = participant_count
        .checked_mul(3)
        .expect("three setup packets per participant fit");
    let candidate_outer_packet_schedule_count = setup_packet_count
        .checked_add(SELECTED_MAXIMUM_CANDIDATE_PACKAGES_PER_ACTION)
        .and_then(|count| count.checked_add(participant_count))
        .expect("candidate outer packet schedule count fits");

    assert_eq!(participant_count, 10);
    assert_eq!(setup_packet_count, 30);
    assert_eq!(
        candidate_outer_packet_schedule_count,
        CANDIDATE_OUTER_PACKET_SCHEDULE_COUNT
    );

    let after_vss_family_identifiers = RING_NATIVE_CANDIDATE_FAMILIES
        .iter()
        .filter(|family| family.epoch == RingNativeCandidateEpoch::AfterVerifiedVss)
        .map(|family| family.application_statement_schema_identifier)
        .collect::<Vec<_>>();
    assert_eq!(
        after_vss_family_identifiers,
        vec![0x2111, 0x1211, 0x1212, 0x1214, 0x1217]
    );

    let round_two_family_identifiers = RING_NATIVE_CANDIDATE_FAMILIES
        .iter()
        .filter(|family| family.epoch == RingNativeCandidateEpoch::AfterFrozenRoundOneAggregate)
        .map(|family| family.application_statement_schema_identifier)
        .collect::<Vec<_>>();
    assert_eq!(round_two_family_identifiers, vec![0x1216]);
}

#[test]
fn direct_rns_candidate_geometry_is_derived_from_the_exact_bgv_basis() {
    let mut extended_basis = DATA_PRIMES.to_vec();
    extended_basis.extend(SPECIAL_PRIMES);

    assert_eq!(POLYNOMIAL_DEGREE, 32_768);
    assert_eq!(DATA_PRIMES.len(), 23);
    assert_eq!(SPECIAL_PRIMES.len(), 3);
    assert_eq!(modulus_product_bit_length(&DATA_PRIMES[..8]), 251);
    assert_eq!(modulus_product_bit_length(&DATA_PRIMES), 691);
    assert_eq!(modulus_product_bit_length(&SPECIAL_PRIMES), 115);
    assert_eq!(modulus_product_bit_length(&extended_basis), 805);

    let extended_modulus_product = extended_basis
        .iter()
        .fold(BigUint::from(1_u8), |product, modulus| {
            product * BigUint::from(*modulus)
        });
    let candidate_field_modulus = direct_rns_candidate_field_modulus();

    // The candidate field is intentionally not a reconstruction of Q or Q*P.
    // Every physical RNS limb remains a separate exact integer equation, and a
    // bounded quotient proves reduction by that limb's public modulus.
    assert_eq!(candidate_field_modulus.bits(), 440);
    assert!(candidate_field_modulus < extended_modulus_product);
    assert_eq!(
        &candidate_field_modulus % BigUint::from(2 * POLYNOMIAL_DEGREE),
        BigUint::from(1_u8)
    );

    // 181_765_148 = 2^2 * 45_441_287. These witnesses certify the complete
    // factorization of p - 1, so Pocklington proves p prime.
    assert_eq!(
        BigUint::from(CANDIDATE_PROOF_FIELD_BASE),
        BigUint::from(2_u8).pow(2) * BigUint::from(45_441_287_u64)
    );
    assert_small_prime(45_441_287);
    for (prime_factor, witness) in [(2, 3), (45_441_287, 2)] {
        assert_pocklington_witness(&candidate_field_modulus, prime_factor, witness);
    }

    // This is a necessary preimplementation envelope, not the final compiler
    // theorem. The successor compiler must emit and check an exact interval for
    // every accepted constraint. Even a deliberately broad sixteen-product
    // limb equation is far below the candidate field.
    let maximum_limb_modulus = DATA_PRIMES
        .iter()
        .chain(SPECIAL_PRIMES.iter())
        .copied()
        .max()
        .expect("the selected RNS basis is nonempty");
    let minimum_limb_modulus = DATA_PRIMES
        .iter()
        .chain(SPECIAL_PRIMES.iter())
        .copied()
        .min()
        .expect("the selected RNS basis is nonempty");
    assert_eq!(minimum_limb_modulus.ilog2() + 1, 27);
    assert_eq!(maximum_limb_modulus.ilog2() + 1, 39);
    let maximum_centered_span = BigUint::from(maximum_limb_modulus - 1);
    let conservative_limb_expression_bound = BigUint::from(16_u8)
        * BigUint::from(POLYNOMIAL_DEGREE)
        * &maximum_centered_span
        * &maximum_centered_span
        + BigUint::from(32_u8) * maximum_centered_span;
    assert!(candidate_field_modulus > conservative_limb_expression_bound * BigUint::from(2_u8));

    let selected_flooding_bound =
        selected_target_decryption_flooding_bound().expect("selected flooding bound derives");
    assert_eq!(selected_flooding_bound.bits(), 146);
    assert!(candidate_field_modulus > selected_flooding_bound * BigUint::from(32_u8));

    assert!(
        RING_NATIVE_CANDIDATE_FAMILIES
            .iter()
            .all(|family| { !family.required_capabilities.is_empty() })
    );
}

#[test]
fn candidate_field_repairs_the_asymptotic_qrom_headroom_failure() {
    // BGTZ23 Corollary 1.6 gives O(t^2 * epsilon + t^3 / 2^lambda).
    // Reserve t = 2^81 for the declared 2^80 - 1 adversarial queries plus
    // verifier overhead, and union all 60 outer packets. This test checks only
    // the exact parameter capacity around that asymptotic result. Selection
    // still requires a concrete transform with explicit constants and the
    // compiler-derived algebraic soundness numerator for every PCS segment.
    let total_query_parameter =
        BigUint::from(1_u8) << CANDIDATE_TOTAL_QROM_QUERY_PARAMETER_BIT_LENGTH;
    let target_inverse_probability =
        BigUint::from(1_u8) << MOBILE_PROTOTYPE_INVALID_ACCEPTANCE_BIT_LENGTH;
    let outer_packet_count = BigUint::from(CANDIDATE_OUTER_PACKET_SCHEDULE_COUNT);
    let field_term_denominator = &outer_packet_count
        * &total_query_parameter
        * &total_query_parameter
        * &target_inverse_probability;

    let retired_field_numerator_capacity =
        retired_example_field_modulus() / &field_term_denominator;
    let candidate_field_numerator_capacity =
        direct_rns_candidate_field_modulus() / &field_term_denominator;

    // The 255-bit example field cannot even absorb the ring-size factor in the
    // HLS row-check error O(degree * N / p) at the active query budget.
    assert_eq!(retired_field_numerator_capacity, BigUint::from(68_u8));
    assert!(retired_field_numerator_capacity < BigUint::from(POLYNOMIAL_DEGREE));

    // The 440-bit field leaves 192 bits for the exact product of degree,
    // segment multiplicity, and explicit transform constants. This is
    // headroom, not a substitute for deriving those quantities.
    assert_eq!(candidate_field_numerator_capacity.bits(), 192);
    assert_eq!(
        candidate_field_numerator_capacity,
        BigUint::parse_bytes(
            b"3347800959056978902887273872196104785627078630777090119890",
            10,
        )
        .expect("candidate field numerator capacity parses")
    );

    let oracle_term_constant_capacity = (BigUint::from(1_u8)
        << CANDIDATE_TRANSCRIPT_ORACLE_OUTPUT_BIT_LENGTH)
        / (outer_packet_count * total_query_parameter.pow(3) * target_inverse_probability);
    assert_eq!(oracle_term_constant_capacity.bits(), 184);
}
