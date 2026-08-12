//! Static correspondence for the compact ring-vector common-proof candidate.
//!
//! This module is test-only evidence. It does not select a proof backend or
//! authorize any proof bytes. Its purpose is to keep the candidate relation
//! inventory, dependency barriers, radix arithmetic envelope, conditional
//! QROM capacity, and bounded hash-PCS stripe geometry derived from the same
//! production constants as the incumbent proof inventory.

#[cfg(test)]
use num_bigint::BigUint;
#[cfg(test)]
use num_traits::Signed;

use crate::{
    bgv::{
        evaluator::candidate_evidence::EvaluatorCandidateInput,
        parameters::{DATA_PRIMES, POLYNOMIAL_DEGREE},
        setup::{SETUP_COMMITMENT_MODULE_RANK, SETUP_COMMITMENT_MODULUS_LIMB_INDICES},
    },
    foundation::selected_sharing_data_prime_coordinates,
};
#[cfg(test)]
use crate::{
    bgv::{
        evaluator::noise_recurrence::{
            DirectBallotTargetReleaseNoiseInput, direct_ballot_target_noise_bounds,
            direct_ballot_target_noise_bounds_for_key_switch_topology,
            direct_ballot_target_release_noise_trace_for_key_switch_topology,
        },
        key_switch_topology::KeySwitchDecompositionTopology,
        key_switch_topology::canonical_residue_byte_length,
        parameters::{RootParameters, SPECIAL_PRIMES},
        target_decryption::kllps_release::{
            KLLPS_DENOMINATOR_CLEARING_FACTOR, KLLPS_RECONSTRUCTION_THRESHOLD,
            MAXIMUM_AUTHORIZED_COEFFICIENT_NORM, factor_four_required_flooding_bound,
        },
    },
    foundation::{
        FOUNDATION_PROFILE, ProofApplicationSlotCeilings,
        SELECTED_MAXIMUM_CANDIDATE_PACKAGES_PER_ACTION,
    },
};

#[cfg(test)]
use super::relation_plan::MODULAR_QUOTIENT_BIT_COUNT;
#[cfg(test)]
use super::relation_plan::{MODULAR_QUOTIENT_MAXIMUM, MODULAR_QUOTIENT_MINIMUM};
use super::relation_plan::{MODULAR_QUOTIENT_VALUE_COUNT, TRUSTEE_QUOTIENT_MAXIMUM_ABSOLUTE_VALUE};
#[cfg(test)]
use super::selected_target_decryption_flooding_bound;

#[cfg(test)]
const GOLDILOCKS_BASE_FIELD_MODULUS: u64 = 0xffff_ffff_0000_0001;
const CANDIDATE_LOOKUP_EXTENSION_DEGREE: u32 = 5;
#[cfg(test)]
const CANDIDATE_BASE_FIELD_RBR_REPETITION_COUNT: u32 = 8;
#[cfg(test)]
const CANDIDATE_RADIX_DIGIT_BIT_LENGTH: u32 = 16;
const CANDIDATE_RANDOMIZED_CODE_MESSAGE_LENGTH: u64 = 65_536;
const CANDIDATE_INVERSE_RATE: u64 = 4;
const CANDIDATE_THEOREM_MAIN_CODE_INVERSE_RATE: u64 = 2;
#[cfg(test)]
const CANDIDATE_LOW_MEMORY_LOGICAL_COLUMN_STRIPE_WIDTH: u64 = 64;
#[cfg(test)]
const CANDIDATE_LOGICAL_COLUMN_STRIPE_WIDTH: u64 = 128;
const CANDIDATE_TRANSFORM_BATCH_WIDTH: u64 = 32;
const CANDIDATE_QUINTIC_EXTENSION_TRANSFORM_BATCH_WIDTH: u64 = 8;
const PREFERRED_POST_VSS_RING_VECTOR_PACKING_FACTOR: u64 = 8;
const CANDIDATE_MERKLE_DIGEST_BYTE_LENGTH: u64 = 64;
const CANDIDATE_SHAKE256_STATE_BYTE_LENGTH: u64 = 25 * 8;
const CANDIDATE_NON_MATRIX_WORKSPACE_BYTE_LENGTH: u64 = 192 * 1024 * 1024;
#[cfg(test)]
const NOMINAL_WASM_LINEAR_MEMORY_BYTE_LENGTH: u64 = 402_653_184;
#[cfg(test)]
const AUTOMATIC_WASM_LINEAR_MEMORY_BYTE_LENGTH: u64 = 603_979_776;
#[cfg(test)]
const HARD_WASM_LINEAR_MEMORY_BYTE_LENGTH: u64 = 671_088_640;
#[cfg(test)]
const AUTOMATIC_PROOF_BYTE_LENGTH: u64 = 7_864_320;
#[cfg(test)]
const ABSOLUTE_PROOF_PARSER_BYTE_LENGTH: u64 = 268_435_456;
#[cfg(test)]
const CANDIDATE_ADVERSARIAL_QUERY_BUDGET_BIT_LENGTH: u32 = 80;
#[cfg(test)]
const CANDIDATE_INTERACTIVE_ROUND_COUNT_CEILING: u64 = 64;
#[cfg(test)]
const CDHZ_STATE_RESTORATION_CONSTANT: u64 = 80;
#[cfg(test)]
const CDHZ_BCS_STATE_RESTORATION_MULTIPLIER: u64 = 4;
#[cfg(test)]
const MOBILE_PROTOTYPE_INVALID_ACCEPTANCE_BIT_LENGTH: u32 = 80;
#[cfg(test)]
const CANDIDATE_OUTER_PACKET_SCHEDULE_COUNT: u32 = 60;
const CANDIDATE_LOOKUP_QUERY_COUNT: u64 = 393;
const CFW_R1CS_INNER_MASK_MESSAGE_LENGTH: u64 = 4;
const CFW_R1CS_OUTER_MASK_MESSAGE_LENGTH: u64 = 8;
const CFW_MASK_CODE_INVERSE_RATE: u64 = 4;
const CANDIDATE_MAXIMUM_LOGICAL_COLUMNS_PER_POWER_OF_TWO_STRIPE: u64 = 128;
const PREFERRED_CANDIDATE_KEY_SWITCH_BLOCK_WIDTH: usize = 10;
const PREFERRED_CANDIDATE_SPECIAL_LIMB_COUNT: usize = 6;
pub(super) const PREFERRED_CANDIDATE_SPECIAL_MODULI: [u64; 6] = [
    2_251_798_701_539_329,
    2_251_798_448_898_049,
    2_251_798_432_055_297,
    2_251_797_893_087_233,
    2_251_797_842_558_977,
    2_251_797_286_748_161,
];
#[cfg(test)]
const SELECTED_VSS_COMPLETE_BUTTERFLY_COUNT: u64 = 365_944_635_392;
#[cfg(test)]
const SELECTED_VSS_COMPLETE_SALTED_LEAF_HASH_COUNT: u64 = 2_382_364_672;

#[cfg(test)]
const PREFERRED_CANDIDATE_SPECIAL_ROOT_PARAMETERS: [RootParameters; 6] = [
    RootParameters {
        modulus: PREFERRED_CANDIDATE_SPECIAL_MODULI[0],
        primitive_generator: 7,
        negacyclic_root: 562_557_076_070_937,
        cyclic_root: 1_754_608_259_064_067,
        inverse_negacyclic_root: 131_662_764_262_369,
        inverse_cyclic_root: 2_191_331_489_653_236,
        inverse_polynomial_degree: 2_251_729_982_096_533,
    },
    RootParameters {
        modulus: PREFERRED_CANDIDATE_SPECIAL_MODULI[1],
        primitive_generator: 11,
        negacyclic_root: 1_110_712_104_471_340,
        cyclic_root: 1_800_058_931_807_704,
        inverse_negacyclic_root: 1_956_954_478_823_839,
        inverse_cyclic_root: 1_287_981_358_550_208,
        inverse_polynomial_degree: 2_251_729_729_462_963,
    },
    RootParameters {
        modulus: PREFERRED_CANDIDATE_SPECIAL_MODULI[2],
        primitive_generator: 3,
        negacyclic_root: 1_114_074_411_895_913,
        cyclic_root: 2_092_012_855_630_247,
        inverse_negacyclic_root: 1_885_214_485_032_793,
        inverse_cyclic_root: 1_235_939_603_748_920,
        inverse_polynomial_degree: 2_251_729_712_620_725,
    },
    RootParameters {
        modulus: PREFERRED_CANDIDATE_SPECIAL_MODULI[3],
        primitive_generator: 5,
        negacyclic_root: 1_745_645_221_913_553,
        cyclic_root: 445_434_756_848_208,
        inverse_negacyclic_root: 2_070_726_251_246_923,
        inverse_cyclic_root: 10_534_731_474_792,
        inverse_polynomial_degree: 2_251_729_173_669_109,
    },
    RootParameters {
        modulus: PREFERRED_CANDIDATE_SPECIAL_MODULI[4],
        primitive_generator: 5,
        negacyclic_root: 739_278_346_482_331,
        cyclic_root: 636_405_116_676_223,
        inverse_negacyclic_root: 748_254_782_643_005,
        inverse_cyclic_root: 2_093_871_902_026_835,
        inverse_polynomial_degree: 2_251_729_123_142_395,
    },
    RootParameters {
        modulus: PREFERRED_CANDIDATE_SPECIAL_MODULI[5],
        primitive_generator: 14,
        negacyclic_root: 549_071_366_575_609,
        cyclic_root: 764_654_676_160_024,
        inverse_negacyclic_root: 1_206_553_578_274_134,
        inverse_cyclic_root: 381_491_349_637_754,
        inverse_polynomial_degree: 2_251_728_567_348_541,
    },
];

#[cfg(test)]
const PREFERRED_CANDIDATE_SPECIAL_GROUP_PRIME_FACTORS: [&[u64]; 6] = [
    &[2, 3, 71, 257, 34_871],
    &[2, 3, 257, 44_565_133],
    &[2, 257, 941, 71_039],
    &[2, 3, 7, 23, 257, 138_401],
    &[2, 3, 257, 44_565_121],
    &[2, 3, 5, 257, 4_456_511],
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CompactPublicKeyWorkInventory {
    ternary_vector_count: u64,
    eta_two_vector_count: u64,
    signed_modular_quotient_count: u64,
    quotient_lookup_table_value_count: u64,
    small_set_multiplication_helper_logical_column_count: u64,
    inverse_helper_logical_column_count: u64,
}

fn compact_public_key_work_inventory() -> CompactPublicKeyWorkInventory {
    let relation_input = super::selected_public_key_share_relation_plan_input()
        .expect("selected public-key-share relation input derives");
    let data_limb_count =
        u64::try_from(relation_input.data_modulus_indices.len()).expect("data-limb count fits u64");
    let anchor_count = u64::try_from(relation_input.commitment_data_modulus_indices.len())
        .expect("anchor count fits u64");
    let commitment_rank = u64::from(relation_input.commitment_module_rank);
    let anchor_row_count = anchor_count
        .checked_mul(commitment_rank + 1)
        .expect("anchor-row count fits u64");
    let ternary_vector_count = 1_u64
        .checked_add(
            anchor_count
                .checked_mul(2 * commitment_rank + 1)
                .expect("anchor small-vector count fits u64"),
        )
        .expect("ternary-vector count fits u64");
    let eta_two_vector_count = 1_u64;
    let signed_modular_quotient_count = data_limb_count
        .checked_add(anchor_row_count)
        .expect("public-key quotient count fits u64");
    CompactPublicKeyWorkInventory {
        ternary_vector_count,
        eta_two_vector_count,
        signed_modular_quotient_count,
        quotient_lookup_table_value_count: MODULAR_QUOTIENT_VALUE_COUNT,
        small_set_multiplication_helper_logical_column_count: ternary_vector_count
            .checked_add(3 * eta_two_vector_count)
            .expect("public-key small-set helper width fits u64"),
        inverse_helper_logical_column_count: signed_modular_quotient_count,
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CompactPublicKeyPacketInventory {
    relation_plan_hash: [u8; 64],
    ring_degree: u64,
    data_limb_count: u64,
    anchor_count: u64,
    anchor_row_count: u64,
    ternary_vector_count: u64,
    eta_two_vector_count: u64,
    signed_modular_quotient_count: u64,
    quotient_interval_minimum: i64,
    quotient_interval_maximum: i64,
    quotient_lookup_table_value_count: u64,
    quotient_lookup_table_column_count: u64,
    structured_public_ring_product_count: u64,
    coefficient_local_exact_equation_count: u64,
    lookup_inverse_multiplication_constraint_count: u64,
    small_set_multiplication_constraint_count: u64,
    known_multiplication_constraint_count: u64,
    public_key_quotient_interval_minimum: i64,
    public_key_quotient_interval_maximum: i64,
    first_anchor_quotient_interval_minimum: i64,
    first_anchor_quotient_interval_maximum: i64,
    final_anchor_quotient_interval_minimum: i64,
    final_anchor_quotient_interval_maximum: i64,
    maximum_direct_integer_lift_residual_interval_width: u64,
    pre_challenge_source_logical_column_count: u64,
    small_set_multiplication_helper_logical_column_count: u64,
    inverse_helper_logical_column_count: u64,
    r1cs_witness_logical_column_count: u64,
}

#[cfg(test)]
fn compact_public_key_packet_inventory() -> CompactPublicKeyPacketInventory {
    let compact_relation_catalog: super::relation_plan::CompactPublicKeyRelationCatalog =
        super::relation_plan::selected_compact_public_key_relation_catalog()
            .expect("selected compact public-key relation catalog derives and checks");
    let relation_input = super::selected_public_key_share_relation_plan_input()
        .expect("selected public-key-share relation input derives");

    let ring_degree = relation_input.ring_degree;
    assert_eq!(ring_degree, u64::try_from(POLYNOMIAL_DEGREE).unwrap());
    let data_limb_count =
        u64::try_from(relation_input.data_modulus_indices.len()).expect("data-limb count fits u64");
    let anchor_count = u64::try_from(relation_input.commitment_data_modulus_indices.len())
        .expect("anchor count fits u64");
    let commitment_rank = u64::from(relation_input.commitment_module_rank);
    let anchor_row_count = anchor_count
        .checked_mul(commitment_rank + 1)
        .expect("anchor-row count fits u64");

    // The compact compiler represents each full N-coefficient source exactly
    // once rather than preserving the incumbent trace's two half-columns.
    // There is one common ternary secret. Every prime-local anchor contributes
    // rank + 1 ternary hiding secrets and rank ternary hiding errors. The one
    // public-key error uses the exact eta-two set {-2,-1,0,1,2}.
    let ternary_vector_count = 1_u64
        .checked_add(
            anchor_count
                .checked_mul(2 * commitment_rank + 1)
                .expect("anchor small-vector count fits u64"),
        )
        .expect("ternary-vector count fits u64");
    let eta_two_vector_count = 1_u64;
    assert_eq!(
        ternary_vector_count,
        compact_relation_catalog.shifted_ternary_vector_count()
    );

    // One signed quotient vector combines the incumbent low/high trace halves.
    // There is one quotient per public-key RNS limb and one per anchor row.
    let signed_modular_quotient_count = data_limb_count
        .checked_add(anchor_row_count)
        .expect("public-key quotient count fits u64");
    assert_eq!(
        signed_modular_quotient_count,
        compact_relation_catalog.quotient_vector_count()
    );
    let quotient_interval_minimum = MODULAR_QUOTIENT_MINIMUM;
    let quotient_interval_maximum = MODULAR_QUOTIENT_MAXIMUM;
    let quotient_lookup_table_value_count = MODULAR_QUOTIENT_VALUE_COUNT;
    assert_eq!(
        quotient_lookup_table_value_count,
        compact_relation_catalog.quotient_lookup_table_value_count()
    );
    let quotient_lookup_table_column_count =
        quotient_lookup_table_value_count.div_ceil(ring_degree);

    // Each public RNS limb owns one public-by-private ring product. For every
    // anchor, each of the rank ordinary rows owns rank + 1 products and the
    // final row owns rank products. These are structured public linear maps,
    // not witness NTT images or multiplication gates.
    let structured_public_ring_product_count = data_limb_count
        .checked_add(
            anchor_count
                .checked_mul(commitment_rank * (commitment_rank + 2))
                .expect("anchor product count fits u64"),
        )
        .expect("public-key product count fits u64");
    assert_eq!(
        structured_public_ring_product_count,
        compact_relation_catalog.structured_public_ring_product_count()
    );
    let coefficient_local_exact_equation_count = signed_modular_quotient_count
        .checked_mul(ring_degree)
        .expect("public-key exact-equation count fits u64");

    // The R1CS field is the quintic Goldilocks extension. One reciprocal is
    // therefore one field variable and `(beta + quotient) * inverse = 1` is
    // one multiplication constraint. The five base-field coordinates belong
    // only to canonical encoding, transforms, memory, and transport. Counting
    // them as five algebraic variables would change the R1CS theorem and then
    // charge the physical representation a second time.
    let lookup_inverse_multiplication_constraint_count = coefficient_local_exact_equation_count;
    let small_set_multiplication_constraint_count = ternary_vector_count
        .checked_mul(2)
        .and_then(|count| count.checked_add(eta_two_vector_count * 4))
        .and_then(|count| count.checked_mul(ring_degree))
        .expect("public-key small-set multiplication count fits u64");
    let known_multiplication_constraint_count = lookup_inverse_multiplication_constraint_count
        .checked_add(small_set_multiplication_constraint_count)
        .expect("public-key multiplication count fits u64");

    fn quotient_interval(
        numerator_minimum: i128,
        numerator_maximum: i128,
        modulus: u64,
    ) -> (i64, i64) {
        let modulus = i128::from(modulus);
        let minimum = -((-numerator_minimum).div_euclid(modulus));
        let maximum = numerator_maximum.div_euclid(modulus);
        (
            i64::try_from(minimum).expect("quotient minimum fits i64"),
            i64::try_from(maximum).expect("quotient maximum fits i64"),
        )
    }

    fn residual_interval_width(
        numerator_minimum: i128,
        numerator_maximum: i128,
        modulus: u64,
    ) -> u64 {
        let modulus = i128::from(modulus);
        let residual_minimum = numerator_minimum - modulus * i128::from(MODULAR_QUOTIENT_MAXIMUM);
        let residual_maximum = numerator_maximum - modulus * i128::from(MODULAR_QUOTIENT_MINIMUM);
        u64::try_from(residual_maximum - residual_minimum)
            .expect("direct integer-lift residual width fits u64")
    }

    let maximum_public_key_modulus = relation_input
        .data_modulus_indices
        .iter()
        .map(|index| DATA_PRIMES[usize::from(*index)])
        .max()
        .expect("public-key relation has data limbs");
    let maximum_anchor_modulus = relation_input
        .commitment_data_modulus_indices
        .iter()
        .map(|index| DATA_PRIMES[usize::from(*index)])
        .max()
        .expect("public-key relation has anchors");
    let ring_degree_integer = i128::from(ring_degree);
    let plaintext_modulus = i128::from(relation_input.plaintext_modulus);
    let public_key_modulus_integer = i128::from(maximum_public_key_modulus);
    let public_key_product_bound = ring_degree_integer * (public_key_modulus_integer - 1);
    let public_key_numerator_minimum = public_key_product_bound
        .checked_neg()
        .and_then(|value| value.checked_sub(2 * plaintext_modulus))
        .expect("public-key numerator minimum fits i128");
    let public_key_numerator_maximum = (ring_degree_integer + 1)
        .checked_mul(public_key_modulus_integer - 1)
        .and_then(|value| value.checked_add(2 * plaintext_modulus))
        .expect("public-key numerator maximum fits i128");
    let (public_key_quotient_interval_minimum, public_key_quotient_interval_maximum) =
        quotient_interval(
            public_key_numerator_minimum,
            public_key_numerator_maximum,
            maximum_public_key_modulus,
        );

    let anchor_modulus_integer = i128::from(maximum_anchor_modulus);
    let anchor_product_bound = ring_degree_integer * (anchor_modulus_integer - 1);
    let first_anchor_product_count = i128::from(commitment_rank + 1);
    let first_anchor_numerator_minimum = -(first_anchor_product_count * anchor_product_bound) - 1;
    let first_anchor_numerator_maximum =
        (anchor_modulus_integer - 1) + first_anchor_product_count * anchor_product_bound + 1;
    let (first_anchor_quotient_interval_minimum, first_anchor_quotient_interval_maximum) =
        quotient_interval(
            first_anchor_numerator_minimum,
            first_anchor_numerator_maximum,
            maximum_anchor_modulus,
        );
    let final_anchor_numerator_minimum = -anchor_product_bound - 2;
    let final_anchor_numerator_maximum = (anchor_modulus_integer - 1) + anchor_product_bound + 2;
    let (final_anchor_quotient_interval_minimum, final_anchor_quotient_interval_maximum) =
        quotient_interval(
            final_anchor_numerator_minimum,
            final_anchor_numerator_maximum,
            maximum_anchor_modulus,
        );
    let maximum_direct_integer_lift_residual_interval_width = [
        residual_interval_width(
            public_key_numerator_minimum,
            public_key_numerator_maximum,
            maximum_public_key_modulus,
        ),
        residual_interval_width(
            first_anchor_numerator_minimum,
            first_anchor_numerator_maximum,
            maximum_anchor_modulus,
        ),
        residual_interval_width(
            final_anchor_numerator_minimum,
            final_anchor_numerator_maximum,
            maximum_anchor_modulus,
        ),
    ]
    .into_iter()
    .max()
    .expect("public-key residual intervals exist");

    // Quotients, public-table multiplicities, small sources, and their
    // deterministic multiplication-chain helpers are all independent of the
    // lookup challenge. A ternary check x(x-1)(x-2)=0 needs one retained R1CS
    // intermediate; an eta-two quintic needs three. Challenge-dependent
    // inverse helpers use one extension-field element per quotient. Its five
    // Goldilocks coordinates are accounted only by the physical ledgers.
    let pre_challenge_source_logical_column_count = signed_modular_quotient_count
        .checked_add(quotient_lookup_table_column_count)
        .and_then(|count| count.checked_add(ternary_vector_count + eta_two_vector_count))
        .expect("public-key pre-challenge source width fits u64");
    let small_set_multiplication_helper_logical_column_count = ternary_vector_count
        .checked_add(3 * eta_two_vector_count)
        .expect("public-key small-set helper width fits u64");
    let inverse_helper_logical_column_count = signed_modular_quotient_count;
    let r1cs_witness_logical_column_count = pre_challenge_source_logical_column_count
        .checked_add(small_set_multiplication_helper_logical_column_count)
        .and_then(|count| count.checked_add(inverse_helper_logical_column_count))
        .expect("public-key R1CS witness width fits u64");
    assert_eq!(
        r1cs_witness_logical_column_count,
        compact_relation_catalog.witness_ring_vector_count()
    );

    CompactPublicKeyPacketInventory {
        relation_plan_hash: compact_relation_catalog.relation_plan_hash(),
        ring_degree,
        data_limb_count,
        anchor_count,
        anchor_row_count,
        ternary_vector_count,
        eta_two_vector_count,
        signed_modular_quotient_count,
        quotient_interval_minimum,
        quotient_interval_maximum,
        quotient_lookup_table_value_count,
        quotient_lookup_table_column_count,
        structured_public_ring_product_count,
        coefficient_local_exact_equation_count,
        lookup_inverse_multiplication_constraint_count,
        small_set_multiplication_constraint_count,
        known_multiplication_constraint_count,
        public_key_quotient_interval_minimum,
        public_key_quotient_interval_maximum,
        first_anchor_quotient_interval_minimum,
        first_anchor_quotient_interval_maximum,
        final_anchor_quotient_interval_minimum,
        final_anchor_quotient_interval_maximum,
        maximum_direct_integer_lift_residual_interval_width,
        pre_challenge_source_logical_column_count,
        small_set_multiplication_helper_logical_column_count,
        inverse_helper_logical_column_count,
        r1cs_witness_logical_column_count,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CompactPostVssPacketInventory {
    aggregate_threshold_quotient_vector_count: u64,
    shared_anchor_quotient_vector_count: u64,
    public_key_quotient_vector_count: u64,
    relinearization_round_one_quotient_vector_count: u64,
    galois_quotient_vector_count: u64,
    quotient_vector_count: u64,
}

#[cfg(test)]
fn compact_post_vss_packet_inventory() -> CompactPostVssPacketInventory {
    let sharing_limb_count = u64::try_from(
        selected_sharing_data_prime_coordinates()
            .expect("selected sharing coordinates derive")
            .len(),
    )
    .expect("sharing-limb count fits u64");
    let aggregate_threshold_quotient_vector_count = sharing_limb_count * 2;

    // The same-secret, public-key, relinearization, and Galois relations bind
    // the same commitment openings. A packet compiler proves those openings
    // once; retaining one copy is required, while retaining four copies would
    // be a compiler artifact rather than a distinct cryptographic relation.
    let shared_anchor_quotient_vector_count = u64::try_from(
        SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len() * (SETUP_COMMITMENT_MODULE_RANK + 1),
    )
    .expect("shared-anchor quotient count fits u64");
    let public_key_quotient_vector_count =
        u64::try_from(DATA_PRIMES.len()).expect("data-limb count fits u64");

    let evaluator_candidate =
        EvaluatorCandidateInput::implemented().expect("selected evaluator candidate derives");
    let [relinearization_catalog_level] = evaluator_candidate.relinearization_levels.as_slice()
    else {
        panic!("the selected evaluator owns exactly one relinearization level");
    };
    let relinearization_topology =
        KeySwitchDecompositionTopology::for_level(*relinearization_catalog_level)
            .expect("selected relinearization topology derives");
    let relinearization_row_count = relinearization_topology
        .data_block_count()
        .checked_mul(relinearization_topology.extended_limb_count())
        .expect("relinearization row count fits usize");
    let relinearization_round_one_quotient_vector_count =
        u64::try_from(relinearization_row_count * 2)
            .expect("round-one quotient-vector count fits u64");

    let galois_quotient_vector_count = evaluator_candidate
        .galois_key_schedule
        .iter()
        .map(|(_, catalog_level)| {
            let topology = KeySwitchDecompositionTopology::for_level(*catalog_level)
                .expect("selected Galois topology derives");
            u64::try_from(
                topology
                    .data_block_count()
                    .checked_mul(topology.extended_limb_count())
                    .expect("Galois row count fits usize"),
            )
            .expect("Galois quotient-vector count fits u64")
        })
        .sum::<u64>();

    let quotient_vector_count = aggregate_threshold_quotient_vector_count
        + shared_anchor_quotient_vector_count
        + public_key_quotient_vector_count
        + relinearization_round_one_quotient_vector_count
        + galois_quotient_vector_count;

    CompactPostVssPacketInventory {
        aggregate_threshold_quotient_vector_count,
        shared_anchor_quotient_vector_count,
        public_key_quotient_vector_count,
        relinearization_round_one_quotient_vector_count,
        galois_quotient_vector_count,
        quotient_vector_count,
    }
}

fn preferred_compact_post_vss_packet_inventory() -> CompactPostVssPacketInventory {
    let sharing_limb_count = u64::try_from(
        selected_sharing_data_prime_coordinates()
            .expect("selected sharing coordinates derive")
            .len(),
    )
    .expect("sharing-limb count fits u64");
    let aggregate_threshold_quotient_vector_count = sharing_limb_count * 2;
    let shared_anchor_quotient_vector_count = u64::try_from(
        SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len() * (SETUP_COMMITMENT_MODULE_RANK + 1),
    )
    .expect("shared-anchor quotient count fits u64");
    let public_key_quotient_vector_count =
        u64::try_from(DATA_PRIMES.len()).expect("data-limb count fits u64");

    let evaluator_candidate =
        EvaluatorCandidateInput::implemented().expect("selected evaluator candidate derives");
    let [relinearization_catalog_level] = evaluator_candidate.relinearization_levels.as_slice()
    else {
        panic!("the selected evaluator owns exactly one relinearization level");
    };
    let quotient_vector_count_for_level = |catalog_level: usize| {
        let active_data_limb_count = catalog_level
            .checked_add(1)
            .expect("active data-limb count fits usize");
        let data_block_count =
            active_data_limb_count.div_ceil(PREFERRED_CANDIDATE_KEY_SWITCH_BLOCK_WIDTH);
        let extended_limb_count = active_data_limb_count
            .checked_add(PREFERRED_CANDIDATE_SPECIAL_LIMB_COUNT)
            .expect("extended limb count fits usize");
        u64::try_from(
            data_block_count
                .checked_mul(extended_limb_count)
                .expect("candidate key-switch quotient count fits usize"),
        )
        .expect("candidate key-switch quotient count fits u64")
    };
    let relinearization_round_one_quotient_vector_count =
        quotient_vector_count_for_level(*relinearization_catalog_level) * 2;
    let galois_quotient_vector_count = evaluator_candidate
        .galois_key_schedule
        .iter()
        .map(|(_, catalog_level)| quotient_vector_count_for_level(*catalog_level))
        .sum::<u64>();
    let quotient_vector_count = aggregate_threshold_quotient_vector_count
        + shared_anchor_quotient_vector_count
        + public_key_quotient_vector_count
        + relinearization_round_one_quotient_vector_count
        + galois_quotient_vector_count;

    CompactPostVssPacketInventory {
        aggregate_threshold_quotient_vector_count,
        shared_anchor_quotient_vector_count,
        public_key_quotient_vector_count,
        relinearization_round_one_quotient_vector_count,
        galois_quotient_vector_count,
        quotient_vector_count,
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompactLookupTranscriptOperation {
    CommitQuotientsAndMultiplicities,
    SampleExtensionChallenge,
    CommitCompleteR1csEncoding,
    SampleCrossEpochColumnWeights,
    SampleCrossEpochMultilinearPoint,
    ReduceCrossEpochEqualityToExplicitPointOpenings,
    EnterJointCfwWhirReduction,
    DeriveSharedPcsQueriesAfterEveryPredecessor,
}

#[cfg(test)]
const COMPACT_LOOKUP_TRANSCRIPT_CHRONOLOGY: [CompactLookupTranscriptOperation; 8] = [
    CompactLookupTranscriptOperation::CommitQuotientsAndMultiplicities,
    CompactLookupTranscriptOperation::SampleExtensionChallenge,
    CompactLookupTranscriptOperation::CommitCompleteR1csEncoding,
    CompactLookupTranscriptOperation::SampleCrossEpochColumnWeights,
    CompactLookupTranscriptOperation::SampleCrossEpochMultilinearPoint,
    CompactLookupTranscriptOperation::ReduceCrossEpochEqualityToExplicitPointOpenings,
    CompactLookupTranscriptOperation::EnterJointCfwWhirReduction,
    CompactLookupTranscriptOperation::DeriveSharedPcsQueriesAfterEveryPredecessor,
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CompactLookupWorkLedger {
    pub(super) quotient_entry_count: u64,
    pub(super) lookup_table_value_count: u64,
    pub(super) padded_lookup_table_entry_count: u64,
    pub(super) complete_inverse_element_count: u64,
    pub(super) lookup_soundness_numerator: u64,
    pub(super) pre_challenge_logical_column_count: u64,
    pub(super) inverse_helper_logical_column_count: u64,
    pub(super) logical_column_count: u64,
    pub(super) ordered_physical_stripe_widths: Vec<u64>,
    pub(super) randomized_code_message_length: u64,
    pub(super) randomized_code_randomness_length_per_logical_column: u64,
    pub(super) encoded_row_count: u64,
    pub(super) physical_column_count: u64,
    pub(super) private_random_field_element_count: u64,
    pub(super) incremental_commitment_peak_live_byte_length: u64,
    pub(super) monolithic_peak_live_byte_length: u64,
    pub(super) peak_live_byte_length: u64,
    pub(super) one_pass_encoded_field_element_count: u64,
    pub(super) complete_two_pass_encoded_field_element_count: u64,
    pub(super) complete_two_pass_butterfly_count: u64,
    pub(super) complete_two_pass_salted_leaf_hash_count: u64,
    pub(super) opened_row_byte_length: u64,
    pub(super) naive_authentication_path_byte_length: u64,
}

/// Necessary CFW R1CS-mask work implied by the compact lookup core alone.
///
/// This is deliberately a lower bound, not a complete proof ledger. The
/// production relation compiler can add witness elements, and the CFW
/// constrained-code IOPP adds further code-switch masks according to its exact
/// WHIR stage parameters. Keeping this lower bound separate prevents the
/// direct-opening randomizers from being misreported as complete nonlinear
/// zero knowledge.
#[derive(Clone, Debug, PartialEq, Eq)]
struct CfwR1csMaskLowerBoundLedger {
    relation_base_field_element_count: u64,
    padded_r1cs_witness_element_count: u64,
    padded_public_input_element_count: u64,
    padded_r1cs_constraint_count: u64,
    r1cs_variable_count: u32,
    rbr_repetition_count: u32,
    inner_mask_oracle_count: u64,
    outer_mask_oracle_count: u64,
    randomized_encoding_count_including_main: u64,
    mask_code_encoded_row_count: u64,
    mask_physical_column_count: u64,
    mask_commitment_root_count: u64,
    mask_one_pass_encoded_field_element_count: u64,
    mask_opened_row_byte_length: u64,
    mask_naive_authentication_path_byte_length: u64,
    sumcheck_non_oracle_message_byte_length: u64,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CfwFieldStrategyStaticLedger {
    field_extension_degree: u32,
    rbr_repetition_count: u32,
    transform_batch_logical_column_count: u64,
    incremental_commitment_peak_live_byte_length: u64,
    conservative_peak_live_byte_length: u64,
    main_complete_two_pass_base_coordinate_butterfly_count: u64,
    mask_one_pass_base_coordinate_element_count: u64,
    known_component_naive_path_subtotal_byte_length: u64,
}

/// Static geometry for the theorem-shaped two-epoch lookup construction.
///
/// CFW Theorem 11.3 encodes one `ell`-element R1CS witness, where `ell` is a
/// power of two and equals the padded public-input length. CFW permits any
/// power-of-two interleaving split of that message. One base-code message can
/// therefore concatenate several consecutive degree-`N` ring vectors; the
/// interleaving width is then `ell / (N * packing_factor)`. This differs from
/// the direct-opening stripe subtotal, which is useful for primitive
/// sensitivities but is not the theorem's main code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct CfwTwoEpochPacketStaticLedger {
    padded_r1cs_witness_element_count: u64,
    pub(super) field_extension_degree: u32,
    pub(super) ring_vector_packing_factor: u64,
    pub(super) transform_batch_logical_component_count: u64,
    pub(super) main_interleaved_component_count: u64,
    pub(super) relation_message_element_count_per_component: u64,
    pub(super) populated_message_element_count_per_component: u64,
    pub(super) encoded_row_count: u64,
    minimum_distance_coordinate_count: u64,
    unique_decoding_radius_coordinate_count: u64,
    pre_challenge_logical_component_count: u64,
    pre_challenge_physical_component_count: u64,
    pre_challenge_commitment_root_count: u64,
    cross_epoch_column_weight_count: u64,
    cross_epoch_multilinear_point_coordinate_count: u32,
    cross_epoch_binding_error_numerator: u64,
    cross_epoch_explicit_point_opening_count: u64,
    pub(super) incremental_commitment_peak_live_byte_length: u64,
    pub(super) conservative_peak_live_byte_length: u64,
    pub(super) main_complete_two_pass_base_coordinate_butterfly_count: u64,
    pre_challenge_complete_two_pass_base_field_butterfly_count: u64,
    pub(super) complete_two_pass_base_coordinate_butterfly_count: u64,
    pub(super) main_oracle_query_answer_byte_length: u64,
    pub(super) known_component_naive_path_subtotal_byte_length: u64,
}

fn power_of_two_stripe_widths(logical_column_count: u64) -> Vec<u64> {
    let mut remaining_logical_column_count = logical_column_count;
    let mut widths = Vec::new();
    while remaining_logical_column_count != 0 {
        let stripe_logical_column_count = remaining_logical_column_count
            .min(CANDIDATE_MAXIMUM_LOGICAL_COLUMNS_PER_POWER_OF_TWO_STRIPE);
        let physical_width = stripe_logical_column_count
            .checked_next_power_of_two()
            .expect("candidate physical stripe width derives");
        widths.push(physical_width);
        remaining_logical_column_count -= stripe_logical_column_count;
    }
    widths
}

#[cfg(test)]
pub(super) fn compact_lookup_work_ledger() -> CompactLookupWorkLedger {
    let quotient_vector_count = compact_post_vss_packet_inventory().quotient_vector_count;
    compact_lookup_work_ledger_for_quotient_inventory(
        quotient_vector_count,
        TRUSTEE_QUOTIENT_MAXIMUM_ABSOLUTE_VALUE
            .checked_mul(2)
            .and_then(|count| count.checked_add(1))
            .expect("lookup-table value count fits"),
        0,
        quotient_vector_count
            .checked_mul(u64::from(CANDIDATE_LOOKUP_EXTENSION_DEGREE))
            .expect("legacy primitive inverse-coordinate width fits"),
    )
}

pub(super) fn preferred_compact_lookup_work_ledger() -> CompactLookupWorkLedger {
    let quotient_vector_count = preferred_compact_post_vss_packet_inventory().quotient_vector_count;
    compact_lookup_work_ledger_for_quotient_inventory(
        quotient_vector_count,
        TRUSTEE_QUOTIENT_MAXIMUM_ABSOLUTE_VALUE
            .checked_mul(2)
            .and_then(|count| count.checked_add(1))
            .expect("lookup-table value count fits"),
        0,
        quotient_vector_count
            .checked_mul(u64::from(CANDIDATE_LOOKUP_EXTENSION_DEGREE))
            .expect("legacy primitive inverse-coordinate width fits"),
    )
}

#[cfg(any(test, feature = "primitive-measurement-evidence"))]
fn compact_public_key_work_ledger() -> CompactLookupWorkLedger {
    let inventory = compact_public_key_work_inventory();
    compact_lookup_work_ledger_for_quotient_inventory(
        inventory.signed_modular_quotient_count,
        inventory.quotient_lookup_table_value_count,
        inventory
            .ternary_vector_count
            .checked_add(inventory.eta_two_vector_count)
            .and_then(|count| {
                count.checked_add(inventory.small_set_multiplication_helper_logical_column_count)
            })
            .expect("public-key additional pre-challenge width fits"),
        inventory.inverse_helper_logical_column_count,
    )
}

fn compact_lookup_work_ledger_for_quotient_inventory(
    quotient_vector_count: u64,
    lookup_table_value_count: u64,
    additional_pre_challenge_logical_column_count: u64,
    inverse_helper_logical_column_count: u64,
) -> CompactLookupWorkLedger {
    let ring_degree = u64::try_from(POLYNOMIAL_DEGREE).expect("ring degree fits u64");
    let quotient_entry_count = quotient_vector_count
        .checked_mul(ring_degree)
        .expect("quotient-entry count fits");
    assert!(lookup_table_value_count > 0);
    let lookup_table_column_count = lookup_table_value_count.div_ceil(ring_degree);
    let padded_lookup_table_entry_count = lookup_table_column_count
        .checked_mul(ring_degree)
        .expect("padded lookup-table entry count fits");
    let lookup_soundness_numerator = quotient_entry_count
        .checked_add(padded_lookup_table_entry_count)
        .and_then(|count| count.checked_sub(1))
        .expect("lookup soundness numerator fits");
    let complete_inverse_element_count = quotient_entry_count
        .checked_add(padded_lookup_table_entry_count)
        .expect("complete inverse-element count fits");

    // Quotients and table multiplicities are fixed before the lookup
    // challenge. The caller supplies the logical inverse width because the
    // current post-VSS primitive ledger still records its historical
    // coordinate-wise experiment, whereas the public-key R1CS catalog uses
    // one quintic-extension symbol per reciprocal.
    let pre_challenge_logical_column_count = quotient_vector_count
        .checked_add(lookup_table_column_count)
        .and_then(|count| count.checked_add(additional_pre_challenge_logical_column_count))
        .expect("pre-challenge logical-column count fits");
    let logical_column_count = pre_challenge_logical_column_count
        .checked_add(inverse_helper_logical_column_count)
        .expect("lookup logical-column count fits");

    // Every logical column is independently randomized with 393 private
    // Reed-Solomon message coefficients. This is the interleaved-code
    // construction covered by the t-query ZK encoding theorem; a single
    // rank-one pad column cannot hide a row containing many secret symbols.
    // Tail stripes are rounded only for the packed transform implementation.
    let mut ordered_physical_stripe_widths =
        power_of_two_stripe_widths(pre_challenge_logical_column_count);
    ordered_physical_stripe_widths.extend(power_of_two_stripe_widths(
        inverse_helper_logical_column_count,
    ));
    let physical_column_count = ordered_physical_stripe_widths.iter().sum::<u64>();
    assert!(ring_degree + CANDIDATE_LOOKUP_QUERY_COUNT <= CANDIDATE_RANDOMIZED_CODE_MESSAGE_LENGTH);
    let encoded_row_count = CANDIDATE_RANDOMIZED_CODE_MESSAGE_LENGTH
        .checked_mul(CANDIDATE_INVERSE_RATE)
        .expect("encoded row count fits");
    let one_pass_encoded_field_element_count = physical_column_count
        .checked_mul(encoded_row_count)
        .expect("one-pass encoded element count fits");
    let complete_two_pass_encoded_field_element_count = one_pass_encoded_field_element_count * 2;

    // A stripe is a batch of independent degree-N coefficient polynomials,
    // not one flattened polynomial whose degree grows with the stripe width.
    // The forward radix-two encoder therefore owns log2(encoded_row_count)
    // layers per column. Counting log2(width * encoded_row_count) would charge
    // nonexistent cross-column butterflies.
    let butterfly_count_per_physical_column =
        encoded_row_count / 2 * u64::from(encoded_row_count.ilog2());
    let complete_two_pass_butterfly_count = physical_column_count
        .checked_mul(butterfly_count_per_physical_column)
        .and_then(|count| count.checked_mul(2))
        .expect("complete two-pass butterfly count fits");
    let complete_two_pass_salted_leaf_hash_count =
        u64::try_from(ordered_physical_stripe_widths.len())
            .expect("stripe count fits u64")
            .checked_mul(encoded_row_count)
            .and_then(|count| count.checked_mul(2))
            .expect("complete salted-leaf count fits");

    let largest_physical_stripe_width = ordered_physical_stripe_widths
        .iter()
        .copied()
        .max()
        .expect("the lookup owns at least one stripe");
    let largest_stripe_matrix_byte_length = largest_physical_stripe_width
        .checked_mul(encoded_row_count)
        .and_then(|count| count.checked_mul(8))
        .expect("largest stripe matrix byte length fits");
    let complete_binary_tree_byte_length = (2 * encoded_row_count - 1)
        .checked_mul(CANDIDATE_MERKLE_DIGEST_BYTE_LENGTH)
        .expect("complete binary-tree byte length fits");
    let monolithic_peak_live_byte_length = largest_stripe_matrix_byte_length
        .checked_add(complete_binary_tree_byte_length)
        .and_then(|count| count.checked_add(CANDIDATE_NON_MATRIX_WORKSPACE_BYTE_LENGTH))
        .expect("candidate monolithic peak live byte length fits");

    // The canonical 128-column leaf is incremental: retain one zeroized raw
    // SHAKE256 state per encoded row, feed it four independently randomized
    // 32-column transform batches, and finish the canonical Merkle root with a
    // logarithmic frontier. Batching changes neither leaf bytes nor the root.
    // The complete-tree and 128-column matrix sizes above remain only a
    // monolithic sensitivity; they are not simultaneously resident on the
    // selected path.
    assert!(largest_physical_stripe_width.is_multiple_of(CANDIDATE_TRANSFORM_BATCH_WIDTH));
    let transform_batch_matrix_byte_length = CANDIDATE_TRANSFORM_BATCH_WIDTH
        .checked_mul(encoded_row_count)
        .and_then(|count| count.checked_mul(8))
        .expect("candidate transform-batch matrix byte length fits");
    let replay_column_byte_length = encoded_row_count
        .checked_mul(8)
        .expect("candidate replay-column byte length fits");
    let hash_state_byte_length = encoded_row_count
        .checked_mul(CANDIDATE_SHAKE256_STATE_BYTE_LENGTH)
        .expect("candidate hash-state byte length fits");
    let twiddle_byte_length = encoded_row_count
        .checked_sub(1)
        .and_then(|count| count.checked_mul(2))
        .and_then(|count| count.checked_mul(8))
        .expect("candidate twiddle byte length fits");
    let incremental_commitment_peak_live_byte_length = transform_batch_matrix_byte_length
        .checked_add(replay_column_byte_length)
        .and_then(|count| count.checked_add(hash_state_byte_length))
        .and_then(|count| count.checked_add(twiddle_byte_length))
        .expect("candidate incremental commitment peak live byte length fits");
    let peak_live_byte_length = incremental_commitment_peak_live_byte_length
        .checked_add(CANDIDATE_NON_MATRIX_WORKSPACE_BYTE_LENGTH)
        .expect("candidate incremental complete peak live byte length fits");

    let stripe_count =
        u64::try_from(ordered_physical_stripe_widths.len()).expect("stripe count fits u64");
    let opened_row_byte_length = physical_column_count
        .checked_mul(8)
        .and_then(|count| count.checked_mul(CANDIDATE_LOOKUP_QUERY_COUNT))
        .expect("opened-row byte length fits");
    let naive_authentication_path_byte_length = stripe_count
        .checked_mul(CANDIDATE_LOOKUP_QUERY_COUNT)
        .and_then(|count| count.checked_mul(u64::from(encoded_row_count.ilog2())))
        .and_then(|count| count.checked_mul(CANDIDATE_MERKLE_DIGEST_BYTE_LENGTH))
        .expect("authentication-path byte length fits");

    CompactLookupWorkLedger {
        quotient_entry_count,
        lookup_table_value_count,
        padded_lookup_table_entry_count,
        complete_inverse_element_count,
        lookup_soundness_numerator,
        pre_challenge_logical_column_count,
        inverse_helper_logical_column_count,
        logical_column_count,
        ordered_physical_stripe_widths,
        randomized_code_message_length: CANDIDATE_RANDOMIZED_CODE_MESSAGE_LENGTH,
        randomized_code_randomness_length_per_logical_column: CANDIDATE_LOOKUP_QUERY_COUNT,
        encoded_row_count,
        physical_column_count,
        private_random_field_element_count: logical_column_count * CANDIDATE_LOOKUP_QUERY_COUNT,
        incremental_commitment_peak_live_byte_length,
        monolithic_peak_live_byte_length,
        peak_live_byte_length,
        one_pass_encoded_field_element_count,
        complete_two_pass_encoded_field_element_count,
        complete_two_pass_butterfly_count,
        complete_two_pass_salted_leaf_hash_count,
        opened_row_byte_length,
        naive_authentication_path_byte_length,
    }
}

#[cfg(test)]
fn cfw_r1cs_mask_lower_bound_ledger(
    lookup_ledger: &CompactLookupWorkLedger,
) -> CfwR1csMaskLowerBoundLedger {
    cfw_r1cs_mask_lower_bound_ledger_for_repetition_count(
        lookup_ledger,
        CANDIDATE_BASE_FIELD_RBR_REPETITION_COUNT,
    )
}

fn cfw_r1cs_mask_lower_bound_ledger_for_repetition_count(
    lookup_ledger: &CompactLookupWorkLedger,
    rbr_repetition_count: u32,
) -> CfwR1csMaskLowerBoundLedger {
    assert!(rbr_repetition_count > 0);
    let ring_degree = u64::try_from(POLYNOMIAL_DEGREE).expect("ring degree fits u64");
    let relation_base_field_element_count = lookup_ledger
        .logical_column_count
        .checked_mul(ring_degree)
        .expect("lookup relation element count fits");
    let padded_r1cs_witness_element_count = relation_base_field_element_count
        .checked_next_power_of_two()
        .expect("padded R1CS witness length derives");
    // CFW Theorem 11.3 assumes ell = n_0 and imposes one constraint for every
    // coordinate of (v, w). The public input can be implicitly zero-padded,
    // but the 2*ell matrix dimension and O(ell) verifier work remain operative.
    let padded_public_input_element_count = padded_r1cs_witness_element_count;
    let padded_r1cs_constraint_count = padded_r1cs_witness_element_count
        .checked_mul(2)
        .expect("padded R1CS constraint count fits");
    let r1cs_variable_count = padded_r1cs_witness_element_count.ilog2();
    let mask_oracle_count_per_repetition = u64::from(r1cs_variable_count + 1);
    let repetition_count = u64::from(rbr_repetition_count);
    let inner_mask_oracle_count = mask_oracle_count_per_repetition
        .checked_mul(3)
        .and_then(|count| count.checked_mul(repetition_count))
        .expect("CFW inner-mask count fits");
    let outer_mask_oracle_count = mask_oracle_count_per_repetition
        .checked_mul(repetition_count)
        .expect("CFW outer-mask count fits");
    let randomized_encoding_count_including_main = inner_mask_oracle_count
        .checked_add(outer_mask_oracle_count)
        .and_then(|count| count.checked_add(1))
        .expect("CFW randomized-encoding count fits");

    let mask_code_populated_message_length = CFW_R1CS_OUTER_MASK_MESSAGE_LENGTH
        .max(CFW_R1CS_INNER_MASK_MESSAGE_LENGTH)
        .checked_add(CANDIDATE_LOOKUP_QUERY_COUNT)
        .expect("CFW mask-code populated message length fits");
    let mask_code_encoded_row_count = mask_code_populated_message_length
        .checked_mul(CFW_MASK_CODE_INVERSE_RATE)
        .and_then(u64::checked_next_power_of_two)
        .expect("CFW mask-code row count derives");
    let inner_physical_stripe_widths = power_of_two_stripe_widths(inner_mask_oracle_count);
    let outer_physical_stripe_widths = power_of_two_stripe_widths(outer_mask_oracle_count);
    let mask_physical_column_count = inner_physical_stripe_widths
        .iter()
        .chain(outer_physical_stripe_widths.iter())
        .sum::<u64>();
    let mask_commitment_root_count =
        u64::try_from(inner_physical_stripe_widths.len() + outer_physical_stripe_widths.len())
            .expect("CFW mask commitment-root count fits");
    let mask_one_pass_encoded_field_element_count = mask_physical_column_count
        .checked_mul(mask_code_encoded_row_count)
        .expect("CFW mask one-pass encoded element count fits");
    let mask_opened_row_byte_length = mask_physical_column_count
        .checked_mul(CANDIDATE_LOOKUP_QUERY_COUNT)
        .and_then(|count| count.checked_mul(8))
        .expect("CFW mask opened-row byte length fits");
    let mask_naive_authentication_path_byte_length = mask_commitment_root_count
        .checked_mul(CANDIDATE_LOOKUP_QUERY_COUNT)
        .and_then(|count| count.checked_mul(u64::from(mask_code_encoded_row_count.ilog2())))
        .and_then(|count| count.checked_mul(CANDIDATE_MERKLE_DIGEST_BYTE_LENGTH))
        .expect("CFW mask authentication-path byte length fits");
    let sumcheck_non_oracle_message_byte_length = mask_oracle_count_per_repetition
        .checked_mul(CFW_R1CS_OUTER_MASK_MESSAGE_LENGTH + 1)
        .and_then(|count| count.checked_add(4))
        .and_then(|count| count.checked_mul(repetition_count))
        .and_then(|count| count.checked_mul(8))
        .expect("CFW non-oracle message byte length fits");

    CfwR1csMaskLowerBoundLedger {
        relation_base_field_element_count,
        padded_r1cs_witness_element_count,
        padded_public_input_element_count,
        padded_r1cs_constraint_count,
        r1cs_variable_count,
        rbr_repetition_count,
        inner_mask_oracle_count,
        outer_mask_oracle_count,
        randomized_encoding_count_including_main,
        mask_code_encoded_row_count,
        mask_physical_column_count,
        mask_commitment_root_count,
        mask_one_pass_encoded_field_element_count,
        mask_opened_row_byte_length,
        mask_naive_authentication_path_byte_length,
        sumcheck_non_oracle_message_byte_length,
    }
}

#[cfg(test)]
fn cfw_field_strategy_static_ledger(
    lookup_ledger: &CompactLookupWorkLedger,
    mask_ledger: &CfwR1csMaskLowerBoundLedger,
    field_extension_degree: u32,
    transform_batch_logical_column_count: u64,
) -> CfwFieldStrategyStaticLedger {
    assert!(field_extension_degree > 0);
    assert!(transform_batch_logical_column_count > 0);
    assert!(
        CANDIDATE_LOGICAL_COLUMN_STRIPE_WIDTH.is_multiple_of(transform_batch_logical_column_count)
    );
    let field_coordinate_count = u64::from(field_extension_degree);
    let encoded_row_count = lookup_ledger.encoded_row_count;
    let encoded_field_element_byte_length = field_coordinate_count
        .checked_mul(8)
        .expect("encoded field-element byte length fits");
    let transform_batch_matrix_byte_length = transform_batch_logical_column_count
        .checked_mul(encoded_row_count)
        .and_then(|count| count.checked_mul(encoded_field_element_byte_length))
        .expect("field-strategy transform batch fits");
    let replay_column_byte_length = encoded_row_count
        .checked_mul(encoded_field_element_byte_length)
        .expect("field-strategy replay column fits");
    let hash_state_byte_length = encoded_row_count
        .checked_mul(CANDIDATE_SHAKE256_STATE_BYTE_LENGTH)
        .expect("field-strategy hash states fit");
    // The evaluation domain and its twiddles remain in the Goldilocks
    // subfield, so one twiddle catalog is shared across extension coordinates.
    let twiddle_byte_length = encoded_row_count
        .checked_sub(1)
        .and_then(|count| count.checked_mul(2 * 8))
        .expect("field-strategy twiddle catalog fits");
    let incremental_commitment_peak_live_byte_length = transform_batch_matrix_byte_length
        .checked_add(replay_column_byte_length)
        .and_then(|count| count.checked_add(hash_state_byte_length))
        .and_then(|count| count.checked_add(twiddle_byte_length))
        .expect("field-strategy incremental commitment peak fits");
    let conservative_peak_live_byte_length = incremental_commitment_peak_live_byte_length
        .checked_add(CANDIDATE_NON_MATRIX_WORKSPACE_BYTE_LENGTH)
        .expect("field-strategy conservative peak fits");
    let main_complete_two_pass_base_coordinate_butterfly_count = lookup_ledger
        .complete_two_pass_butterfly_count
        .checked_mul(field_coordinate_count)
        .expect("field-strategy butterfly count fits");
    let mask_one_pass_base_coordinate_element_count = mask_ledger
        .mask_one_pass_encoded_field_element_count
        .checked_mul(field_coordinate_count)
        .expect("field-strategy mask work fits");

    let direct_root_count = u64::try_from(lookup_ledger.ordered_physical_stripe_widths.len())
        .expect("field-strategy direct root count fits");
    let known_component_naive_path_subtotal_byte_length = lookup_ledger
        .opened_row_byte_length
        .checked_mul(field_coordinate_count)
        .and_then(|count| count.checked_add(lookup_ledger.naive_authentication_path_byte_length))
        .and_then(|count| {
            count.checked_add(mask_ledger.mask_opened_row_byte_length * field_coordinate_count)
        })
        .and_then(|count| count.checked_add(mask_ledger.mask_naive_authentication_path_byte_length))
        .and_then(|count| {
            count.checked_add(
                mask_ledger.sumcheck_non_oracle_message_byte_length * field_coordinate_count,
            )
        })
        .and_then(|count| {
            count.checked_add(
                (direct_root_count + mask_ledger.mask_commitment_root_count)
                    * CANDIDATE_MERKLE_DIGEST_BYTE_LENGTH,
            )
        })
        .expect("field-strategy known-component subtotal fits");

    CfwFieldStrategyStaticLedger {
        field_extension_degree,
        rbr_repetition_count: mask_ledger.rbr_repetition_count,
        transform_batch_logical_column_count,
        incremental_commitment_peak_live_byte_length,
        conservative_peak_live_byte_length,
        main_complete_two_pass_base_coordinate_butterfly_count,
        mask_one_pass_base_coordinate_element_count,
        known_component_naive_path_subtotal_byte_length,
    }
}

fn cfw_two_epoch_packet_static_ledger(
    lookup_ledger: &CompactLookupWorkLedger,
    mask_ledger: &CfwR1csMaskLowerBoundLedger,
    field_extension_degree: u32,
    ring_vector_packing_factor: u64,
) -> CfwTwoEpochPacketStaticLedger {
    assert_eq!(mask_ledger.rbr_repetition_count, 1);
    assert!(field_extension_degree > 0);
    assert!(ring_vector_packing_factor.is_power_of_two());

    let ring_degree = u64::try_from(POLYNOMIAL_DEGREE).expect("ring degree fits u64");
    assert!(ring_degree.is_power_of_two());
    let padded_r1cs_witness_element_count = mask_ledger.padded_r1cs_witness_element_count;
    let relation_message_element_count_per_component = ring_degree
        .checked_mul(ring_vector_packing_factor)
        .expect("packed relation message length fits");
    assert!(
        padded_r1cs_witness_element_count
            .is_multiple_of(relation_message_element_count_per_component)
    );
    let main_interleaved_component_count =
        padded_r1cs_witness_element_count / relation_message_element_count_per_component;
    assert!(main_interleaved_component_count.is_power_of_two());

    // Each component carries the selected number of consecutive complete ring
    // vectors and enough independent coefficients for the declared direct-
    // query budget. Targeting inverse rate two and rounding the evaluation
    // domain to a power of two preserves the conservative unique-decoding
    // regime. The older 65,536-message/rate-four primitive is retained as a
    // conservative measurement geometry, not as the selected theorem main
    // code.
    let populated_message_element_count_per_component =
        relation_message_element_count_per_component
            .checked_add(CANDIDATE_LOOKUP_QUERY_COUNT)
            .expect("populated main-code message length fits");
    let encoded_row_count = populated_message_element_count_per_component
        .checked_mul(CANDIDATE_THEOREM_MAIN_CODE_INVERSE_RATE)
        .and_then(u64::checked_next_power_of_two)
        .expect("theorem main-code domain derives");
    let minimum_distance_coordinate_count = encoded_row_count
        .checked_sub(populated_message_element_count_per_component)
        .and_then(|count| count.checked_add(1))
        .expect("Reed-Solomon minimum distance derives");
    let unique_decoding_radius_coordinate_count =
        minimum_distance_coordinate_count.saturating_sub(1) / 2;

    // Only quotients and public-table multiplicities must precede the lookup
    // challenge. Small-set witnesses and multiplication helpers can enter the
    // complete post-challenge R1CS encoding. Tail components are padded to
    // power-of-two stripe widths so the commitment implementation never
    // changes the canonical row alphabet.
    let quotient_vector_count = lookup_ledger.quotient_entry_count / ring_degree;
    let public_table_component_count = lookup_ledger.padded_lookup_table_entry_count / ring_degree;
    let unpacked_pre_challenge_ring_vector_count = quotient_vector_count
        .checked_add(public_table_component_count)
        .expect("pre-challenge ring-vector count fits");
    let pre_challenge_logical_component_count =
        unpacked_pre_challenge_ring_vector_count.div_ceil(ring_vector_packing_factor);
    let pre_challenge_physical_stripe_widths =
        power_of_two_stripe_widths(pre_challenge_logical_component_count);
    let pre_challenge_physical_component_count =
        pre_challenge_physical_stripe_widths.iter().sum::<u64>();
    let pre_challenge_commitment_root_count =
        u64::try_from(pre_challenge_physical_stripe_widths.len())
            .expect("pre-challenge root count fits u64");

    // After both epochs are committed, extension-field weights compress every
    // copied packed-component equality to one multilinear polynomial. If a
    // copy differs, a random combination is identically zero with probability
    // at most 1/|F|; otherwise its multilinear extension vanishes at the
    // sampled point with probability at most log2(N * packing_factor)/|F|.
    // The binding owns two explicit-point openings.
    let cross_epoch_multilinear_point_coordinate_count =
        relation_message_element_count_per_component.ilog2();
    let cross_epoch_binding_error_numerator =
        u64::from(cross_epoch_multilinear_point_coordinate_count + 1);

    let field_coordinate_count = u64::from(field_extension_degree);
    let encoded_field_element_byte_length = field_coordinate_count
        .checked_mul(8)
        .expect("extension element byte length fits");
    let transform_batch_logical_component_count =
        (CANDIDATE_QUINTIC_EXTENSION_TRANSFORM_BATCH_WIDTH / ring_vector_packing_factor).max(1);
    assert!(
        main_interleaved_component_count.is_multiple_of(transform_batch_logical_component_count)
    );
    let transform_batch_matrix_byte_length = transform_batch_logical_component_count
        .checked_mul(encoded_row_count)
        .and_then(|count| count.checked_mul(encoded_field_element_byte_length))
        .expect("theorem main-code transform batch fits");
    let replay_column_byte_length = encoded_row_count
        .checked_mul(encoded_field_element_byte_length)
        .expect("theorem main-code replay column fits");
    let hash_state_byte_length = encoded_row_count
        .checked_mul(CANDIDATE_SHAKE256_STATE_BYTE_LENGTH)
        .expect("theorem main-code hash states fit");
    let twiddle_byte_length = encoded_row_count
        .checked_sub(1)
        .and_then(|count| count.checked_mul(2 * 8))
        .expect("theorem main-code twiddles fit");
    let incremental_commitment_peak_live_byte_length = transform_batch_matrix_byte_length
        .checked_add(replay_column_byte_length)
        .and_then(|count| count.checked_add(hash_state_byte_length))
        .and_then(|count| count.checked_add(twiddle_byte_length))
        .expect("theorem main-code commitment peak fits");
    let conservative_peak_live_byte_length = incremental_commitment_peak_live_byte_length
        .checked_add(CANDIDATE_NON_MATRIX_WORKSPACE_BYTE_LENGTH)
        .expect("theorem main-code conservative peak fits");

    let two_pass_butterfly_count_per_component = encoded_row_count
        .checked_mul(u64::from(encoded_row_count.ilog2()))
        .expect("two-pass component butterfly count fits");
    let main_complete_two_pass_base_coordinate_butterfly_count =
        two_pass_butterfly_count_per_component
            .checked_mul(main_interleaved_component_count)
            .and_then(|count| count.checked_mul(field_coordinate_count))
            .expect("theorem main-code butterfly count fits");
    let pre_challenge_complete_two_pass_base_field_butterfly_count =
        two_pass_butterfly_count_per_component
            .checked_mul(pre_challenge_physical_component_count)
            .expect("pre-challenge butterfly count fits");
    let complete_two_pass_base_coordinate_butterfly_count =
        main_complete_two_pass_base_coordinate_butterfly_count
            .checked_add(pre_challenge_complete_two_pass_base_field_butterfly_count)
            .expect("two-epoch butterfly count fits");

    let pre_challenge_opened_row_byte_length = pre_challenge_physical_component_count
        .checked_mul(CANDIDATE_LOOKUP_QUERY_COUNT)
        .and_then(|count| count.checked_mul(8))
        .expect("pre-challenge opened rows fit");
    let pre_challenge_naive_path_byte_length = pre_challenge_commitment_root_count
        .checked_mul(CANDIDATE_LOOKUP_QUERY_COUNT)
        .and_then(|count| count.checked_mul(u64::from(encoded_row_count.ilog2())))
        .and_then(|count| count.checked_mul(CANDIDATE_MERKLE_DIGEST_BYTE_LENGTH))
        .expect("pre-challenge paths fit");
    let main_opened_row_byte_length = main_interleaved_component_count
        .checked_mul(CANDIDATE_LOOKUP_QUERY_COUNT)
        .and_then(|count| count.checked_mul(encoded_field_element_byte_length))
        .expect("theorem main-code opened rows fit");
    let main_naive_path_byte_length = CANDIDATE_LOOKUP_QUERY_COUNT
        .checked_mul(u64::from(encoded_row_count.ilog2()))
        .and_then(|count| count.checked_mul(CANDIDATE_MERKLE_DIGEST_BYTE_LENGTH))
        .expect("theorem main-code paths fit");
    let mask_opened_row_byte_length = mask_ledger
        .mask_opened_row_byte_length
        .checked_mul(field_coordinate_count)
        .expect("extension mask openings fit");
    let sumcheck_non_oracle_message_byte_length = mask_ledger
        .sumcheck_non_oracle_message_byte_length
        .checked_mul(field_coordinate_count)
        .expect("extension sumcheck messages fit");
    let root_byte_length = pre_challenge_commitment_root_count
        .checked_add(1)
        .and_then(|count| count.checked_add(mask_ledger.mask_commitment_root_count))
        .and_then(|count| count.checked_mul(CANDIDATE_MERKLE_DIGEST_BYTE_LENGTH))
        .expect("two-epoch root bytes fit");
    let known_component_naive_path_subtotal_byte_length = pre_challenge_opened_row_byte_length
        .checked_add(pre_challenge_naive_path_byte_length)
        .and_then(|count| count.checked_add(main_opened_row_byte_length))
        .and_then(|count| count.checked_add(main_naive_path_byte_length))
        .and_then(|count| count.checked_add(mask_opened_row_byte_length))
        .and_then(|count| count.checked_add(mask_ledger.mask_naive_authentication_path_byte_length))
        .and_then(|count| count.checked_add(sumcheck_non_oracle_message_byte_length))
        .and_then(|count| count.checked_add(root_byte_length))
        .expect("two-epoch known-component subtotal fits");

    CfwTwoEpochPacketStaticLedger {
        padded_r1cs_witness_element_count,
        field_extension_degree,
        ring_vector_packing_factor,
        transform_batch_logical_component_count,
        main_interleaved_component_count,
        relation_message_element_count_per_component,
        populated_message_element_count_per_component,
        encoded_row_count,
        minimum_distance_coordinate_count,
        unique_decoding_radius_coordinate_count,
        pre_challenge_logical_component_count,
        pre_challenge_physical_component_count,
        pre_challenge_commitment_root_count,
        cross_epoch_column_weight_count: pre_challenge_logical_component_count,
        cross_epoch_multilinear_point_coordinate_count,
        cross_epoch_binding_error_numerator,
        cross_epoch_explicit_point_opening_count: 2,
        incremental_commitment_peak_live_byte_length,
        conservative_peak_live_byte_length,
        main_complete_two_pass_base_coordinate_butterfly_count,
        pre_challenge_complete_two_pass_base_field_butterfly_count,
        complete_two_pass_base_coordinate_butterfly_count,
        main_oracle_query_answer_byte_length: main_opened_row_byte_length,
        known_component_naive_path_subtotal_byte_length,
    }
}

pub(super) fn public_key_cfw_two_epoch_packet_static_ledger() -> CfwTwoEpochPacketStaticLedger {
    let lookup_ledger = compact_public_key_work_ledger();
    let mask_ledger = cfw_r1cs_mask_lower_bound_ledger_for_repetition_count(&lookup_ledger, 1);
    cfw_two_epoch_packet_static_ledger(
        &lookup_ledger,
        &mask_ledger,
        CANDIDATE_LOOKUP_EXTENSION_DEGREE,
        1,
    )
}

pub(super) fn factor_eight_post_vss_cfw_two_epoch_packet_static_ledger()
-> CfwTwoEpochPacketStaticLedger {
    let lookup_ledger = preferred_compact_lookup_work_ledger();
    let mask_ledger = cfw_r1cs_mask_lower_bound_ledger_for_repetition_count(&lookup_ledger, 1);
    cfw_two_epoch_packet_static_ledger(
        &lookup_ledger,
        &mask_ledger,
        CANDIDATE_LOOKUP_EXTENSION_DEGREE,
        PREFERRED_POST_VSS_RING_VECTOR_PACKING_FACTOR,
    )
}

#[cfg(test)]
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

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RingNativeCandidateDisposition {
    /// The family remains a logical relation inside a secret-bearing proof.
    SecretBearingRelation,
    /// No independent proof is emitted. The successor must bind the aggregate
    /// through a canonical linear commitment derived from already verified
    /// source commitments and a streaming commitment to the aggregate bytes.
    PublicLinearAggregate,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RingNativeCandidateEpoch {
    DealerVss,
    AfterVerifiedVss,
    AfterFrozenRoundOneAggregate,
    BallotAttempt,
    TargetRelease,
    PublicRecomputation,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RingNativeCandidateFamily {
    application_statement_schema_identifier: u16,
    disposition: RingNativeCandidateDisposition,
    epoch: RingNativeCandidateEpoch,
    required_capabilities: &'static [RingNativeConstraintCapability],
}

#[cfg(test)]
const COMMITTED_MATERIAL: &[RingNativeConstraintCapability] = &[
    RingNativeConstraintCapability::ArbitraryLinearMap,
    RingNativeConstraintCapability::CanonicalCoefficientEncoding,
    RingNativeConstraintCapability::CoefficientInfinityNorm,
    RingNativeConstraintCapability::ExactRnsLimbIntegerLift,
];

#[cfg(test)]
const SAME_SECRET: &[RingNativeConstraintCapability] = &[
    RingNativeConstraintCapability::ArbitraryLinearMap,
    RingNativeConstraintCapability::CanonicalCoefficientEncoding,
    RingNativeConstraintCapability::CoefficientInfinityNorm,
    RingNativeConstraintCapability::SmallSetMembership,
    RingNativeConstraintCapability::ExactRnsLimbIntegerLift,
];

#[cfg(test)]
const RING_SAMPLE: &[RingNativeConstraintCapability] = &[
    RingNativeConstraintCapability::ArbitraryLinearMap,
    RingNativeConstraintCapability::CanonicalCoefficientEncoding,
    RingNativeConstraintCapability::NegacyclicRingArithmetic,
    RingNativeConstraintCapability::CoefficientInfinityNorm,
    RingNativeConstraintCapability::SmallSetMembership,
    RingNativeConstraintCapability::ExactRnsLimbIntegerLift,
];

#[cfg(test)]
const GALOIS_SAMPLE: &[RingNativeConstraintCapability] = &[
    RingNativeConstraintCapability::ArbitraryLinearMap,
    RingNativeConstraintCapability::CanonicalCoefficientEncoding,
    RingNativeConstraintCapability::NegacyclicRingArithmetic,
    RingNativeConstraintCapability::CoefficientInfinityNorm,
    RingNativeConstraintCapability::CyclotomicAutomorphism,
    RingNativeConstraintCapability::SmallSetMembership,
    RingNativeConstraintCapability::ExactRnsLimbIntegerLift,
];

#[cfg(test)]
const BALLOT_SAMPLE: &[RingNativeConstraintCapability] = &[
    RingNativeConstraintCapability::ArbitraryLinearMap,
    RingNativeConstraintCapability::CanonicalCoefficientEncoding,
    RingNativeConstraintCapability::NegacyclicRingArithmetic,
    RingNativeConstraintCapability::CoefficientInfinityNorm,
    RingNativeConstraintCapability::SmallSetMembership,
    RingNativeConstraintCapability::ExactRnsLimbIntegerLift,
];

#[cfg(test)]
const TARGET_SAMPLE: &[RingNativeConstraintCapability] = &[
    RingNativeConstraintCapability::ArbitraryLinearMap,
    RingNativeConstraintCapability::CanonicalCoefficientEncoding,
    RingNativeConstraintCapability::NegacyclicRingArithmetic,
    RingNativeConstraintCapability::CoefficientInfinityNorm,
    RingNativeConstraintCapability::SmallSetMembership,
    RingNativeConstraintCapability::ExactRnsLimbIntegerLift,
];

#[cfg(test)]
const PUBLIC_AGGREGATE: &[RingNativeConstraintCapability] = &[
    RingNativeConstraintCapability::ArbitraryLinearMap,
    RingNativeConstraintCapability::CanonicalCoefficientEncoding,
];

#[cfg(test)]
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

#[cfg(test)]
fn modulus_product_bit_length(moduli: &[u64]) -> u64 {
    moduli
        .iter()
        .fold(BigUint::from(1_u8), |product, modulus| {
            product * BigUint::from(*modulus)
        })
        .bits()
}

#[cfg(test)]
fn candidate_multiply_modular(left: u64, right: u64, modulus: u64) -> u64 {
    u64::try_from((u128::from(left) * u128::from(right)) % u128::from(modulus))
        .expect("candidate modular product fits u64")
}

#[cfg(test)]
fn candidate_modular_power(mut base: u64, mut exponent: u64, modulus: u64) -> u64 {
    let mut result = 1_u64;
    while exponent != 0 {
        if exponent & 1 == 1 {
            result = candidate_multiply_modular(result, base, modulus);
        }
        base = candidate_multiply_modular(base, base, modulus);
        exponent >>= 1;
    }
    result
}

#[cfg(test)]
fn candidate_small_prime_is_prime(candidate: u64) -> bool {
    if candidate < 2 || candidate.is_multiple_of(2) {
        return candidate == 2;
    }
    let mut divisor = 3_u64;
    while divisor <= candidate / divisor {
        if candidate.is_multiple_of(divisor) {
            return false;
        }
        divisor += 2;
    }
    true
}

#[cfg(test)]
fn candidate_root_certificate_is_valid(
    roots: RootParameters,
    distinct_group_prime_factors: &[u64],
) -> bool {
    let group_order = roots.modulus - 1;
    let mut remaining_group_order = group_order;
    for prime_factor in distinct_group_prime_factors {
        if !candidate_small_prime_is_prime(*prime_factor)
            || !remaining_group_order.is_multiple_of(*prime_factor)
        {
            return false;
        }
        while remaining_group_order.is_multiple_of(*prime_factor) {
            remaining_group_order /= *prime_factor;
        }
    }
    let polynomial_degree = u64::try_from(POLYNOMIAL_DEGREE).expect("ring degree fits u64");
    let twice_polynomial_degree = polynomial_degree * 2;
    remaining_group_order == 1
        && candidate_modular_power(roots.primitive_generator, group_order, roots.modulus) == 1
        && distinct_group_prime_factors.iter().all(|prime_factor| {
            candidate_modular_power(
                roots.primitive_generator,
                group_order / *prime_factor,
                roots.modulus,
            ) != 1
        })
        && candidate_modular_power(roots.negacyclic_root, polynomial_degree, roots.modulus)
            == roots.modulus - 1
        && candidate_modular_power(
            roots.negacyclic_root,
            twice_polynomial_degree,
            roots.modulus,
        ) == 1
        && roots.cyclic_root
            == candidate_multiply_modular(
                roots.negacyclic_root,
                roots.negacyclic_root,
                roots.modulus,
            )
        && candidate_multiply_modular(
            roots.negacyclic_root,
            roots.inverse_negacyclic_root,
            roots.modulus,
        ) == 1
        && candidate_multiply_modular(roots.cyclic_root, roots.inverse_cyclic_root, roots.modulus)
            == 1
        && candidate_multiply_modular(
            polynomial_degree,
            roots.inverse_polynomial_degree,
            roots.modulus,
        ) == 1
}

#[cfg(test)]
fn maximum_consecutive_block_product(moduli: &[u64], block_width: usize) -> BigUint {
    moduli
        .chunks(block_width)
        .map(|block| {
            block
                .iter()
                .map(|modulus| BigUint::from(*modulus))
                .product::<BigUint>()
        })
        .max()
        .expect("candidate data basis is nonempty")
}

#[cfg(test)]
fn preferred_candidate_component_byte_lengths(catalog_level: usize) -> (u64, u64) {
    let active_data_moduli = &DATA_PRIMES[..=catalog_level];
    let block_count = active_data_moduli
        .len()
        .div_ceil(PREFERRED_CANDIDATE_KEY_SWITCH_BLOCK_WIDTH);
    let special_moduli = PREFERRED_CANDIDATE_SPECIAL_ROOT_PARAMETERS.map(|roots| roots.modulus);
    let coefficient_wire_byte_length = active_data_moduli
        .iter()
        .chain(special_moduli.iter())
        .map(|modulus| {
            u64::try_from(
                canonical_residue_byte_length(*modulus).expect("candidate residue width derives"),
            )
            .expect("candidate residue width fits u64")
        })
        .sum::<u64>();
    let coefficient_resident_byte_length =
        u64::try_from(active_data_moduli.len() + PREFERRED_CANDIDATE_SPECIAL_LIMB_COUNT)
            .expect("candidate extended-limb count fits u64")
            * 8;
    let coefficient_count = u64::try_from(block_count).expect("candidate block count fits u64")
        * u64::try_from(POLYNOMIAL_DEGREE).expect("ring degree fits u64");
    (
        coefficient_count * coefficient_wire_byte_length,
        coefficient_count * coefficient_resident_byte_length,
    )
}

#[cfg(test)]
fn candidate_lookup_challenge_field_order() -> BigUint {
    BigUint::from(GOLDILOCKS_BASE_FIELD_MODULUS).pow(CANDIDATE_LOOKUP_EXTENSION_DEGREE)
}

#[cfg(test)]
fn radix_digit_count(maximum_magnitude: &BigUint) -> u64 {
    let bit_length = maximum_magnitude.bits().max(1);
    bit_length.div_ceil(u64::from(CANDIDATE_RADIX_DIGIT_BIT_LENGTH))
}

#[cfg(test)]
fn candidate_stripe_matrix_byte_length(logical_column_count: u64) -> u64 {
    let encoded_row_count = CANDIDATE_RANDOMIZED_CODE_MESSAGE_LENGTH
        .checked_mul(CANDIDATE_INVERSE_RATE)
        .expect("candidate encoded row count fits");
    encoded_row_count
        .checked_mul(logical_column_count)
        .and_then(|element_count| element_count.checked_mul(8))
        .expect("candidate stripe matrix byte length fits")
}

#[test]
fn compact_public_key_packet_inventory_follows_the_production_relation_geometry() {
    let inventory = compact_public_key_packet_inventory();

    assert_eq!(DATA_PRIMES.len(), 23);
    assert_eq!(SETUP_COMMITMENT_MODULUS_LIMB_INDICES, [0, 1, 2]);
    assert_eq!(SETUP_COMMITMENT_MODULE_RANK, 1);
    assert_eq!(MODULAR_QUOTIENT_BIT_COUNT, 17);
    assert_ne!(inventory.relation_plan_hash, [0_u8; 64]);
    assert_eq!(inventory.ring_degree, 32_768);
    assert_eq!(inventory.data_limb_count, 23);
    assert_eq!(inventory.anchor_count, 3);
    assert_eq!(inventory.anchor_row_count, 6);
    assert_eq!(inventory.ternary_vector_count, 10);
    assert_eq!(inventory.eta_two_vector_count, 1);
    assert_eq!(inventory.signed_modular_quotient_count, 29);
    assert_eq!(inventory.quotient_interval_minimum, -65_535);
    assert_eq!(inventory.quotient_interval_maximum, 65_536);
    assert_eq!(inventory.quotient_lookup_table_value_count, 131_072);
    assert_eq!(inventory.quotient_lookup_table_column_count, 4);
    assert_eq!(inventory.structured_public_ring_product_count, 32);
    assert_eq!(inventory.coefficient_local_exact_equation_count, 950_272);
    assert_eq!(
        inventory.lookup_inverse_multiplication_constraint_count,
        950_272
    );
    assert_eq!(inventory.small_set_multiplication_constraint_count, 786_432);
    assert_eq!(inventory.known_multiplication_constraint_count, 1_736_704);
    assert_eq!(inventory.public_key_quotient_interval_minimum, -32_767);
    assert_eq!(inventory.public_key_quotient_interval_maximum, 32_768);
    assert_eq!(inventory.first_anchor_quotient_interval_minimum, -65_535);
    assert_eq!(inventory.first_anchor_quotient_interval_maximum, 65_536);
    assert_eq!(inventory.final_anchor_quotient_interval_minimum, -32_767);
    assert_eq!(inventory.final_anchor_quotient_interval_maximum, 32_768);
    assert_eq!(
        inventory.maximum_direct_integer_lift_residual_interval_width,
        662_283_957_175_299
    );
    assert!(
        u128::from(inventory.maximum_direct_integer_lift_residual_interval_width) * (1 << 14)
            < u128::from(GOLDILOCKS_BASE_FIELD_MODULUS)
    );
    assert!(
        u128::from(inventory.maximum_direct_integer_lift_residual_interval_width) * (1 << 15)
            > u128::from(GOLDILOCKS_BASE_FIELD_MODULUS)
    );
    assert_eq!(inventory.pre_challenge_source_logical_column_count, 44);
    assert_eq!(
        inventory.small_set_multiplication_helper_logical_column_count,
        13
    );
    assert_eq!(inventory.inverse_helper_logical_column_count, 29);
    assert_eq!(inventory.r1cs_witness_logical_column_count, 86);

    // Schema 0x1212 contains only public-by-private ring maps: the public-key
    // common reference and every anchor matrix are verifier-owned. The compact
    // compiler must therefore lower them as structured public linear maps. The
    // selected lookup replaces, rather than supplements, the rejected 493-bit-
    // column decomposition. It must not materialize NTT images, transposes,
    // convolution accumulators, or cyclotomic quotient vectors as witness
    // columns. This inventory is not a substitute for the missing compiler and
    // its checked constraint list.
    assert_eq!(
        ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
        0x1212
    );
}

#[test]
fn compact_post_vss_packet_inventory_follows_every_selected_topology() {
    let inventory = compact_post_vss_packet_inventory();

    assert_eq!(selected_sharing_data_prime_coordinates().unwrap().len(), 8);
    assert_eq!(inventory.aggregate_threshold_quotient_vector_count, 16);
    assert_eq!(inventory.shared_anchor_quotient_vector_count, 6);
    assert_eq!(inventory.public_key_quotient_vector_count, 23);
    assert_eq!(
        inventory.relinearization_round_one_quotient_vector_count,
        416
    );
    assert_eq!(inventory.galois_quotient_vector_count, 732);
    assert_eq!(inventory.quotient_vector_count, 1_193);

    // The current radix-three representation owns eleven N-coefficient
    // columns per trustee quotient. Applying it unchanged to the fused packet
    // would therefore create 13,123 quotient columns before any material,
    // secret, error, or masking column. This is a rejected representation, not
    // a reason to weaken the exact quotient bounds.
    assert_eq!(inventory.quotient_vector_count * 11, 13_123);
}

#[test]
fn preferred_block_ten_candidate_cuts_the_post_vss_quotient_inventory() {
    let inventory = preferred_compact_post_vss_packet_inventory();

    assert_eq!(PREFERRED_CANDIDATE_KEY_SWITCH_BLOCK_WIDTH, 10);
    assert_eq!(PREFERRED_CANDIDATE_SPECIAL_LIMB_COUNT, 6);
    assert_eq!(inventory.aggregate_threshold_quotient_vector_count, 16);
    assert_eq!(inventory.shared_anchor_quotient_vector_count, 6);
    assert_eq!(inventory.public_key_quotient_vector_count, 23);
    assert_eq!(
        inventory.relinearization_round_one_quotient_vector_count,
        174
    );
    assert_eq!(inventory.galois_quotient_vector_count, 276);
    assert_eq!(inventory.quotient_vector_count, 495);
    assert!(inventory.quotient_vector_count * 2 < 1_193);

    // This is a topology candidate, not a parameter selection. It becomes
    // eligible only after exact special-prime certificates, the complete
    // source-linked estimator record, and the production noise recurrence
    // all bind the same bytes.
}

#[test]
fn logarithmic_derivative_lookup_has_exact_capacity_and_bounded_work() {
    let ledger = compact_lookup_work_ledger();

    assert_eq!(TRUSTEE_QUOTIENT_MAXIMUM_ABSOLUTE_VALUE, 147_622);
    assert_eq!(ledger.quotient_entry_count, 39_092_224);
    assert_eq!(ledger.lookup_table_value_count, 295_245);
    assert_eq!(ledger.padded_lookup_table_entry_count, 327_680);
    assert_eq!(ledger.complete_inverse_element_count, 39_419_904);
    assert_eq!(ledger.lookup_soundness_numerator, 39_419_903);
    assert_eq!(ledger.pre_challenge_logical_column_count, 1_203);
    assert_eq!(ledger.inverse_helper_logical_column_count, 5_965);
    assert_eq!(ledger.logical_column_count, 7_168);
    assert_eq!(ledger.randomized_code_message_length, 65_536);
    assert_eq!(
        ledger.randomized_code_randomness_length_per_logical_column,
        393
    );
    assert_eq!(ledger.encoded_row_count, 262_144);
    assert_eq!(ledger.physical_column_count, 7_232);

    assert_eq!(ledger.ordered_physical_stripe_widths.len(), 57);
    assert_eq!(
        ledger
            .ordered_physical_stripe_widths
            .iter()
            .filter(|width| **width == 128)
            .count(),
        56
    );
    assert_eq!(
        ledger
            .ordered_physical_stripe_widths
            .iter()
            .filter(|width| **width == 64)
            .count(),
        1
    );
    assert_eq!(ledger.private_random_field_element_count, 2_817_024);
    assert_eq!(
        ledger.incremental_commitment_peak_live_byte_length,
        125_829_104
    );
    assert_eq!(ledger.monolithic_peak_live_byte_length, 503_316_416);
    assert_eq!(ledger.peak_live_byte_length, 327_155_696);
    assert!(ledger.peak_live_byte_length < NOMINAL_WASM_LINEAR_MEMORY_BYTE_LENGTH);

    assert_eq!(ledger.one_pass_encoded_field_element_count, 1_895_825_408);
    assert_eq!(
        ledger.complete_two_pass_encoded_field_element_count,
        3_791_650_816
    );
    assert_eq!(ledger.complete_two_pass_butterfly_count, 34_124_857_344);
    assert_eq!(ledger.complete_two_pass_salted_leaf_hash_count, 29_884_416);
    assert!(ledger.complete_two_pass_butterfly_count * 10 < SELECTED_VSS_COMPLETE_BUTTERFLY_COUNT);
    assert!(
        ledger.complete_two_pass_salted_leaf_hash_count * 10
            < SELECTED_VSS_COMPLETE_SALTED_LEAF_HASH_COUNT
    );

    assert_eq!(ledger.opened_row_byte_length, 22_737_408);
    assert_eq!(ledger.naive_authentication_path_byte_length, 25_805_952);
    assert!(
        ledger.opened_row_byte_length + ledger.naive_authentication_path_byte_length
            < 64 * 1024 * 1024
    );

    // For one flattened lookup column, the logarithmic-derivative identity is
    // a rational-function identity. If a committed quotient lies outside the
    // public table, its cross-multiplied numerator is nonzero and has degree
    // at most the exact numerator below. This is the load-bearing algebraic
    // term; the final certificate must add the masked-sumcheck and WHIR RBR
    // terms rather than calling this one comparison a complete proof.
    let challenge_field_order = candidate_lookup_challenge_field_order();
    assert_eq!(challenge_field_order.bits(), 320);
    assert!((BigUint::from(ledger.lookup_soundness_numerator) << 294_u32) < challenge_field_order);

    let adversarial_query_budget = (BigUint::from(1_u8)
        << CANDIDATE_ADVERSARIAL_QUERY_BUDGET_BIT_LENGTH)
        - BigUint::from(1_u8);
    let target_inverse_probability =
        BigUint::from(1_u8) << MOBILE_PROTOTYPE_INVALID_ACCEPTANCE_BIT_LENGTH;
    let outer_packet_count = BigUint::from(CANDIDATE_OUTER_PACKET_SCHEDULE_COUNT);
    let round_count = BigUint::from(CANDIDATE_INTERACTIVE_ROUND_COUNT_CEILING);
    let state_restoration_denominator = &outer_packet_count
        * BigUint::from(CDHZ_BCS_STATE_RESTORATION_MULTIPLIER)
        * BigUint::from(CDHZ_STATE_RESTORATION_CONSTANT)
        * (&adversarial_query_budget + &round_count + BigUint::from(1_u8))
        * (&adversarial_query_budget + &round_count)
        * &target_inverse_probability;
    let raw_rbr_numerator_capacity = &challenge_field_order / &state_restoration_denominator;
    assert!(BigUint::from(ledger.lookup_soundness_numerator) < raw_rbr_numerator_capacity);
}

#[test]
fn preferred_block_ten_lookup_has_direct_opening_randomization_and_bounded_work() {
    let ledger = preferred_compact_lookup_work_ledger();

    assert_eq!(ledger.quotient_entry_count, 16_220_160);
    assert_eq!(ledger.lookup_table_value_count, 295_245);
    assert_eq!(ledger.padded_lookup_table_entry_count, 327_680);
    assert_eq!(ledger.complete_inverse_element_count, 16_547_840);
    assert_eq!(ledger.lookup_soundness_numerator, 16_547_839);
    assert_eq!(ledger.pre_challenge_logical_column_count, 505);
    assert_eq!(ledger.inverse_helper_logical_column_count, 2_475);
    assert_eq!(ledger.logical_column_count, 2_980);
    assert_eq!(ledger.randomized_code_message_length, 65_536);
    assert_eq!(
        ledger.randomized_code_randomness_length_per_logical_column,
        CANDIDATE_LOOKUP_QUERY_COUNT
    );
    assert_eq!(ledger.encoded_row_count, 262_144);
    assert_eq!(ledger.ordered_physical_stripe_widths.len(), 24);
    assert_eq!(
        ledger
            .ordered_physical_stripe_widths
            .iter()
            .filter(|width| **width == 128)
            .count(),
        23
    );
    assert_eq!(
        ledger
            .ordered_physical_stripe_widths
            .iter()
            .filter(|width| **width == 64)
            .count(),
        1
    );
    assert_eq!(ledger.physical_column_count, 3_008);
    assert_eq!(ledger.private_random_field_element_count, 1_171_140);
    assert_eq!(
        ledger.incremental_commitment_peak_live_byte_length,
        125_829_104
    );
    assert_eq!(ledger.monolithic_peak_live_byte_length, 503_316_416);
    assert_eq!(ledger.peak_live_byte_length, 327_155_696);
    assert!(ledger.peak_live_byte_length < NOMINAL_WASM_LINEAR_MEMORY_BYTE_LENGTH);
    assert!(ledger.peak_live_byte_length < HARD_WASM_LINEAR_MEMORY_BYTE_LENGTH);

    assert_eq!(ledger.one_pass_encoded_field_element_count, 788_529_152);
    assert_eq!(
        ledger.complete_two_pass_encoded_field_element_count,
        1_577_058_304
    );
    assert_eq!(ledger.complete_two_pass_butterfly_count, 14_193_524_736);
    assert_eq!(ledger.complete_two_pass_salted_leaf_hash_count, 12_582_912);
    assert_eq!(ledger.opened_row_byte_length, 9_457_152);
    assert_eq!(ledger.naive_authentication_path_byte_length, 10_865_664);
    assert!(
        ledger.opened_row_byte_length + ledger.naive_authentication_path_byte_length
            < 64 * 1024 * 1024
    );

    // These random coefficients give every main-code column the CFW
    // t-query randomized-encoding property. They do not hide nonlinear R1CS
    // or sumcheck messages; those require the independently encoded masks
    // counted in the next lower-bound test and the still-uncompiled masks of
    // the constrained-code IOPP.
}

#[test]
fn public_key_lookup_and_r1cs_lower_bound_are_source_derived_before_prover_work() {
    let inventory = compact_public_key_packet_inventory();
    let ledger = compact_public_key_work_ledger();
    let mask_ledger = cfw_r1cs_mask_lower_bound_ledger(&ledger);

    assert_eq!(ledger.quotient_entry_count, 950_272);
    assert_eq!(ledger.lookup_table_value_count, 131_072);
    assert_eq!(ledger.padded_lookup_table_entry_count, 131_072);
    assert_eq!(ledger.complete_inverse_element_count, 1_081_344);
    assert_eq!(ledger.lookup_soundness_numerator, 1_081_343);

    // The first epoch consists of 44 source columns and 13 multiplication-
    // chain helpers for exact ternary/eta-two membership. The second epoch has
    // one quintic-extension inverse symbol for each of 29 quotients. Its five
    // canonical Goldilocks coordinates are physical representation, not five
    // independent R1CS variables.
    assert_eq!(inventory.pre_challenge_source_logical_column_count, 44);
    assert_eq!(
        inventory.small_set_multiplication_helper_logical_column_count,
        13
    );
    assert_eq!(ledger.pre_challenge_logical_column_count, 57);
    assert_eq!(ledger.inverse_helper_logical_column_count, 29);
    assert_eq!(ledger.logical_column_count, 86);
    assert_eq!(
        ledger.logical_column_count,
        inventory.r1cs_witness_logical_column_count
    );

    assert_eq!(ledger.ordered_physical_stripe_widths, vec![64, 32]);
    assert_eq!(ledger.physical_column_count, 96);
    assert_eq!(ledger.private_random_field_element_count, 33_798);
    assert_eq!(ledger.one_pass_encoded_field_element_count, 25_165_824);
    assert_eq!(
        ledger.complete_two_pass_encoded_field_element_count,
        50_331_648
    );
    assert_eq!(ledger.complete_two_pass_butterfly_count, 452_984_832);
    assert_eq!(ledger.complete_two_pass_salted_leaf_hash_count, 1_048_576);
    assert_eq!(ledger.opened_row_byte_length, 301_824);
    assert_eq!(ledger.naive_authentication_path_byte_length, 905_472);

    assert_eq!(mask_ledger.relation_base_field_element_count, 2_818_048);
    assert_eq!(mask_ledger.padded_r1cs_witness_element_count, 4_194_304);
    assert_eq!(mask_ledger.padded_public_input_element_count, 4_194_304);
    assert_eq!(mask_ledger.padded_r1cs_constraint_count, 8_388_608);
    assert_eq!(mask_ledger.r1cs_variable_count, 22);
    assert_eq!(mask_ledger.inner_mask_oracle_count, 552);
    assert_eq!(mask_ledger.outer_mask_oracle_count, 184);
    assert_eq!(mask_ledger.randomized_encoding_count_including_main, 737);
    assert_eq!(mask_ledger.mask_physical_column_count, 768);
    assert_eq!(mask_ledger.mask_commitment_root_count, 7);
    assert_eq!(mask_ledger.mask_opened_row_byte_length, 2_414_592);
    assert_eq!(
        mask_ledger.mask_naive_authentication_path_byte_length,
        1_936_704
    );
    assert_eq!(mask_ledger.sumcheck_non_oracle_message_byte_length, 13_504);

    let direct_root_count = u64::try_from(ledger.ordered_physical_stripe_widths.len())
        .expect("public-key direct root count fits u64");
    let known_component_naive_path_subtotal = ledger
        .opened_row_byte_length
        .checked_add(ledger.naive_authentication_path_byte_length)
        .and_then(|count| count.checked_add(mask_ledger.mask_opened_row_byte_length))
        .and_then(|count| count.checked_add(mask_ledger.mask_naive_authentication_path_byte_length))
        .and_then(|count| count.checked_add(mask_ledger.sumcheck_non_oracle_message_byte_length))
        .and_then(|count| {
            count.checked_add(
                (direct_root_count + mask_ledger.mask_commitment_root_count)
                    * CANDIDATE_MERKLE_DIGEST_BYTE_LENGTH,
            )
        })
        .expect("public-key known-component subtotal fits");
    assert_eq!(known_component_naive_path_subtotal, 5_572_672);
    assert!(known_component_naive_path_subtotal < AUTOMATIC_PROOF_BYTE_LENGTH);

    // This is the first source-derived static subtotal for schema 0x1212, not
    // a lower or upper bound on a complete proof. Naive authentication paths
    // can shrink in a canonical multiproof, while constrained-code/WHIR code-
    // switch masks, folds, framing, and the theorem cost of binding the two
    // oracle epochs can only be known after compilation. A prover is not
    // eligible until those terms come from one checked interactive catalog.
}

#[test]
fn cfw_r1cs_masks_are_an_explicit_lower_bound_beyond_direct_opening_randomization() {
    let lookup_ledger = preferred_compact_lookup_work_ledger();
    let mask_ledger = cfw_r1cs_mask_lower_bound_ledger(&lookup_ledger);

    assert_eq!(mask_ledger.relation_base_field_element_count, 97_648_640);
    assert_eq!(mask_ledger.padded_r1cs_witness_element_count, 134_217_728);
    assert_eq!(mask_ledger.padded_public_input_element_count, 134_217_728);
    assert_eq!(mask_ledger.padded_r1cs_constraint_count, 268_435_456);
    assert_eq!(mask_ledger.r1cs_variable_count, 27);
    assert_eq!(mask_ledger.rbr_repetition_count, 8);

    // CFW Theorem 11.3 requires 3(log2(ell) + 1) inner masks and
    // log2(ell) + 1 outer masks per R1CS repetition. Eight independently
    // masked base-field repetitions avoid turning the large main code into
    // extension-field symbols while leaving a conservative QROM reserve.
    assert_eq!(mask_ledger.inner_mask_oracle_count, 672);
    assert_eq!(mask_ledger.outer_mask_oracle_count, 224);
    assert_eq!(mask_ledger.randomized_encoding_count_including_main, 897);
    assert_eq!(mask_ledger.mask_code_encoded_row_count, 2_048);
    assert_eq!(mask_ledger.mask_physical_column_count, 928);
    assert_eq!(mask_ledger.mask_commitment_root_count, 8);
    assert_eq!(
        mask_ledger.mask_one_pass_encoded_field_element_count,
        1_900_544
    );
    assert_eq!(mask_ledger.mask_opened_row_byte_length, 2_917_632);
    assert_eq!(
        mask_ledger.mask_naive_authentication_path_byte_length,
        2_213_376
    );
    assert_eq!(mask_ledger.sumcheck_non_oracle_message_byte_length, 16_384);

    // This ledger covers only the R1CS reduction applied to the current
    // lookup core. CFW Theorem 10.2 adds code-switch mask oracles from the
    // exact WHIR stage parameters, and the production compiler can increase
    // the padded witness length. Neither quantity may be guessed here.
}

#[test]
fn one_quintic_cfw_run_is_the_theorem_minimizing_field_strategy() {
    // CFW Theorem 11.3's R1CS zero-knowledge argument requires a field whose
    // characteristic is not two. Goldilocks has odd prime characteristic.
    assert_ne!(GOLDILOCKS_BASE_FIELD_MODULUS % 2, 0);
    assert_eq!(
        usize::try_from(CANDIDATE_LOOKUP_EXTENSION_DEGREE).unwrap(),
        super::PROOF_CHALLENGE_EXTENSION_DEGREE
    );
    let public_key_lookup = compact_public_key_work_ledger();
    let public_key_masks =
        cfw_r1cs_mask_lower_bound_ledger_for_repetition_count(&public_key_lookup, 1);
    let public_key_strategy = cfw_field_strategy_static_ledger(
        &public_key_lookup,
        &public_key_masks,
        CANDIDATE_LOOKUP_EXTENSION_DEGREE,
        CANDIDATE_QUINTIC_EXTENSION_TRANSFORM_BATCH_WIDTH,
    );
    assert_eq!(public_key_masks.inner_mask_oracle_count, 69);
    assert_eq!(public_key_masks.outer_mask_oracle_count, 23);
    assert_eq!(
        public_key_masks.randomized_encoding_count_including_main,
        93
    );
    assert_eq!(public_key_masks.mask_physical_column_count, 160);
    assert_eq!(public_key_masks.mask_commitment_root_count, 2);
    assert_eq!(public_key_strategy.field_extension_degree, 5);
    assert_eq!(public_key_strategy.rbr_repetition_count, 1);
    assert_eq!(public_key_strategy.transform_batch_logical_column_count, 8);
    assert_eq!(
        public_key_strategy.incremental_commitment_peak_live_byte_length,
        150_994_928
    );
    assert_eq!(
        public_key_strategy.conservative_peak_live_byte_length,
        352_321_520
    );
    assert!(
        public_key_strategy.conservative_peak_live_byte_length
            < NOMINAL_WASM_LINEAR_MEMORY_BYTE_LENGTH
    );
    assert_eq!(
        public_key_strategy.main_complete_two_pass_base_coordinate_butterfly_count,
        2_264_924_160
    );
    assert_eq!(
        public_key_strategy.mask_one_pass_base_coordinate_element_count,
        1_638_400
    );
    assert_eq!(
        public_key_strategy.known_component_naive_path_subtotal_byte_length,
        5_491_832
    );
    assert_eq!(
        AUTOMATIC_PROOF_BYTE_LENGTH
            - public_key_strategy.known_component_naive_path_subtotal_byte_length,
        2_372_488
    );
    assert!(
        public_key_strategy.known_component_naive_path_subtotal_byte_length
            < ABSOLUTE_PROOF_PARSER_BYTE_LENGTH
    );

    let post_vss_lookup = preferred_compact_lookup_work_ledger();
    let post_vss_masks = cfw_r1cs_mask_lower_bound_ledger_for_repetition_count(&post_vss_lookup, 1);
    let post_vss_strategy = cfw_field_strategy_static_ledger(
        &post_vss_lookup,
        &post_vss_masks,
        CANDIDATE_LOOKUP_EXTENSION_DEGREE,
        CANDIDATE_QUINTIC_EXTENSION_TRANSFORM_BATCH_WIDTH,
    );
    assert_eq!(post_vss_masks.inner_mask_oracle_count, 84);
    assert_eq!(post_vss_masks.outer_mask_oracle_count, 28);
    assert_eq!(post_vss_masks.randomized_encoding_count_including_main, 113);
    assert_eq!(post_vss_masks.mask_physical_column_count, 160);
    assert_eq!(post_vss_masks.mask_commitment_root_count, 2);
    assert_eq!(
        post_vss_strategy.main_complete_two_pass_base_coordinate_butterfly_count,
        70_967_623_680
    );
    assert_eq!(
        post_vss_strategy.known_component_naive_path_subtotal_byte_length,
        61_231_872
    );
    assert_eq!(
        ABSOLUTE_PROOF_PARSER_BYTE_LENGTH
            - post_vss_strategy.known_component_naive_path_subtotal_byte_length,
        207_203_584
    );

    // The quintic extension is already the selected, irreducibility-checked
    // challenge field. Its one-run CFW instantiation avoids assuming that
    // eight shared-main-code base-field repetitions multiply RBR knowledge
    // error. These subtotals still exclude WHIR/code-switch masks, compact
    // multiproofs, the two-epoch lookup binding, and canonical framing. The
    // dominant packet must be segmented if those exact terms exhaust its
    // parser headroom.
}

#[test]
fn theorem_aligned_two_epoch_packets_have_a_bounded_single_quintic_path() {
    let public_key_packet = public_key_cfw_two_epoch_packet_static_ledger();

    assert_eq!(
        public_key_packet.padded_r1cs_witness_element_count,
        4_194_304
    );
    assert_eq!(public_key_packet.ring_vector_packing_factor, 1);
    assert_eq!(public_key_packet.main_interleaved_component_count, 128);
    assert_eq!(
        public_key_packet.relation_message_element_count_per_component,
        32_768
    );
    assert_eq!(public_key_packet.field_extension_degree, 5);
    assert_eq!(public_key_packet.transform_batch_logical_component_count, 8);
    assert_eq!(
        public_key_packet.populated_message_element_count_per_component,
        33_161
    );
    assert_eq!(public_key_packet.encoded_row_count, 131_072);
    assert_eq!(public_key_packet.minimum_distance_coordinate_count, 97_912);
    assert_eq!(
        public_key_packet.unique_decoding_radius_coordinate_count,
        48_955
    );
    assert_eq!(public_key_packet.pre_challenge_logical_component_count, 33);
    assert_eq!(public_key_packet.pre_challenge_physical_component_count, 64);
    assert_eq!(public_key_packet.pre_challenge_commitment_root_count, 1);
    assert_eq!(public_key_packet.cross_epoch_column_weight_count, 33);
    assert_eq!(
        public_key_packet.cross_epoch_multilinear_point_coordinate_count,
        15
    );
    assert_eq!(public_key_packet.cross_epoch_binding_error_numerator, 16);
    assert_eq!(
        public_key_packet.cross_epoch_explicit_point_opening_count,
        2
    );
    assert_eq!(
        public_key_packet.incremental_commitment_peak_live_byte_length,
        75_497_456
    );
    assert_eq!(
        public_key_packet.conservative_peak_live_byte_length,
        276_824_048
    );
    assert!(
        public_key_packet.conservative_peak_live_byte_length
            < NOMINAL_WASM_LINEAR_MEMORY_BYTE_LENGTH
    );
    assert_eq!(
        public_key_packet.main_complete_two_pass_base_coordinate_butterfly_count,
        1_426_063_360
    );
    assert_eq!(
        public_key_packet.pre_challenge_complete_two_pass_base_field_butterfly_count,
        142_606_336
    );
    assert_eq!(
        public_key_packet.complete_two_pass_base_coordinate_butterfly_count,
        1_568_669_696
    );
    assert_eq!(
        public_key_packet.known_component_naive_path_subtotal_byte_length,
        6_145_784
    );
    assert_eq!(
        public_key_packet.main_oracle_query_answer_byte_length,
        2_012_160
    );
    assert_eq!(
        AUTOMATIC_PROOF_BYTE_LENGTH
            - public_key_packet.known_component_naive_path_subtotal_byte_length,
        1_718_536
    );
    assert!(
        public_key_packet.known_component_naive_path_subtotal_byte_length
            < ABSOLUTE_PROOF_PARSER_BYTE_LENGTH
    );

    let post_vss_lookup = preferred_compact_lookup_work_ledger();
    let post_vss_masks = cfw_r1cs_mask_lower_bound_ledger_for_repetition_count(&post_vss_lookup, 1);
    let natural_ring_post_vss_packet = cfw_two_epoch_packet_static_ledger(
        &post_vss_lookup,
        &post_vss_masks,
        CANDIDATE_LOOKUP_EXTENSION_DEGREE,
        1,
    );
    assert_eq!(
        natural_ring_post_vss_packet.padded_r1cs_witness_element_count,
        134_217_728
    );
    assert_eq!(natural_ring_post_vss_packet.ring_vector_packing_factor, 1);
    assert_eq!(
        natural_ring_post_vss_packet.main_interleaved_component_count,
        4_096
    );
    assert_eq!(
        natural_ring_post_vss_packet.pre_challenge_logical_component_count,
        505
    );
    assert_eq!(
        natural_ring_post_vss_packet.pre_challenge_physical_component_count,
        512
    );
    assert_eq!(
        natural_ring_post_vss_packet.pre_challenge_commitment_root_count,
        4
    );
    assert_eq!(
        natural_ring_post_vss_packet.cross_epoch_column_weight_count,
        505
    );
    assert_eq!(
        natural_ring_post_vss_packet.main_complete_two_pass_base_coordinate_butterfly_count,
        45_634_027_520
    );
    assert_eq!(
        natural_ring_post_vss_packet.pre_challenge_complete_two_pass_base_field_butterfly_count,
        1_140_850_688
    );
    assert_eq!(
        natural_ring_post_vss_packet.complete_two_pass_base_coordinate_butterfly_count,
        46_774_878_208
    );
    assert_eq!(
        natural_ring_post_vss_packet.main_oracle_query_answer_byte_length,
        64_389_120
    );
    assert_eq!(
        natural_ring_post_vss_packet.known_component_naive_path_subtotal_byte_length,
        71_216_000
    );

    assert_eq!(
        natural_ring_post_vss_packet.conservative_peak_live_byte_length,
        276_824_048
    );
    assert!(
        natural_ring_post_vss_packet.known_component_naive_path_subtotal_byte_length
            < ABSOLUTE_PROOF_PARSER_BYTE_LENGTH
    );

    // The natural-ring interleaving is not the current static default: CFW
    // queries the original oracle over its complete alphabet, so its
    // 64,389,120 main-query bytes are unavoidable even when later code
    // switches are compact. That exceeds the soft proof target but remains
    // below the absolute parser bound, so it is an engineering tradeoff rather
    // than a cryptographic rejection.
    let post_vss_packet = factor_eight_post_vss_cfw_two_epoch_packet_static_ledger();
    assert_eq!(post_vss_packet.ring_vector_packing_factor, 8);
    assert_eq!(
        post_vss_packet.relation_message_element_count_per_component,
        262_144
    );
    assert_eq!(post_vss_packet.main_interleaved_component_count, 512);
    assert_eq!(
        post_vss_packet.populated_message_element_count_per_component,
        262_537
    );
    assert_eq!(post_vss_packet.encoded_row_count, 1_048_576);
    assert_eq!(post_vss_packet.transform_batch_logical_component_count, 1);
    assert_eq!(post_vss_packet.pre_challenge_logical_component_count, 64);
    assert_eq!(post_vss_packet.pre_challenge_physical_component_count, 64);
    assert_eq!(post_vss_packet.pre_challenge_commitment_root_count, 1);
    assert_eq!(post_vss_packet.cross_epoch_column_weight_count, 64);
    assert_eq!(
        post_vss_packet.cross_epoch_multilinear_point_coordinate_count,
        18
    );
    assert_eq!(post_vss_packet.cross_epoch_binding_error_numerator, 19);
    assert_eq!(
        post_vss_packet.incremental_commitment_peak_live_byte_length,
        310_378_480
    );
    assert_eq!(
        post_vss_packet.conservative_peak_live_byte_length,
        511_705_072
    );
    assert!(
        post_vss_packet.conservative_peak_live_byte_length
            < AUTOMATIC_WASM_LINEAR_MEMORY_BYTE_LENGTH
    );
    assert_eq!(
        post_vss_packet.main_complete_two_pass_base_coordinate_butterfly_count,
        53_687_091_200
    );
    assert_eq!(
        post_vss_packet.pre_challenge_complete_two_pass_base_field_butterfly_count,
        1_342_177_280
    );
    assert_eq!(
        post_vss_packet.complete_two_pass_base_coordinate_butterfly_count,
        55_029_268_480
    );
    assert_eq!(
        post_vss_packet.main_oracle_query_answer_byte_length,
        8_048_640
    );
    assert_eq!(
        post_vss_packet.known_component_naive_path_subtotal_byte_length,
        12_334_976
    );
    assert_eq!(
        ABSOLUTE_PROOF_PARSER_BYTE_LENGTH
            - post_vss_packet.known_component_naive_path_subtotal_byte_length,
        256_100_480
    );

    // Factor two materially lowers work and memory relative to the current
    // factor-eight default while retaining a parser-bounded answer. Factor four
    // is the balanced lower-memory comparator. Only the complete proof ledger
    // may select among these tradeoffs. Factor sixteen would halve the current
    // main answer again, but its direct retained commitment state breaches the
    // hard WebAssembly limit before any prover workspace.
    let lower_work_post_vss_packet = cfw_two_epoch_packet_static_ledger(
        &post_vss_lookup,
        &post_vss_masks,
        CANDIDATE_LOOKUP_EXTENSION_DEGREE,
        2,
    );
    assert_eq!(
        lower_work_post_vss_packet.main_interleaved_component_count,
        2_048
    );
    assert_eq!(lower_work_post_vss_packet.encoded_row_count, 262_144);
    assert_eq!(
        lower_work_post_vss_packet.pre_challenge_logical_component_count,
        253
    );
    assert_eq!(
        lower_work_post_vss_packet.pre_challenge_physical_component_count,
        256
    );
    assert_eq!(
        lower_work_post_vss_packet.pre_challenge_commitment_root_count,
        2
    );
    assert_eq!(
        lower_work_post_vss_packet.cross_epoch_column_weight_count,
        253
    );
    assert_eq!(
        lower_work_post_vss_packet.cross_epoch_multilinear_point_coordinate_count,
        16
    );
    assert_eq!(
        lower_work_post_vss_packet.cross_epoch_binding_error_numerator,
        17
    );
    assert_eq!(
        lower_work_post_vss_packet.conservative_peak_live_byte_length,
        310_378_480
    );
    assert_eq!(
        lower_work_post_vss_packet.complete_two_pass_base_coordinate_butterfly_count,
        49_526_341_632
    );
    assert_eq!(
        lower_work_post_vss_packet.main_oracle_query_answer_byte_length,
        32_194_560
    );
    assert_eq!(
        lower_work_post_vss_packet.known_component_naive_path_subtotal_byte_length,
        37_436_736
    );
    let lower_memory_post_vss_packet = cfw_two_epoch_packet_static_ledger(
        &post_vss_lookup,
        &post_vss_masks,
        CANDIDATE_LOOKUP_EXTENSION_DEGREE,
        4,
    );
    assert_eq!(
        lower_memory_post_vss_packet.conservative_peak_live_byte_length,
        377_487_344
    );
    assert_eq!(
        lower_memory_post_vss_packet.complete_two_pass_base_coordinate_butterfly_count,
        52_277_805_056
    );
    assert_eq!(
        lower_memory_post_vss_packet.main_oracle_query_answer_byte_length,
        16_097_280
    );
    assert_eq!(
        lower_memory_post_vss_packet.known_component_naive_path_subtotal_byte_length,
        20_534_528
    );
    let overwide_post_vss_packet = cfw_two_epoch_packet_static_ledger(
        &post_vss_lookup,
        &post_vss_masks,
        CANDIDATE_LOOKUP_EXTENSION_DEGREE,
        16,
    );
    assert_eq!(
        overwide_post_vss_packet.conservative_peak_live_byte_length,
        822_083_568
    );
    assert!(
        overwide_post_vss_packet.conservative_peak_live_byte_length
            > HARD_WASM_LINEAR_MEMORY_BYTE_LENGTH
    );

    // These are source-derived construction inputs, not a complete proof
    // ledger. The explicit-point equality reduction, structured R1CS matrix
    // evaluators, every CFW code switch and WHIR stage, compact multiproofs,
    // and the complete CDHZ/Merkle partition must still be compiled before a
    // prover is eligible. The result does rule out the former 2^18-row,
    // 2,980-column direct layout as the theorem's main-code geometry.
}

#[test]
fn lookup_challenge_follows_every_witness_independent_commitment() {
    assert_eq!(
        COMPACT_LOOKUP_TRANSCRIPT_CHRONOLOGY,
        [
            CompactLookupTranscriptOperation::CommitQuotientsAndMultiplicities,
            CompactLookupTranscriptOperation::SampleExtensionChallenge,
            CompactLookupTranscriptOperation::CommitCompleteR1csEncoding,
            CompactLookupTranscriptOperation::SampleCrossEpochColumnWeights,
            CompactLookupTranscriptOperation::SampleCrossEpochMultilinearPoint,
            CompactLookupTranscriptOperation::ReduceCrossEpochEqualityToExplicitPointOpenings,
            CompactLookupTranscriptOperation::EnterJointCfwWhirReduction,
            CompactLookupTranscriptOperation::DeriveSharedPcsQueriesAfterEveryPredecessor,
        ]
    );

    // Multiplicities must not be selected after seeing the challenge: one
    // challenge-point equality would then be solvable even for an invalid
    // quotient multiset. The complete R1CS encoding follows the challenge
    // because it contains reciprocal helpers. Its quotient and multiplicity
    // copies are bound back to the first-epoch message by challenges sampled
    // only after both commitment roots.
    assert!(
        COMPACT_LOOKUP_TRANSCRIPT_CHRONOLOGY
            .iter()
            .position(|operation| {
                *operation == CompactLookupTranscriptOperation::CommitQuotientsAndMultiplicities
            })
            < COMPACT_LOOKUP_TRANSCRIPT_CHRONOLOGY
                .iter()
                .position(|operation| {
                    *operation == CompactLookupTranscriptOperation::SampleExtensionChallenge
                })
    );
    assert!(
        COMPACT_LOOKUP_TRANSCRIPT_CHRONOLOGY
            .iter()
            .position(|operation| {
                *operation == CompactLookupTranscriptOperation::SampleExtensionChallenge
            })
            < COMPACT_LOOKUP_TRANSCRIPT_CHRONOLOGY
                .iter()
                .position(|operation| {
                    *operation == CompactLookupTranscriptOperation::CommitCompleteR1csEncoding
                })
    );
    assert!(
        COMPACT_LOOKUP_TRANSCRIPT_CHRONOLOGY
            .iter()
            .position(|operation| {
                *operation == CompactLookupTranscriptOperation::CommitCompleteR1csEncoding
            })
            < COMPACT_LOOKUP_TRANSCRIPT_CHRONOLOGY
                .iter()
                .position(|operation| {
                    *operation == CompactLookupTranscriptOperation::SampleCrossEpochColumnWeights
                })
    );
    assert!(
        COMPACT_LOOKUP_TRANSCRIPT_CHRONOLOGY
            .iter()
            .position(|operation| {
                *operation
                    == CompactLookupTranscriptOperation::ReduceCrossEpochEqualityToExplicitPointOpenings
            })
            < COMPACT_LOOKUP_TRANSCRIPT_CHRONOLOGY
                .iter()
                .position(|operation| {
                    *operation == CompactLookupTranscriptOperation::EnterJointCfwWhirReduction
                })
    );
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

    let ceilings = ProofApplicationSlotCeilings::derive(
        FOUNDATION_PROFILE.participant_count,
        1,
        1,
        SELECTED_MAXIMUM_CANDIDATE_PACKAGES_PER_ACTION,
    )
    .expect("selected proof-family ceilings derive");
    let inventory = ceilings
        .derive_proof_family_application_inventory(6, 7)
        .expect("selected proof-family inventory derives");

    let logical_relations_per_participant_packet = |epoch: RingNativeCandidateEpoch| -> u32 {
        RING_NATIVE_CANDIDATE_FAMILIES
            .iter()
            .filter(|family| family.epoch == epoch)
            .map(|family| {
                let family_inventory = inventory
                    .family_entry(family.application_statement_schema_identifier)
                    .expect("candidate family has production inventory");
                assert_eq!(
                    family_inventory.physical_proof_application_count(),
                    participant_count
                );
                family_inventory.logical_relation_instance_count() / participant_count
            })
            .sum()
    };

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
    assert_eq!(
        logical_relations_per_participant_packet(RingNativeCandidateEpoch::DealerVss),
        1
    );
    assert_eq!(
        logical_relations_per_participant_packet(RingNativeCandidateEpoch::AfterVerifiedVss),
        10
    );
    assert_eq!(
        logical_relations_per_participant_packet(
            RingNativeCandidateEpoch::AfterFrozenRoundOneAggregate
        ),
        1
    );
    assert_eq!(
        logical_relations_per_participant_packet(RingNativeCandidateEpoch::TargetRelease),
        1
    );

    let ballot_inventory = inventory
        .family_entry(ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER)
        .expect("ballot inventory exists");
    assert_eq!(
        ballot_inventory.physical_proof_application_count(),
        SELECTED_MAXIMUM_CANDIDATE_PACKAGES_PER_ACTION
    );
    assert_eq!(
        ballot_inventory.logical_relation_instance_count()
            / ballot_inventory.physical_proof_application_count(),
        1
    );

    // The 159-relation value describes the complete ceremony inventory, not
    // one packet or one participant operation. The post-VSS packet is the only
    // packet currently known to combine more than one logical relation. Its
    // committed-polynomial count remains a compiler output, not this count.
    assert_eq!(
        participant_count * (1 + 10 + 1 + 1) + SELECTED_MAXIMUM_CANDIDATE_PACKAGES_PER_ACTION + 9,
        159
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
fn preferred_block_ten_special_basis_has_complete_root_and_dominance_certificates() {
    assert_eq!(PREFERRED_CANDIDATE_SPECIAL_ROOT_PARAMETERS.len(), 6);
    assert_eq!(
        PREFERRED_CANDIDATE_SPECIAL_GROUP_PRIME_FACTORS.len(),
        PREFERRED_CANDIDATE_SPECIAL_ROOT_PARAMETERS.len()
    );
    for (roots, group_prime_factors) in PREFERRED_CANDIDATE_SPECIAL_ROOT_PARAMETERS
        .iter()
        .copied()
        .zip(PREFERRED_CANDIDATE_SPECIAL_GROUP_PRIME_FACTORS)
    {
        assert_eq!(u64::BITS - roots.modulus.leading_zeros(), 51);
        assert_eq!(roots.modulus % (2 * POLYNOMIAL_DEGREE as u64), 1);
        assert_eq!(roots.modulus % 257, 1);
        assert!(candidate_root_certificate_is_valid(
            roots,
            group_prime_factors
        ));
    }

    let candidate_special_moduli =
        PREFERRED_CANDIDATE_SPECIAL_ROOT_PARAMETERS.map(|roots| roots.modulus);
    assert_eq!(candidate_special_moduli, PREFERRED_CANDIDATE_SPECIAL_MODULI);
    let candidate_special_product = candidate_special_moduli
        .iter()
        .map(|modulus| BigUint::from(*modulus))
        .product::<BigUint>();
    let candidate_maximum_block_product =
        maximum_consecutive_block_product(&DATA_PRIMES, PREFERRED_CANDIDATE_KEY_SWITCH_BLOCK_WIDTH);
    assert_eq!(candidate_special_product.bits(), 306);
    assert_eq!(candidate_maximum_block_product.bits(), 305);
    assert!(candidate_special_product > candidate_maximum_block_product);

    let candidate_block_count = DATA_PRIMES
        .len()
        .div_ceil(PREFERRED_CANDIDATE_KEY_SWITCH_BLOCK_WIDTH);
    assert!(
        BigUint::from(candidate_block_count) * candidate_maximum_block_product
            < BigUint::from(2_u8) * candidate_special_product
    );

    // The special basis strictly dominates every data block, while the
    // conservative block-count-weighted approximation term remains below two.
    // This is not a substitute for the complete evaluator noise recurrence.
}

#[test]
fn preferred_block_ten_basis_replays_the_complete_evaluator_and_release_recurrence() {
    let candidate_special_moduli = PREFERRED_CANDIDATE_SPECIAL_MODULI;
    let participant_count = u64::from(FOUNDATION_PROFILE.participant_count);
    let ballot_count = usize::from(FOUNDATION_PROFILE.participant_count);
    let option_count = usize::from(FOUNDATION_PROFILE.option_count);
    let minimum_score = u64::from(FOUNDATION_PROFILE.minimum_score);
    let maximum_score = u64::from(FOUNDATION_PROFILE.maximum_score);

    let selected_bounds = direct_ballot_target_noise_bounds(
        participant_count,
        ballot_count,
        option_count,
        minimum_score,
        maximum_score,
    )
    .expect("selected evaluator recurrence derives");
    let candidate_bounds = direct_ballot_target_noise_bounds_for_key_switch_topology(
        participant_count,
        ballot_count,
        option_count,
        minimum_score,
        maximum_score,
        PREFERRED_CANDIDATE_KEY_SWITCH_BLOCK_WIDTH,
        &candidate_special_moduli,
    )
    .expect("candidate evaluator recurrence derives");

    assert_eq!(candidate_bounds.len(), selected_bounds.len());
    for (candidate, selected) in candidate_bounds.iter().zip(&selected_bounds) {
        assert_eq!(candidate.top_count, selected.top_count);
        for (candidate_target, selected_target) in [
            (&candidate.target_identifier, &selected.target_identifier),
            (&candidate.target_order, &selected.target_order),
        ] {
            assert_eq!(candidate_target.level, selected_target.level);
            assert_eq!(
                candidate_target.message_coefficient_bound,
                selected_target.message_coefficient_bound
            );
            assert!(candidate_target.minimum_decryption_margin.is_positive());
        }
    }

    let candidate_maximum_error = candidate_bounds
        .iter()
        .map(|bound| bound.maximum_error_coefficient_bound())
        .max()
        .cloned()
        .expect("candidate evaluator has target bounds");
    let selected_maximum_error = selected_bounds
        .iter()
        .map(|bound| bound.maximum_error_coefficient_bound())
        .max()
        .cloned()
        .expect("selected evaluator has target bounds");
    assert_eq!(candidate_maximum_error, BigUint::from(2_331_605_782_u64));
    assert!(candidate_maximum_error <= selected_maximum_error);

    let candidate_flooding_bound = factor_four_required_flooding_bound(&candidate_maximum_error)
        .expect("candidate flooding bound derives");
    assert_eq!(
        candidate_flooding_bound.to_str_radix(10),
        "48425557508880960588220213618157405536780288"
    );
    let release_trace = direct_ballot_target_release_noise_trace_for_key_switch_topology(
        DirectBallotTargetReleaseNoiseInput {
            participant_count,
            ballot_count,
            option_count,
            minimum_score,
            maximum_score,
            denominator_clearing_factor: KLLPS_DENOMINATOR_CLEARING_FACTOR,
            reconstruction_threshold: KLLPS_RECONSTRUCTION_THRESHOLD,
            maximum_authorized_coefficient_norm: MAXIMUM_AUTHORIZED_COEFFICIENT_NORM,
            flooding_coefficient_bound: &candidate_flooding_bound,
        },
        PREFERRED_CANDIDATE_KEY_SWITCH_BLOCK_WIDTH,
        &candidate_special_moduli,
    )
    .expect("candidate target-release recurrence derives");
    assert_eq!(release_trace.len(), 6);
    assert!(
        release_trace
            .iter()
            .all(|bound| bound.scaled_no_wrap_margin.is_positive())
    );
    assert_eq!(
        release_trace
            .iter()
            .map(|bound| &bound.scaled_no_wrap_margin)
            .min()
            .expect("candidate release trace has a margin")
            .to_str_radix(10),
        "4543364398166265061884015711662381158228153471672541944534292260771566183581"
    );
}

#[test]
fn preferred_block_ten_candidate_cuts_key_material_wire_and_resident_bytes() {
    let evaluator_candidate =
        EvaluatorCandidateInput::implemented().expect("selected evaluator candidate derives");
    let [relinearization_catalog_level] = evaluator_candidate.relinearization_levels.as_slice()
    else {
        panic!("the selected evaluator owns exactly one relinearization level");
    };

    let selected_relinearization_topology =
        KeySwitchDecompositionTopology::for_level(*relinearization_catalog_level)
            .expect("selected relinearization topology derives");
    let selected_full_component_wire_byte_length = selected_relinearization_topology
        .canonical_component_wire_byte_length(POLYNOMIAL_DEGREE)
        .expect("selected component wire length derives");
    let selected_full_component_resident_byte_length = selected_relinearization_topology
        .resident_component_byte_length(POLYNOMIAL_DEGREE)
        .expect("selected component resident length derives");
    let (candidate_full_component_wire_byte_length, candidate_full_component_resident_byte_length) =
        preferred_candidate_component_byte_lengths(*relinearization_catalog_level);

    let mut selected_galois_wire_byte_length = 0_u64;
    let mut selected_galois_resident_byte_length = 0_u64;
    let mut candidate_galois_wire_byte_length = 0_u64;
    let mut candidate_galois_resident_byte_length = 0_u64;
    for (_, catalog_level) in &evaluator_candidate.galois_key_schedule {
        let selected_topology = KeySwitchDecompositionTopology::for_level(*catalog_level)
            .expect("selected Galois topology derives");
        selected_galois_wire_byte_length += selected_topology
            .canonical_component_wire_byte_length(POLYNOMIAL_DEGREE)
            .expect("selected Galois wire length derives");
        selected_galois_resident_byte_length += selected_topology
            .resident_component_byte_length(POLYNOMIAL_DEGREE)
            .expect("selected Galois resident length derives");
        let (candidate_wire_byte_length, candidate_resident_byte_length) =
            preferred_candidate_component_byte_lengths(*catalog_level);
        candidate_galois_wire_byte_length += candidate_wire_byte_length;
        candidate_galois_resident_byte_length += candidate_resident_byte_length;
    }

    let selected_source_wire_byte_length =
        3 * selected_full_component_wire_byte_length + selected_galois_wire_byte_length;
    let selected_source_resident_byte_length =
        3 * selected_full_component_resident_byte_length + selected_galois_resident_byte_length;
    let selected_final_wire_byte_length =
        2 * selected_full_component_wire_byte_length + selected_galois_wire_byte_length;
    let selected_final_resident_byte_length =
        2 * selected_full_component_resident_byte_length + selected_galois_resident_byte_length;
    let candidate_source_wire_byte_length =
        3 * candidate_full_component_wire_byte_length + candidate_galois_wire_byte_length;
    let candidate_source_resident_byte_length =
        3 * candidate_full_component_resident_byte_length + candidate_galois_resident_byte_length;
    let candidate_final_wire_byte_length =
        2 * candidate_full_component_wire_byte_length + candidate_galois_wire_byte_length;
    let candidate_final_resident_byte_length =
        2 * candidate_full_component_resident_byte_length + candidate_galois_resident_byte_length;

    assert_eq!(selected_source_wire_byte_length, 183_631_872);
    assert_eq!(selected_source_resident_byte_length, 355_467_264);
    assert_eq!(selected_final_wire_byte_length, 155_582_464);
    assert_eq!(selected_final_resident_byte_length, 300_941_312);
    assert_eq!(candidate_source_wire_byte_length, 82_771_968);
    assert_eq!(candidate_source_resident_byte_length, 140_771_328);
    assert_eq!(candidate_final_wire_byte_length, 69_599_232);
    assert_eq!(candidate_final_resident_byte_length, 117_964_800);
    assert!(candidate_source_wire_byte_length * 2 < selected_source_wire_byte_length);
    assert!(candidate_final_wire_byte_length * 2 < selected_final_wire_byte_length);
    assert_eq!(
        10 * candidate_source_wire_byte_length + candidate_final_wire_byte_length,
        897_318_912
    );

    // These exact bytes close the topology arithmetic only. The pinned
    // estimator currently gives the candidate comfortable known-attack
    // diagnostic margin, and the complete noise recurrence passes. Production
    // selection still requires the explicit circular/KDM assumption boundary
    // and malicious-threshold joint auxiliary-input composition.
}

#[test]
fn compact_candidate_radix_geometry_is_derived_from_the_exact_bgv_basis() {
    let mut extended_basis = DATA_PRIMES.to_vec();
    extended_basis.extend(SPECIAL_PRIMES);

    assert_eq!(POLYNOMIAL_DEGREE, 32_768);
    assert_eq!(DATA_PRIMES.len(), 23);
    assert_eq!(SPECIAL_PRIMES.len(), 3);
    assert_eq!(modulus_product_bit_length(&DATA_PRIMES[..8]), 251);
    assert_eq!(modulus_product_bit_length(&DATA_PRIMES), 691);
    assert_eq!(modulus_product_bit_length(&SPECIAL_PRIMES), 115);
    assert_eq!(modulus_product_bit_length(&extended_basis), 805);

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

    let radix = BigUint::from(1_u8) << CANDIDATE_RADIX_DIGIT_BIT_LENGTH;
    let maximum_radix_digit = &radix - BigUint::from(1_u8);
    let maximum_limb_residue = BigUint::from(maximum_limb_modulus - 1);
    let maximum_limb_radix_digit_count = radix_digit_count(&maximum_limb_residue);
    assert_eq!(maximum_limb_radix_digit_count, 3);

    // For canonical a, b, and c modulo one physical RNS prime q, the integer
    // lift a*b-c=q*z in Z[X]/(X^N+1) has |z_i| below this quotient bound.
    // The compiler must encode its sign and prove every digit and carry range.
    let maximum_raw_convolution_magnitude =
        BigUint::from(POLYNOMIAL_DEGREE) * &maximum_limb_residue * &maximum_limb_residue;
    let maximum_reduction_quotient_magnitude = (&maximum_raw_convolution_magnitude
        + BigUint::from(2_u8) * &maximum_limb_residue)
        / BigUint::from(maximum_limb_modulus);
    let maximum_quotient_radix_digit_count =
        radix_digit_count(&maximum_reduction_quotient_magnitude);
    assert_eq!(maximum_reduction_quotient_magnitude.bits(), 54);
    assert_eq!(maximum_quotient_radix_digit_count, 4);

    // A radix diagonal of a negacyclic digit convolution contains at most N
    // products for each of three input-digit pairs. Its exact integer range,
    // plus the public-modulus product and propagated carry, remains far below
    // half the Goldilocks modulus. Field equality therefore cannot hide a
    // nonzero multiple of that modulus once the compiler proves these ranges.
    let maximum_digit_pair_count = maximum_limb_radix_digit_count;
    let maximum_digit_convolution_magnitude = BigUint::from(POLYNOMIAL_DEGREE)
        * BigUint::from(maximum_digit_pair_count)
        * &maximum_radix_digit
        * &maximum_radix_digit;
    let maximum_modulus_quotient_diagonal_magnitude =
        BigUint::from(maximum_limb_radix_digit_count.min(maximum_quotient_radix_digit_count))
            * &maximum_radix_digit
            * &maximum_radix_digit;
    let mut maximum_carry_magnitude = BigUint::from(0_u8);
    let reduction_digit_position_count =
        maximum_limb_radix_digit_count + maximum_quotient_radix_digit_count;
    let goldilocks_half_modulus = BigUint::from(GOLDILOCKS_BASE_FIELD_MODULUS / 2);
    for _ in 0..reduction_digit_position_count {
        let maximum_recurrence_magnitude = &maximum_digit_convolution_magnitude
            + &maximum_modulus_quotient_diagonal_magnitude
            + &maximum_radix_digit
            + &maximum_carry_magnitude;
        assert!(maximum_recurrence_magnitude < goldilocks_half_modulus);
        maximum_carry_magnitude = (&maximum_recurrence_magnitude + &maximum_radix_digit) / &radix;
    }
    assert_eq!(maximum_digit_convolution_magnitude.bits(), 49);
    assert_eq!(maximum_carry_magnitude.bits(), 33);

    let selected_flooding_bound =
        selected_target_decryption_flooding_bound().expect("selected flooding bound derives");
    assert_eq!(selected_flooding_bound.bits(), 146);
    assert_eq!(radix_digit_count(&selected_flooding_bound), 10);

    assert!(
        RING_NATIVE_CANDIDATE_FAMILIES
            .iter()
            .all(|family| { !family.required_capabilities.is_empty() })
    );
}

#[test]
fn single_quintic_candidate_has_conditional_cdhz_qrom_capacity() {
    // CDHZ Theorem 6.9 gives
    // 80*(t+k+1)*(w+k)*epsilon_RBR + (t+k+1)*k/2^r_min.
    // The adaptive BCS theorem charges four times that state-restoration term.
    // This exact capacity calculation unions 60 outer packets and assigns the
    // complete 2^-80 budget to this one term. It is deliberately optimistic:
    // selection still requires the compiler-derived RBR numerator, exact round
    // count, Merkle terms, masking loss, and complete ceremony partition.
    let adversarial_query_budget = (BigUint::from(1_u8)
        << CANDIDATE_ADVERSARIAL_QUERY_BUDGET_BIT_LENGTH)
        - BigUint::from(1_u8);
    let target_inverse_probability =
        BigUint::from(1_u8) << MOBILE_PROTOTYPE_INVALID_ACCEPTANCE_BIT_LENGTH;
    let outer_packet_count = BigUint::from(CANDIDATE_OUTER_PACKET_SCHEDULE_COUNT);
    let round_count = BigUint::from(CANDIDATE_INTERACTIVE_ROUND_COUNT_CEILING);
    // The selected hypothesis uses one R1CS/CFW/WHIR execution over the
    // irreducibility-checked quintic field. This is a field, so it avoids the
    // unproved claim that parallel base-field executions sharing one main code
    // multiply their round-by-round knowledge error.
    let challenge_field_order = candidate_lookup_challenge_field_order();
    let state_restoration_denominator = &outer_packet_count
        * BigUint::from(CDHZ_BCS_STATE_RESTORATION_MULTIPLIER)
        * BigUint::from(CDHZ_STATE_RESTORATION_CONSTANT)
        * (&adversarial_query_budget + &round_count + BigUint::from(1_u8))
        * (&adversarial_query_budget + &round_count)
        * &target_inverse_probability;
    let raw_rbr_numerator_capacity = &challenge_field_order / &state_restoration_denominator;

    assert_eq!(challenge_field_order.bits(), 320);
    assert_eq!(raw_rbr_numerator_capacity.bits(), 66);

    // Use the complete lookup numerator as a deliberately conservative
    // placeholder for the still-uncompiled RBR numerator. The single quintic
    // field leaves between 41 and 42 bits of state-term-only reserve beyond
    // that placeholder. This is capacity, not a soundness certificate: the
    // generated CFW/WHIR error vector and every positive Merkle and ceremony
    // term must replace the placeholder before selection.
    let conservative_rbr_numerator_placeholder =
        BigUint::from(preferred_compact_lookup_work_ledger().lookup_soundness_numerator);
    assert!((&conservative_rbr_numerator_placeholder << 41_u32) < raw_rbr_numerator_capacity);
    assert!((&conservative_rbr_numerator_placeholder << 42_u32) >= raw_rbr_numerator_capacity);

    let minimum_round_randomness_term_denominator = &outer_packet_count
        * BigUint::from(CDHZ_BCS_STATE_RESTORATION_MULTIPLIER)
        * (&adversarial_query_budget + &round_count + BigUint::from(1_u8))
        * &round_count
        * &target_inverse_probability;
    assert!(challenge_field_order > minimum_round_randomness_term_denominator);
}

#[test]
fn compact_candidate_single_stripe_sensitivity_fits_the_wasm_memory_policy() {
    let public_key_ledger = compact_public_key_work_ledger();
    let encoded_row_count = CANDIDATE_RANDOMIZED_CODE_MESSAGE_LENGTH * CANDIDATE_INVERSE_RATE;
    let bytes_per_encoded_base_field_column = encoded_row_count * 8;
    let complete_binary_tree_byte_length =
        (2 * encoded_row_count - 1) * CANDIDATE_MERKLE_DIGEST_BYTE_LENGTH;
    let stripe_matrix_byte_length =
        candidate_stripe_matrix_byte_length(CANDIDATE_LOGICAL_COLUMN_STRIPE_WIDTH);
    let stripe_peak_live_byte_length = stripe_matrix_byte_length
        + complete_binary_tree_byte_length
        + CANDIDATE_NON_MATRIX_WORKSPACE_BYTE_LENGTH;

    assert_eq!(encoded_row_count, 262_144);
    assert_eq!(bytes_per_encoded_base_field_column, 2_097_152);
    assert_eq!(stripe_matrix_byte_length, 268_435_456);
    assert_eq!(complete_binary_tree_byte_length, 33_554_368);
    assert_eq!(stripe_peak_live_byte_length, 503_316_416);
    assert!(stripe_peak_live_byte_length > NOMINAL_WASM_LINEAR_MEMORY_BYTE_LENGTH);
    assert!(stripe_peak_live_byte_length < AUTOMATIC_WASM_LINEAR_MEMORY_BYTE_LENGTH);

    let low_memory_stripe_peak_live_byte_length =
        candidate_stripe_matrix_byte_length(CANDIDATE_LOW_MEMORY_LOGICAL_COLUMN_STRIPE_WIDTH)
            + complete_binary_tree_byte_length
            + CANDIDATE_NON_MATRIX_WORKSPACE_BYTE_LENGTH;
    assert_eq!(low_memory_stripe_peak_live_byte_length, 369_098_688);
    assert!(low_memory_stripe_peak_live_byte_length < NOMINAL_WASM_LINEAR_MEMORY_BYTE_LENGTH);

    let transform_batch_matrix_byte_length =
        candidate_stripe_matrix_byte_length(CANDIDATE_TRANSFORM_BATCH_WIDTH);
    let replay_column_byte_length = encoded_row_count * 8;
    let hash_state_byte_length = encoded_row_count * CANDIDATE_SHAKE256_STATE_BYTE_LENGTH;
    let twiddle_byte_length = 2 * (encoded_row_count - 1) * 8;
    let incremental_commitment_peak_live_byte_length = transform_batch_matrix_byte_length
        + replay_column_byte_length
        + hash_state_byte_length
        + twiddle_byte_length;
    let incremental_complete_peak_live_byte_length =
        incremental_commitment_peak_live_byte_length + CANDIDATE_NON_MATRIX_WORKSPACE_BYTE_LENGTH;
    assert_eq!(transform_batch_matrix_byte_length, 67_108_864);
    assert_eq!(replay_column_byte_length, 2_097_152);
    assert_eq!(hash_state_byte_length, 52_428_800);
    assert_eq!(twiddle_byte_length, 4_194_288);
    assert_eq!(incremental_commitment_peak_live_byte_length, 125_829_104);
    assert_eq!(incremental_complete_peak_live_byte_length, 327_155_696);
    assert!(incremental_complete_peak_live_byte_length < NOMINAL_WASM_LINEAR_MEMORY_BYTE_LENGTH);

    let monolithic_sensitivity_peak_live_byte_length =
        candidate_stripe_matrix_byte_length(public_key_ledger.physical_column_count)
            + complete_binary_tree_byte_length
            + CANDIDATE_NON_MATRIX_WORKSPACE_BYTE_LENGTH;
    assert_eq!(monolithic_sensitivity_peak_live_byte_length, 436_207_552);
    assert!(monolithic_sensitivity_peak_live_byte_length < HARD_WASM_LINEAR_MEMORY_BYTE_LENGTH);

    let required_stripe_count = public_key_ledger.ordered_physical_stripe_widths.len();
    assert_eq!(required_stripe_count, 2);
    assert_eq!(
        public_key_ledger.ordered_physical_stripe_widths,
        vec![64, 32]
    );

    let encoded_base_field_byte_length = encoded_row_count * 8;
    let total_physical_matrix_byte_length =
        encoded_base_field_byte_length * public_key_ledger.physical_column_count;
    assert_eq!(total_physical_matrix_byte_length, 201_326_592);

    // This is a liveness envelope, not a PCS proof or a selected width. The
    // packet compiler must derive its real columns, all stripe roots must be
    // bound before shared queries, and deterministic recomputation must match
    // the committed roots and canonical openings byte for byte.
}
