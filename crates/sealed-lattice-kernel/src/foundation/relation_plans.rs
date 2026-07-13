use std::mem::size_of;

use super::schemas::{
    SchemaResult, read_hash, read_hash_list, require_header,
};
use super::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple,
    FoundationSchemaError, Hash512, ProofFamily, ProofProfileSet, RefusalReason, SuiteRecord,
};

mod canonical_relation_plan;

use canonical_relation_plan::CanonicalRelationPlan;
use super::suite_record::modular_power;

pub const COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER: u16 = 0x1213;
pub const RELATION_PLAN_SCHEMA_IDENTIFIER: u16 = 0x2204;
pub const RELATION_PLAN_VARIANT_SCHEMA_IDENTIFIER: u16 = 0x2205;

const RELATION_SCHEMA_VERSION: u16 = 1;
const RELATION_PLAN_MAXIMUM_BYTE_LENGTH: usize = 65_536;
const SUITE_MODULUS_REFERENCE_SCHEMA_IDENTIFIER: u16 = 0x220e;
const RELATION_COLUMN_DESCRIPTOR_SCHEMA_IDENTIFIER: u16 = 0x2206;
const PROOF_CREATED_TREE_DESCRIPTOR_SCHEMA_IDENTIFIER: u16 = 0x2207;
const BOUND_PUBLIC_TREE_DESCRIPTOR_SCHEMA_IDENTIFIER: u16 = 0x2208;
const RELATION_CONSTRAINT_DESCRIPTOR_SCHEMA_IDENTIFIER: u16 = 0x2209;
const RELATION_OPENING_POINT_DESCRIPTOR_SCHEMA_IDENTIFIER: u16 = 0x220a;
const RELATION_OPENING_CLAIM_DESCRIPTOR_SCHEMA_IDENTIFIER: u16 = 0x220b;
const RELATION_MASK_DESCRIPTOR_SCHEMA_IDENTIFIER: u16 = 0x220c;
const RELATION_PUBLIC_SAMPLER_DESCRIPTOR_SCHEMA_IDENTIFIER: u16 = 0x220f;
const RELATION_APPLICATION_STATEMENT_SOURCE_DESCRIPTOR_SCHEMA_IDENTIFIER: u16 = 0x2220;
const RELATION_PROTOCOL_SOURCE_DESCRIPTOR_SCHEMA_IDENTIFIER: u16 = 0x2221;
const RELATION_SUITE_SOURCE_DESCRIPTOR_SCHEMA_IDENTIFIER: u16 = 0x2222;
const RELATION_APPLICATION_SLOT_SOURCE_DESCRIPTOR_SCHEMA_IDENTIFIER: u16 = 0x2223;
const RELATION_SAMPLER_OUTPUT_SOURCE_DESCRIPTOR_SCHEMA_IDENTIFIER: u16 = 0x2224;
const RELATION_SELECTOR_PATH_STEP_SCHEMA_IDENTIFIER: u16 = 0x2225;
const RELATION_VALUE_LAYOUT_SCHEMA_IDENTIFIER: u16 = 0x2226;
const RELATION_VERIFIER_SEQUENCE_COLUMN_ORIGIN_SCHEMA_IDENTIFIER: u16 = 0x2227;
const RELATION_BOUND_TREE_COLUMN_ORIGIN_SCHEMA_IDENTIFIER: u16 = 0x2228;
const RELATION_PROVER_COLUMN_ORIGIN_SCHEMA_IDENTIFIER: u16 = 0x2229;
const RELATION_ROOT_COMPATIBILITY_EDGE_SCHEMA_IDENTIFIER: u16 = 0x222a;
const RELATION_ROOT_ENDPOINT_SCHEMA_IDENTIFIER: u16 = 0x222b;
const RELATION_BASE_FIELD_CONSTANT_SCHEMA_IDENTIFIER: u16 = 0x2210;
const RELATION_EVALUATION_VARIABLE_SCHEMA_IDENTIFIER: u16 = 0x2211;
const RELATION_COLUMN_VALUE_SCHEMA_IDENTIFIER: u16 = 0x2212;
const RELATION_TRANSCRIPT_CHALLENGE_SCHEMA_IDENTIFIER: u16 = 0x2213;
const RELATION_ADDITION_SCHEMA_IDENTIFIER: u16 = 0x2214;
const RELATION_MULTIPLICATION_SCHEMA_IDENTIFIER: u16 = 0x2215;
const RELATION_NEGATION_SCHEMA_IDENTIFIER: u16 = 0x2216;
const RELATION_NONNEGATIVE_POWER_SCHEMA_IDENTIFIER: u16 = 0x2217;
const RELATION_FROBENIUS_CONJUGATE_SCHEMA_IDENTIFIER: u16 = 0x2218;

const PUBLIC_ONLY_DETERMINISTIC_PROOF_PRIVACY_MODE: u16 = 1;
const DATA_MODULUS_CATALOG: u16 = 1;
const HASH_VALUE_LAYOUT_ELEMENT_KIND: u16 = 1;
const NO_VALUE_LAYOUT_EMBEDDING: u16 = 0;
const BASE_FIELD_COLUMN_VALUE_TYPE: u16 = 1;
const SETUP_POLYNOMIAL_CONSTRUCTION_KIND: u16 = 2;
const INPUT_ROOT_USE: u16 = 1;
const OUTPUT_ROOT_USE: u16 = 2;
const TREE_COLUMN_OPENING_SOURCE_CLASS: u16 = 1;
const QUOTIENT_OPENING_SOURCE_CLASS: u16 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectivePublicKeyAggregateStatement {
    pub setup_proof_context_hash: Hash512,
    pub ordered_public_key_share_roots: Vec<Hash512>,
    pub collective_public_key_root: Hash512,
    pub collective_public_key_full_object_digest: Hash512,
}

impl CollectivePublicKeyAggregateStatement {
    pub fn new(
        setup_proof_context_hash: Hash512,
        ordered_public_key_share_roots: Vec<Hash512>,
        collective_public_key_root: Hash512,
        collective_public_key_full_object_digest: Hash512,
    ) -> SchemaResult<Self> {
        if ordered_public_key_share_roots.is_empty() {
            return Err(schema_error(
                RefusalReason::OutsideSupportedProfile,
                "collective public-key aggregate statement must contain source-share roots",
            ));
        }
        Ok(Self {
            setup_proof_context_hash,
            ordered_public_key_share_roots,
            collective_public_key_root,
            collective_public_key_full_object_digest,
        })
    }

    pub fn validate_for_suite(&self, suite_record: &SuiteRecord) -> SchemaResult<()> {
        suite_record.validate_intrinsic()?;
        if self.ordered_public_key_share_roots.len() != usize::from(suite_record.roster_size) {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "collective public-key aggregate source-root count must match the suite roster",
            ));
        }
        Ok(())
    }

    fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
        if self.ordered_public_key_share_roots.is_empty() {
            return Err(schema_error(
                RefusalReason::OutsideSupportedProfile,
                "collective public-key aggregate statement must contain source-share roots",
            ));
        }
        Ok(CanonicalTuple::new(
            COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            RELATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::hash512(self.setup_proof_context_hash.into_bytes()),
                encode_hash_list(&self.ordered_public_key_share_roots)?,
                CanonicalItem::hash512(self.collective_public_key_root.into_bytes()),
                CanonicalItem::hash512(
                    self.collective_public_key_full_object_digest.into_bytes(),
                ),
            ],
        ))
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple()?.encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        require_header(
            &tuple,
            COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            4,
        )?;
        Self::new(
            read_hash(&tuple.items[0])?,
            read_hash_list(&tuple.items[1])?,
            read_hash(&tuple.items[2])?,
            read_hash(&tuple.items[3])?,
        )
    }
}

/// The verifier-source and bound-root slice of the public-key-share relation.
///
/// This is deliberately not a relation plan and cannot be encoded as one. It records only the
/// public sources and reusable setup-polynomial roots whose layouts are already fixed by the
/// public-key-share statement and the lattice-commitment profile. The secret witness columns,
/// constraints, openings, masks, and degree certificates must be added before schema `0x1212`
/// can enter a proof-profile set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PublicKeyShareRelationRootStructure {
    lattice_commitment_profile: LatticeCommitmentProfile,
    ordered_verifier_sources: Vec<CanonicalTuple>,
    ordered_columns: Vec<CanonicalTuple>,
    ordered_trees: Vec<CanonicalTuple>,
    anchor_root_source_ordinals: Vec<u32>,
    public_key_share_root_source_ordinal: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublicKeyShareRootSourceIdentity {
    Anchor(usize),
    PublicKeyShare,
}

impl PublicKeyShareRelationRootStructure {
    pub(crate) fn from_suite_artifact(
        suite_record: &SuiteRecord,
        proof_profile_set: &ProofProfileSet,
        canonical_lattice_commitment_profile_bytes: Option<&[u8]>,
        limits: &CanonicalDecodeLimits,
    ) -> SchemaResult<Self> {
        suite_record.validate_intrinsic()?;
        let canonical_lattice_commitment_profile_bytes =
            canonical_lattice_commitment_profile_bytes.ok_or_else(|| {
                schema_error(
                    RefusalReason::MissingPrerequisite,
                    "lattice-commitment profile bytes are required to derive the public-key-share relation",
                )
            })?;
        let lattice_commitment_profile_reference = suite_record
            .artifacts
            .iter()
            .find(|reference| {
                reference.artifact_kind == ArtifactKind::LatticeCommitmentProfile
            })
            .ok_or_else(|| {
                schema_error(
                    RefusalReason::WrongContext,
                    "suite record is missing its lattice-commitment profile reference",
                )
            })?;
        let lattice_commitment_profile = LatticeCommitmentProfile::decode_verified_artifact(
            lattice_commitment_profile_reference,
            canonical_lattice_commitment_profile_bytes,
            limits,
            suite_record,
        )?;
        Self::for_candidate_suite(
            suite_record,
            proof_profile_set,
            &lattice_commitment_profile,
        )
    }

    pub(crate) fn for_candidate_suite(
        suite_record: &SuiteRecord,
        proof_profile_set: &ProofProfileSet,
        lattice_commitment_profile: &LatticeCommitmentProfile,
    ) -> SchemaResult<Self> {
        suite_record.validate_intrinsic()?;
        proof_profile_set.validate_for_suite(suite_record)?;
        lattice_commitment_profile.validate_for_suite(suite_record)?;
        let commitment_module_rank = lattice_commitment_profile.commitment_module_rank;
        let ordered_commitment_data_prime_indexes =
            &lattice_commitment_profile.ordered_commitment_data_prime_indexes;
        let (proof_field, _) =
            proof_profile_set.field_and_schedule_for_family(ProofFamily::PublicKeyShare)?;
        let trace_domain_size = u64::from(suite_record.polynomial_degree);

        let commitment_module_rank_as_usize = usize::from(commitment_module_rank);
        let matrix_source_count_per_prime = commitment_module_rank_as_usize
            .checked_mul(
                commitment_module_rank_as_usize
                    .checked_add(1)
                    .ok_or_else(|| {
                        schema_error(
                            RefusalReason::OutsideSupportedProfile,
                            "public-key-share commitment matrix width overflows",
                        )
                    })?,
            )
            .and_then(|first_matrix_count| {
                first_matrix_count.checked_add(commitment_module_rank_as_usize)
            })
            .ok_or_else(|| {
                schema_error(
                    RefusalReason::OutsideSupportedProfile,
                    "public-key-share commitment matrix source count overflows",
                )
            })?;
        let verifier_source_count = matrix_source_count_per_prime
            .checked_mul(ordered_commitment_data_prime_indexes.len())
            .and_then(|count| count.checked_add(suite_record.ordered_data_primes.len()))
            .and_then(|count| count.checked_add(ordered_commitment_data_prime_indexes.len()))
            .and_then(|count| count.checked_add(1))
            .ok_or_else(|| {
                schema_error(
                    RefusalReason::OutsideSupportedProfile,
                    "public-key-share verifier-source count overflows",
                )
            })?;
        if verifier_source_count
            .checked_mul(8)
            .is_none_or(|minimum_bytes| minimum_bytes > RELATION_PLAN_MAXIMUM_BYTE_LENGTH)
        {
            return Err(schema_error(
                RefusalReason::OutsideSupportedProfile,
                "public-key-share verifier-source catalog cannot fit a relation plan",
            ));
        }

        let mut source_entries = Vec::with_capacity(verifier_source_count);
        for anchor_position in 0..ordered_commitment_data_prime_indexes.len() {
            let source = application_statement_hash_source(
                3,
                Some(u64::try_from(anchor_position).map_err(|_| {
                    schema_error(
                        RefusalReason::OutsideSupportedProfile,
                        "public-key-share anchor position does not fit u64",
                    )
                })?),
            )?;
            source_entries.push((
                Some(PublicKeyShareRootSourceIdentity::Anchor(anchor_position)),
                source.encode()?,
                source,
            ));
        }
        let public_key_share_root_source = application_statement_hash_source(4, None)?;
        source_entries.push((
            Some(PublicKeyShareRootSourceIdentity::PublicKeyShare),
            public_key_share_root_source.encode()?,
            public_key_share_root_source,
        ));

        for commitment_data_prime_index in ordered_commitment_data_prime_indexes {
            let modulus_index = *commitment_data_prime_index;
            for row in 0..commitment_module_rank {
                for column in 0..=commitment_module_rank {
                    let source = protocol_polynomial_source(
                        COMMITMENT_MATRIX_SOURCE_KIND,
                        &[
                            u64::from(modulus_index),
                            FIRST_COMMITMENT_MATRIX_PART,
                            u64::from(row),
                            u64::from(column),
                        ],
                        modulus_index,
                        trace_domain_size,
                    )?;
                    source_entries.push((None, source.encode()?, source));
                }
            }
            for column in 0..commitment_module_rank {
                let source = protocol_polynomial_source(
                    COMMITMENT_MATRIX_SOURCE_KIND,
                    &[
                        u64::from(modulus_index),
                        SECOND_COMMITMENT_MATRIX_PART,
                        0,
                        u64::from(column),
                    ],
                    modulus_index,
                    trace_domain_size,
                )?;
                source_entries.push((None, source.encode()?, source));
            }
        }
        for data_prime_index in 0..suite_record.ordered_data_primes.len() {
            let modulus_index = index_as_u16(data_prime_index)?;
            let source = protocol_polynomial_source(
                COLLECTIVE_PUBLIC_KEY_COMMON_POLYNOMIAL_SOURCE_KIND,
                &[u64::from(modulus_index)],
                modulus_index,
                trace_domain_size,
            )?;
            source_entries.push((None, source.encode()?, source));
        }

        source_entries.sort_by(|left, right| left.1.cmp(&right.1));
        if source_entries
            .windows(2)
            .any(|pair| pair[0].1 >= pair[1].1)
            || source_entries
                .iter()
                .try_fold(0usize, |byte_count, entry| {
                    byte_count.checked_add(entry.1.len())
                })
                .is_none_or(|byte_count| byte_count > RELATION_PLAN_MAXIMUM_BYTE_LENGTH)
        {
            return Err(schema_error(
                RefusalReason::OutsideSupportedProfile,
                "public-key-share verifier-source catalog is duplicate or too large",
            ));
        }

        let mut anchor_root_source_ordinals =
            vec![u32::MAX; ordered_commitment_data_prime_indexes.len()];
        let mut public_key_share_root_source_ordinal = None;
        for (source_ordinal, (identity, _, _)) in source_entries.iter().enumerate() {
            let source_ordinal = index_as_u32(source_ordinal)?;
            match identity {
                Some(PublicKeyShareRootSourceIdentity::Anchor(anchor_position)) => {
                    anchor_root_source_ordinals[*anchor_position] = source_ordinal;
                }
                Some(PublicKeyShareRootSourceIdentity::PublicKeyShare) => {
                    public_key_share_root_source_ordinal = Some(source_ordinal);
                }
                None => {}
            }
        }
        if anchor_root_source_ordinals
            .iter()
            .any(|source_ordinal| *source_ordinal == u32::MAX)
        {
            return Err(schema_error(
                RefusalReason::WrongContext,
                "public-key-share anchor root source was lost during canonical ordering",
            ));
        }
        let public_key_share_root_source_ordinal =
            public_key_share_root_source_ordinal.ok_or_else(|| {
                schema_error(
                    RefusalReason::WrongContext,
                    "public-key-share output root source was lost during canonical ordering",
                )
            })?;
        let ordered_verifier_sources = source_entries
            .into_iter()
            .map(|(_, _, source)| source)
            .collect::<Vec<_>>();

        let anchor_column_count = ordered_commitment_data_prime_indexes
            .len()
            .checked_mul(
                commitment_module_rank_as_usize
                    .checked_add(1)
                    .ok_or_else(|| {
                        schema_error(
                            RefusalReason::OutsideSupportedProfile,
                            "public-key-share anchor width overflows",
                        )
                    })?,
            )
            .ok_or_else(|| {
                schema_error(
                    RefusalReason::OutsideSupportedProfile,
                    "public-key-share anchor column count overflows",
                )
            })?;
        let total_column_count = anchor_column_count
            .checked_add(suite_record.ordered_data_primes.len())
            .ok_or_else(|| {
                schema_error(
                    RefusalReason::OutsideSupportedProfile,
                    "public-key-share bound column count overflows",
                )
            })?;
        let mut ordered_columns = Vec::with_capacity(total_column_count);
        let mut ordered_trees =
            Vec::with_capacity(ordered_commitment_data_prime_indexes.len() + 1);
        for source_ordinal in &anchor_root_source_ordinals {
            append_bound_public_polynomial_tree(
                &mut ordered_columns,
                &mut ordered_trees,
                *source_ordinal,
                INPUT_ROOT_USE,
                commitment_module_rank_as_usize + 1,
                trace_domain_size,
            )?;
        }
        append_bound_public_polynomial_tree(
            &mut ordered_columns,
            &mut ordered_trees,
            public_key_share_root_source_ordinal,
            OUTPUT_ROOT_USE,
            suite_record.ordered_data_primes.len(),
            trace_domain_size,
        )?;

        let partial_canonical_byte_length = ordered_verifier_sources
            .iter()
            .chain(&ordered_columns)
            .chain(&ordered_trees)
            .try_fold(0usize, |byte_length, tuple| {
                byte_length.checked_add(tuple.encode()?.len()).ok_or_else(|| {
                    schema_error(
                        RefusalReason::OutsideSupportedProfile,
                        "public-key-share root structure byte length overflows",
                    )
                })
            })?;
        if partial_canonical_byte_length > RELATION_PLAN_MAXIMUM_BYTE_LENGTH {
            return Err(schema_error(
                RefusalReason::OutsideSupportedProfile,
                "public-key-share root structure cannot fit a relation plan",
            ));
        }

        validate_partial_relation_bound_root_structure(
            ProofFamily::PublicKeyShare,
            suite_record,
            proof_field,
            &ordered_verifier_sources,
            &ordered_columns,
            &ordered_trees,
        )?;
        Ok(Self {
            lattice_commitment_profile: lattice_commitment_profile.clone(),
            ordered_verifier_sources,
            ordered_columns,
            ordered_trees,
            anchor_root_source_ordinals,
            public_key_share_root_source_ordinal,
        })
    }
}

/// The deterministic public-only relation plan for collective public-key aggregation.
///
/// This type owns only the relation slice whose statement schema is `0x1213`.
/// It does not implement proof generation, proof verification, or witness extraction.
/// Every plan byte is regenerated from an accepted suite record and its family schedule;
/// callers cannot provide alternate constraint programs, source selectors, masks, or trees.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectivePublicKeyAggregationRelationPlan {
    canonical_bytes: Vec<u8>,
}

impl CollectivePublicKeyAggregationRelationPlan {
    pub fn for_suite(
        suite_record: &SuiteRecord,
        proof_profile_set: &ProofProfileSet,
    ) -> SchemaResult<Self> {
        suite_record.validate_intrinsic()?;
        let (proof_field, field_schedule) = proof_profile_set
            .field_and_schedule_for_family(ProofFamily::CollectivePublicKeyAggregate)?;

        let roster_size = suite_record.roster_size;
        let trace_domain_size = u64::from(suite_record.polynomial_degree);
        if trace_domain_size < 2 || !trace_domain_size.is_power_of_two() {
            return Err(schema_error(
                RefusalReason::OutsideSupportedProfile,
                "collective public-key aggregation trace domain must be a power of two",
            ));
        }
        let opening_degree_bound_exclusive = trace_domain_size;
        let evaluation_domain_size = opening_degree_bound_exclusive
            .checked_next_power_of_two()
            .and_then(|domain_size| {
                domain_size.checked_mul(u64::from(field_schedule.evaluation_blowup_factor))
            })
            .ok_or_else(|| {
                schema_error(
                    RefusalReason::OutsideSupportedProfile,
                    "collective public-key aggregation evaluation domain overflows",
                )
            })?;
        if evaluation_domain_size > proof_field.maximum_two_adic_subgroup_order()
            || !(proof_field.base_field_modulus - 1).is_multiple_of(evaluation_domain_size)
            || modular_power(
                field_schedule.evaluation_coset_offset,
                evaluation_domain_size,
                proof_field.base_field_modulus,
            ) == 1
        {
            return Err(schema_error(
                RefusalReason::OutsideSupportedProfile,
                "collective public-key aggregation evaluation coset does not fit the proof field",
            ));
        }
        let _fri_fold_count = derive_positive_radix_two_fold_count(
            opening_degree_bound_exclusive,
            u64::from(field_schedule.final_polynomial_degree_bound_exclusive),
        )?;
        let quotient_component_count = derive_public_aggregate_quotient_component_count(
            roster_size,
            trace_domain_size,
        )?;
        if u64::from(field_schedule.unique_query_count) > evaluation_domain_size / 2 {
            return Err(schema_error(
                RefusalReason::OutsideSupportedProfile,
                "collective public-key aggregation query count exceeds half the evaluation domain",
            ));
        }
        if usize::from(field_schedule.non_native_modular_identity_challenge_count)
            < suite_record.ordered_data_primes.len()
        {
            return Err(schema_error(
                RefusalReason::OutsideSupportedProfile,
                "collective public-key aggregation schedule has too few non-native challenges",
            ));
        }
        for data_modulus in &suite_record.ordered_data_primes {
            let exact_interval_upper_bound = u128::from(roster_size)
                .checked_mul(u128::from(*data_modulus))
                .ok_or_else(|| {
                    schema_error(
                        RefusalReason::OutsideSupportedProfile,
                        "collective public-key aggregation exact interval overflows",
                    )
                })?;
            if exact_interval_upper_bound >= u128::from(proof_field.base_field_modulus) {
                return Err(schema_error(
                    RefusalReason::OutsideSupportedProfile,
                    "collective public-key aggregation exact interval does not fit the proof field",
                ));
            }
        }

        let variant = build_collective_public_key_aggregation_variant(
            roster_size,
            &suite_record.ordered_data_primes,
            trace_domain_size,
            evaluation_domain_size,
            opening_degree_bound_exclusive,
            field_schedule.deep_point_count,
            quotient_component_count,
            proof_field.base_field_modulus,
        )?;
        let variant_item = CanonicalItem::nested_tuple(&variant)?;
        let canonical_bytes = CanonicalTuple::new(
            RELATION_PLAN_SCHEMA_IDENTIFIER,
            RELATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(
                    COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
                ),
                CanonicalItem::homogeneous_list(
                    CanonicalItemType::NestedTuple,
                    &[variant_item],
                )?,
            ],
        )
        .encode()?;
        if canonical_bytes.len() > RELATION_PLAN_MAXIMUM_BYTE_LENGTH {
            return Err(schema_error(
                RefusalReason::OutsideSupportedProfile,
                "collective public-key aggregation relation plan exceeds its bounded length",
            ));
        }
        let typed_plan = CanonicalRelationPlan::decode(
            &canonical_bytes,
            &CanonicalDecodeLimits::default(),
        )?;
        typed_plan.validate_for_suite(suite_record, proof_profile_set)?;
        Ok(Self { canonical_bytes })
    }

    pub fn encode(&self) -> Vec<u8> {
        self.canonical_bytes.clone()
    }

    pub fn decode_for_suite(
        bytes: &[u8],
        limits: &CanonicalDecodeLimits,
        suite_record: &SuiteRecord,
        proof_profile_set: &ProofProfileSet,
    ) -> SchemaResult<Self> {
        if bytes.len() > RELATION_PLAN_MAXIMUM_BYTE_LENGTH {
            return Err(schema_error(
                RefusalReason::OutsideSupportedProfile,
                "collective public-key aggregation relation plan exceeds its bounded length",
            ));
        }
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        require_header(&tuple, RELATION_PLAN_SCHEMA_IDENTIFIER, 2)?;
        let typed_plan = CanonicalRelationPlan::decode(bytes, limits)?;
        typed_plan.validate_for_suite(suite_record, proof_profile_set)?;
        let expected = Self::for_suite(suite_record, proof_profile_set)?;
        if expected.canonical_bytes != bytes {
            return Err(schema_error(
                RefusalReason::WrongContext,
                "collective public-key aggregation relation plan does not match the accepted suite",
            ));
        }
        Ok(expected)
    }
}

fn derive_positive_radix_two_fold_count(
    opening_degree_bound_exclusive: u64,
    final_polynomial_degree_bound_exclusive: u64,
) -> SchemaResult<u16> {
    if opening_degree_bound_exclusive <= 1
        || final_polynomial_degree_bound_exclusive == 0
        || final_polynomial_degree_bound_exclusive >= opening_degree_bound_exclusive
    {
        return Err(schema_error(
            RefusalReason::OutsideSupportedProfile,
            "collective public-key aggregation terminal degree bound must be positive and smaller than the initial bound",
        ));
    }

    let mut folded_degree_bound = opening_degree_bound_exclusive - 1;
    for fold_count in 1..=u16::try_from(u64::BITS).expect("u64 bit width fits u16") {
        folded_degree_bound = folded_degree_bound.div_ceil(2);
        if folded_degree_bound <= final_polynomial_degree_bound_exclusive {
            return Ok(fold_count);
        }
    }

    Err(schema_error(
        RefusalReason::OutsideSupportedProfile,
        "collective public-key aggregation radix-two fold count cannot be represented",
    ))
}

fn derive_public_aggregate_quotient_component_count(
    roster_size: u16,
    trace_domain_size: u64,
) -> SchemaResult<u32> {
    let numerator_degree_upper_bound = u64::from(roster_size)
        .checked_mul(trace_domain_size.checked_sub(1).ok_or_else(|| {
            schema_error(
                RefusalReason::OutsideSupportedProfile,
                "collective public-key aggregation trace domain is empty",
            )
        })?)
        .ok_or_else(|| {
            schema_error(
                RefusalReason::OutsideSupportedProfile,
                "collective public-key aggregation numerator degree overflows",
            )
        })?;
    let quotient_degree_bound_exclusive = if numerator_degree_upper_bound < trace_domain_size {
        1
    } else {
        numerator_degree_upper_bound
            .checked_sub(trace_domain_size)
            .and_then(|maximum_quotient_degree| maximum_quotient_degree.checked_add(1))
            .ok_or_else(|| {
                schema_error(
                    RefusalReason::OutsideSupportedProfile,
                    "collective public-key aggregation quotient degree overflows",
                )
            })?
    };
    let component_count = quotient_degree_bound_exclusive
        .div_ceil(trace_domain_size)
        .max(2);
    u32::try_from(component_count).map_err(|_| {
        schema_error(
            RefusalReason::OutsideSupportedProfile,
            "collective public-key aggregation quotient-component count does not fit u32",
        )
    })
}

#[allow(clippy::too_many_arguments)]
fn build_collective_public_key_aggregation_variant(
    roster_size: u16,
    ordered_data_primes: &[u64],
    trace_domain_size: u64,
    evaluation_domain_size: u64,
    opening_degree_bound_exclusive: u64,
    deep_point_count: u16,
    quotient_component_count: u32,
    proof_field_modulus: u64,
) -> SchemaResult<CanonicalTuple> {
    let source_root_count = usize::from(roster_size);
    let tree_count = source_root_count.checked_add(1).ok_or_else(|| {
        schema_error(
            RefusalReason::OutsideSupportedProfile,
            "collective public-key aggregation tree count overflows",
        )
    })?;
    let modulus_count = ordered_data_primes.len();
    let column_count = tree_count.checked_mul(modulus_count).ok_or_else(|| {
        schema_error(
            RefusalReason::OutsideSupportedProfile,
            "collective public-key aggregation column count overflows",
        )
    })?;
    if modulus_count == 0 || column_count == 0 {
        return Err(schema_error(
            RefusalReason::OutsideSupportedProfile,
            "collective public-key aggregation relation requires data moduli and columns",
        ));
    }

    let modulus_references = (0..modulus_count)
        .map(|modulus_index| {
            canonical_tuple_item(CanonicalTuple::new(
                SUITE_MODULUS_REFERENCE_SCHEMA_IDENTIFIER,
                RELATION_SCHEMA_VERSION,
                vec![
                    CanonicalItem::unsigned16(DATA_MODULUS_CATALOG),
                    CanonicalItem::unsigned16(index_as_u16(modulus_index)?),
                ],
            ))
        })
        .collect::<SchemaResult<Vec<_>>>()?;

    let mut verifier_source_entries = Vec::with_capacity(tree_count);
    for roster_position in 0..roster_size {
        let source = application_statement_hash_source(1, Some(u64::from(roster_position)))?;
        verifier_source_entries.push((
            usize::from(roster_position),
            source.encode()?,
            canonical_tuple_item(source)?,
        ));
    }
    let aggregate_source = application_statement_hash_source(2, None)?;
    verifier_source_entries.push((
        source_root_count,
        aggregate_source.encode()?,
        canonical_tuple_item(aggregate_source)?,
    ));
    verifier_source_entries.sort_by(|left, right| left.1.cmp(&right.1));
    let mut verifier_source_ordinals_by_tree = vec![0u32; tree_count];
    for (source_ordinal, (tree_ordinal, _, _)) in verifier_source_entries.iter().enumerate() {
        verifier_source_ordinals_by_tree[*tree_ordinal] = index_as_u32(source_ordinal)?;
    }
    let verifier_sources = verifier_source_entries
        .into_iter()
        .map(|(_, _, source)| source)
        .collect::<Vec<_>>();

    let mut columns = Vec::with_capacity(column_count);
    for tree_ordinal in 0..tree_count {
        let source_ordinal = verifier_source_ordinals_by_tree[tree_ordinal];
        for _ in 0..modulus_count {
            let origin = CanonicalTuple::new(
                RELATION_BOUND_TREE_COLUMN_ORIGIN_SCHEMA_IDENTIFIER,
                RELATION_SCHEMA_VERSION,
                vec![CanonicalItem::unsigned32(source_ordinal)],
            );
            columns.push(canonical_tuple_item(CanonicalTuple::new(
                RELATION_COLUMN_DESCRIPTOR_SCHEMA_IDENTIFIER,
                RELATION_SCHEMA_VERSION,
                vec![
                    CanonicalItem::nested_tuple(&origin)?,
                    CanonicalItem::unsigned16(BASE_FIELD_COLUMN_VALUE_TYPE),
                    CanonicalItem::unsigned64(trace_domain_size),
                ],
            ))?);
        }
    }

    let mut trees = Vec::with_capacity(tree_count);
    for tree_ordinal in 0..tree_count {
        let first_column_ordinal = tree_ordinal.checked_mul(modulus_count).ok_or_else(|| {
            schema_error(
                RefusalReason::OutsideSupportedProfile,
                "collective public-key aggregation tree column offset overflows",
            )
        })?;
        let column_ordinals = (0..modulus_count)
            .map(|modulus_index| {
                first_column_ordinal
                    .checked_add(modulus_index)
                    .ok_or_else(|| {
                        schema_error(
                            RefusalReason::OutsideSupportedProfile,
                            "collective public-key aggregation tree column ordinal overflows",
                        )
                    })
                    .and_then(index_as_u32)
            })
            .collect::<SchemaResult<Vec<_>>>()?;
        trees.push(canonical_tuple_item(CanonicalTuple::new(
            BOUND_PUBLIC_TREE_DESCRIPTOR_SCHEMA_IDENTIFIER,
            RELATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(SETUP_POLYNOMIAL_CONSTRUCTION_KIND),
                CanonicalItem::unsigned32(verifier_source_ordinals_by_tree[tree_ordinal]),
                CanonicalItem::unsigned16(if tree_ordinal < source_root_count {
                    INPUT_ROOT_USE
                } else {
                    OUTPUT_ROOT_USE
                }),
                encode_u32_list(&column_ordinals)?,
            ],
        ))?);
    }

    let constraints = ordered_data_primes
        .iter()
        .copied()
        .enumerate()
        .map(|(modulus_index, data_modulus)| {
            let numerator_expression = aggregate_constraint_expression(
                roster_size,
                modulus_count,
                modulus_index,
                data_modulus,
                proof_field_modulus,
            )?;
            let zeroifier_expression = trace_zeroifier_expression(
                trace_domain_size,
                proof_field_modulus,
            )?;
            canonical_tuple_item(CanonicalTuple::new(
                RELATION_CONSTRAINT_DESCRIPTOR_SCHEMA_IDENTIFIER,
                RELATION_SCHEMA_VERSION,
                vec![
                    CanonicalItem::unsigned16(1),
                    encode_u64_list(&[u64::try_from(modulus_index).map_err(|_| {
                        schema_error(
                            RefusalReason::OutsideSupportedProfile,
                            "collective public-key aggregation modulus ordinal does not fit u64",
                        )
                    })?])?,
                    encode_nested_tuple_list(&numerator_expression)?,
                    encode_nested_tuple_list(&zeroifier_expression)?,
                ],
            ))
        })
        .collect::<SchemaResult<Vec<_>>>()?;

    let opening_points = (0..deep_point_count)
        .map(|deep_point_ordinal| {
            canonical_tuple_item(CanonicalTuple::new(
                RELATION_OPENING_POINT_DESCRIPTOR_SCHEMA_IDENTIFIER,
                RELATION_SCHEMA_VERSION,
                vec![
                    CanonicalItem::unsigned16(deep_point_ordinal),
                    CanonicalItem::unsigned8(0),
                    CanonicalItem::unsigned64(0),
                    CanonicalItem::unsigned16(0),
                ],
            ))
        })
        .collect::<SchemaResult<Vec<_>>>()?;

    let tree_column_opening_count = column_count
        .checked_mul(usize::from(deep_point_count))
        .ok_or_else(|| {
            schema_error(
                RefusalReason::OutsideSupportedProfile,
                "collective public-key aggregation tree-column opening count overflows",
            )
        })?;
    let quotient_opening_count = usize::try_from(quotient_component_count)
        .ok()
        .and_then(|count| count.checked_mul(usize::from(deep_point_count)))
        .ok_or_else(|| {
            schema_error(
                RefusalReason::OutsideSupportedProfile,
                "collective public-key aggregation quotient opening count overflows",
            )
        })?;
    let mut opening_claims = Vec::with_capacity(
        tree_column_opening_count
            .checked_add(quotient_opening_count)
            .ok_or_else(|| {
                schema_error(
                    RefusalReason::OutsideSupportedProfile,
                    "collective public-key aggregation opening count overflows",
                )
            })?,
    );
    for tree_ordinal in 0..tree_count {
        for modulus_index in 0..modulus_count {
            let column_ordinal = tree_ordinal
                .checked_mul(modulus_count)
                .and_then(|value| value.checked_add(modulus_index))
                .ok_or_else(|| {
                    schema_error(
                        RefusalReason::OutsideSupportedProfile,
                        "collective public-key aggregation opening column ordinal overflows",
                    )
                })?;
            for opening_point_ordinal in 0..deep_point_count {
                let column_item = CanonicalItem::unsigned32(index_as_u32(column_ordinal)?);
                opening_claims.push(canonical_tuple_item(CanonicalTuple::new(
                    RELATION_OPENING_CLAIM_DESCRIPTOR_SCHEMA_IDENTIFIER,
                    RELATION_SCHEMA_VERSION,
                    vec![
                        CanonicalItem::unsigned16(TREE_COLUMN_OPENING_SOURCE_CLASS),
                        CanonicalItem::unsigned32(index_as_u32(tree_ordinal)?),
                        CanonicalItem::optional(CanonicalItemType::Unsigned32, Some(&column_item))?,
                        CanonicalItem::unsigned32(u32::from(opening_point_ordinal)),
                        CanonicalItem::unsigned64(trace_domain_size),
                    ],
                ))?);
            }
        }
    }
    for quotient_component_ordinal in 0..quotient_component_count {
        for opening_point_ordinal in 0..deep_point_count {
            opening_claims.push(canonical_tuple_item(CanonicalTuple::new(
                RELATION_OPENING_CLAIM_DESCRIPTOR_SCHEMA_IDENTIFIER,
                RELATION_SCHEMA_VERSION,
                vec![
                    CanonicalItem::unsigned16(QUOTIENT_OPENING_SOURCE_CLASS),
                    CanonicalItem::unsigned32(quotient_component_ordinal),
                    CanonicalItem::optional(CanonicalItemType::Unsigned32, None)?,
                    CanonicalItem::unsigned32(u32::from(opening_point_ordinal)),
                    CanonicalItem::unsigned64(opening_degree_bound_exclusive),
                ],
            ))?);
        }
    }

    Ok(CanonicalTuple::new(
        RELATION_PLAN_VARIANT_SCHEMA_IDENTIFIER,
        RELATION_SCHEMA_VERSION,
        vec![
            CanonicalItem::optional(CanonicalItemType::Unsigned32, None)?,
            CanonicalItem::optional(CanonicalItemType::Unsigned16, None)?,
            CanonicalItem::unsigned16(PUBLIC_ONLY_DETERMINISTIC_PROOF_PRIVACY_MODE),
            CanonicalItem::unsigned64(trace_domain_size),
            CanonicalItem::unsigned64(evaluation_domain_size),
            CanonicalItem::unsigned64(opening_degree_bound_exclusive),
            CanonicalItem::homogeneous_list(CanonicalItemType::NestedTuple, &modulus_references)?,
            CanonicalItem::homogeneous_list(CanonicalItemType::NestedTuple, &verifier_sources)?,
            CanonicalItem::homogeneous_list(CanonicalItemType::NestedTuple, &[])?,
            CanonicalItem::homogeneous_list(CanonicalItemType::NestedTuple, &columns)?,
            CanonicalItem::homogeneous_list(CanonicalItemType::NestedTuple, &trees)?,
            CanonicalItem::homogeneous_list(CanonicalItemType::NestedTuple, &constraints)?,
            CanonicalItem::homogeneous_list(CanonicalItemType::NestedTuple, &opening_points)?,
            CanonicalItem::homogeneous_list(CanonicalItemType::NestedTuple, &opening_claims)?,
            CanonicalItem::homogeneous_list(CanonicalItemType::NestedTuple, &[])?,
        ],
    ))
}

fn application_statement_hash_source(
    statement_field_index: u64,
    list_index: Option<u64>,
) -> SchemaResult<CanonicalTuple> {
    let mut path_steps = vec![canonical_tuple_item(CanonicalTuple::new(
        RELATION_SELECTOR_PATH_STEP_SCHEMA_IDENTIFIER,
        RELATION_SCHEMA_VERSION,
        vec![
            CanonicalItem::unsigned16(1),
            CanonicalItem::unsigned64(statement_field_index),
        ],
    ))?];
    if let Some(list_index) = list_index {
        path_steps.push(canonical_tuple_item(CanonicalTuple::new(
            RELATION_SELECTOR_PATH_STEP_SCHEMA_IDENTIFIER,
            RELATION_SCHEMA_VERSION,
            vec![CanonicalItem::unsigned16(2), CanonicalItem::unsigned64(list_index)],
        ))?);
    }
    let hash_layout = CanonicalTuple::new(
        RELATION_VALUE_LAYOUT_SCHEMA_IDENTIFIER,
        RELATION_SCHEMA_VERSION,
        vec![
            CanonicalItem::unsigned16(HASH_VALUE_LAYOUT_ELEMENT_KIND),
            CanonicalItem::optional(CanonicalItemType::NestedTuple, None)?,
            encode_u64_list(&[])?,
            CanonicalItem::unsigned16(NO_VALUE_LAYOUT_EMBEDDING),
        ],
    );
    Ok(CanonicalTuple::new(
        RELATION_APPLICATION_STATEMENT_SOURCE_DESCRIPTOR_SCHEMA_IDENTIFIER,
        RELATION_SCHEMA_VERSION,
        vec![
            CanonicalItem::homogeneous_list(CanonicalItemType::NestedTuple, &path_steps)?,
            CanonicalItem::nested_tuple(&hash_layout)?,
        ],
    ))
}

fn protocol_polynomial_source(
    protocol_source_kind: u16,
    source_coordinates: &[u64],
    data_prime_index: u16,
    polynomial_degree: u64,
) -> SchemaResult<CanonicalTuple> {
    let binding_path = [canonical_tuple_item(CanonicalTuple::new(
        RELATION_SELECTOR_PATH_STEP_SCHEMA_IDENTIFIER,
        RELATION_SCHEMA_VERSION,
        vec![
            CanonicalItem::unsigned16(1),
            CanonicalItem::unsigned64(0),
        ],
    ))?];
    let modulus_reference = CanonicalTuple::new(
        SUITE_MODULUS_REFERENCE_SCHEMA_IDENTIFIER,
        RELATION_SCHEMA_VERSION,
        vec![
            CanonicalItem::unsigned16(DATA_MODULUS_CATALOG),
            CanonicalItem::unsigned16(data_prime_index),
        ],
    );
    let modulus_reference_item = CanonicalItem::nested_tuple(&modulus_reference)?;
    let value_layout = CanonicalTuple::new(
        RELATION_VALUE_LAYOUT_SCHEMA_IDENTIFIER,
        RELATION_SCHEMA_VERSION,
        vec![
            CanonicalItem::unsigned16(SUITE_RESIDUE_VALUE_LAYOUT_ELEMENT_KIND),
            CanonicalItem::optional(
                CanonicalItemType::NestedTuple,
                Some(&modulus_reference_item),
            )?,
            encode_u64_list(&[polynomial_degree])?,
            CanonicalItem::unsigned16(LEAST_NONNEGATIVE_VALUE_LAYOUT_EMBEDDING),
        ],
    );
    Ok(CanonicalTuple::new(
        RELATION_PROTOCOL_SOURCE_DESCRIPTOR_SCHEMA_IDENTIFIER,
        RELATION_SCHEMA_VERSION,
        vec![
            CanonicalItem::unsigned16(protocol_source_kind),
            encode_u64_list(source_coordinates)?,
            CanonicalItem::homogeneous_list(CanonicalItemType::NestedTuple, &binding_path)?,
            CanonicalItem::nested_tuple(&value_layout)?,
        ],
    ))
}

fn append_bound_public_polynomial_tree(
    ordered_columns: &mut Vec<CanonicalTuple>,
    ordered_trees: &mut Vec<CanonicalTuple>,
    expected_root_source_ordinal: u32,
    root_use: u16,
    column_count: usize,
    source_degree_bound_exclusive: u64,
) -> SchemaResult<()> {
    if column_count == 0 {
        return Err(schema_error(
            RefusalReason::OutsideSupportedProfile,
            "bound public polynomial tree must contain at least one column",
        ));
    }
    let first_column_ordinal = ordered_columns.len();
    for _ in 0..column_count {
        let origin = CanonicalTuple::new(
            RELATION_BOUND_TREE_COLUMN_ORIGIN_SCHEMA_IDENTIFIER,
            RELATION_SCHEMA_VERSION,
            vec![CanonicalItem::unsigned32(expected_root_source_ordinal)],
        );
        ordered_columns.push(CanonicalTuple::new(
            RELATION_COLUMN_DESCRIPTOR_SCHEMA_IDENTIFIER,
            RELATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::nested_tuple(&origin)?,
                CanonicalItem::unsigned16(BASE_FIELD_COLUMN_VALUE_TYPE),
                CanonicalItem::unsigned64(source_degree_bound_exclusive),
            ],
        ));
    }
    let ordered_column_ordinals = (first_column_ordinal..ordered_columns.len())
        .map(index_as_u32)
        .collect::<SchemaResult<Vec<_>>>()?;
    ordered_trees.push(CanonicalTuple::new(
        BOUND_PUBLIC_TREE_DESCRIPTOR_SCHEMA_IDENTIFIER,
        RELATION_SCHEMA_VERSION,
        vec![
            CanonicalItem::unsigned16(SETUP_POLYNOMIAL_CONSTRUCTION_KIND),
            CanonicalItem::unsigned32(expected_root_source_ordinal),
            CanonicalItem::unsigned16(root_use),
            encode_u32_list(&ordered_column_ordinals)?,
        ],
    ));
    Ok(())
}

fn aggregate_constraint_expression(
    roster_size: u16,
    modulus_count: usize,
    modulus_index: usize,
    data_modulus: u64,
    proof_field_modulus: u64,
) -> SchemaResult<Vec<CanonicalItem>> {
    let mut expression = Vec::new();
    for multiple in 0..roster_size {
        append_aggregate_difference_expression(
            &mut expression,
            roster_size,
            modulus_count,
            modulus_index,
        )?;
        if multiple != 0 {
            let constant = u64::from(multiple)
                .checked_mul(data_modulus)
                .ok_or_else(|| {
                    schema_error(
                        RefusalReason::OutsideSupportedProfile,
                        "collective public-key aggregation constraint constant overflows",
                    )
                })?;
            expression.push(base_field_constant(constant, proof_field_modulus)?);
            expression.push(empty_instruction(RELATION_NEGATION_SCHEMA_IDENTIFIER)?);
            expression.push(empty_instruction(RELATION_ADDITION_SCHEMA_IDENTIFIER)?);
        }
        if multiple != 0 {
            expression.push(empty_instruction(RELATION_MULTIPLICATION_SCHEMA_IDENTIFIER)?);
        }
    }
    Ok(expression)
}

fn append_aggregate_difference_expression(
    expression: &mut Vec<CanonicalItem>,
    roster_size: u16,
    modulus_count: usize,
    modulus_index: usize,
) -> SchemaResult<()> {
    for roster_position in 0..roster_size {
        let column_ordinal = usize::from(roster_position)
            .checked_mul(modulus_count)
            .and_then(|value| value.checked_add(modulus_index))
            .ok_or_else(|| {
                schema_error(
                    RefusalReason::OutsideSupportedProfile,
                    "collective public-key aggregation source column ordinal overflows",
                )
            })?;
        expression.push(column_value_instruction(index_as_u32(column_ordinal)?)?);
        if roster_position != 0 {
            expression.push(empty_instruction(RELATION_ADDITION_SCHEMA_IDENTIFIER)?);
        }
    }
    let aggregate_column_ordinal = usize::from(roster_size)
        .checked_mul(modulus_count)
        .and_then(|value| value.checked_add(modulus_index))
        .ok_or_else(|| {
            schema_error(
                RefusalReason::OutsideSupportedProfile,
                "collective public-key aggregation output column ordinal overflows",
            )
        })?;
    expression.push(column_value_instruction(index_as_u32(
        aggregate_column_ordinal,
    )?)?);
    expression.push(empty_instruction(RELATION_NEGATION_SCHEMA_IDENTIFIER)?);
    expression.push(empty_instruction(RELATION_ADDITION_SCHEMA_IDENTIFIER)?);
    Ok(())
}

fn trace_zeroifier_expression(
    trace_domain_size: u64,
    proof_field_modulus: u64,
) -> SchemaResult<Vec<CanonicalItem>> {
    Ok(vec![
        empty_instruction(RELATION_EVALUATION_VARIABLE_SCHEMA_IDENTIFIER)?,
        canonical_tuple_item(CanonicalTuple::new(
            RELATION_NONNEGATIVE_POWER_SCHEMA_IDENTIFIER,
            RELATION_SCHEMA_VERSION,
            vec![CanonicalItem::unsigned64(trace_domain_size)],
        ))?,
        base_field_constant(1, proof_field_modulus)?,
        empty_instruction(RELATION_NEGATION_SCHEMA_IDENTIFIER)?,
        empty_instruction(RELATION_ADDITION_SCHEMA_IDENTIFIER)?,
    ])
}

fn column_value_instruction(column_ordinal: u32) -> SchemaResult<CanonicalItem> {
    canonical_tuple_item(CanonicalTuple::new(
        RELATION_COLUMN_VALUE_SCHEMA_IDENTIFIER,
        RELATION_SCHEMA_VERSION,
        vec![
            CanonicalItem::unsigned32(column_ordinal),
            CanonicalItem::unsigned8(0),
            CanonicalItem::unsigned64(0),
        ],
    ))
}

fn empty_instruction(schema_identifier: u16) -> SchemaResult<CanonicalItem> {
    canonical_tuple_item(CanonicalTuple::new(
        schema_identifier,
        RELATION_SCHEMA_VERSION,
        Vec::new(),
    ))
}

fn base_field_constant(value: u64, proof_field_modulus: u64) -> SchemaResult<CanonicalItem> {
    if value >= proof_field_modulus {
        return Err(schema_error(
            RefusalReason::OutsideSupportedProfile,
            "collective public-key aggregation constant is not a proof-field residue",
        ));
    }
    let field_byte_length = usize::try_from(
        (u64::BITS - (proof_field_modulus - 1).leading_zeros()).div_ceil(8),
    )
    .map_err(|_| {
        schema_error(
            RefusalReason::OutsideSupportedProfile,
            "proof-field element width does not fit the runtime",
        )
    })?;
    let field_element = CanonicalItem::from_canonical_bytes(
        CanonicalItemType::FieldElement,
        value.to_le_bytes()[..field_byte_length].to_vec(),
        &CanonicalDecodeLimits::default(),
    )?;
    canonical_tuple_item(CanonicalTuple::new(
        RELATION_BASE_FIELD_CONSTANT_SCHEMA_IDENTIFIER,
        RELATION_SCHEMA_VERSION,
        vec![field_element],
    ))
}

fn canonical_tuple_item(tuple: CanonicalTuple) -> SchemaResult<CanonicalItem> {
    Ok(CanonicalItem::nested_tuple(&tuple)?)
}

fn encode_nested_tuple_list(items: &[CanonicalItem]) -> SchemaResult<CanonicalItem> {
    Ok(CanonicalItem::homogeneous_list(
        CanonicalItemType::NestedTuple,
        items,
    )?)
}

fn encode_hash_list(values: &[Hash512]) -> SchemaResult<CanonicalItem> {
    let items = values
        .iter()
        .map(|value| CanonicalItem::hash512(value.into_bytes()))
        .collect::<Vec<_>>();
    Ok(CanonicalItem::homogeneous_list(
        CanonicalItemType::Hash512,
        &items,
    )?)
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

fn read_u16_list(item: &CanonicalItem) -> SchemaResult<Vec<u16>> {
    let (count, bytes) = read_list_header(item, CanonicalItemType::Unsigned16)?;
    let expected_byte_length = count.checked_mul(size_of::<u16>()).ok_or_else(|| {
        schema_error(
            RefusalReason::MalformedEncoding,
            "lattice-commitment u16-list byte length overflows",
        )
    })?;
    if bytes.len() != expected_byte_length {
        return Err(schema_error(
            RefusalReason::MalformedEncoding,
            "lattice-commitment u16-list byte length is malformed",
        ));
    }
    bytes
        .chunks_exact(size_of::<u16>())
        .map(|chunk| {
            let value_bytes: [u8; size_of::<u16>()] = chunk.try_into().map_err(|_| {
                schema_error(
                    RefusalReason::MalformedEncoding,
                    "lattice-commitment u16-list element length is malformed",
                )
            })?;
            Ok(u16::from_le_bytes(value_bytes))
        })
        .collect()
}

fn encode_u32_list(values: &[u32]) -> SchemaResult<CanonicalItem> {
    let items = values
        .iter()
        .copied()
        .map(CanonicalItem::unsigned32)
        .collect::<Vec<_>>();
    Ok(CanonicalItem::homogeneous_list(
        CanonicalItemType::Unsigned32,
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

fn index_as_u16(index: usize) -> SchemaResult<u16> {
    u16::try_from(index).map_err(|_| {
        schema_error(
            RefusalReason::OutsideSupportedProfile,
            "relation catalog index does not fit u16",
        )
    })
}

fn index_as_u32(index: usize) -> SchemaResult<u32> {
    u32::try_from(index).map_err(|_| {
        schema_error(
            RefusalReason::OutsideSupportedProfile,
            "relation catalog index does not fit u32",
        )
    })
}

fn require_lattice_commitment_profile_byte_bound(byte_length: usize) -> SchemaResult<()> {
    if byte_length > LATTICE_COMMITMENT_PROFILE_MAXIMUM_BYTE_LENGTH {
        return Err(schema_error(
            RefusalReason::OutsideSupportedProfile,
            "lattice-commitment profile exceeds the 65,536-byte decode bound",
        ));
    }
    Ok(())
}

fn schema_error(refusal_reason: RefusalReason, message: &'static str) -> FoundationSchemaError {
    FoundationSchemaError::new(refusal_reason, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::{
        ArtifactKind, ArtifactReference, DistributionKind, DistributionRecord, FOUNDATION_PROFILE,
        ProofFamilyProfile, ProofFieldProfile, ProofFieldSchedule,
    };

    fn hash(byte: u8) -> Hash512 {
        Hash512::from_bytes([byte; Hash512::BYTE_LENGTH])
    }

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
                    if kind == DistributionKind::Ternary { 0 } else { 2 },
                )
                .expect("test distribution")
            })
            .collect();
        let artifacts = (1..=6)
            .map(|artifact_code| {
                ArtifactReference::new(
                    ArtifactKind::from_canonical_code(artifact_code).expect("artifact kind"),
                    100 + u64::from(artifact_code),
                    hash(u8::try_from(artifact_code).expect("artifact byte")),
                )
                .expect("artifact reference")
            })
            .collect();
        SuiteRecord {
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

    fn valid_profile_set(suite_record: &SuiteRecord) -> ProofProfileSet {
        let schedule = ProofFieldSchedule::new(0, 4, 3, 2, 8, 4, 3, 6)
            .expect("test schedule");
        let families = ProofFamily::ALL
            .into_iter()
            .collect::<Vec<_>>();
        let mut families = families;
        families.sort_by_key(|family| family.statement_schema_identifier());
        ProofProfileSet::new(
            vec![ProofFieldProfile::new(769, 7, vec![0]).expect("test proof field")],
            families
                .into_iter()
                .map(|family| ProofFamilyProfile::new(family, schedule).expect("family profile"))
                .collect(),
            suite_record,
        )
        .expect("test profile set")
    }

    #[test]
    fn collective_public_key_statement_codec_is_exact_and_suite_checked() {
        let suite_record = valid_suite_record();
        let statement = CollectivePublicKeyAggregateStatement::new(
            hash(1),
            (0..suite_record.roster_size)
                .map(|position| hash(u8::try_from(position + 2).expect("small position")))
                .collect(),
            hash(0x40),
            hash(0x41),
        )
        .expect("statement");
        statement
            .validate_for_suite(&suite_record)
            .expect("suite binds the root count");
        let encoded = statement.encode().expect("statement encodes");
        assert_eq!(
            CollectivePublicKeyAggregateStatement::decode(
                &encoded,
                &CanonicalDecodeLimits::default(),
            )
            .expect("statement decodes"),
            statement
        );

        let mut missing_source = statement.clone();
        missing_source.ordered_public_key_share_roots.pop();
        assert_eq!(
            missing_source
                .validate_for_suite(&suite_record)
                .expect_err("wrong source count refuses")
                .refusal_reason,
            RefusalReason::WrongTypeOrLength
        );
        assert_eq!(
            CollectivePublicKeyAggregateStatement::new(hash(1), Vec::new(), hash(2), hash(3))
                .expect_err("empty source list refuses")
                .refusal_reason,
            RefusalReason::OutsideSupportedProfile
        );
    }

    #[test]
    fn public_key_share_root_structure_has_exact_sources_and_bound_tree_layouts() {
        let suite_record = valid_suite_record();
        let profile_set = valid_profile_set(&suite_record);
        let commitment_data_prime_indexes = [0, 2];
        let structure = PublicKeyShareRelationRootStructure::for_suite(
            &suite_record,
            &profile_set,
            2,
            &commitment_data_prime_indexes,
        )
        .expect("public-key-share root structure derives");

        let source_bytes = structure
            .ordered_verifier_sources
            .iter()
            .map(CanonicalTuple::encode)
            .collect::<Result<Vec<_>, _>>()
            .expect("sources encode");
        assert!(source_bytes.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(structure.ordered_verifier_sources.len(), 22);
        assert_eq!(structure.ordered_columns.len(), 9);
        assert_eq!(structure.ordered_trees.len(), 3);

        for (anchor_position, source_ordinal) in structure
            .anchor_root_source_ordinals
            .iter()
            .copied()
            .enumerate()
        {
            assert_eq!(
                structure.ordered_verifier_sources[usize::try_from(source_ordinal).unwrap()],
                application_statement_hash_source(
                    3,
                    Some(u64::try_from(anchor_position).unwrap())
                )
                .unwrap()
            );
        }
        assert_eq!(
            structure.ordered_verifier_sources
                [usize::try_from(structure.public_key_share_root_source_ordinal).unwrap()],
            application_statement_hash_source(4, None).unwrap()
        );

        let mut matrix_coordinates = Vec::new();
        let mut common_polynomial_coordinates = Vec::new();
        for source in &structure.ordered_verifier_sources {
            if source.schema_identifier != RELATION_PROTOCOL_SOURCE_DESCRIPTOR_SCHEMA_IDENTIFIER {
                continue;
            }
            match super::super::schemas::read_u16(&source.items[0]).unwrap() {
                COMMITMENT_MATRIX_SOURCE_KIND => matrix_coordinates.push(
                    super::super::schemas::read_u64_list(&source.items[1]).unwrap(),
                ),
                COLLECTIVE_PUBLIC_KEY_COMMON_POLYNOMIAL_SOURCE_KIND => {
                    common_polynomial_coordinates.push(
                        super::super::schemas::read_u64_list(&source.items[1]).unwrap(),
                    );
                }
                source_kind => panic!("unexpected protocol source kind {source_kind}"),
            }
        }
        let mut expected_matrix_coordinates = Vec::new();
        for commitment_data_prime_index in commitment_data_prime_indexes {
            for row in 0..2 {
                for column in 0..=2 {
                    expected_matrix_coordinates.push(vec![
                        u64::from(commitment_data_prime_index),
                        FIRST_COMMITMENT_MATRIX_PART,
                        row,
                        column,
                    ]);
                }
            }
            for column in 0..2 {
                expected_matrix_coordinates.push(vec![
                    u64::from(commitment_data_prime_index),
                    SECOND_COMMITMENT_MATRIX_PART,
                    0,
                    column,
                ]);
            }
        }
        matrix_coordinates.sort();
        expected_matrix_coordinates.sort();
        common_polynomial_coordinates.sort();
        assert_eq!(matrix_coordinates, expected_matrix_coordinates);
        assert_eq!(
            common_polynomial_coordinates,
            vec![vec![0], vec![1], vec![2]]
        );

        for (tree_position, tree) in structure.ordered_trees.iter().enumerate() {
            assert_eq!(
                tree.schema_identifier,
                BOUND_PUBLIC_TREE_DESCRIPTOR_SCHEMA_IDENTIFIER
            );
            assert_eq!(
                super::super::schemas::read_u16(&tree.items[0]).unwrap(),
                SETUP_POLYNOMIAL_CONSTRUCTION_KIND
            );
            let expected_source_ordinal = if tree_position < 2 {
                structure.anchor_root_source_ordinals[tree_position]
            } else {
                structure.public_key_share_root_source_ordinal
            };
            assert_eq!(
                super::super::schemas::read_u32(&tree.items[1]).unwrap(),
                expected_source_ordinal
            );
            assert_eq!(
                super::super::schemas::read_u16(&tree.items[2]).unwrap(),
                if tree_position < 2 {
                    INPUT_ROOT_USE
                } else {
                    OUTPUT_ROOT_USE
                }
            );
            let column_ordinals =
                super::super::schemas::read_u32_list(&tree.items[3]).unwrap();
            assert_eq!(column_ordinals.len(), 3);
            for column_ordinal in column_ordinals {
                let column =
                    &structure.ordered_columns[usize::try_from(column_ordinal).unwrap()];
                let origin = super::super::schemas::read_nested_tuple(
                    &column.items[0],
                    &CanonicalDecodeLimits::default(),
                )
                .unwrap();
                assert_eq!(
                    origin.schema_identifier,
                    RELATION_BOUND_TREE_COLUMN_ORIGIN_SCHEMA_IDENTIFIER
                );
                assert_eq!(
                    super::super::schemas::read_u32(&origin.items[0]).unwrap(),
                    expected_source_ordinal
                );
                assert_eq!(
                    super::super::schemas::read_u16(&column.items[1]).unwrap(),
                    BASE_FIELD_COLUMN_VALUE_TYPE
                );
                assert_eq!(
                    super::super::schemas::read_u64(&column.items[2]).unwrap(),
                    u64::from(suite_record.polynomial_degree)
                );
            }
        }
    }

    #[test]
    fn public_key_share_output_root_matches_the_public_aggregate_input_layout() {
        let suite_record = valid_suite_record();
        let profile_set = valid_profile_set(&suite_record);
        let structure = PublicKeyShareRelationRootStructure::for_suite(
            &suite_record,
            &profile_set,
            2,
            &[0, 2],
        )
        .expect("public-key-share root structure derives");
        let producer_tree = structure.ordered_trees.last().expect("producer output tree");
        let producer_column_ordinals =
            super::super::schemas::read_u32_list(&producer_tree.items[3]).unwrap();

        let consumer_plan =
            CollectivePublicKeyAggregationRelationPlan::for_suite(&suite_record, &profile_set)
                .expect("aggregate plan derives")
                .encode();
        let consumer_plan_tuple =
            CanonicalTuple::decode(&consumer_plan, &CanonicalDecodeLimits::default()).unwrap();
        let consumer_variants = super::super::schemas::read_nested_tuple_list(
            &consumer_plan_tuple.items[1],
            &CanonicalDecodeLimits::default(),
        )
        .unwrap();
        let consumer_columns = super::super::schemas::read_nested_tuple_list(
            &consumer_variants[0].items[9],
            &CanonicalDecodeLimits::default(),
        )
        .unwrap();
        let consumer_trees = super::super::schemas::read_nested_tuple_list(
            &consumer_variants[0].items[10],
            &CanonicalDecodeLimits::default(),
        )
        .unwrap();
        let consumer_tree = &consumer_trees[0];
        let consumer_column_ordinals =
            super::super::schemas::read_u32_list(&consumer_tree.items[3]).unwrap();

        assert_eq!(
            super::super::schemas::read_u16(&producer_tree.items[0]).unwrap(),
            super::super::schemas::read_u16(&consumer_tree.items[0]).unwrap()
        );
        assert_eq!(
            super::super::schemas::read_u16(&producer_tree.items[2]).unwrap(),
            OUTPUT_ROOT_USE
        );
        assert_eq!(
            super::super::schemas::read_u16(&consumer_tree.items[2]).unwrap(),
            INPUT_ROOT_USE
        );
        assert_eq!(producer_column_ordinals.len(), consumer_column_ordinals.len());
        for (producer_column_ordinal, consumer_column_ordinal) in producer_column_ordinals
            .into_iter()
            .zip(consumer_column_ordinals)
        {
            let producer_column =
                &structure.ordered_columns[usize::try_from(producer_column_ordinal).unwrap()];
            let consumer_column =
                &consumer_columns[usize::try_from(consumer_column_ordinal).unwrap()];
            assert_eq!(producer_column.items[1], consumer_column.items[1]);
            assert_eq!(producer_column.items[2], consumer_column.items[2]);
        }
    }

    #[test]
    fn public_key_share_root_structure_refuses_invalid_commitment_profiles() {
        let suite_record = valid_suite_record();
        let profile_set = valid_profile_set(&suite_record);
        for (rank, indexes, expected_reason) in [
            (0, vec![0], RefusalReason::OutsideSupportedProfile),
            (2, vec![], RefusalReason::WrongTypeOrLength),
            (2, vec![0, 0], RefusalReason::WrongTypeOrLength),
            (2, vec![2, 0], RefusalReason::WrongTypeOrLength),
            (2, vec![3], RefusalReason::WrongTypeOrLength),
            (
                u16::MAX,
                vec![0],
                RefusalReason::OutsideSupportedProfile,
            ),
        ] {
            assert_eq!(
                PublicKeyShareRelationRootStructure::for_suite(
                    &suite_record,
                    &profile_set,
                    rank,
                    &indexes,
                )
                .expect_err("invalid commitment profile must refuse")
                .refusal_reason,
                expected_reason
            );
        }
    }

    #[test]
    fn public_aggregation_plan_is_deterministic_maskless_and_suite_bound() {
        let suite_record = valid_suite_record();
        let profile_set = valid_profile_set(&suite_record);
        let plan = CollectivePublicKeyAggregationRelationPlan::for_suite(
            &suite_record,
            &profile_set,
        )
        .expect("plan derives");
        let encoded = plan.encode();
        let decoded = CollectivePublicKeyAggregationRelationPlan::decode_for_suite(
            &encoded,
            &CanonicalDecodeLimits::default(),
            &suite_record,
            &profile_set,
        )
        .expect("suite-bound plan decodes");
        assert_eq!(decoded, plan);

        let plan_tuple = CanonicalTuple::decode(&encoded, &CanonicalDecodeLimits::default())
            .expect("plan tuple");
        let variants = super::super::schemas::read_nested_tuple_list(
            &plan_tuple.items[1],
            &CanonicalDecodeLimits::default(),
        )
        .expect("variant list");
        assert_eq!(variants.len(), 1);
        let variant = &variants[0];
        assert_eq!(variant.schema_identifier, RELATION_PLAN_VARIANT_SCHEMA_IDENTIFIER);
        assert_eq!(super::super::schemas::read_u16(&variant.items[2]).unwrap(), 1);
        assert_eq!(
            super::super::schemas::read_nested_tuple_list(
                &variant.items[8],
                &CanonicalDecodeLimits::default(),
            )
            .unwrap(),
            Vec::new(),
            "public aggregation has no relation public sampler"
        );
        let opening_claims = super::super::schemas::read_nested_tuple_list(
            &variant.items[13],
            &CanonicalDecodeLimits::default(),
        )
        .expect("opening claims");
        let tree_column_opening_count = (usize::from(suite_record.roster_size) + 1)
            * suite_record.ordered_data_primes.len()
            * 2;
        let quotient_component_count = derive_public_aggregate_quotient_component_count(
            suite_record.roster_size,
            u64::from(suite_record.polynomial_degree),
        )
        .expect("quotient component count");
        assert_eq!(
            opening_claims.len(),
            tree_column_opening_count
                + usize::try_from(quotient_component_count).unwrap() * 2
        );
        assert!(opening_claims[..tree_column_opening_count]
            .iter()
            .all(|claim| super::super::schemas::read_u16(&claim.items[0]).unwrap()
                == TREE_COLUMN_OPENING_SOURCE_CLASS));
        for (claim_index, claim) in opening_claims[tree_column_opening_count..]
            .iter()
            .enumerate()
        {
            assert_eq!(
                super::super::schemas::read_u16(&claim.items[0]).unwrap(),
                QUOTIENT_OPENING_SOURCE_CLASS
            );
            assert_eq!(
                super::super::schemas::read_u32(&claim.items[1]).unwrap(),
                u32::try_from(claim_index / 2).unwrap()
            );
            assert_eq!(
                super::super::schemas::read_u32(&claim.items[3]).unwrap(),
                u32::try_from(claim_index % 2).unwrap()
            );
            assert_eq!(
                super::super::schemas::read_u64(&claim.items[4]).unwrap(),
                u64::from(suite_record.polynomial_degree)
            );
        }
        assert_eq!(
            super::super::schemas::read_nested_tuple_list(
                &variant.items[14],
                &CanonicalDecodeLimits::default(),
            )
            .unwrap(),
            Vec::new(),
            "public aggregation has no private mask"
        );
    }

    #[test]
    fn public_aggregation_quotient_segmentation_follows_the_constraint_degree() {
        assert_eq!(
            derive_public_aggregate_quotient_component_count(
                FOUNDATION_PROFILE.participant_count,
                2,
            )
            .unwrap(),
            5
        );
        assert_eq!(
            derive_public_aggregate_quotient_component_count(
                FOUNDATION_PROFILE.participant_count,
                32_768,
            )
            .unwrap(),
            9
        );

        for roster_size in 1..=16 {
            for trace_domain_size in [2, 4, 8, 32, 1_024, 32_768] {
                let component_count = u64::from(
                    derive_public_aggregate_quotient_component_count(
                        roster_size,
                        trace_domain_size,
                    )
                    .unwrap(),
                );
                let numerator_degree_upper_bound =
                    u64::from(roster_size) * (trace_domain_size - 1);
                let quotient_degree_bound_exclusive = if numerator_degree_upper_bound
                    < trace_domain_size
                {
                    1
                } else {
                    numerator_degree_upper_bound - trace_domain_size + 1
                };
                assert!(component_count >= 2);
                assert!(quotient_degree_bound_exclusive <= component_count * trace_domain_size);
                if component_count > 2 {
                    assert!(
                        quotient_degree_bound_exclusive
                            > (component_count - 1) * trace_domain_size
                    );
                }
            }
        }
    }

    #[test]
    fn every_single_byte_plan_mutation_refuses_or_fails_canonical_decoding() {
        let suite_record = valid_suite_record();
        let profile_set = valid_profile_set(&suite_record);
        let encoded = CollectivePublicKeyAggregationRelationPlan::for_suite(
            &suite_record,
            &profile_set,
        )
        .expect("plan derives")
        .encode();

        for byte_index in 0..encoded.len() {
            let mut mutated = encoded.clone();
            mutated[byte_index] ^= 1;
            assert!(
                CollectivePublicKeyAggregationRelationPlan::decode_for_suite(
                    &mutated,
                    &CanonicalDecodeLimits::default(),
                    &suite_record,
                    &profile_set,
                )
                .is_err(),
                "single-byte mutation {byte_index} must refuse"
            );
        }
    }

    #[test]
    fn exact_interval_requirement_refuses_an_inadequate_proof_field() {
        let suite_record = valid_suite_record();
        let schedule = ProofFieldSchedule::new(0, 4, 3, 2, 8, 4, 3, 6)
            .expect("test schedule");
        let mut families = ProofFamily::ALL;
        families.sort_by_key(|family| family.statement_schema_identifier());
        let profile_set = ProofProfileSet::new(
            vec![ProofFieldProfile::new(97, 28, vec![5, 0]).expect("small proof field")],
            families
                .into_iter()
                .map(|family| ProofFamilyProfile::new(family, schedule).expect("family profile"))
                .collect(),
            &suite_record,
        )
        .expect_err("inadequate exact interval must refuse");

        assert_eq!(
            profile_set.refusal_reason,
            RefusalReason::OutsideSupportedProfile
        );
    }
}
