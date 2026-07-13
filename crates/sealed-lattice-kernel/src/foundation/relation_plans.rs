use super::schemas::{SchemaResult, read_hash, read_hash_list, require_header};
use super::suite_record::modular_power;
use super::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple, FoundationSchemaError,
    Hash512, ProofFamily, ProofProfileSet, RefusalReason, SuiteRecord,
};

pub const COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER: u16 = 0x1213;
pub const RELATION_PLAN_SCHEMA_IDENTIFIER: u16 = 0x2204;
pub const RELATION_PLAN_VARIANT_SCHEMA_IDENTIFIER: u16 = 0x2205;

const RELATION_SCHEMA_VERSION: u16 = 1;
const RELATION_PLAN_MAXIMUM_BYTE_LENGTH: usize = 65_536;
const SUITE_MODULUS_REFERENCE_SCHEMA_IDENTIFIER: u16 = 0x220e;
const RELATION_COLUMN_DESCRIPTOR_SCHEMA_IDENTIFIER: u16 = 0x2206;
const BOUND_PUBLIC_TREE_DESCRIPTOR_SCHEMA_IDENTIFIER: u16 = 0x2208;
const RELATION_CONSTRAINT_DESCRIPTOR_SCHEMA_IDENTIFIER: u16 = 0x2209;
const RELATION_OPENING_POINT_DESCRIPTOR_SCHEMA_IDENTIFIER: u16 = 0x220a;
const RELATION_OPENING_CLAIM_DESCRIPTOR_SCHEMA_IDENTIFIER: u16 = 0x220b;
const RELATION_APPLICATION_STATEMENT_SOURCE_DESCRIPTOR_SCHEMA_IDENTIFIER: u16 = 0x2220;
const RELATION_SELECTOR_PATH_STEP_SCHEMA_IDENTIFIER: u16 = 0x2225;
const RELATION_VALUE_LAYOUT_SCHEMA_IDENTIFIER: u16 = 0x2226;
const RELATION_BOUND_TREE_COLUMN_ORIGIN_SCHEMA_IDENTIFIER: u16 = 0x2228;
const RELATION_BASE_FIELD_CONSTANT_SCHEMA_IDENTIFIER: u16 = 0x2210;
const RELATION_EVALUATION_VARIABLE_SCHEMA_IDENTIFIER: u16 = 0x2211;
const RELATION_COLUMN_VALUE_SCHEMA_IDENTIFIER: u16 = 0x2212;
const RELATION_ADDITION_SCHEMA_IDENTIFIER: u16 = 0x2214;
const RELATION_MULTIPLICATION_SCHEMA_IDENTIFIER: u16 = 0x2215;
const RELATION_NEGATION_SCHEMA_IDENTIFIER: u16 = 0x2216;
const RELATION_NONNEGATIVE_POWER_SCHEMA_IDENTIFIER: u16 = 0x2217;

const PUBLIC_ONLY_DETERMINISTIC_PROOF_PRIVACY_MODE: u16 = 1;
const DATA_MODULUS_CATALOG: u16 = 1;
const HASH_VALUE_LAYOUT_ELEMENT_KIND: u16 = 1;
const NO_VALUE_LAYOUT_EMBEDDING: u16 = 0;
const BASE_FIELD_COLUMN_VALUE_TYPE: u16 = 1;
const SETUP_POLYNOMIAL_CONSTRUCTION_KIND: u16 = 2;
const INPUT_ROOT_USE: u16 = 1;
const OUTPUT_ROOT_USE: u16 = 2;
const TREE_COLUMN_OPENING_SOURCE_CLASS: u16 = 1;

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
                CanonicalItem::hash512(self.collective_public_key_full_object_digest.into_bytes()),
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
                CanonicalItem::homogeneous_list(CanonicalItemType::NestedTuple, &[variant_item])?,
            ],
        )
        .encode()?;
        if canonical_bytes.len() > RELATION_PLAN_MAXIMUM_BYTE_LENGTH {
            return Err(schema_error(
                RefusalReason::OutsideSupportedProfile,
                "collective public-key aggregation relation plan exceeds its bounded length",
            ));
        }
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

#[allow(clippy::too_many_arguments)]
fn build_collective_public_key_aggregation_variant(
    roster_size: u16,
    ordered_data_primes: &[u64],
    trace_domain_size: u64,
    evaluation_domain_size: u64,
    opening_degree_bound_exclusive: u64,
    deep_point_count: u16,
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

    let mut verifier_sources = Vec::with_capacity(tree_count);
    for roster_position in 0..roster_size {
        verifier_sources.push(canonical_tuple_item(application_statement_hash_source(
            1,
            Some(u64::from(roster_position)),
        )?)?);
    }
    verifier_sources.push(canonical_tuple_item(application_statement_hash_source(
        2, None,
    )?)?);

    let mut columns = Vec::with_capacity(column_count);
    for source_ordinal in 0..tree_count {
        for _ in 0..modulus_count {
            let origin = CanonicalTuple::new(
                RELATION_BOUND_TREE_COLUMN_ORIGIN_SCHEMA_IDENTIFIER,
                RELATION_SCHEMA_VERSION,
                vec![CanonicalItem::unsigned32(index_as_u32(source_ordinal)?)],
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
    for source_ordinal in 0..tree_count {
        let first_column_ordinal = source_ordinal.checked_mul(modulus_count).ok_or_else(|| {
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
                CanonicalItem::unsigned32(index_as_u32(source_ordinal)?),
                CanonicalItem::unsigned16(if source_ordinal < source_root_count {
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
            let zeroifier_expression =
                trace_zeroifier_expression(trace_domain_size, proof_field_modulus)?;
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

    let mut opening_claims = Vec::with_capacity(
        column_count
            .checked_mul(usize::from(deep_point_count))
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
            vec![
                CanonicalItem::unsigned16(2),
                CanonicalItem::unsigned64(list_index),
            ],
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
            expression.push(empty_instruction(
                RELATION_MULTIPLICATION_SCHEMA_IDENTIFIER,
            )?);
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
    let field_byte_length =
        usize::try_from((u64::BITS - (proof_field_modulus - 1).leading_zeros()).div_ceil(8))
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
            "collective public-key aggregation index does not fit u16",
        )
    })
}

fn index_as_u32(index: usize) -> SchemaResult<u32> {
    u32::try_from(index).map_err(|_| {
        schema_error(
            RefusalReason::OutsideSupportedProfile,
            "collective public-key aggregation index does not fit u32",
        )
    })
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
                    hash(u8::try_from(artifact_code).expect("artifact byte")),
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

    fn valid_profile_set(suite_record: &SuiteRecord) -> ProofProfileSet {
        let schedule = ProofFieldSchedule::new(0, 4, 3, 2, 8, 4, 3, 6).expect("test schedule");
        let families = ProofFamily::ALL.into_iter().collect::<Vec<_>>();
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
    fn public_aggregation_plan_is_deterministic_maskless_and_suite_bound() {
        let suite_record = valid_suite_record();
        let profile_set = valid_profile_set(&suite_record);
        let plan =
            CollectivePublicKeyAggregationRelationPlan::for_suite(&suite_record, &profile_set)
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
        assert_eq!(
            variant.schema_identifier,
            RELATION_PLAN_VARIANT_SCHEMA_IDENTIFIER
        );
        assert_eq!(
            super::super::schemas::read_u16(&variant.items[2]).unwrap(),
            1
        );
        assert_eq!(
            super::super::schemas::read_nested_tuple_list(
                &variant.items[8],
                &CanonicalDecodeLimits::default(),
            )
            .unwrap(),
            Vec::new(),
            "public aggregation has no relation public sampler"
        );
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
    fn every_single_byte_plan_mutation_refuses_or_fails_canonical_decoding() {
        let suite_record = valid_suite_record();
        let profile_set = valid_profile_set(&suite_record);
        let encoded =
            CollectivePublicKeyAggregationRelationPlan::for_suite(&suite_record, &profile_set)
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
        let schedule = ProofFieldSchedule::new(0, 4, 3, 2, 8, 4, 3, 6).expect("test schedule");
        let mut families = ProofFamily::ALL;
        families.sort_by_key(|family| family.statement_schema_identifier());
        let error = ProofProfileSet::new(
            vec![ProofFieldProfile::new(97, 28, vec![5, 0]).expect("small proof field")],
            families
                .into_iter()
                .map(|family| ProofFamilyProfile::new(family, schedule).expect("family profile"))
                .collect(),
            &suite_record,
        )
        .expect_err("inadequate exact interval must refuse");

        assert_eq!(error.refusal_reason, RefusalReason::OutsideSupportedProfile);
    }
}
