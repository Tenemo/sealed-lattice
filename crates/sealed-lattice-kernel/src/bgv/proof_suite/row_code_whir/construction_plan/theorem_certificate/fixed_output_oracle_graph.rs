use super::*;

const CMS19_FIXED_OUTPUT_ORACLE_GRAPH_IDENTITY_DOMAIN: &str =
    "sealed-lattice/common-proof/fixed-output-oracle-graph-certificate/v1";

fn append_graph_identity_bytes(
    destination: &mut Vec<u8>,
    bytes: &[u8],
) -> Result<(), WhirTheoremCertificateError> {
    destination.extend_from_slice(
        &u64::try_from(bytes.len())
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?
            .to_le_bytes(),
    );
    destination.extend_from_slice(bytes);
    Ok(())
}

fn append_graph_identity_big_uint(
    destination: &mut Vec<u8>,
    value: &BigUint,
) -> Result<(), WhirTheoremCertificateError> {
    append_graph_identity_bytes(destination, &value.to_bytes_le())
}

fn append_graph_identity_fraction(
    destination: &mut Vec<u8>,
    value: &ExactBigFraction,
) -> Result<(), WhirTheoremCertificateError> {
    append_graph_identity_big_uint(destination, &value.numerator)?;
    append_graph_identity_big_uint(destination, &value.denominator)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Cms19AuxiliaryTableConcentrationStep {
    IndependentRowsFromDistinctSeedBoundPreimages,
    PointFibresUseBinomialStochasticDomination,
    AgreementFamiliesEnumerateEveryPopulationSubset,
    FactorThreeChernoffBaseIsAtMostOneThird,
    OneThirdPowerIsAtMostTheBinaryPower,
    EventUnionPaysTheDerivedFamilyAndRowCounts,
    ExhaustionUsesMarkovConditioningBeforeThePrimaryReduction,
}

const CMS19_AUXILIARY_TABLE_CONCENTRATION_STEPS: [Cms19AuxiliaryTableConcentrationStep; 7] = [
    Cms19AuxiliaryTableConcentrationStep::IndependentRowsFromDistinctSeedBoundPreimages,
    Cms19AuxiliaryTableConcentrationStep::PointFibresUseBinomialStochasticDomination,
    Cms19AuxiliaryTableConcentrationStep::AgreementFamiliesEnumerateEveryPopulationSubset,
    Cms19AuxiliaryTableConcentrationStep::FactorThreeChernoffBaseIsAtMostOneThird,
    Cms19AuxiliaryTableConcentrationStep::OneThirdPowerIsAtMostTheBinaryPower,
    Cms19AuxiliaryTableConcentrationStep::EventUnionPaysTheDerivedFamilyAndRowCounts,
    Cms19AuxiliaryTableConcentrationStep::ExhaustionUsesMarkovConditioningBeforeThePrimaryReduction,
];

/// Executable arithmetic premises for the universal auxiliary-table event.
///
/// For a point row, every output fibre is stochastically dominated by a
/// binomial variable with mean at most `2^512 / conditionalCardinality`. For a
/// query row, the exact bad-vector probability gives the binomial parameter
/// directly. The factor-three multiplicative Chernoff bound has base
/// `e^2 / 27 < 1/3 < 1/2`; the stored binary exponent is therefore a
/// conservative integer bound. Pointwise fibre bounds cover every adaptive
/// point set by summation, while the query rows union over every subset of the
/// declared population before the primary oracle is sampled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Cms19AuxiliaryTableUniversalGoodnessCertificate {
    seed_space_cardinality: BigUint,
    density_expansion_factor_numerator: u64,
    chernoff_base_rational_ceiling_numerator: u64,
    chernoff_base_rational_ceiling_denominator: u64,
    binary_power_base_numerator: u64,
    binary_power_base_denominator: u64,
    point_event_count: usize,
    query_event_count: usize,
    complete_event_count: usize,
    complete_event_count_log2_ceiling: usize,
    minimum_bad_event_inverse_power_of_two_exponent_floor: BigUint,
    charged_bad_event_probability_ceiling: ExactBigFraction,
    proof_steps: [Cms19AuxiliaryTableConcentrationStep; 7],
}

impl Cms19AuxiliaryTableUniversalGoodnessCertificate {
    pub(super) fn is_complete_for(
        &self,
        seed_space_cardinality: &BigUint,
        point_rows: &[Cms19PrecommittedSamplerTablePointConcentrationRow],
        query_rows: &[Cms19PrecommittedSamplerTableQueryConcentrationRow],
        charged_bad_event_probability_ceiling: &ExactBigFraction,
    ) -> bool {
        derive_auxiliary_table_universal_goodness_certificate(
            seed_space_cardinality,
            point_rows,
            query_rows,
            charged_bad_event_probability_ceiling,
        )
        .is_ok_and(|expected| expected == *self)
    }
}

pub(super) fn derive_auxiliary_table_universal_goodness_certificate(
    seed_space_cardinality: &BigUint,
    point_rows: &[Cms19PrecommittedSamplerTablePointConcentrationRow],
    query_rows: &[Cms19PrecommittedSamplerTableQueryConcentrationRow],
    charged_bad_event_probability_ceiling: &ExactBigFraction,
) -> Result<Cms19AuxiliaryTableUniversalGoodnessCertificate, WhirTheoremCertificateError> {
    if seed_space_cardinality != &(BigUint::one() << CMS19_REQUIRED_ORACLE_OUTPUT_BIT_LENGTH)
        || point_rows.is_empty()
        || query_rows.is_empty()
    {
        return Err(WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence);
    }

    for row in point_rows {
        let expected_mean_floor =
            seed_space_cardinality / &row.conditional_uniform_output_cardinality_floor;
        let family_count_ceiling = BigUint::from(row.output_family_log2_count_ceiling);
        if row.possible_output_point_count.is_zero()
            || row.conditional_uniform_output_cardinality_floor.is_zero()
            || row.conditional_uniform_output_cardinality_floor > row.possible_output_point_count
            || row.seed_space_to_output_mean_floor != expected_mean_floor
            || expected_mean_floor <= family_count_ceiling
            || row.table_bad_event_inverse_power_of_two_exponent_floor
                != expected_mean_floor - family_count_ceiling
            || biguint_log2_ceiling(&row.possible_output_point_count)?
                != usize::try_from(row.output_family_log2_count_ceiling)
                    .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?
        {
            return Err(WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence);
        }
    }

    for row in query_rows {
        let expected_mean_floor = (seed_space_cardinality
            * &row.exact_bad_vector_probability_ceiling.numerator)
            / &row.exact_bad_vector_probability_ceiling.denominator;
        let agreement_family_log2_count_ceiling = BigUint::from(row.population);
        if row.population == 0
            || row.agreement_ceiling >= row.population
            || row.query_count == 0
            || row.query_count > row.sampler_output_count
            || row.agreement_family_log2_count_ceiling != row.population
            || row.seed_space_bad_vector_mean_floor != expected_mean_floor
            || expected_mean_floor <= agreement_family_log2_count_ceiling
            || row.table_bad_event_inverse_power_of_two_exponent_floor
                != expected_mean_floor - agreement_family_log2_count_ceiling
        {
            return Err(WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence);
        }
    }

    let complete_event_count = point_rows
        .len()
        .checked_add(query_rows.len())
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    let complete_event_count_log2_ceiling =
        biguint_log2_ceiling(&BigUint::from(complete_event_count))?;
    let minimum_bad_event_inverse_power_of_two_exponent_floor = point_rows
        .iter()
        .map(|row| &row.table_bad_event_inverse_power_of_two_exponent_floor)
        .chain(
            query_rows
                .iter()
                .map(|row| &row.table_bad_event_inverse_power_of_two_exponent_floor),
        )
        .min()
        .cloned()
        .ok_or(WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence)?;
    let required_exponent = BigUint::from(
        CMS19_AUXILIARY_TABLE_DENSITY_BAD_EVENT_SECURITY_BITS
            .checked_add(complete_event_count_log2_ceiling)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
    );
    let expected_charged_probability = ExactBigFraction::new(
        BigUint::one(),
        BigUint::one() << CMS19_AUXILIARY_TABLE_DENSITY_BAD_EVENT_SECURITY_BITS,
    )?;
    if minimum_bad_event_inverse_power_of_two_exponent_floor < required_exponent
        || charged_bad_event_probability_ceiling != &expected_charged_probability
    {
        return Err(WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence);
    }

    Ok(Cms19AuxiliaryTableUniversalGoodnessCertificate {
        seed_space_cardinality: seed_space_cardinality.clone(),
        density_expansion_factor_numerator: CMS19_AUXILIARY_TABLE_DENSITY_EXPANSION_NUMERATOR,
        // `e < 3` gives `e^2 / 27 < 1/3`, and `1/3 < 1/2`.
        chernoff_base_rational_ceiling_numerator: 1,
        chernoff_base_rational_ceiling_denominator: 3,
        binary_power_base_numerator: 1,
        binary_power_base_denominator: 2,
        point_event_count: point_rows.len(),
        query_event_count: query_rows.len(),
        complete_event_count,
        complete_event_count_log2_ceiling,
        minimum_bad_event_inverse_power_of_two_exponent_floor,
        charged_bad_event_probability_ceiling: expected_charged_probability,
        proof_steps: CMS19_AUXILIARY_TABLE_CONCENTRATION_STEPS,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Cms19PrimaryPreimagePointerSlot {
    PriorTranscriptState,
    ResponseRoot,
    StreamingLeafPredecessor,
    MerkleLeftChild,
    MerkleRightChild,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Cms19PrimaryPreimagePointerEncoding {
    CanonicalFoundationTupleArgument { argument_index: u16 },
    RawDigestBytes { byte_offset: usize },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Cms19PrimaryPreimagePointerDescriptor {
    slot: Cms19PrimaryPreimagePointerSlot,
    encoding: Cms19PrimaryPreimagePointerEncoding,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Cms19PrimaryPreimageGrammarRow {
    database_role: Cms19DatabaseSupportRole,
    preimage_family: Cms19ConcreteShake256PreimageFamily,
    designated_predecessor_slots: Vec<Cms19PrimaryPreimagePointerSlot>,
    designated_predecessor_descriptors: Vec<Cms19PrimaryPreimagePointerDescriptor>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Cms19PrimaryPreimageGrammarClass {
    preimage_family: Cms19ConcreteShake256PreimageFamily,
    designated_predecessor_slots: Vec<Cms19PrimaryPreimagePointerSlot>,
    designated_predecessor_descriptors: Vec<Cms19PrimaryPreimagePointerDescriptor>,
}

fn primary_preimage_families_are_identical_or_disjoint(
    left: Cms19ConcreteShake256PreimageFamily,
    right: Cms19ConcreteShake256PreimageFamily,
) -> bool {
    if left == right {
        return true;
    }
    match (left, right) {
        (
            Cms19ConcreteShake256PreimageFamily::CanonicalFoundationTuplePrimary {
                domain: left_domain,
            },
            Cms19ConcreteShake256PreimageFamily::CanonicalFoundationTuplePrimary {
                domain: right_domain,
            },
        )
        | (
            Cms19ConcreteShake256PreimageFamily::LegacyFramedHash512Primary {
                domain: left_domain,
            },
            Cms19ConcreteShake256PreimageFamily::LegacyFramedHash512Primary {
                domain: right_domain,
            },
        ) => left_domain != right_domain,
        (
            Cms19ConcreteShake256PreimageFamily::CanonicalFoundationTuplePrimary { .. },
            noncanonical,
        )
        | (
            noncanonical,
            Cms19ConcreteShake256PreimageFamily::CanonicalFoundationTuplePrimary { .. },
        ) => {
            let canonical_header = [
                CANONICAL_TUPLE_SCHEMA_IDENTIFIER.to_le_bytes(),
                CANONICAL_TUPLE_VERSION.to_le_bytes(),
            ]
            .concat();
            cms19_raw_primary_fixed_prefix(noncanonical)
                .is_some_and(|prefix| fixed_prefixes_are_incompatible(&canonical_header, &prefix))
        }
        _ => cms19_raw_primary_fixed_prefix(left)
            .zip(cms19_raw_primary_fixed_prefix(right))
            .is_some_and(|(left_prefix, right_prefix)| {
                fixed_prefixes_are_incompatible(&left_prefix, &right_prefix)
            }),
    }
}

fn derive_primary_preimage_grammar_classes(
    grammar_rows: &[Cms19PrimaryPreimageGrammarRow],
) -> Option<Vec<Cms19PrimaryPreimageGrammarClass>> {
    let mut grammar_classes = Vec::<Cms19PrimaryPreimageGrammarClass>::new();
    for grammar_row in grammar_rows {
        if let Some(grammar_class) = grammar_classes
            .iter_mut()
            .find(|class| class.preimage_family == grammar_row.preimage_family)
        {
            grammar_class
                .designated_predecessor_slots
                .extend(grammar_row.designated_predecessor_slots.iter().copied());
            grammar_class.designated_predecessor_slots.sort_unstable();
            grammar_class.designated_predecessor_slots.dedup();
            grammar_class.designated_predecessor_descriptors.extend(
                grammar_row
                    .designated_predecessor_descriptors
                    .iter()
                    .copied(),
            );
            grammar_class
                .designated_predecessor_descriptors
                .sort_unstable();
            grammar_class.designated_predecessor_descriptors.dedup();
        } else {
            grammar_classes.push(Cms19PrimaryPreimageGrammarClass {
                preimage_family: grammar_row.preimage_family,
                designated_predecessor_slots: grammar_row.designated_predecessor_slots.clone(),
                designated_predecessor_descriptors: grammar_row
                    .designated_predecessor_descriptors
                    .clone(),
            });
        }
    }
    if grammar_classes.is_empty()
        || grammar_classes.iter().any(|class| {
            class.designated_predecessor_slots.len() > 2
                || class.designated_predecessor_descriptors.len()
                    != class.designated_predecessor_slots.len()
                || !class
                    .designated_predecessor_slots
                    .windows(2)
                    .all(|slots| slots[0] < slots[1])
        })
        || grammar_classes
            .iter()
            .enumerate()
            .any(|(class_index, class)| {
                grammar_classes.iter().skip(class_index + 1).any(|other| {
                    !primary_preimage_families_are_identical_or_disjoint(
                        class.preimage_family,
                        other.preimage_family,
                    )
                })
            })
    {
        return None;
    }
    Some(grammar_classes)
}

fn fixed_width_u64(bytes: &[u8], byte_offset: usize) -> Option<u64> {
    let byte_end = byte_offset.checked_add(size_of::<u64>())?;
    Some(u64::from_le_bytes(
        bytes.get(byte_offset..byte_end)?.try_into().ok()?,
    ))
}

fn fixed_width_digest(bytes: &[u8], byte_offset: usize) -> Option<[u8; Hash512::BYTE_LENGTH]> {
    let byte_end = byte_offset.checked_add(Hash512::BYTE_LENGTH)?;
    bytes.get(byte_offset..byte_end)?.try_into().ok()
}

fn parse_canonical_foundation_primary_preimage(
    preimage: &[u8],
    domain: &str,
    descriptors: &[Cms19PrimaryPreimagePointerDescriptor],
) -> Option<Vec<[u8; Hash512::BYTE_LENGTH]>> {
    let tuple = crate::foundation::CanonicalTuple::decode(
        preimage,
        &crate::foundation::CanonicalDecodeLimits::default(),
    )
    .ok()?;
    let domain_item = tuple.items.first()?;
    if tuple.schema_identifier != CANONICAL_TUPLE_SCHEMA_IDENTIFIER
        || tuple.schema_version != CANONICAL_TUPLE_VERSION
        || domain_item.item_type() != CanonicalItemType::Ascii
        || domain_item.variable_value_bytes().ok()? != domain.as_bytes()
    {
        return None;
    }
    descriptors
        .iter()
        .map(|descriptor| {
            let Cms19PrimaryPreimagePointerEncoding::CanonicalFoundationTupleArgument {
                argument_index,
            } = descriptor.encoding
            else {
                return None;
            };
            let item_index = usize::from(argument_index).checked_add(1)?;
            let item = tuple.items.get(item_index)?;
            if item.item_type() != CanonicalItemType::Hash512 {
                return None;
            }
            item.canonical_bytes().try_into().ok()
        })
        .collect()
}

fn legacy_framed_hash_primary_preimage_is_canonical(preimage: &[u8], domain: &str) -> bool {
    let mut reader = crate::encoding::CanonicalReader::new(preimage);
    if reader.read_exact(HASH512_PREIMAGE_PREFIX.len()).ok() != Some(HASH512_PREIMAGE_PREFIX)
        || reader.read_bytes().ok().as_deref() != Some(domain.as_bytes())
    {
        return false;
    }
    let Some(part_count) = reader
        .read_varuint()
        .ok()
        .and_then(|count| usize::try_from(count).ok())
    else {
        return false;
    };
    if part_count > preimage.len() {
        return false;
    }
    for _ in 0..part_count {
        if reader.read_bytes().is_err() {
            return false;
        }
    }
    reader.is_finished()
}

fn phase_column_leaf_primary_preimage_is_canonical(preimage: &[u8]) -> bool {
    const PREAMBLE_WORD_COUNT: usize = 7;
    let preamble_byte_length = PREAMBLE_WORD_COUNT * size_of::<u64>();
    if preimage.len() < preamble_byte_length
        || !preimage.starts_with(ROW_CODE_WHIR_PHASE_COLUMN_LEAF_DOMAIN)
    {
        return false;
    }
    let Some(row_count) = fixed_width_u64(preimage, 4 * size_of::<u64>())
        .and_then(|count| usize::try_from(count).ok())
    else {
        return false;
    };
    let Some(encoded_column_count) = fixed_width_u64(preimage, 5 * size_of::<u64>())
        .and_then(|count| usize::try_from(count).ok())
    else {
        return false;
    };
    let Some(salt_byte_length) = fixed_width_u64(preimage, 6 * size_of::<u64>())
        .and_then(|count| usize::try_from(count).ok())
    else {
        return false;
    };
    if row_count == 0
        || encoded_column_count == 0
        || !matches!(salt_byte_length, 0 | PRIVATE_LEAF_SALT_BYTE_LENGTH)
    {
        return false;
    }
    let Some(value_byte_offset) = preamble_byte_length.checked_add(salt_byte_length) else {
        return false;
    };
    let Some(expected_byte_length) = row_count
        .checked_mul(size_of::<u64>())
        .and_then(|value_byte_length| value_byte_offset.checked_add(value_byte_length))
    else {
        return false;
    };
    preimage.len() == expected_byte_length
        && preimage[value_byte_offset..]
            .chunks_exact(size_of::<u64>())
            .all(|bytes| {
                u64::from_le_bytes(bytes.try_into().expect("one field word has eight bytes"))
                    < crate::bgv::proof_suite::row_code_whir::GOLDILOCKS_MODULUS
            })
}

fn phase_column_parent_primary_predecessors(
    preimage: &[u8],
) -> Option<Vec<[u8; Hash512::BYTE_LENGTH]>> {
    let left_byte_offset =
        size_of::<u64>().checked_add(ROW_CODE_WHIR_PHASE_COLUMN_NODE_DOMAIN.len())?;
    let expected_byte_length = left_byte_offset.checked_add(2 * Hash512::BYTE_LENGTH)?;
    if preimage.len() != expected_byte_length
        || fixed_width_u64(preimage, 0)
            != u64::try_from(ROW_CODE_WHIR_PHASE_COLUMN_NODE_DOMAIN.len()).ok()
        || preimage.get(size_of::<u64>()..left_byte_offset)?
            != ROW_CODE_WHIR_PHASE_COLUMN_NODE_DOMAIN
    {
        return None;
    }
    Some(vec![
        fixed_width_digest(preimage, left_byte_offset)?,
        fixed_width_digest(preimage, left_byte_offset + Hash512::BYTE_LENGTH)?,
    ])
}

fn aggregate_leaf_primary_predecessors(preimage: &[u8]) -> Option<Vec<[u8; Hash512::BYTE_LENGTH]>> {
    let domain_length_byte_offset = ROW_CODE_WHIR_SHAKE256_PROTOCOL_DOMAIN.len();
    let domain_byte_offset = domain_length_byte_offset.checked_add(size_of::<u64>())?;
    let frame_byte_offset =
        domain_byte_offset.checked_add(ROW_CODE_WHIR_AGGREGATE_LEAF_DOMAIN.len())?;
    let payload_byte_offset = frame_byte_offset.checked_add(size_of::<u8>())?;
    if !preimage.starts_with(ROW_CODE_WHIR_SHAKE256_PROTOCOL_DOMAIN)
        || fixed_width_u64(preimage, domain_length_byte_offset)
            != u64::try_from(ROW_CODE_WHIR_AGGREGATE_LEAF_DOMAIN.len()).ok()
        || preimage.get(domain_byte_offset..frame_byte_offset)?
            != ROW_CODE_WHIR_AGGREGATE_LEAF_DOMAIN
    {
        return None;
    }
    match *preimage.get(frame_byte_offset)? {
        frame if frame
            == crate::bgv::proof_suite::row_code_whir::ROW_CODE_WHIR_AGGREGATE_LEAF_FRAME_TAGS[0] =>
        {
            let salt_length_byte_offset = payload_byte_offset.checked_add(size_of::<u64>())?;
            let salt_byte_length = fixed_width_u64(preimage, salt_length_byte_offset)
                .and_then(|length| usize::try_from(length).ok())?;
            let expected_byte_length = salt_length_byte_offset
                .checked_add(size_of::<u64>())?
                .checked_add(salt_byte_length)?;
            if preimage.len() != expected_byte_length
                || fixed_width_u64(preimage, payload_byte_offset)? == 0
                || !matches!(salt_byte_length, 0 | PRIVATE_LEAF_SALT_BYTE_LENGTH)
            {
                return None;
            }
            Some(Vec::new())
        }
        frame if frame
            == crate::bgv::proof_suite::row_code_whir::ROW_CODE_WHIR_AGGREGATE_LEAF_FRAME_TAGS[1] =>
        {
            let predecessor_byte_offset = payload_byte_offset.checked_add(size_of::<u64>())?;
            let expected_byte_length = predecessor_byte_offset
                .checked_add(Hash512::BYTE_LENGTH)?
                .checked_add(PROOF_CHALLENGE_EXTENSION_DEGREE.checked_mul(size_of::<u64>())?)?;
            if preimage.len() != expected_byte_length {
                return None;
            }
            let field_values_byte_offset = predecessor_byte_offset + Hash512::BYTE_LENGTH;
            if !preimage[field_values_byte_offset..]
                .chunks_exact(size_of::<u64>())
                .all(|bytes| {
                    u64::from_le_bytes(bytes.try_into().expect("one field word has eight bytes"))
                        < crate::bgv::proof_suite::row_code_whir::GOLDILOCKS_MODULUS
                })
            {
                return None;
            }
            Some(vec![fixed_width_digest(preimage, predecessor_byte_offset)?])
        }
        frame if frame
            == crate::bgv::proof_suite::row_code_whir::ROW_CODE_WHIR_AGGREGATE_LEAF_FRAME_TAGS[2] =>
        {
            let predecessor_byte_offset = payload_byte_offset.checked_add(size_of::<u64>())?;
            let expected_byte_length = predecessor_byte_offset.checked_add(Hash512::BYTE_LENGTH)?;
            if preimage.len() != expected_byte_length
                || fixed_width_u64(preimage, payload_byte_offset)? == 0
            {
                return None;
            }
            Some(vec![fixed_width_digest(preimage, predecessor_byte_offset)?])
        }
        _ => None,
    }
}

fn aggregate_parent_primary_predecessors(
    preimage: &[u8],
) -> Option<Vec<[u8; Hash512::BYTE_LENGTH]>> {
    let domain_length_byte_offset = ROW_CODE_WHIR_SHAKE256_PROTOCOL_DOMAIN.len();
    let domain_byte_offset = domain_length_byte_offset.checked_add(size_of::<u64>())?;
    let left_byte_offset =
        domain_byte_offset.checked_add(ROW_CODE_WHIR_AGGREGATE_NODE_DOMAIN.len())?;
    let expected_byte_length = left_byte_offset.checked_add(2 * Hash512::BYTE_LENGTH)?;
    if preimage.len() != expected_byte_length
        || !preimage.starts_with(ROW_CODE_WHIR_SHAKE256_PROTOCOL_DOMAIN)
        || fixed_width_u64(preimage, domain_length_byte_offset)
            != u64::try_from(ROW_CODE_WHIR_AGGREGATE_NODE_DOMAIN.len()).ok()
        || preimage.get(domain_byte_offset..left_byte_offset)?
            != ROW_CODE_WHIR_AGGREGATE_NODE_DOMAIN
    {
        return None;
    }
    Some(vec![
        fixed_width_digest(preimage, left_byte_offset)?,
        fixed_width_digest(preimage, left_byte_offset + Hash512::BYTE_LENGTH)?,
    ])
}

fn parse_primary_preimage_class(
    preimage: &[u8],
    grammar_class: &Cms19PrimaryPreimageGrammarClass,
) -> Option<Vec<[u8; Hash512::BYTE_LENGTH]>> {
    match grammar_class.preimage_family {
        Cms19ConcreteShake256PreimageFamily::CanonicalFoundationTuplePrimary { domain } => {
            parse_canonical_foundation_primary_preimage(
                preimage,
                domain,
                &grammar_class.designated_predecessor_descriptors,
            )
        }
        Cms19ConcreteShake256PreimageFamily::AtomicChallengeOutputBlockFoundationTuple512 => None,
        Cms19ConcreteShake256PreimageFamily::LegacyFramedHash512Primary { domain } => {
            (grammar_class.designated_predecessor_descriptors.is_empty()
                && legacy_framed_hash_primary_preimage_is_canonical(preimage, domain))
            .then(Vec::new)
        }
        Cms19ConcreteShake256PreimageFamily::PhaseColumnLeafPrimary => {
            (grammar_class.designated_predecessor_descriptors.is_empty()
                && phase_column_leaf_primary_preimage_is_canonical(preimage))
            .then(Vec::new)
        }
        Cms19ConcreteShake256PreimageFamily::PhaseColumnParentPrimary => {
            phase_column_parent_primary_predecessors(preimage)
        }
        Cms19ConcreteShake256PreimageFamily::AggregateColumnStreamableLeafPrimary => {
            aggregate_leaf_primary_predecessors(preimage)
        }
        Cms19ConcreteShake256PreimageFamily::AggregateWideParentPrimary => {
            aggregate_parent_primary_predecessors(preimage)
        }
    }
}

fn parse_designated_primary_predecessors(
    preimage: &[u8],
    grammar_classes: &[Cms19PrimaryPreimageGrammarClass],
) -> Option<Vec<[u8; Hash512::BYTE_LENGTH]>> {
    let mut matching_predecessors = grammar_classes
        .iter()
        .filter_map(|grammar_class| parse_primary_preimage_class(preimage, grammar_class));
    let only_match = matching_predecessors.next()?;
    matching_predecessors.next().is_none().then_some(only_match)
}

fn designated_primary_predecessor_slots(
    role: Cms19DatabaseSupportRole,
) -> Vec<Cms19PrimaryPreimagePointerSlot> {
    use Cms19PrimaryPreimagePointerSlot as Pointer;
    match role {
        Cms19DatabaseSupportRole::TypedTranscript { role } => match role {
            OracleEquationRole::InitialHeaderRoot | OracleEquationRole::ResponseRoot => Vec::new(),
            OracleEquationRole::InitialAbsorption => vec![Pointer::ResponseRoot],
            OracleEquationRole::ResponseBinding
            | OracleEquationRole::EmptyProverResponseAbsorption
            | OracleEquationRole::AtomicChallengeSeed => vec![Pointer::PriorTranscriptState],
            OracleEquationRole::ResponseAbsorption => {
                vec![Pointer::PriorTranscriptState, Pointer::ResponseRoot]
            }
            OracleEquationRole::AtomicChallengeOutputBlock => Vec::new(),
        },
        Cms19DatabaseSupportRole::AggregateLeafTransitionAndFinal { .. } => {
            vec![Pointer::StreamingLeafPredecessor]
        }
        Cms19DatabaseSupportRole::MerkleParents { .. } => {
            vec![Pointer::MerkleLeftChild, Pointer::MerkleRightChild]
        }
        Cms19DatabaseSupportRole::OrdinaryMerkleLeaf { .. }
        | Cms19DatabaseSupportRole::AggregateLeafSharedInitial { .. }
        | Cms19DatabaseSupportRole::AggregateLeafPrivateInitial { .. }
        | Cms19DatabaseSupportRole::FixedVerifierHash { .. } => Vec::new(),
    }
}

fn designated_primary_predecessor_descriptors(
    role: Cms19DatabaseSupportRole,
    family: Cms19ConcreteShake256PreimageFamily,
) -> Result<Vec<Cms19PrimaryPreimagePointerDescriptor>, WhirTheoremCertificateError> {
    use Cms19PrimaryPreimagePointerEncoding as Encoding;
    use Cms19PrimaryPreimagePointerSlot as Pointer;
    let canonical = |slot, argument_index| Cms19PrimaryPreimagePointerDescriptor {
        slot,
        encoding: Encoding::CanonicalFoundationTupleArgument { argument_index },
    };
    let raw = |slot, byte_offset| Cms19PrimaryPreimagePointerDescriptor {
        slot,
        encoding: Encoding::RawDigestBytes { byte_offset },
    };
    let descriptors = match role {
        Cms19DatabaseSupportRole::TypedTranscript { role } => match role {
            OracleEquationRole::InitialHeaderRoot | OracleEquationRole::ResponseRoot => Vec::new(),
            OracleEquationRole::InitialAbsorption => vec![canonical(Pointer::ResponseRoot, 2)],
            OracleEquationRole::ResponseBinding
            | OracleEquationRole::EmptyProverResponseAbsorption
            | OracleEquationRole::AtomicChallengeSeed => {
                vec![canonical(Pointer::PriorTranscriptState, 0)]
            }
            OracleEquationRole::ResponseAbsorption => vec![
                canonical(Pointer::PriorTranscriptState, 0),
                canonical(Pointer::ResponseRoot, 2),
            ],
            OracleEquationRole::AtomicChallengeOutputBlock => Vec::new(),
        },
        Cms19DatabaseSupportRole::AggregateLeafTransitionAndFinal { .. } => {
            let Cms19ConcreteShake256PreimageFamily::AggregateColumnStreamableLeafPrimary = family
            else {
                return Err(WhirTheoremCertificateError::IncompleteOracleEquationMapping);
            };
            let byte_offset = ROW_CODE_WHIR_SHAKE256_PROTOCOL_DOMAIN
                .len()
                .checked_add(size_of::<u64>())
                .and_then(|offset| offset.checked_add(ROW_CODE_WHIR_AGGREGATE_LEAF_DOMAIN.len()))
                .and_then(|offset| offset.checked_add(size_of::<u8>()))
                .and_then(|offset| offset.checked_add(size_of::<u64>()))
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
            let production_hasher = aggregate_leaf_hasher(ProofPrivacyMode::SecretBearing);
            let column_frame =
                production_hasher.frame_descriptor(ColumnStreamableLeafOracleFrame::Column);
            let final_frame =
                production_hasher.frame_descriptor(ColumnStreamableLeafOracleFrame::Final);
            let predecessor_end = byte_offset
                .checked_add(Hash512::BYTE_LENGTH)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
            let column_extension_byte_length = PROOF_CHALLENGE_EXTENSION_DEGREE
                .checked_mul(size_of::<u64>())
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
            if predecessor_end.checked_add(column_extension_byte_length)
                != Some(column_frame.canonical_input_byte_length)
                || predecessor_end != final_frame.canonical_input_byte_length
                || column_frame.predecessor_digest_count != 1
                || final_frame.predecessor_digest_count != 1
            {
                return Err(WhirTheoremCertificateError::IncompleteOracleEquationMapping);
            }
            vec![raw(Pointer::StreamingLeafPredecessor, byte_offset)]
        }
        Cms19DatabaseSupportRole::MerkleParents { .. } => match family {
            Cms19ConcreteShake256PreimageFamily::PhaseColumnParentPrimary => {
                let left_offset = size_of::<u64>()
                    .checked_add(ROW_CODE_WHIR_PHASE_COLUMN_NODE_DOMAIN.len())
                    .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
                vec![
                    raw(Pointer::MerkleLeftChild, left_offset),
                    raw(
                        Pointer::MerkleRightChild,
                        left_offset
                            .checked_add(Hash512::BYTE_LENGTH)
                            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
                    ),
                ]
            }
            Cms19ConcreteShake256PreimageFamily::AggregateWideParentPrimary => {
                let left_offset = ROW_CODE_WHIR_SHAKE256_PROTOCOL_DOMAIN
                    .len()
                    .checked_add(size_of::<u64>())
                    .and_then(|offset| {
                        offset.checked_add(ROW_CODE_WHIR_AGGREGATE_NODE_DOMAIN.len())
                    })
                    .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
                vec![
                    raw(Pointer::MerkleLeftChild, left_offset),
                    raw(
                        Pointer::MerkleRightChild,
                        left_offset
                            .checked_add(Hash512::BYTE_LENGTH)
                            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
                    ),
                ]
            }
            Cms19ConcreteShake256PreimageFamily::CanonicalFoundationTuplePrimary { domain } => {
                let (_, committed_parent_domain) =
                    crate::bgv::proof_suite::committed_material::committed_material_merkle_hash_domains();
                let (_, _, setup_parent_domain) =
                    crate::bgv::proof_suite::setup_public_polynomial::setup_public_polynomial_hash_domains();
                let first_child_argument_index = if domain == committed_parent_domain {
                    2
                } else if domain == setup_parent_domain {
                    3
                } else {
                    return Err(WhirTheoremCertificateError::IncompleteOracleEquationMapping);
                };
                vec![
                    canonical(Pointer::MerkleLeftChild, first_child_argument_index),
                    canonical(Pointer::MerkleRightChild, first_child_argument_index + 1),
                ]
            }
            _ => return Err(WhirTheoremCertificateError::IncompleteOracleEquationMapping),
        },
        Cms19DatabaseSupportRole::OrdinaryMerkleLeaf { .. }
        | Cms19DatabaseSupportRole::AggregateLeafSharedInitial { .. }
        | Cms19DatabaseSupportRole::AggregateLeafPrivateInitial { .. }
        | Cms19DatabaseSupportRole::FixedVerifierHash { .. } => Vec::new(),
    };
    if descriptors
        .iter()
        .map(|descriptor| descriptor.slot)
        .collect::<Vec<_>>()
        != designated_primary_predecessor_slots(role)
    {
        return Err(WhirTheoremCertificateError::IncompleteOracleEquationMapping);
    }
    Ok(descriptors)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Cms19PrimarySupportProofStep {
    CanonicalPreimageParserIsUniqueOrRejects,
    InvalidAndAuxiliaryPreimagesContributeNoPrimaryPointers,
    ExtractorsTraverseOnlyDesignatedPredecessorSlots,
    ANewEntryChangesExtractionOnlyAtTheTargetOrAnOldDesignatedPointer,
    EveryPrimaryEntryContributesAtMostTwoDistinctPointers,
    ThereforeSupportCardinalityIsAtMostTwiceTheDatabaseSize,
}

const CMS19_PRIMARY_SUPPORT_PROOF_STEPS: [Cms19PrimarySupportProofStep; 6] = [
    Cms19PrimarySupportProofStep::CanonicalPreimageParserIsUniqueOrRejects,
    Cms19PrimarySupportProofStep::InvalidAndAuxiliaryPreimagesContributeNoPrimaryPointers,
    Cms19PrimarySupportProofStep::ExtractorsTraverseOnlyDesignatedPredecessorSlots,
    Cms19PrimarySupportProofStep::ANewEntryChangesExtractionOnlyAtTheTargetOrAnOldDesignatedPointer,
    Cms19PrimarySupportProofStep::EveryPrimaryEntryContributesAtMostTwoDistinctPointers,
    Cms19PrimarySupportProofStep::ThereforeSupportCardinalityIsAtMostTwiceTheDatabaseSize,
];

/// Exact production specialization of the `S(D)` support used by CMS19.
///
/// `S_P(D)` is the union of the designated 512-bit predecessor slots parsed
/// from canonical primary-restriction inputs in `D`. Invalid inputs and the
/// disjoint auxiliary block grammar contribute no elements. Each recognized
/// primary input contributes at most two values, hence
/// `|S_P(D)| <= 2 |D|`, including databases populated by adversarial queries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Cms19PrimaryPreimageSupportCertificate {
    construction_plan_identity_hash: [u8; 64],
    grammar_rows: Vec<Cms19PrimaryPreimageGrammarRow>,
    grammar_classes: Vec<Cms19PrimaryPreimageGrammarClass>,
    maximum_designated_predecessor_count: usize,
    support_cardinality_per_database_entry_ceiling: usize,
    proof_steps: [Cms19PrimarySupportProofStep; 6],
}

impl Cms19PrimaryPreimageSupportCertificate {
    fn derive(
        partition: &Cms19ConcreteShake256OraclePartitionCertificate,
        whole_database_support: &Cms19WholeDatabaseSupportCertificate,
    ) -> Result<Self, WhirTheoremCertificateError> {
        if partition.construction_plan_identity_hash
            != whole_database_support.construction_plan_identity_hash
            || partition.rows.len() != whole_database_support.rows.len()
            || !partition.has_canonically_disjoint_restrictions()
        {
            return Err(WhirTheoremCertificateError::IncompleteOracleEquationMapping);
        }
        let mut grammar_rows = Vec::new();
        for (partition_row, support_row) in partition.rows.iter().zip(&whole_database_support.rows)
        {
            if partition_row.database_role != support_row.role {
                return Err(WhirTheoremCertificateError::IncompleteOracleEquationMapping);
            }
            match partition_row.restriction {
                Cms19ConcreteShake256OracleRestriction::PrecommittedAuxiliarySamplerTable => {
                    if !matches!(
                        partition_row.database_role,
                        Cms19DatabaseSupportRole::TypedTranscript {
                            role: OracleEquationRole::AtomicChallengeOutputBlock,
                        }
                    ) {
                        return Err(WhirTheoremCertificateError::IncompleteOracleEquationMapping);
                    }
                }
                Cms19ConcreteShake256OracleRestriction::PrimaryCms19Database => {
                    let designated_predecessor_slots =
                        designated_primary_predecessor_slots(partition_row.database_role);
                    let designated_predecessor_descriptors =
                        designated_primary_predecessor_descriptors(
                            partition_row.database_role,
                            partition_row.preimage_family,
                        )?;
                    if designated_predecessor_slots.len()
                        != usize::from(support_row.predecessor_support_count)
                        || designated_predecessor_descriptors.len()
                            != designated_predecessor_slots.len()
                        || designated_predecessor_slots.len() > 2
                    {
                        return Err(WhirTheoremCertificateError::IncompleteOracleEquationMapping);
                    }
                    grammar_rows.push(Cms19PrimaryPreimageGrammarRow {
                        database_role: partition_row.database_role,
                        preimage_family: partition_row.preimage_family,
                        designated_predecessor_slots,
                        designated_predecessor_descriptors,
                    });
                }
            }
        }
        let maximum_designated_predecessor_count = grammar_rows
            .iter()
            .map(|row| row.designated_predecessor_slots.len())
            .max()
            .ok_or(WhirTheoremCertificateError::IncompleteOracleEquationMapping)?;
        if maximum_designated_predecessor_count != 2 {
            return Err(WhirTheoremCertificateError::IncompleteOracleEquationMapping);
        }
        let grammar_classes = derive_primary_preimage_grammar_classes(&grammar_rows)
            .ok_or(WhirTheoremCertificateError::IncompleteOracleEquationMapping)?;
        Ok(Self {
            construction_plan_identity_hash: partition.construction_plan_identity_hash,
            grammar_rows,
            grammar_classes,
            maximum_designated_predecessor_count,
            support_cardinality_per_database_entry_ceiling: 2,
            proof_steps: CMS19_PRIMARY_SUPPORT_PROOF_STEPS,
        })
    }

    fn is_complete_for(
        &self,
        partition: &Cms19ConcreteShake256OraclePartitionCertificate,
        whole_database_support: &Cms19WholeDatabaseSupportCertificate,
    ) -> bool {
        Self::derive(partition, whole_database_support).is_ok_and(|expected| expected == *self)
    }

    fn is_self_consistent(&self) -> bool {
        self.construction_plan_identity_hash != [0_u8; 64]
            && !self.grammar_rows.is_empty()
            && self.grammar_rows.iter().all(|row| {
                row.designated_predecessor_slots
                    == designated_primary_predecessor_slots(row.database_role)
                    && designated_primary_predecessor_descriptors(
                        row.database_role,
                        row.preimage_family,
                    )
                    .is_ok_and(|descriptors| descriptors == row.designated_predecessor_descriptors)
                    && row.designated_predecessor_slots.len() <= 2
            })
            && self.maximum_designated_predecessor_count == 2
            && self.maximum_designated_predecessor_count
                == self
                    .grammar_rows
                    .iter()
                    .map(|row| row.designated_predecessor_slots.len())
                    .max()
                    .unwrap_or(usize::MAX)
            && derive_primary_preimage_grammar_classes(&self.grammar_rows)
                .is_some_and(|classes| classes == self.grammar_classes)
            && self.support_cardinality_per_database_entry_ceiling == 2
            && self.proof_steps == CMS19_PRIMARY_SUPPORT_PROOF_STEPS
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Cms19CoherentAuxiliaryAccessClass {
    WholeAnswer,
    AnswerFragment,
    AnswerSuffix,
    RepeatedInput,
    OverlappingAnswerRanges,
    OutOfOrderOrGuessedGraphPredecessor,
}

const CMS19_COHERENT_AUXILIARY_ACCESS_CLASSES: [Cms19CoherentAuxiliaryAccessClass; 6] = [
    Cms19CoherentAuxiliaryAccessClass::WholeAnswer,
    Cms19CoherentAuxiliaryAccessClass::AnswerFragment,
    Cms19CoherentAuxiliaryAccessClass::AnswerSuffix,
    Cms19CoherentAuxiliaryAccessClass::RepeatedInput,
    Cms19CoherentAuxiliaryAccessClass::OverlappingAnswerRanges,
    Cms19CoherentAuxiliaryAccessClass::OutOfOrderOrGuessedGraphPredecessor,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Cms19FixedOutputGraphProofStep {
    EmbedEachFiniteVariableLengthAdversaryRegisterIntoOneFixedBinaryInputDomain,
    SplitTheInputDomainIntoCanonicallyDecidablePrimaryAndAuxiliaryRestrictions,
    FactorTheUniformRandomFunctionAcrossTheDisjointRestrictions,
    FactorEachFullQueryIntoCommutingPrimaryAndAuxiliaryUnitaries,
    TreatFragmentsSuffixesRepeatsAndOverlapsAsComputationOnCachedFixedAnswers,
    ConditionOnOneUniversallyGoodAuxiliaryTable,
    AbsorbTheFixedAuxiliaryUnitaryIntoTheAdversaryBetweenPrimaryQueries,
    PurifyTheRemainingFixedOutputPrimaryOracleWithTheCms19CompressedPhaseOracle,
    RecordEveryAcceptingPrimaryEquationWithTheCms19OracleToDatabaseLemma,
    ApplyTheProductionSupportLemmaToCollisionFreeExtraction,
    ApplyTheStrongOriginalChainStateTransitionAndAcceptingDatabasePartition,
    BoundConditionalInstabilityWithTheAtomicFailureRowsAndPrimarySupport,
    LiftConditionalInstabilityWithTheCms19DatabaseLemmas,
    LiftTheRecordedDatabaseGameToTheOracleGame,
    ChargeTheAuxiliaryTableBadEventOutsideThePrimaryCms19Multiplier,
}

const CMS19_FIXED_OUTPUT_GRAPH_PROOF_STEPS: [Cms19FixedOutputGraphProofStep; 15] = [
    Cms19FixedOutputGraphProofStep::EmbedEachFiniteVariableLengthAdversaryRegisterIntoOneFixedBinaryInputDomain,
    Cms19FixedOutputGraphProofStep::SplitTheInputDomainIntoCanonicallyDecidablePrimaryAndAuxiliaryRestrictions,
    Cms19FixedOutputGraphProofStep::FactorTheUniformRandomFunctionAcrossTheDisjointRestrictions,
    Cms19FixedOutputGraphProofStep::FactorEachFullQueryIntoCommutingPrimaryAndAuxiliaryUnitaries,
    Cms19FixedOutputGraphProofStep::TreatFragmentsSuffixesRepeatsAndOverlapsAsComputationOnCachedFixedAnswers,
    Cms19FixedOutputGraphProofStep::ConditionOnOneUniversallyGoodAuxiliaryTable,
    Cms19FixedOutputGraphProofStep::AbsorbTheFixedAuxiliaryUnitaryIntoTheAdversaryBetweenPrimaryQueries,
    Cms19FixedOutputGraphProofStep::PurifyTheRemainingFixedOutputPrimaryOracleWithTheCms19CompressedPhaseOracle,
    Cms19FixedOutputGraphProofStep::RecordEveryAcceptingPrimaryEquationWithTheCms19OracleToDatabaseLemma,
    Cms19FixedOutputGraphProofStep::ApplyTheProductionSupportLemmaToCollisionFreeExtraction,
    Cms19FixedOutputGraphProofStep::ApplyTheStrongOriginalChainStateTransitionAndAcceptingDatabasePartition,
    Cms19FixedOutputGraphProofStep::BoundConditionalInstabilityWithTheAtomicFailureRowsAndPrimarySupport,
    Cms19FixedOutputGraphProofStep::LiftConditionalInstabilityWithTheCms19DatabaseLemmas,
    Cms19FixedOutputGraphProofStep::LiftTheRecordedDatabaseGameToTheOracleGame,
    Cms19FixedOutputGraphProofStep::ChargeTheAuxiliaryTableBadEventOutsideThePrimaryCms19Multiplier,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Cms19FixedOutputInputDomainReduction {
    InjectiveLengthFramingIntoOneFixedRegisterForEveryFiniteAdversaryCircuit,
    UnprovedUnboundedVariableLengthOracle,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Cms19FixedOutputOracleAccessModel {
    Standard512BitXorOracleAndEquivalentCompressedPhaseOracle,
    VariableOutputIdealXof,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Cms19ConcreteHashTheoremBoundary {
    ConditionalOnOneFixed512BitIdealQroForTheDeployedShake256CallInterface,
    ConcreteShake256IsProvedIdeal,
}

const fn primary_pointer_slot_tag(slot: Cms19PrimaryPreimagePointerSlot) -> u16 {
    match slot {
        Cms19PrimaryPreimagePointerSlot::PriorTranscriptState => 1,
        Cms19PrimaryPreimagePointerSlot::ResponseRoot => 2,
        Cms19PrimaryPreimagePointerSlot::StreamingLeafPredecessor => 3,
        Cms19PrimaryPreimagePointerSlot::MerkleLeftChild => 4,
        Cms19PrimaryPreimagePointerSlot::MerkleRightChild => 5,
    }
}

fn append_primary_preimage_family_identity(
    destination: &mut Vec<u8>,
    family: Cms19ConcreteShake256PreimageFamily,
) -> Result<(), WhirTheoremCertificateError> {
    let (tag, domain) = match family {
        Cms19ConcreteShake256PreimageFamily::CanonicalFoundationTuplePrimary { domain } => {
            (1_u16, Some(domain))
        }
        Cms19ConcreteShake256PreimageFamily::AtomicChallengeOutputBlockFoundationTuple512 => {
            (2, None)
        }
        Cms19ConcreteShake256PreimageFamily::LegacyFramedHash512Primary { domain } => {
            (3, Some(domain))
        }
        Cms19ConcreteShake256PreimageFamily::PhaseColumnLeafPrimary => (4, None),
        Cms19ConcreteShake256PreimageFamily::PhaseColumnParentPrimary => (5, None),
        Cms19ConcreteShake256PreimageFamily::AggregateColumnStreamableLeafPrimary => (6, None),
        Cms19ConcreteShake256PreimageFamily::AggregateWideParentPrimary => (7, None),
    };
    destination.extend_from_slice(&tag.to_le_bytes());
    append_graph_identity_bytes(destination, domain.unwrap_or_default().as_bytes())
}

fn append_primary_pointer_descriptor_identity(
    destination: &mut Vec<u8>,
    descriptor: Cms19PrimaryPreimagePointerDescriptor,
) -> Result<(), WhirTheoremCertificateError> {
    destination.extend_from_slice(&primary_pointer_slot_tag(descriptor.slot).to_le_bytes());
    match descriptor.encoding {
        Cms19PrimaryPreimagePointerEncoding::CanonicalFoundationTupleArgument {
            argument_index,
        } => {
            destination.extend_from_slice(&1_u16.to_le_bytes());
            destination.extend_from_slice(&u64::from(argument_index).to_le_bytes());
        }
        Cms19PrimaryPreimagePointerEncoding::RawDigestBytes { byte_offset } => {
            destination.extend_from_slice(&2_u16.to_le_bytes());
            destination.extend_from_slice(
                &u64::try_from(byte_offset)
                    .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?
                    .to_le_bytes(),
            );
        }
    }
    Ok(())
}

const fn coherent_access_class_tag(access_class: Cms19CoherentAuxiliaryAccessClass) -> u16 {
    match access_class {
        Cms19CoherentAuxiliaryAccessClass::WholeAnswer => 1,
        Cms19CoherentAuxiliaryAccessClass::AnswerFragment => 2,
        Cms19CoherentAuxiliaryAccessClass::AnswerSuffix => 3,
        Cms19CoherentAuxiliaryAccessClass::RepeatedInput => 4,
        Cms19CoherentAuxiliaryAccessClass::OverlappingAnswerRanges => 5,
        Cms19CoherentAuxiliaryAccessClass::OutOfOrderOrGuessedGraphPredecessor => 6,
    }
}

const fn fixed_output_graph_proof_step_tag(step: Cms19FixedOutputGraphProofStep) -> u16 {
    match step {
        Cms19FixedOutputGraphProofStep::EmbedEachFiniteVariableLengthAdversaryRegisterIntoOneFixedBinaryInputDomain => 1,
        Cms19FixedOutputGraphProofStep::SplitTheInputDomainIntoCanonicallyDecidablePrimaryAndAuxiliaryRestrictions => 2,
        Cms19FixedOutputGraphProofStep::FactorTheUniformRandomFunctionAcrossTheDisjointRestrictions => 3,
        Cms19FixedOutputGraphProofStep::FactorEachFullQueryIntoCommutingPrimaryAndAuxiliaryUnitaries => 4,
        Cms19FixedOutputGraphProofStep::TreatFragmentsSuffixesRepeatsAndOverlapsAsComputationOnCachedFixedAnswers => 5,
        Cms19FixedOutputGraphProofStep::ConditionOnOneUniversallyGoodAuxiliaryTable => 6,
        Cms19FixedOutputGraphProofStep::AbsorbTheFixedAuxiliaryUnitaryIntoTheAdversaryBetweenPrimaryQueries => 7,
        Cms19FixedOutputGraphProofStep::PurifyTheRemainingFixedOutputPrimaryOracleWithTheCms19CompressedPhaseOracle => 8,
        Cms19FixedOutputGraphProofStep::RecordEveryAcceptingPrimaryEquationWithTheCms19OracleToDatabaseLemma => 9,
        Cms19FixedOutputGraphProofStep::ApplyTheProductionSupportLemmaToCollisionFreeExtraction => 10,
        Cms19FixedOutputGraphProofStep::ApplyTheStrongOriginalChainStateTransitionAndAcceptingDatabasePartition => 11,
        Cms19FixedOutputGraphProofStep::BoundConditionalInstabilityWithTheAtomicFailureRowsAndPrimarySupport => 12,
        Cms19FixedOutputGraphProofStep::LiftConditionalInstabilityWithTheCms19DatabaseLemmas => 13,
        Cms19FixedOutputGraphProofStep::LiftTheRecordedDatabaseGameToTheOracleGame => 14,
        Cms19FixedOutputGraphProofStep::ChargeTheAuxiliaryTableBadEventOutsideThePrimaryCms19Multiplier => 15,
    }
}

const fn primary_support_proof_step_tag(step: Cms19PrimarySupportProofStep) -> u16 {
    match step {
        Cms19PrimarySupportProofStep::CanonicalPreimageParserIsUniqueOrRejects => 1,
        Cms19PrimarySupportProofStep::InvalidAndAuxiliaryPreimagesContributeNoPrimaryPointers => 2,
        Cms19PrimarySupportProofStep::ExtractorsTraverseOnlyDesignatedPredecessorSlots => 3,
        Cms19PrimarySupportProofStep::ANewEntryChangesExtractionOnlyAtTheTargetOrAnOldDesignatedPointer => 4,
        Cms19PrimarySupportProofStep::EveryPrimaryEntryContributesAtMostTwoDistinctPointers => 5,
        Cms19PrimarySupportProofStep::ThereforeSupportCardinalityIsAtMostTwiceTheDatabaseSize => 6,
    }
}

/// Complete graph reduction for one production construction.
///
/// This certificate proves the reduction only in the declared ideal-QRO
/// model. It deliberately contains no claim that concrete SHAKE256 is a random
/// oracle. The production call interface is mapped to that model as an
/// explicit assumption after all query widths and canonical preimages derive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Cms19FixedOutputOracleGraphCertificate {
    construction_plan_identity_hash: [u8; 64],
    canonical_oracle_plan_hash: [u8; 64],
    oracle_output_bit_length: usize,
    input_domain_reduction: Cms19FixedOutputInputDomainReduction,
    oracle_access_model: Cms19FixedOutputOracleAccessModel,
    adversarial_query_bound: BigUint,
    primary_oracle_query_bound: BigUint,
    primary_preimage_support: Cms19PrimaryPreimageSupportCertificate,
    coherent_auxiliary_access_classes: [Cms19CoherentAuxiliaryAccessClass; 6],
    proof_steps: [Cms19FixedOutputGraphProofStep; 15],
    concrete_hash_theorem_boundary: Cms19ConcreteHashTheoremBoundary,
    charged_density_bad_event_probability_ceiling: ExactBigFraction,
    exhaustion_table_bad_event_probability_ceiling: ExactBigFraction,
    auxiliary_table_bad_event_probability_ceiling: ExactBigFraction,
    primary_oracle_qrom_failure_probability_ceiling: ExactBigFraction,
    complete_qrom_failure_probability_ceiling: ExactBigFraction,
}

#[derive(Clone, Copy)]
pub(super) struct Cms19FixedOutputOracleGraphInput<'a> {
    pub(super) plan: &'a RowCodeWhirConstructionPlan,
    pub(super) partition: &'a Cms19ConcreteShake256OraclePartitionCertificate,
    pub(super) selected_plan_state_predicate: &'a SelectedPlanStatePredicateCertificate,
    pub(super) whole_state_transitions: &'a Cms19WholeStateTransitionCertificate,
    pub(super) whole_database_support: &'a Cms19WholeDatabaseSupportCertificate,
    pub(super) commitment_subtree_extraction: &'a CommitmentSubtreeExtractionCertificate,
    pub(super) nonlinear_commitment_binding: &'a NonlinearCommitmentBindingCertificate,
    pub(super) atomic_round_semantics: &'a Cms19AtomicRoundSemanticCertificate,
    pub(super) deployed_leaf_oracle: &'a DeployedAggregateLeafOracleCertificate,
    pub(super) sampler_model: &'a Cms19FixedOutputSeededSamplerModelCertificate,
    pub(super) strong_round_semantics: &'a Cms19StrongRoundByRoundSemanticCertificate,
    pub(super) state_predicate: &'a Cms19StatePredicateCertificate,
    pub(super) exact_failure: &'a ExactFailureMagnitudeCertificate,
    pub(super) arithmetic: &'a Cms19ArithmeticCertificate,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Cms19FixedOutputOracleGraphFault {
    OmitPrimaryGrammarRow,
    AddThirdPrimaryGrammarPointer,
    RaiseSupportCoefficient,
    OmitOverlappingAccessClass,
    OmitOracleToDatabaseRecordingStep,
    DropFiniteInputRegisterEmbedding,
    ReplaceFixedOutputOracleWithVariableOutputXof,
    ReduceAdversarialQueryBudget,
    ClaimConcreteShake256IsProvedIdeal,
    ChangeAuxiliaryBadEvent,
}

impl Cms19FixedOutputOracleGraphCertificate {
    pub(super) fn canonical_identity_hash(&self) -> Result<[u8; 64], WhirTheoremCertificateError> {
        if !self.has_internal_consistency() {
            return Err(WhirTheoremCertificateError::IncompleteFixedOutputOracleGraph);
        }
        let mut canonical_bytes = Vec::new();
        canonical_bytes.extend_from_slice(&2_u16.to_le_bytes());
        canonical_bytes.extend_from_slice(&self.construction_plan_identity_hash);
        canonical_bytes.extend_from_slice(&self.canonical_oracle_plan_hash);
        canonical_bytes.extend_from_slice(
            &u64::try_from(self.oracle_output_bit_length)
                .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?
                .to_le_bytes(),
        );
        let input_domain_reduction_tag = match self.input_domain_reduction {
            Cms19FixedOutputInputDomainReduction::InjectiveLengthFramingIntoOneFixedRegisterForEveryFiniteAdversaryCircuit => 1_u16,
            Cms19FixedOutputInputDomainReduction::UnprovedUnboundedVariableLengthOracle => 2,
        };
        canonical_bytes.extend_from_slice(&input_domain_reduction_tag.to_le_bytes());
        let oracle_access_model_tag = match self.oracle_access_model {
            Cms19FixedOutputOracleAccessModel::Standard512BitXorOracleAndEquivalentCompressedPhaseOracle => 1_u16,
            Cms19FixedOutputOracleAccessModel::VariableOutputIdealXof => 2,
        };
        canonical_bytes.extend_from_slice(&oracle_access_model_tag.to_le_bytes());
        append_graph_identity_big_uint(&mut canonical_bytes, &self.adversarial_query_bound)?;
        append_graph_identity_big_uint(&mut canonical_bytes, &self.primary_oracle_query_bound)?;

        let support = &self.primary_preimage_support;
        canonical_bytes.extend_from_slice(&support.construction_plan_identity_hash);
        canonical_bytes.extend_from_slice(
            &u64::try_from(support.grammar_rows.len())
                .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?
                .to_le_bytes(),
        );
        for row in &support.grammar_rows {
            append_primary_preimage_family_identity(&mut canonical_bytes, row.preimage_family)?;
            canonical_bytes.extend_from_slice(
                &u64::try_from(row.designated_predecessor_slots.len())
                    .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?
                    .to_le_bytes(),
            );
            for slot in &row.designated_predecessor_slots {
                canonical_bytes.extend_from_slice(&primary_pointer_slot_tag(*slot).to_le_bytes());
            }
            canonical_bytes.extend_from_slice(
                &u64::try_from(row.designated_predecessor_descriptors.len())
                    .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?
                    .to_le_bytes(),
            );
            for descriptor in &row.designated_predecessor_descriptors {
                append_primary_pointer_descriptor_identity(&mut canonical_bytes, *descriptor)?;
            }
        }
        canonical_bytes.extend_from_slice(
            &u64::try_from(support.grammar_classes.len())
                .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?
                .to_le_bytes(),
        );
        for grammar_class in &support.grammar_classes {
            append_primary_preimage_family_identity(
                &mut canonical_bytes,
                grammar_class.preimage_family,
            )?;
            canonical_bytes.extend_from_slice(
                &u64::try_from(grammar_class.designated_predecessor_slots.len())
                    .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?
                    .to_le_bytes(),
            );
            for slot in &grammar_class.designated_predecessor_slots {
                canonical_bytes.extend_from_slice(&primary_pointer_slot_tag(*slot).to_le_bytes());
            }
            canonical_bytes.extend_from_slice(
                &u64::try_from(grammar_class.designated_predecessor_descriptors.len())
                    .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?
                    .to_le_bytes(),
            );
            for descriptor in &grammar_class.designated_predecessor_descriptors {
                append_primary_pointer_descriptor_identity(&mut canonical_bytes, *descriptor)?;
            }
        }
        canonical_bytes.extend_from_slice(
            &u64::try_from(support.maximum_designated_predecessor_count)
                .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?
                .to_le_bytes(),
        );
        canonical_bytes.extend_from_slice(
            &u64::try_from(support.support_cardinality_per_database_entry_ceiling)
                .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?
                .to_le_bytes(),
        );
        for step in support.proof_steps {
            canonical_bytes.extend_from_slice(&primary_support_proof_step_tag(step).to_le_bytes());
        }
        for access_class in self.coherent_auxiliary_access_classes {
            canonical_bytes
                .extend_from_slice(&coherent_access_class_tag(access_class).to_le_bytes());
        }
        for step in self.proof_steps {
            canonical_bytes
                .extend_from_slice(&fixed_output_graph_proof_step_tag(step).to_le_bytes());
        }
        let concrete_hash_boundary_tag = match self.concrete_hash_theorem_boundary {
            Cms19ConcreteHashTheoremBoundary::ConditionalOnOneFixed512BitIdealQroForTheDeployedShake256CallInterface => 1_u16,
            Cms19ConcreteHashTheoremBoundary::ConcreteShake256IsProvedIdeal => 2,
        };
        canonical_bytes.extend_from_slice(&concrete_hash_boundary_tag.to_le_bytes());
        append_graph_identity_fraction(
            &mut canonical_bytes,
            &self.charged_density_bad_event_probability_ceiling,
        )?;
        append_graph_identity_fraction(
            &mut canonical_bytes,
            &self.exhaustion_table_bad_event_probability_ceiling,
        )?;
        append_graph_identity_fraction(
            &mut canonical_bytes,
            &self.auxiliary_table_bad_event_probability_ceiling,
        )?;
        append_graph_identity_fraction(
            &mut canonical_bytes,
            &self.primary_oracle_qrom_failure_probability_ceiling,
        )?;
        append_graph_identity_fraction(
            &mut canonical_bytes,
            &self.complete_qrom_failure_probability_ceiling,
        )?;
        Ok(crate::hashing::hash_framed_parts_512(
            CMS19_FIXED_OUTPUT_ORACLE_GRAPH_IDENTITY_DOMAIN,
            &[&canonical_bytes],
        ))
    }

    pub(super) fn derive(
        input: Cms19FixedOutputOracleGraphInput<'_>,
    ) -> Result<Self, WhirTheoremCertificateError> {
        let catalog = input
            .plan
            .oracle_equation_catalog()
            .map_err(|_| WhirTheoremCertificateError::IncompleteFixedOutputOracleGraph)?;
        let construction_plan_identity_hash = input
            .plan
            .canonical_identity_hash()
            .map_err(|_| WhirTheoremCertificateError::IncompleteFixedOutputOracleGraph)?;
        if construction_plan_identity_hash != input.partition.construction_plan_identity_hash
            || input.partition.construction_plan_identity_hash
                != input.whole_database_support.construction_plan_identity_hash
            || !input.partition.is_complete_for(
                input.whole_database_support,
                input.nonlinear_commitment_binding,
            )
            || input.sampler_model.construction_plan_identity_hash
                != input.partition.construction_plan_identity_hash
            || input.sampler_model.canonical_oracle_plan_hash
                != input
                    .strong_round_semantics
                    .state_evaluator
                    .state_transitions
                    .linear_bcs_transcript_plan_hash
            || !input.partition.every_mapped_call_returns_exactly_512_bits()
            || !input.partition.has_canonically_disjoint_restrictions()
            || !input.strong_round_semantics.is_complete()
            || !input.strong_round_semantics.is_complete_for(
                input.plan,
                input.whole_state_transitions,
                input.whole_database_support,
                input.commitment_subtree_extraction,
                input.state_predicate,
                input.exact_failure,
            )
            || !input.atomic_round_semantics.is_complete_for(
                input.plan,
                &catalog,
                input.selected_plan_state_predicate,
                input.whole_state_transitions,
                input.whole_database_support,
                input.commitment_subtree_extraction,
            )
            || !input
                .deployed_leaf_oracle
                .semantic_state_transition_correspondence_established()
            || !input.state_predicate.is_complete()
            || !input.state_predicate.has_exact_abstract_partition()
            || !input.exact_failure.is_complete()
            || input.arithmetic.adversarial_query_bound
                != BigUint::from(DECLARED_ADVERSARIAL_QUERY_BUDGET)
            || input.exact_failure.cms19_verifier_hash_query_count
                != input.arithmetic.verifier_hash_query_count
            || input.exact_failure.cms19_accepting_database_equation_count
                != input.arithmetic.accepting_database_equation_count
            || !input
                .exact_failure
                .precommitted_sampler_table
                .universal_goodness
                .is_complete_for(
                    &input
                        .exact_failure
                        .precommitted_sampler_table
                        .seed_space_cardinality,
                    &input.exact_failure.precommitted_sampler_table.point_rows,
                    &input.exact_failure.precommitted_sampler_table.query_rows,
                    &input
                        .exact_failure
                        .precommitted_sampler_table
                        .charged_density_bad_event_probability_ceiling,
                )
        {
            return Err(WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence);
        }
        let primary_preimage_support = Cms19PrimaryPreimageSupportCertificate::derive(
            input.partition,
            input.whole_database_support,
        )?;
        let certificate = Self {
            construction_plan_identity_hash: input.partition.construction_plan_identity_hash,
            canonical_oracle_plan_hash: input.sampler_model.canonical_oracle_plan_hash,
            oracle_output_bit_length: CMS19_REQUIRED_ORACLE_OUTPUT_BIT_LENGTH,
            input_domain_reduction: Cms19FixedOutputInputDomainReduction::InjectiveLengthFramingIntoOneFixedRegisterForEveryFiniteAdversaryCircuit,
            oracle_access_model: Cms19FixedOutputOracleAccessModel::Standard512BitXorOracleAndEquivalentCompressedPhaseOracle,
            adversarial_query_bound: input.arithmetic.adversarial_query_bound.clone(),
            primary_oracle_query_bound: input.arithmetic.adversarial_query_bound.clone(),
            primary_preimage_support,
            coherent_auxiliary_access_classes: CMS19_COHERENT_AUXILIARY_ACCESS_CLASSES,
            proof_steps: CMS19_FIXED_OUTPUT_GRAPH_PROOF_STEPS,
            concrete_hash_theorem_boundary:
                Cms19ConcreteHashTheoremBoundary::ConditionalOnOneFixed512BitIdealQroForTheDeployedShake256CallInterface,
            charged_density_bad_event_probability_ceiling: input
                .exact_failure
                .precommitted_sampler_table
                .charged_density_bad_event_probability_ceiling
                .clone(),
            exhaustion_table_bad_event_probability_ceiling: input
                .exact_failure
                .precommitted_sampler_table
                .exhaustion_table_bad_event_probability_ceiling
                .clone(),
            auxiliary_table_bad_event_probability_ceiling: input
                .exact_failure
                .auxiliary_table_bad_event_probability_ceiling
                .clone(),
            primary_oracle_qrom_failure_probability_ceiling: input
                .exact_failure
                .cms19_primary_oracle_qrom_failure_probability_ceiling
                .clone(),
            complete_qrom_failure_probability_ceiling: input
                .exact_failure
                .qrom_failure_probability_ceiling
                .clone(),
        };
        if !certificate.is_complete_for(input) {
            return Err(WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence);
        }
        Ok(certificate)
    }

    fn has_exact_graph_fields_for(&self, input: Cms19FixedOutputOracleGraphInput<'_>) -> bool {
        self.construction_plan_identity_hash == input.partition.construction_plan_identity_hash
            && self.canonical_oracle_plan_hash == input.sampler_model.canonical_oracle_plan_hash
            && self.oracle_output_bit_length == CMS19_REQUIRED_ORACLE_OUTPUT_BIT_LENGTH
            && self.input_domain_reduction
                == Cms19FixedOutputInputDomainReduction::InjectiveLengthFramingIntoOneFixedRegisterForEveryFiniteAdversaryCircuit
            && self.oracle_access_model
                == Cms19FixedOutputOracleAccessModel::Standard512BitXorOracleAndEquivalentCompressedPhaseOracle
            && self.adversarial_query_bound == BigUint::from(DECLARED_ADVERSARIAL_QUERY_BUDGET)
            && self.primary_oracle_query_bound == self.adversarial_query_bound
            && self.primary_preimage_support.is_complete_for(
                input.partition,
                input.whole_database_support,
            )
            && self.coherent_auxiliary_access_classes
                == CMS19_COHERENT_AUXILIARY_ACCESS_CLASSES
            && self.proof_steps == CMS19_FIXED_OUTPUT_GRAPH_PROOF_STEPS
            && self.concrete_hash_theorem_boundary
                == Cms19ConcreteHashTheoremBoundary::ConditionalOnOneFixed512BitIdealQroForTheDeployedShake256CallInterface
            && self.charged_density_bad_event_probability_ceiling
                == input
                    .exact_failure
                    .precommitted_sampler_table
                    .charged_density_bad_event_probability_ceiling
            && self.exhaustion_table_bad_event_probability_ceiling
                == input
                    .exact_failure
                    .precommitted_sampler_table
                    .exhaustion_table_bad_event_probability_ceiling
            && self.auxiliary_table_bad_event_probability_ceiling
                == input
                    .exact_failure
                    .auxiliary_table_bad_event_probability_ceiling
            && self.primary_oracle_qrom_failure_probability_ceiling
                == input
                    .exact_failure
                    .cms19_primary_oracle_qrom_failure_probability_ceiling
            && self.complete_qrom_failure_probability_ceiling
                == input.exact_failure.qrom_failure_probability_ceiling
            && self
                .primary_oracle_qrom_failure_probability_ceiling
                .add(&self.auxiliary_table_bad_event_probability_ceiling)
                .is_ok_and(|expected| expected == self.complete_qrom_failure_probability_ceiling)
    }

    pub(super) fn has_internal_consistency(&self) -> bool {
        self.construction_plan_identity_hash != [0_u8; 64]
            && self.canonical_oracle_plan_hash != [0_u8; 64]
            && self.primary_preimage_support.construction_plan_identity_hash
                == self.construction_plan_identity_hash
            && self.oracle_output_bit_length == CMS19_REQUIRED_ORACLE_OUTPUT_BIT_LENGTH
            && self.input_domain_reduction
                == Cms19FixedOutputInputDomainReduction::InjectiveLengthFramingIntoOneFixedRegisterForEveryFiniteAdversaryCircuit
            && self.oracle_access_model
                == Cms19FixedOutputOracleAccessModel::Standard512BitXorOracleAndEquivalentCompressedPhaseOracle
            && self.adversarial_query_bound == BigUint::from(DECLARED_ADVERSARIAL_QUERY_BUDGET)
            && self.primary_oracle_query_bound == self.adversarial_query_bound
            && self.primary_preimage_support.is_self_consistent()
            && self.coherent_auxiliary_access_classes
                == CMS19_COHERENT_AUXILIARY_ACCESS_CLASSES
            && self.proof_steps == CMS19_FIXED_OUTPUT_GRAPH_PROOF_STEPS
            && self.concrete_hash_theorem_boundary
                == Cms19ConcreteHashTheoremBoundary::ConditionalOnOneFixed512BitIdealQroForTheDeployedShake256CallInterface
            && ExactBigFraction::new(
                BigUint::one(),
                BigUint::one() << CMS19_AUXILIARY_TABLE_DENSITY_BAD_EVENT_SECURITY_BITS,
            )
            .is_ok_and(|expected| {
                expected == self.charged_density_bad_event_probability_ceiling
            })
            && !self
                .charged_density_bad_event_probability_ceiling
                .denominator
                .is_zero()
            && !self
                .exhaustion_table_bad_event_probability_ceiling
                .denominator
                .is_zero()
            && !self
                .auxiliary_table_bad_event_probability_ceiling
                .denominator
                .is_zero()
            && !self
                .primary_oracle_qrom_failure_probability_ceiling
                .denominator
                .is_zero()
            && !self.complete_qrom_failure_probability_ceiling.denominator.is_zero()
            && self
                .charged_density_bad_event_probability_ceiling
                .add(&self.exhaustion_table_bad_event_probability_ceiling)
                .is_ok_and(|expected| {
                    expected == self.auxiliary_table_bad_event_probability_ceiling
                })
            && self
                .primary_oracle_qrom_failure_probability_ceiling
                .add(&self.auxiliary_table_bad_event_probability_ceiling)
                .is_ok_and(|expected| expected == self.complete_qrom_failure_probability_ceiling)
    }

    pub(super) fn is_complete_for(&self, input: Cms19FixedOutputOracleGraphInput<'_>) -> bool {
        let catalog = input.plan.oracle_equation_catalog();
        input
            .plan
            .canonical_identity_hash()
            .is_ok_and(|identity| identity == input.partition.construction_plan_identity_hash)
            && input.partition.construction_plan_identity_hash
                == input.whole_database_support.construction_plan_identity_hash
            && input.partition.is_complete_for(
                input.whole_database_support,
                input.nonlinear_commitment_binding,
            )
            && input.sampler_model.construction_plan_identity_hash
                == input.partition.construction_plan_identity_hash
            && input.sampler_model.canonical_oracle_plan_hash
                == input
                    .strong_round_semantics
                    .state_evaluator
                    .state_transitions
                    .linear_bcs_transcript_plan_hash
            && input.partition.every_mapped_call_returns_exactly_512_bits()
            && input.partition.has_canonically_disjoint_restrictions()
            && input.strong_round_semantics.is_complete()
            && input.strong_round_semantics.is_complete_for(
                input.plan,
                input.whole_state_transitions,
                input.whole_database_support,
                input.commitment_subtree_extraction,
                input.state_predicate,
                input.exact_failure,
            )
            && catalog.is_ok_and(|catalog| {
                input.atomic_round_semantics.is_complete_for(
                    input.plan,
                    &catalog,
                    input.selected_plan_state_predicate,
                    input.whole_state_transitions,
                    input.whole_database_support,
                    input.commitment_subtree_extraction,
                )
            })
            && input
                .deployed_leaf_oracle
                .semantic_state_transition_correspondence_established()
            && input.state_predicate.is_complete()
            && input.state_predicate.has_exact_abstract_partition()
            && input.exact_failure.is_complete()
            && input.arithmetic.adversarial_query_bound
                == BigUint::from(DECLARED_ADVERSARIAL_QUERY_BUDGET)
            && input.exact_failure.cms19_verifier_hash_query_count
                == input.arithmetic.verifier_hash_query_count
            && input.exact_failure.cms19_accepting_database_equation_count
                == input.arithmetic.accepting_database_equation_count
            && input
                .exact_failure
                .precommitted_sampler_table
                .universal_goodness
                .is_complete_for(
                    &input
                        .exact_failure
                        .precommitted_sampler_table
                        .seed_space_cardinality,
                    &input.exact_failure.precommitted_sampler_table.point_rows,
                    &input.exact_failure.precommitted_sampler_table.query_rows,
                    &input
                        .exact_failure
                        .precommitted_sampler_table
                        .charged_density_bad_event_probability_ceiling,
                )
            && self.has_exact_graph_fields_for(input)
    }
}

#[cfg(test)]
pub(super) fn checked_fixed_output_oracle_graph_with_fault(
    baseline: &Cms19FixedOutputOracleGraphCertificate,
    input: Cms19FixedOutputOracleGraphInput<'_>,
    fault: Cms19FixedOutputOracleGraphFault,
) -> Result<Cms19FixedOutputOracleGraphCertificate, WhirTheoremCertificateError> {
    let mut certificate = baseline.clone();
    match fault {
        Cms19FixedOutputOracleGraphFault::OmitPrimaryGrammarRow => {
            certificate.primary_preimage_support.grammar_rows.pop();
        }
        Cms19FixedOutputOracleGraphFault::AddThirdPrimaryGrammarPointer => {
            certificate.primary_preimage_support.grammar_classes[0].designated_predecessor_slots = vec![
                Cms19PrimaryPreimagePointerSlot::PriorTranscriptState,
                Cms19PrimaryPreimagePointerSlot::MerkleLeftChild,
                Cms19PrimaryPreimagePointerSlot::MerkleRightChild,
            ];
        }
        Cms19FixedOutputOracleGraphFault::RaiseSupportCoefficient => {
            certificate
                .primary_preimage_support
                .support_cardinality_per_database_entry_ceiling += 1;
        }
        Cms19FixedOutputOracleGraphFault::OmitOverlappingAccessClass => {
            certificate.coherent_auxiliary_access_classes[4] =
                Cms19CoherentAuxiliaryAccessClass::RepeatedInput;
        }
        Cms19FixedOutputOracleGraphFault::OmitOracleToDatabaseRecordingStep => {
            certificate.proof_steps[13] =
                Cms19FixedOutputGraphProofStep::LiftConditionalInstabilityWithTheCms19DatabaseLemmas;
        }
        Cms19FixedOutputOracleGraphFault::DropFiniteInputRegisterEmbedding => {
            certificate.input_domain_reduction =
                Cms19FixedOutputInputDomainReduction::UnprovedUnboundedVariableLengthOracle;
        }
        Cms19FixedOutputOracleGraphFault::ReplaceFixedOutputOracleWithVariableOutputXof => {
            certificate.oracle_access_model =
                Cms19FixedOutputOracleAccessModel::VariableOutputIdealXof;
        }
        Cms19FixedOutputOracleGraphFault::ReduceAdversarialQueryBudget => {
            certificate.adversarial_query_bound -= BigUint::one();
        }
        Cms19FixedOutputOracleGraphFault::ClaimConcreteShake256IsProvedIdeal => {
            certificate.concrete_hash_theorem_boundary =
                Cms19ConcreteHashTheoremBoundary::ConcreteShake256IsProvedIdeal;
        }
        Cms19FixedOutputOracleGraphFault::ChangeAuxiliaryBadEvent => {
            certificate.exhaustion_table_bad_event_probability_ceiling = ExactBigFraction::zero();
        }
    }
    if certificate.has_exact_graph_fields_for(input) {
        Ok(certificate)
    } else {
        Err(WhirTheoremCertificateError::IncompleteFixedOutputOracleGraph)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::row_code_whir::Goldilocks;
    use p3_field::PrimeCharacteristicRing;

    fn grammar_class_for(
        database_role: Cms19DatabaseSupportRole,
        preimage_family: Cms19ConcreteShake256PreimageFamily,
    ) -> Cms19PrimaryPreimageGrammarClass {
        Cms19PrimaryPreimageGrammarClass {
            preimage_family,
            designated_predecessor_slots: designated_primary_predecessor_slots(database_role),
            designated_predecessor_descriptors: designated_primary_predecessor_descriptors(
                database_role,
                preimage_family,
            )
            .expect("the test grammar class derives from the production role"),
        }
    }

    fn test_primary_support_certificate() -> Cms19PrimaryPreimageSupportCertificate {
        let database_role = Cms19DatabaseSupportRole::TypedTranscript {
            role: OracleEquationRole::ResponseAbsorption,
        };
        let preimage_family =
            Cms19ConcreteShake256PreimageFamily::CanonicalFoundationTuplePrimary {
                domain: TRANSCRIPT_ABSORB_DOMAIN,
            };
        let grammar_row = Cms19PrimaryPreimageGrammarRow {
            database_role,
            preimage_family,
            designated_predecessor_slots: designated_primary_predecessor_slots(database_role),
            designated_predecessor_descriptors: designated_primary_predecessor_descriptors(
                database_role,
                preimage_family,
            )
            .expect("the test grammar row derives"),
        };
        let grammar_rows = vec![grammar_row];
        Cms19PrimaryPreimageSupportCertificate {
            construction_plan_identity_hash: [7_u8; 64],
            grammar_classes: derive_primary_preimage_grammar_classes(&grammar_rows)
                .expect("the test grammar classes derive"),
            grammar_rows,
            maximum_designated_predecessor_count: 2,
            support_cardinality_per_database_entry_ceiling: 2,
            proof_steps: CMS19_PRIMARY_SUPPORT_PROOF_STEPS,
        }
    }

    fn test_graph_certificate() -> Cms19FixedOutputOracleGraphCertificate {
        let charged_density_bad_event_probability_ceiling = ExactBigFraction::new(
            BigUint::one(),
            BigUint::one() << CMS19_AUXILIARY_TABLE_DENSITY_BAD_EVENT_SECURITY_BITS,
        )
        .expect("the test density event derives");
        let exhaustion_table_bad_event_probability_ceiling =
            ExactBigFraction::new(BigUint::one(), BigUint::one() << 384_usize)
                .expect("the test exhaustion event derives");
        let auxiliary_table_bad_event_probability_ceiling =
            charged_density_bad_event_probability_ceiling
                .add(&exhaustion_table_bad_event_probability_ceiling)
                .expect("the complete test auxiliary event derives");
        let primary_oracle_qrom_failure_probability_ceiling =
            ExactBigFraction::new(BigUint::one(), BigUint::one() << 128_usize)
                .expect("the test primary failure event derives");
        let complete_qrom_failure_probability_ceiling =
            primary_oracle_qrom_failure_probability_ceiling
                .add(&auxiliary_table_bad_event_probability_ceiling)
                .expect("the complete test QROM event derives");
        Cms19FixedOutputOracleGraphCertificate {
            construction_plan_identity_hash: [7_u8; 64],
            canonical_oracle_plan_hash: [11_u8; 64],
            oracle_output_bit_length: CMS19_REQUIRED_ORACLE_OUTPUT_BIT_LENGTH,
            input_domain_reduction: Cms19FixedOutputInputDomainReduction::InjectiveLengthFramingIntoOneFixedRegisterForEveryFiniteAdversaryCircuit,
            oracle_access_model: Cms19FixedOutputOracleAccessModel::Standard512BitXorOracleAndEquivalentCompressedPhaseOracle,
            adversarial_query_bound: BigUint::from(DECLARED_ADVERSARIAL_QUERY_BUDGET),
            primary_oracle_query_bound: BigUint::from(DECLARED_ADVERSARIAL_QUERY_BUDGET),
            primary_preimage_support: test_primary_support_certificate(),
            coherent_auxiliary_access_classes: CMS19_COHERENT_AUXILIARY_ACCESS_CLASSES,
            proof_steps: CMS19_FIXED_OUTPUT_GRAPH_PROOF_STEPS,
            concrete_hash_theorem_boundary:
                Cms19ConcreteHashTheoremBoundary::ConditionalOnOneFixed512BitIdealQroForTheDeployedShake256CallInterface,
            charged_density_bad_event_probability_ceiling,
            exhaustion_table_bad_event_probability_ceiling,
            auxiliary_table_bad_event_probability_ceiling,
            primary_oracle_qrom_failure_probability_ceiling,
            complete_qrom_failure_probability_ceiling,
        }
    }

    #[test]
    fn coherent_access_inventory_is_exact_and_has_no_concrete_shake_claim() {
        assert_eq!(
            CMS19_COHERENT_AUXILIARY_ACCESS_CLASSES,
            [
                Cms19CoherentAuxiliaryAccessClass::WholeAnswer,
                Cms19CoherentAuxiliaryAccessClass::AnswerFragment,
                Cms19CoherentAuxiliaryAccessClass::AnswerSuffix,
                Cms19CoherentAuxiliaryAccessClass::RepeatedInput,
                Cms19CoherentAuxiliaryAccessClass::OverlappingAnswerRanges,
                Cms19CoherentAuxiliaryAccessClass::OutOfOrderOrGuessedGraphPredecessor,
            ]
        );
        assert_eq!(CMS19_FIXED_OUTPUT_GRAPH_PROOF_STEPS.len(), 15);
        assert_eq!(CMS19_PRIMARY_SUPPORT_PROOF_STEPS.len(), 6);
    }

    #[test]
    fn canonical_graph_identity_binds_every_load_bearing_certificate_component() {
        let certificate = test_graph_certificate();
        assert!(certificate.has_internal_consistency());
        let identity = certificate
            .canonical_identity_hash()
            .expect("the graph identity derives");

        let mut changed_oracle_plan = certificate.clone();
        changed_oracle_plan.canonical_oracle_plan_hash[0] ^= 1;
        assert_ne!(
            changed_oracle_plan
                .canonical_identity_hash()
                .expect("the changed oracle-plan graph identity derives"),
            identity,
        );

        let mut changed_primary_failure = certificate.clone();
        changed_primary_failure.primary_oracle_qrom_failure_probability_ceiling =
            ExactBigFraction::new(BigUint::one(), BigUint::one() << 127_usize)
                .expect("the changed failure fraction derives");
        changed_primary_failure.complete_qrom_failure_probability_ceiling = changed_primary_failure
            .primary_oracle_qrom_failure_probability_ceiling
            .add(&changed_primary_failure.auxiliary_table_bad_event_probability_ceiling)
            .expect("the changed complete failure fraction derives");
        assert_ne!(
            changed_primary_failure
                .canonical_identity_hash()
                .expect("the changed failure graph identity derives"),
            identity,
        );

        let mut changed_exhaustion_event = certificate.clone();
        changed_exhaustion_event.exhaustion_table_bad_event_probability_ceiling =
            ExactBigFraction::new(BigUint::one(), BigUint::one() << 383_usize)
                .expect("the changed exhaustion fraction derives");
        changed_exhaustion_event.auxiliary_table_bad_event_probability_ceiling =
            changed_exhaustion_event
                .charged_density_bad_event_probability_ceiling
                .add(&changed_exhaustion_event.exhaustion_table_bad_event_probability_ceiling)
                .expect("the changed auxiliary event derives");
        changed_exhaustion_event.complete_qrom_failure_probability_ceiling =
            changed_exhaustion_event
                .primary_oracle_qrom_failure_probability_ceiling
                .add(&changed_exhaustion_event.auxiliary_table_bad_event_probability_ceiling)
                .expect("the changed complete event derives");
        assert_ne!(
            changed_exhaustion_event
                .canonical_identity_hash()
                .expect("the changed exhaustion graph identity derives"),
            identity,
        );

        let mut changed_density_event = certificate.clone();
        changed_density_event.charged_density_bad_event_probability_ceiling =
            ExactBigFraction::new(BigUint::one(), BigUint::one() << 511_usize)
                .expect("the changed density fraction derives");
        changed_density_event.auxiliary_table_bad_event_probability_ceiling = changed_density_event
            .charged_density_bad_event_probability_ceiling
            .add(&changed_density_event.exhaustion_table_bad_event_probability_ceiling)
            .expect("the changed auxiliary event derives");
        changed_density_event.complete_qrom_failure_probability_ceiling = changed_density_event
            .primary_oracle_qrom_failure_probability_ceiling
            .add(&changed_density_event.auxiliary_table_bad_event_probability_ceiling)
            .expect("the changed complete event derives");
        assert!(changed_density_event.canonical_identity_hash().is_err());

        let mut raised_support = certificate.clone();
        raised_support
            .primary_preimage_support
            .support_cardinality_per_database_entry_ceiling = 3;
        assert!(raised_support.canonical_identity_hash().is_err());

        let mut omitted_overlap = certificate;
        omitted_overlap.coherent_auxiliary_access_classes[4] =
            Cms19CoherentAuxiliaryAccessClass::RepeatedInput;
        assert!(omitted_overlap.canonical_identity_hash().is_err());
    }

    #[test]
    fn primary_parser_extracts_production_preimages_and_refuses_malformed_frames() {
        let prior_transcript_state = [17_u8; Hash512::BYTE_LENGTH];
        let response_root = [29_u8; Hash512::BYTE_LENGTH];
        let transcript_class = grammar_class_for(
            Cms19DatabaseSupportRole::TypedTranscript {
                role: OracleEquationRole::ResponseAbsorption,
            },
            Cms19ConcreteShake256PreimageFamily::CanonicalFoundationTuplePrimary {
                domain: TRANSCRIPT_ABSORB_DOMAIN,
            },
        );
        let transcript_preimage = canonical_foundation_tuple_hash_preimage(
            TRANSCRIPT_ABSORB_DOMAIN,
            &[
                CanonicalItem::hash512(prior_transcript_state),
                CanonicalItem::unsigned64(3),
                CanonicalItem::hash512(response_root),
            ],
        )
        .expect("the transcript preimage encodes");
        assert_eq!(
            parse_primary_preimage_class(&transcript_preimage, &transcript_class),
            Some(vec![prior_transcript_state, response_root]),
        );
        let mut transcript_with_trailing_byte = transcript_preimage.to_vec();
        transcript_with_trailing_byte.push(0);
        assert_eq!(
            parse_primary_preimage_class(&transcript_with_trailing_byte, &transcript_class),
            None,
        );

        let aggregate_class = grammar_class_for(
            Cms19DatabaseSupportRole::AggregateLeafTransitionAndFinal {
                role: MerkleOracleEquationRole::WhirEpoch { epoch_ordinal: 0 },
            },
            Cms19ConcreteShake256PreimageFamily::AggregateColumnStreamableLeafPrimary,
        );
        let aggregate_hasher = aggregate_leaf_hasher(ProofPrivacyMode::SecretBearing);
        let aggregate_salt = [31_u8; PRIVATE_LEAF_SALT_BYTE_LENGTH];
        let initial_preimage = aggregate_hasher.canonical_oracle_input_bytes(
            crate::bgv::proof_suite::row_code_whir::ColumnStreamableLeafOracleInput::Initial {
                column_count: 9,
                private_leaf_salt: Some(aggregate_salt),
            },
        );
        assert_eq!(
            parse_primary_preimage_class(&initial_preimage, &aggregate_class),
            Some(Vec::new()),
            "an initial frame is recognized but contributes no predecessor",
        );
        let predecessor_words = core::array::from_fn(|word_index| {
            u64::try_from(word_index + 41).expect("the word index fits u64")
        });
        let predecessor_state =
            crate::bgv::proof_suite::row_code_whir::ColumnStreamableLeafState(predecessor_words);
        let predecessor_digest = predecessor_words
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect::<Vec<_>>()
            .try_into()
            .expect("the predecessor has 64 bytes");
        let column_preimage = aggregate_hasher.canonical_oracle_input_bytes(
            crate::bgv::proof_suite::row_code_whir::ColumnStreamableLeafOracleInput::Column {
                column_index: 4,
                predecessor: predecessor_state,
                value: ChallengeField::ZERO,
            },
        );
        assert_eq!(
            parse_primary_preimage_class(&column_preimage, &aggregate_class),
            Some(vec![predecessor_digest]),
        );
        let final_preimage = aggregate_hasher.canonical_oracle_input_bytes(
            crate::bgv::proof_suite::row_code_whir::ColumnStreamableLeafOracleInput::Final {
                column_count: 9,
                predecessor: predecessor_state,
            },
        );
        assert_eq!(
            parse_primary_preimage_class(&final_preimage, &aggregate_class),
            Some(vec![predecessor_digest]),
        );
        let mut noncanonical_column = column_preimage;
        let coefficient_byte_offset = noncanonical_column.len() - size_of::<u64>();
        noncanonical_column[coefficient_byte_offset..].copy_from_slice(
            &crate::bgv::proof_suite::row_code_whir::GOLDILOCKS_MODULUS.to_le_bytes(),
        );
        assert_eq!(
            parse_primary_preimage_class(&noncanonical_column, &aggregate_class),
            None,
        );
        let mut unknown_frame = final_preimage;
        let frame_byte_offset = ROW_CODE_WHIR_SHAKE256_PROTOCOL_DOMAIN.len()
            + size_of::<u64>()
            + ROW_CODE_WHIR_AGGREGATE_LEAF_DOMAIN.len();
        unknown_frame[frame_byte_offset] = 255;
        assert_eq!(
            parse_primary_preimage_class(&unknown_frame, &aggregate_class),
            None,
        );
    }

    #[test]
    fn primary_parser_matches_raw_leaf_parent_and_legacy_encoders() {
        let phase_values = [Goldilocks::from_u64(3), Goldilocks::from_u64(5)];
        let phase_leaf_preimage = crate::bgv::proof_suite::row_code_whir::column_commitment::canonical_phase_column_leaf_oracle_input_bytes(
            &phase_values,
            7,
            None,
        );
        let phase_leaf_class = grammar_class_for(
            Cms19DatabaseSupportRole::OrdinaryMerkleLeaf {
                role: MerkleOracleEquationRole::RelationPhase {
                    phase: RowCodeWhirPhase::Base,
                },
            },
            Cms19ConcreteShake256PreimageFamily::PhaseColumnLeafPrimary,
        );
        assert_eq!(
            parse_primary_preimage_class(&phase_leaf_preimage, &phase_leaf_class),
            Some(Vec::new()),
        );
        let mut noncanonical_phase_leaf = phase_leaf_preimage;
        let last_word_byte_offset = noncanonical_phase_leaf.len() - size_of::<u64>();
        noncanonical_phase_leaf[last_word_byte_offset..].copy_from_slice(
            &crate::bgv::proof_suite::row_code_whir::GOLDILOCKS_MODULUS.to_le_bytes(),
        );
        assert_eq!(
            parse_primary_preimage_class(&noncanonical_phase_leaf, &phase_leaf_class),
            None,
        );

        let left_words = core::array::from_fn(|word_index| {
            u64::try_from(word_index + 101).expect("the left word index fits u64")
        });
        let right_words = core::array::from_fn(|word_index| {
            u64::try_from(word_index + 201).expect("the right word index fits u64")
        });
        let left_digest = left_words
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect::<Vec<_>>()
            .try_into()
            .expect("the left digest has 64 bytes");
        let right_digest = right_words
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect::<Vec<_>>()
            .try_into()
            .expect("the right digest has 64 bytes");
        let phase_parent_preimage = crate::bgv::proof_suite::row_code_whir::column_commitment::canonical_phase_column_parent_oracle_input_bytes(
            &left_words,
            &right_words,
        );
        let phase_parent_class = grammar_class_for(
            Cms19DatabaseSupportRole::MerkleParents {
                role: MerkleOracleEquationRole::RelationPhase {
                    phase: RowCodeWhirPhase::Base,
                },
            },
            Cms19ConcreteShake256PreimageFamily::PhaseColumnParentPrimary,
        );
        assert_eq!(
            parse_primary_preimage_class(&phase_parent_preimage, &phase_parent_class),
            Some(vec![left_digest, right_digest]),
        );

        let aggregate_parent_preimage =
            crate::bgv::proof_suite::row_code_whir::DomainSeparatedShake256 {
                domain: ROW_CODE_WHIR_AGGREGATE_NODE_DOMAIN,
            }
            .canonical_u64_oracle_input_bytes(left_words.into_iter().chain(right_words));
        let aggregate_parent_class = grammar_class_for(
            Cms19DatabaseSupportRole::MerkleParents {
                role: MerkleOracleEquationRole::WhirEpoch { epoch_ordinal: 0 },
            },
            Cms19ConcreteShake256PreimageFamily::AggregateWideParentPrimary,
        );
        assert_eq!(
            parse_primary_preimage_class(&aggregate_parent_preimage, &aggregate_parent_class),
            Some(vec![left_digest, right_digest]),
        );

        let legacy_domain =
            crate::bgv::proof_suite::verifier::verified_common_proof_statement_hash_domain();
        let legacy_preimage = crate::hashing::framed_hash512_preimage(
            legacy_domain,
            &[b"first part", b"second part"],
        );
        let legacy_class = grammar_class_for(
            Cms19DatabaseSupportRole::FixedVerifierHash {
                role: FixedVerifierHashRole::ApplicationStatement,
            },
            Cms19ConcreteShake256PreimageFamily::LegacyFramedHash512Primary {
                domain: legacy_domain,
            },
        );
        assert_eq!(
            parse_primary_preimage_class(&legacy_preimage, &legacy_class),
            Some(Vec::new()),
        );
        let mut nonminimal_part_count = legacy_preimage;
        let part_count_byte_offset = HASH512_PREIMAGE_PREFIX.len()
            + crate::encoding::encode_varuint(
                u64::try_from(legacy_domain.len()).expect("the domain length fits u64"),
            )
            .len()
            + legacy_domain.len();
        nonminimal_part_count.splice(part_count_byte_offset..=part_count_byte_offset, [0x82, 0]);
        assert_eq!(
            parse_primary_preimage_class(&nonminimal_part_count, &legacy_class),
            None,
        );

        let all_classes = vec![
            phase_leaf_class,
            phase_parent_class,
            aggregate_parent_class,
            legacy_class,
        ];
        assert_eq!(
            parse_designated_primary_predecessors(&phase_parent_preimage, &all_classes),
            Some(vec![left_digest, right_digest]),
        );
        assert_eq!(
            parse_designated_primary_predecessors(b"not a canonical oracle input", &all_classes),
            None,
        );
    }

    #[test]
    fn predecessor_slots_are_derived_from_the_exact_database_role() {
        assert_eq!(
            designated_primary_predecessor_slots(Cms19DatabaseSupportRole::TypedTranscript {
                role: OracleEquationRole::ResponseAbsorption,
            }),
            vec![
                Cms19PrimaryPreimagePointerSlot::PriorTranscriptState,
                Cms19PrimaryPreimagePointerSlot::ResponseRoot,
            ]
        );
        assert_eq!(
            designated_primary_predecessor_slots(Cms19DatabaseSupportRole::TypedTranscript {
                role: OracleEquationRole::EmptyProverResponseAbsorption,
            }),
            vec![Cms19PrimaryPreimagePointerSlot::PriorTranscriptState]
        );
        assert_eq!(
            designated_primary_predecessor_slots(Cms19DatabaseSupportRole::MerkleParents {
                role: MerkleOracleEquationRole::WhirEpoch { epoch_ordinal: 0 },
            }),
            vec![
                Cms19PrimaryPreimagePointerSlot::MerkleLeftChild,
                Cms19PrimaryPreimagePointerSlot::MerkleRightChild,
            ]
        );
        assert!(
            designated_primary_predecessor_slots(Cms19DatabaseSupportRole::TypedTranscript {
                role: OracleEquationRole::AtomicChallengeOutputBlock,
            })
            .is_empty()
        );
    }

    #[test]
    fn primary_grammar_discriminators_are_pairwise_exact() {
        let canonical_initial =
            Cms19ConcreteShake256PreimageFamily::CanonicalFoundationTuplePrimary {
                domain: TRANSCRIPT_INITIAL_DOMAIN,
            };
        let canonical_absorb =
            Cms19ConcreteShake256PreimageFamily::CanonicalFoundationTuplePrimary {
                domain: TRANSCRIPT_ABSORB_DOMAIN,
            };
        let legacy_statement = Cms19ConcreteShake256PreimageFamily::LegacyFramedHash512Primary {
            domain: crate::bgv::proof_suite::verifier::verified_common_proof_statement_hash_domain(
            ),
        };
        assert!(primary_preimage_families_are_identical_or_disjoint(
            canonical_initial,
            canonical_initial,
        ));
        assert!(primary_preimage_families_are_identical_or_disjoint(
            canonical_initial,
            canonical_absorb,
        ));
        assert!(primary_preimage_families_are_identical_or_disjoint(
            canonical_initial,
            legacy_statement,
        ));
        assert!(primary_preimage_families_are_identical_or_disjoint(
            Cms19ConcreteShake256PreimageFamily::PhaseColumnLeafPrimary,
            Cms19ConcreteShake256PreimageFamily::AggregateColumnStreamableLeafPrimary,
        ));
        assert!(primary_preimage_families_are_identical_or_disjoint(
            Cms19ConcreteShake256PreimageFamily::AggregateColumnStreamableLeafPrimary,
            Cms19ConcreteShake256PreimageFamily::AggregateWideParentPrimary,
        ));
    }

    #[test]
    fn primary_pointer_locations_match_the_production_encoders() {
        assert_eq!(
            designated_primary_predecessor_descriptors(
                Cms19DatabaseSupportRole::TypedTranscript {
                    role: OracleEquationRole::ResponseAbsorption,
                },
                Cms19ConcreteShake256PreimageFamily::CanonicalFoundationTuplePrimary {
                    domain: TRANSCRIPT_ABSORB_DOMAIN,
                },
            ),
            Ok(vec![
                Cms19PrimaryPreimagePointerDescriptor {
                    slot: Cms19PrimaryPreimagePointerSlot::PriorTranscriptState,
                    encoding:
                        Cms19PrimaryPreimagePointerEncoding::CanonicalFoundationTupleArgument {
                            argument_index: 0,
                        },
                },
                Cms19PrimaryPreimagePointerDescriptor {
                    slot: Cms19PrimaryPreimagePointerSlot::ResponseRoot,
                    encoding:
                        Cms19PrimaryPreimagePointerEncoding::CanonicalFoundationTupleArgument {
                            argument_index: 2,
                        },
                },
            ])
        );
        let aggregate_predecessor_offset = ROW_CODE_WHIR_SHAKE256_PROTOCOL_DOMAIN.len()
            + size_of::<u64>()
            + ROW_CODE_WHIR_AGGREGATE_LEAF_DOMAIN.len()
            + size_of::<u8>()
            + size_of::<u64>();
        assert_eq!(
            designated_primary_predecessor_descriptors(
                Cms19DatabaseSupportRole::AggregateLeafTransitionAndFinal {
                    role: MerkleOracleEquationRole::WhirEpoch { epoch_ordinal: 0 },
                },
                Cms19ConcreteShake256PreimageFamily::AggregateColumnStreamableLeafPrimary,
            ),
            Ok(vec![Cms19PrimaryPreimagePointerDescriptor {
                slot: Cms19PrimaryPreimagePointerSlot::StreamingLeafPredecessor,
                encoding: Cms19PrimaryPreimagePointerEncoding::RawDigestBytes {
                    byte_offset: aggregate_predecessor_offset,
                },
            }])
        );
    }
}
