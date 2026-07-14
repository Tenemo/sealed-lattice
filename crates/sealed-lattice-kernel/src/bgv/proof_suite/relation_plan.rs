use std::collections::BTreeSet;

use crate::bgv::parameters::{DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE, SPECIAL_PRIME};

use super::{COMMON_PROOF_PROFILE, profile::ProfileValidationError};

pub(crate) const MAXIMUM_PROOF_OBJECT_BYTE_LENGTH: u64 = 5_242_880;
const TRACE_MASK_DEGREE_BOUND_EXCLUSIVE: u64 = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub(crate) enum ProofFamily {
    SameSecret = 0x1211,
    PublicKeyShare = 0x1212,
    CollectivePublicKey = 0x1213,
    RelinearizationRoundOne = 0x1214,
    RelinearizationRoundOneAggregate = 0x1215,
    RelinearizationRoundTwo = 0x1216,
    GaloisKeyShare = 0x1217,
    EvaluatorKeyAggregate = 0x1218,
    DirectBallot = 0x1302,
    TargetDecryptionShare = 0x1621,
    VssShareLinkage = 0x2110,
    AggregateThresholdShare = 0x2111,
}

impl ProofFamily {
    pub(crate) const ALL: [Self; 12] = [
        Self::SameSecret,
        Self::PublicKeyShare,
        Self::CollectivePublicKey,
        Self::RelinearizationRoundOne,
        Self::RelinearizationRoundOneAggregate,
        Self::RelinearizationRoundTwo,
        Self::GaloisKeyShare,
        Self::EvaluatorKeyAggregate,
        Self::DirectBallot,
        Self::TargetDecryptionShare,
        Self::VssShareLinkage,
        Self::AggregateThresholdShare,
    ];

    pub(crate) const fn schema_identifier(self) -> u16 {
        self as u16
    }

    pub(crate) fn from_schema_identifier(schema_identifier: u16) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|family| family.schema_identifier() == schema_identifier)
    }

    pub(crate) const fn privacy_mode(self) -> ProofPrivacyMode {
        match self {
            Self::CollectivePublicKey
            | Self::RelinearizationRoundOneAggregate
            | Self::EvaluatorKeyAggregate => ProofPrivacyMode::PublicOnly,
            _ => ProofPrivacyMode::SecretBearing,
        }
    }

    pub(crate) const fn slot_ceiling(
        self,
        roster_size: u32,
        relinearization_position_count: u32,
        galois_position_count: u32,
        candidate_package_count: u32,
        target_share_submission_count: u32,
    ) -> Option<u32> {
        match self {
            Self::VssShareLinkage
            | Self::AggregateThresholdShare
            | Self::SameSecret
            | Self::PublicKeyShare => Some(roster_size),
            Self::CollectivePublicKey | Self::EvaluatorKeyAggregate => Some(1),
            Self::RelinearizationRoundOne | Self::RelinearizationRoundTwo => {
                roster_size.checked_mul(relinearization_position_count)
            }
            Self::RelinearizationRoundOneAggregate => Some(relinearization_position_count),
            Self::GaloisKeyShare => roster_size.checked_mul(galois_position_count),
            Self::DirectBallot => Some(candidate_package_count),
            Self::TargetDecryptionShare => Some(target_share_submission_count),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub(crate) enum ProofPrivacyMode {
    PublicOnly = 1,
    SecretBearing = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum RelationPlanVariantSelector {
    Unscheduled,
    SchedulePosition(u32),
    TopCount(u16),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RelationColumnSource {
    Verifier,
    Prover,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProofTreeValueType {
    BaseField,
    ChallengeField,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProofTreeRole {
    BoundPublicInput,
    BoundPublicOutput,
    Witness,
    QuotientComponent,
    OpeningBatchMask,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationColumnDescriptor {
    pub(crate) source: RelationColumnSource,
    pub(crate) degree_bound_exclusive: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProofTreeDescriptor {
    pub(crate) ordinal: u16,
    pub(crate) role: ProofTreeRole,
    pub(crate) value_type: ProofTreeValueType,
    pub(crate) row_width: u16,
    pub(crate) degree_bound_exclusive: u64,
    pub(crate) secret_bearing: bool,
    pub(crate) salted_leaves: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConstraintKind {
    LinearIdentity,
    ProductIdentity,
    TernaryRange,
    SchoolbookCarry,
    ImportedRootEquality,
    PublicFiniteSum,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Zeroifier {
    Trace,
    BoundaryRow(u32),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationConstraintDescriptor {
    pub(crate) kind: ConstraintKind,
    pub(crate) normalized_degree_bound_exclusive: u64,
    pub(crate) zeroifier: Zeroifier,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationOpeningClaimDescriptor {
    pub(crate) tree_ordinal: u16,
    pub(crate) source_degree_bound_exclusive: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationMaskDescriptor {
    pub(crate) purpose: u16,
    pub(crate) degree_bound_exclusive: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NonnativeModulusCertificate {
    pub(crate) modulus: u64,
    pub(crate) radix_bit_length: u16,
    pub(crate) limb_count: u16,
    pub(crate) maximum_schoolbook_accumulator: u128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OpeningDegreeCertificate {
    pub(crate) trace_domain_size: u64,
    pub(crate) trace_mask_degree_bound_exclusive: u64,
    pub(crate) quotient_segment_count: u16,
    pub(crate) quotient_segment_degree_bound_exclusive: u64,
    pub(crate) query_closure_coordinate_count: u32,
    pub(crate) opening_degree_bound_exclusive: u64,
    pub(crate) fri_round_count: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProofGrammarMetrics {
    pub(crate) proof_byte_ceiling: u64,
    pub(crate) merkle_authentication_hash_equations: u64,
    pub(crate) iop_round_count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationPlanVariant {
    pub(crate) selector: RelationPlanVariantSelector,
    pub(crate) privacy_mode: ProofPrivacyMode,
    pub(crate) trace_domain_size: u64,
    pub(crate) evaluation_domain_size: u64,
    pub(crate) ordered_nonnative_moduli: Vec<NonnativeModulusCertificate>,
    pub(crate) ordered_columns: Vec<RelationColumnDescriptor>,
    pub(crate) ordered_trees: Vec<ProofTreeDescriptor>,
    pub(crate) ordered_constraints: Vec<RelationConstraintDescriptor>,
    pub(crate) ordered_opening_claims: Vec<RelationOpeningClaimDescriptor>,
    pub(crate) ordered_masks: Vec<RelationMaskDescriptor>,
    pub(crate) degree_certificate: OpeningDegreeCertificate,
    pub(crate) proof_grammar_metrics: ProofGrammarMetrics,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationPlan {
    pub(crate) family: ProofFamily,
    pub(crate) variants: Vec<RelationPlanVariant>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum RootConstructionKind {
    CommittedMaterial,
    SetupPolynomial,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RelationRootCompatibilityEdge {
    pub(crate) producer_family: ProofFamily,
    pub(crate) producer_tree_ordinal: u16,
    pub(crate) consumer_family: ProofFamily,
    pub(crate) consumer_tree_ordinal: u16,
    pub(crate) construction_kind: RootConstructionKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationPlanCatalog {
    pub(crate) plans: Vec<RelationPlan>,
    pub(crate) root_compatibility_edges: Vec<RelationRootCompatibilityEdge>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RelationPlanValidationError {
    EmptyScheduleCatalog,
    FamilyCatalogMismatch,
    VariantCatalogMismatch,
    PrivacyModeMismatch,
    InvalidDomain,
    Profile(ProfileValidationError),
    InvalidNonnativeModulus,
    NonnativeAccumulatorWrapsBaseField,
    InvalidColumnCatalog,
    InvalidTreeCatalog,
    InvalidConstraintCatalog,
    InvalidOpeningCatalog,
    InvalidMaskCatalog,
    InvalidDegreeCertificate,
    ProofByteCeilingExceeded,
    RootCompatibilityMismatch,
    ArithmeticOverflow,
}

pub(crate) fn build_relation_plan_catalog(
    relinearization_catalog_length: u32,
    galois_catalog_length: u32,
) -> Result<RelationPlanCatalog, RelationPlanValidationError> {
    if relinearization_catalog_length == 0 || galois_catalog_length == 0 {
        return Err(RelationPlanValidationError::EmptyScheduleCatalog);
    }
    let mut plans = Vec::with_capacity(ProofFamily::ALL.len());
    let mut next_mask_purpose = 1_u16;
    for family in ProofFamily::ALL {
        let selectors = match family {
            ProofFamily::RelinearizationRoundOne
            | ProofFamily::RelinearizationRoundOneAggregate
            | ProofFamily::RelinearizationRoundTwo => (0..relinearization_catalog_length)
                .map(RelationPlanVariantSelector::SchedulePosition)
                .collect(),
            ProofFamily::GaloisKeyShare => (0..galois_catalog_length)
                .map(RelationPlanVariantSelector::SchedulePosition)
                .collect(),
            ProofFamily::EvaluatorKeyAggregate => (1..=20)
                .map(RelationPlanVariantSelector::TopCount)
                .collect(),
            _ => vec![RelationPlanVariantSelector::Unscheduled],
        };
        let mut variants = Vec::with_capacity(selectors.len());
        for selector in selectors {
            let ordered_mask_purposes =
                allocate_mask_purposes(family.privacy_mode(), &mut next_mask_purpose)?;
            variants.push(build_variant(family, selector, ordered_mask_purposes)?);
        }
        plans.push(RelationPlan { family, variants });
    }

    let root_compatibility_edges = vec![
        edge(
            ProofFamily::VssShareLinkage,
            ProofFamily::AggregateThresholdShare,
            RootConstructionKind::CommittedMaterial,
        ),
        edge(
            ProofFamily::VssShareLinkage,
            ProofFamily::SameSecret,
            RootConstructionKind::CommittedMaterial,
        ),
        edge(
            ProofFamily::SameSecret,
            ProofFamily::PublicKeyShare,
            RootConstructionKind::CommittedMaterial,
        ),
        edge(
            ProofFamily::PublicKeyShare,
            ProofFamily::CollectivePublicKey,
            RootConstructionKind::SetupPolynomial,
        ),
        edge(
            ProofFamily::CollectivePublicKey,
            ProofFamily::RelinearizationRoundOne,
            RootConstructionKind::SetupPolynomial,
        ),
        edge(
            ProofFamily::RelinearizationRoundOne,
            ProofFamily::RelinearizationRoundOneAggregate,
            RootConstructionKind::SetupPolynomial,
        ),
        edge(
            ProofFamily::RelinearizationRoundOneAggregate,
            ProofFamily::RelinearizationRoundTwo,
            RootConstructionKind::SetupPolynomial,
        ),
        edge(
            ProofFamily::RelinearizationRoundTwo,
            ProofFamily::EvaluatorKeyAggregate,
            RootConstructionKind::SetupPolynomial,
        ),
        edge(
            ProofFamily::GaloisKeyShare,
            ProofFamily::EvaluatorKeyAggregate,
            RootConstructionKind::SetupPolynomial,
        ),
    ];
    let catalog = RelationPlanCatalog {
        plans,
        root_compatibility_edges,
    };
    catalog.validate(relinearization_catalog_length, galois_catalog_length)?;
    Ok(catalog)
}

fn edge(
    producer_family: ProofFamily,
    consumer_family: ProofFamily,
    construction_kind: RootConstructionKind,
) -> RelationRootCompatibilityEdge {
    RelationRootCompatibilityEdge {
        producer_family,
        producer_tree_ordinal: 1,
        consumer_family,
        consumer_tree_ordinal: 0,
        construction_kind,
    }
}

fn build_variant(
    family: ProofFamily,
    selector: RelationPlanVariantSelector,
    ordered_mask_purposes: Vec<u16>,
) -> Result<RelationPlanVariant, RelationPlanValidationError> {
    let privacy_mode = family.privacy_mode();
    let trace_domain_size = POLYNOMIAL_DEGREE as u64;
    let secret_bearing = privacy_mode == ProofPrivacyMode::SecretBearing;
    let trace_mask_degree_bound_exclusive = if secret_bearing {
        TRACE_MASK_DEGREE_BOUND_EXCLUSIVE
    } else {
        0
    };
    let quotient_segment_count = 3_u16;
    let quotient_segment_degree_bound_exclusive = if secret_bearing {
        trace_domain_size
            .checked_add(
                (u64::from(quotient_segment_count) + 1)
                    .checked_mul(trace_mask_degree_bound_exclusive)
                    .ok_or(RelationPlanValidationError::ArithmeticOverflow)?
                    .div_ceil(u64::from(quotient_segment_count)),
            )
            .ok_or(RelationPlanValidationError::ArithmeticOverflow)?
    } else {
        trace_domain_size
    };
    let query_closure_coordinate_count = COMMON_PROOF_PROFILE.unique_query_count;
    let quotient_mask_degree = u64::from(COMMON_PROOF_PROFILE.deep_point_count)
        + u64::from(query_closure_coordinate_count);
    let opening_degree_bound_exclusive = quotient_segment_degree_bound_exclusive
        .checked_add(if secret_bearing {
            quotient_mask_degree
        } else {
            0
        })
        .ok_or(RelationPlanValidationError::ArithmeticOverflow)?;
    let rounded_opening_bound = opening_degree_bound_exclusive.next_power_of_two();
    let evaluation_domain_size = rounded_opening_bound
        .checked_mul(u64::from(COMMON_PROOF_PROFILE.evaluation_blowup_factor))
        .ok_or(RelationPlanValidationError::ArithmeticOverflow)?;
    let fri_round_count = fri_round_count(opening_degree_bound_exclusive)?;

    let (public_column_count, prover_column_count) = semantic_column_counts(family);
    let mut ordered_columns = Vec::new();
    ordered_columns.extend((0..public_column_count).map(|_| RelationColumnDescriptor {
        source: RelationColumnSource::Verifier,
        degree_bound_exclusive: trace_domain_size,
    }));
    ordered_columns.extend((0..prover_column_count).map(|_| RelationColumnDescriptor {
        source: RelationColumnSource::Prover,
        degree_bound_exclusive: trace_domain_size + trace_mask_degree_bound_exclusive,
    }));
    let mut ordered_trees = vec![
        ProofTreeDescriptor {
            ordinal: 0,
            role: ProofTreeRole::BoundPublicInput,
            value_type: ProofTreeValueType::BaseField,
            row_width: public_column_count,
            degree_bound_exclusive: trace_domain_size,
            secret_bearing: false,
            salted_leaves: false,
        },
        ProofTreeDescriptor {
            ordinal: 1,
            role: ProofTreeRole::BoundPublicOutput,
            value_type: ProofTreeValueType::BaseField,
            row_width: 2,
            degree_bound_exclusive: trace_domain_size,
            secret_bearing: false,
            salted_leaves: false,
        },
    ];
    if secret_bearing {
        ordered_trees.push(ProofTreeDescriptor {
            ordinal: u16::try_from(ordered_trees.len())
                .map_err(|_| RelationPlanValidationError::ArithmeticOverflow)?,
            role: ProofTreeRole::Witness,
            value_type: ProofTreeValueType::BaseField,
            row_width: prover_column_count,
            degree_bound_exclusive: trace_domain_size + trace_mask_degree_bound_exclusive,
            secret_bearing: true,
            salted_leaves: true,
        });
    }
    for _ in 0..quotient_segment_count {
        ordered_trees.push(ProofTreeDescriptor {
            ordinal: u16::try_from(ordered_trees.len())
                .map_err(|_| RelationPlanValidationError::ArithmeticOverflow)?,
            role: ProofTreeRole::QuotientComponent,
            value_type: ProofTreeValueType::ChallengeField,
            row_width: 1,
            degree_bound_exclusive: opening_degree_bound_exclusive,
            secret_bearing,
            salted_leaves: secret_bearing,
        });
    }
    if secret_bearing {
        ordered_trees.push(ProofTreeDescriptor {
            ordinal: u16::try_from(ordered_trees.len())
                .map_err(|_| RelationPlanValidationError::ArithmeticOverflow)?,
            role: ProofTreeRole::OpeningBatchMask,
            value_type: ProofTreeValueType::ChallengeField,
            row_width: 1,
            degree_bound_exclusive: quotient_mask_degree,
            secret_bearing: true,
            salted_leaves: true,
        });
    }

    let ordered_constraints = semantic_constraints(family, trace_domain_size);
    let ordered_opening_claims = ordered_trees
        .iter()
        .map(|tree| RelationOpeningClaimDescriptor {
            tree_ordinal: tree.ordinal,
            source_degree_bound_exclusive: tree.degree_bound_exclusive,
        })
        .collect::<Vec<_>>();
    let ordered_masks = if secret_bearing {
        if ordered_mask_purposes.len() != 2 {
            return Err(RelationPlanValidationError::InvalidMaskCatalog);
        }
        vec![
            RelationMaskDescriptor {
                purpose: ordered_mask_purposes[0],
                degree_bound_exclusive: trace_mask_degree_bound_exclusive,
            },
            RelationMaskDescriptor {
                purpose: ordered_mask_purposes[1],
                degree_bound_exclusive: quotient_mask_degree,
            },
        ]
    } else {
        if !ordered_mask_purposes.is_empty() {
            return Err(RelationPlanValidationError::InvalidMaskCatalog);
        }
        Vec::new()
    };
    let ordered_nonnative_moduli = nonnative_moduli_for_family(family)
        .into_iter()
        .map(nonnative_certificate)
        .collect::<Result<Vec<_>, _>>()?;
    let degree_certificate = OpeningDegreeCertificate {
        trace_domain_size,
        trace_mask_degree_bound_exclusive,
        quotient_segment_count,
        quotient_segment_degree_bound_exclusive,
        query_closure_coordinate_count,
        opening_degree_bound_exclusive,
        fri_round_count,
    };
    let proof_grammar_metrics = proof_grammar_metrics(
        evaluation_domain_size,
        &ordered_trees,
        &ordered_opening_claims,
        fri_round_count,
    )?;

    Ok(RelationPlanVariant {
        selector,
        privacy_mode,
        trace_domain_size,
        evaluation_domain_size,
        ordered_nonnative_moduli,
        ordered_columns,
        ordered_trees,
        ordered_constraints,
        ordered_opening_claims,
        ordered_masks,
        degree_certificate,
        proof_grammar_metrics,
    })
}

fn allocate_mask_purposes(
    privacy_mode: ProofPrivacyMode,
    next_mask_purpose: &mut u16,
) -> Result<Vec<u16>, RelationPlanValidationError> {
    if privacy_mode == ProofPrivacyMode::PublicOnly {
        return Ok(Vec::new());
    }

    let mut purposes = Vec::with_capacity(2);
    for _ in 0..2 {
        if *next_mask_purpose == 0 || *next_mask_purpose >= 0xff00 {
            return Err(RelationPlanValidationError::ArithmeticOverflow);
        }
        purposes.push(*next_mask_purpose);
        *next_mask_purpose = next_mask_purpose
            .checked_add(1)
            .ok_or(RelationPlanValidationError::ArithmeticOverflow)?;
    }
    Ok(purposes)
}

fn semantic_column_counts(family: ProofFamily) -> (u16, u16) {
    match family {
        ProofFamily::VssShareLinkage => (8, 12),
        ProofFamily::AggregateThresholdShare => (8, 8),
        ProofFamily::SameSecret => (10, 10),
        ProofFamily::PublicKeyShare => (12, 12),
        ProofFamily::CollectivePublicKey => (12, 0),
        ProofFamily::RelinearizationRoundOne => (16, 20),
        ProofFamily::RelinearizationRoundOneAggregate => (16, 0),
        ProofFamily::RelinearizationRoundTwo => (20, 28),
        ProofFamily::GaloisKeyShare => (16, 20),
        ProofFamily::EvaluatorKeyAggregate => (20, 0),
        ProofFamily::DirectBallot => (12, 32),
        ProofFamily::TargetDecryptionShare => (16, 24),
    }
}

fn semantic_constraints(
    family: ProofFamily,
    trace_domain_size: u64,
) -> Vec<RelationConstraintDescriptor> {
    let mut kinds = vec![
        ConstraintKind::LinearIdentity,
        ConstraintKind::ImportedRootEquality,
    ];
    if family.privacy_mode() == ProofPrivacyMode::PublicOnly {
        kinds.push(ConstraintKind::PublicFiniteSum);
    } else {
        kinds.extend([
            ConstraintKind::ProductIdentity,
            ConstraintKind::TernaryRange,
            ConstraintKind::SchoolbookCarry,
        ]);
    }
    kinds
        .into_iter()
        .enumerate()
        .map(|(constraint_index, kind)| RelationConstraintDescriptor {
            kind,
            normalized_degree_bound_exclusive: match kind {
                ConstraintKind::ProductIdentity | ConstraintKind::SchoolbookCarry => {
                    3 * trace_domain_size
                }
                ConstraintKind::TernaryRange => 4 * trace_domain_size,
                _ => 2 * trace_domain_size,
            },
            zeroifier: if constraint_index == 0 {
                Zeroifier::BoundaryRow(0)
            } else {
                Zeroifier::Trace
            },
        })
        .collect()
}

fn nonnative_moduli_for_family(family: ProofFamily) -> Vec<u64> {
    let mut moduli = vec![PLAINTEXT_MODULUS];
    match family {
        ProofFamily::VssShareLinkage
        | ProofFamily::AggregateThresholdShare
        | ProofFamily::SameSecret => moduli.extend(DATA_PRIMES[..3].iter().copied()),
        ProofFamily::TargetDecryptionShare => {
            moduli.extend(
                DATA_PRIMES[..=crate::bgv::evaluator::top_k::CANONICAL_TARGET_CIPHERTEXT_LEVEL]
                    .iter()
                    .copied(),
            );
        }
        _ => {
            moduli.extend(DATA_PRIMES);
            if matches!(
                family,
                ProofFamily::RelinearizationRoundOne
                    | ProofFamily::RelinearizationRoundOneAggregate
                    | ProofFamily::RelinearizationRoundTwo
                    | ProofFamily::GaloisKeyShare
                    | ProofFamily::EvaluatorKeyAggregate
            ) {
                moduli.push(SPECIAL_PRIME);
            }
        }
    }
    moduli.sort_unstable();
    moduli.dedup();
    moduli
}

fn nonnative_certificate(
    modulus: u64,
) -> Result<NonnativeModulusCertificate, RelationPlanValidationError> {
    let radix_bit_length = 16_u16;
    let modulus_bit_length = 64_u32 - modulus.leading_zeros();
    let limb_count = u16::try_from(modulus_bit_length.div_ceil(u32::from(radix_bit_length)))
        .map_err(|_| RelationPlanValidationError::ArithmeticOverflow)?;
    let maximum_limb = (1_u128 << radix_bit_length) - 1;
    let maximum_schoolbook_accumulator = u128::from(limb_count)
        .checked_mul(maximum_limb * maximum_limb)
        .and_then(|value| value.checked_add(maximum_limb * 2))
        .ok_or(RelationPlanValidationError::ArithmeticOverflow)?;
    Ok(NonnativeModulusCertificate {
        modulus,
        radix_bit_length,
        limb_count,
        maximum_schoolbook_accumulator,
    })
}

fn fri_round_count(
    opening_degree_bound_exclusive: u64,
) -> Result<u16, RelationPlanValidationError> {
    let terminal_bound = u64::from(COMMON_PROOF_PROFILE.final_polynomial_degree_bound_exclusive);
    if opening_degree_bound_exclusive <= 1 || terminal_bound >= opening_degree_bound_exclusive - 1 {
        return Err(RelationPlanValidationError::InvalidDegreeCertificate);
    }

    // The protocol folds a polynomial whose degree is strictly smaller than
    // opening_degree_bound_exclusive - 1. It requires the smallest positive
    // fold count whose resulting exclusive bound fits the terminal bound.
    let mut folded_bound = (opening_degree_bound_exclusive - 1).div_ceil(2);
    let mut rounds = 1_u16;
    while folded_bound > terminal_bound {
        folded_bound = folded_bound.div_ceil(2);
        rounds = rounds
            .checked_add(1)
            .ok_or(RelationPlanValidationError::ArithmeticOverflow)?;
    }
    Ok(rounds)
}

fn proof_grammar_metrics(
    evaluation_domain_size: u64,
    trees: &[ProofTreeDescriptor],
    opening_claims: &[RelationOpeningClaimDescriptor],
    fri_round_count: u16,
) -> Result<ProofGrammarMetrics, RelationPlanValidationError> {
    let query_count = u64::from(COMMON_PROOF_PROFILE.unique_query_count);
    let initial_tree_depth = u64::from(evaluation_domain_size.trailing_zeros());
    let mut authentication_equations_per_query = initial_tree_depth
        .checked_mul(
            u64::try_from(trees.len())
                .map_err(|_| RelationPlanValidationError::ArithmeticOverflow)?,
        )
        .ok_or(RelationPlanValidationError::ArithmeticOverflow)?;
    let mut query_bytes = 8_u64;
    for tree in trees {
        let value_byte_length = match tree.value_type {
            ProofTreeValueType::BaseField => 8_u64,
            ProofTreeValueType::ChallengeField => 40_u64,
        };
        query_bytes = query_bytes
            .checked_add(value_byte_length * u64::from(tree.row_width))
            .and_then(|value| value.checked_add(initial_tree_depth * 64))
            .and_then(|value| value.checked_add(if tree.salted_leaves { 64 } else { 0 }))
            .ok_or(RelationPlanValidationError::ArithmeticOverflow)?;
    }
    let committed_fri_layer_count = fri_round_count
        .checked_sub(1)
        .ok_or(RelationPlanValidationError::InvalidDegreeCertificate)?;
    for round_index in 0..committed_fri_layer_count {
        let round_domain_size = evaluation_domain_size >> u32::from(round_index + 1);
        let round_depth = u64::from(round_domain_size.trailing_zeros());
        authentication_equations_per_query = authentication_equations_per_query
            .checked_add(round_depth)
            .ok_or(RelationPlanValidationError::ArithmeticOverflow)?;
        query_bytes = query_bytes
            .checked_add(80)
            .and_then(|value| value.checked_add(round_depth * 64))
            .ok_or(RelationPlanValidationError::ArithmeticOverflow)?;
    }
    let merkle_authentication_hash_equations = authentication_equations_per_query
        .checked_mul(query_count)
        .ok_or(RelationPlanValidationError::ArithmeticOverflow)?;
    let root_count = u64::try_from(trees.len())
        .map_err(|_| RelationPlanValidationError::ArithmeticOverflow)?
        .checked_add(u64::from(committed_fri_layer_count))
        .ok_or(RelationPlanValidationError::ArithmeticOverflow)?;
    let deep_value_bytes = u64::try_from(opening_claims.len())
        .map_err(|_| RelationPlanValidationError::ArithmeticOverflow)?
        .checked_mul(u64::from(COMMON_PROOF_PROFILE.deep_point_count))
        .and_then(|value| value.checked_mul(40))
        .ok_or(RelationPlanValidationError::ArithmeticOverflow)?;
    let terminal_bytes = u64::from(COMMON_PROOF_PROFILE.final_polynomial_degree_bound_exclusive)
        .checked_mul(40)
        .ok_or(RelationPlanValidationError::ArithmeticOverflow)?;
    let proof_byte_ceiling = 96_u64
        .checked_add(root_count * 64)
        .and_then(|value| value.checked_add(deep_value_bytes))
        .and_then(|value| value.checked_add(query_bytes * query_count))
        .and_then(|value| value.checked_add(terminal_bytes))
        .ok_or(RelationPlanValidationError::ArithmeticOverflow)?;
    let iop_round_count = u32::try_from(trees.len())
        .map_err(|_| RelationPlanValidationError::ArithmeticOverflow)?
        .checked_add(u32::from(committed_fri_layer_count))
        .and_then(|value| value.checked_add(2))
        .ok_or(RelationPlanValidationError::ArithmeticOverflow)?;
    Ok(ProofGrammarMetrics {
        proof_byte_ceiling,
        merkle_authentication_hash_equations,
        iop_round_count,
    })
}

impl RelationPlanCatalog {
    pub(crate) fn validate(
        &self,
        relinearization_catalog_length: u32,
        galois_catalog_length: u32,
    ) -> Result<(), RelationPlanValidationError> {
        if self.plans.len() != ProofFamily::ALL.len()
            || self
                .plans
                .iter()
                .map(|plan| plan.family)
                .ne(ProofFamily::ALL)
        {
            return Err(RelationPlanValidationError::FamilyCatalogMismatch);
        }
        for plan in &self.plans {
            let expected_variant_count = match plan.family {
                ProofFamily::RelinearizationRoundOne
                | ProofFamily::RelinearizationRoundOneAggregate
                | ProofFamily::RelinearizationRoundTwo => relinearization_catalog_length,
                ProofFamily::GaloisKeyShare => galois_catalog_length,
                ProofFamily::EvaluatorKeyAggregate => 20,
                _ => 1,
            };
            if plan.variants.len() != expected_variant_count as usize {
                return Err(RelationPlanValidationError::VariantCatalogMismatch);
            }
            for (variant_index, variant) in plan.variants.iter().enumerate() {
                validate_variant(plan.family, variant, variant_index)?;
            }
        }
        let mut global_mask_purposes = BTreeSet::new();
        let mut next_expected_mask_purpose = 1_u16;
        for mask in self
            .plans
            .iter()
            .flat_map(|plan| &plan.variants)
            .flat_map(|variant| &variant.ordered_masks)
        {
            if mask.purpose != next_expected_mask_purpose
                || mask.purpose >= 0xff00
                || !global_mask_purposes.insert(mask.purpose)
            {
                return Err(RelationPlanValidationError::InvalidMaskCatalog);
            }
            next_expected_mask_purpose = next_expected_mask_purpose
                .checked_add(1)
                .ok_or(RelationPlanValidationError::ArithmeticOverflow)?;
        }
        let edge_set = self
            .root_compatibility_edges
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        if edge_set.len() != self.root_compatibility_edges.len() {
            return Err(RelationPlanValidationError::RootCompatibilityMismatch);
        }
        for edge in &self.root_compatibility_edges {
            let producer = self
                .plans
                .iter()
                .find(|plan| plan.family == edge.producer_family)
                .ok_or(RelationPlanValidationError::RootCompatibilityMismatch)?;
            let consumer = self
                .plans
                .iter()
                .find(|plan| plan.family == edge.consumer_family)
                .ok_or(RelationPlanValidationError::RootCompatibilityMismatch)?;
            if producer.variants.iter().any(|variant| {
                variant
                    .ordered_trees
                    .get(edge.producer_tree_ordinal as usize)
                    .map(|tree| tree.role)
                    != Some(ProofTreeRole::BoundPublicOutput)
            }) || consumer.variants.iter().any(|variant| {
                variant
                    .ordered_trees
                    .get(edge.consumer_tree_ordinal as usize)
                    .map(|tree| tree.role)
                    != Some(ProofTreeRole::BoundPublicInput)
            }) {
                return Err(RelationPlanValidationError::RootCompatibilityMismatch);
            }
        }
        Ok(())
    }

    pub(crate) fn plan(&self, family: ProofFamily) -> Option<&RelationPlan> {
        self.plans.iter().find(|plan| plan.family == family)
    }

    pub(crate) fn validate_mask_purpose(
        &self,
        family: ProofFamily,
        selector: RelationPlanVariantSelector,
        purpose: u16,
    ) -> Result<(), RelationPlanValidationError> {
        let variant = self
            .plan(family)
            .and_then(|plan| {
                plan.variants
                    .iter()
                    .find(|variant| variant.selector == selector)
            })
            .ok_or(RelationPlanValidationError::VariantCatalogMismatch)?;
        if !variant
            .ordered_masks
            .iter()
            .any(|mask| mask.purpose == purpose)
        {
            return Err(RelationPlanValidationError::InvalidMaskCatalog);
        }
        Ok(())
    }

    pub(crate) fn maximum_evaluation_domain_size(&self) -> u64 {
        self.plans
            .iter()
            .flat_map(|plan| &plan.variants)
            .map(|variant| variant.evaluation_domain_size)
            .max()
            .expect("the validated relation-plan catalog is nonempty")
    }

    pub(crate) fn maximum_security_metrics(&self) -> (u64, u32) {
        self.plans
            .iter()
            .flat_map(|plan| &plan.variants)
            .map(|variant| {
                (
                    variant
                        .proof_grammar_metrics
                        .merkle_authentication_hash_equations,
                    variant.proof_grammar_metrics.iop_round_count,
                )
            })
            .max()
            .expect("the validated relation-plan catalog is nonempty")
    }
}

fn validate_variant(
    family: ProofFamily,
    variant: &RelationPlanVariant,
    variant_index: usize,
) -> Result<(), RelationPlanValidationError> {
    if variant.privacy_mode != family.privacy_mode() {
        return Err(RelationPlanValidationError::PrivacyModeMismatch);
    }
    COMMON_PROOF_PROFILE
        .validate(variant.trace_domain_size, variant.evaluation_domain_size)
        .map_err(RelationPlanValidationError::Profile)?;
    let expected_evaluation_domain_size = variant
        .degree_certificate
        .opening_degree_bound_exclusive
        .next_power_of_two()
        .checked_mul(u64::from(COMMON_PROOF_PROFILE.evaluation_blowup_factor))
        .ok_or(RelationPlanValidationError::ArithmeticOverflow)?;
    if variant.evaluation_domain_size != expected_evaluation_domain_size {
        return Err(RelationPlanValidationError::InvalidDomain);
    }
    if variant.ordered_nonnative_moduli.is_empty() {
        return Err(RelationPlanValidationError::InvalidNonnativeModulus);
    }
    let mut previous_modulus = None;
    for certificate in &variant.ordered_nonnative_moduli {
        if certificate.modulus >= COMMON_PROOF_PROFILE.base_field_modulus
            || previous_modulus.is_some_and(|previous| previous >= certificate.modulus)
        {
            return Err(RelationPlanValidationError::InvalidNonnativeModulus);
        }
        if certificate.maximum_schoolbook_accumulator
            >= u128::from(COMMON_PROOF_PROFILE.base_field_modulus)
        {
            return Err(RelationPlanValidationError::NonnativeAccumulatorWrapsBaseField);
        }
        previous_modulus = Some(certificate.modulus);
    }
    if variant.ordered_columns.is_empty()
        || !variant
            .ordered_columns
            .iter()
            .any(|column| column.source == RelationColumnSource::Verifier)
    {
        return Err(RelationPlanValidationError::InvalidColumnCatalog);
    }
    let has_prover_column = variant
        .ordered_columns
        .iter()
        .any(|column| column.source == RelationColumnSource::Prover);
    let has_private_tree = variant
        .ordered_trees
        .iter()
        .any(|tree| tree.secret_bearing || tree.salted_leaves);
    match variant.privacy_mode {
        ProofPrivacyMode::PublicOnly
            if has_prover_column || has_private_tree || !variant.ordered_masks.is_empty() =>
        {
            return Err(RelationPlanValidationError::PrivacyModeMismatch);
        }
        ProofPrivacyMode::SecretBearing
            if !has_prover_column || !has_private_tree || variant.ordered_masks.is_empty() =>
        {
            return Err(RelationPlanValidationError::PrivacyModeMismatch);
        }
        _ => {}
    }
    if variant
        .ordered_trees
        .iter()
        .enumerate()
        .any(|(ordinal, tree)| tree.ordinal as usize != ordinal || tree.row_width == 0)
    {
        return Err(RelationPlanValidationError::InvalidTreeCatalog);
    }
    if variant.ordered_constraints.is_empty()
        || variant.ordered_constraints.iter().any(|constraint| {
            constraint.normalized_degree_bound_exclusive == 0
                || matches!(constraint.zeroifier, Zeroifier::BoundaryRow(row) if u64::from(row) >= variant.trace_domain_size)
        })
    {
        return Err(RelationPlanValidationError::InvalidConstraintCatalog);
    }
    if variant.ordered_opening_claims.len() != variant.ordered_trees.len()
        || variant.ordered_opening_claims.iter().any(|claim| {
            claim.source_degree_bound_exclusive == 0
                || claim.source_degree_bound_exclusive
                    > variant.degree_certificate.opening_degree_bound_exclusive
                || variant
                    .ordered_trees
                    .get(claim.tree_ordinal as usize)
                    .is_none()
        })
    {
        return Err(RelationPlanValidationError::InvalidOpeningCatalog);
    }
    let unique_mask_purposes = variant
        .ordered_masks
        .iter()
        .map(|mask| mask.purpose)
        .collect::<BTreeSet<_>>();
    if unique_mask_purposes.len() != variant.ordered_masks.len()
        || variant.ordered_masks.iter().any(|mask| {
            mask.purpose == 0 || mask.purpose >= 0xff00 || mask.degree_bound_exclusive == 0
        })
    {
        return Err(RelationPlanValidationError::InvalidMaskCatalog);
    }
    let certificate = &variant.degree_certificate;
    let expected_mask_degree = if variant.privacy_mode == ProofPrivacyMode::SecretBearing {
        TRACE_MASK_DEGREE_BOUND_EXCLUSIVE
    } else {
        0
    };
    let expected_fri_round_count = fri_round_count(certificate.opening_degree_bound_exclusive)?;
    if certificate.trace_domain_size != variant.trace_domain_size
        || certificate.trace_mask_degree_bound_exclusive != expected_mask_degree
        || certificate.quotient_segment_count != 3
        || certificate.query_closure_coordinate_count != COMMON_PROOF_PROFILE.unique_query_count
        || certificate.fri_round_count != expected_fri_round_count
        || (variant.privacy_mode == ProofPrivacyMode::SecretBearing
            && 2 * (5 * u32::from(COMMON_PROOF_PROFILE.deep_point_count)
                + certificate.query_closure_coordinate_count)
                > certificate.trace_mask_degree_bound_exclusive as u32)
    {
        return Err(RelationPlanValidationError::InvalidDegreeCertificate);
    }
    if variant.proof_grammar_metrics.proof_byte_ceiling > MAXIMUM_PROOF_OBJECT_BYTE_LENGTH {
        return Err(RelationPlanValidationError::ProofByteCeilingExceeded);
    }
    let expected_selector = match family {
        ProofFamily::RelinearizationRoundOne
        | ProofFamily::RelinearizationRoundOneAggregate
        | ProofFamily::RelinearizationRoundTwo
        | ProofFamily::GaloisKeyShare => {
            RelationPlanVariantSelector::SchedulePosition(variant_index as u32)
        }
        ProofFamily::EvaluatorKeyAggregate => {
            RelationPlanVariantSelector::TopCount((variant_index + 1) as u16)
        }
        _ => RelationPlanVariantSelector::Unscheduled,
    };
    if variant.selector != expected_selector {
        return Err(RelationPlanValidationError::VariantCatalogMismatch);
    }
    Ok(())
}
