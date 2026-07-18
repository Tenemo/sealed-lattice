use std::collections::{BTreeMap, BTreeSet};

use num_traits::ToPrimitive;
use zeroize::Zeroizing;

use crate::{
    bgv::{
        parameters::PLAINTEXT_MODULUS,
        setup::{
            SETUP_COMMITMENT_MODULE_RANK, SetupGenerationAuthorityHandle,
            SetupGenerationKeyRelationApplication, SetupGenerationKeyRelationSource,
            SetupKeyRelationProofFamily, sample_collective_public_key_common_reference_limb,
            setup_commitment_matrix_polynomial, with_setup_generation_key_relation,
        },
    },
    foundation::{Hash512, PreparedActionProofAttemptSource, RefusalReason},
    hashing::hash_framed_parts_512,
    transcript_core::encode_hex,
};

use super::super::prover::{integer_lift_derived_columns, proof_created_tree_roles_by_column};
use super::super::{
    CommonProofBoundTreeLeafSaltRequest, CommonProofProverError, CommonProofRelationPlanCapability,
    CommonProofSourcePolynomial, CommonProofSourcePolynomialProvider,
    CommonProofSourcePolynomialProviderPoll, CommonProofSourcePolynomialReplayIdentity,
    CommonProofSourcePolynomialRequest, CommonProofSourcePolynomialRequestContext,
    ProofBaseFieldElement, ProofEvaluationDomain, ProofLeafVisibility, ProofTreeRole,
    ProvidedCommonProofSourcePolynomial, RelationProofTreeInput, StatementOwnedProofTreeInput,
};
use super::{
    BoundTreeConstructionKind, PublicKeyShareSourceLayout, RelationBoundCertificate,
    RelationColumnOrigin, RelationIntegerLiftCoefficient, RelationIntegerLiftFullRingHalf,
    RelationIntegerLiftFullRingNegacyclicProductDescriptor, RelationPlanCheckContext,
    RelationPlanVariant, RelationTreeDescriptor, RelationVerifierSource, SameSecretSourceLayout,
    SuiteModulusReference,
    galois_key_share_adapter::{
        anchor_full_row, canonical_comparator_column_rows, centered_residue,
        exact_modular_quotient, exact_negacyclic_product_radix, exact_negacyclic_product_small,
        half_position, requested_source_column_ordinals, resolve_integer_lift_coefficient,
        signed_integer_to_base_field, split_rows_match, split_signed_i8_polynomial,
        split_signed_polynomial,
    },
    key_relation::{EXACT_INTEGER_LIFT_RADIX, SplitIntegerVector},
};

const SAME_SECRET_SOURCE_REPLAY_IDENTITY_DOMAIN: &str =
    "sealed-lattice/same-secret/source-replay-identity/v1";
const PUBLIC_KEY_SHARE_SOURCE_REPLAY_IDENTITY_DOMAIN: &str =
    "sealed-lattice/public-key-share/source-replay-identity/v1";

enum SetupKeyRelationSourceLayout {
    SameSecret(SameSecretSourceLayout),
    PublicKeyShare(PublicKeyShareSourceLayout),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CachedQuotientKey {
    Anchor {
        family: SetupKeyRelationProofFamily,
        anchor_ordinal: usize,
        row_ordinal: usize,
    },
    PublicKeyShare {
        limb_ordinal: usize,
    },
}

struct CachedQuotient {
    key: CachedQuotientKey,
    coefficients: Zeroizing<Vec<i128>>,
}

#[derive(Clone, Copy)]
struct BoundMaterialTreeSource {
    tree_catalog_index: u16,
    material_ordinal: usize,
}

/// Ordered generation-only source provider for the selected same-secret and
/// public-key-share relations. It retains reset-stable binding facts and
/// relation layout only; every secret or authenticated material read reenters
/// the browser-owned setup authority.
pub(crate) struct SetupKeyRelationSourcePolynomialAdapter {
    authority_identifier: u32,
    family: SetupKeyRelationProofFamily,
    prepared_attempt: PreparedActionProofAttemptSource,
    canonical_application_statement_bytes: Vec<u8>,
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    roster_position: u16,
    setup_attempt_identifier: [u8; 32],
    source_setup_intent_object_hash: [u8; Hash512::BYTE_LENGTH],
    action_randomness_authorization_hash: [u8; Hash512::BYTE_LENGTH],
    request_context: CommonProofSourcePolynomialRequestContext,
    relation_plan_variant: RelationPlanVariant,
    relation_context: RelationPlanCheckContext,
    ring_degree: usize,
    source_layout: SetupKeyRelationSourceLayout,
    requested_column_ordinals: Box<[u32]>,
    bound_material_tree_sources: Box<[BoundMaterialTreeSource]>,
    next_source_index: usize,
    next_leaf_salt_source_ordinal: usize,
    next_leaf_salt_index: usize,
    cached_quotient: Option<CachedQuotient>,
    source_polynomials_finished: bool,
    leaf_salts_finished: bool,
}

impl SetupKeyRelationSourcePolynomialAdapter {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_same_secret(
        source: &SetupGenerationKeyRelationSource<'_, '_>,
        relation_plan: &CommonProofRelationPlanCapability,
        relation_plan_variant: RelationPlanVariant,
        relation_context: RelationPlanCheckContext,
        ring_degree: usize,
        source_layout: SameSecretSourceLayout,
    ) -> Result<Self, CommonProofProverError> {
        Self::new(
            source,
            relation_plan,
            relation_plan_variant,
            relation_context,
            ring_degree,
            SetupKeyRelationSourceLayout::SameSecret(source_layout),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_public_key_share(
        source: &SetupGenerationKeyRelationSource<'_, '_>,
        relation_plan: &CommonProofRelationPlanCapability,
        relation_plan_variant: RelationPlanVariant,
        relation_context: RelationPlanCheckContext,
        ring_degree: usize,
        source_layout: PublicKeyShareSourceLayout,
    ) -> Result<Self, CommonProofProverError> {
        Self::new(
            source,
            relation_plan,
            relation_plan_variant,
            relation_context,
            ring_degree,
            SetupKeyRelationSourceLayout::PublicKeyShare(source_layout),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        source: &SetupGenerationKeyRelationSource<'_, '_>,
        relation_plan: &CommonProofRelationPlanCapability,
        relation_plan_variant: RelationPlanVariant,
        relation_context: RelationPlanCheckContext,
        ring_degree: usize,
        source_layout: SetupKeyRelationSourceLayout,
    ) -> Result<Self, CommonProofProverError> {
        if relation_plan_variant.schedule_position().is_some()
            || relation_plan_variant.top_count().is_some()
            || ring_degree == 0
            || ring_degree != source.ring_degree()
            || source.family()
                != match &source_layout {
                    SetupKeyRelationSourceLayout::SameSecret(_) => {
                        SetupKeyRelationProofFamily::SameSecret
                    }
                    SetupKeyRelationSourceLayout::PublicKeyShare(_) => {
                        SetupKeyRelationProofFamily::PublicKeyShare
                    }
                }
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        let request_context = CommonProofSourcePolynomialRequestContext::new(
            source.protocol_version(),
            source.suite_identifier(),
            source.family().statement_schema_identifier(),
            source
                .prepared_attempt()
                .application_statement_hash()
                .into_bytes(),
            relation_plan.relation_plan_hash(),
            relation_plan.relation_plan_variant_hash(),
            None,
            None,
        );
        let requested_column_ordinals =
            requested_source_column_ordinals(&relation_plan_variant)?.into_boxed_slice();
        let bound_material_tree_sources = match &source_layout {
            SetupKeyRelationSourceLayout::SameSecret(layout) => relation_plan_variant
                .ordered_trees()
                .iter()
                .enumerate()
                .filter_map(|(tree_catalog_index, tree)| {
                    let RelationTreeDescriptor::BoundPublic {
                        construction_kind: BoundTreeConstructionKind::CommittedMaterial,
                        ordered_column_ordinals,
                        ..
                    } = tree
                    else {
                        return None;
                    };
                    let material_ordinal = layout.ordered_materials.iter().position(|material| {
                        material_columns_match(material, ordered_column_ordinals)
                    });
                    Some((tree_catalog_index, material_ordinal))
                })
                .map(|(tree_catalog_index, material_ordinal)| {
                    Ok::<BoundMaterialTreeSource, CommonProofProverError>(BoundMaterialTreeSource {
                        tree_catalog_index: u16::try_from(tree_catalog_index)
                            .map_err(|_| CommonProofProverError::CountOverflow)?,
                        material_ordinal: material_ordinal
                            .ok_or(CommonProofProverError::InvalidTree)?,
                    })
                })
                .collect::<Result<Vec<_>, _>>()?
                .into_boxed_slice(),
            SetupKeyRelationSourceLayout::PublicKeyShare(_) => Box::new([]),
        };
        Ok(Self {
            authority_identifier: source.authority_identifier(),
            family: source.family(),
            prepared_attempt: *source.prepared_attempt(),
            canonical_application_statement_bytes: source
                .canonical_application_statement_bytes()
                .to_vec(),
            setup_proof_context_hash: source.setup_proof_context_hash(),
            roster_hash: source.roster_hash(),
            participant_identity: source.participant_identity(),
            roster_position: source.roster_position(),
            setup_attempt_identifier: source.setup_attempt_identifier(),
            source_setup_intent_object_hash: source.source_setup_intent_object_hash(),
            action_randomness_authorization_hash: source.action_randomness_authorization_hash(),
            request_context,
            relation_plan_variant,
            relation_context,
            ring_degree,
            source_layout,
            requested_column_ordinals,
            bound_material_tree_sources,
            next_source_index: 0,
            next_leaf_salt_source_ordinal: 0,
            next_leaf_salt_index: 0,
            cached_quotient: None,
            source_polynomials_finished: false,
            leaf_salts_finished: false,
        })
    }

    fn application(&self) -> SetupGenerationKeyRelationApplication<'_> {
        SetupGenerationKeyRelationApplication::from_runtime_binding(
            self.family,
            self.prepared_attempt,
            &self.canonical_application_statement_bytes,
            self.setup_proof_context_hash,
            self.roster_hash,
            self.participant_identity,
            self.roster_position,
        )
    }

    fn replay_identity(
        &self,
        column_ordinal: u32,
    ) -> Result<CommonProofSourcePolynomialReplayIdentity, CommonProofProverError> {
        let domain = match self.family {
            SetupKeyRelationProofFamily::SameSecret => SAME_SECRET_SOURCE_REPLAY_IDENTITY_DOMAIN,
            SetupKeyRelationProofFamily::PublicKeyShare => {
                PUBLIC_KEY_SHARE_SOURCE_REPLAY_IDENTITY_DOMAIN
            }
        };
        CommonProofSourcePolynomialReplayIdentity::from_authenticated_source(hash_framed_parts_512(
            domain,
            &[
                &self.request_context.stable_generation_binding_hash(),
                &column_ordinal.to_le_bytes(),
                &self.setup_attempt_identifier,
                &self.source_setup_intent_object_hash,
                &self.action_randomness_authorization_hash,
                &self.setup_proof_context_hash,
                &self.roster_hash,
                &self.participant_identity,
                &self.roster_position.to_le_bytes(),
            ],
        ))
    }

    fn derive_source_polynomial(
        &mut self,
        column_ordinal: u32,
    ) -> Result<CommonProofSourcePolynomial, CommonProofProverError> {
        let authority_handle =
            SetupGenerationAuthorityHandle::from_identifier(self.authority_identifier);
        let application = SetupGenerationKeyRelationApplication::from_runtime_binding(
            self.family,
            self.prepared_attempt,
            &self.canonical_application_statement_bytes,
            self.setup_proof_context_hash,
            self.roster_hash,
            self.participant_identity,
            self.roster_position,
        );
        let relation_plan_variant = &self.relation_plan_variant;
        let relation_context = &self.relation_context;
        let ring_degree = self.ring_degree;
        let source_layout = &self.source_layout;
        let cached_quotient = &mut self.cached_quotient;
        let polynomial = with_setup_generation_key_relation::<_, RefusalReason>(
            &authority_handle,
            &application,
            |source| {
                if let SetupKeyRelationSourceLayout::SameSecret(layout) = source_layout
                    && let Some((material_ordinal, physical_column_ordinal)) =
                        bound_material_column(layout, column_ordinal)
                {
                    let coefficients = source
                        .degree_zero_material(material_ordinal)?
                        .owned_authenticated_source()
                        .regenerate_masked_coefficients(physical_column_ordinal)
                        .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
                    return Ok(
                        CommonProofSourcePolynomial::from_protected_base_coefficients(coefficients),
                    );
                }
                if let SetupKeyRelationSourceLayout::PublicKeyShare(layout) = source_layout
                    && let Some((limb_ordinal, quarter_ordinal)) =
                        public_key_bound_quarter(layout, column_ordinal)
                {
                    let coefficients = source
                        .public_key_share()
                        .ordered_limb_coefficients()
                        .get(limb_ordinal)
                        .ok_or(RefusalReason::WrongTypeOrLength)?;
                    if coefficients.len() != ring_degree || coefficients.len() % 4 != 0 {
                        return Err(RefusalReason::WrongTypeOrLength);
                    }
                    let quarter_size = coefficients.len() / 4;
                    let start = quarter_ordinal
                        .checked_mul(quarter_size)
                        .ok_or(RefusalReason::OutsideSupportedProfile)?;
                    let end = start
                        .checked_add(quarter_size)
                        .ok_or(RefusalReason::OutsideSupportedProfile)?;
                    let quarter = coefficients
                        .get(start..end)
                        .ok_or(RefusalReason::WrongTypeOrLength)?;
                    let field_coefficients = quarter
                        .iter()
                        .copied()
                        .map(ProofBaseFieldElement::from_canonical)
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
                    return Ok(
                        CommonProofSourcePolynomial::from_protected_base_coefficients(
                            Zeroizing::new(field_coefficients),
                        ),
                    );
                }
                let signed_rows = match source_layout {
                    SetupKeyRelationSourceLayout::SameSecret(layout) => {
                        let mut derivation = SameSecretColumnDerivation {
                            source: &source,
                            relation_plan_variant,
                            relation_context,
                            ring_degree,
                            source_layout: layout,
                            cached_rows: BTreeMap::new(),
                            active_columns: BTreeSet::new(),
                            cached_quotient,
                        };
                        derivation.derive_rows(column_ordinal)?
                    }
                    SetupKeyRelationSourceLayout::PublicKeyShare(layout) => {
                        let mut derivation = PublicKeyShareColumnDerivation {
                            source: &source,
                            relation_plan_variant,
                            relation_context,
                            ring_degree,
                            source_layout: layout,
                            cached_rows: BTreeMap::new(),
                            active_columns: BTreeSet::new(),
                            cached_quotient,
                        };
                        derivation.derive_rows(column_ordinal)?
                    }
                };
                let mut field_values = Zeroizing::new(
                    signed_rows
                        .iter()
                        .copied()
                        .map(signed_integer_to_base_field)
                        .collect::<Result<Vec<_>, _>>()?,
                );
                let descriptor = relation_plan_variant
                    .ordered_columns()
                    .get(
                        usize::try_from(column_ordinal)
                            .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
                    )
                    .ok_or(RefusalReason::WrongTypeOrLength)?;
                let is_public_key_half_projection = matches!(source_layout,
                    SetupKeyRelationSourceLayout::PublicKeyShare(layout)
                        if is_public_key_half_projection(layout, column_ordinal));
                if !matches!(descriptor.origin(), RelationColumnOrigin::BoundTree { .. })
                    && !is_public_key_half_projection
                {
                    ProofEvaluationDomain::new_subgroup(
                        usize::try_from(relation_plan_variant.trace_domain_size())
                            .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
                    )
                    .map_err(|_| RefusalReason::InvalidArithmeticRelation)?
                    .interpolate_base_polynomial_in_place(&mut field_values)
                    .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
                }
                Ok(CommonProofSourcePolynomial::from_protected_base_coefficients(field_values))
            },
        )
        .map_err(|_| CommonProofProverError::InvalidColumn)?;
        Ok(polynomial)
    }
}

impl CommonProofSourcePolynomialProvider for SetupKeyRelationSourcePolynomialAdapter {
    fn poll_source_polynomial(
        &mut self,
        request: CommonProofSourcePolynomialRequest<'_>,
    ) -> Result<CommonProofSourcePolynomialProviderPoll, CommonProofProverError> {
        if self.source_polynomials_finished
            || request.request_context() != self.request_context
            || self
                .requested_column_ordinals
                .get(self.next_source_index)
                .copied()
                != Some(request.column_ordinal())
            || self.relation_plan_variant.ordered_columns().get(
                usize::try_from(request.column_ordinal())
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            ) != Some(request.descriptor())
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let column_ordinal = request.column_ordinal();
        let replay_identity = self.replay_identity(column_ordinal)?;
        let polynomial = self.derive_source_polynomial(column_ordinal)?;
        self.next_source_index = self
            .next_source_index
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
        Ok(CommonProofSourcePolynomialProviderPoll::Ready(
            ProvidedCommonProofSourcePolynomial::new(polynomial, replay_identity),
        ))
    }

    fn finish(&mut self) -> Result<(), CommonProofProverError> {
        if self.source_polynomials_finished
            || self.next_source_index != self.requested_column_ordinals.len()
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        self.cached_quotient = None;
        self.source_polynomials_finished = true;
        Ok(())
    }

    fn provide_bound_tree_leaf_salt(
        &mut self,
        request: CommonProofBoundTreeLeafSaltRequest,
    ) -> Result<
        Option<[u8; super::super::COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]>,
        CommonProofProverError,
    > {
        if !self.source_polynomials_finished || self.leaf_salts_finished {
            return Err(CommonProofProverError::InvalidTree);
        }
        let bound_source = self
            .bound_material_tree_sources
            .get(self.next_leaf_salt_source_ordinal)
            .copied()
            .ok_or(CommonProofProverError::InvalidTree)?;
        let authority_handle =
            SetupGenerationAuthorityHandle::from_identifier(self.authority_identifier);
        let application = self.application();
        let leaf_index = self.next_leaf_salt_index;
        let salt_and_leaf_count = with_setup_generation_key_relation::<_, RefusalReason>(
            &authority_handle,
            &application,
            |source| {
                let material = source.degree_zero_material(bound_source.material_ordinal)?;
                let compact_source = material.compact_source();
                let leaf_count = compact_source.profile().evaluation_domain_size() / 2;
                if request.request_context() != self.request_context
                    || request.tree_catalog_index() != bound_source.tree_catalog_index
                    || request.expected_root() != compact_source.root()
                    || usize::try_from(request.leaf_index()).ok() != Some(leaf_index)
                    || leaf_index >= leaf_count
                {
                    return Err(RefusalReason::WrongContext);
                }
                Ok((
                    compact_source
                        .persistent_leaf_salt(leaf_index)
                        .map_err(|_| RefusalReason::InvalidArithmeticRelation)?,
                    leaf_count,
                ))
            },
        )
        .map_err(|_| CommonProofProverError::InvalidTree)?;
        self.next_leaf_salt_index = self
            .next_leaf_salt_index
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
        if self.next_leaf_salt_index == salt_and_leaf_count.1 {
            self.next_leaf_salt_source_ordinal = self
                .next_leaf_salt_source_ordinal
                .checked_add(1)
                .ok_or(CommonProofProverError::CountOverflow)?;
            self.next_leaf_salt_index = 0;
        }
        Ok(Some(salt_and_leaf_count.0))
    }

    fn finish_bound_tree_leaf_salts(&mut self) -> Result<(), CommonProofProverError> {
        if self.source_polynomials_finished
            && !self.leaf_salts_finished
            && self.next_leaf_salt_source_ordinal == self.bound_material_tree_sources.len()
            && self.next_leaf_salt_index == 0
        {
            self.leaf_salts_finished = true;
            Ok(())
        } else {
            Err(CommonProofProverError::InvalidTree)
        }
    }
}

pub(crate) fn same_secret_relation_tree_inputs(
    source: &SetupGenerationKeyRelationSource<'_, '_>,
    relation_plan_variant: &RelationPlanVariant,
    source_layout: &SameSecretSourceLayout,
) -> Result<Vec<RelationProofTreeInput>, CommonProofProverError> {
    relation_tree_inputs(source, relation_plan_variant, |tree, tree_catalog_index| {
        let RelationTreeDescriptor::BoundPublic {
            construction_kind,
            ordered_column_ordinals,
            ..
        } = tree
        else {
            return Ok(None);
        };
        match construction_kind {
            BoundTreeConstructionKind::CommittedMaterial => {
                let material_ordinal = source_layout
                    .ordered_materials
                    .iter()
                    .position(|material| material_columns_match(material, ordered_column_ordinals))
                    .ok_or(CommonProofProverError::InvalidTree)?;
                let material = source
                    .degree_zero_material(material_ordinal)
                    .map_err(|_| CommonProofProverError::InvalidTree)?;
                let _ = u16::try_from(tree_catalog_index)
                    .map_err(|_| CommonProofProverError::CountOverflow)?;
                Ok(Some(RelationProofTreeInput::BoundPublic(
                    StatementOwnedProofTreeInput::CommittedMaterial {
                        material_context_hash: material.compact_source().material_context_hash(),
                        expected_root: material.compact_source().root(),
                    },
                )))
            }
            BoundTreeConstructionKind::SetupPolynomial => {
                let anchor_ordinal = source_layout
                    .ordered_anchors
                    .iter()
                    .position(|anchor| {
                        split_rows_match(&anchor.commitments, ordered_column_ordinals)
                    })
                    .ok_or(CommonProofProverError::InvalidTree)?;
                let anchor = source
                    .anchor_openings()
                    .get(anchor_ordinal)
                    .ok_or(CommonProofProverError::InvalidTree)?;
                Ok(Some(RelationProofTreeInput::BoundPublic(
                    StatementOwnedProofTreeInput::SetupPolynomial {
                        public_polynomial_context_hash: anchor.public_polynomial_context_hash(),
                        row_width: u32::try_from(ordered_column_ordinals.len())
                            .map_err(|_| CommonProofProverError::CountOverflow)?,
                        expected_root: anchor.root(),
                    },
                )))
            }
            _ => Err(CommonProofProverError::InvalidTree),
        }
    })
}

pub(crate) fn public_key_share_relation_tree_inputs(
    source: &SetupGenerationKeyRelationSource<'_, '_>,
    relation_plan_variant: &RelationPlanVariant,
    source_layout: &PublicKeyShareSourceLayout,
) -> Result<Vec<RelationProofTreeInput>, CommonProofProverError> {
    relation_tree_inputs(source, relation_plan_variant, |tree, _| {
        let RelationTreeDescriptor::BoundPublic {
            construction_kind: BoundTreeConstructionKind::SetupPolynomial,
            ordered_column_ordinals,
            ..
        } = tree
        else {
            return Err(CommonProofProverError::InvalidTree);
        };
        if source_layout
            .public_key_share_limbs
            .iter()
            .flat_map(|limb| limb.quarters)
            .eq(ordered_column_ordinals.iter().copied())
        {
            return Ok(Some(RelationProofTreeInput::BoundPublic(
                StatementOwnedProofTreeInput::SetupPolynomial {
                    public_polynomial_context_hash: source
                        .public_key_share()
                        .public_polynomial_context_hash(),
                    row_width: u32::try_from(ordered_column_ordinals.len())
                        .map_err(|_| CommonProofProverError::CountOverflow)?,
                    expected_root: source.public_key_share().root(),
                },
            )));
        }
        let anchor_ordinal = source_layout
            .ordered_anchors
            .iter()
            .position(|anchor| split_rows_match(&anchor.commitments, ordered_column_ordinals))
            .ok_or(CommonProofProverError::InvalidTree)?;
        let anchor = source
            .anchor_openings()
            .get(anchor_ordinal)
            .ok_or(CommonProofProverError::InvalidTree)?;
        Ok(Some(RelationProofTreeInput::BoundPublic(
            StatementOwnedProofTreeInput::SetupPolynomial {
                public_polynomial_context_hash: anchor.public_polynomial_context_hash(),
                row_width: u32::try_from(ordered_column_ordinals.len())
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
                expected_root: anchor.root(),
            },
        )))
    })
}

fn relation_tree_inputs(
    _source: &SetupGenerationKeyRelationSource<'_, '_>,
    relation_plan_variant: &RelationPlanVariant,
    mut bound_tree: impl FnMut(
        &RelationTreeDescriptor,
        usize,
    ) -> Result<Option<RelationProofTreeInput>, CommonProofProverError>,
) -> Result<Vec<RelationProofTreeInput>, CommonProofProverError> {
    let mut relation_trees = Vec::with_capacity(relation_plan_variant.ordered_trees().len());
    for (tree_catalog_index, tree) in relation_plan_variant.ordered_trees().iter().enumerate() {
        match tree {
            RelationTreeDescriptor::ProofCreated {
                proof_tree_role,
                ordered_column_ordinals,
            } => {
                let tree_role = match *proof_tree_role {
                    value if value == ProofTreeRole::BaseOracle as u16 => ProofTreeRole::BaseOracle,
                    value if value == ProofTreeRole::AuxiliaryOracle as u16 => {
                        ProofTreeRole::AuxiliaryOracle
                    }
                    _ => return Err(CommonProofProverError::InvalidTree),
                };
                let leaf_visibility = ordered_column_ordinals.iter().try_fold(
                    ProofLeafVisibility::Public,
                    |visibility, column_ordinal| {
                        let descriptor = relation_plan_variant
                            .ordered_columns()
                            .get(
                                usize::try_from(*column_ordinal)
                                    .map_err(|_| CommonProofProverError::CountOverflow)?,
                            )
                            .ok_or(CommonProofProverError::InvalidColumn)?;
                        Ok::<_, CommonProofProverError>(
                            if matches!(descriptor.origin(), RelationColumnOrigin::Prover) {
                                ProofLeafVisibility::SecretBearing
                            } else {
                                visibility
                            },
                        )
                    },
                )?;
                relation_trees.push(RelationProofTreeInput::ProofCreated {
                    tree_role,
                    row_width: u32::try_from(ordered_column_ordinals.len())
                        .map_err(|_| CommonProofProverError::CountOverflow)?,
                    leaf_visibility,
                });
            }
            RelationTreeDescriptor::BoundPublic { .. } => relation_trees.push(
                bound_tree(tree, tree_catalog_index)?.ok_or(CommonProofProverError::InvalidTree)?,
            ),
        }
    }
    Ok(relation_trees)
}

fn material_columns_match(
    material: &super::same_secret_anchor::SameSecretMaterialSourceLayout,
    ordered_column_ordinals: &[u32],
) -> bool {
    let first = material.material[0].ordered_digit_column_ordinals();
    let second = material.material[1].ordered_digit_column_ordinals();
    first.len() == 2
        && second.len() == 2
        && ordered_column_ordinals == [first[0], second[0], first[1], second[1]]
}

fn bound_material_column(
    source_layout: &SameSecretSourceLayout,
    column_ordinal: u32,
) -> Option<(usize, usize)> {
    source_layout
        .ordered_materials
        .iter()
        .enumerate()
        .find_map(|(material_ordinal, material)| {
            let first = material.material[0].ordered_digit_column_ordinals();
            let second = material.material[1].ordered_digit_column_ordinals();
            [first[0], second[0], first[1], second[1]]
                .iter()
                .position(|candidate| *candidate == column_ordinal)
                .map(|physical_column_ordinal| (material_ordinal, physical_column_ordinal))
        })
}

fn is_public_key_half_projection(
    source_layout: &PublicKeyShareSourceLayout,
    column_ordinal: u32,
) -> bool {
    source_layout
        .public_key_share_limbs
        .iter()
        .any(|limb| limb.half_projections.halves.contains(&column_ordinal))
}

fn public_key_bound_quarter(
    source_layout: &PublicKeyShareSourceLayout,
    column_ordinal: u32,
) -> Option<(usize, usize)> {
    source_layout
        .public_key_share_limbs
        .iter()
        .enumerate()
        .find_map(|(limb_ordinal, limb)| {
            limb.quarters
                .iter()
                .position(|candidate| *candidate == column_ordinal)
                .map(|quarter_ordinal| (limb_ordinal, quarter_ordinal))
        })
}

pub(super) trait KeyRelationColumnDerivation {
    fn relation_plan_variant(&self) -> &RelationPlanVariant;
    fn relation_context(&self) -> &RelationPlanCheckContext;
    fn exact_radix_digits_by_column(&self) -> &BTreeMap<u32, Box<[u32]>>;
    fn cached_rows(&self) -> &BTreeMap<u32, Zeroizing<Vec<i128>>>;
    fn cached_rows_mut(&mut self) -> &mut BTreeMap<u32, Zeroizing<Vec<i128>>>;
    fn active_columns_mut(&mut self) -> &mut BTreeSet<u32>;
    fn direct_witness_rows(
        &mut self,
        column_ordinal: u32,
    ) -> Result<Option<Zeroizing<Vec<i128>>>, RefusalReason>;
    fn full_verifier_sequence(
        &self,
        source: &RelationVerifierSource,
    ) -> Result<Vec<u64>, RefusalReason>;

    fn derive_rows(&mut self, column_ordinal: u32) -> Result<Zeroizing<Vec<i128>>, RefusalReason> {
        if let Some(rows) = self.cached_rows().get(&column_ordinal) {
            return Ok(Zeroizing::new(rows.to_vec()));
        }
        if !self.active_columns_mut().insert(column_ordinal) {
            return Err(RefusalReason::InvalidArithmeticRelation);
        }
        let rows = if let Some(rows) = self.direct_witness_rows(column_ordinal)? {
            rows
        } else if let Some(rows) = self.exact_radix_digit_rows(column_ordinal)? {
            rows
        } else if let Some(rows) = self.verifier_sequence_rows(column_ordinal)? {
            rows
        } else if let Some(rows) = self.semantic_auxiliary_rows(column_ordinal)? {
            rows
        } else if let Some(rows) = self.exact_integer_lift_carry_rows(column_ordinal)? {
            rows
        } else {
            return Err(RefusalReason::InvalidArithmeticRelation);
        };
        self.active_columns_mut().remove(&column_ordinal);
        if rows.len()
            != usize::try_from(self.relation_plan_variant().trace_domain_size())
                .map_err(|_| RefusalReason::OutsideSupportedProfile)?
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        self.cached_rows_mut()
            .insert(column_ordinal, Zeroizing::new(rows.to_vec()));
        Ok(rows)
    }

    fn exact_radix_digit_rows(
        &mut self,
        column_ordinal: u32,
    ) -> Result<Option<Zeroizing<Vec<i128>>>, RefusalReason> {
        let source_and_digit = self.exact_radix_digits_by_column().iter().find_map(
            |(source_column_ordinal, digit_column_ordinals)| {
                digit_column_ordinals
                    .iter()
                    .position(|candidate| *candidate == column_ordinal)
                    .map(|digit_ordinal| (*source_column_ordinal, digit_ordinal))
            },
        );
        let Some((source_column_ordinal, digit_ordinal)) = source_and_digit else {
            return Ok(None);
        };
        let source_rows = self.derive_rows(source_column_ordinal)?;
        let divisor = i128::from(EXACT_INTEGER_LIFT_RADIX)
            .checked_pow(
                u32::try_from(digit_ordinal).map_err(|_| RefusalReason::OutsideSupportedProfile)?,
            )
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        source_rows
            .iter()
            .map(|value| {
                if *value < 0 {
                    Err(RefusalReason::InvalidArithmeticRelation)
                } else {
                    Ok((*value / divisor) % i128::from(EXACT_INTEGER_LIFT_RADIX))
                }
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Zeroizing::new)
            .map(Some)
    }

    fn verifier_sequence_rows(
        &self,
        column_ordinal: u32,
    ) -> Result<Option<Zeroizing<Vec<i128>>>, RefusalReason> {
        let descriptor = self
            .relation_plan_variant()
            .ordered_columns()
            .get(
                usize::try_from(column_ordinal)
                    .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
            )
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        let RelationColumnOrigin::VerifierSequence {
            verifier_source_ordinal,
            first_logical_element_index,
            logical_element_stride,
        } = descriptor.origin()
        else {
            return Ok(None);
        };
        let source = self
            .relation_plan_variant()
            .verifier_source(*verifier_source_ordinal)
            .ok_or(RefusalReason::InvalidArithmeticRelation)?;
        let sequence = self.full_verifier_sequence(source)?;
        let trace_size = usize::try_from(self.relation_plan_variant().trace_domain_size())
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        let first_index = usize::try_from(*first_logical_element_index)
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        let stride = usize::try_from(*logical_element_stride)
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        (0..trace_size)
            .map(|row_ordinal| {
                first_index
                    .checked_add(
                        row_ordinal
                            .checked_mul(stride)
                            .ok_or(RefusalReason::OutsideSupportedProfile)?,
                    )
                    .and_then(|index| sequence.get(index).copied())
                    .map(i128::from)
                    .ok_or(RefusalReason::WrongTypeOrLength)
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Zeroizing::new)
            .map(Some)
    }

    fn semantic_auxiliary_rows(
        &mut self,
        column_ordinal: u32,
    ) -> Result<Option<Zeroizing<Vec<i128>>>, RefusalReason> {
        let certificate = self
            .relation_plan_variant()
            .ordered_semantic_cells
            .iter()
            .find_map(|semantic_cell| match &semantic_cell.bound_certificate {
                RelationBoundCertificate::UnsignedRadixRecomposition {
                    radix,
                    ordered_digit_column_ordinals,
                    ..
                } if ordered_digit_column_ordinals.contains(&column_ordinal) => Some((
                    semantic_cell.column_ordinal,
                    SemanticAuxiliaryRecipe::Radix {
                        radix: *radix,
                        offset: 0,
                        digit_ordinal: ordered_digit_column_ordinals
                            .iter()
                            .position(|candidate| *candidate == column_ordinal)?,
                    },
                )),
                RelationBoundCertificate::ShiftedRadixRecomposition {
                    radix,
                    offset,
                    ordered_digit_column_ordinals,
                    ..
                } if ordered_digit_column_ordinals.contains(&column_ordinal) => Some((
                    semantic_cell.column_ordinal,
                    SemanticAuxiliaryRecipe::Radix {
                        radix: *radix,
                        offset: offset.to_i128()?,
                        digit_ordinal: ordered_digit_column_ordinals
                            .iter()
                            .position(|candidate| *candidate == column_ordinal)?,
                    },
                )),
                RelationBoundCertificate::CanonicalModulusRecomposition {
                    modulus_reference,
                    radix,
                    ordered_digit_column_ordinals,
                    ordered_difference_digit_column_ordinals,
                    ordered_borrow_column_ordinals,
                    ..
                } if ordered_digit_column_ordinals.contains(&column_ordinal)
                    || ordered_difference_digit_column_ordinals.contains(&column_ordinal)
                    || ordered_borrow_column_ordinals.contains(&column_ordinal) =>
                {
                    Some((
                        semantic_cell.column_ordinal,
                        SemanticAuxiliaryRecipe::CanonicalComparator {
                            modulus_reference: *modulus_reference,
                            radix: *radix,
                            digit_columns: ordered_digit_column_ordinals.clone(),
                            difference_columns: ordered_difference_digit_column_ordinals.clone(),
                            borrow_columns: ordered_borrow_column_ordinals.clone(),
                        },
                    ))
                }
                _ => None,
            });
        let Some((target_column_ordinal, recipe)) = certificate else {
            return Ok(None);
        };
        let target = self.derive_rows(target_column_ordinal)?;
        match recipe {
            SemanticAuxiliaryRecipe::Radix {
                radix,
                offset,
                digit_ordinal,
            } => {
                let divisor = i128::from(radix)
                    .checked_pow(
                        u32::try_from(digit_ordinal)
                            .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
                    )
                    .ok_or(RefusalReason::OutsideSupportedProfile)?;
                target
                    .iter()
                    .map(|value| {
                        value
                            .checked_add(offset)
                            .filter(|shifted| *shifted >= 0)
                            .map(|shifted| (shifted / divisor) % i128::from(radix))
                            .ok_or(RefusalReason::InvalidArithmeticRelation)
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .map(Zeroizing::new)
                    .map(Some)
            }
            SemanticAuxiliaryRecipe::CanonicalComparator {
                modulus_reference,
                radix,
                digit_columns,
                difference_columns,
                borrow_columns,
            } => canonical_comparator_column_rows(
                &target,
                self.relation_context()
                    .resolved_modulus(modulus_reference)
                    .map_err(|_| RefusalReason::InvalidArithmeticRelation)?,
                radix,
                &digit_columns,
                &difference_columns,
                &borrow_columns,
                column_ordinal,
            )
            .map(Some),
        }
    }

    fn exact_integer_lift_carry_rows(
        &mut self,
        column_ordinal: u32,
    ) -> Result<Option<Zeroizing<Vec<i128>>>, RefusalReason> {
        let component = self
            .relation_plan_variant()
            .ordered_integer_lift_batches()
            .iter()
            .flat_map(|batch| batch.ordered_components.iter())
            .find(|component| {
                component.ordered_linear_terms.iter().any(|term| {
                    term.negative
                        && term.column_ordinal == column_ordinal
                        && term.column_offset == 0
                        && term.coefficient
                            == RelationIntegerLiftCoefficient::Constant(EXACT_INTEGER_LIFT_RADIX)
                })
            })
            .cloned();
        let Some(component) = component else {
            return Ok(None);
        };
        let trace_size = usize::try_from(self.relation_plan_variant().trace_domain_size())
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        let mut accumulated = Zeroizing::new(vec![0_i128; trace_size]);
        for term in &component.ordered_linear_terms {
            if term.negative
                && term.column_ordinal == column_ordinal
                && term.column_offset == 0
                && term.coefficient
                    == RelationIntegerLiftCoefficient::Constant(EXACT_INTEGER_LIFT_RADIX)
            {
                continue;
            }
            let rows = self.derive_rows(term.column_ordinal)?;
            let coefficient = i128::from(resolve_integer_lift_coefficient(
                term.coefficient,
                self.relation_context(),
            )?);
            for (accumulated, value) in accumulated.iter_mut().zip(rows.iter()) {
                let shifted = value
                    .checked_sub(i128::from(term.column_offset))
                    .ok_or(RefusalReason::InvalidArithmeticRelation)?;
                let contribution = shifted
                    .checked_mul(coefficient)
                    .ok_or(RefusalReason::InvalidArithmeticRelation)?;
                *accumulated = if term.negative {
                    accumulated.checked_sub(contribution)
                } else {
                    accumulated.checked_add(contribution)
                }
                .ok_or(RefusalReason::InvalidArithmeticRelation)?;
            }
        }
        for product in &component.ordered_full_ring_negacyclic_products {
            let product_rows = self.full_ring_product_rows(product)?;
            for (accumulated, value) in accumulated.iter_mut().zip(product_rows.iter()) {
                *accumulated = accumulated
                    .checked_add(*value)
                    .ok_or(RefusalReason::InvalidArithmeticRelation)?;
            }
        }
        let radix = i128::from(EXACT_INTEGER_LIFT_RADIX);
        accumulated
            .iter()
            .copied()
            .map(|value| {
                if value % radix == 0 {
                    Ok(value / radix)
                } else {
                    Err(RefusalReason::InvalidArithmeticRelation)
                }
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Zeroizing::new)
            .map(Some)
    }

    fn full_ring_product_rows(
        &mut self,
        product: &RelationIntegerLiftFullRingNegacyclicProductDescriptor,
    ) -> Result<Zeroizing<Vec<i128>>, RefusalReason> {
        let multiplicand_low = self.derive_rows(product.multiplicand_low_column_ordinal)?;
        let multiplicand_high = self.derive_rows(product.multiplicand_high_column_ordinal)?;
        let multiplier_low = self.derive_rows(product.multiplier_low_column_ordinal)?;
        let multiplier_high = self.derive_rows(product.multiplier_high_column_ordinal)?;
        let multiplicand = multiplicand_low
            .iter()
            .chain(multiplicand_high.iter())
            .copied()
            .collect::<Vec<_>>();
        let multiplier = multiplier_low
            .iter()
            .map(|value| value - i128::from(product.multiplier_low_offset))
            .chain(
                multiplier_high
                    .iter()
                    .map(|value| value - i128::from(product.multiplier_high_offset)),
            )
            .collect::<Vec<_>>();
        let product_coefficients = exact_negacyclic_product_small(&multiplicand, &multiplier)?;
        let half_size = multiplicand_low.len();
        let selected = match product.selected_half {
            RelationIntegerLiftFullRingHalf::Low => &product_coefficients[..half_size],
            RelationIntegerLiftFullRingHalf::High => &product_coefficients[half_size..],
        };
        Ok(Zeroizing::new(
            selected
                .iter()
                .map(|value| if product.negative { -*value } else { *value })
                .collect(),
        ))
    }
}

enum SemanticAuxiliaryRecipe {
    Radix {
        radix: u64,
        offset: i128,
        digit_ordinal: usize,
    },
    CanonicalComparator {
        modulus_reference: SuiteModulusReference,
        radix: u64,
        digit_columns: Vec<u32>,
        difference_columns: Vec<u32>,
        borrow_columns: Vec<u32>,
    },
}

struct SameSecretColumnDerivation<'source, 'authority, 'statement, 'plan> {
    source: &'source SetupGenerationKeyRelationSource<'authority, 'statement>,
    relation_plan_variant: &'plan RelationPlanVariant,
    relation_context: &'plan RelationPlanCheckContext,
    ring_degree: usize,
    source_layout: &'plan SameSecretSourceLayout,
    cached_rows: BTreeMap<u32, Zeroizing<Vec<i128>>>,
    active_columns: BTreeSet<u32>,
    cached_quotient: &'plan mut Option<CachedQuotient>,
}

impl KeyRelationColumnDerivation for SameSecretColumnDerivation<'_, '_, '_, '_> {
    fn relation_plan_variant(&self) -> &RelationPlanVariant {
        self.relation_plan_variant
    }

    fn relation_context(&self) -> &RelationPlanCheckContext {
        self.relation_context
    }

    fn exact_radix_digits_by_column(&self) -> &BTreeMap<u32, Box<[u32]>> {
        &self.source_layout.exact_radix_digits_by_column
    }

    fn cached_rows(&self) -> &BTreeMap<u32, Zeroizing<Vec<i128>>> {
        &self.cached_rows
    }

    fn cached_rows_mut(&mut self) -> &mut BTreeMap<u32, Zeroizing<Vec<i128>>> {
        &mut self.cached_rows
    }

    fn active_columns_mut(&mut self) -> &mut BTreeSet<u32> {
        &mut self.active_columns
    }

    fn direct_witness_rows(
        &mut self,
        column_ordinal: u32,
    ) -> Result<Option<Zeroizing<Vec<i128>>>, RefusalReason> {
        if let Some(half_ordinal) = half_position(
            self.source_layout.common_secret.coefficients,
            column_ordinal,
        ) {
            return split_signed_i8_polynomial(
                self.source.common_secret_coefficients(),
                half_ordinal,
            )
            .map(Some);
        }
        if let Some(half_ordinal) = self
            .source_layout
            .negative_indicator
            .iter()
            .position(|candidate| *candidate == column_ordinal)
        {
            let indicator = self
                .source
                .common_secret_coefficients()
                .iter()
                .map(|coefficient| if *coefficient == -1 { 1 } else { 0 })
                .collect::<Vec<_>>();
            return split_signed_polynomial(&indicator, half_ordinal).map(Some);
        }
        for (material_ordinal, material_layout) in
            self.source_layout.ordered_materials.iter().enumerate()
        {
            for half_ordinal in 0..2 {
                if let Some(material_digit_ordinal) = material_layout.material[half_ordinal]
                    .ordered_digit_column_ordinals()
                    .iter()
                    .position(|candidate| *candidate == column_ordinal)
                {
                    let authenticated_source = self
                        .source
                        .degree_zero_material(material_ordinal)?
                        .owned_authenticated_source();
                    let trace_size =
                        usize::try_from(self.relation_plan_variant.trace_domain_size())
                            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
                    return (0..trace_size)
                        .map(|row_ordinal| {
                            authenticated_source
                                .material_digit(half_ordinal, material_digit_ordinal, row_ordinal)
                                .map(i128::from)
                                .map_err(|_| RefusalReason::InvalidArithmeticRelation)
                        })
                        .collect::<Result<Vec<_>, _>>()
                        .map(Zeroizing::new)
                        .map(Some);
                }
            }
        }
        anchor_direct_witness_rows(
            self.source,
            self.relation_plan_variant,
            self.relation_context,
            self.ring_degree,
            SetupKeyRelationProofFamily::SameSecret,
            &self.source_layout.ordered_anchors,
            column_ordinal,
            self.cached_quotient,
        )
    }

    fn full_verifier_sequence(
        &self,
        source: &RelationVerifierSource,
    ) -> Result<Vec<u64>, RefusalReason> {
        setup_verifier_sequence(
            source,
            self.source.public_setup_seed(),
            self.relation_context,
            self.ring_degree,
            false,
        )
    }
}

struct PublicKeyShareColumnDerivation<'source, 'authority, 'statement, 'plan> {
    source: &'source SetupGenerationKeyRelationSource<'authority, 'statement>,
    relation_plan_variant: &'plan RelationPlanVariant,
    relation_context: &'plan RelationPlanCheckContext,
    ring_degree: usize,
    source_layout: &'plan PublicKeyShareSourceLayout,
    cached_rows: BTreeMap<u32, Zeroizing<Vec<i128>>>,
    active_columns: BTreeSet<u32>,
    cached_quotient: &'plan mut Option<CachedQuotient>,
}

impl KeyRelationColumnDerivation for PublicKeyShareColumnDerivation<'_, '_, '_, '_> {
    fn relation_plan_variant(&self) -> &RelationPlanVariant {
        self.relation_plan_variant
    }

    fn relation_context(&self) -> &RelationPlanCheckContext {
        self.relation_context
    }

    fn exact_radix_digits_by_column(&self) -> &BTreeMap<u32, Box<[u32]>> {
        &self.source_layout.exact_radix_digits_by_column
    }

    fn cached_rows(&self) -> &BTreeMap<u32, Zeroizing<Vec<i128>>> {
        &self.cached_rows
    }

    fn cached_rows_mut(&mut self) -> &mut BTreeMap<u32, Zeroizing<Vec<i128>>> {
        &mut self.cached_rows
    }

    fn active_columns_mut(&mut self) -> &mut BTreeSet<u32> {
        &mut self.active_columns
    }

    fn direct_witness_rows(
        &mut self,
        column_ordinal: u32,
    ) -> Result<Option<Zeroizing<Vec<i128>>>, RefusalReason> {
        if let Some(half_ordinal) = half_position(
            self.source_layout.common_secret.source.coefficients,
            column_ordinal,
        ) {
            return split_signed_i8_polynomial(
                self.source.common_secret_coefficients(),
                half_ordinal,
            )
            .map(Some);
        }
        if let Some(half_ordinal) = half_position(
            self.source_layout.public_key_error.coefficients,
            column_ordinal,
        ) {
            return split_signed_i8_polynomial(
                self.source.public_key_share().centered_error_coefficients(),
                half_ordinal,
            )
            .map(Some);
        }
        for (limb_ordinal, limb_layout) in self
            .source_layout
            .public_key_share_limbs
            .iter()
            .copied()
            .enumerate()
        {
            let coefficients = self
                .source
                .public_key_share()
                .ordered_limb_coefficients()
                .get(limb_ordinal)
                .ok_or(RefusalReason::WrongTypeOrLength)?;
            if let Some(half_ordinal) = half_position(limb_layout.half_projections, column_ordinal)
            {
                let signed = coefficients
                    .iter()
                    .copied()
                    .map(i128::from)
                    .collect::<Vec<_>>();
                return split_signed_polynomial(&signed, half_ordinal).map(Some);
            }
        }
        for (limb_ordinal, limb_layout) in self.source_layout.ordered_limbs.iter().enumerate() {
            if let Some(half_ordinal) = limb_layout
                .quotient_columns
                .iter()
                .position(|candidate| *candidate == column_ordinal)
            {
                let quotient = self.cached_public_key_quotient(limb_ordinal)?;
                return split_signed_polynomial(quotient, half_ordinal).map(Some);
            }
        }
        anchor_direct_witness_rows(
            self.source,
            self.relation_plan_variant,
            self.relation_context,
            self.ring_degree,
            SetupKeyRelationProofFamily::PublicKeyShare,
            &self.source_layout.ordered_anchors,
            column_ordinal,
            self.cached_quotient,
        )
    }

    fn full_verifier_sequence(
        &self,
        source: &RelationVerifierSource,
    ) -> Result<Vec<u64>, RefusalReason> {
        setup_verifier_sequence(
            source,
            self.source.public_setup_seed(),
            self.relation_context,
            self.ring_degree,
            true,
        )
    }
}

impl PublicKeyShareColumnDerivation<'_, '_, '_, '_> {
    fn cached_public_key_quotient(
        &mut self,
        limb_ordinal: usize,
    ) -> Result<&[i128], RefusalReason> {
        let key = CachedQuotientKey::PublicKeyShare { limb_ordinal };
        if self.cached_quotient.as_ref().map(|cache| cache.key) != Some(key) {
            let coefficients = self.derive_public_key_quotient(limb_ordinal)?;
            *self.cached_quotient = Some(CachedQuotient { key, coefficients });
        }
        self.cached_quotient
            .as_ref()
            .map(|cache| cache.coefficients.as_slice())
            .ok_or(RefusalReason::ConsumedState)
    }

    fn derive_public_key_quotient(
        &self,
        limb_ordinal: usize,
    ) -> Result<Zeroizing<Vec<i128>>, RefusalReason> {
        let limb_layout = self
            .source_layout
            .ordered_limbs
            .get(limb_ordinal)
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        let modulus = self
            .relation_context
            .resolved_modulus(SuiteModulusReference::data(limb_layout.data_modulus_index))
            .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
        let public_key_share = self
            .source
            .public_key_share()
            .ordered_limb_coefficients()
            .get(limb_ordinal)
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        let common_reference = sample_collective_public_key_common_reference_limb(
            &self.source.public_setup_seed(),
            limb_layout.data_modulus_index,
            self.ring_degree,
        )
        .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
        let secret = self
            .source
            .common_secret_coefficients()
            .iter()
            .copied()
            .map(i128::from)
            .collect::<Vec<_>>();
        let product = exact_negacyclic_product_radix(
            &common_reference
                .into_iter()
                .map(|value| centered_residue(value, modulus))
                .collect::<Vec<_>>(),
            &secret,
        )?;
        let error = self.source.public_key_share().centered_error_coefficients();
        exact_modular_quotient(
            public_key_share
                .iter()
                .copied()
                .zip(product.iter().copied())
                .zip(error.iter().copied()),
            modulus,
            |((public_key_share, product), error)| {
                i128::from(public_key_share)
                    .checked_add(product)
                    .and_then(|value| {
                        value.checked_sub(i128::from(PLAINTEXT_MODULUS) * i128::from(error))
                    })
            },
        )
    }
}

trait AnchorSourceLayout {
    fn data_modulus_index(&self) -> u16;
    fn opening(&self) -> &super::key_relation::AnchorOpeningWitness;
    fn commitments(&self) -> &[super::key_relation::SplitIntegerVector];
    fn first_matrix(&self) -> &[Box<[super::key_relation::SplitIntegerVector]>];
    fn second_matrix(&self) -> &[super::key_relation::SplitIntegerVector];
    fn quotient_rows(&self) -> &[[u32; 2]];
}

impl AnchorSourceLayout for super::same_secret_anchor::SameSecretAnchorSourceLayout {
    fn data_modulus_index(&self) -> u16 {
        self.data_modulus_index
    }
    fn opening(&self) -> &super::key_relation::AnchorOpeningWitness {
        &self.opening
    }
    fn commitments(&self) -> &[super::key_relation::SplitIntegerVector] {
        &self.commitments
    }
    fn first_matrix(&self) -> &[Box<[super::key_relation::SplitIntegerVector]>] {
        &self.first_matrix
    }
    fn second_matrix(&self) -> &[super::key_relation::SplitIntegerVector] {
        &self.second_matrix
    }
    fn quotient_rows(&self) -> &[[u32; 2]] {
        self.quotients.rows()
    }
}

impl AnchorSourceLayout for super::public_key_share::PublicKeyShareAnchorSourceLayout {
    fn data_modulus_index(&self) -> u16 {
        self.data_modulus_index
    }
    fn opening(&self) -> &super::key_relation::AnchorOpeningWitness {
        &self.opening
    }
    fn commitments(&self) -> &[super::key_relation::SplitIntegerVector] {
        &self.commitments
    }
    fn first_matrix(&self) -> &[Box<[super::key_relation::SplitIntegerVector]>] {
        &self.first_matrix
    }
    fn second_matrix(&self) -> &[super::key_relation::SplitIntegerVector] {
        &self.second_matrix
    }
    fn quotient_rows(&self) -> &[[u32; 2]] {
        self.quotients.rows()
    }
}

#[allow(clippy::too_many_arguments)]
fn anchor_direct_witness_rows<Layout: AnchorSourceLayout>(
    source: &SetupGenerationKeyRelationSource<'_, '_>,
    relation_plan_variant: &RelationPlanVariant,
    relation_context: &RelationPlanCheckContext,
    ring_degree: usize,
    family: SetupKeyRelationProofFamily,
    layouts: &[Layout],
    column_ordinal: u32,
    cached_quotient: &mut Option<CachedQuotient>,
) -> Result<Option<Zeroizing<Vec<i128>>>, RefusalReason> {
    for (anchor_ordinal, (layout, anchor)) in
        layouts.iter().zip(source.anchor_openings()).enumerate()
    {
        for (polynomial_ordinal, hiding_secret) in
            layout.opening().hiding_secrets().iter().enumerate()
        {
            if let Some(half_ordinal) =
                half_position(hiding_secret.source.coefficients, column_ordinal)
            {
                return split_signed_i8_polynomial(
                    anchor
                        .hiding_secret_polynomials()
                        .get(polynomial_ordinal)
                        .ok_or(RefusalReason::WrongTypeOrLength)?,
                    half_ordinal,
                )
                .map(Some);
            }
        }
        for (polynomial_ordinal, hiding_error) in
            layout.opening().hiding_errors().iter().enumerate()
        {
            if let Some(half_ordinal) = half_position(hiding_error.coefficients, column_ordinal) {
                return split_signed_i8_polynomial(
                    anchor
                        .hiding_error_polynomials()
                        .get(polynomial_ordinal)
                        .ok_or(RefusalReason::WrongTypeOrLength)?,
                    half_ordinal,
                )
                .map(Some);
            }
        }
        for (row_ordinal, commitment) in layout.commitments().iter().copied().enumerate() {
            if let Some(half_ordinal) = half_position(commitment, column_ordinal) {
                return anchor
                    .ordered_coefficient_columns()
                    .get(row_ordinal * 2 + half_ordinal)
                    .map(|column| {
                        Zeroizing::new(
                            column
                                .iter()
                                .map(|value| i128::from(value.canonical()))
                                .collect(),
                        )
                    })
                    .ok_or(RefusalReason::WrongTypeOrLength)
                    .map(Some);
            }
        }
        for matrix_row in layout.first_matrix() {
            for matrix in matrix_row.iter() {
                if let Some(rows) = recentered_matrix_rows(
                    matrix,
                    column_ordinal,
                    source,
                    relation_plan_variant,
                    relation_context,
                    ring_degree,
                )? {
                    return Ok(Some(rows));
                }
            }
        }
        for matrix in layout.second_matrix() {
            if let Some(rows) = recentered_matrix_rows(
                matrix,
                column_ordinal,
                source,
                relation_plan_variant,
                relation_context,
                ring_degree,
            )? {
                return Ok(Some(rows));
            }
        }
        for (row_ordinal, quotient_columns) in layout.quotient_rows().iter().enumerate() {
            if let Some(half_ordinal) = quotient_columns
                .iter()
                .position(|candidate| *candidate == column_ordinal)
            {
                let key = CachedQuotientKey::Anchor {
                    family,
                    anchor_ordinal,
                    row_ordinal,
                };
                if cached_quotient.as_ref().map(|cache| cache.key) != Some(key) {
                    let coefficients = derive_anchor_quotient(
                        source,
                        relation_context,
                        ring_degree,
                        layout,
                        anchor_ordinal,
                        row_ordinal,
                    )?;
                    *cached_quotient = Some(CachedQuotient { key, coefficients });
                }
                let quotient = cached_quotient
                    .as_ref()
                    .map(|cache| cache.coefficients.as_slice())
                    .ok_or(RefusalReason::ConsumedState)?;
                return split_signed_polynomial(quotient, half_ordinal).map(Some);
            }
        }
    }
    Ok(None)
}

fn recentered_matrix_rows(
    matrix: &SplitIntegerVector,
    column_ordinal: u32,
    source: &SetupGenerationKeyRelationSource<'_, '_>,
    relation_plan_variant: &RelationPlanVariant,
    relation_context: &RelationPlanCheckContext,
    ring_degree: usize,
) -> Result<Option<Zeroizing<Vec<i128>>>, RefusalReason> {
    for half_ordinal in 0..2 {
        if matrix.halves[half_ordinal] == column_ordinal {
            let canonical_column = matrix.halves[half_ordinal];
            let descriptor = relation_plan_variant
                .ordered_columns()
                .get(
                    usize::try_from(canonical_column)
                        .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
                )
                .ok_or(RefusalReason::WrongTypeOrLength)?;
            let RelationColumnOrigin::VerifierSequence {
                verifier_source_ordinal,
                first_logical_element_index,
                logical_element_stride,
            } = descriptor.origin()
            else {
                return Err(RefusalReason::InvalidArithmeticRelation);
            };
            let verifier_source = relation_plan_variant
                .verifier_source(*verifier_source_ordinal)
                .ok_or(RefusalReason::InvalidArithmeticRelation)?;
            let sequence = setup_verifier_sequence(
                verifier_source,
                source.public_setup_seed(),
                relation_context,
                ring_degree,
                source.family() == SetupKeyRelationProofFamily::PublicKeyShare,
            )?;
            let trace_size = usize::try_from(relation_plan_variant.trace_domain_size())
                .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
            let first_index = usize::try_from(*first_logical_element_index)
                .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
            let stride = usize::try_from(*logical_element_stride)
                .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
            let canonical = (0..trace_size)
                .map(|row_ordinal| {
                    first_index
                        .checked_add(row_ordinal.checked_mul(stride)?)
                        .and_then(|index| sequence.get(index).copied())
                })
                .collect::<Option<Vec<_>>>()
                .ok_or(RefusalReason::WrongTypeOrLength)?;
            return Ok(Some(Zeroizing::new(
                canonical.into_iter().map(i128::from).collect(),
            )));
        }
    }
    Ok(None)
}

fn derive_anchor_quotient<Layout: AnchorSourceLayout>(
    source: &SetupGenerationKeyRelationSource<'_, '_>,
    relation_context: &RelationPlanCheckContext,
    ring_degree: usize,
    layout: &Layout,
    anchor_ordinal: usize,
    row_ordinal: usize,
) -> Result<Zeroizing<Vec<i128>>, RefusalReason> {
    let anchor = source
        .anchor_openings()
        .get(anchor_ordinal)
        .ok_or(RefusalReason::WrongTypeOrLength)?;
    if row_ordinal > SETUP_COMMITMENT_MODULE_RANK {
        return Err(RefusalReason::WrongTypeOrLength);
    }
    let modulus = relation_context
        .resolved_modulus(SuiteModulusReference::data(layout.data_modulus_index()))
        .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
    let commitment = anchor_full_row(anchor, row_ordinal)?;
    let seed = encode_hex(&source.public_setup_seed());
    let mut products = Vec::new();
    let product_columns = if row_ordinal < SETUP_COMMITMENT_MODULE_RANK {
        SETUP_COMMITMENT_MODULE_RANK + 1
    } else {
        SETUP_COMMITMENT_MODULE_RANK
    };
    for column_ordinal in 0..product_columns {
        let matrix_row = if row_ordinal < SETUP_COMMITMENT_MODULE_RANK {
            row_ordinal
        } else {
            SETUP_COMMITMENT_MODULE_RANK
        };
        let matrix = setup_commitment_matrix_polynomial(
            &seed,
            usize::from(layout.data_modulus_index()),
            matrix_row,
            column_ordinal,
            ring_degree,
            modulus,
        )
        .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
        let centered_matrix = matrix
            .into_iter()
            .map(|value| centered_residue(value, modulus))
            .collect::<Vec<_>>();
        let hiding_secret = anchor
            .hiding_secret_polynomials()
            .get(column_ordinal)
            .ok_or(RefusalReason::WrongTypeOrLength)?
            .iter()
            .copied()
            .map(i128::from)
            .collect::<Vec<_>>();
        products.push(exact_negacyclic_product_radix(
            &centered_matrix,
            &hiding_secret,
        )?);
    }
    let last_hiding_secret = anchor
        .hiding_secret_polynomials()
        .get(SETUP_COMMITMENT_MODULE_RANK)
        .ok_or(RefusalReason::WrongTypeOrLength)?;
    let hiding_error = (row_ordinal < SETUP_COMMITMENT_MODULE_RANK)
        .then(|| anchor.hiding_error_polynomials().get(row_ordinal))
        .flatten();
    exact_modular_quotient(0..ring_degree, modulus, |coefficient_ordinal| {
        let product_sum = products.iter().try_fold(0_i128, |sum, product| {
            sum.checked_add(product[coefficient_ordinal])
        })?;
        let value = commitment[coefficient_ordinal].checked_sub(product_sum)?;
        if let Some(error) = hiding_error {
            value.checked_sub(i128::from(error[coefficient_ordinal]))
        } else {
            value
                .checked_sub(i128::from(last_hiding_secret[coefficient_ordinal]))
                .and_then(|value| {
                    value.checked_sub(i128::from(
                        source.common_secret_coefficients()[coefficient_ordinal],
                    ))
                })
        }
    })
}

fn setup_verifier_sequence(
    source: &RelationVerifierSource,
    public_setup_seed: [u8; Hash512::BYTE_LENGTH],
    relation_context: &RelationPlanCheckContext,
    ring_degree: usize,
    allow_public_key_reference: bool,
) -> Result<Vec<u64>, RefusalReason> {
    match source {
        RelationVerifierSource::Protocol {
            protocol_source_kind: 5,
            source_coordinates,
            ..
        } => {
            let [data_modulus_index, matrix_part, row, column] = source_coordinates.as_slice()
            else {
                return Err(RefusalReason::WrongTypeOrLength);
            };
            let data_modulus_index =
                u16::try_from(*data_modulus_index).map_err(|_| RefusalReason::WrongTypeOrLength)?;
            let matrix_part =
                u16::try_from(*matrix_part).map_err(|_| RefusalReason::WrongTypeOrLength)?;
            let matrix_row = match matrix_part {
                1 => usize::try_from(*row).map_err(|_| RefusalReason::WrongTypeOrLength)?,
                2 if *row == 0 => SETUP_COMMITMENT_MODULE_RANK,
                _ => return Err(RefusalReason::WrongTypeOrLength),
            };
            let modulus = relation_context
                .resolved_modulus(SuiteModulusReference::data(data_modulus_index))
                .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
            setup_commitment_matrix_polynomial(
                &encode_hex(&public_setup_seed),
                usize::from(data_modulus_index),
                matrix_row,
                usize::try_from(*column).map_err(|_| RefusalReason::WrongTypeOrLength)?,
                ring_degree,
                modulus,
            )
            .map_err(|_| RefusalReason::InvalidArithmeticRelation)
        }
        RelationVerifierSource::Protocol {
            protocol_source_kind: 6,
            source_coordinates,
            ..
        } if allow_public_key_reference => {
            let [data_modulus_index] = source_coordinates.as_slice() else {
                return Err(RefusalReason::WrongTypeOrLength);
            };
            sample_collective_public_key_common_reference_limb(
                &public_setup_seed,
                u16::try_from(*data_modulus_index).map_err(|_| RefusalReason::WrongTypeOrLength)?,
                ring_degree,
            )
            .map_err(|_| RefusalReason::InvalidArithmeticRelation)
        }
        _ => Err(RefusalReason::WrongTypeOrLength),
    }
}
